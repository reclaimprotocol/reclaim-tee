package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// peerReadTimeout caps how long we wait for TEE_K to send the pair_id
// handshake before tearing the connection down. RA-TLS mTLS already
// authenticated the peer, but a misbehaving authenticated peer could
// otherwise pin a goroutine.
const peerReadTimeout = 10 * time.Second

// peerListenerShutdownTimeout bounds how long we wait for the HTTPS
// server to drain on shutdown.
const peerListenerShutdownTimeout = 5 * time.Second

// runPeerListener serves /ws/peer on the given listener. The caller is
// responsible for creating the listener (production: net.Listen on the
// port from SELF_ADDR; tests: net.Listen on 127.0.0.1:0). Each incoming
// connection is mTLS-verified by tlsConfig. The first message on the
// WebSocket must be a PeerHandshake carrying the pair_id; after that the
// connection is held open as a liveness signal. The first time a valid
// pair_id arrives, register is called and startHeartbeat triggers the
// heartbeat goroutine.
func runPeerListener(
	ctx context.Context,
	listener net.Listener,
	tlsConfig *tls.Config,
	state *teetRouterState,
	register func(ctx context.Context, pairID string) error,
	startHeartbeat func(),
	logger *shared.Logger,
) {
	// Wrap startHeartbeat in sync.Once so multiple peer connects (e.g. K
	// reconnects after a network blip) don't spawn duplicate heartbeat
	// goroutines. The contract — "heartbeat starts at most once" — lives
	// inside the listener so callers don't have to wire their own Once.
	var heartbeatOnce sync.Once
	startHeartbeatOnce := func() { heartbeatOnce.Do(startHeartbeat) }

	mux := http.NewServeMux()
	mux.HandleFunc("/ws/peer", func(w http.ResponseWriter, r *http.Request) {
		handlePeerConn(r.Context(), w, r, state, register, startHeartbeatOnce, logger)
	})

	srv := &http.Server{
		Handler:   mux,
		TLSConfig: tlsConfig,
		// ReadHeaderTimeout guards against a peer that completes mTLS but
		// then drips bytes; the WebSocket upgrade itself sets its own
		// deadlines once the handshake starts.
		ReadHeaderTimeout: 10 * time.Second,
		// BaseContext makes r.Context() in each handler a descendant of
		// our outer ctx, so cancelling outer ctx also cancels in-flight
		// request contexts. Without this, r.Context() is rooted at
		// context.Background() and the ctx-cancel guard in handlePeerConn
		// would never fire on shutdown.
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}

	// Force-close server on ctx cancel. http.Server.Shutdown waits for
	// in-flight requests to finish; our handler holds the WS read open
	// indefinitely, so a graceful shutdown alone would hang.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), peerListenerShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Warn("peer listener shutdown returned", zap.Error(err))
			_ = srv.Close()
		}
	}()

	logger.Info("peer listener starting", zap.String("addr", listener.Addr().String()))
	// ServeTLS with empty cert/key paths uses TLSConfig.GetCertificate.
	if err := srv.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Critical("peer listener failed", zap.Error(err))
	}
}

var peerUpgrader = websocket.Upgrader{
	// Origin check is moot — mTLS at the TLS layer already authenticated
	// the peer as a TEE we trust.
	CheckOrigin: func(_ *http.Request) bool { return true },
}

func handlePeerConn(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	state *teetRouterState,
	register func(ctx context.Context, pairID string) error,
	startHeartbeat func(),
	logger *shared.Logger,
) {
	conn, err := peerUpgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Warn("peer upgrade failed", zap.Error(err))
		return
	}
	defer func() {
		state.controlHealthy.Store(false)
		_ = conn.Close()
	}()

	// First envelope must be the pair_id assignment. Bounded read deadline
	// so a stalled peer can't hold the goroutine forever.
	_ = conn.SetReadDeadline(time.Now().Add(peerReadTimeout))
	pairID, err := readPairAssignment(conn)
	if err != nil {
		logger.Warn("peer pair-assignment read failed", zap.Error(err))
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	if _, err := uuid.Parse(pairID); err != nil {
		logger.Warn("peer pair_id invalid", zap.String("pair_id", pairID), zap.Error(err))
		return
	}

	// First connection with a new pair_id (or first connection ever)
	// triggers registration. Re-connections with the same pair_id reuse
	// the existing record — register is still idempotent at the router,
	// so calling each time is safe; we skip only to avoid noise.
	if prev := state.pairID.Load(); prev == nil || *prev != pairID {
		if err := register(ctx, pairID); err != nil {
			logger.Error("register with received pair_id failed",
				zap.String("pair_id", pairID), zap.Error(err))
			return
		}
		state.pairID.Store(&pairID)
	}
	startHeartbeat()

	state.controlHealthy.Store(true)
	logger.Info("peer connected, pair_id received",
		zap.String("pair_id", pairID),
		zap.String("peer", r.RemoteAddr))

	// Hold connection open via ping/pong heartbeat from shared.WSConnection,
	// same pattern as TEE_K's client side.
	wsConn := shared.NewWSConnection(conn)
	wsConn.StartControlHeartbeat(logger)

	// ctx cancellation must unblock the read loop. ReadMessage doesn't
	// honor context, so guard-and-close on ctx.Done.
	closed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-closed:
		}
	}()
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			logger.Info("peer connection closed", zap.Error(err))
			break
		}
	}
	close(closed)
}

// readPairAssignment reads one envelope off the connection and returns the
// pair_id from a TEEKPairAssignment payload. Anything else — wrong payload
// type, malformed envelope, non-binary frame — is an error.
func readPairAssignment(conn *websocket.Conn) (string, error) {
	mt, data, err := conn.ReadMessage()
	if err != nil {
		return "", fmt.Errorf("read message: %w", err)
	}
	if mt != websocket.BinaryMessage {
		return "", fmt.Errorf("unexpected message type %d (want BinaryMessage)", mt)
	}
	var env teeproto.Envelope
	if err := proto.Unmarshal(data, &env); err != nil {
		return "", fmt.Errorf("unmarshal envelope: %w", err)
	}
	assignment, ok := env.Payload.(*teeproto.Envelope_TeekPairAssignment)
	if !ok {
		return "", fmt.Errorf("unexpected first payload %T (want TeekPairAssignment)", env.Payload)
	}
	return assignment.TeekPairAssignment.GetPairId(), nil
}
