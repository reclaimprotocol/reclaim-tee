package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// peerDialBackoffInitial / Max bound the reconnect-retry interval when
// PEER_ADDR is unreachable. Values picked to ride out brief network blips
// without hammering the network on long outages.
const (
	peerDialBackoffInitial = 1 * time.Second
	peerDialBackoffMax     = 30 * time.Second
	peerHandshakeTimeout   = 10 * time.Second
)

// peerVerifier is the signature crypto/tls expects for VerifyPeerCertificate.
// shared.VerifyRATLSPeer returns one; tests inject simpler stubs.
type peerVerifier func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

// buildPeerTLSConfig assembles the TLS config the TEE_K uses when dialing
// TEE_T over RA-TLS. Default CA-chain verification is disabled
// (InsecureSkipVerify=true) so the custom VerifyPeerCertificate is the
// only path that runs — and that path enforces the GCP attestation +
// SPKI-hash binding instead of public-CA trust.
//
// ratls supplies our own cert+key so the peer can mTLS-verify us by the
// same machinery; Refresh()es are picked up automatically via the
// GetClientCertificate callback.
func buildPeerTLSConfig(verifier peerVerifier, ratls *shared.RATLSManager) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verifier,
		GetClientCertificate:  ratls.GetClientCertificate,
		MinVersion:            tls.VersionTLS12,
		MaxVersion:            tls.VersionTLS13,
	}
}

// runPeerConnection dials PEER_ADDR, sends pair_id as the first message,
// and keeps the connection alive as a liveness signal. controlHealthy flips
// on connect/disconnect. On any failure (dial, handshake, send, read), it
// backs off exponentially capped at peerDialBackoffMax and reconnects until
// the context is cancelled. pair_id is re-sent on every reconnect so TEE_T
// always knows the current value.
//
// OT precompute and session-protocol messages on top of this connection
// come in subsequent PRs.
func runPeerConnection(
	ctx context.Context,
	peerAddr string,
	pairID string,
	tlsConfig *tls.Config,
	state *heartbeatState,
	logger *shared.Logger,
) {
	defer state.controlHealthy.Store(false)

	wsURL := &url.URL{
		Scheme: "wss",
		Host:   peerAddr,
		Path:   "/ws/peer",
	}
	dialer := &websocket.Dialer{
		TLSClientConfig:  tlsConfig,
		HandshakeTimeout: peerHandshakeTimeout,
	}

	backoff := peerDialBackoffInitial
	for {
		if ctx.Err() != nil {
			return
		}

		conn, _, err := dialer.DialContext(ctx, wsURL.String(), nil)
		if err != nil {
			logger.Warn("peer dial failed", zap.String("peer", peerAddr), zap.Error(err))
			if sleepCtx(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, peerDialBackoffMax)
			continue
		}
		backoff = peerDialBackoffInitial

		// First envelope on a fresh peer connection is always the pair_id
		// assignment. TEE_T uses this to register with the router under the
		// same pair_id we already registered with.
		if err := sendPairAssignment(conn, pairID); err != nil {
			logger.Warn("peer pair_id send failed", zap.Error(err))
			_ = conn.Close()
			if sleepCtx(ctx, peerDialBackoffInitial) {
				return
			}
			continue
		}

		state.controlHealthy.Store(true)
		logger.Info("peer connected", zap.String("peer", peerAddr))

		wsConn := shared.NewWSConnection(conn)
		wsConn.StartControlHeartbeat(logger)

		// conn.ReadMessage doesn't honor context cancellation, so a
		// straight `<-ctx.Done()` would never unblock the read loop on
		// shutdown. Spawn a guard that force-closes the connection when
		// ctx fires; the read loop then exits with an error like any
		// other peer-initiated close.
		closed := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				_ = conn.Close()
			case <-closed:
			}
		}()

		// Hold the connection open by reading. Any error (peer close, TCP
		// reset, read deadline exceeded by missed ping/pong, our own close
		// on ctx cancel) ends the loop and triggers reconnect.
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				logger.Info("peer connection closed", zap.Error(err))
				break
			}
		}
		close(closed)
		state.controlHealthy.Store(false)
		_ = conn.Close()

		// Brief pause before reconnecting so a peer that immediately closes
		// on accept doesn't pin us in a busy loop.
		if sleepCtx(ctx, peerDialBackoffInitial) {
			return
		}
	}
}

// sleepCtx sleeps for d or until ctx is done, whichever is first.
// Returns true if ctx was cancelled (caller should bail).
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-t.C:
		return false
	}
}

// sendPairAssignment writes a single TEEKPairAssignment envelope as a
// binary WebSocket frame. Same wire format as every other TEE↔TEE
// message — proto.Marshal'd Envelope with a oneof payload.
func sendPairAssignment(conn *websocket.Conn, pairID string) error {
	env := &teeproto.Envelope{
		Sender:      teeproto.Sender_SENDER_TEE_K,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_TeekPairAssignment{
			TeekPairAssignment: &teeproto.TEEKPairAssignment{PairId: pairID},
		},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal pair assignment: %w", err)
	}
	return conn.WriteMessage(websocket.BinaryMessage, data)
}
