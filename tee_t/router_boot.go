package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// ratlsRefreshInterval matches TEE_K's cadence. GCP Confidential Space
// tokens expire in ~5 minutes; refreshing every 4 keeps new handshakes
// validating cleanly.
const ratlsRefreshInterval = 4 * time.Minute

// heartbeatInterval matches the router's 3-missed-in-15s tolerance.
const heartbeatInterval = 5 * time.Second

// teetRouterState bundles the observation state we report to the router
// plus the pair_id we received from TEE_K. pair_id is set on first peer
// connection; before that, heartbeat doesn't run.
type teetRouterState struct {
	controlHealthy atomic.Bool
	otReady        atomic.Bool
	activeSessions atomic.Int32

	// pairID is the UUID TEE_K generated at boot and sent over the peer
	// connection. nil before TEE_K connects; pointer is swapped atomically
	// so heartbeat reads aren't torn.
	pairID atomic.Pointer[string]
}

// startRouterMode is TEE_T's boot path when ROUTER_URL is set. Unlike
// TEE_K, TEE_T cannot register at boot — it doesn't know the pair_id
// yet. Registration happens when TEE_K connects to the peer-listener
// and sends the pair_id as the first message.
func startRouterMode(parent context.Context, config *TEETConfig, logger *shared.Logger) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	logger.Info("=== TEE_T Router Mode ===",
		zap.String("router_url", config.RouterURL),
		zap.String("self_addr", config.SelfAddr),
		zap.String("peer_addr", config.PeerAddr))

	if err := validateRouterConfig(config); err != nil {
		logger.Critical("router-mode config invalid", zap.Error(err))
		return
	}

	ratls, err := shared.NewRATLSManager(ctx, "tee_t", nil)
	if err != nil {
		logger.Critical("RA-TLS manager init failed", zap.Error(err))
		return
	}
	logger.Info("RA-TLS manager initialized",
		zap.String("spki_hash", fmt.Sprintf("%x", ratls.SPKIHash())))

	router := shared.NewRouterClient(config.RouterURL, shared.MetadataServerTokenSource)
	state := &teetRouterState{}

	register := func(ctx context.Context, pairID string) error {
		imageDigest, attestationJWT, err := extractIdentityFromRATLS(ratls, logger)
		if err != nil {
			return fmt.Errorf("extract identity: %w", err)
		}
		resp, err := router.Register(ctx, shared.RegisterRequest{
			PairID:         pairID,
			Role:           "T",
			SelfAddr:       config.SelfAddr,
			PeerAddrClaim:  config.PeerAddr,
			ImageDigest:    imageDigest,
			AttestationJWT: string(attestationJWT),
		})
		if err != nil {
			return err
		}
		logger.Info("registered with router",
			zap.String("pair_id", resp.PairID),
			zap.String("status", resp.Status))
		return nil
	}

	go runRATLSRefresh(ctx, ratls, logger)

	// Heartbeat is gated on first peer connect, since pair_id isn't known
	// until then. The listener wraps this call in sync.Once so we don't
	// spawn duplicate loops on K reconnects.
	startHeartbeat := func() {
		go runHeartbeats(ctx, router, state, "T", logger, register, heartbeatInterval)
	}

	// Build server TLS config for the peer listener — mTLS, with our own
	// cert via GetCertificate and the RA-TLS verifier on the peer side.
	serverTLS := ratls.ServerTLSConfig()
	serverTLS.ClientAuth = tls.RequireAnyClientCert
	serverTLS.VerifyPeerCertificate = shared.VerifyRATLSPeer(shared.RATLSVerifyOptions{
		PeerRole:            "tee_k",
		ExpectedImageDigest: config.ExpectedPeerImageDigest,
		Logger:              logger,
	})

	listenPort, err := portFromAddr(config.SelfAddr)
	if err != nil {
		logger.Critical("invalid SELF_ADDR", zap.Error(err))
		return
	}
	listener, err := net.Listen("tcp", ":"+listenPort)
	if err != nil {
		logger.Critical("peer-listener bind failed",
			zap.String("port", listenPort), zap.Error(err))
		return
	}

	go runPeerListener(ctx, listener, serverTLS, state, register, startHeartbeat, logger)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	logger.Info("TEE_T router-mode bootstrap complete; awaiting peer connection")
	<-sigChan
	logger.Info("shutting down router-mode TEE_T")
}

// runHeartbeats is TEE_T's heartbeat loop. Identical in shape to TEE_K's
// but reads pair_id from the atomic-pointer that the peer listener
// populates on first connect, so the loop can be started before the
// pair_id is known (it just won't send anything until pairID is set).
func runHeartbeats(
	ctx context.Context,
	router *shared.RouterClient,
	state *teetRouterState,
	role string,
	logger *shared.Logger,
	onLost func(context.Context, string) error,
	interval time.Duration,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pidPtr := state.pairID.Load()
			if pidPtr == nil {
				// Pair_id not yet received from peer; nothing to report.
				continue
			}
			pid := *pidPtr
			_, err := router.Heartbeat(ctx, shared.HeartbeatRequest{
				PairID:         pid,
				Role:           role,
				ControlHealthy: state.controlHealthy.Load(),
				OTReady:        state.otReady.Load(),
				ActiveSessions: int(state.activeSessions.Load()),
			})
			switch {
			case err == nil:
				// happy path
			case errors.Is(err, shared.ErrRouterNotFound):
				logger.Warn("router lost pair_id, re-registering", zap.String("pair_id", pid))
				if regErr := onLost(ctx, pid); regErr != nil {
					logger.Error("re-register failed", zap.Error(regErr))
				}
			default:
				logger.Error("heartbeat failed", zap.Error(err))
			}
		}
	}
}

func validateRouterConfig(c *TEETConfig) error {
	switch {
	case c.SelfAddr == "":
		return errors.New("SELF_ADDR is required in router mode")
	case c.PeerAddr == "":
		return errors.New("PEER_ADDR is required in router mode")
	case c.ExpectedPeerImageDigest == "":
		return errors.New("EXPECTED_PEER_IMAGE_DIGEST is required in router mode")
	case c.JWTPublicKey == "":
		return errors.New("JWT_PUBLIC_KEY is required in router mode")
	}
	return nil
}

func extractIdentityFromRATLS(ratls *shared.RATLSManager, logger *shared.Logger) (string, []byte, error) {
	cert := ratls.Certificate()
	if cert == nil || cert.Leaf == nil {
		return "", nil, errors.New("RA-TLS manager has no current cert")
	}
	attestationJWT, err := shared.ExtractAttestationFromCert(cert.Leaf)
	if err != nil {
		return "", nil, fmt.Errorf("extract attestation: %w", err)
	}
	digest, err := shared.ExtractImageDigestFromGCPAttestation(attestationJWT, logger)
	if err != nil {
		return "", nil, fmt.Errorf("extract image digest: %w", err)
	}
	return digest, attestationJWT, nil
}

func runRATLSRefresh(ctx context.Context, ratls *shared.RATLSManager, logger *shared.Logger) {
	ticker := time.NewTicker(ratlsRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ratls.Refresh(ctx); err != nil {
				logger.Error("RA-TLS refresh failed", zap.Error(err))
				continue
			}
			logger.Debug("RA-TLS refreshed")
		}
	}
}

// portFromAddr extracts the port from a host:port string. Used to pick the
// listen port from SELF_ADDR — we listen on all interfaces, just the port
// has to match what we told the router we're reachable at.
func portFromAddr(addr string) (string, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("split host:port from %q: %w", addr, err)
	}
	return port, nil
}
