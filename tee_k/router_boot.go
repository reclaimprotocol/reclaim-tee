package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ratlsRefreshInterval is how often we rotate the RA-TLS certificate's
// attestation. GCP Confidential Space tokens have a TTL of ~5 minutes, so
// 4 minutes matches the existing attestation-refresh cadence used by the
// legacy Lego/ACME path and leaves a comfortable margin.
const ratlsRefreshInterval = 4 * time.Minute

// heartbeatInterval is the cadence at which TEE_K reports liveness +
// health observations to the router. Matches the router's expected window
// (3 missed = ~15s = "dead").
const heartbeatInterval = 5 * time.Second

// heartbeatState holds the slowly-changing per-TEE state we report to the
// router. Each field is owned by a different subsystem — peer reconnect
// flips controlHealthy, OT precompute completion flips otReady, the
// session manager updates activeSessions — and read concurrently by the
// heartbeat goroutine. Atomics for lock-free access from any goroutine.
//
// In this PR all writers are still missing; everything stays false/0 until
// PR 3.2c (peer connection) and PR 3.2d (session JWT validation) land.
type heartbeatState struct {
	controlHealthy atomic.Bool
	otReady        atomic.Bool
	activeSessions atomic.Int32
}

// startRouterMode is the boot path used when ROUTER_URL is set. It brings
// up an RA-TLS-backed identity for the TEE, registers with the router,
// starts the heartbeat goroutine, dials the peer over RA-TLS, and blocks
// on a shutdown signal.
//
// Still missing vs. full Phase 3: client-websocket JWT validation
// (lands in 3.2d) and OT-precompute / session-protocol on top of the
// peer connection (also 3.2d). Old TEE_K logic in connection_manager.go,
// websocket.go, attestation.go is intentionally left untouched — the
// legacy enclave path uses it, the router path doesn't.
func startRouterMode(parent context.Context, config *TEEKConfig, logger *shared.Logger) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	logger.Info("=== TEE_K Router Mode ===",
		zap.String("router_url", config.RouterURL),
		zap.String("self_addr", config.SelfAddr),
		zap.String("peer_addr", config.PeerAddr))

	if err := validateRouterConfig(config); err != nil {
		logger.Critical("router-mode config invalid", zap.Error(err))
		return
	}

	pairID := uuid.NewString()
	logger.Info("Generated pair ID", zap.String("pair_id", pairID))

	ratls, err := shared.NewRATLSManager(ctx, "tee_k", nil)
	if err != nil {
		logger.Critical("RA-TLS manager init failed", zap.Error(err))
		return
	}
	logger.Info("RA-TLS manager initialized",
		zap.String("spki_hash", fmt.Sprintf("%x", ratls.SPKIHash())))

	router := shared.NewRouterClient(config.RouterURL, shared.MetadataServerTokenSource)

	// register pulls a fresh attestation off the current RA-TLS cert each
	// time, so the same closure also serves as the re-register path triggered
	// by a 404 from /heartbeat (e.g. after a router restart in single-replica
	// mode wiped in-memory state).
	register := func(ctx context.Context) error {
		imageDigest, attestationJWT, err := extractIdentityFromRATLS(ratls, logger)
		if err != nil {
			return fmt.Errorf("extract identity: %w", err)
		}
		resp, err := router.Register(ctx, shared.RegisterRequest{
			PairID:         pairID,
			Role:           "K",
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

	if err := register(ctx); err != nil {
		logger.Critical("router registration failed", zap.Error(err))
		return
	}

	// Background RA-TLS refresh keeps the embedded attestation fresh so
	// later TLS handshakes verifying via VerifyRATLSPeer don't trip on the
	// JWT's exp claim.
	go runRATLSRefresh(ctx, ratls, logger)

	// Heartbeat goroutine reports liveness + observation state to router.
	// State writes happen via the existing connection-manager flow once it
	// gets wired into router mode in the next step.
	state := &heartbeatState{}
	go runHeartbeats(ctx, router, state, pairID, "K", logger, register, heartbeatInterval)

	// Peer connection wiring lands in the next step — the existing
	// tee_k/connection_manager.go gets adapted to dial PEER_ADDR over
	// RA-TLS and to send TEEKPairAssignment as its first envelope. For
	// now, router-mode TEE_K registers + heartbeats but does not connect
	// to its peer.

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	logger.Info("TEE_K router-mode bootstrap complete",
		zap.String("pair_id", pairID))
	<-sigChan
	logger.Info("shutting down router-mode TEE_K")
}

// runHeartbeats fires a heartbeat to the router every `interval` until
// ctx is cancelled. On ErrRouterNotFound (router lost our pair_id, e.g.
// after a restart in single-replica mode), it calls onLost to re-register;
// other errors are logged but don't abort the loop.
func runHeartbeats(
	ctx context.Context,
	router *shared.RouterClient,
	state *heartbeatState,
	pairID, role string,
	logger *shared.Logger,
	onLost func(context.Context) error,
	interval time.Duration,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			req := shared.HeartbeatRequest{
				PairID:         pairID,
				Role:           role,
				ControlHealthy: state.controlHealthy.Load(),
				OTReady:        state.otReady.Load(),
				ActiveSessions: int(state.activeSessions.Load()),
			}
			_, err := router.Heartbeat(ctx, req)
			switch {
			case err == nil:
				// happy path
			case errors.Is(err, shared.ErrRouterNotFound):
				logger.Warn("router lost pair_id, re-registering",
					zap.String("pair_id", pairID))
				if regErr := onLost(ctx); regErr != nil {
					logger.Error("re-register failed", zap.Error(regErr))
				}
			default:
				logger.Error("heartbeat failed", zap.Error(err))
			}
		}
	}
}

// validateRouterConfig surfaces missing router-mode env vars at boot rather
// than failing mysteriously deep in router/register or RA-TLS code.
func validateRouterConfig(c *TEEKConfig) error {
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

// extractIdentityFromRATLS reads the in-flight RA-TLS cert and pulls the
// attestation JWT + container image digest out of it. The same JWT goes
// into the router registration body; the digest is the router's
// allowlist key.
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
