package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ratlsRefreshInterval is how often we rotate the RA-TLS certificate's
// attestation. GCP Confidential Space tokens have a TTL of ~5 minutes;
// 4 minutes matches the existing attestation-refresh cadence and leaves
// a comfortable margin.
const ratlsRefreshInterval = 4 * time.Minute

// heartbeatInterval is the cadence at which TEE_K reports liveness +
// observation state to the router. Matches the router's expected window
// (3 missed = ~15s = "dead").
const heartbeatInterval = 5 * time.Second

// startRouterMode is TEE_K's V2 boot path, used when ROUTER_URL is set.
// It brings up an RA-TLS identity, registers with the router, kicks off
// the existing control-connection flow against PEER_ADDR, and runs the
// heartbeat goroutine.
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

	teek := NewTEEKForRouter(config, ratls, router, pairID)
	teek.sessionManager.StartCleanupRoutine()

	register := func(ctx context.Context) error {
		imageDigest, attestationJWT, err := extractIdentityFromRATLS(teek.ratls, logger)
		if err != nil {
			return fmt.Errorf("extract identity: %w", err)
		}
		resp, err := teek.router.Register(ctx, shared.RegisterRequest{
			PairID:         teek.pairID,
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

	go runRATLSRefresh(ctx, teek.ratls, logger)
	go runHeartbeats(ctx, teek, "K", logger, register, heartbeatInterval)

	// Bring up the existing control connection (and OT precomputation) against
	// PEER_ADDR. The connection manager picks up router mode via teek.ratls
	// (RA-TLS dialer + mTLS) and teek.pairID (sends TEEKPairAssignment first).
	go teek.establishSharedTEETConnection()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	logger.Info("TEE_K router-mode bootstrap complete",
		zap.String("pair_id", teek.pairID))
	<-sigChan
	logger.Info("shutting down router-mode TEE_K")
}

// runHeartbeats fires a heartbeat to the router every `interval` until
// ctx is cancelled. On ErrRouterNotFound (router lost our pair_id, e.g.
// after a restart in single-replica mode), it calls onLost to re-register;
// other errors are logged but don't abort the loop.
func runHeartbeats(
	ctx context.Context,
	teek *TEEK,
	role string,
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
				PairID:         teek.pairID,
				Role:           role,
				ControlHealthy: teek.controlHealthy.Load(),
				OTReady:        teek.otReady.Load(),
				ActiveSessions: int(teek.activeSessions.Load()),
			}
			_, err := teek.router.Heartbeat(ctx, req)
			switch {
			case err == nil:
				// happy path
			case errors.Is(err, shared.ErrRouterNotFound):
				logger.Warn("router lost pair_id, re-registering",
					zap.String("pair_id", teek.pairID))
				if regErr := onLost(ctx); regErr != nil {
					logger.Error("re-register failed", zap.Error(regErr))
				}
			default:
				logger.Error("heartbeat failed", zap.Error(err))
			}
		}
	}
}

// validateRouterConfig surfaces missing router-mode env vars at boot
// rather than failing mysteriously inside RA-TLS or router-client code.
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
