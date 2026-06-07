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

	"go.uber.org/zap"
)

// ratlsRefreshInterval matches TEE_K's cadence. GCP Confidential Space
// tokens expire in ~5 minutes; refreshing every 4 keeps new handshakes
// validating cleanly.
const ratlsRefreshInterval = 4 * time.Minute

// heartbeatInterval matches the router's 3-missed-in-15s tolerance.
const heartbeatInterval = 5 * time.Second

// teetRouterState bundles the observation state we report to the router
// plus the pair_id we received from TEE_K via the control-connection
// handshake. pair_id is set when TEE_K's first envelope arrives; before
// that, heartbeat doesn't fire.
type teetRouterState struct {
	controlHealthy atomic.Bool
	otReady        atomic.Bool
	activeSessions atomic.Int32

	pairID atomic.Pointer[string]
}

// startRouterMode is TEE_T's V2 boot path. Unlike TEE_K, TEE_T cannot
// register at boot — it doesn't know the pair_id yet. Registration is
// triggered by TEE_K's TEEKPairAssignment envelope once
// connection_manager.go is adapted for router mode in the next step.
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

	go runRATLSRefresh(ctx, ratls, logger)

	// Peer-server + register/heartbeat wiring lands in the next step.
	// The existing tee_t/connection_manager.go gets adapted to read
	// TEEKPairAssignment as its first envelope, call back to register
	// with the router using the received pair_id, and trigger the
	// heartbeat goroutine.

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	logger.Info("TEE_T router-mode bootstrap complete; awaiting peer + protocol wiring")
	<-sigChan
	logger.Info("shutting down router-mode TEE_T")
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
