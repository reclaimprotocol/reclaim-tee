package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

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
		imageDigest, attestationJWT, err := shared.ExtractIdentityFromRATLS(teek.ratls, logger)
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

	go shared.RunRATLSRefresh(ctx, teek.ratls, logger)
	go shared.RunHeartbeats(ctx, teek, "K", logger, register, shared.RouterHeartbeatInterval)

	// Bring up the existing control connection (and OT precomputation) against
	// PEER_ADDR. The connection manager picks up router mode via teek.ratls
	// (RA-TLS dialer + mTLS) and teek.pairID (sends TEEKPairAssignment first).
	go teek.establishSharedTEETConnection()

	// Client-facing HTTPS server: serves /ws (client) over RA-TLS with no
	// client cert required. Clients authenticate via ClientAuth (JWT) as
	// their first envelope — see tee_k/websocket.go.
	srvTLS := teek.ratls.ServerTLSConfig()
	srvTLS.ClientAuth = tls.NoClientCert
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.Port),
		Handler:      setupRoutes(teek),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		TLSConfig:    srvTLS,
	}
	logger.Info("Starting router-mode HTTPS server", zap.Int("port", config.Port))
	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Critical("HTTPS server failed", zap.Error(err))
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	logger.Info("TEE_K router-mode bootstrap complete",
		zap.String("pair_id", teek.pairID))
	<-sigChan
	logger.Info("shutting down router-mode TEE_K")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTPS server shutdown error", zap.Error(err))
	}
}

// validateRouterConfig surfaces missing router-mode env vars at boot
// rather than failing mysteriously inside RA-TLS, router-client, or
// OPRF-storage code. Order matters for the error message: we report the
// first unset var encountered.
func validateRouterConfig(c *TEEKConfig) error {
	required := []struct {
		name, value string
	}{
		{"SELF_ADDR", c.SelfAddr},
		{"PEER_ADDR", c.PeerAddr},
		{"EXPECTED_PEER_IMAGE_DIGEST", c.ExpectedPeerImageDigest},
		{"JWT_PUBLIC_KEY", c.JWTPublicKey},
		{"EXPECTED_JWT_ISSUER", c.ExpectedJWTIssuer},
		{"KMS_ENCLAVE_DOMAIN_KEY", c.KMSEnclaveDomainKey},
	}
	for _, r := range required {
		if r.value == "" {
			return fmt.Errorf("%s is required in router mode", r.name)
		}
	}
	return nil
}
