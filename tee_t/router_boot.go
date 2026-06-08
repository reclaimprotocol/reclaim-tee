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

	"go.uber.org/zap"
)

// ratlsRefreshInterval matches TEE_K's cadence. GCP Confidential Space
// tokens expire in ~5 minutes; refreshing every 4 keeps new handshakes
// validating cleanly.
const ratlsRefreshInterval = 4 * time.Minute

// heartbeatInterval matches the router's 3-missed-in-15s tolerance.
const heartbeatInterval = 5 * time.Second

// startRouterMode is TEE_T's V2 boot path. TEE_T cannot register at boot —
// it doesn't know the pair_id yet — so it brings up the RA-TLS HTTPS
// server, sets an onPairAssigned hook that will register + start the
// heartbeat the moment TEE_K's first envelope arrives, and waits.
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

	teet := NewTEETForRouter(config.Port, ratls, router, logger)
	if config.JWTPublicKey != "" {
		pubKey, err := shared.ParseECDSAPublicKeyPEM([]byte(config.JWTPublicKey))
		if err != nil {
			logger.Critical("parse JWT_PUBLIC_KEY failed", zap.Error(err))
			return
		}
		teet.jwtPubKey = pubKey
	}
	teet.sessionManager.StartCleanupRoutine()

	register := func(ctx context.Context, pairID string) error {
		imageDigest, attestationJWT, err := extractIdentityFromRATLS(teet.ratls, logger)
		if err != nil {
			return fmt.Errorf("extract identity: %w", err)
		}
		resp, err := teet.router.Register(ctx, shared.RegisterRequest{
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

	// The pair_id arrives on the wire from TEE_K, not the env. When it does,
	// register + spin up the heartbeat. Wrap in sync.Once via a guard so a
	// reconnect doesn't trigger a duplicate goroutine — the pair_id never
	// changes for the life of this process.
	heartbeatStarted := false
	teet.onPairAssigned = func(pairID string) {
		if heartbeatStarted {
			return
		}
		heartbeatStarted = true
		if err := register(ctx, pairID); err != nil {
			logger.Critical("router registration failed", zap.Error(err))
			return
		}
		go runHeartbeats(ctx, teet, "T", logger, register, heartbeatInterval)
	}

	go runRATLSRefresh(ctx, teet.ratls, logger)

	// Build the RA-TLS-protected HTTPS server: same routes as standalone,
	// but the TLS layer enforces mTLS with attestation-verified peer.
	srvTLS := ratls.ServerTLSConfig()
	srvTLS.ClientAuth = tls.RequireAnyClientCert
	srvTLS.VerifyPeerCertificate = shared.VerifyRATLSPeer(shared.RATLSVerifyOptions{
		PeerRole:            "tee_k",
		ExpectedImageDigest: config.ExpectedPeerImageDigest,
		Logger:              logger,
	})

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.Port),
		Handler:      setupRoutes(teet),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		TLSConfig:    srvTLS,
	}

	logger.Info("Starting router-mode HTTPS server", zap.Int("port", config.Port))
	go func() {
		// Cert + key are sourced from TLSConfig.GetCertificate, so
		// ListenAndServeTLS is called with empty cert/key paths.
		if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Critical("HTTPS server failed", zap.Error(err))
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	logger.Info("TEE_T router-mode bootstrap complete; awaiting peer")
	<-sigChan
	logger.Info("shutting down router-mode TEE_T")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTPS server shutdown error", zap.Error(err))
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

// extractIdentityFromRATLS reads the in-flight RA-TLS cert and pulls the
// attestation JWT + container image digest out of it. Same shape as the
// TEE_K helper; kept package-local so each binary stays self-contained.
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

// runHeartbeats fires a heartbeat to the router every `interval` until
// ctx is cancelled. Mirrors TEE_K's version but reads pair_id off the
// atomic.Pointer since TEE_T learns it from the wire.
func runHeartbeats(
	ctx context.Context,
	teet *TEET,
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
			pidPtr := teet.pairID.Load()
			if pidPtr == nil {
				continue
			}
			pid := *pidPtr
			req := shared.HeartbeatRequest{
				PairID:         pid,
				Role:           role,
				ControlHealthy: teet.controlHealthy.Load(),
				OTReady:        teet.otReady.Load(),
				ActiveSessions: int(teet.activeSessions.Load()),
			}
			_, err := teet.router.Heartbeat(ctx, req)
			switch {
			case err == nil:
				// happy path
			case errors.Is(err, shared.ErrRouterNotFound):
				logger.Warn("router lost pair_id, re-registering",
					zap.String("pair_id", pid))
				if regErr := onLost(ctx, pid); regErr != nil {
					logger.Error("re-register failed", zap.Error(regErr))
				}
			default:
				logger.Error("heartbeat failed", zap.Error(err))
			}
		}
	}
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
