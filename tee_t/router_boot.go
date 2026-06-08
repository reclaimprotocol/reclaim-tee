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

	teet := NewTEETForRouter(config, ratls, router, logger)
	if config.JWTPublicKey != "" {
		pubKey, err := shared.ParseECDSAPublicKeyPEM([]byte(config.JWTPublicKey))
		if err != nil {
			logger.Critical("parse JWT_PUBLIC_KEY failed", zap.Error(err))
			return
		}
		teet.jwtPubKey = pubKey
		teet.expectedJWTIssuer = config.ExpectedJWTIssuer
	}
	teet.sessionManager.StartCleanupRoutine()

	register := func(ctx context.Context) error {
		pid := teet.PairID()
		if pid == "" {
			return errors.New("register: pair_id not yet known")
		}
		imageDigest, attestationJWT, err := shared.ExtractIdentityFromRATLS(teet.ratls, logger)
		if err != nil {
			return fmt.Errorf("extract identity: %w", err)
		}
		resp, err := teet.router.Register(ctx, shared.RegisterRequest{
			PairID:         pid,
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
	// register + spin up the heartbeat. Guarded so a peer reconnect doesn't
	// trigger a duplicate goroutine — the pair_id never changes for the life
	// of this process.
	heartbeatStarted := false
	teet.onPairAssigned = func(pairID string) {
		if heartbeatStarted {
			return
		}
		heartbeatStarted = true
		if err := register(ctx); err != nil {
			logger.Critical("router registration failed", zap.Error(err))
			return
		}
		go shared.RunHeartbeats(ctx, teet, "T", logger, register, shared.RouterHeartbeatInterval)
	}

	go shared.RunRATLSRefresh(ctx, teet.ratls, logger)

	// Single RA-TLS-protected HTTPS server serving both peers and clients:
	//   - TEE_K peer dials /ws/control + /ws/session, presents its RA-TLS
	//     client cert; VerifyPeerCertificate validates it against the
	//     expected tee_k image_digest.
	//   - Clients dial /ws, present no client cert; JWT auth on first
	//     envelope (see tee_t/websocket_handlers.go).
	// ClientAuth=RequestClientCert lets both flows complete the TLS
	// handshake; enforcePeerMTLS gates the peer routes on a verified cert
	// at the HTTP layer.
	srvTLS := ratls.ServerTLSConfig()
	srvTLS.ClientAuth = tls.RequestClientCert
	srvTLS.VerifyPeerCertificate = shared.VerifyRATLSPeer(shared.RATLSVerifyOptions{
		PeerRole:            "tee_k",
		ExpectedImageDigest: teet.expectedPeerImageDigest,
		Logger:              logger,
	})

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.Port),
		Handler:      enforcePeerMTLS(setupRoutes(teet)),
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

// enforcePeerMTLS gates the peer routes (/ws/control, /ws/session) on a
// verified RA-TLS client certificate. The router-mode TLS config uses
// RequestClientCert (not Require) so client connections to /ws can
// complete the handshake without a cert; this middleware adds the
// route-specific assertion at the HTTP layer.
//
// A non-empty r.TLS.PeerCertificates here means the cert ALSO passed
// tls.Config.VerifyPeerCertificate (image_digest + SPKI binding). An
// empty PeerCertificates means no cert was sent — those requests must
// not reach the peer routes.
func enforcePeerMTLS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ws/control", "/ws/session":
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "peer certificate required", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func validateRouterConfig(c *TEETConfig) error {
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
