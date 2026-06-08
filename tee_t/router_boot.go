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
// it doesn't know the pair_id yet — so it brings up the server, sets an
// onPairAssigned hook that registers + starts the heartbeat the moment
// TEE_K's first envelope arrives, and waits.
//
// In production (running inside GCP Confidential Space, detected via
// launcher socket) the server is HTTPS over RA-TLS + mTLS for peer
// connections. In local dev the server is plain HTTP; JWT validation
// and pair-assignment exchange still happen.
func startRouterMode(parent context.Context, config *TEETConfig, logger *shared.Logger) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	devMode := !shared.IsEnclaveMode()
	logger.Info("=== TEE_T Router Mode ===",
		zap.String("router_url", config.RouterURL),
		zap.String("self_addr", config.SelfAddr),
		zap.String("peer_addr", config.PeerAddr),
		zap.Bool("local_dev", devMode))
	if devMode {
		logger.Warn("LOCAL-DEV MODE: launcher socket absent, attestation checks relaxed — do not run in production")
	}

	if err := validateRouterConfig(config); err != nil {
		logger.Critical("router-mode config invalid", zap.Error(err))
		return
	}

	var ratls *shared.RATLSManager
	if !devMode {
		var err error
		ratls, err = shared.NewRATLSManager(ctx, "tee_t", nil)
		if err != nil {
			logger.Critical("RA-TLS manager init failed", zap.Error(err))
			return
		}
		logger.Info("RA-TLS manager initialized",
			zap.String("spki_hash", fmt.Sprintf("%x", ratls.SPKIHash())))
	}

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
		var imageDigest string
		var attestationJWT []byte
		if teet.ratls != nil {
			var err error
			imageDigest, attestationJWT, err = shared.ExtractIdentityFromRATLS(teet.ratls, logger)
			if err != nil {
				return fmt.Errorf("extract identity: %w", err)
			}
		} else {
			imageDigest = "local-dev"
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

	if teet.ratls != nil {
		go shared.RunRATLSRefresh(ctx, teet.ratls, logger)
	}

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.Port),
		Handler:      enforcePeerMTLS(setupRoutes(teet)),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	serveErrCh := make(chan error, 1)
	if teet.ratls != nil {
		// Production: RA-TLS-protected HTTPS, RequestClientCert so peers
		// can present an attested client cert (gated on the peer routes
		// by enforcePeerMTLS) while anonymous clients hit /ws.
		srvTLS := ratls.ServerTLSConfig()
		srvTLS.ClientAuth = tls.RequestClientCert
		srvTLS.VerifyPeerCertificate = shared.VerifyRATLSPeer(shared.RATLSVerifyOptions{
			PeerRole:            "tee_k",
			ExpectedImageDigest: teet.expectedPeerImageDigest,
			Logger:              logger,
		})
		server.TLSConfig = srvTLS
		logger.Info("Starting router-mode HTTPS server", zap.Int("port", config.Port))
		go func() { serveErrCh <- server.ListenAndServeTLS("", "") }()
	} else {
		// Local dev: plain HTTP, no peer mTLS at all. enforcePeerMTLS
		// rejects /ws/control + /ws/session calls — but local TEE_K
		// dials over plain ws:// without a client cert in this mode, so
		// we have to skip the peer-mTLS check here too.
		server.Handler = setupRoutes(teet)
		logger.Info("Starting router-mode HTTP server (local dev, no RA-TLS)", zap.Int("port", config.Port))
		go func() { serveErrCh <- server.ListenAndServe() }()
	}
	go func() {
		if err := <-serveErrCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Critical("HTTP server failed", zap.Error(err))
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
		logger.Error("HTTP server shutdown error", zap.Error(err))
	}
}

// enforcePeerMTLS gates the peer routes (/ws/control, /ws/session) on a
// verified RA-TLS client certificate. Only used in production (HTTPS
// mode) — local dev wires setupRoutes(teet) directly without this
// middleware because there is no client cert to check.
//
// A non-empty r.TLS.PeerCertificates here means the cert ALSO passed
// tls.Config.VerifyPeerCertificate (image_digest + SPKI binding).
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
		{"JWT_PUBLIC_KEY", c.JWTPublicKey},
		{"EXPECTED_JWT_ISSUER", c.ExpectedJWTIssuer},
	}
	if shared.IsEnclaveMode() {
		required = append(required,
			struct{ name, value string }{"EXPECTED_PEER_IMAGE_DIGEST", c.ExpectedPeerImageDigest},
			struct{ name, value string }{"KMS_ENCLAVE_DOMAIN_KEY", c.KMSEnclaveDomainKey},
		)
	}
	for _, r := range required {
		if r.value == "" {
			return fmt.Errorf("%s is required in router mode", r.name)
		}
	}
	return nil
}
