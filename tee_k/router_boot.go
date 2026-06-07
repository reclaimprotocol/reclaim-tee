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
// attestation. GCP Confidential Space tokens have a TTL of ~5 minutes, so
// 4 minutes matches the existing attestation-refresh cadence used by the
// legacy Lego/ACME path and leaves a comfortable margin.
const ratlsRefreshInterval = 4 * time.Minute

// startRouterMode is the boot path used when ROUTER_URL is set. It brings
// up an RA-TLS-backed identity for the TEE, registers the pair with the
// router, and stays alive.
//
// This PR keeps scope tight: it does NOT yet rewire the TEE_K↔TEE_T
// control connection (still TEET_URL-based in the existing connection
// manager), does NOT yet validate allocation JWTs on the client websocket,
// and does NOT yet send heartbeats. Those land in subsequent PRs against
// this same boot path.
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

	imageDigest, attestationJWT, err := extractIdentityFromRATLS(ratls, logger)
	if err != nil {
		logger.Critical("could not extract identity from RA-TLS cert", zap.Error(err))
		return
	}

	router := shared.NewRouterClient(config.RouterURL, shared.MetadataServerTokenSource)
	regResp, err := router.Register(ctx, shared.RegisterRequest{
		PairID:         pairID,
		Role:           "K",
		SelfAddr:       config.SelfAddr,
		PeerAddrClaim:  config.PeerAddr,
		ImageDigest:    imageDigest,
		AttestationJWT: string(attestationJWT),
	})
	if err != nil {
		logger.Critical("router registration failed", zap.Error(err))
		return
	}
	logger.Info("registered with router",
		zap.String("pair_id", regResp.PairID),
		zap.String("status", regResp.Status))

	// Background RA-TLS refresh keeps the embedded attestation fresh so
	// later TLS handshakes verifying via VerifyRATLSPeer don't trip on the
	// JWT's exp claim.
	go runRATLSRefresh(ctx, ratls, logger)

	// Block on shutdown signal. Peer connection, heartbeat, and session
	// serving come in subsequent PRs.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	logger.Info("TEE_K router-mode bootstrap complete; idle until peer + session logic lands",
		zap.String("pair_id", pairID))
	<-sigChan
	logger.Info("shutting down router-mode TEE_K")
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
	case c.SATokenAudience == "":
		return errors.New("SA_TOKEN_AUDIENCE is required in router mode")
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
