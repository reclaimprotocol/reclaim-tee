package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// getCurrentCertRaw returns the bytes of the RA-TLS certificate currently
// being served on this TEE_T's TLS endpoint (rotated by RATLSManager.Refresh).
// Returns an error in standalone mode (no RA-TLS).
func (t *TEET) getCurrentCertRaw() ([]byte, error) {
	raw := t.ratls.CertificateRaw()
	if raw == nil {
		return nil, fmt.Errorf("RA-TLS cert not yet available")
	}
	return raw, nil
}

// generateAttestationDoc produces a fresh GCP attestation token bound to
// the supplied nonces, against the launcher socket on the host.
func (t *TEET) generateAttestationDoc(ctx context.Context, nonces ...string) ([]byte, error) {
	return shared.GenerateGCPAttestation(ctx, nonces...)
}

func (t *TEET) startAttestationRefresh(ctx context.Context) {
	t.logger.Debug("Starting background attestation refresh (4-minute interval)")
	if err := t.refreshAttestation(); err != nil {
		t.logger.Error("Failed to pre-generate initial attestation", zap.Error(err))
	} else {
		t.logger.Debug("Successfully pre-generated initial attestation")
	}
	ticker := time.NewTicker(4 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.logger.Debug("Stopping attestation refresh due to context cancellation")
			return
		case <-ticker.C:
			if err := t.refreshAttestation(); err != nil {
				t.logger.Error("Failed to refresh attestation", zap.Error(err))
			} else {
				t.logger.Debug("Successfully refreshed attestation")
			}
		}
	}
}

func (t *TEET) refreshAttestation() error {
	if t.ratls == nil {
		return nil
	}
	ethAddress := t.signingKeyPair.GetEthAddress()

	tlsCert, err := t.getCurrentCertRaw()
	if err != nil {
		return fmt.Errorf("failed to get TLS certificate: %v", err)
	}
	certHash := sha256.Sum256(tlsCert)

	publicKeyNonce := fmt.Sprintf("tee_t_public_key:%s", ethAddress.Hex())
	certHashNonce := fmt.Sprintf("tee_t_cert_hash:%x", certHash[:])

	raw, err := t.generateAttestationDoc(context.Background(), publicKeyNonce, certHashNonce)
	if err != nil {
		return fmt.Errorf("failed to generate attestation: %v", err)
	}

	// Attestation type is always GCP
	attestationReport := &teeproto.AttestationReport{Type: "gcp", Report: raw}
	t.attestationMutex.Lock()
	t.cachedAttestation = attestationReport
	t.attestationExpiry = time.Now().Add(5 * time.Minute)
	t.attestationMutex.Unlock()
	t.logger.Debug("Cached new attestation",
		zap.String("type", attestationReport.Type),
		zap.Int("bytes", len(attestationReport.Report)))
	return nil
}

func (t *TEET) getCachedAttestation(sessionID string) (*teeproto.AttestationReport, error) {
	if t.ratls == nil {
		return nil, nil
	}
	t.attestationMutex.RLock()
	cached := t.cachedAttestation
	expiry := t.attestationExpiry
	t.attestationMutex.RUnlock()
	if cached != nil && time.Now().Before(expiry) {
		t.logger.Debug("Using cached attestation",
			zap.String("session_id", sessionID),
			zap.String("type", cached.Type))
		return cached, nil
	}
	t.logger.WarnIf("Cached attestation expired or missing, generating new one",
		zap.String("session_id", sessionID))
	if err := t.refreshAttestation(); err != nil {
		return nil, fmt.Errorf("failed to generate fallback attestation: %v", err)
	}
	t.attestationMutex.RLock()
	result := t.cachedAttestation
	t.attestationMutex.RUnlock()
	return result, nil
}

func (t *TEET) generateAttestationReport(sessionID string) (*teeproto.AttestationReport, error) {
	return t.getCachedAttestation(sessionID)
}

// generateAttestationForTEEK generates attestation with cert hash for mutual auth
func (t *TEET) generateAttestationForTEEK() (*teeproto.AttestationReport, error) {
	// Standalone (local-dev) mode: peer won't run a real attestation verifier.
	if t.ratls == nil {
		return &teeproto.AttestationReport{
			Type:   "standalone",
			Report: []byte("standalone"),
		}, nil
	}

	// Router mode: cert hash sourced from the active RA-TLS cert.
	tlsCert, err := t.getCurrentCertRaw()
	if err != nil {
		return nil, fmt.Errorf("failed to get current TLS certificate: %v", err)
	}
	if len(tlsCert) == 0 {
		return nil, fmt.Errorf("TLS certificate not loaded")
	}

	certHash := sha256.Sum256(tlsCert)
	userData := fmt.Sprintf("tee_t_cert_hash:%x", certHash[:])

	t.logger.Debug("Generating attestation for TEE_K",
		zap.Int("cert_bytes", len(tlsCert)))

	attestationDoc, err := t.generateAttestationDoc(context.Background(), userData)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation: %v", err)
	}

	// Attestation type is always GCP
	attestationType := "gcp"

	t.logger.Debug("Generated attestation for TEE_K",
		zap.String("type", attestationType))

	return &teeproto.AttestationReport{
		Type:   attestationType,
		Report: attestationDoc,
	}, nil
}

// verifyTEEKAttestation verifies TEE_K's attestation request. Symmetric to
// TEE_K's verifyTEETAttestation: extract the eat_nonce userData from the
// GCP attestation JWT and confirm it equals "tee_k_cert_hash:<sha256(peer
// cert)>" — binding the inner attestation to the TLS cert TEE_K presented
// during the mTLS handshake.
//
// peerCert is the raw DER of TEE_K's client cert (PeerCertificates[0] of
// the TLS connection underlying this control WebSocket). Pass nil in
// standalone mode; the function will branch into the standalone path.
func (t *TEET) verifyTEEKAttestation(req *teeproto.TEEKAttestationRequest, peerCert []byte) error {
	attestation := req.AttestationReport

	// Standalone (local-dev) mode
	if attestation.Type == "standalone" {
		if t.ratls == nil && string(attestation.Report) == "standalone" {
			t.logger.Debug("Standalone mode attestation accepted")
			return nil
		}
		return fmt.Errorf("mode mismatch: received standalone but in router mode")
	}

	// Router mode
	if t.ratls == nil {
		return fmt.Errorf("mode mismatch: received GCP attestation but in standalone mode")
	}

	if len(peerCert) == 0 {
		return fmt.Errorf("no peer TLS certificate available for cert-hash binding")
	}

	// RA-TLS already verified peer image_digest at the TLS handshake (against
	// EXPECTED_PEER_IMAGE_DIGEST). Here we additionally bind the attestation
	// to the TLS cert via the cert_hash nonce, mirroring TEE_K's check.
	certHash := sha256.Sum256(peerCert)
	expectedUserData := fmt.Sprintf("tee_k_cert_hash:%x", certHash[:])

	actualUserData, err := shared.ExtractUserDataFromGCPAttestation(attestation.Report, t.logger)
	if err != nil {
		return fmt.Errorf("extract userData from TEE_K attestation: %w", err)
	}
	if actualUserData != expectedUserData {
		return fmt.Errorf("TEE_K cert hash mismatch: attestation nonce %q does not match peer cert", actualUserData)
	}

	t.logger.Debug("TEE_K cert hash verified")
	return nil
}
