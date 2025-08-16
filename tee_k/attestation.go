package main

import (
	"context"
	"fmt"
	"time"

	teeproto "tee-mpc/proto"

	"go.uber.org/zap"
)

// startAttestationRefresh starts a background goroutine that pre-generates and refreshes attestations
func (t *TEEK) startAttestationRefresh(ctx context.Context) {
	t.logger.Info("Starting background attestation refresh (4-minute interval)")

	// Pre-generate the first attestation
	if err := t.refreshAttestation(); err != nil {
		t.logger.Error("Failed to pre-generate initial attestation", zap.Error(err))
	} else {
		t.logger.Info("Successfully pre-generated initial attestation")
	}

	// Set up 4-minute ticker for refresh
	ticker := time.NewTicker(4 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.logger.Info("Stopping attestation refresh due to context cancellation")
			return
		case <-ticker.C:
			if err := t.refreshAttestation(); err != nil {
				t.logger.Error("Failed to refresh attestation", zap.Error(err))
			} else {
				t.logger.Info("Successfully refreshed attestation")
			}
		}
	}
}

// refreshAttestation generates a new attestation and caches it
func (t *TEEK) refreshAttestation() error {
	// Skip in standalone mode
	if t.enclaveManager == nil {
		return nil
	}

	// Get ETH address for this key pair
	ethAddress := t.signingKeyPair.GetEthAddress()

	// Create user data containing the ETH address
	userData := fmt.Sprintf("tee_k_public_key:%s", ethAddress.Hex())

	// Generate attestation document using enclave manager
	attestationDoc, err := t.enclaveManager.GenerateAttestation(context.Background(), []byte(userData))
	if err != nil {
		return fmt.Errorf("failed to generate attestation: %v", err)
	}

	// Create structured report
	attestationReport := &teeproto.AttestationReport{
		Type:   "nitro",
		Report: attestationDoc,
	}

	// Cache the new attestation
	t.attestationMutex.Lock()
	t.cachedAttestation = attestationReport
	t.attestationExpiry = time.Now().Add(5 * time.Minute) // Cache valid for 5 minutes
	t.attestationMutex.Unlock()

	t.logger.Info("Cached new attestation",
		zap.String("type", attestationReport.Type),
		zap.Int("bytes", len(attestationReport.Report)),
		zap.Time("expires", t.attestationExpiry))

	return nil
}

// getCachedAttestation returns the cached attestation if valid, otherwise generates a new one
func (t *TEEK) getCachedAttestation(sessionID string) (*teeproto.AttestationReport, error) {
	// Skip in standalone mode
	if t.enclaveManager == nil {
		return nil, nil
	}

	t.attestationMutex.RLock()
	cached := t.cachedAttestation
	expiry := t.attestationExpiry
	t.attestationMutex.RUnlock()

	// Use cached attestation if valid
	if cached != nil && time.Now().Before(expiry) {
		t.logger.WithSession(sessionID).Info("Using cached attestation",
			zap.String("type", cached.Type),
			zap.Time("expires", expiry))
		return cached, nil
	}

	// Fallback: generate new attestation if cache is invalid
	t.logger.WithSession(sessionID).Warn("Cached attestation expired or missing, generating new one")

	if err := t.refreshAttestation(); err != nil {
		return nil, fmt.Errorf("failed to generate fallback attestation: %v", err)
	}

	t.attestationMutex.RLock()
	result := t.cachedAttestation
	t.attestationMutex.RUnlock()

	return result, nil
}

// generateAttestationReport generates an AttestationReport for enclave mode (uses cache for performance)
func (t *TEEK) generateAttestationReport(sessionID string) (*teeproto.AttestationReport, error) {
	// Use cached attestation for performance
	return t.getCachedAttestation(sessionID)
}
