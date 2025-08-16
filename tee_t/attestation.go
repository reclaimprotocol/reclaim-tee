package main

import (
	"context"
	"fmt"
	"os"
	"time"

	teeproto "tee-mpc/proto"

	"go.uber.org/zap"
)

func (t *TEET) startAttestationRefresh(ctx context.Context) {
	t.logger.Info("Starting background attestation refresh (4-minute interval)")
	if err := t.refreshAttestation(); err != nil {
		t.logger.Error("Failed to pre-generate initial attestation", zap.Error(err))
	} else {
		t.logger.Info("Successfully pre-generated initial attestation")
	}
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

func (t *TEET) refreshAttestation() error {
	if t.enclaveManager == nil {
		return nil
	}
	ethAddress := t.signingKeyPair.GetEthAddress()
	userData := fmt.Sprintf("tee_t_public_key:%s", ethAddress.Hex())
	provider := os.Getenv("ATTESTATION_PROVIDER")
	var attestationReport *teeproto.AttestationReport
	if provider == "gcp" {
		raw, err := t.enclaveManager.GenerateAttestation(context.Background(), []byte(userData))
		if err != nil {
			return fmt.Errorf("failed to generate GCP attestation: %v", err)
		}
		attestationReport = &teeproto.AttestationReport{Type: "gcp", Report: raw}
	} else {
		raw, err := t.enclaveManager.GenerateAttestation(context.Background(), []byte(userData))
		if err != nil {
			return fmt.Errorf("failed to generate Nitro attestation: %v", err)
		}
		attestationReport = &teeproto.AttestationReport{Type: "nitro", Report: raw}
	}
	t.attestationMutex.Lock()
	t.cachedAttestation = attestationReport
	t.attestationExpiry = time.Now().Add(5 * time.Minute)
	t.attestationMutex.Unlock()
	t.logger.Info("Cached new attestation",
		zap.String("type", attestationReport.Type),
		zap.Int("bytes", len(attestationReport.Report)),
		zap.Time("expires", t.attestationExpiry))
	return nil
}

func (t *TEET) getCachedAttestation(sessionID string) (*teeproto.AttestationReport, error) {
	if t.enclaveManager == nil {
		return nil, nil
	}
	t.attestationMutex.RLock()
	cached := t.cachedAttestation
	expiry := t.attestationExpiry
	t.attestationMutex.RUnlock()
	if cached != nil && time.Now().Before(expiry) {
		t.logger.InfoIf("Using cached attestation",
			zap.String("session_id", sessionID),
			zap.String("type", cached.Type),
			zap.Time("expires", expiry))
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
