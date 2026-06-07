//go:build !mobile

package shared

import (
	"crypto/sha256"
	"crypto/x509"
	"testing"
)

// TestNewRATLSManager_StandaloneFallback verifies that NewRATLSManager
// produces a usable cert even when the GCP Confidential Space launcher
// socket is absent (i.e. local dev). The attestation extension is then
// missing — that's expected and documented.
func TestNewRATLSManager_StandaloneFallback(t *testing.T) {
	m, err := NewRATLSManager(t.Context(), "tee_k", nil)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if m.Certificate() == nil || m.CertificateRaw() == nil {
		t.Fatal("expected non-nil cert")
	}

	leaf, err := x509.ParseCertificate(m.CertificateRaw())
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if leaf.Subject.CommonName != "tee_k" {
		t.Fatalf("subject CN = %q, want tee_k", leaf.Subject.CommonName)
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("expected DigitalSignature key usage")
	}

	// Standalone mode: launcher socket isn't there, so the extension is absent.
	// This test runs outside an enclave, so confirm that's what we see.
	if _, err := ExtractAttestationFromCert(leaf); err == nil {
		t.Fatal("expected ExtractAttestationFromCert to fail in standalone mode")
	}
}

// TestRATLSManager_SPKIHashStable confirms the SPKI hash reported by the
// manager matches what an external verifier would compute from the public
// key in the cert.
func TestRATLSManager_SPKIHashStable(t *testing.T) {
	m, err := NewRATLSManager(t.Context(), "tee_t", nil)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	leaf, err := x509.ParseCertificate(m.CertificateRaw())
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}
	expected := sha256.Sum256(spkiDER)

	if got := m.SPKIHash(); got != expected {
		t.Fatalf("SPKIHash mismatch:\n  manager: %x\n  cert:    %x", got, expected)
	}
}

// TestRATLSManager_DistinctInstancesGetDistinctKeys ensures each manager
// generates a fresh keypair (cert reuse across enclave restarts would
// leak whatever the previous key signed).
func TestRATLSManager_DistinctInstancesGetDistinctKeys(t *testing.T) {
	a, _ := NewRATLSManager(t.Context(), "tee_k", nil)
	b, _ := NewRATLSManager(t.Context(), "tee_k", nil)
	if a.SPKIHash() == b.SPKIHash() {
		t.Fatal("two managers produced identical SPKI hashes — keys are not fresh")
	}
}

func TestSPKINoncePrefix(t *testing.T) {
	if got := SPKINoncePrefix("tee_k"); got != "tee_k_spki_hash:" {
		t.Fatalf("tee_k prefix: %q", got)
	}
	if got := SPKINoncePrefix("tee_t"); got != "tee_t_spki_hash:" {
		t.Fatalf("tee_t prefix: %q", got)
	}
}
