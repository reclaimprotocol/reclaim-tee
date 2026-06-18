//go:build !mobile

package shared

import (
	"os"
	"strings"
	"testing"
)

// TestVerifyCombinedGCPAttestation drives the verifier against a real combined
// attestation captured from a GCP SEV-SNP CVM (snp-poc -combined). The .spki
// file is the ephemeral SPKI the producer bound into report_data.
func TestVerifyCombinedGCPAttestation(t *testing.T) {
	att, err := os.ReadFile("testdata/gcp_combined_attestation.bin")
	if err != nil {
		t.Skipf("no combined fixture: %v", err)
	}
	spki, err := os.ReadFile("testdata/gcp_combined_attestation.spki")
	if err != nil {
		t.Fatalf("read spki: %v", err)
	}
	id, err := VerifyCombinedGCPAttestation(att, spki)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.HasPrefix(id, SEVSNPPCRIdentityPrefix) {
		t.Fatalf("identity %q lacks prefix", id)
	}
	if len(id) != len(SEVSNPPCRIdentityPrefix)+64 {
		t.Fatalf("identity %q wrong length", id)
	}
	t.Logf("verified combined attestation, identity = %s", id)
}

// TestVerifyCombinedGCPAttestation_RejectsWrongSPKI confirms the binding check:
// a different SPKI must not verify against report_data committed to the real one.
func TestVerifyCombinedGCPAttestation_RejectsWrongSPKI(t *testing.T) {
	att, err := os.ReadFile("testdata/gcp_combined_attestation.bin")
	if err != nil {
		t.Skipf("no combined fixture: %v", err)
	}
	if _, err := VerifyCombinedGCPAttestation(att, []byte("not the bound spki")); err == nil {
		t.Fatal("expected binding failure with wrong SPKI")
	}
}
