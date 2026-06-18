//go:build !mobile

package shared

import (
	"os"
	"strings"
	"testing"
)

// TestVerifyCombinedAWSAttestation drives the AWS verifier against a real
// combined attestation (NitroTPM doc + SEV report) captured from an AWS
// SEV-SNP + NitroTPM instance via the nitroprobe.
func TestVerifyCombinedAWSAttestation(t *testing.T) {
	env, err := os.ReadFile("testdata/aws_combined_attestation.bin")
	if err != nil {
		t.Skipf("no AWS combined fixture: %v", err)
	}
	spki, err := os.ReadFile("testdata/aws_combined_attestation.spki")
	if err != nil {
		t.Fatalf("read spki: %v", err)
	}
	id, err := VerifyCombinedAWSAttestation(env, spki)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !strings.HasPrefix(id, SEVSNPPCRIdentityPrefix) || len(id) != len(SEVSNPPCRIdentityPrefix)+64 {
		t.Fatalf("identity = %q", id)
	}
	if _, err := VerifyCombinedAWSAttestation(env, []byte("wrong spki")); err == nil {
		t.Fatal("expected binding failure with wrong SPKI")
	}
	t.Logf("verified AWS combined attestation, identity = %s", id)
}
