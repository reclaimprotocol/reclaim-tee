package auth

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// TestDispatchingValidator_SEVSNP drives the SEV-SNP path end-to-end against a
// real AWS VLEK attestation fixture: base64 in, AMD-chain verified offline,
// snp-measurement identity + report_data SPKI hash out.
func TestDispatchingValidator_SEVSNP(t *testing.T) {
	raw, err := os.ReadFile("../../shared/testdata/aws_vlek_attestation.bin")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	token := []byte(base64.StdEncoding.EncodeToString(raw))

	v := NewDispatchingValidator(zap.NewNop())
	id, spki, err := v.Validate(AttestationTypeSEVSNP, "T", token)
	if err != nil {
		t.Fatalf("validate SEV-SNP: %v", err)
	}
	if !strings.HasPrefix(id, "snp-measurement:") {
		t.Fatalf("identity = %q, want snp-measurement: prefix", id)
	}
	if len(id) != len("snp-measurement:")+96 {
		t.Fatalf("identity = %q, want 96 hex measurement chars", id)
	}
	// spki is report_data[0:32]; the fixture's prober left it zero. Just confirm
	// the field is populated to 32 bytes (no panic / partial copy).
	if len(spki) != 32 {
		t.Fatalf("spki hash len = %d, want 32", len(spki))
	}
}

func TestDispatchingValidator_RejectsBadType(t *testing.T) {
	v := NewDispatchingValidator(zap.NewNop())
	if _, _, err := v.Validate("nonsense", "K", []byte("x")); err == nil {
		t.Fatal("expected error for unknown attestation type")
	}
}

func TestDispatchingValidator_SEVSNPRejectsGarbage(t *testing.T) {
	v := NewDispatchingValidator(zap.NewNop())
	if _, _, err := v.Validate(AttestationTypeSEVSNP, "T", []byte("!!not base64!!")); err == nil {
		t.Fatal("expected error for non-base64 SEV-SNP token")
	}
}
