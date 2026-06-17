package auth

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/reclaimprotocol/reclaim-tee/router/store"
	"github.com/reclaimprotocol/reclaim-tee/shared"

	"go.uber.org/zap"
)

// Attestation types carried in the /register body's attestation_type field.
// Empty defaults to CS so existing Confidential Space TEEs need no change.
const (
	AttestationTypeCS     = "cs"
	AttestationTypeSEVSNP = "sev-snp"
)

// AttestationValidator validates a TEE attestation and returns the image
// identity to pin (sha256:<digest> for Confidential Space, snp-measurement:<hex>
// for SEV-SNP) plus the SPKI hash the attestation commits to (CS eat_nonce /
// SEV-SNP report_data[0:32]). The caller binds that hash to the registering key.
type AttestationValidator interface {
	Validate(attType, role string, token []byte) (imageIdentity string, spkiHash [32]byte, err error)
}

// DispatchingValidator routes by attestation type so Confidential Space and
// SEV-SNP TEEs share one /register path.
type DispatchingValidator struct {
	logger *zap.Logger
}

func NewDispatchingValidator(logger *zap.Logger) *DispatchingValidator {
	return &DispatchingValidator{logger: logger}
}

func (v *DispatchingValidator) Validate(attType, role string, token []byte) (string, [32]byte, error) {
	switch attType {
	case AttestationTypeSEVSNP:
		return validateSEVSNP(token)
	case AttestationTypeCS, "":
		return validateCS(token, role, v.logger)
	default:
		var zero [32]byte
		return "", zero, fmt.Errorf("unknown attestation type %q", attType)
	}
}

// validateCS verifies a Confidential Space attestation JWT (signature + chain)
// and returns the image digest and the role-scoped SPKI hash from eat_nonce.
// ExtractImageDigestFromGCPAttestation verifies the JWT, so the nonce read by
// FindNonceValue afterward is trustworthy.
func validateCS(token []byte, role string, logger *zap.Logger) (string, [32]byte, error) {
	var spki [32]byte
	digest, err := shared.ExtractImageDigestFromGCPAttestation(token, &shared.Logger{Logger: logger})
	if err != nil {
		return "", spki, fmt.Errorf("validate CS attestation: %w", err)
	}
	nonceRole := "tee_k"
	if store.Role(role) == store.RoleT {
		nonceRole = "tee_t"
	}
	expectedHex, err := shared.FindNonceValue(token, shared.SPKINoncePrefix(nonceRole))
	if err != nil {
		return "", spki, fmt.Errorf("find SPKI nonce: %w", err)
	}
	raw, err := hex.DecodeString(expectedHex)
	if err != nil || len(raw) != 32 {
		return "", spki, errors.New("CS eat_nonce SPKI hash malformed")
	}
	copy(spki[:], raw)
	return digest, spki, nil
}

// validateSEVSNP verifies a SEV-SNP attestation (VCEK/VLEK -> AMD root) and
// returns the launch-measurement identity and the SPKI hash from report_data.
// token is base64(std) of the marshaled go-sev-guest Attestation proto — it
// must be base64 because the register body is JSON (UTF-8 strings only).
func validateSEVSNP(token []byte) (string, [32]byte, error) {
	var spki [32]byte
	raw, err := base64.StdEncoding.DecodeString(string(token))
	if err != nil {
		return "", spki, fmt.Errorf("decode SEV-SNP attestation base64: %w", err)
	}
	measurement, rd, err := shared.VerifySEVSNPAttestation(raw, true)
	if err != nil {
		return "", spki, fmt.Errorf("validate SEV-SNP attestation: %w", err)
	}
	return shared.SEVSNPIdentity(measurement), rd.SPKIHash, nil
}
