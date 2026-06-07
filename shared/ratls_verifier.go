//go:build !mobile

package shared

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// RATLSVerifyOptions controls the peer-certificate check installed via
// tls.Config.VerifyPeerCertificate. PeerRole is the role of the side whose
// cert we are about to verify ("tee_k" or "tee_t"); ExpectedImageDigest is
// the image digest we require the peer to attest to (matches the value
// passed via metadata at deploy time, e.g. EXPECTED_PEER_IMAGE_DIGEST).
type RATLSVerifyOptions struct {
	PeerRole            string
	ExpectedImageDigest string
	Logger              *Logger
}

// VerifyRATLSPeer returns a tls.Config.VerifyPeerCertificate callback that
// validates a peer presenting an RA-TLS certificate:
//
//  1. Pulls the GCP attestation JWT out of the AttestationOID extension.
//  2. Validates the JWT signature against Google's roots (reuses the
//     existing GoogleAttestor).
//  3. Confirms submods.container.image_digest matches the expected value.
//  4. Confirms the SPKI hash nonce in the JWT matches the actual SPKI of
//     the cert that was presented.
//
// Any failure returns an error, which the TLS handshake propagates as a
// connection failure.
//
// Standalone (non-enclave) peers — i.e. RATLSManager instances that booted
// without the GCP launcher socket — present certs without the attestation
// extension and will be rejected here with "attestation extension not
// present on certificate". This is deliberate: production deployments must
// always go through enclave attestation. Local-dev TEE↔TEE comms that
// want to tolerate missing attestation should use a different verifier
// path (e.g. a thin wrapper that returns nil for the standalone case).
func VerifyRATLSPeer(opts RATLSVerifyOptions) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("ratls: no peer certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("ratls: parse peer cert: %w", err)
		}

		attestation, err := ExtractAttestationFromCert(leaf)
		if err != nil {
			return fmt.Errorf("ratls: %w", err)
		}

		attestor, err := NewGoogleAttestor()
		if err != nil {
			return fmt.Errorf("ratls: build attestor: %w", err)
		}
		if err := attestor.Validate(attestation, opts.Logger); err != nil {
			return fmt.Errorf("ratls: attestation invalid: %w", err)
		}

		gotDigest, err := ExtractImageDigestFromGCPAttestation(attestation, opts.Logger)
		if err != nil {
			return fmt.Errorf("ratls: extract image digest: %w", err)
		}
		if gotDigest != opts.ExpectedImageDigest {
			return fmt.Errorf("ratls: image_digest mismatch: expected %q, got %q",
				opts.ExpectedImageDigest, gotDigest)
		}

		spkiDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
		if err != nil {
			return fmt.Errorf("ratls: marshal peer SPKI: %w", err)
		}
		actualHash := sha256.Sum256(spkiDER)
		actualHex := hex.EncodeToString(actualHash[:])

		expectedHex, err := findNonceValue(attestation, SPKINoncePrefix(opts.PeerRole))
		if err != nil {
			return fmt.Errorf("ratls: %w", err)
		}
		if expectedHex != actualHex {
			return fmt.Errorf("ratls: SPKI hash mismatch: attestation says %q, cert is %q",
				expectedHex, actualHex)
		}
		return nil
	}
}

// ExtractAttestationFromCert returns the raw GCP attestation JWT bytes from
// the AttestationOID X.509 extension on the given cert, or an error if the
// extension is missing.
func ExtractAttestationFromCert(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(AttestationOID) {
			return ext.Value, nil
		}
	}
	return nil, errors.New("attestation extension not present on certificate")
}

// findNonceValue inspects the eat_nonce claim of an attestation JWT for a
// nonce starting with the given prefix and returns the substring after the
// prefix. Handles both string and []any forms of eat_nonce.
func findNonceValue(attestation []byte, prefix string) (string, error) {
	tokenStr := strings.TrimSpace(string(attestation))
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid JWT format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("unmarshal claims: %w", err)
	}
	raw, ok := claims["eat_nonce"]
	if !ok {
		return "", errors.New("eat_nonce missing from attestation")
	}
	switch v := raw.(type) {
	case string:
		if val, ok := strings.CutPrefix(v, prefix); ok {
			return val, nil
		}
	case []any:
		for _, n := range v {
			s, ok := n.(string)
			if !ok {
				continue
			}
			if val, ok := strings.CutPrefix(s, prefix); ok {
				return val, nil
			}
		}
	}
	return "", fmt.Errorf("nonce with prefix %q not found", prefix)
}
