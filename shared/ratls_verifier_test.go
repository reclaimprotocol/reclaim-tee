//go:build !mobile

package shared

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// TestExtractAttestationFromCert handles a cert that does and doesn't carry
// the attestation extension.
func TestExtractAttestationFromCert(t *testing.T) {
	t.Run("missing extension", func(t *testing.T) {
		cert := &x509.Certificate{}
		if _, err := ExtractAttestationFromCert(cert); err == nil {
			t.Fatal("expected error when extension absent")
		}
	})

	t.Run("extension present", func(t *testing.T) {
		want := []byte("attestation-payload-bytes")
		cert := &x509.Certificate{
			Extensions: []pkix.Extension{
				{Id: AttestationOID, Value: want},
			},
		}
		got, err := ExtractAttestationFromCert(cert)
		if err != nil {
			t.Fatalf("extract: %v", err)
		}
		if string(got) != string(want) {
			t.Fatalf("extension value mismatch: got %q, want %q", got, want)
		}
	})
}

// fakeJWT produces a JWT-shaped string (header.payload.signature) where
// payload is the JSON-encoded claims. Signature is bogus but findNonceValue
// doesn't inspect it — signature validity is the GoogleAttestor's concern,
// covered by separate tests.
func fakeJWT(claims map[string]any) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	return hdr + "." + payload + ".sig"
}

func TestFindNonceValue(t *testing.T) {
	t.Run("string form", func(t *testing.T) {
		jwt := fakeJWT(map[string]any{"eat_nonce": "tee_k_spki_hash:abcd1234"})
		got, err := findNonceValue([]byte(jwt), "tee_k_spki_hash:")
		if err != nil {
			t.Fatalf("find: %v", err)
		}
		if got != "abcd1234" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("array form picks matching prefix", func(t *testing.T) {
		jwt := fakeJWT(map[string]any{"eat_nonce": []any{
			"tee_k_public_key:0xabc",
			"tee_k_spki_hash:cafef00d",
			"some_other:value",
		}})
		got, err := findNonceValue([]byte(jwt), "tee_k_spki_hash:")
		if err != nil {
			t.Fatalf("find: %v", err)
		}
		if got != "cafef00d" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("no matching prefix", func(t *testing.T) {
		jwt := fakeJWT(map[string]any{"eat_nonce": "tee_k_public_key:0xabc"})
		_, err := findNonceValue([]byte(jwt), "tee_k_spki_hash:")
		if err == nil {
			t.Fatal("expected error when no nonce matches prefix")
		}
	})

	t.Run("missing eat_nonce claim", func(t *testing.T) {
		jwt := fakeJWT(map[string]any{"sub": "something"})
		_, err := findNonceValue([]byte(jwt), "tee_k_spki_hash:")
		if err == nil {
			t.Fatal("expected error when eat_nonce absent")
		}
	})

	t.Run("malformed JWT", func(t *testing.T) {
		_, err := findNonceValue([]byte("not.a.jwt.at.all"), "x")
		if err == nil {
			t.Fatal("expected error on malformed JWT")
		}
		if !strings.Contains(err.Error(), "JWT") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
