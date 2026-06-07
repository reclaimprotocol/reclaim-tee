//go:build !mobile

package shared

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"
)

// AttestationOID is the X.509 extension OID under which a GCP Confidential
// Space attestation JWT is embedded in an RA-TLS certificate.
//
// Placeholder under an unassigned arc. Replace with our IANA-issued Private
// Enterprise Number when one is registered (1.3.6.1.4.1.<PEN>.1).
var AttestationOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}

// SPKINoncePrefix returns the eat_nonce prefix used to bind the TLS public
// key hash into the attestation report. role is "tee_k" or "tee_t".
func SPKINoncePrefix(role string) string {
	return role + "_spki_hash:"
}

// RATLSManager owns an ephemeral ECDSA P-256 keypair and a self-signed
// X.509 certificate that embeds a GCP attestation report as an extension.
// Cert lifetime is the lifetime of the manager (i.e. the enclave process);
// the verifier never checks NotBefore/NotAfter — trust comes from the
// attestation, not chain time.
type RATLSManager struct {
	cert     *tls.Certificate
	spkiHash [32]byte
	role     string
}

// NewRATLSManager generates a fresh keypair, requests a GCP attestation
// over the SPKI hash plus any extraNonces (e.g. an eth-address binding),
// and builds a self-signed cert with the attestation embedded.
//
// In standalone mode (no Confidential Space launcher socket), the cert is
// still produced but without the attestation extension — peers verifying
// in standalone mode skip the attestation step. This lets local dev keep
// using the same code path as enclave deployments.
func NewRATLSManager(ctx context.Context, role string, extraNonces []string) (*RATLSManager, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ecdsa key: %w", err)
	}

	spkiDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal SPKI: %w", err)
	}
	spkiHash := sha256.Sum256(spkiDER)
	spkiNonce := SPKINoncePrefix(role) + hex.EncodeToString(spkiHash[:])

	var extraExts []pkix.Extension
	nonces := append([]string{spkiNonce}, extraNonces...)
	attestation, err := GenerateGCPAttestation(ctx, nonces...)
	if err != nil {
		// Standalone mode: launcher socket unavailable. Fall through with no
		// extension; verifier must accept this only in matching mode.
		attestation = nil
	}
	if len(attestation) > 0 {
		extraExts = append(extraExts, pkix.Extension{
			Id:       AttestationOID,
			Critical: false,
			Value:    attestation,
		})
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("random serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: role},
		// Time bounds are formality only — RA-TLS verification doesn't use
		// them. Set a 1-year window so any consumer doing strict checks still
		// accepts during normal enclave lifetime.
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       extraExts,
	}
	derCert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}

	return &RATLSManager{
		cert: &tls.Certificate{
			Certificate: [][]byte{derCert},
			PrivateKey:  priv,
			Leaf:        mustParse(derCert),
		},
		spkiHash: spkiHash,
		role:     role,
	}, nil
}

// Certificate returns the manager's TLS certificate, suitable for use in a
// tls.Config.Certificates list.
func (m *RATLSManager) Certificate() *tls.Certificate {
	return m.cert
}

// CertificateRaw returns the DER-encoded leaf certificate. Provided for
// callers (e.g. attestation refresh code) that need the raw bytes — kept
// API-compatible with the LegoManager.GetCertificateRaw() shape it replaces.
func (m *RATLSManager) CertificateRaw() []byte {
	return m.cert.Certificate[0]
}

// SPKIHash returns sha256(SPKI) of the TLS keypair. Exposed for callers
// that need to log it or cross-reference against the attestation.
func (m *RATLSManager) SPKIHash() [32]byte {
	return m.spkiHash
}

// ServerTLSConfig returns a tls.Config that serves this cert. No client
// auth here — peer verification is done by the WebSocket-level RA-TLS
// verifier wired up by the application.
func (m *RATLSManager) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{*m.cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}
}

// mustParse parses the DER cert we just created. CreateCertificate produces
// well-formed DER by construction, so a parse failure here would be a bug.
func mustParse(der []byte) *x509.Certificate {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(fmt.Sprintf("ratls: parse just-created cert: %v", err))
	}
	return c
}
