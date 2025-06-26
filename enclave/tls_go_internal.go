package enclave

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"golang.org/x/crypto/hkdf"
)

// This file adapts Go's internal TLS 1.3 implementation from crypto/tls
// Source: https://github.com/golang/go/tree/master/src/crypto/tls

// TLS 1.3 labels from Go's crypto/tls/key_schedule.go
const (
	labelClientHandshakeTrafficSecret   = "c hs traffic"
	labelServerHandshakeTrafficSecret   = "s hs traffic"
	labelClientApplicationTrafficSecret = "c ap traffic"
	labelServerApplicationTrafficSecret = "s ap traffic"
	labelApplicationTrafficSecret       = "ap traffic"
	labelEarlyTrafficSecret             = "e traffic"
	labelExporterMasterSecret           = "exp master"
	labelResumptionMasterSecret         = "res master"
	labelGoTrafficKey                   = "key"      // Renamed to avoid conflict
	labelGoTrafficIV                    = "iv"       // Renamed to avoid conflict
	labelGoFinishedKey                  = "finished" // Renamed to avoid conflict
	labelDerived                        = "derived"
)

// aeadNonceLength is the nonce length for AEAD ciphers (12 bytes for GCM and ChaCha20-Poly1305)
const aeadNonceLength = 12

// cipherSuiteTLS13 represents a TLS 1.3 cipher suite
// Follows Go's internal structure from crypto/tls/cipher_suites.go
type cipherSuiteTLS13 struct {
	id     uint16
	keyLen int
	hash   struct {
		New  func() hash.Hash
		Size func() int
	}
}

// cipherSuiteFromID returns cipher suite information
// Adapted from Go's crypto/tls/cipher_suites.go
func cipherSuiteFromID(id uint16) *cipherSuiteTLS13 {
	switch id {
	case TLS_AES_128_GCM_SHA256:
		return &cipherSuiteTLS13{
			id:     TLS_AES_128_GCM_SHA256,
			keyLen: 16,
			hash: struct {
				New  func() hash.Hash
				Size func() int
			}{New: sha256.New, Size: func() int { return 32 }},
		}
	case TLS_AES_256_GCM_SHA384:
		return &cipherSuiteTLS13{
			id:     TLS_AES_256_GCM_SHA384,
			keyLen: 32,
			hash: struct {
				New  func() hash.Hash
				Size func() int
			}{New: sha512.New384, Size: func() int { return 48 }},
		}
	case TLS_CHACHA20_POLY1305_SHA256:
		return &cipherSuiteTLS13{
			id:     TLS_CHACHA20_POLY1305_SHA256,
			keyLen: 32,
			hash: struct {
				New  func() hash.Hash
				Size func() int
			}{New: sha256.New, Size: func() int { return 32 }},
		}
	default:
		return nil
	}
}

// expandLabel implements HKDF-Expand-Label from RFC 8446, Section 7.1
// This is Go's exact implementation pattern from crypto/tls/key_schedule.go
func (c *cipherSuiteTLS13) expandLabel(secret []byte, label string, context []byte, length int) []byte {
	if length > 255 {
		panic("tls: HKDF-Expand-Label length too large")
	}

	// Build HkdfLabel structure exactly as Go does:
	// struct {
	//     uint16 length = Length;
	//     opaque label<7..255> = "tls13 " + Label;
	//     opaque context<0..255> = Context;
	// } HkdfLabel;

	hkdfLabel := make([]byte, 0, 2+1+6+len(label)+1+len(context))

	// Length (2 bytes)
	hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))

	// Label length and data (prefixed with "tls13 ")
	fullLabel := "tls13 " + label
	hkdfLabel = append(hkdfLabel, byte(len(fullLabel)))
	hkdfLabel = append(hkdfLabel, []byte(fullLabel)...)

	// Context length and data
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)

	// Use HKDF-Expand exactly as Go does
	out := make([]byte, length)
	n, err := hkdf.Expand(c.hash.New, secret, hkdfLabel).Read(out)
	if err != nil || n != length {
		panic("tls: HKDF-Expand-Label invocation failed unexpectedly")
	}

	return out
}

// deriveSecret implements Derive-Secret from RFC 8446, Section 7.1
// Follows Go's exact pattern from crypto/tls/key_schedule.go
func (c *cipherSuiteTLS13) deriveSecret(secret []byte, label string, transcript hash.Hash) []byte {
	if transcript == nil {
		transcript = c.hash.New()
	}
	return c.expandLabel(secret, label, transcript.Sum(nil), c.hash.Size())
}

// extract implements HKDF-Extract with the cipher suite hash
// Follows Go's exact pattern from crypto/tls/key_schedule.go
func (c *cipherSuiteTLS13) extract(newSecret, currentSecret []byte) []byte {
	if newSecret == nil {
		newSecret = make([]byte, c.hash.Size())
	}
	return hkdf.Extract(c.hash.New, newSecret, currentSecret)
}

// nextTrafficSecret generates the next traffic secret, given the current one,
// according to RFC 8446, Section 7.2
// This is Go's exact implementation from crypto/tls/key_schedule.go
func (c *cipherSuiteTLS13) nextTrafficSecret(trafficSecret []byte) []byte {
	return c.expandLabel(trafficSecret, "traffic upd", nil, c.hash.Size())
}

// trafficKey generates traffic keys according to RFC 8446, Section 7.3
// This is Go's exact implementation from crypto/tls/key_schedule.go
func (c *cipherSuiteTLS13) trafficKey(trafficSecret []byte) (key, iv []byte) {
	key = c.expandLabel(trafficSecret, "key", nil, c.keyLen)
	iv = c.expandLabel(trafficSecret, "iv", nil, aeadNonceLength)
	return
}

// finishedHash generates the Finished verify_data according to RFC 8446, Section 4.4.4
// This is Go's exact implementation from crypto/tls/key_schedule.go
func (c *cipherSuiteTLS13) finishedHash(baseKey []byte, transcript hash.Hash) []byte {
	finishedKey := c.expandLabel(baseKey, "finished", nil, c.hash.Size())
	verifyData := hmac.New(c.hash.New, finishedKey)
	verifyData.Write(transcript.Sum(nil))
	return verifyData.Sum(nil)
}

// GoTLSKeySchedule manages the TLS 1.3 key derivation using Go's internal patterns
type GoTLSKeySchedule struct {
	cipherSuite *cipherSuiteTLS13

	// Key schedule secrets (following RFC 8446 flow)
	earlySecret     []byte
	handshakeSecret []byte
	masterSecret    []byte

	// Traffic secrets
	clientHandshakeSecret []byte
	serverHandshakeSecret []byte
	clientAppSecret       []byte
	serverAppSecret       []byte

	// Handshake transcript hash
	transcript hash.Hash
}

// NewGoTLSKeySchedule creates a new Go-style TLS 1.3 key schedule
func NewGoTLSKeySchedule(cipherSuiteID uint16) (*GoTLSKeySchedule, error) {
	cs := cipherSuiteFromID(cipherSuiteID)
	if cs == nil {
		return nil, fmt.Errorf("unsupported cipher suite: 0x%04x", cipherSuiteID)
	}

	return &GoTLSKeySchedule{
		cipherSuite: cs,
		transcript:  cs.hash.New(),
	}, nil
}

// InitializeEarlySecret initializes the early secret (PSK = 0 for ECDHE-only)
func (ks *GoTLSKeySchedule) InitializeEarlySecret() {
	// Early Secret = HKDF-Extract(0, 0) for ECDHE-only connections
	zeroSalt := make([]byte, ks.cipherSuite.hash.Size())
	zeroIKM := make([]byte, ks.cipherSuite.hash.Size())
	ks.earlySecret = ks.cipherSuite.extract(zeroIKM, zeroSalt)
}

// DeriveHandshakeSecret derives the handshake secret from ECDH shared secret
func (ks *GoTLSKeySchedule) DeriveHandshakeSecret(sharedSecret []byte) error {
	if ks.earlySecret == nil {
		return fmt.Errorf("early secret not initialized")
	}

	// Derive-Secret(Early Secret, "derived", "")
	derivedSecret := ks.cipherSuite.deriveSecret(ks.earlySecret, "derived", nil)

	// Handshake Secret = HKDF-Extract(Derived-Secret, ECDH)
	ks.handshakeSecret = ks.cipherSuite.extract(sharedSecret, derivedSecret)

	return nil
}

// DeriveHandshakeTrafficSecrets derives client and server handshake traffic secrets
func (ks *GoTLSKeySchedule) DeriveHandshakeTrafficSecrets() error {
	if ks.handshakeSecret == nil {
		return fmt.Errorf("handshake secret not derived")
	}

	// Client handshake traffic secret
	ks.clientHandshakeSecret = ks.cipherSuite.deriveSecret(
		ks.handshakeSecret, "c hs traffic", ks.transcript)

	// Server handshake traffic secret
	ks.serverHandshakeSecret = ks.cipherSuite.deriveSecret(
		ks.handshakeSecret, "s hs traffic", ks.transcript)

	return nil
}

// DeriveMasterSecret derives the master secret
func (ks *GoTLSKeySchedule) DeriveMasterSecret() error {
	if ks.handshakeSecret == nil {
		return fmt.Errorf("handshake secret not derived")
	}

	// Derive-Secret(Handshake Secret, "derived", "")
	derivedSecret := ks.cipherSuite.deriveSecret(ks.handshakeSecret, "derived", nil)

	// Master Secret = HKDF-Extract(Derived-Secret, 0)
	zeroIKM := make([]byte, ks.cipherSuite.hash.Size())
	ks.masterSecret = ks.cipherSuite.extract(zeroIKM, derivedSecret)

	return nil
}

// DeriveApplicationTrafficSecrets derives client and server application traffic secrets
func (ks *GoTLSKeySchedule) DeriveApplicationTrafficSecrets() error {
	if ks.masterSecret == nil {
		return fmt.Errorf("master secret not derived")
	}

	// Client application traffic secret
	ks.clientAppSecret = ks.cipherSuite.deriveSecret(
		ks.masterSecret, "c ap traffic", ks.transcript)

	// Server application traffic secret
	ks.serverAppSecret = ks.cipherSuite.deriveSecret(
		ks.masterSecret, "s ap traffic", ks.transcript)

	return nil
}

// GetHandshakeTrafficKeys returns client and server handshake traffic keys
func (ks *GoTLSKeySchedule) GetHandshakeTrafficKeys() (clientKey, clientIV, serverKey, serverIV []byte, err error) {
	if ks.clientHandshakeSecret == nil || ks.serverHandshakeSecret == nil {
		return nil, nil, nil, nil, fmt.Errorf("handshake traffic secrets not derived")
	}

	clientKey, clientIV = ks.cipherSuite.trafficKey(ks.clientHandshakeSecret)
	serverKey, serverIV = ks.cipherSuite.trafficKey(ks.serverHandshakeSecret)

	return clientKey, clientIV, serverKey, serverIV, nil
}

// GetApplicationTrafficKeys returns client and server application traffic keys
func (ks *GoTLSKeySchedule) GetApplicationTrafficKeys() (clientKey, clientIV, serverKey, serverIV []byte, err error) {
	if ks.clientAppSecret == nil || ks.serverAppSecret == nil {
		return nil, nil, nil, nil, fmt.Errorf("application traffic secrets not derived")
	}

	clientKey, clientIV = ks.cipherSuite.trafficKey(ks.clientAppSecret)
	serverKey, serverIV = ks.cipherSuite.trafficKey(ks.serverAppSecret)

	return clientKey, clientIV, serverKey, serverIV, nil
}

// UpdateTranscript updates the handshake transcript hash
func (ks *GoTLSKeySchedule) UpdateTranscript(data []byte) {
	ks.transcript.Write(data)
}

// GetTranscriptHash returns the current transcript hash
func (ks *GoTLSKeySchedule) GetTranscriptHash() []byte {
	return ks.transcript.Sum(nil)
}

// GetCipherSuite returns the cipher suite ID
func (ks *GoTLSKeySchedule) GetCipherSuite() uint16 {
	return ks.cipherSuite.id
}

// GetKeyLength returns the key length for the cipher suite
func (ks *GoTLSKeySchedule) GetKeyLength() int {
	return ks.cipherSuite.keyLen
}

// GetHashSize returns the hash size for the cipher suite
func (ks *GoTLSKeySchedule) GetHashSize() int {
	return ks.cipherSuite.hash.Size()
}

// SecureZero securely zeros all sensitive key material
func (ks *GoTLSKeySchedule) SecureZero() {
	secureZeroBytes(ks.earlySecret)
	secureZeroBytes(ks.handshakeSecret)
	secureZeroBytes(ks.masterSecret)
	secureZeroBytes(ks.clientHandshakeSecret)
	secureZeroBytes(ks.serverHandshakeSecret)
	secureZeroBytes(ks.clientAppSecret)
	secureZeroBytes(ks.serverAppSecret)
}
