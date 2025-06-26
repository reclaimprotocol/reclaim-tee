package enclave

import (
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

// cipherSuiteFromID returns cipher suite information
// Adapted from Go's crypto/tls/cipher_suites.go
func cipherSuiteFromID(id uint16) *cipherSuiteTLS13 {
	switch id {
	case TLS_AES_128_GCM_SHA256:
		return &cipherSuiteTLS13{
			id:     TLS_AES_128_GCM_SHA256,
			keyLen: 16,
			ivLen:  12,
			hash:   sha256.New,
		}
	case TLS_AES_256_GCM_SHA384:
		return &cipherSuiteTLS13{
			id:     TLS_AES_256_GCM_SHA384,
			keyLen: 32,
			ivLen:  12,
			hash:   sha512.New384,
		}
	case TLS_CHACHA20_POLY1305_SHA256:
		return &cipherSuiteTLS13{
			id:     TLS_CHACHA20_POLY1305_SHA256,
			keyLen: 32,
			ivLen:  12,
			hash:   sha256.New,
		}
	default:
		return nil
	}
}

// cipherSuiteTLS13 represents a TLS 1.3 cipher suite
// Adapted from Go's crypto/tls/cipher_suites.go
type cipherSuiteTLS13 struct {
	id     uint16
	keyLen int
	ivLen  int
	hash   func() hash.Hash
}

// expandLabel implements HKDF-Expand-Label from RFC 8446
// This is directly adapted from Go's crypto/tls/key_schedule.go
func (c *cipherSuiteTLS13) expandLabel(secret []byte, label string, context []byte, length int) []byte {
	var hkdfLabel []byte
	hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))
	hkdfLabel = append(hkdfLabel, byte(len("tls13 "+label)))
	hkdfLabel = append(hkdfLabel, "tls13 "+label...)
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)

	out := make([]byte, length)
	n, err := hkdf.Expand(c.hash, secret, hkdfLabel).Read(out)
	if err != nil || n != length {
		panic("tls: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}

// extract implements HKDF-Extract
// Adapted from Go's crypto/tls/key_schedule.go
func (c *cipherSuiteTLS13) extract(newSecret, currentSecret []byte) []byte {
	if newSecret == nil {
		newSecret = make([]byte, c.hash().Size())
	}
	return hkdf.Extract(c.hash, newSecret, currentSecret)
}

// deriveSecret implements the Derive-Secret function from RFC 8446
// Adapted from Go's crypto/tls/key_schedule.go
func (c *cipherSuiteTLS13) deriveSecret(secret []byte, label string, transcript hash.Hash) []byte {
	if transcript == nil {
		transcript = c.hash()
	}
	return c.expandLabel(secret, label, transcript.Sum(nil), c.hash().Size())
}

// nextTrafficSecret generates the next traffic secret in the sequence
// Adapted from Go's crypto/tls/key_schedule.go
func (c *cipherSuiteTLS13) nextTrafficSecret(trafficSecret []byte) []byte {
	return c.expandLabel(trafficSecret, "traffic upd", nil, c.hash().Size())
}

// trafficKey generates a traffic key from a traffic secret
// Adapted from Go's crypto/tls/key_schedule.go
func (c *cipherSuiteTLS13) trafficKey(trafficSecret []byte) []byte {
	return c.expandLabel(trafficSecret, labelGoTrafficKey, nil, c.keyLen)
}

// trafficIV generates a traffic IV from a traffic secret
// Adapted from Go's crypto/tls/key_schedule.go
func (c *cipherSuiteTLS13) trafficIV(trafficSecret []byte) []byte {
	return c.expandLabel(trafficSecret, labelGoTrafficIV, nil, c.ivLen)
}

// finishedKey generates the finished key from a traffic secret
// Adapted from Go's crypto/tls/key_schedule.go
func (c *cipherSuiteTLS13) finishedKey(baseKey []byte) []byte {
	return c.expandLabel(baseKey, labelGoFinishedKey, nil, c.hash().Size())
}

// GoTLSKeySchedule implements TLS 1.3 key schedule using Go's internal logic
// This replaces our custom implementation with Go's proven algorithms
type GoTLSKeySchedule struct {
	suite                 *cipherSuiteTLS13
	earlySecret           []byte
	handshakeSecret       []byte
	masterSecret          []byte
	clientHandshakeSecret []byte
	serverHandshakeSecret []byte
	clientAppSecret       []byte
	serverAppSecret       []byte
}

// NewGoTLSKeySchedule creates a key schedule using Go's TLS 1.3 implementation
func NewGoTLSKeySchedule(cipherSuite uint16) (*GoTLSKeySchedule, error) {
	suite := cipherSuiteFromID(cipherSuite)
	if suite == nil {
		return nil, fmt.Errorf("unsupported cipher suite: 0x%04x", cipherSuite)
	}

	ks := &GoTLSKeySchedule{
		suite: suite,
	}

	// Initialize early secret (HKDF-Extract(0, 0))
	ks.earlySecret = suite.extract(nil, nil)

	return ks, nil
}

// DeriveHandshakeSecrets derives handshake secrets from ECDH shared secret
// Following Go's crypto/tls/key_schedule.go logic
func (ks *GoTLSKeySchedule) DeriveHandshakeSecrets(sharedKey []byte, transcript hash.Hash) error {
	if ks.earlySecret == nil {
		return fmt.Errorf("early secret not initialized")
	}

	// Derive handshake secret
	// handshakeSecret = HKDF-Extract(Derive-Secret(earlySecret, "derived", ""), sharedKey)
	derivedSecret := ks.suite.deriveSecret(ks.earlySecret, labelDerived, nil)
	ks.handshakeSecret = ks.suite.extract(sharedKey, derivedSecret)

	// Derive client and server handshake traffic secrets
	ks.clientHandshakeSecret = ks.suite.deriveSecret(ks.handshakeSecret, labelClientHandshakeTrafficSecret, transcript)
	ks.serverHandshakeSecret = ks.suite.deriveSecret(ks.handshakeSecret, labelServerHandshakeTrafficSecret, transcript)

	return nil
}

// DeriveApplicationSecrets derives application traffic secrets
// Following Go's crypto/tls/key_schedule.go logic
func (ks *GoTLSKeySchedule) DeriveApplicationSecrets(transcript hash.Hash) error {
	if ks.handshakeSecret == nil {
		return fmt.Errorf("handshake secret not derived")
	}

	// Derive master secret
	// masterSecret = HKDF-Extract(Derive-Secret(handshakeSecret, "derived", ""), 0)
	derivedSecret := ks.suite.deriveSecret(ks.handshakeSecret, labelDerived, nil)
	ks.masterSecret = ks.suite.extract(nil, derivedSecret)

	// Derive client and server application traffic secrets
	ks.clientAppSecret = ks.suite.deriveSecret(ks.masterSecret, labelClientApplicationTrafficSecret, transcript)
	ks.serverAppSecret = ks.suite.deriveSecret(ks.masterSecret, labelServerApplicationTrafficSecret, transcript)

	return nil
}

// GetHandshakeKeys returns handshake traffic keys
func (ks *GoTLSKeySchedule) GetHandshakeKeys() (clientKey, serverKey, clientIV, serverIV []byte) {
	if ks.clientHandshakeSecret == nil || ks.serverHandshakeSecret == nil {
		return nil, nil, nil, nil
	}

	clientKey = ks.suite.trafficKey(ks.clientHandshakeSecret)
	serverKey = ks.suite.trafficKey(ks.serverHandshakeSecret)
	clientIV = ks.suite.trafficIV(ks.clientHandshakeSecret)
	serverIV = ks.suite.trafficIV(ks.serverHandshakeSecret)

	return
}

// GetApplicationKeys returns application traffic keys
func (ks *GoTLSKeySchedule) GetApplicationKeys() (clientKey, serverKey, clientIV, serverIV []byte) {
	if ks.clientAppSecret == nil || ks.serverAppSecret == nil {
		return nil, nil, nil, nil
	}

	clientKey = ks.suite.trafficKey(ks.clientAppSecret)
	serverKey = ks.suite.trafficKey(ks.serverAppSecret)
	clientIV = ks.suite.trafficIV(ks.clientAppSecret)
	serverIV = ks.suite.trafficIV(ks.serverAppSecret)

	return
}

// GetCipherSuite returns the cipher suite ID
func (ks *GoTLSKeySchedule) GetCipherSuite() uint16 {
	return ks.suite.id
}

// SecureZero securely zeros all secrets
func (ks *GoTLSKeySchedule) SecureZero() {
	secureZeroBytes(ks.earlySecret)
	secureZeroBytes(ks.handshakeSecret)
	secureZeroBytes(ks.masterSecret)
	secureZeroBytes(ks.clientHandshakeSecret)
	secureZeroBytes(ks.serverHandshakeSecret)
	secureZeroBytes(ks.clientAppSecret)
	secureZeroBytes(ks.serverAppSecret)
}
