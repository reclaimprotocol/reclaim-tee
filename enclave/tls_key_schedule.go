package enclave

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"golang.org/x/crypto/hkdf"
)

// TLS 1.3 Key Schedule Implementation
// Based on RFC 8446 Section 7.1: Key Schedule

// TLS 1.3 labels for HKDF-Expand-Label
const (
	labelEarlySecret       = "tls13 early"
	labelHandshakeSecret   = "tls13 hs traffic"
	labelMasterSecret      = "tls13 ap traffic"
	labelClientHandshake   = "tls13 c hs traffic"
	labelServerHandshake   = "tls13 s hs traffic"
	labelClientApplication = "tls13 c ap traffic"
	labelServerApplication = "tls13 s ap traffic"
	labelExporterMaster    = "tls13 exp master"
	labelResumptionMaster  = "tls13 res master"
	labelFinishedKey       = "tls13 finished"
	labelKeyUpdate         = "tls13 ku"
)

// Key derivation labels for traffic keys
const (
	labelTrafficKey = "tls13 key"
	labelTrafficIV  = "tls13 iv"
)

// TLSKeySchedule manages the TLS 1.3 key derivation process
type TLSKeySchedule struct {
	cipherSuite uint16
	hashFunc    func() hash.Hash
	hashSize    int
	keyLength   int
	ivLength    int

	// Secrets in the key schedule
	earlySecret     []byte
	handshakeSecret []byte
	masterSecret    []byte

	// Traffic secrets
	clientHandshakeSecret []byte
	serverHandshakeSecret []byte
	clientAppSecret       []byte
	serverAppSecret       []byte

	// Handshake hash context
	handshakeHash []byte
}

// NewTLSKeySchedule creates a new TLS 1.3 key schedule for the given cipher suite
func NewTLSKeySchedule(cipherSuite uint16) (*TLSKeySchedule, error) {
	ks := &TLSKeySchedule{
		cipherSuite: cipherSuite,
	}

	// Set hash function and key parameters based on cipher suite
	switch cipherSuite {
	case TLS_AES_128_GCM_SHA256:
		ks.hashFunc = sha256.New
		ks.hashSize = 32
		ks.keyLength = 16
		ks.ivLength = 12

	case TLS_AES_256_GCM_SHA384:
		ks.hashFunc = sha512.New384
		ks.hashSize = 48
		ks.keyLength = 32
		ks.ivLength = 12

	case TLS_CHACHA20_POLY1305_SHA256:
		ks.hashFunc = sha256.New
		ks.hashSize = 32
		ks.keyLength = 32
		ks.ivLength = 12

	default:
		return nil, fmt.Errorf("unsupported cipher suite: 0x%04x", cipherSuite)
	}

	return ks, nil
}

// hkdfExtract implements HKDF-Extract operation
func (ks *TLSKeySchedule) hkdfExtract(salt, ikm []byte) []byte {
	if salt == nil {
		salt = make([]byte, ks.hashSize)
	}

	h := hmac.New(ks.hashFunc, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

// hkdfExpandLabel implements HKDF-Expand-Label from RFC 8446
func (ks *TLSKeySchedule) hkdfExpandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	if length > 255 {
		return nil, fmt.Errorf("HKDF-Expand-Label length too large: %d", length)
	}

	// Build HkdfLabel structure:
	// struct {
	//     uint16 length = Length;
	//     opaque label<7..255> = "tls13 " + Label;
	//     opaque context<0..255> = Context;
	// } HkdfLabel;

	hkdfLabel := make([]byte, 0, 2+1+len(label)+1+len(context))

	// Length (2 bytes)
	hkdfLabel = append(hkdfLabel, byte(length>>8), byte(length))

	// Label length and data
	hkdfLabel = append(hkdfLabel, byte(len(label)))
	hkdfLabel = append(hkdfLabel, []byte(label)...)

	// Context length and data
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)

	// Use HKDF-Expand
	reader := hkdf.Expand(ks.hashFunc, secret, hkdfLabel)
	result := make([]byte, length)
	n, err := reader.Read(result)
	if err != nil {
		return nil, fmt.Errorf("HKDF-Expand failed: %v", err)
	}
	if n != length {
		return nil, fmt.Errorf("HKDF-Expand returned wrong length: expected %d, got %d", length, n)
	}

	return result, nil
}

// deriveSecret implements Derive-Secret from RFC 8446
func (ks *TLSKeySchedule) deriveSecret(secret []byte, label string, messages []byte) ([]byte, error) {
	// Hash the messages
	h := ks.hashFunc()
	h.Write(messages)
	messagesHash := h.Sum(nil)

	// HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
	return ks.hkdfExpandLabel(secret, label, messagesHash, ks.hashSize)
}

// InitializeEarlySecret initializes the early secret (step 1 of key schedule)
func (ks *TLSKeySchedule) InitializeEarlySecret() error {
	// Early Secret = HKDF-Extract(0, 0)
	zeroSalt := make([]byte, ks.hashSize)
	zeroIKM := make([]byte, ks.hashSize)

	ks.earlySecret = ks.hkdfExtract(zeroSalt, zeroIKM)

	if len(ks.earlySecret) != ks.hashSize {
		return fmt.Errorf("early secret has wrong length: expected %d, got %d", ks.hashSize, len(ks.earlySecret))
	}

	return nil
}

// DeriveHandshakeSecret derives the handshake secret from ECDH shared secret
func (ks *TLSKeySchedule) DeriveHandshakeSecret(sharedSecret []byte) error {
	if ks.earlySecret == nil {
		return fmt.Errorf("early secret not initialized")
	}

	if len(sharedSecret) == 0 {
		return fmt.Errorf("shared secret cannot be empty")
	}

	// Derive-Secret(Early Secret, "derived", "")
	derivedSecret, err := ks.deriveSecret(ks.earlySecret, "tls13 derived", nil)
	if err != nil {
		return fmt.Errorf("failed to derive handshake salt: %v", err)
	}

	// Handshake Secret = HKDF-Extract(Derived-Secret, ECDH)
	ks.handshakeSecret = ks.hkdfExtract(derivedSecret, sharedSecret)

	if len(ks.handshakeSecret) != ks.hashSize {
		return fmt.Errorf("handshake secret has wrong length: expected %d, got %d", ks.hashSize, len(ks.handshakeSecret))
	}

	return nil
}

// DeriveHandshakeTrafficSecrets derives client and server handshake traffic secrets
func (ks *TLSKeySchedule) DeriveHandshakeTrafficSecrets(handshakeHash []byte) error {
	if ks.handshakeSecret == nil {
		return fmt.Errorf("handshake secret not derived")
	}

	if len(handshakeHash) != ks.hashSize {
		return fmt.Errorf("handshake hash has wrong length: expected %d, got %d", ks.hashSize, len(handshakeHash))
	}

	var err error

	// Client handshake traffic secret
	ks.clientHandshakeSecret, err = ks.hkdfExpandLabel(ks.handshakeSecret, labelClientHandshake, handshakeHash, ks.hashSize)
	if err != nil {
		return fmt.Errorf("failed to derive client handshake secret: %v", err)
	}

	// Server handshake traffic secret
	ks.serverHandshakeSecret, err = ks.hkdfExpandLabel(ks.handshakeSecret, labelServerHandshake, handshakeHash, ks.hashSize)
	if err != nil {
		return fmt.Errorf("failed to derive server handshake secret: %v", err)
	}

	return nil
}

// DeriveMasterSecret derives the master secret
func (ks *TLSKeySchedule) DeriveMasterSecret() error {
	if ks.handshakeSecret == nil {
		return fmt.Errorf("handshake secret not derived")
	}

	// Derive-Secret(Handshake Secret, "derived", "")
	derivedSecret, err := ks.deriveSecret(ks.handshakeSecret, "tls13 derived", nil)
	if err != nil {
		return fmt.Errorf("failed to derive master salt: %v", err)
	}

	// Master Secret = HKDF-Extract(Derived-Secret, 0)
	zeroIKM := make([]byte, ks.hashSize)
	ks.masterSecret = ks.hkdfExtract(derivedSecret, zeroIKM)

	if len(ks.masterSecret) != ks.hashSize {
		return fmt.Errorf("master secret has wrong length: expected %d, got %d", ks.hashSize, len(ks.masterSecret))
	}

	return nil
}

// DeriveApplicationTrafficSecrets derives client and server application traffic secrets
func (ks *TLSKeySchedule) DeriveApplicationTrafficSecrets(handshakeHash []byte) error {
	if ks.masterSecret == nil {
		return fmt.Errorf("master secret not derived")
	}

	if len(handshakeHash) != ks.hashSize {
		return fmt.Errorf("handshake hash has wrong length: expected %d, got %d", ks.hashSize, len(handshakeHash))
	}

	var err error

	// Client application traffic secret
	ks.clientAppSecret, err = ks.hkdfExpandLabel(ks.masterSecret, labelClientApplication, handshakeHash, ks.hashSize)
	if err != nil {
		return fmt.Errorf("failed to derive client application secret: %v", err)
	}

	// Server application traffic secret
	ks.serverAppSecret, err = ks.hkdfExpandLabel(ks.masterSecret, labelServerApplication, handshakeHash, ks.hashSize)
	if err != nil {
		return fmt.Errorf("failed to derive server application secret: %v", err)
	}

	return nil
}

// DeriveTrafficKeys derives the actual encryption keys and IVs from traffic secrets
func (ks *TLSKeySchedule) DeriveTrafficKeys(trafficSecret []byte) (*TrafficKeys, error) {
	if len(trafficSecret) != ks.hashSize {
		return nil, fmt.Errorf("traffic secret has wrong length: expected %d, got %d", ks.hashSize, len(trafficSecret))
	}

	// Derive key: HKDF-Expand-Label(Secret, "key", "", key_length)
	key, err := ks.hkdfExpandLabel(trafficSecret, labelTrafficKey, nil, ks.keyLength)
	if err != nil {
		return nil, fmt.Errorf("failed to derive traffic key: %v", err)
	}

	// Derive IV: HKDF-Expand-Label(Secret, "iv", "", iv_length)
	iv, err := ks.hkdfExpandLabel(trafficSecret, labelTrafficIV, nil, ks.ivLength)
	if err != nil {
		return nil, fmt.Errorf("failed to derive traffic IV: %v", err)
	}

	return &TrafficKeys{
		Key: key,
		IV:  iv,
	}, nil
}

// TrafficKeys holds a key and IV pair for AEAD operations
type TrafficKeys struct {
	Key []byte
	IV  []byte
}

// GetHandshakeTrafficKeys returns the handshake traffic keys for both client and server
func (ks *TLSKeySchedule) GetHandshakeTrafficKeys() (*TrafficKeys, *TrafficKeys, error) {
	if ks.clientHandshakeSecret == nil || ks.serverHandshakeSecret == nil {
		return nil, nil, fmt.Errorf("handshake traffic secrets not derived")
	}

	clientKeys, err := ks.DeriveTrafficKeys(ks.clientHandshakeSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive client handshake keys: %v", err)
	}

	serverKeys, err := ks.DeriveTrafficKeys(ks.serverHandshakeSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive server handshake keys: %v", err)
	}

	return clientKeys, serverKeys, nil
}

// GetApplicationTrafficKeys returns the application traffic keys for both client and server
func (ks *TLSKeySchedule) GetApplicationTrafficKeys() (*TrafficKeys, *TrafficKeys, error) {
	if ks.clientAppSecret == nil || ks.serverAppSecret == nil {
		return nil, nil, fmt.Errorf("application traffic secrets not derived")
	}

	clientKeys, err := ks.DeriveTrafficKeys(ks.clientAppSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive client application keys: %v", err)
	}

	serverKeys, err := ks.DeriveTrafficKeys(ks.serverAppSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive server application keys: %v", err)
	}

	return clientKeys, serverKeys, nil
}

// GetCipherSuite returns the cipher suite this key schedule is for
func (ks *TLSKeySchedule) GetCipherSuite() uint16 {
	return ks.cipherSuite
}

// GetHashSize returns the hash size for this cipher suite
func (ks *TLSKeySchedule) GetHashSize() int {
	return ks.hashSize
}

// GetKeyLength returns the key length for this cipher suite
func (ks *TLSKeySchedule) GetKeyLength() int {
	return ks.keyLength
}

// GetIVLength returns the IV length for this cipher suite
func (ks *TLSKeySchedule) GetIVLength() int {
	return ks.ivLength
}

// SecureZero securely zeros sensitive data
func (ks *TLSKeySchedule) SecureZero() {
	// Zero out all secrets
	secureZeroBytes(ks.earlySecret)
	secureZeroBytes(ks.handshakeSecret)
	secureZeroBytes(ks.masterSecret)
	secureZeroBytes(ks.clientHandshakeSecret)
	secureZeroBytes(ks.serverHandshakeSecret)
	secureZeroBytes(ks.clientAppSecret)
	secureZeroBytes(ks.serverAppSecret)
	secureZeroBytes(ks.handshakeHash)
}

// secureZeroBytes securely zeros a byte slice
func secureZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SecureZero securely zeros traffic keys
func (tk *TrafficKeys) SecureZero() {
	secureZeroBytes(tk.Key)
	secureZeroBytes(tk.IV)
}
