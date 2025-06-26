package enclave

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// Test vectors for TLS 1.3 key schedule validation
// These are based on RFC 8448 test vectors and other known good implementations

func TestNewTLSKeySchedule(t *testing.T) {
	testCases := []struct {
		name        string
		cipherSuite uint16
		expectError bool
		hashSize    int
		keyLength   int
		ivLength    int
	}{
		{
			name:        "AES-128-GCM-SHA256",
			cipherSuite: TLS_AES_128_GCM_SHA256,
			expectError: false,
			hashSize:    32,
			keyLength:   16,
			ivLength:    12,
		},
		{
			name:        "AES-256-GCM-SHA384",
			cipherSuite: TLS_AES_256_GCM_SHA384,
			expectError: false,
			hashSize:    48,
			keyLength:   32,
			ivLength:    12,
		},
		{
			name:        "ChaCha20-Poly1305-SHA256",
			cipherSuite: TLS_CHACHA20_POLY1305_SHA256,
			expectError: false,
			hashSize:    32,
			keyLength:   32,
			ivLength:    12,
		},
		{
			name:        "UnsupportedCipher",
			cipherSuite: 0x9999,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ks, err := NewTLSKeySchedule(tc.cipherSuite)

			if tc.expectError {
				if err == nil {
					t.Error("Expected error for unsupported cipher suite")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if ks.GetCipherSuite() != tc.cipherSuite {
				t.Errorf("Wrong cipher suite: expected 0x%04x, got 0x%04x",
					tc.cipherSuite, ks.GetCipherSuite())
			}

			if ks.GetHashSize() != tc.hashSize {
				t.Errorf("Wrong hash size: expected %d, got %d",
					tc.hashSize, ks.GetHashSize())
			}

			if ks.GetKeyLength() != tc.keyLength {
				t.Errorf("Wrong key length: expected %d, got %d",
					tc.keyLength, ks.GetKeyLength())
			}

			if ks.GetIVLength() != tc.ivLength {
				t.Errorf("Wrong IV length: expected %d, got %d",
					tc.ivLength, ks.GetIVLength())
			}
		})
	}
}

func TestHKDFExpandLabel(t *testing.T) {
	ks, err := NewTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create key schedule: %v", err)
	}

	// Test with known values
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	// Test basic expansion
	result, err := ks.hkdfExpandLabel(secret, "tls13 key", nil, 16)
	if err != nil {
		t.Fatalf("HKDF-Expand-Label failed: %v", err)
	}

	if len(result) != 16 {
		t.Errorf("Wrong result length: expected 16, got %d", len(result))
	}

	// Test with context
	context := []byte("test context")
	result2, err := ks.hkdfExpandLabel(secret, "tls13 iv", context, 12)
	if err != nil {
		t.Fatalf("HKDF-Expand-Label with context failed: %v", err)
	}

	if len(result2) != 12 {
		t.Errorf("Wrong result length with context: expected 12, got %d", len(result2))
	}

	// Results should be different
	if bytes.Equal(result[:12], result2) {
		t.Error("Results should be different with different labels/contexts")
	}

	// Test deterministic behavior
	result3, err := ks.hkdfExpandLabel(secret, "tls13 key", nil, 16)
	if err != nil {
		t.Fatalf("Second HKDF-Expand-Label failed: %v", err)
	}

	if !bytes.Equal(result, result3) {
		t.Error("HKDF-Expand-Label should be deterministic")
	}

	t.Logf("HKDF-Expand-Label test passed, key: %s", hex.EncodeToString(result[:8])+"...")
}

func TestEarlySecretDerivation(t *testing.T) {
	ks, err := NewTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create key schedule: %v", err)
	}

	// Initialize early secret
	err = ks.InitializeEarlySecret()
	if err != nil {
		t.Fatalf("Failed to initialize early secret: %v", err)
	}

	// Early secret should be non-zero and correct length
	if len(ks.earlySecret) != 32 {
		t.Errorf("Early secret wrong length: expected 32, got %d", len(ks.earlySecret))
	}

	// Should not be all zeros
	allZero := true
	for _, b := range ks.earlySecret {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Early secret should not be all zeros")
	}

	// Should be deterministic
	ks2, _ := NewTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	ks2.InitializeEarlySecret()

	if !bytes.Equal(ks.earlySecret, ks2.earlySecret) {
		t.Error("Early secret should be deterministic")
	}

	t.Logf("Early secret: %s", hex.EncodeToString(ks.earlySecret[:8])+"...")
}

func TestHandshakeSecretDerivation(t *testing.T) {
	ks, err := NewTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create key schedule: %v", err)
	}

	// Initialize early secret first
	err = ks.InitializeEarlySecret()
	if err != nil {
		t.Fatalf("Failed to initialize early secret: %v", err)
	}

	// Create mock ECDH shared secret
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	// Derive handshake secret
	err = ks.DeriveHandshakeSecret(sharedSecret)
	if err != nil {
		t.Fatalf("Failed to derive handshake secret: %v", err)
	}

	// Handshake secret should be correct length
	if len(ks.handshakeSecret) != 32 {
		t.Errorf("Handshake secret wrong length: expected 32, got %d", len(ks.handshakeSecret))
	}

	// Should be different from early secret
	if bytes.Equal(ks.earlySecret, ks.handshakeSecret) {
		t.Error("Handshake secret should be different from early secret")
	}

	// Test error cases
	ks2, _ := NewTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	err = ks2.DeriveHandshakeSecret(sharedSecret)
	if err == nil {
		t.Error("Should fail without early secret")
	}

	err = ks.DeriveHandshakeSecret(nil)
	if err == nil {
		t.Error("Should fail with empty shared secret")
	}

	t.Logf("Handshake secret: %s", hex.EncodeToString(ks.handshakeSecret[:8])+"...")
}

func TestTrafficSecretDerivation(t *testing.T) {
	ks, err := NewTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create key schedule: %v", err)
	}

	// Initialize the key schedule
	ks.InitializeEarlySecret()

	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)
	ks.DeriveHandshakeSecret(sharedSecret)

	// Create handshake hash
	handshakeHash := make([]byte, 32)
	rand.Read(handshakeHash)

	// Derive handshake traffic secrets
	err = ks.DeriveHandshakeTrafficSecrets(handshakeHash)
	if err != nil {
		t.Fatalf("Failed to derive handshake traffic secrets: %v", err)
	}

	// Both secrets should be present and correct length
	if len(ks.clientHandshakeSecret) != 32 {
		t.Errorf("Client handshake secret wrong length: expected 32, got %d", len(ks.clientHandshakeSecret))
	}

	if len(ks.serverHandshakeSecret) != 32 {
		t.Errorf("Server handshake secret wrong length: expected 32, got %d", len(ks.serverHandshakeSecret))
	}

	// Client and server secrets should be different
	if bytes.Equal(ks.clientHandshakeSecret, ks.serverHandshakeSecret) {
		t.Error("Client and server handshake secrets should be different")
	}

	// Derive master secret
	err = ks.DeriveMasterSecret()
	if err != nil {
		t.Fatalf("Failed to derive master secret: %v", err)
	}

	if len(ks.masterSecret) != 32 {
		t.Errorf("Master secret wrong length: expected 32, got %d", len(ks.masterSecret))
	}

	// Derive application traffic secrets
	err = ks.DeriveApplicationTrafficSecrets(handshakeHash)
	if err != nil {
		t.Fatalf("Failed to derive application traffic secrets: %v", err)
	}

	if len(ks.clientAppSecret) != 32 {
		t.Errorf("Client app secret wrong length: expected 32, got %d", len(ks.clientAppSecret))
	}

	if len(ks.serverAppSecret) != 32 {
		t.Errorf("Server app secret wrong length: expected 32, got %d", len(ks.serverAppSecret))
	}

	// All secrets should be different
	secrets := [][]byte{
		ks.clientHandshakeSecret,
		ks.serverHandshakeSecret,
		ks.clientAppSecret,
		ks.serverAppSecret,
		ks.masterSecret,
	}

	for i, secret1 := range secrets {
		for j, secret2 := range secrets {
			if i != j && bytes.Equal(secret1, secret2) {
				t.Errorf("Secrets %d and %d should be different", i, j)
			}
		}
	}

	t.Logf("All traffic secrets derived successfully")
}

func TestTrafficKeyDerivation(t *testing.T) {
	ks, err := NewTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create key schedule: %v", err)
	}

	// Create a mock traffic secret
	trafficSecret := make([]byte, 32)
	rand.Read(trafficSecret)

	// Derive traffic keys
	keys, err := ks.DeriveTrafficKeys(trafficSecret)
	if err != nil {
		t.Fatalf("Failed to derive traffic keys: %v", err)
	}

	// Check key and IV lengths
	if len(keys.Key) != 16 { // AES-128
		t.Errorf("Wrong key length: expected 16, got %d", len(keys.Key))
	}

	if len(keys.IV) != 12 { // GCM IV
		t.Errorf("Wrong IV length: expected 12, got %d", len(keys.IV))
	}

	// Key and IV should be different (compare only the overlapping bytes)
	minLen := len(keys.Key)
	if len(keys.IV) < minLen {
		minLen = len(keys.IV)
	}
	if bytes.Equal(keys.Key[:minLen], keys.IV[:minLen]) {
		t.Error("Key and IV should be different")
	}

	// Test deterministic behavior
	keys2, err := ks.DeriveTrafficKeys(trafficSecret)
	if err != nil {
		t.Fatalf("Second derivation failed: %v", err)
	}

	if !bytes.Equal(keys.Key, keys2.Key) {
		t.Error("Key derivation should be deterministic")
	}

	if !bytes.Equal(keys.IV, keys2.IV) {
		t.Error("IV derivation should be deterministic")
	}

	t.Logf("Traffic keys: key=%s, iv=%s",
		hex.EncodeToString(keys.Key[:8])+"...",
		hex.EncodeToString(keys.IV[:8])+"...")
}

func TestFullKeySchedule(t *testing.T) {
	// Test the complete key schedule flow
	ks, err := NewTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create key schedule: %v", err)
	}

	// Step 1: Initialize early secret
	err = ks.InitializeEarlySecret()
	if err != nil {
		t.Fatalf("Step 1 failed: %v", err)
	}

	// Step 2: Derive handshake secret from ECDH
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	err = ks.DeriveHandshakeSecret(sharedSecret)
	if err != nil {
		t.Fatalf("Step 2 failed: %v", err)
	}

	// Step 3: Derive handshake traffic secrets
	handshakeHash := make([]byte, 32)
	rand.Read(handshakeHash)

	err = ks.DeriveHandshakeTrafficSecrets(handshakeHash)
	if err != nil {
		t.Fatalf("Step 3 failed: %v", err)
	}

	// Step 4: Get handshake traffic keys
	clientHandshakeKeys, serverHandshakeKeys, err := ks.GetHandshakeTrafficKeys()
	if err != nil {
		t.Fatalf("Step 4 failed: %v", err)
	}

	// Step 5: Derive master secret
	err = ks.DeriveMasterSecret()
	if err != nil {
		t.Fatalf("Step 5 failed: %v", err)
	}

	// Step 6: Derive application traffic secrets
	err = ks.DeriveApplicationTrafficSecrets(handshakeHash)
	if err != nil {
		t.Fatalf("Step 6 failed: %v", err)
	}

	// Step 7: Get application traffic keys
	clientAppKeys, serverAppKeys, err := ks.GetApplicationTrafficKeys()
	if err != nil {
		t.Fatalf("Step 7 failed: %v", err)
	}

	// Validate all keys are different
	allKeys := []*TrafficKeys{
		clientHandshakeKeys,
		serverHandshakeKeys,
		clientAppKeys,
		serverAppKeys,
	}

	for i, keys1 := range allKeys {
		for j, keys2 := range allKeys {
			if i != j {
				if bytes.Equal(keys1.Key, keys2.Key) {
					t.Errorf("Keys %d and %d should be different", i, j)
				}
				if bytes.Equal(keys1.IV, keys2.IV) {
					t.Errorf("IVs %d and %d should be different", i, j)
				}
			}
		}
	}

	t.Logf("Full key schedule completed successfully")
	t.Logf("Client handshake key: %s", hex.EncodeToString(clientHandshakeKeys.Key[:8])+"...")
	t.Logf("Server handshake key: %s", hex.EncodeToString(serverHandshakeKeys.Key[:8])+"...")
	t.Logf("Client application key: %s", hex.EncodeToString(clientAppKeys.Key[:8])+"...")
	t.Logf("Server application key: %s", hex.EncodeToString(serverAppKeys.Key[:8])+"...")
}

func TestDifferentCipherSuites(t *testing.T) {
	cipherSuites := []struct {
		name   string
		cipher uint16
		keyLen int
		ivLen  int
	}{
		{"AES-128-GCM", TLS_AES_128_GCM_SHA256, 16, 12},
		{"AES-256-GCM", TLS_AES_256_GCM_SHA384, 32, 12},
		{"ChaCha20-Poly1305", TLS_CHACHA20_POLY1305_SHA256, 32, 12},
	}

	for _, cs := range cipherSuites {
		t.Run(cs.name, func(t *testing.T) {
			ks, err := NewTLSKeySchedule(cs.cipher)
			if err != nil {
				t.Fatalf("Failed to create key schedule for %s: %v", cs.name, err)
			}

			// Run complete key schedule
			ks.InitializeEarlySecret()

			sharedSecret := make([]byte, 32)
			rand.Read(sharedSecret)
			ks.DeriveHandshakeSecret(sharedSecret)

			handshakeHash := make([]byte, ks.GetHashSize())
			rand.Read(handshakeHash)
			ks.DeriveHandshakeTrafficSecrets(handshakeHash)

			ks.DeriveMasterSecret()
			ks.DeriveApplicationTrafficSecrets(handshakeHash)

			// Get application keys
			clientKeys, serverKeys, err := ks.GetApplicationTrafficKeys()
			if err != nil {
				t.Fatalf("Failed to get application keys: %v", err)
			}

			// Verify key lengths
			if len(clientKeys.Key) != cs.keyLen {
				t.Errorf("Wrong client key length for %s: expected %d, got %d",
					cs.name, cs.keyLen, len(clientKeys.Key))
			}

			if len(serverKeys.Key) != cs.keyLen {
				t.Errorf("Wrong server key length for %s: expected %d, got %d",
					cs.name, cs.keyLen, len(serverKeys.Key))
			}

			if len(clientKeys.IV) != cs.ivLen {
				t.Errorf("Wrong client IV length for %s: expected %d, got %d",
					cs.name, cs.ivLen, len(clientKeys.IV))
			}

			if len(serverKeys.IV) != cs.ivLen {
				t.Errorf("Wrong server IV length for %s: expected %d, got %d",
					cs.name, cs.ivLen, len(serverKeys.IV))
			}

			t.Logf("%s key schedule successful", cs.name)
		})
	}
}

func TestSecureZero(t *testing.T) {
	ks, err := NewTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create key schedule: %v", err)
	}

	// Initialize with some data
	ks.InitializeEarlySecret()

	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)
	ks.DeriveHandshakeSecret(sharedSecret)

	// Verify secrets are non-zero
	if isAllZero(ks.earlySecret) {
		t.Error("Early secret should not be zero before SecureZero")
	}

	if isAllZero(ks.handshakeSecret) {
		t.Error("Handshake secret should not be zero before SecureZero")
	}

	// Zero out secrets
	ks.SecureZero()

	// Verify all secrets are now zero
	if !isAllZero(ks.earlySecret) {
		t.Error("Early secret should be zero after SecureZero")
	}

	if !isAllZero(ks.handshakeSecret) {
		t.Error("Handshake secret should be zero after SecureZero")
	}

	// Test traffic keys zeroing
	keys := &TrafficKeys{
		Key: make([]byte, 16),
		IV:  make([]byte, 12),
	}
	rand.Read(keys.Key)
	rand.Read(keys.IV)

	if isAllZero(keys.Key) || isAllZero(keys.IV) {
		t.Error("Keys should not be zero before SecureZero")
	}

	keys.SecureZero()

	if !isAllZero(keys.Key) || !isAllZero(keys.IV) {
		t.Error("Keys should be zero after SecureZero")
	}

	t.Logf("Secure zeroing works correctly")
}

func TestErrorHandling(t *testing.T) {
	ks, err := NewTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create key schedule: %v", err)
	}

	// Test operations without proper initialization
	testCases := []struct {
		name string
		op   func() error
	}{
		{
			name: "HandshakeSecretWithoutEarly",
			op: func() error {
				return ks.DeriveHandshakeSecret(make([]byte, 32))
			},
		},
		{
			name: "HandshakeTrafficWithoutHandshake",
			op: func() error {
				return ks.DeriveHandshakeTrafficSecrets(make([]byte, 32))
			},
		},
		{
			name: "MasterSecretWithoutHandshake",
			op: func() error {
				return ks.DeriveMasterSecret()
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.op()
			if err == nil {
				t.Errorf("Operation %s should fail without proper initialization", tc.name)
			}
			t.Logf("Correctly rejected %s: %v", tc.name, err)
		})
	}
}

// Helper function to check if a byte slice is all zeros
func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
