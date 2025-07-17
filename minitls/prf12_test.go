package minitls

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// TestTLS12PRF tests the basic TLS 1.2 PRF function
func TestTLS12PRF(t *testing.T) {
	// Test vectors based on known TLS 1.2 PRF behavior
	testCases := []struct {
		name        string
		cipherSuite uint16
		secret      string
		label       string
		seed        string
		length      int
	}{
		{
			name:        "AES-128-GCM with SHA-256",
			cipherSuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			secret:      "0123456789abcdef0123456789abcdef",
			label:       "test label",
			seed:        "fedcba9876543210fedcba9876543210",
			length:      32,
		},
		{
			name:        "AES-256-GCM with SHA-384",
			cipherSuite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			secret:      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			label:       "master secret",
			seed:        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
			length:      48,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			secret, _ := hex.DecodeString(tc.secret)
			seed, _ := hex.DecodeString(tc.seed)

			result := prf12(tc.cipherSuite, secret, tc.label, seed, tc.length)

			// Verify length
			if len(result) != tc.length {
				t.Errorf("Expected length %d, got %d", tc.length, len(result))
			}

			// Verify determinism - same inputs should give same output
			result2 := prf12(tc.cipherSuite, secret, tc.label, seed, tc.length)
			if !bytes.Equal(result, result2) {
				t.Error("PRF is not deterministic - same inputs gave different outputs")
			}

			// Verify output is not all zeros
			allZeros := make([]byte, tc.length)
			if bytes.Equal(result, allZeros) {
				t.Error("PRF output is all zeros, which is suspicious")
			}

			t.Logf("✅ %s: Generated %d bytes PRF output", tc.name, len(result))
		})
	}
}

// TestTLS12KeySchedule tests the TLS 1.2 key schedule implementation
func TestTLS12KeySchedule(t *testing.T) {
	testCases := []struct {
		name        string
		cipherSuite uint16
		keyLen      int
		ivLen       int
	}{
		{
			name:        "AES-128-GCM",
			cipherSuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			keyLen:      16,
			ivLen:       4,
		},
		{
			name:        "AES-256-GCM",
			cipherSuite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			keyLen:      32,
			ivLen:       4,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate test data
			preMasterSecret := make([]byte, 48)
			clientRandom := make([]byte, 32)
			serverRandom := make([]byte, 32)

			rand.Read(preMasterSecret)
			rand.Read(clientRandom)
			rand.Read(serverRandom)

			// Create key schedule
			ks := NewTLS12KeySchedule(tc.cipherSuite, nil, clientRandom, serverRandom)

			// Derive master secret
			ks.DeriveMasterSecret(preMasterSecret)

			// Verify master secret length
			if len(ks.masterSecret) != 48 {
				t.Errorf("Master secret length: got %d, want 48", len(ks.masterSecret))
			}

			// Derive keys
			clientWriteKey, clientWriteIV, serverWriteKey, serverWriteIV, err := ks.DeriveKeys()
			if err != nil {
				t.Fatalf("Failed to derive keys: %v", err)
			}

			// Verify key lengths
			if len(clientWriteKey) != tc.keyLen {
				t.Errorf("Client write key length: got %d, want %d", len(clientWriteKey), tc.keyLen)
			}
			if len(serverWriteKey) != tc.keyLen {
				t.Errorf("Server write key length: got %d, want %d", len(serverWriteKey), tc.keyLen)
			}
			if len(clientWriteIV) != tc.ivLen {
				t.Errorf("Client write IV length: got %d, want %d", len(clientWriteIV), tc.ivLen)
			}
			if len(serverWriteIV) != tc.ivLen {
				t.Errorf("Server write IV length: got %d, want %d", len(serverWriteIV), tc.ivLen)
			}

			// Verify keys are different from each other
			if bytes.Equal(clientWriteKey, serverWriteKey) {
				t.Error("Client and server write keys are identical")
			}
			if bytes.Equal(clientWriteIV, serverWriteIV) {
				t.Error("Client and server write IVs are identical")
			}

			t.Logf("✅ %s: Derived keys successfully", tc.name)
		})
	}
}
