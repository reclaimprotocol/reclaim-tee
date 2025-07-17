package minitls

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestTLS12AEADBasic tests basic TLS 1.2 AEAD encrypt/decrypt functionality
func TestTLS12AEADBasic(t *testing.T) {
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
		{
			name:        "ChaCha20-Poly1305",
			cipherSuite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			keyLen:      32,
			ivLen:       12,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate test keys and IVs
			writeKey := make([]byte, tc.keyLen)
			writeIV := make([]byte, tc.ivLen)
			readKey := make([]byte, tc.keyLen)
			readIV := make([]byte, tc.ivLen)

			if _, err := rand.Read(writeKey); err != nil {
				t.Fatalf("Failed to generate write key: %v", err)
			}
			if _, err := rand.Read(writeIV); err != nil {
				t.Fatalf("Failed to generate write IV: %v", err)
			}
			if _, err := rand.Read(readKey); err != nil {
				t.Fatalf("Failed to generate read key: %v", err)
			}
			if _, err := rand.Read(readIV); err != nil {
				t.Fatalf("Failed to generate read IV: %v", err)
			}

			// Create AEAD contexts (simulate client/server)
			clientCtx, err := NewTLS12AEADContext(writeKey, writeIV, readKey, readIV, tc.cipherSuite)
			if err != nil {
				t.Fatalf("Failed to create client AEAD context: %v", err)
			}

			serverCtx, err := NewTLS12AEADContext(readKey, readIV, writeKey, writeIV, tc.cipherSuite)
			if err != nil {
				t.Fatalf("Failed to create server AEAD context: %v", err)
			}

			// Test data
			plaintext := []byte("Hello, TLS 1.2 AEAD encryption!")
			recordHeader := []byte{23, 0x03, 0x03, 0x00, 0x20} // Application data record header

			// Client encrypts
			ciphertext, err := clientCtx.Encrypt(plaintext, recordHeader)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Server decrypts
			decrypted, err := serverCtx.Decrypt(ciphertext, recordHeader)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify
			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("Decrypted text doesn't match original:\nOriginal:  %q\nDecrypted: %q", plaintext, decrypted)
			}

			t.Logf("✅ %s: Successfully encrypted/decrypted %d bytes", tc.name, len(plaintext))
		})
	}
}

// TestTLS12AEADSequenceNumbers tests that sequence numbers work correctly
func TestTLS12AEADSequenceNumbers(t *testing.T) {
	// Use AES-128-GCM for this test
	cipherSuite := uint16(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)

	// Generate test keys
	writeKey := make([]byte, 16)
	writeIV := make([]byte, 4)
	readKey := make([]byte, 16)
	readIV := make([]byte, 4)

	rand.Read(writeKey)
	rand.Read(writeIV)
	rand.Read(readKey)
	rand.Read(readIV)

	// Create AEAD contexts
	clientCtx, err := NewTLS12AEADContext(writeKey, writeIV, readKey, readIV, cipherSuite)
	if err != nil {
		t.Fatalf("Failed to create client AEAD context: %v", err)
	}

	serverCtx, err := NewTLS12AEADContext(readKey, readIV, writeKey, writeIV, cipherSuite)
	if err != nil {
		t.Fatalf("Failed to create server AEAD context: %v", err)
	}

	// Test multiple messages with incrementing sequence numbers
	messages := []string{
		"First message",
		"Second message with different content",
		"Third message is even longer and has more data to encrypt",
	}

	recordHeader := []byte{23, 0x03, 0x03, 0x00, 0x30}

	for i, msg := range messages {
		// Check sequence numbers before encryption
		expectedSeq := uint64(i)
		if clientCtx.GetWriteSequence() != expectedSeq {
			t.Errorf("Client write sequence = %d, want %d", clientCtx.GetWriteSequence(), expectedSeq)
		}
		if serverCtx.GetReadSequence() != expectedSeq {
			t.Errorf("Server read sequence = %d, want %d", serverCtx.GetReadSequence(), expectedSeq)
		}

		// Encrypt and decrypt
		plaintext := []byte(msg)
		ciphertext, err := clientCtx.Encrypt(plaintext, recordHeader)
		if err != nil {
			t.Fatalf("Message %d encryption failed: %v", i, err)
		}

		decrypted, err := serverCtx.Decrypt(ciphertext, recordHeader)
		if err != nil {
			t.Fatalf("Message %d decryption failed: %v", i, err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("Message %d: decrypted text doesn't match original", i)
		}

		// Check sequence numbers after encryption
		expectedSeqAfter := uint64(i + 1)
		if clientCtx.GetWriteSequence() != expectedSeqAfter {
			t.Errorf("Client write sequence after = %d, want %d", clientCtx.GetWriteSequence(), expectedSeqAfter)
		}
		if serverCtx.GetReadSequence() != expectedSeqAfter {
			t.Errorf("Server read sequence after = %d, want %d", serverCtx.GetReadSequence(), expectedSeqAfter)
		}

		t.Logf("Message %d (seq=%d): ✅ %d bytes", i, expectedSeq, len(plaintext))
	}
}

// TestTLS12AEADKeyLengthValidation tests key and IV length validation
func TestTLS12AEADKeyLengthValidation(t *testing.T) {
	testCases := []struct {
		name        string
		cipherSuite uint16
		writeKeyLen int
		writeIVLen  int
		readKeyLen  int
		readIVLen   int
		expectError bool
	}{
		{
			name:        "Valid AES-128-GCM",
			cipherSuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			writeKeyLen: 16,
			writeIVLen:  4,
			readKeyLen:  16,
			readIVLen:   4,
			expectError: false,
		},
		{
			name:        "Invalid write key length",
			cipherSuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			writeKeyLen: 32, // Wrong length for AES-128
			writeIVLen:  4,
			readKeyLen:  16,
			readIVLen:   4,
			expectError: true,
		},
		{
			name:        "Invalid IV length",
			cipherSuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			writeKeyLen: 16,
			writeIVLen:  12, // Wrong length for GCM
			readKeyLen:  16,
			readIVLen:   4,
			expectError: true,
		},
		{
			name:        "Valid ChaCha20-Poly1305",
			cipherSuite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			writeKeyLen: 32,
			writeIVLen:  12,
			readKeyLen:  32,
			readIVLen:   12,
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			writeKey := make([]byte, tc.writeKeyLen)
			writeIV := make([]byte, tc.writeIVLen)
			readKey := make([]byte, tc.readKeyLen)
			readIV := make([]byte, tc.readIVLen)

			_, err := NewTLS12AEADContext(writeKey, writeIV, readKey, readIV, tc.cipherSuite)

			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestTLS12AEADWrongSequence tests that wrong sequence numbers cause decryption failures
func TestTLS12AEADWrongSequence(t *testing.T) {
	// Create contexts
	writeKey := make([]byte, 16)
	writeIV := make([]byte, 4)
	readKey := make([]byte, 16)
	readIV := make([]byte, 4)

	rand.Read(writeKey)
	rand.Read(writeIV)
	rand.Read(readKey)
	rand.Read(readIV)

	clientCtx, err := NewTLS12AEADContext(writeKey, writeIV, readKey, readIV, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create client context: %v", err)
	}

	serverCtx, err := NewTLS12AEADContext(readKey, readIV, writeKey, writeIV, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create server context: %v", err)
	}

	plaintext := []byte("Test message")
	recordHeader := []byte{23, 0x03, 0x03, 0x00, 0x0C}

	// Encrypt a message
	ciphertext, err := clientCtx.Encrypt(plaintext, recordHeader)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Now artificially advance the server's read sequence
	serverCtx.readSeq++ // This will cause sequence mismatch

	// Try to decrypt - should fail
	_, err = serverCtx.Decrypt(ciphertext, recordHeader)
	if err == nil {
		t.Error("Expected decryption to fail with wrong sequence number, but it succeeded")
	}

	t.Logf("✅ Correctly detected sequence number mismatch: %v", err)
}
