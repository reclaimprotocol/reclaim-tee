package minitls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestSplitAEADvsStandardGCM(t *testing.T) {
	testCases := []struct {
		name        string
		keySize     int
		cipherSuite uint16
	}{
		{
			name:        "AES-128-GCM",
			keySize:     16,
			cipherSuite: TLS_AES_128_GCM_SHA256,
		},
		{
			name:        "AES-256-GCM",
			keySize:     32,
			cipherSuite: TLS_AES_256_GCM_SHA384,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test data
			key := make([]byte, tc.keySize)
			iv := make([]byte, 4)         // TLS 1.2 implicit IV
			explicitIV := make([]byte, 8) // TLS 1.2 explicit IV
			plaintext := []byte("Hello, World! This is a test message for AES-GCM encryption.")
			aad := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x17, 0x03, 0x03, 0x00, 0x3e} // TLS 1.2 AAD

			// Fill with random data
			rand.Read(key)
			rand.Read(iv)
			rand.Read(explicitIV)

			t.Logf("Key: %s", hex.EncodeToString(key))
			t.Logf("IV: %s", hex.EncodeToString(iv))
			t.Logf("Explicit IV: %s", hex.EncodeToString(explicitIV))
			t.Logf("Plaintext: %s", string(plaintext))
			t.Logf("AAD: %s", hex.EncodeToString(aad))

			// === Standard Go AES-GCM ===
			block, err := aes.NewCipher(key)
			if err != nil {
				t.Fatalf("Failed to create AES cipher: %v", err)
			}

			gcm, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatalf("Failed to create GCM: %v", err)
			}

			// TLS 1.2 nonce: implicit_iv(4) || explicit_iv(8) = 12 bytes
			nonce := make([]byte, 12)
			copy(nonce[0:4], iv)
			copy(nonce[4:12], explicitIV)

			// Encrypt with standard GCM
			standardCiphertext := gcm.Seal(nil, nonce, plaintext, aad)
			standardEncrypted := standardCiphertext[:len(plaintext)]
			standardTag := standardCiphertext[len(plaintext):]

			t.Logf("Standard nonce: %s", hex.EncodeToString(nonce))
			t.Logf("Standard encrypted: %s", hex.EncodeToString(standardEncrypted))
			t.Logf("Standard tag: %s", hex.EncodeToString(standardTag))

			// === Split AEAD (TEE_K style) ===

			// Generate keystream using AES-CTR (matching Go GCM)
			// Go GCM uses counter 2 for first plaintext block (counter 1 is for tag generation)
			ctrNonce := make([]byte, 16)
			copy(ctrNonce, nonce) // Copy 12-byte GCM nonce
			ctrNonce[15] = 2      // Set counter to 2 (matching Go GCM)

			stream := cipher.NewCTR(block, ctrNonce)
			splitEncrypted := make([]byte, len(plaintext))
			stream.XORKeyStream(splitEncrypted, plaintext)

			// Generate tag secrets for Split AEAD using existing implementation
			splitAEAD := &SplitAEAD{
				key:         key,
				iv:          iv,
				cipherSuite: tc.cipherSuite,
				seq:         1,
			}
			tagSecrets := splitAEAD.generateGCMTagSecrets(block, nonce)

			// Compute tag using ComputeTagFromSecrets
			splitTag, err := ComputeTagFromSecrets(splitEncrypted, tagSecrets, tc.cipherSuite, aad)
			if err != nil {
				t.Fatalf("Failed to compute split AEAD tag: %v", err)
			}

			t.Logf("Split encrypted: %s", hex.EncodeToString(splitEncrypted))
			t.Logf("Split tag: %s", hex.EncodeToString(splitTag))
			t.Logf("Tag secrets: %s", hex.EncodeToString(tagSecrets))

			// === Compare Results ===
			if hex.EncodeToString(standardEncrypted) != hex.EncodeToString(splitEncrypted) {
				t.Errorf("Encrypted data mismatch!\nStandard: %s\nSplit:    %s",
					hex.EncodeToString(standardEncrypted),
					hex.EncodeToString(splitEncrypted))
			}

			if hex.EncodeToString(standardTag) != hex.EncodeToString(splitTag) {
				t.Errorf("Tag mismatch!\nStandard: %s\nSplit:    %s",
					hex.EncodeToString(standardTag),
					hex.EncodeToString(splitTag))
			}

			// === Test Decryption ===

			// Standard decryption
			decrypted1, err := gcm.Open(nil, nonce, standardCiphertext, aad)
			if err != nil {
				t.Fatalf("Standard decryption failed: %v", err)
			}

			// Split decryption (keystream approach)
			stream2 := cipher.NewCTR(block, ctrNonce)
			decrypted2 := make([]byte, len(splitEncrypted))
			stream2.XORKeyStream(decrypted2, splitEncrypted)

			if string(decrypted1) != string(plaintext) {
				t.Errorf("Standard decryption incorrect: got %s, want %s", string(decrypted1), string(plaintext))
			}

			if string(decrypted2) != string(plaintext) {
				t.Errorf("Split decryption incorrect: got %s, want %s", string(decrypted2), string(plaintext))
			}

			if string(decrypted1) != string(decrypted2) {
				t.Errorf("Decryption mismatch!\nStandard: %s\nSplit:    %s", string(decrypted1), string(decrypted2))
			}

			t.Logf("✅ %s: All tests passed!", tc.name)
		})
	}
}
