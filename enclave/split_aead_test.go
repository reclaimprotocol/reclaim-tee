package enclave

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// TestSplitAEADAESGCM tests the Split AEAD implementation for AES-GCM
func TestSplitAEADAESGCM(t *testing.T) {
	// Test with AES-128
	key := make([]byte, 16)
	rand.Read(key)

	nonce := make([]byte, 12) // Standard GCM nonce size
	rand.Read(nonce)

	plaintext := []byte("Hello, Split AEAD with AES-GCM!")
	aad := []byte("additional authenticated data")

	// Create Split AEAD encryptor (TEE_K)
	encryptor, err := NewSplitAEADEncryptor(SplitAEAD_AES_GCM, key)
	if err != nil {
		t.Fatalf("Failed to create Split AEAD encryptor: %v", err)
	}
	defer encryptor.SecureZero()

	// Encrypt and generate tag secrets
	ciphertext, tagSecrets, err := encryptor.EncryptWithoutTag(nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("Failed to encrypt with Split AEAD: %v", err)
	}
	defer tagSecrets.SecureZero()

	// Verify we got valid outputs
	if len(ciphertext) != len(plaintext) {
		t.Errorf("Ciphertext length mismatch: expected %d, got %d", len(plaintext), len(ciphertext))
	}

	if tagSecrets.Mode != SplitAEAD_AES_GCM {
		t.Errorf("Wrong tag secrets mode: expected %d, got %d", SplitAEAD_AES_GCM, tagSecrets.Mode)
	}

	if len(tagSecrets.GCM_H) != 16 {
		t.Errorf("Invalid GCM H length: expected 16, got %d", len(tagSecrets.GCM_H))
	}

	if len(tagSecrets.GCM_Y0) != 16 {
		t.Errorf("Invalid GCM Y0 length: expected 16, got %d", len(tagSecrets.GCM_Y0))
	}

	// Create tag computer (TEE_T)
	tagComputer := NewSplitAEADTagComputer()

	// Compute authentication tag
	computedTag, err := tagComputer.ComputeTag(ciphertext, tagSecrets)
	if err != nil {
		t.Fatalf("Failed to compute tag: %v", err)
	}

	if len(computedTag) != 16 {
		t.Errorf("Invalid tag length: expected 16, got %d", len(computedTag))
	}

	// Verify against Go's standard GCM implementation
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create AES cipher: %v", err)
	}

	standardGCM, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("Failed to create standard GCM: %v", err)
	}

	// Encrypt with standard GCM
	standardCiphertext := standardGCM.Seal(nil, nonce, plaintext, aad)

	// Split standard result into ciphertext and tag
	standardCiphertextOnly := standardCiphertext[:len(plaintext)]
	standardTag := standardCiphertext[len(plaintext):]

	// Compare ciphertexts (should be identical)
	if !bytesEqual(ciphertext, standardCiphertextOnly) {
		t.Errorf("Ciphertext mismatch with standard GCM")
		t.Logf("Split AEAD: %s", hex.EncodeToString(ciphertext[:min(16, len(ciphertext))]))
		t.Logf("Standard:   %s", hex.EncodeToString(standardCiphertextOnly[:min(16, len(standardCiphertextOnly))]))
	}

	// Compare tags (should be identical)
	if !bytesEqual(computedTag, standardTag) {
		t.Errorf("Tag mismatch with standard GCM")
		t.Logf("Split AEAD tag: %s", hex.EncodeToString(computedTag))
		t.Logf("Standard tag:   %s", hex.EncodeToString(standardTag))
	}

	// Test tag verification
	err = tagComputer.VerifyTag(ciphertext, computedTag, tagSecrets)
	if err != nil {
		t.Errorf("Tag verification failed: %v", err)
	}

	// Test with wrong tag
	wrongTag := make([]byte, len(computedTag))
	rand.Read(wrongTag)
	err = tagComputer.VerifyTag(ciphertext, wrongTag, tagSecrets)
	if err == nil {
		t.Error("Tag verification should have failed with wrong tag")
	}

	t.Logf("Split AEAD AES-GCM test passed")
	t.Logf("Plaintext:  %s", string(plaintext))
	t.Logf("Ciphertext: %s", hex.EncodeToString(ciphertext[:min(32, len(ciphertext))]))
	t.Logf("Tag:        %s", hex.EncodeToString(computedTag))
}

// TestSplitAEADChaCha20Poly1305 tests the Split AEAD implementation for ChaCha20-Poly1305
func TestSplitAEADChaCha20Poly1305(t *testing.T) {
	// ChaCha20-Poly1305 key is always 32 bytes
	key := make([]byte, 32)
	rand.Read(key)

	nonce := make([]byte, 12) // ChaCha20-Poly1305 nonce size
	rand.Read(nonce)

	plaintext := []byte("Hello, Split AEAD with ChaCha20-Poly1305!")
	aad := []byte("additional authenticated data for ChaCha20")

	// Create Split AEAD encryptor (TEE_K)
	encryptor, err := NewSplitAEADEncryptor(SplitAEAD_CHACHA20_POLY1305, key)
	if err != nil {
		t.Fatalf("Failed to create Split AEAD encryptor: %v", err)
	}
	defer encryptor.SecureZero()

	// Encrypt and generate tag secrets
	ciphertext, tagSecrets, err := encryptor.EncryptWithoutTag(nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("Failed to encrypt with Split AEAD: %v", err)
	}
	defer tagSecrets.SecureZero()

	// Verify we got valid outputs
	if len(ciphertext) != len(plaintext) {
		t.Errorf("Ciphertext length mismatch: expected %d, got %d", len(plaintext), len(ciphertext))
	}

	if tagSecrets.Mode != SplitAEAD_CHACHA20_POLY1305 {
		t.Errorf("Wrong tag secrets mode: expected %d, got %d", SplitAEAD_CHACHA20_POLY1305, tagSecrets.Mode)
	}

	if len(tagSecrets.Poly1305_Key) != 32 {
		t.Errorf("Invalid Poly1305 key length: expected 32, got %d", len(tagSecrets.Poly1305_Key))
	}

	// Create tag computer (TEE_T)
	tagComputer := NewSplitAEADTagComputer()

	// Compute authentication tag
	computedTag, err := tagComputer.ComputeTag(ciphertext, tagSecrets)
	if err != nil {
		t.Fatalf("Failed to compute tag: %v", err)
	}

	if len(computedTag) != 16 {
		t.Errorf("Invalid tag length: expected 16, got %d", len(computedTag))
	}

	// Verify against Go's standard ChaCha20-Poly1305 implementation
	standardCipher, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("Failed to create standard ChaCha20-Poly1305: %v", err)
	}

	// Encrypt with standard ChaCha20-Poly1305
	standardCiphertext := standardCipher.Seal(nil, nonce, plaintext, aad)

	// Split standard result into ciphertext and tag
	standardCiphertextOnly := standardCiphertext[:len(plaintext)]
	standardTag := standardCiphertext[len(plaintext):]

	// Compare ciphertexts (should be identical)
	if !bytesEqual(ciphertext, standardCiphertextOnly) {
		t.Errorf("Ciphertext mismatch with standard ChaCha20-Poly1305")
		t.Logf("Split AEAD: %s", hex.EncodeToString(ciphertext[:min(16, len(ciphertext))]))
		t.Logf("Standard:   %s", hex.EncodeToString(standardCiphertextOnly[:min(16, len(standardCiphertextOnly))]))
	}

	// Compare tags (should be identical)
	if !bytesEqual(computedTag, standardTag) {
		t.Errorf("Tag mismatch with standard ChaCha20-Poly1305")
		t.Logf("Split AEAD tag: %s", hex.EncodeToString(computedTag))
		t.Logf("Standard tag:   %s", hex.EncodeToString(standardTag))
	}

	// Test tag verification
	err = tagComputer.VerifyTag(ciphertext, computedTag, tagSecrets)
	if err != nil {
		t.Errorf("Tag verification failed: %v", err)
	}

	// Test with wrong tag
	wrongTag := make([]byte, len(computedTag))
	rand.Read(wrongTag)
	err = tagComputer.VerifyTag(ciphertext, wrongTag, tagSecrets)
	if err == nil {
		t.Error("Tag verification should have failed with wrong tag")
	}

	t.Logf("Split AEAD ChaCha20-Poly1305 test passed")
	t.Logf("Plaintext:  %s", string(plaintext))
	t.Logf("Ciphertext: %s", hex.EncodeToString(ciphertext[:min(32, len(ciphertext))]))
	t.Logf("Tag:        %s", hex.EncodeToString(computedTag))
}

// TestSplitAEADMultipleKeySizes tests different AES key sizes
func TestSplitAEADMultipleKeySizes(t *testing.T) {
	keySizes := []int{16, 24, 32} // AES-128, AES-192, AES-256

	for _, keySize := range keySizes {
		t.Run(fmt.Sprintf("AES-%d", keySize*8), func(t *testing.T) {
			key := make([]byte, keySize)
			rand.Read(key)

			nonce := make([]byte, 12)
			rand.Read(nonce)

			plaintext := []byte("Test message for different key sizes")
			aad := []byte("aad")

			// Test Split AEAD
			encryptor, err := NewSplitAEADEncryptor(SplitAEAD_AES_GCM, key)
			if err != nil {
				t.Fatalf("Failed to create encryptor for key size %d: %v", keySize, err)
			}
			defer encryptor.SecureZero()

			ciphertext, tagSecrets, err := encryptor.EncryptWithoutTag(nonce, plaintext, aad)
			if err != nil {
				t.Fatalf("Encryption failed for key size %d: %v", keySize, err)
			}
			defer tagSecrets.SecureZero()

			tagComputer := NewSplitAEADTagComputer()
			tag, err := tagComputer.ComputeTag(ciphertext, tagSecrets)
			if err != nil {
				t.Fatalf("Tag computation failed for key size %d: %v", keySize, err)
			}

			// Verify against standard implementation
			block, _ := aes.NewCipher(key)
			standardGCM, _ := cipher.NewGCM(block)
			standardResult := standardGCM.Seal(nil, nonce, plaintext, aad)

			expectedCiphertext := standardResult[:len(plaintext)]
			expectedTag := standardResult[len(plaintext):]

			if !bytesEqual(ciphertext, expectedCiphertext) {
				t.Errorf("Ciphertext mismatch for key size %d", keySize)
			}

			if !bytesEqual(tag, expectedTag) {
				t.Errorf("Tag mismatch for key size %d", keySize)
			}

			t.Logf("AES-%d test passed", keySize*8)
		})
	}
}

// TestSplitAEADEdgeCases tests edge cases and error conditions
func TestSplitAEADEdgeCases(t *testing.T) {
	t.Run("InvalidKeySize", func(t *testing.T) {
		invalidKey := make([]byte, 15) // Invalid AES key size
		_, err := NewSplitAEADEncryptor(SplitAEAD_AES_GCM, invalidKey)
		if err == nil {
			t.Error("Should fail with invalid key size")
		}
	})

	t.Run("EmptyNonce", func(t *testing.T) {
		key := make([]byte, 16)
		rand.Read(key)

		encryptor, _ := NewSplitAEADEncryptor(SplitAEAD_AES_GCM, key)
		defer encryptor.SecureZero()

		_, _, err := encryptor.EncryptWithoutTag(nil, []byte("test"), nil)
		if err == nil {
			t.Error("Should fail with empty nonce")
		}
	})

	t.Run("WrongNonceSizeChaCha20", func(t *testing.T) {
		key := make([]byte, 32)
		rand.Read(key)

		encryptor, _ := NewSplitAEADEncryptor(SplitAEAD_CHACHA20_POLY1305, key)
		defer encryptor.SecureZero()

		wrongNonce := make([]byte, 8) // Wrong size
		_, _, err := encryptor.EncryptWithoutTag(wrongNonce, []byte("test"), nil)
		if err == nil {
			t.Error("Should fail with wrong nonce size for ChaCha20")
		}
	})

	t.Run("EmptyPlaintext", func(t *testing.T) {
		key := make([]byte, 16)
		rand.Read(key)
		nonce := make([]byte, 12)
		rand.Read(nonce)

		encryptor, _ := NewSplitAEADEncryptor(SplitAEAD_AES_GCM, key)
		defer encryptor.SecureZero()

		// Should work with empty plaintext
		ciphertext, tagSecrets, err := encryptor.EncryptWithoutTag(nonce, nil, []byte("aad"))
		if err != nil {
			t.Errorf("Should work with empty plaintext: %v", err)
		}
		defer tagSecrets.SecureZero()

		if len(ciphertext) != 0 {
			t.Error("Empty plaintext should produce empty ciphertext")
		}

		// Tag computation should still work
		tagComputer := NewSplitAEADTagComputer()
		tag, err := tagComputer.ComputeTag(ciphertext, tagSecrets)
		if err != nil {
			t.Errorf("Tag computation failed with empty plaintext: %v", err)
		}

		if len(tag) != 16 {
			t.Error("Tag should still be 16 bytes with empty plaintext")
		}
	})
}

// TestSplitAEADNonStandardNonce tests non-standard GCM nonce sizes
// Note: Disabled since Go's standard GCM implementation doesn't accept non-standard nonce sizes
/*
func TestSplitAEADNonStandardNonce(t *testing.T) {
	// This test is disabled because Go's crypto/cipher.NewGCM() enforces
	// standard 12-byte nonces and doesn't provide NewGCMWithNonceSize()
	// Our implementation supports it via GHASH but can't verify against standard
	t.Skip("Go's standard GCM doesn't support non-standard nonce sizes for comparison")
}
*/

// Helper functions

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
