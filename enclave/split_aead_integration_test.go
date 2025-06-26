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

// TestSplitAEADIntegration tests the complete Split AEAD flow
// This simulates the protocol flow between TEE_K and TEE_T
func TestSplitAEADIntegration(t *testing.T) {
	t.Run("AES-GCM Integration", func(t *testing.T) {
		testSplitAEADIntegration(t, SplitAEAD_AES_GCM, 16)
	})

	t.Run("ChaCha20-Poly1305 Integration", func(t *testing.T) {
		testSplitAEADIntegration(t, SplitAEAD_CHACHA20_POLY1305, 32)
	})
}

func testSplitAEADIntegration(t *testing.T, mode SplitAEADMode, keySize int) {
	// Simulate TLS session keys
	key := make([]byte, keySize)
	rand.Read(key)

	var nonceSize int
	switch mode {
	case SplitAEAD_AES_GCM:
		nonceSize = 12 // GCM standard nonce
	case SplitAEAD_CHACHA20_POLY1305:
		nonceSize = 12 // ChaCha20-Poly1305 nonce
	}

	nonce := make([]byte, nonceSize)
	rand.Read(nonce)

	// Test data representing HTTP request
	plaintext := []byte("GET /api/data HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer secret_token\r\n\r\n")
	aad := []byte("additional_data") // Could be TLS record header

	t.Logf("Testing %v integration with %d-byte key", mode, keySize)
	t.Logf("Plaintext (%d bytes): %s", len(plaintext), string(plaintext))

	// PHASE 1: TEE_K Operation (Encryption without tag)
	t.Logf("PHASE 1: TEE_K encrypts data and generates tag secrets")

	encryptor, err := NewSplitAEADEncryptor(mode, key)
	if err != nil {
		t.Fatalf("TEE_K: Failed to create encryptor: %v", err)
	}
	defer encryptor.SecureZero()

	// TEE_K encrypts and generates secrets for TEE_T
	ciphertext, tagSecrets, err := encryptor.EncryptWithoutTag(nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("TEE_K: Encryption failed: %v", err)
	}
	defer tagSecrets.SecureZero()

	t.Logf("TEE_K: Encryption successful")
	t.Logf("TEE_K: Ciphertext (%d bytes): %s", len(ciphertext), hex.EncodeToString(ciphertext[:min(32, len(ciphertext))]))
	t.Logf("TEE_K: Generated tag secrets for TEE_T")

	// Validate tag secrets
	switch mode {
	case SplitAEAD_AES_GCM:
		if len(tagSecrets.GCM_H) != 16 {
			t.Errorf("TEE_K: Invalid GCM H length: expected 16, got %d", len(tagSecrets.GCM_H))
		}
		if len(tagSecrets.GCM_Y0) != 16 {
			t.Errorf("TEE_K: Invalid GCM Y0 length: expected 16, got %d", len(tagSecrets.GCM_Y0))
		}
		t.Logf("TEE_K: GCM auth key (H): %s", hex.EncodeToString(tagSecrets.GCM_H[:8])+"...")
		t.Logf("TEE_K: GCM Y0 block: %s", hex.EncodeToString(tagSecrets.GCM_Y0[:8])+"...")

	case SplitAEAD_CHACHA20_POLY1305:
		if len(tagSecrets.Poly1305_Key) != 32 {
			t.Errorf("TEE_K: Invalid Poly1305 key length: expected 32, got %d", len(tagSecrets.Poly1305_Key))
		}
		t.Logf("TEE_K: Poly1305 one-time key: %s", hex.EncodeToString(tagSecrets.Poly1305_Key[:8])+"...")
	}

	// PHASE 2: TEE_T Operation (Tag computation)
	t.Logf("PHASE 2: TEE_T computes authentication tag")

	tagComputer := NewSplitAEADTagComputer()

	// TEE_T computes the authentication tag
	computedTag, err := tagComputer.ComputeTag(ciphertext, tagSecrets)
	if err != nil {
		t.Fatalf("TEE_T: Tag computation failed: %v", err)
	}

	if len(computedTag) != 16 {
		t.Errorf("TEE_T: Invalid tag length: expected 16, got %d", len(computedTag))
	}

	t.Logf("TEE_T: Tag computation successful")
	t.Logf("TEE_T: Authentication tag: %s", hex.EncodeToString(computedTag))

	// PHASE 3: Verification (TEE_T verifies the tag)
	t.Logf("PHASE 3: TEE_T verifies the computed tag")

	err = tagComputer.VerifyTag(ciphertext, computedTag, tagSecrets)
	if err != nil {
		t.Errorf("TEE_T: Tag verification failed: %v", err)
	} else {
		t.Logf("TEE_T: Tag verification successful")
	}

	// PHASE 4: End-to-end validation against standard AEAD
	t.Logf("PHASE 4: Validating against Go's standard AEAD implementation")

	switch mode {
	case SplitAEAD_AES_GCM:
		validateAgainstStandardGCM(t, key, nonce, plaintext, aad, ciphertext, computedTag)
	case SplitAEAD_CHACHA20_POLY1305:
		validateAgainstStandardChaCha20Poly1305(t, key, nonce, plaintext, aad, ciphertext, computedTag)
	}

	// PHASE 5: Test malicious tag detection
	t.Logf("PHASE 5: Testing malicious tag detection")

	// Create a wrong tag
	wrongTag := make([]byte, len(computedTag))
	rand.Read(wrongTag)

	err = tagComputer.VerifyTag(ciphertext, wrongTag, tagSecrets)
	if err == nil {
		t.Error("TEE_T: Should have detected malicious tag")
	} else {
		t.Logf("TEE_T: Correctly rejected malicious tag: %v", err)
	}

	// Test with modified ciphertext
	if len(ciphertext) > 0 {
		modifiedCiphertext := make([]byte, len(ciphertext))
		copy(modifiedCiphertext, ciphertext)
		modifiedCiphertext[0] ^= 0x01 // Flip one bit

		err = tagComputer.VerifyTag(modifiedCiphertext, computedTag, tagSecrets)
		if err == nil {
			t.Error("TEE_T: Should have detected modified ciphertext")
		} else {
			t.Logf("TEE_T: Correctly rejected modified ciphertext: %v", err)
		}
	}

	t.Logf("Split AEAD %v integration test PASSED", mode)
}

// validateAgainstStandardGCM compares our Split AEAD results with Go's standard GCM
func validateAgainstStandardGCM(t *testing.T, key, nonce, plaintext, aad, splitCiphertext, splitTag []byte) {
	// Create standard GCM
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create AES cipher: %v", err)
	}

	standardGCM, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("Failed to create standard GCM: %v", err)
	}

	// Encrypt with standard GCM
	standardResult := standardGCM.Seal(nil, nonce, plaintext, aad)

	// Split into ciphertext and tag
	standardCiphertext := standardResult[:len(plaintext)]
	standardTag := standardResult[len(plaintext):]

	// Compare ciphertexts
	if !bytesEqual(splitCiphertext, standardCiphertext) {
		t.Errorf("Ciphertext mismatch with standard GCM")
		t.Logf("Split AEAD: %s", hex.EncodeToString(splitCiphertext[:min(32, len(splitCiphertext))]))
		t.Logf("Standard:   %s", hex.EncodeToString(standardCiphertext[:min(32, len(standardCiphertext))]))
		return
	}

	// Compare tags
	if !bytesEqual(splitTag, standardTag) {
		t.Errorf("Tag mismatch with standard GCM")
		t.Logf("Split AEAD tag: %s", hex.EncodeToString(splitTag))
		t.Logf("Standard tag:   %s", hex.EncodeToString(standardTag))
		return
	}

	t.Logf("VALIDATION: Split AEAD matches Go's standard GCM perfectly")
}

// validateAgainstStandardChaCha20Poly1305 compares our Split AEAD results with Go's standard ChaCha20-Poly1305
func validateAgainstStandardChaCha20Poly1305(t *testing.T, key, nonce, plaintext, aad, splitCiphertext, splitTag []byte) {
	// Create standard ChaCha20-Poly1305
	standardCipher, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("Failed to create standard ChaCha20-Poly1305: %v", err)
	}

	// Encrypt with standard ChaCha20-Poly1305
	standardResult := standardCipher.Seal(nil, nonce, plaintext, aad)

	// Split into ciphertext and tag
	standardCiphertext := standardResult[:len(plaintext)]
	standardTag := standardResult[len(plaintext):]

	// Compare ciphertexts
	if !bytesEqual(splitCiphertext, standardCiphertext) {
		t.Errorf("Ciphertext mismatch with standard ChaCha20-Poly1305")
		t.Logf("Split AEAD: %s", hex.EncodeToString(splitCiphertext[:min(32, len(splitCiphertext))]))
		t.Logf("Standard:   %s", hex.EncodeToString(standardCiphertext[:min(32, len(standardCiphertext))]))
		return
	}

	// Compare tags
	if !bytesEqual(splitTag, standardTag) {
		t.Errorf("Tag mismatch with standard ChaCha20-Poly1305")
		t.Logf("Split AEAD tag: %s", hex.EncodeToString(splitTag))
		t.Logf("Standard tag:   %s", hex.EncodeToString(standardTag))
		return
	}

	t.Logf("VALIDATION: Split AEAD matches Go's standard ChaCha20-Poly1305 perfectly")
}

// TestSplitAEADProtocolFlow tests the complete protocol flow with multiple requests
func TestSplitAEADProtocolFlow(t *testing.T) {
	// Simulate multiple HTTP requests in a TLS session
	requests := [][]byte{
		[]byte("GET /api/user/123 HTTP/1.1\r\nHost: api.example.com\r\n\r\n"),
		[]byte("POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 13\r\n\r\n{\"key\":\"value\"}"),
		[]byte("PUT /api/user/123 HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 25\r\n\r\n{\"name\":\"Updated Name\"}"),
	}

	// Use AES-128-GCM for this test
	key := make([]byte, 16)
	rand.Read(key)

	encryptor, err := NewSplitAEADEncryptor(SplitAEAD_AES_GCM, key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}
	defer encryptor.SecureZero()

	tagComputer := NewSplitAEADTagComputer()

	for i, request := range requests {
		t.Logf("Processing request %d: %s", i+1, string(request[:min(50, len(request))]))

		// Use different nonce for each request (simulating TLS record sequence)
		nonce := make([]byte, 12)
		rand.Read(nonce)

		aad := []byte("record_header") // Simulated TLS record header

		// TEE_K: Encrypt
		ciphertext, tagSecrets, err := encryptor.EncryptWithoutTag(nonce, request, aad)
		if err != nil {
			t.Fatalf("Request %d: Encryption failed: %v", i+1, err)
		}

		// TEE_T: Compute tag
		tag, err := tagComputer.ComputeTag(ciphertext, tagSecrets)
		if err != nil {
			t.Fatalf("Request %d: Tag computation failed: %v", i+1, err)
		}

		// TEE_T: Verify tag
		err = tagComputer.VerifyTag(ciphertext, tag, tagSecrets)
		if err != nil {
			t.Errorf("Request %d: Tag verification failed: %v", i+1, err)
		}

		t.Logf("Request %d: Successfully processed (%d bytes -> %d bytes + 16-byte tag)",
			i+1, len(request), len(ciphertext))

		// Clean up secrets
		tagSecrets.SecureZero()
	}

	t.Logf("Protocol flow test with %d requests PASSED", len(requests))
}

// TestSplitAEADConcurrency tests concurrent operations
func TestSplitAEADConcurrency(t *testing.T) {
	const numGoroutines = 10
	const numOperationsPerGoroutine = 5

	key := make([]byte, 16)
	rand.Read(key)

	results := make(chan error, numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			encryptor, err := NewSplitAEADEncryptor(SplitAEAD_AES_GCM, key)
			if err != nil {
				results <- err
				return
			}
			defer encryptor.SecureZero()

			tagComputer := NewSplitAEADTagComputer()

			for i := 0; i < numOperationsPerGoroutine; i++ {
				plaintext := []byte(fmt.Sprintf("Goroutine %d operation %d", goroutineID, i))
				nonce := make([]byte, 12)
				rand.Read(nonce)

				ciphertext, tagSecrets, err := encryptor.EncryptWithoutTag(nonce, plaintext, nil)
				if err != nil {
					results <- err
					return
				}

				tag, err := tagComputer.ComputeTag(ciphertext, tagSecrets)
				if err != nil {
					tagSecrets.SecureZero()
					results <- err
					return
				}

				err = tagComputer.VerifyTag(ciphertext, tag, tagSecrets)
				tagSecrets.SecureZero()
				if err != nil {
					results <- err
					return
				}
			}

			results <- nil
		}(g)
	}

	// Collect results
	for i := 0; i < numGoroutines; i++ {
		if err := <-results; err != nil {
			t.Errorf("Goroutine failed: %v", err)
		}
	}

	t.Logf("Concurrency test with %d goroutines × %d operations PASSED",
		numGoroutines, numOperationsPerGoroutine)
}
