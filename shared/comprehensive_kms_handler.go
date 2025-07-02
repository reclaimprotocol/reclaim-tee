package shared

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"

	"github.com/austinast/nitro-enclaves-sdk-go/crypto/cms"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"golang.org/x/crypto/acme/autocert"
)

// KMSConnectionManager defines the interface for KMS connection management
type KMSConnectionManager interface {
	SendKMSRequest(ctx context.Context, operation string, data interface{}) ([]byte, error)
}

// ComprehensiveKMSHandler ensures ALL KMS operations use attestation documents
// This matches the exact pattern from nitro.go for maximum security
type ComprehensiveKMSHandler struct {
	connectionMgr KMSConnectionManager
	kmsKeyID      string
}

// NewComprehensiveKMSHandler creates a new comprehensive KMS handler
func NewComprehensiveKMSHandler(connectionMgr KMSConnectionManager, kmsKeyID string) *ComprehensiveKMSHandler {
	return &ComprehensiveKMSHandler{
		connectionMgr: connectionMgr,
		kmsKeyID:      kmsKeyID,
	}
}

// EncryptAndStoreCacheItem encrypts data and stores it - ALWAYS uses attestation
// This exactly matches the pattern from nitro.go encryptAndStoreCacheItem function
func (c *ComprehensiveKMSHandler) EncryptAndStoreCacheItem(ctx context.Context, data []byte, filename string) error {
	log.Printf("[ComprehensiveKMS] Starting encrypted storage for item: %s (%d bytes)", filename, len(data))

	// CRITICAL: Get global singleton handle safely (NO PANIC)
	handle, err := SafeGetEnclaveHandle()
	if err != nil {
		return fmt.Errorf("failed to get enclave handle: %v", err)
	}

	// CRITICAL: Generate fresh attestation document for EVERY operation
	attestationDoc, err := c.generateAttestation(handle, nil)
	if err != nil {
		return fmt.Errorf("failed to generate attestation: %v", err)
	}

	log.Printf("[ComprehensiveKMS] Generated attestation document (%d bytes) for storage operation", len(attestationDoc))

	// Create KMS GenerateDataKey request with attestation (matching nitro.go exactly)
	input := kms.GenerateDataKeyInput{
		KeyId:   aws.String(c.kmsKeyID),
		KeySpec: "AES_256", // Using string format as in nitro.go
		Recipient: &types.RecipientInfoType{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
		},
	}

	// Send KMS request via VSock
	resp, err := c.sendVsockRequest(ctx, "GenerateDataKey", input)
	if err != nil {
		return fmt.Errorf("KMS GenerateDataKey failed: %v", err)
	}

	var output kms.GenerateDataKeyOutput
	if err = json.Unmarshal(resp, &output); err != nil {
		return fmt.Errorf("failed to parse KMS output: %v", err)
	}

	log.Printf("[ComprehensiveKMS] KMS GenerateDataKey response - CiphertextBlob: %d bytes, CiphertextForRecipient: %d bytes",
		len(output.CiphertextBlob), len(output.CiphertextForRecipient))

	// CRITICAL: Decrypt envelope key using enclave's private key
	plaintextKey, err := cms.DecryptEnvelopedKey(handle.PrivateKey(), output.CiphertextForRecipient)
	if err != nil {
		return fmt.Errorf("failed to decrypt KMS data key: %v", err)
	}

	log.Printf("[ComprehensiveKMS] Successfully decrypted envelope key (%d bytes)", len(plaintextKey))

	// Encrypt data using the decrypted key
	encryptedData, err := aesGCMOperation(plaintextKey, data, true)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}

	log.Printf("[ComprehensiveKMS] Encrypted data (%d bytes -> %d bytes)", len(data), len(encryptedData))

	// Store encrypted data and ciphertext blob (matching nitro.go StoreItemInput structure)
	storeInput := struct {
		Data     []byte `json:"data"`
		Key      []byte `json:"key"`
		Filename string `json:"filename"`
	}{
		Data:     encryptedData,
		Key:      output.CiphertextBlob, // Store the standard ciphertext blob
		Filename: filename,
	}

	resp, err = c.sendVsockRequest(ctx, "StoreEncryptedItem", storeInput)
	if err != nil {
		return fmt.Errorf("failed to store encrypted item: %v", err)
	}

	var status struct {
		Status string `json:"status"`
	}
	if err = json.Unmarshal(resp, &status); err != nil {
		return fmt.Errorf("failed to parse StoreEncryptedItem response: %v", err)
	}

	if status.Status != "success" {
		return fmt.Errorf("failed to store item: %s", filename)
	}

	log.Printf("[ComprehensiveKMS] Successfully stored encrypted item: %s", filename)
	return nil
}

// LoadAndDecryptCacheItem loads and decrypts an item - ALWAYS uses attestation
// This exactly matches the pattern from nitro.go decryptItem function
func (c *ComprehensiveKMSHandler) LoadAndDecryptCacheItem(ctx context.Context, filename string) ([]byte, error) {
	log.Printf("[ComprehensiveKMS] Loading encrypted item: %s", filename)

	// Load encrypted item from storage (matching nitro.go GetItemInput pattern)
	loadInput := struct {
		Filename string `json:"filename"`
	}{
		Filename: filename,
	}

	resp, err := c.sendVsockRequest(ctx, "GetEncryptedItem", loadInput)
	if err != nil {
		log.Printf("[ComprehensiveKMS] Failed to get encrypted item %s: %v", filename, err)
		return nil, autocert.ErrCacheMiss
	}

	// Parse response directly (matching advanced_kms.go pattern)
	var output struct {
		Data []byte `json:"data"`
		Key  []byte `json:"key"`
	}
	if err = json.Unmarshal(resp, &output); err != nil {
		log.Printf("[ComprehensiveKMS] Failed to parse response for %s: %v", filename, err)
		return nil, autocert.ErrCacheMiss
	}

	log.Printf("[ComprehensiveKMS] Retrieved encrypted item - data: %d bytes, key: %d bytes", len(output.Data), len(output.Key))

	// Decrypt the item (matching nitro.go decryptItem exactly)
	decryptedData, err := c.decryptItem(ctx, output.Data, output.Key)
	if err != nil {
		log.Printf("[ComprehensiveKMS] Failed to decrypt item %s: %v", filename, err)
		return nil, autocert.ErrCacheMiss
	}

	log.Printf("[ComprehensiveKMS] Successfully decrypted item %s: %d bytes", filename, len(decryptedData))
	return decryptedData, nil
}

// decryptItem decrypts item data - EXACTLY matching nitro.go decryptItem function
func (c *ComprehensiveKMSHandler) decryptItem(ctx context.Context, encryptedData, ciphertextBlob []byte) ([]byte, error) {
	// CRITICAL: Get global singleton handle safely (NO PANIC)
	handle, err := SafeGetEnclaveHandle()
	if err != nil {
		log.Printf("[ComprehensiveKMS] Failed to get enclave handle: %v", err)
		return nil, fmt.Errorf("failed to get enclave handle: %v", err)
	}

	// CRITICAL: Generate simple attestation document (matching nitro.go exactly)
	attestationDoc, err := c.generateAttestation(handle, nil)
	if err != nil {
		log.Printf("[ComprehensiveKMS] Failed to generate attestation: %v", err)
		return nil, fmt.Errorf("failed to generate attestation: %v", err)
	}

	log.Printf("[ComprehensiveKMS] Generated attestation document (%d bytes) for decrypt operation", len(attestationDoc))

	// Create KMS Decrypt request with attestation (matching nitro.go exactly)
	input := kms.DecryptInput{
		KeyId:               aws.String(c.kmsKeyID),
		CiphertextBlob:      ciphertextBlob,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		Recipient: &types.RecipientInfoType{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
		},
	}

	// Send KMS request via VSock
	resp, err := c.sendVsockRequest(ctx, "Decrypt", input)
	if err != nil {
		log.Printf("[ComprehensiveKMS] KMS Decrypt request failed: %v", err)
		return nil, fmt.Errorf("KMS Decrypt failed: %v", err)
	}

	var output kms.DecryptOutput
	if err = json.Unmarshal(resp, &output); err != nil {
		log.Printf("[ComprehensiveKMS] Failed to parse KMS decrypt response: %v", err)
		return nil, fmt.Errorf("failed to parse KMS output: %v", err)
	}

	log.Printf("[ComprehensiveKMS] KMS Decrypt response - CiphertextForRecipient: %d bytes", len(output.CiphertextForRecipient))

	// CRITICAL: Decrypt envelope key using enclave's private key
	plaintextKey, err := cms.DecryptEnvelopedKey(handle.PrivateKey(), output.CiphertextForRecipient)
	if err != nil {
		log.Printf("[ComprehensiveKMS] Failed to decrypt envelope key: %v", err)
		return nil, fmt.Errorf("failed to decrypt KMS ciphertext for recipient: %v", err)
	}

	log.Printf("[ComprehensiveKMS] Successfully decrypted envelope key (%d bytes)", len(plaintextKey))

	// Decrypt the actual data using the decrypted key (matching nitro.go aesGCMOperation)
	plaintext, err := aesGCMOperation(plaintextKey, encryptedData, false)
	if err != nil {
		log.Printf("[ComprehensiveKMS] AES-GCM decryption failed: %v", err)
		return nil, fmt.Errorf("AES-GCM decryption failed: %v", err)
	}

	log.Printf("[ComprehensiveKMS] AES-GCM decryption successful (%d bytes)", len(plaintext))
	return plaintext, nil
}

// generateAttestation generates attestation document - matching nitro.go pattern exactly
func (c *ComprehensiveKMSHandler) generateAttestation(handle *EnclaveHandle, userData []byte) ([]byte, error) {
	// Use "Reclaim Protocol" as default user data if none provided (matching nitro.go)
	if userData == nil {
		userData = []byte("Reclaim Protocol")
	}

	// Generate 32-byte random nonce (matching nitro.go)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Generate attestation document (matching nitro.go AttestationOptions)
	return handle.generateAttestation(userData)
}

// sendVsockRequest sends a request via VSock connection manager
func (c *ComprehensiveKMSHandler) sendVsockRequest(ctx context.Context, operation string, input interface{}) ([]byte, error) {
	return c.connectionMgr.SendKMSRequest(ctx, operation, input)
}

// DeleteCacheItem deletes an encrypted item from storage
func (c *ComprehensiveKMSHandler) DeleteCacheItem(ctx context.Context, filename string) error {
	log.Printf("[ComprehensiveKMS] Deleting encrypted item: %s", filename)

	deleteInput := struct {
		Filename string `json:"filename"`
	}{
		Filename: filename,
	}

	resp, err := c.sendVsockRequest(ctx, "DeleteEncryptedItem", deleteInput)
	if err != nil {
		return fmt.Errorf("failed to delete encrypted item: %v", err)
	}

	var status struct {
		Status string `json:"status"`
	}
	if err = json.Unmarshal(resp, &status); err != nil {
		return fmt.Errorf("failed to parse delete response: %v", err)
	}

	if status.Status != "success" {
		return fmt.Errorf("failed to delete item: %s", filename)
	}

	log.Printf("[ComprehensiveKMS] Successfully deleted encrypted item: %s", filename)
	return nil
}

// TestKMSAttestationRoundTrip performs a simple encryption/decryption test to verify KMS attestation works
func (c *ComprehensiveKMSHandler) TestKMSAttestationRoundTrip(ctx context.Context) error {
	testData := []byte("Hello from Nitro Enclave - KMS Attestation Test")
	log.Printf("[KMSTest] Starting KMS attestation round-trip test with %d bytes", len(testData))

	// STEP 1: Get enclave handle
	handle, err := SafeGetEnclaveHandle()
	if err != nil {
		return fmt.Errorf("failed to get enclave handle: %v", err)
	}

	// STEP 2: Generate attestation document
	attestationDoc, err := c.generateAttestation(handle, nil)
	if err != nil {
		return fmt.Errorf("failed to generate attestation: %v", err)
	}
	log.Printf("[KMSTest] Generated attestation document (%d bytes)", len(attestationDoc))

	// STEP 3: Generate data key with attestation
	input := kms.GenerateDataKeyInput{
		KeyId:   aws.String(c.kmsKeyID),
		KeySpec: "AES_256",
		Recipient: &types.RecipientInfoType{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
		},
	}

	resp, err := c.sendVsockRequest(ctx, "GenerateDataKey", input)
	if err != nil {
		return fmt.Errorf("KMS GenerateDataKey failed: %v", err)
	}

	var output kms.GenerateDataKeyOutput
	if err = json.Unmarshal(resp, &output); err != nil {
		return fmt.Errorf("failed to parse KMS output: %v", err)
	}
	log.Printf("[KMSTest] GenerateDataKey success - CiphertextBlob: %d bytes, CiphertextForRecipient: %d bytes",
		len(output.CiphertextBlob), len(output.CiphertextForRecipient))

	// STEP 4: Decrypt envelope key
	plaintextKey, err := cms.DecryptEnvelopedKey(handle.PrivateKey(), output.CiphertextForRecipient)
	if err != nil {
		return fmt.Errorf("failed to decrypt envelope key: %v", err)
	}
	log.Printf("[KMSTest] Decrypted envelope key (%d bytes)", len(plaintextKey))

	// STEP 5: Encrypt test data with AES-GCM
	encryptedData, err := aesGCMOperation(plaintextKey, testData, true)
	if err != nil {
		return fmt.Errorf("AES-GCM encryption failed: %v", err)
	}
	log.Printf("[KMSTest] AES-GCM encryption success (%d -> %d bytes)", len(testData), len(encryptedData))

	// STEP 6: Generate NEW attestation for decrypt (simulating restart scenario)
	freshAttestationDoc, err := c.generateAttestation(handle, nil)
	if err != nil {
		return fmt.Errorf("failed to generate fresh attestation: %v", err)
	}
	log.Printf("[KMSTest] Generated fresh attestation document (%d bytes)", len(freshAttestationDoc))

	// STEP 7: Decrypt using fresh attestation (this tests if attestation documents are consistent)
	decryptInput := kms.DecryptInput{
		KeyId:               aws.String(c.kmsKeyID),
		CiphertextBlob:      output.CiphertextBlob,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		Recipient: &types.RecipientInfoType{
			AttestationDocument:    freshAttestationDoc,
			KeyEncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
		},
	}

	decryptResp, err := c.sendVsockRequest(ctx, "Decrypt", decryptInput)
	if err != nil {
		log.Printf("[KMSTest] KMS Decrypt with fresh attestation FAILED: %v", err)
		log.Printf("[KMSTest] This suggests attestation documents are changing between operations")
		return fmt.Errorf("KMS Decrypt failed: %v", err)
	}

	var decryptOutput kms.DecryptOutput
	if err = json.Unmarshal(decryptResp, &decryptOutput); err != nil {
		return fmt.Errorf("failed to parse decrypt response: %v", err)
	}
	log.Printf("[KMSTest] KMS Decrypt success - CiphertextForRecipient: %d bytes", len(decryptOutput.CiphertextForRecipient))

	// STEP 8: Decrypt envelope key with fresh attestation
	freshPlaintextKey, err := cms.DecryptEnvelopedKey(handle.PrivateKey(), decryptOutput.CiphertextForRecipient)
	if err != nil {
		return fmt.Errorf("failed to decrypt envelope key with fresh attestation: %v", err)
	}
	log.Printf("[KMSTest] Decrypted envelope key with fresh attestation (%d bytes)", len(freshPlaintextKey))

	// STEP 9: Decrypt test data with fresh key
	decryptedData, err := aesGCMOperation(freshPlaintextKey, encryptedData, false)
	if err != nil {
		return fmt.Errorf("AES-GCM decryption failed: %v", err)
	}
	log.Printf("[KMSTest] AES-GCM decryption success (%d bytes)", len(decryptedData))

	// STEP 10: Verify data integrity
	if string(decryptedData) != string(testData) {
		return fmt.Errorf("data mismatch - original: %q, decrypted: %q", string(testData), string(decryptedData))
	}

	log.Printf("[KMSTest] ✓ ROUND-TRIP TEST SUCCESSFUL - KMS attestation encryption/decryption working correctly")
	log.Printf("[KMSTest] ✓ Original: %q", string(testData))
	log.Printf("[KMSTest] ✓ Decrypted: %q", string(decryptedData))
	return nil
}
