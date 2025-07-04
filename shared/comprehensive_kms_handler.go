package shared

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
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

// KMSHandler ensures ALL KMS operations use attestation documents
// This matches the exact pattern from nitro.go for maximum security
type KMSHandler struct {
	connectionMgr KMSConnectionManager
	kmsKeyID      string
	serviceName   string
}

// NewKMSHandler creates a new comprehensive KMS handler
func NewKMSHandler(connectionMgr KMSConnectionManager, kmsKeyID string, serviceName string) *KMSHandler {
	return &KMSHandler{
		connectionMgr: connectionMgr,
		kmsKeyID:      kmsKeyID,
		serviceName:   serviceName,
	}
}

// EncryptAndStoreCacheItem encrypts data and stores it - ALWAYS uses attestation
// This exactly matches the pattern from nitro.go encryptAndStoreCacheItem function
func (c *KMSHandler) EncryptAndStoreCacheItem(ctx context.Context, data []byte, filename string) error {
	log.Printf("[KMS] Starting encrypted storage for item: %s (%d bytes)", filename, len(data))

	handle, err := SafeGetEnclaveHandle()
	if err != nil {
		return fmt.Errorf("failed to get enclave handle: %v", err)
	}

	attestationDoc, err := c.generateAttestation(handle, nil)
	if err != nil {
		return fmt.Errorf("failed to generate attestation: %v", err)
	}

	log.Printf("[KMS] Generated attestation document (%d bytes) for storage operation", len(attestationDoc))

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

	log.Printf("[KMS] GenerateDataKey response (%s)", resp)

	var output kms.GenerateDataKeyOutput
	if err = json.Unmarshal(resp, &output); err != nil {
		return fmt.Errorf("failed to parse KMS output: %v", err)
	}

	log.Printf("[KMS] KMS GenerateDataKey response - CiphertextBlob: %d bytes, CiphertextForRecipient: %d bytes",
		len(output.CiphertextBlob), len(output.CiphertextForRecipient))

	// CRITICAL: Decrypt envelope key using enclave's private key
	plaintextKey, err := cms.DecryptEnvelopedKey(handle.PrivateKey(), output.CiphertextForRecipient)
	if err != nil {
		return fmt.Errorf("failed to decrypt KMS data key: %v", err)
	}

	log.Printf("[KMS] Successfully decrypted envelope key (%d bytes)", len(plaintextKey))

	// Encrypt data using the decrypted key
	encryptedData, err := aesGCMOperation(plaintextKey, data, true)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}

	log.Printf("[KMS] Encrypted data (%d bytes -> %d bytes)", len(data), len(encryptedData))

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

	log.Printf("[KMS] Successfully stored encrypted item: %s", filename)
	return nil
}

// LoadAndDecryptCacheItem loads and decrypts an item - ALWAYS uses attestation
// This exactly matches the pattern from nitro.go decryptItem function
func (c *KMSHandler) LoadAndDecryptCacheItem(ctx context.Context, filename string) ([]byte, error) {
	log.Printf("[KMS] Loading encrypted item: %s", filename)

	// Load encrypted item from storage (matching nitro.go GetItemInput pattern)
	loadInput := struct {
		Filename string `json:"filename"`
	}{
		Filename: filename,
	}

	resp, err := c.sendVsockRequest(ctx, "GetEncryptedItem", loadInput)
	if err != nil {
		log.Printf("[KMS] Failed to get encrypted item %s: %v", filename, err)
		return nil, autocert.ErrCacheMiss
	}

	// Parse response directly (matching advanced_kms.go pattern)
	var output struct {
		Data []byte `json:"data"`
		Key  []byte `json:"key"`
	}
	if err = json.Unmarshal(resp, &output); err != nil {
		log.Printf("[KMS] Failed to parse response for %s: %v", filename, err)
		return nil, autocert.ErrCacheMiss
	}

	if len(output.Data) == 0 || len(output.Key) == 0 {
		log.Printf("[KMS] Failed to get encrypted item: %s", filename)
		return nil, autocert.ErrCacheMiss
	}

	log.Printf("[KMS] Retrieved encrypted item - data: %d bytes, key: %d bytes", len(output.Data), len(output.Key))

	// Decrypt the item (matching nitro.go decryptItem exactly)
	decryptedData, err := c.decryptItem(ctx, output.Data, output.Key)
	if err != nil {
		log.Printf("[KMS] Failed to decrypt item %s: %v", filename, err)
		return nil, autocert.ErrCacheMiss
	}

	log.Printf("[KMS] Successfully decrypted item %s: %d bytes", filename, len(decryptedData))
	return decryptedData, nil
}

// decryptItem decrypts item data - EXACTLY matching nitro.go decryptItem function
func (c *KMSHandler) decryptItem(ctx context.Context, encryptedData, ciphertextBlob []byte) ([]byte, error) {
	// CRITICAL: Get global singleton handle safely (NO PANIC)
	handle, err := SafeGetEnclaveHandle()
	if err != nil {
		log.Printf("[KMS] Failed to get enclave handle: %v", err)
		return nil, fmt.Errorf("failed to get enclave handle: %v", err)
	}

	// CRITICAL: Generate simple attestation document (matching nitro.go exactly)
	attestationDoc, err := c.generateAttestation(handle, nil)
	if err != nil {
		log.Printf("[KMS] Failed to generate attestation: %v", err)
		return nil, fmt.Errorf("failed to generate attestation: %v", err)
	}

	log.Printf("[KMS] Generated attestation document (%d bytes) for decrypt operation", len(attestationDoc))

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
		log.Printf("[KMS] KMS Decrypt request failed: %v", err)
		return nil, fmt.Errorf("KMS Decrypt failed: %v", err)
	}

	var output kms.DecryptOutput
	if err = json.Unmarshal(resp, &output); err != nil {
		log.Printf("[KMS] Failed to parse KMS decrypt response: %v", err)
		return nil, fmt.Errorf("failed to parse KMS output: %v", err)
	}

	log.Printf("[KMS] KMS Decrypt response - CiphertextForRecipient: %d bytes", len(output.CiphertextForRecipient))

	// CRITICAL: Decrypt envelope key using enclave's private key
	plaintextKey, err := cms.DecryptEnvelopedKey(handle.PrivateKey(), output.CiphertextForRecipient)
	if err != nil {
		log.Printf("[KMS] Failed to decrypt envelope key: %v", err)
		return nil, fmt.Errorf("failed to decrypt KMS ciphertext for recipient: %v", err)
	}

	log.Printf("[KMS] Successfully decrypted envelope key (%d bytes)", len(plaintextKey))

	// Decrypt the actual data using the decrypted key (matching nitro.go aesGCMOperation)
	plaintext, err := aesGCMOperation(plaintextKey, encryptedData, false)
	if err != nil {
		log.Printf("[KMS] AES-GCM decryption failed: %v", err)
		return nil, fmt.Errorf("AES-GCM decryption failed: %v", err)
	}

	log.Printf("[KMS] AES-GCM decryption successful (%d bytes)", len(plaintext))
	return plaintext, nil
}

// generateAttestation generates attestation document - matching nitro.go pattern exactly
func (c *KMSHandler) generateAttestation(handle *EnclaveHandle, userData []byte) ([]byte, error) {
	// Generate attestation document (matching nitro.go AttestationOptions)
	return handle.generateAttestation(userData)
}

// sendVsockRequest sends a request via VSock connection manager
func (c *KMSHandler) sendVsockRequest(ctx context.Context, operation string, input interface{}) ([]byte, error) {
	// Check if the connection manager supports the new method with service name
	if mgr, ok := c.connectionMgr.(*VSockConnectionManager); ok {
		return mgr.SendKMSRequestWithService(ctx, operation, c.serviceName, input)
	}
	// Fallback to old method for backward compatibility
	return c.connectionMgr.SendKMSRequest(ctx, operation, input)
}

// DeleteCacheItem deletes an encrypted item from storage
func (c *KMSHandler) DeleteCacheItem(ctx context.Context, filename string) error {
	log.Printf("[KMS] Deleting encrypted item: %s", filename)

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

	log.Printf("[KMS] Successfully deleted encrypted item: %s", filename)
	return nil
}

// aesGCMOperation handles AES-GCM encryption or decryption based on the encrypt flag
// This matches the implementation from nitro.go exactly
func aesGCMOperation(key, data []byte, encrypt bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()

	if encrypt {
		// Encryption: generate nonce and encrypt
		nonce := make([]byte, nonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %v", err)
		}
		// Return nonce + ciphertext
		return append(nonce, gcm.Seal(nil, nonce, data, nil)...), nil
	} else {
		// Decryption: extract nonce and decrypt
		if len(data) < nonceSize {
			return nil, errors.New("encrypted data too short")
		}
		nonce, ciphertext := data[:nonceSize], data[nonceSize:]
		return gcm.Open(nil, nonce, ciphertext, nil)
	}
}
