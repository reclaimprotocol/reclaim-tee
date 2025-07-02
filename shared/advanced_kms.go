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
)

// NOTE: KMSConnectionManager interface moved to comprehensive_kms_handler.go

// AdvancedKMSClient provides KMS operations with attestation document integration
type AdvancedKMSClient struct {
	connectionMgr KMSConnectionManager
	enclaveHandle *EnclaveHandle
	kmsKeyID      string
}

// NewAdvancedKMSClient creates a new advanced KMS client
func NewAdvancedKMSClient(connectionMgr KMSConnectionManager, handle *EnclaveHandle, kmsKeyID string) *AdvancedKMSClient {
	return &AdvancedKMSClient{
		connectionMgr: connectionMgr,
		enclaveHandle: handle,
		kmsKeyID:      kmsKeyID,
	}
}

// GenerateDataKeyWithAttestation generates a data key with attestation document
func (a *AdvancedKMSClient) GenerateDataKeyWithAttestation(ctx context.Context) (*kms.GenerateDataKeyOutput, []byte, error) {
	// Generate attestation document for this operation
	attestationDoc, err := a.enclaveHandle.generateAttestation(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate attestation: %v", err)
	}

	log.Printf("[KMS] Generated attestation document (%d bytes) for data key generation", len(attestationDoc))

	// Create KMS request with attestation as recipient
	input := &kms.GenerateDataKeyInput{
		KeyId:   aws.String(a.kmsKeyID),
		KeySpec: types.DataKeySpecAes256,
		Recipient: &types.RecipientInfoType{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
		},
	}

	log.Printf("[KMS] Requesting data key generation with attestation recipient")

	// Send request via VSock
	response, err := a.connectionMgr.SendKMSRequest(ctx, "GenerateDataKey", input)
	if err != nil {
		return nil, nil, fmt.Errorf("KMS GenerateDataKey request failed: %v", err)
	}

	// Parse KMS response
	var output kms.GenerateDataKeyOutput
	if err := json.Unmarshal(response, &output); err != nil {
		return nil, nil, fmt.Errorf("failed to parse KMS GenerateDataKey response: %v", err)
	}

	log.Printf("[KMS] Received KMS response - CiphertextBlob: %d bytes, CiphertextForRecipient: %d bytes",
		len(output.CiphertextBlob), len(output.CiphertextForRecipient))

	// Decrypt the envelope key using our private key
	plaintextKey, err := cms.DecryptEnvelopedKey(a.enclaveHandle.PrivateKey(), output.CiphertextForRecipient)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt envelope key: %v", err)
	}

	log.Printf("[KMS] Successfully decrypted envelope key (%d bytes)", len(plaintextKey))

	return &output, plaintextKey, nil
}

// DecryptWithAttestation decrypts a ciphertext blob with attestation document
func (a *AdvancedKMSClient) DecryptWithAttestation(ctx context.Context, ciphertextBlob []byte) ([]byte, error) {
	// Generate attestation document for this operation
	attestationDoc, err := a.enclaveHandle.generateAttestation(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation: %v", err)
	}

	log.Printf("[KMS] Generated attestation document (%d bytes) for decryption", len(attestationDoc))

	// Create KMS decrypt request with attestation
	input := &kms.DecryptInput{
		KeyId:               aws.String(a.kmsKeyID),
		CiphertextBlob:      ciphertextBlob,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		Recipient: &types.RecipientInfoType{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
		},
	}

	log.Printf("[KMS] Requesting decryption with attestation recipient")

	// Send request via VSock
	response, err := a.connectionMgr.SendKMSRequest(ctx, "Decrypt", input)
	if err != nil {
		return nil, fmt.Errorf("KMS Decrypt request failed: %v", err)
	}

	// Parse KMS response
	var output kms.DecryptOutput
	if err := json.Unmarshal(response, &output); err != nil {
		return nil, fmt.Errorf("failed to parse KMS Decrypt response: %v", err)
	}

	log.Printf("[KMS] Received KMS decrypt response - CiphertextForRecipient: %d bytes",
		len(output.CiphertextForRecipient))

	// Decrypt the envelope key using our private key
	plaintextKey, err := cms.DecryptEnvelopedKey(a.enclaveHandle.PrivateKey(), output.CiphertextForRecipient)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt envelope key: %v", err)
	}

	log.Printf("[KMS] Successfully decrypted envelope key (%d bytes)", len(plaintextKey))

	return plaintextKey, nil
}

// EncryptAndStoreCacheItem encrypts data and stores it with advanced KMS integration
func (a *AdvancedKMSClient) EncryptAndStoreCacheItem(ctx context.Context, data []byte, filename string) error {
	log.Printf("[KMS] Starting encrypted storage for item: %s (%d bytes)", filename, len(data))

	// Generate data key with attestation
	kmsOutput, plaintextKey, err := a.GenerateDataKeyWithAttestation(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate data key: %v", err)
	}

	// Encrypt data with the plaintext key using AES-GCM
	encryptedData, err := aesGCMOperation(plaintextKey, data, true)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}

	log.Printf("[KMS] Encrypted data (%d bytes -> %d bytes)", len(data), len(encryptedData))

	// Store encrypted data and ciphertext blob
	storeInput := struct {
		Data     []byte `json:"data"`
		Key      []byte `json:"key"`
		Filename string `json:"filename"`
	}{
		Data:     encryptedData,
		Key:      kmsOutput.CiphertextBlob, // Use standard ciphertext blob for storage
		Filename: filename,
	}

	response, err := a.connectionMgr.SendKMSRequest(ctx, "StoreEncryptedItem", storeInput)
	if err != nil {
		return fmt.Errorf("failed to store encrypted item: %v", err)
	}

	// Parse response
	var status struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(response, &status); err != nil {
		return fmt.Errorf("failed to parse store response: %v", err)
	}

	if status.Status != "success" {
		return fmt.Errorf("storage operation failed: %s", status.Status)
	}

	log.Printf("[KMS] Successfully stored encrypted item: %s", filename)
	return nil
}

// LoadAndDecryptCacheItem loads and decrypts an item with advanced KMS integration
func (a *AdvancedKMSClient) LoadAndDecryptCacheItem(ctx context.Context, filename string) ([]byte, error) {
	log.Printf("[KMS] Loading encrypted item: %s", filename)

	// Request encrypted item from storage
	getInput := struct {
		Filename string `json:"filename"`
	}{
		Filename: filename,
	}

	response, err := a.connectionMgr.SendKMSRequest(ctx, "GetEncryptedItem", getInput)
	if err != nil {
		return nil, fmt.Errorf("failed to get encrypted item: %v", err)
	}

	// Parse response
	var output struct {
		Data []byte `json:"data"`
		Key  []byte `json:"key"`
	}
	if err := json.Unmarshal(response, &output); err != nil {
		return nil, fmt.Errorf("failed to parse get response: %v", err)
	}

	log.Printf("[KMS] Retrieved encrypted item - data: %d bytes, key: %d bytes",
		len(output.Data), len(output.Key))

	// Decrypt the ciphertext blob to get the data key
	plaintextKey, err := a.DecryptWithAttestation(ctx, output.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data key: %v", err)
	}

	// Decrypt the actual data using the decrypted key
	plaintext, err := aesGCMOperation(plaintextKey, output.Data, false)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %v", err)
	}

	log.Printf("[KMS] Successfully decrypted item: %s (%d bytes)", filename, len(plaintext))
	return plaintext, nil
}

// DeleteCacheItem deletes an encrypted item from storage
func (a *AdvancedKMSClient) DeleteCacheItem(ctx context.Context, filename string) error {
	log.Printf("[KMS] Deleting encrypted item: %s", filename)

	deleteInput := struct {
		Filename string `json:"filename"`
	}{
		Filename: filename,
	}

	response, err := a.connectionMgr.SendKMSRequest(ctx, "DeleteEncryptedItem", deleteInput)
	if err != nil {
		return fmt.Errorf("failed to delete encrypted item: %v", err)
	}

	// Parse response
	var status struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(response, &status); err != nil {
		return fmt.Errorf("failed to parse delete response: %v", err)
	}

	if status.Status != "success" {
		return fmt.Errorf("delete operation failed: %s", status.Status)
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
