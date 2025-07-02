package shared

import (
	"context"
	"log"
	"sync"

	"golang.org/x/crypto/acme/autocert"
)

// EnclaveCache implements autocert.Cache interface with KMS encryption
type EnclaveCache struct {
	kmsHandler  *ComprehensiveKMSHandler
	mu          sync.RWMutex
	memoryCache map[string][]byte
}

// NewEnclaveCache creates a new enclave cache with comprehensive KMS encryption
func NewEnclaveCache(connectionMgr *VSockConnectionManager, kmsKeyID string) *EnclaveCache {
	return &EnclaveCache{
		kmsHandler:  NewComprehensiveKMSHandler(connectionMgr, kmsKeyID),
		memoryCache: make(map[string][]byte),
	}
}

// Get retrieves and decrypts a cached item using comprehensive KMS handler
func (c *EnclaveCache) Get(ctx context.Context, key string) ([]byte, error) {
	c.mu.RLock()
	// Check memory cache first
	if data, exists := c.memoryCache[key]; exists {
		c.mu.RUnlock()
		log.Printf("[EnclaveCache] Found %s in memory cache (%d bytes)", key, len(data))
		return data, nil
	}
	c.mu.RUnlock()

	log.Printf("[EnclaveCache] %s not in memory cache, loading from KMS", key)

	// Attempt to load from persistent storage using comprehensive KMS handler with attestation
	data, err := c.kmsHandler.LoadAndDecryptCacheItem(ctx, key)
	if err != nil {
		log.Printf("[EnclaveCache] Failed to load %s from KMS: %v", key, err)
		return nil, err
	}

	// Store successfully retrieved data in memory cache
	c.mu.Lock()
	c.memoryCache[key] = data
	c.mu.Unlock()

	log.Printf("[EnclaveCache] Successfully loaded %s from KMS and cached in memory (%d bytes)", key, len(data))
	return data, nil
}

// Put encrypts and stores a cached item using comprehensive KMS handler
func (c *EnclaveCache) Put(ctx context.Context, key string, data []byte) error {
	// Store in memory cache
	c.mu.Lock()
	c.memoryCache[key] = data
	c.mu.Unlock()

	// Store encrypted version using comprehensive KMS handler with attestation
	return c.kmsHandler.EncryptAndStoreCacheItem(ctx, data, key)
}

// Delete removes a cached item using comprehensive KMS handler
func (c *EnclaveCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	delete(c.memoryCache, key)
	c.mu.Unlock()

	// Delete from persistent storage using comprehensive KMS handler
	return c.kmsHandler.DeleteCacheItem(ctx, key)
}

// NOTE: All encryption/decryption operations now handled by ComprehensiveKMSHandler

// Ensure EnclaveCache implements autocert.Cache interface
var _ autocert.Cache = (*EnclaveCache)(nil)
