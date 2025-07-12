package shared

import (
	"context"
	"log"
	"sync"
)

// EnclaveCache implements autocert.Cache interface with KMS encryption
type EnclaveCache struct {
	kmsHandler  *KMSHandler
	serviceName string // Service name prefix (tee_k or tee_t)
	mu          sync.RWMutex
	memoryCache map[string][]byte
	stats       struct {
		hits   int
		misses int
	}
}

// NewEnclaveCache creates a new enclave cache with comprehensive KMS encryption and service-specific prefixes
func NewEnclaveCache(connectionMgr *VSockConnectionManager, kmsKeyID string, serviceName string) *EnclaveCache {
	log.Printf("[EnclaveCache:%s] Creating new enclave cache", serviceName)
	return &EnclaveCache{
		kmsHandler:  NewKMSHandler(connectionMgr, kmsKeyID, serviceName),
		serviceName: serviceName,
		memoryCache: make(map[string][]byte),
	}
}

// Get retrieves and decrypts a cached item using comprehensive KMS handler
func (c *EnclaveCache) Get(ctx context.Context, key string) ([]byte, error) {
	c.mu.RLock()
	// Check memory cache first
	if data, exists := c.memoryCache[key]; exists {
		c.mu.RUnlock()
		c.stats.hits++
		log.Printf("[EnclaveCache:%s] CACHE HIT (%d hits/%d misses) - Found %s in memory cache (%d bytes)",
			c.serviceName, c.stats.hits, c.stats.misses, key, len(data))
		return data, nil
	}
	c.mu.RUnlock()

	c.stats.misses++
	log.Printf("[EnclaveCache:%s] CACHE MISS (%d hits/%d misses) - %s not in memory cache, loading from KMS",
		c.serviceName, c.stats.hits, c.stats.misses, key)

	// Attempt to load from persistent storage using comprehensive KMS handler with attestation
	data, err := c.kmsHandler.LoadAndDecryptCacheItem(ctx, key)
	if err != nil {
		log.Printf("[EnclaveCache:%s] Failed to load %s from KMS: %v", c.serviceName, key, err)
		return nil, err
	}

	// Store successfully retrieved data in memory cache
	c.mu.Lock()
	c.memoryCache[key] = data
	c.mu.Unlock()

	log.Printf("[EnclaveCache:%s] Successfully loaded %s from KMS and cached in memory (%d bytes)", c.serviceName, key, len(data))
	return data, nil
}

// Put encrypts and stores a cached item using comprehensive KMS handler
func (c *EnclaveCache) Put(ctx context.Context, key string, data []byte) error {
	// Store in memory cache first
	c.mu.Lock()
	c.memoryCache[key] = data
	c.mu.Unlock()
	log.Printf("[EnclaveCache:%s] Stored %s in memory cache", c.serviceName, key)

	// Store encrypted version using comprehensive KMS handler with attestation
	err := c.kmsHandler.EncryptAndStoreCacheItem(ctx, data, key)
	if err != nil {
		log.Printf("[EnclaveCache:%s] ERROR storing %s in KMS: %v", c.serviceName, key, err)
		return err
	}

	log.Printf("[EnclaveCache:%s] Successfully stored %s in KMS cache", c.serviceName, key)
	return nil
}

// Delete removes a cached item using comprehensive KMS handler
func (c *EnclaveCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	delete(c.memoryCache, key)
	c.mu.Unlock()

	// Delete from persistent storage using comprehensive KMS handler
	return c.kmsHandler.DeleteCacheItem(ctx, key)
}
