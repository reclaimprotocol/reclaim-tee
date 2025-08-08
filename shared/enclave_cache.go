package shared

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
)

// EnclaveCache implements autocert.Cache interface with KMS encryption
type EnclaveCache struct {
	kmsHandler  *KMSHandler
	kmsAdapter  *KMSHandlerAdapter
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

// NewEnclaveCacheWithProvider creates a cache backed by an abstract KMSProvider
func NewEnclaveCacheWithProvider(provider KMSProvider, connectionMgr *VSockConnectionManager, serviceName string) *EnclaveCache {
	log.Printf("[EnclaveCache:%s] Creating new enclave cache (provider abstraction)", serviceName)
	return &EnclaveCache{
		kmsHandler:  nil,
		kmsAdapter:  &KMSHandlerAdapter{provider: provider, connectionMgr: connectionMgr, serviceName: serviceName},
		serviceName: serviceName,
		memoryCache: make(map[string][]byte),
	}
}

// KMSHandlerAdapter is a drop-in replacement for the subset of methods used by EnclaveCache
type KMSHandlerAdapter struct {
	provider      KMSProvider
	connectionMgr *VSockConnectionManager
	serviceName   string
}

// EncryptAndStoreCacheItem encrypts data using the provider and stores alongside the provider's key blob
func (a *KMSHandlerAdapter) EncryptAndStoreCacheItem(ctx context.Context, data []byte, filename string) error {
	// Generate a new data key via provider
	dk, err := a.provider.GenerateDataKey("")
	if err != nil {
		return err
	}
	// Encrypt data locally with plaintext key
	encryptedData, err := aesGCMOperation(dk.Plaintext, data, true)
	if err != nil {
		return err
	}
	// Store via proxy storage operations to keep behavior identical
	storeInput := struct {
		Data     []byte `json:"data"`
		Key      []byte `json:"key"`
		Filename string `json:"filename"`
	}{
		Data:     encryptedData,
		Key:      dk.CiphertextBlob,
		Filename: filename,
	}
	// Reuse KMS request channel for storage ops
	_, err = a.connectionMgr.SendKMSRequest(ctx, "StoreEncryptedItem", a.serviceName, storeInput)
	return err
}

// LoadAndDecryptCacheItem loads and decrypts an item using the provider to unwrap key
func (a *KMSHandlerAdapter) LoadAndDecryptCacheItem(ctx context.Context, filename string) ([]byte, error) {
	// Load encrypted item
	loadInput := struct {
		Filename string `json:"filename"`
	}{Filename: filename}

	resp, err := a.connectionMgr.SendKMSRequest(ctx, "GetEncryptedItem", a.serviceName, loadInput)
	if err != nil {
		return nil, err
	}
	var output struct {
		Data []byte `json:"data"`
		Key  []byte `json:"key"`
	}
	if err := json.Unmarshal(resp, &output); err != nil {
		return nil, err
	}
	if len(output.Data) == 0 || len(output.Key) == 0 {
		return nil, fmt.Errorf("cache miss")
	}
	// Decrypt using provider
	return a.provider.Decrypt(output.Data, "", output.Key)
}

// DeleteCacheItem deletes stored item
func (a *KMSHandlerAdapter) DeleteCacheItem(ctx context.Context, filename string) error {
	deleteInput := struct {
		Filename string `json:"filename"`
	}{Filename: filename}
	_, err := a.connectionMgr.SendKMSRequest(ctx, "DeleteEncryptedItem", a.serviceName, deleteInput)
	return err
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

	// Attempt to load from persistent storage using configured handler/adapter
	var (
		data []byte
		err  error
	)
	if c.kmsAdapter != nil {
		data, err = c.kmsAdapter.LoadAndDecryptCacheItem(ctx, key)
	} else {
		data, err = c.kmsHandler.LoadAndDecryptCacheItem(ctx, key)
	}
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

	// Store encrypted version using configured handler/adapter
	var err error
	if c.kmsAdapter != nil {
		err = c.kmsAdapter.EncryptAndStoreCacheItem(ctx, data, key)
	} else {
		err = c.kmsHandler.EncryptAndStoreCacheItem(ctx, data, key)
	}
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

	// Delete from persistent storage using configured handler/adapter
	if c.kmsAdapter != nil {
		return c.kmsAdapter.DeleteCacheItem(ctx, key)
	}
	return c.kmsHandler.DeleteCacheItem(ctx, key)
}
