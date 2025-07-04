package shared

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// VSockConnectionManager provides production-grade VSock connection management
// with advanced features from nitro.go
type VSockConnectionManager struct {
	kmsPool      *VSockPool
	internetPool *VSockPool

	// Caching components
	attestationCache *AttestationCache
	memoryCache      *SmartMemoryCache

	mu           sync.RWMutex
	isRunning    bool
	shutdownOnce sync.Once
}

// VSockConfig holds configuration for the enhanced connection manager
type VSockConfig struct {
	ParentCID    uint32
	KMSPort      uint32
	InternetPort uint32
	KMSKeyID     string

	// Pool configurations
	KMSPoolConfig      *ProductionVSockPoolConfig
	InternetPoolConfig *ProductionVSockPoolConfig

	// Cache configurations
	AttestationCacheTTL time.Duration
	MemoryCacheTTL      time.Duration
}

// NewEnhancedVSockConnectionManager creates a new enhanced connection manager
func NewVSockConnectionManager(config *VSockConfig) *VSockConnectionManager {
	if config == nil {
		config = &VSockConfig{
			ParentCID:           3,
			KMSPort:             5000,
			InternetPort:        8444,
			AttestationCacheTTL: 4 * time.Minute,
			MemoryCacheTTL:      10 * time.Minute,
		}
	}

	// Initialize KMS pool
	kmsPoolConfig := config.KMSPoolConfig
	if kmsPoolConfig == nil {
		kmsPoolConfig = &ProductionVSockPoolConfig{
			CID:              config.ParentCID,
			Port:             config.KMSPort,
			MinPoolSize:      5,
			MaxPoolSize:      20,
			ConnectionTTL:    5 * time.Minute,
			IdleTimeout:      30 * time.Second,
			ValidationPeriod: 30 * time.Second,
			CleanupInterval:  60 * time.Second,
		}
	}

	// Initialize Internet pool
	internetPoolConfig := config.InternetPoolConfig
	if internetPoolConfig == nil {
		internetPoolConfig = &ProductionVSockPoolConfig{
			CID:              config.ParentCID,
			Port:             config.InternetPort,
			MinPoolSize:      3,
			MaxPoolSize:      15,
			ConnectionTTL:    3 * time.Minute,
			IdleTimeout:      30 * time.Second,
			ValidationPeriod: 30 * time.Second,
			CleanupInterval:  60 * time.Second,
		}
	}

	manager := &VSockConnectionManager{
		kmsPool:      NewProductionVSockPool(kmsPoolConfig),
		internetPool: NewProductionVSockPool(internetPoolConfig),
	}

	// Initialize attestation cache using global singleton handle
	handle, err := SafeGetEnclaveHandle()
	if err != nil {
		log.Printf("[EnhancedVSock] Warning: Failed to get global handle for attestation cache: %v", err)
	} else {
		manager.attestationCache = NewAttestationCache(handle, config.AttestationCacheTTL)
	}

	return manager
}

// Start initializes all components and begins operation
func (evm *VSockConnectionManager) Start(ctx context.Context) error {
	evm.mu.Lock()
	defer evm.mu.Unlock()

	if evm.isRunning {
		return fmt.Errorf("enhanced connection manager is already running")
	}

	log.Printf("[EnhancedVSock] Starting enhanced VSock connection manager")

	// Start KMS pool
	if err := evm.kmsPool.Start(ctx); err != nil {
		return fmt.Errorf("failed to start KMS pool: %v", err)
	}

	// Start Internet pool
	if err := evm.internetPool.Start(ctx); err != nil {
		evm.kmsPool.Shutdown(ctx)
		return fmt.Errorf("failed to start Internet pool: %v", err)
	}

	// Start attestation cache
	if evm.attestationCache != nil {
		if err := evm.attestationCache.Start(ctx); err != nil {
			log.Printf("[EnhancedVSock] Warning: Failed to start attestation cache: %v", err)
		}
	}

	// Start memory cache
	if evm.memoryCache != nil {
		if err := evm.memoryCache.Start(ctx); err != nil {
			log.Printf("[EnhancedVSock] Warning: Failed to start memory cache: %v", err)
		}
	}

	evm.isRunning = true
	log.Printf("[EnhancedVSock] Enhanced connection manager started successfully")
	return nil
}

// SendKMSRequestWithService sends a request to KMS with service name for cache grouping
func (evm *VSockConnectionManager) SendKMSRequest(ctx context.Context, operation string, serviceName string, data interface{}) ([]byte, error) {
	// Use crypto-secure retry logic
	var result []byte
	err := RetryWithBackoff(DefaultRetryConfig(), func() error {
		conn, err := evm.kmsPool.GetConnection(ctx)
		if err != nil {
			return fmt.Errorf("failed to get KMS connection: %v", err)
		}
		defer evm.kmsPool.ReturnConnection(conn)

		// Prepare request
		request := map[string]interface{}{
			"operation":    operation,
			"service_name": serviceName,
			"input":        data, // Changed from "data" to "input" to match KMS proxy structure
		}

		// Send request
		conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if err = json.NewEncoder(conn).Encode(request); err != nil {
			return fmt.Errorf("failed to send KMS request: %v", err)
		}

		// Read response
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		var response struct {
			Output json.RawMessage `json:"output,omitempty"`
			Error  string          `json:"error,omitempty"`
		}

		if err := json.NewDecoder(conn).Decode(&response); err != nil {
			return fmt.Errorf("failed to read KMS response: %v", err)
		}

		if response.Error != "" {
			return fmt.Errorf("KMS operation failed: %s", response.Error)
		}

		result = response.Output
		return nil

	})

	if err != nil {
		return nil, fmt.Errorf("KMS request failed after retries: %v", err)
	}

	return result, nil
}

// SendInternetRequest sends a request to the internet proxy
func (evm *VSockConnectionManager) SendInternetRequest(ctx context.Context, url string) ([]byte, error) {

	// Use crypto-secure retry logic
	var result []byte
	err := RetryWithBackoff(DefaultRetryConfig(), func() error {
		conn, err := evm.internetPool.GetConnection(ctx)
		if err != nil {
			return fmt.Errorf("failed to get internet connection: %v", err)
		}
		defer evm.internetPool.ReturnConnection(conn)

		// Send URL to proxy
		if _, err := fmt.Fprintf(conn, "%s\n", url); err != nil {
			return fmt.Errorf("failed to send URL: %v", err)
		}

		// Read response
		response := make([]byte, 8192)
		n, err := conn.Read(response)
		if err != nil {
			return fmt.Errorf("failed to read response: %v", err)
		}

		result = response[:n]
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("internet request failed after retries: %v", err)
	}

	return result, nil
}

// GetCachedAttestation retrieves an attestation document with caching
func (evm *VSockConnectionManager) GetCachedAttestation(ctx context.Context, userData []byte) ([]byte, error) {
	if evm.attestationCache == nil {
		return nil, fmt.Errorf("attestation cache not initialized")
	}

	return evm.attestationCache.GetAttestation(ctx, userData)
}

// StoreInCache stores data in the memory cache
func (evm *VSockConnectionManager) StoreInCache(key string, data interface{}) {
	if evm.memoryCache != nil {
		evm.memoryCache.Put(key, data)
	}
}

// GetFromCache retrieves data from the memory cache
func (evm *VSockConnectionManager) GetFromCache(ctx context.Context, key string) (interface{}, error) {
	if evm.memoryCache == nil {
		return nil, fmt.Errorf("memory cache not initialized")
	}

	return evm.memoryCache.Get(ctx, key)
}

// Shutdown gracefully shuts down all components
func (evm *VSockConnectionManager) Shutdown(ctx context.Context) error {
	var shutdownErr error
	evm.shutdownOnce.Do(func() {
		evm.mu.Lock()
		defer evm.mu.Unlock()

		if !evm.isRunning {
			return
		}

		log.Printf("[EnhancedVSock] Shutting down enhanced connection manager")

		// Shutdown memory cache
		if evm.memoryCache != nil {
			if err := evm.memoryCache.Shutdown(ctx); err != nil {
				log.Printf("[EnhancedVSock] Memory cache shutdown error: %v", err)
			}
		}

		// Shutdown attestation cache
		if evm.attestationCache != nil {
			if err := evm.attestationCache.Shutdown(ctx); err != nil {
				log.Printf("[EnhancedVSock] Attestation cache shutdown error: %v", err)
			}
		}

		// Shutdown pools
		if err := evm.internetPool.Shutdown(ctx); err != nil {
			log.Printf("[EnhancedVSock] Internet pool shutdown error: %v", err)
		}

		if err := evm.kmsPool.Shutdown(ctx); err != nil {
			log.Printf("[EnhancedVSock] KMS pool shutdown error: %v", err)
		}

		evm.isRunning = false
		log.Printf("[EnhancedVSock] Enhanced connection manager shutdown completed")
	})

	return shutdownErr
}
