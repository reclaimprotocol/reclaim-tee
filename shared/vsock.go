package shared

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/austinast/nitro-enclaves-sdk-go/crypto/cms"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/hf/nsm/request"
	"github.com/mdlayher/vsock"
	"golang.org/x/crypto/acme/autocert"
)

type CircuitState int32

const (
	enclaveVsockParentCID                         = 3
	maxConnectionRetries, circuitBreakerThreshold = 5, 5
	initialBackoffDelay, maxBackoffDelay          = 100 * time.Millisecond, 10 * time.Second
	connectionTimeout, readWriteTimeout           = 10 * time.Second, 30 * time.Second
	circuitBreakerTimeout                         = 60 * time.Second
)

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

var (
	globalConnectionManager                                              *VSockConnectionManager
	connectionManagerOnce                                                sync.Once
	globalHandle                                                         *EnclaveHandle
	initializationError                                                  error
	initMutex                                                            sync.Mutex
	attestationCache                                                     = make(map[string]attestationCacheEntry)
	attestationMu                                                        sync.RWMutex
	attestationTTL                                                       = 4*time.Minute + 50*time.Second
	enclaveVsockHTTPPort, enclaveVsockHTTPSPort, enclaveVsockForwardPort = 8080, 8443, 8444
	eRetryDelay                                                          = 2 * time.Second
)

type (
	Request struct {
		Operation string          `json:"operation"`
		Input     json.RawMessage `json:"input"`
	}
	Response struct {
		Data  json.RawMessage `json:"output"`
		Error string          `json:"error"`
	}
	GetItemInput struct {
		Filename string `json:"filename"`
	}
	GetItemOutput struct {
		Data []byte `json:"data"`
		Key  []byte `json:"key"`
	}
	DeleteItemInput struct {
		Filename string `json:"filename"`
	}
	StoreItemInput struct {
		Data     []byte `json:"data"`
		Key      []byte `json:"key"`
		Filename string `json:"filename"`
	}
	StatusOutput struct {
		Status string `json:"status"`
	}

	VSockConnectionManager struct {
		pool           *VSockPool
		circuitBreaker *CircuitBreaker
		metrics        *ConnectionMetrics
	}
	CircuitBreaker struct {
		state, failures              int32
		lastFailure, lastStateChange time.Time
		mu                           sync.RWMutex
	}
	ConnectionMetrics struct {
		totalRequests, successfulReqs, failedReqs, avgResponseTime int64
		mu                                                         sync.RWMutex
	}
	VSockPool struct {
		mu                 sync.RWMutex
		connections        chan net.Conn
		factory            func() (net.Conn, error)
		maxIdle, maxActive int
		idleTimeout        time.Duration
		stopCh             chan struct{}
	}
	attestationCacheEntry struct {
		doc       []byte
		createdAt time.Time
	}
	AttestationOptions struct {
		Nonce, UserData []byte
		NoPublicKey     bool
		PublicKey       any
	}
)

func NewVSockPool(maxIdle, maxActive int) *VSockPool {
	pool := &VSockPool{
		connections: make(chan net.Conn, maxIdle),
		maxIdle:     maxIdle,
		maxActive:   maxActive,
		idleTimeout: 5 * time.Minute,
		stopCh:      make(chan struct{}),
		factory: func() (net.Conn, error) {
			ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
			defer cancel()

			log.Printf("Creating new VSock connection to CID %d port 5000", enclaveVsockParentCID)
			startTime := time.Now()
			conn, err := vsock.Dial(enclaveVsockParentCID, 5000, nil)
			if err != nil {
				log.Printf("Failed to create VSock connection after %v: %v", time.Since(startTime), err)
				return nil, err
			}
			log.Printf("Successfully created VSock connection to %s in %v", conn.RemoteAddr(), time.Since(startTime))

			// Set connection timeouts
			if deadline, ok := ctx.Deadline(); ok {
				conn.SetDeadline(deadline)
				log.Printf("Set connection deadline to %v", deadline)
			}

			return conn, nil
		},
	}

	// Start idle connection cleanup routine
	go pool.idleCleanupRoutine()

	return pool
}

func (p *VSockPool) Get(ctx context.Context) (net.Conn, error) {

	select {
	case conn := <-p.connections:
		// Quick validation - try to set deadline
		if err := conn.SetDeadline(time.Now().Add(1 * time.Second)); err != nil {
			log.Printf("Pool connection validation failed, closing and creating new: %v", err)
			conn.Close()
			// Connection is bad, create new one
			return p.factory()
		}
		conn.SetDeadline(time.Time{}) // Clear deadline
		return conn, nil
	default:
		log.Printf("No idle connections available (pool was empty), creating new connection")
		// No idle connections available, create new one
		return p.factory()
	}
}

func (p *VSockPool) Put(conn net.Conn) {
	if conn == nil {
		return
	}

	select {
	case p.connections <- conn:
		log.Printf("Successfully returned connection to pool, remote addr: %s", conn.RemoteAddr())
	default:
		log.Printf("Pool is full, closing connection: %s", conn.RemoteAddr())
		conn.Close()
	}
}

func (p *VSockPool) idleCleanupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.cleanupIdleConnections()
		case <-p.stopCh:
			return
		}
	}
}

func (p *VSockPool) cleanupIdleConnections() {
	// Drain and test connections in the pool
	var validConnections []net.Conn

	// Check up to maxIdle connections
	for i := 0; i < p.maxIdle; i++ {
		select {
		case conn := <-p.connections:
			// Test if connection is still valid
			if err := conn.SetDeadline(time.Now().Add(1 * time.Second)); err != nil {
				conn.Close()
				continue
			}
			conn.SetDeadline(time.Time{}) // Clear deadline
			validConnections = append(validConnections, conn)
		default:
			// No more connections in pool
			break
		}
	}

	// Put valid connections back
	for _, conn := range validConnections {
		select {
		case p.connections <- conn:
		default:
			// Pool is full, close excess connections
			conn.Close()
		}
	}
}

func (p *VSockPool) Close() {
	close(p.stopCh)

	// Close all idle connections
	close(p.connections)
	for conn := range p.connections {
		conn.Close()
	}
}

func getConnectionManager() *VSockConnectionManager {
	connectionManagerOnce.Do(func() {
		globalConnectionManager = &VSockConnectionManager{
			pool: NewVSockPool(10, 50), circuitBreaker: &CircuitBreaker{state: int32(CircuitClosed)}, metrics: &ConnectionMetrics{},
		}
	})
	return globalConnectionManager
}

func (cb *CircuitBreaker) CanExecute() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	state := CircuitState(atomic.LoadInt32(&cb.state))
	switch state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		if time.Since(cb.lastStateChange) >= circuitBreakerTimeout {
			cb.setState(CircuitHalfOpen)
			return true
		}
		return false
	case CircuitHalfOpen:
		return true
	default:
		return false
	}
}

func (cb *CircuitBreaker) OnSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	atomic.StoreInt32(&cb.failures, 0)
	if CircuitState(atomic.LoadInt32(&cb.state)) == CircuitHalfOpen {
		cb.setState(CircuitClosed)
	}
}

func (cb *CircuitBreaker) OnFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	failures := atomic.AddInt32(&cb.failures, 1)
	cb.lastFailure = time.Now()
	if failures >= circuitBreakerThreshold {
		cb.setState(CircuitOpen)
	}
}

func (cb *CircuitBreaker) setState(state CircuitState) {
	atomic.StoreInt32(&cb.state, int32(state))
	cb.lastStateChange = time.Now()
	log.Printf("Circuit breaker state changed to: %d", state)
}

func (m *ConnectionMetrics) recordSuccess(duration time.Duration) {
	atomic.AddInt64(&m.totalRequests, 1)
	atomic.AddInt64(&m.successfulReqs, 1)
	currentAvg := atomic.LoadInt64(&m.avgResponseTime)
	atomic.StoreInt64(&m.avgResponseTime, (currentAvg+duration.Nanoseconds())/2)
}

func (m *ConnectionMetrics) recordFailure() {
	atomic.AddInt64(&m.totalRequests, 1)
	atomic.AddInt64(&m.failedReqs, 1)
}

func (m *ConnectionMetrics) GetStats() (int64, int64, int64, time.Duration) {
	return atomic.LoadInt64(&m.totalRequests), atomic.LoadInt64(&m.successfulReqs),
		atomic.LoadInt64(&m.failedReqs), time.Duration(atomic.LoadInt64(&m.avgResponseTime))
}

func sendVsockRequest(operation string, input interface{}) (Response, error) {
	return sendVsockRequestWithContext(context.Background(), operation, input)
}

func sendVsockRequestWithContext(ctx context.Context, operation string, input interface{}) (Response, error) {
	manager := getConnectionManager()
	if !manager.circuitBreaker.CanExecute() {
		log.Printf("Circuit breaker is open for operation: %s", operation)
		manager.metrics.recordFailure()
		return Response{}, errors.New("circuit breaker is open")
	}

	overallStartTime := time.Now()
	log.Printf("Starting VSock request sequence for operation: %s", operation)
	var lastErr error
	for attempt := 0; attempt < maxConnectionRetries; attempt++ {
		if attempt > 0 {
			backoffDelay := calculateBackoff(attempt)
			log.Printf("Retrying vsock request for %s (attempt %d/%d) after %v", operation, attempt+1, maxConnectionRetries, backoffDelay)
			select {
			case <-ctx.Done():
				log.Printf("Context cancelled during retry for %s: %v", operation, ctx.Err())
				return Response{}, ctx.Err()
			case <-time.After(backoffDelay):
			}
		}

		attemptStartTime := time.Now()
		resp, err := executeSingleRequest(ctx, manager, operation, input)
		if err == nil {
			manager.circuitBreaker.OnSuccess()
			manager.metrics.recordSuccess(time.Since(overallStartTime))
			return resp, nil
		}
		lastErr = err
		log.Printf("VSock request failed for %s (attempt %d/%d) in %v: %v", operation, attempt+1, maxConnectionRetries, time.Since(attemptStartTime), err)
		if isNonRetryableError(err) {
			log.Printf("Non-retryable error for %s, stopping attempts: %v", operation, err)
			break
		}
	}
	log.Printf("All VSock request attempts failed for %s after %v", operation, time.Since(overallStartTime))
	manager.circuitBreaker.OnFailure()
	manager.metrics.recordFailure()
	return Response{}, fmt.Errorf("vsock request failed after %d attempts: %v", maxConnectionRetries, lastErr)
}

func executeSingleRequest(ctx context.Context, manager *VSockConnectionManager, operation string, input interface{}) (Response, error) {
	startTime := time.Now()
	log.Printf("Starting VSock request for operation: %s", operation)

	inputBytes, err := json.Marshal(input)
	if err != nil {
		log.Printf("Failed to marshal input for %s: %v", operation, err)
		return Response{}, fmt.Errorf("failed to marshal input: %v", err)
	}

	req := Request{Operation: operation, Input: inputBytes}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		log.Printf("Failed to marshal request for %s: %v", operation, err)
		return Response{}, fmt.Errorf("failed to marshal request: %v", err)
	}

	connStartTime := time.Now()
	conn, err := manager.pool.Get(ctx)
	if err != nil {
		log.Printf("Failed to get connection for %s after %v: %v", operation, time.Since(connStartTime), err)
		return Response{}, fmt.Errorf("failed to get connection: %v", err)
	}

	defer func() {
		if err != nil {
			log.Printf("Closing connection for %s due to error: %v", operation, err)
			conn.Close()
		} else {
			log.Printf("Returning connection to pool for %s after %v", operation, time.Since(startTime))
			manager.pool.Put(conn)
		}
	}()

	writeStartTime := time.Now()
	conn.SetWriteDeadline(time.Now().Add(readWriteTimeout))
	if _, err = conn.Write(reqBytes); err != nil {
		log.Printf("Failed to write request for %s after %v (conn age: %v): %v", operation, time.Since(writeStartTime), time.Since(startTime), err)
		return Response{}, fmt.Errorf("failed to send request: %v", err)
	}
	log.Printf("Wrote request for %s in %v", operation, time.Since(writeStartTime))

	readStartTime := time.Now()
	conn.SetReadDeadline(time.Now().Add(readWriteTimeout))
	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("Failed to read response for %s after %v (total time: %v): %v", operation, time.Since(readStartTime), time.Since(startTime), err)
		return Response{}, fmt.Errorf("failed to read response: %v", err)
	}
	log.Printf("Read response for %s: %d bytes in %v", operation, n, time.Since(readStartTime))

	parseStartTime := time.Now()
	var resp Response
	if err = json.Unmarshal(buf[:n], &resp); err != nil {
		log.Printf("Failed to parse response for %s: %v, raw response: %s", operation, err, string(buf[:n]))
		return Response{}, fmt.Errorf("failed to parse response: %v", err)
	}
	log.Printf("Parsed response for %s in %v", operation, time.Since(parseStartTime))

	if resp.Error != "" {
		log.Printf("VSock-proxy returned error for %s: %s", operation, resp.Error)
		return Response{}, fmt.Errorf("vsock-proxy error: %s", resp.Error)
	}

	log.Printf("Completed VSock request for %s in total time: %v", operation, time.Since(startTime))
	return resp, nil
}

func calculateBackoff(attempt int) time.Duration {
	if attempt <= 0 {
		return initialBackoffDelay
	}
	delay := time.Duration(float64(initialBackoffDelay) * math.Pow(2, float64(attempt-1)))
	if delay > maxBackoffDelay {
		delay = maxBackoffDelay
	}
	return delay + cryptoJitter(float64(delay)*0.1)
}

func cryptoJitter(maxJitter float64) time.Duration {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return 0
	}
	var n uint64
	for i, b := range bytes {
		n |= uint64(b) << (8 * i)
	}
	return time.Duration(float64(n) / float64(^uint64(0)) * maxJitter)
}

func isNonRetryableError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	for _, nonRetryable := range []string{"invalid input", "unsupported operation", "authentication failed", "authorization failed"} {
		if strings.Contains(errStr, nonRetryable) {
			return true
		}
	}
	return false
}

func loadCachedItem(ctx context.Context, cache *MemoryCache, filename string, kmsKeyID string) error {
	resp, err := sendVsockRequest("GetCachedItem", GetItemInput{Filename: filename})
	if err != nil {
		return err
	}

	var status StatusOutput
	if err = json.Unmarshal(resp.Data, &status); err == nil && status.Status == "not_found" {
		return autocert.ErrCacheMiss
	}

	var output GetItemOutput
	if err = json.Unmarshal(resp.Data, &output); err != nil {
		log.Printf("failed to parse GetCachedItem response for %s: %v", filename, err)
		return autocert.ErrCacheMiss
	}

	if len(output.Data) == 0 || len(output.Key) == 0 {
		return autocert.ErrCacheMiss
	}

	data, err := decryptItem(output.Data, output.Key, kmsKeyID)
	if err != nil {
		return fmt.Errorf("failed to decrypt item for %s: %v", filename, err)
	}

	cache.Put(ctx, filename, data)
	return nil
}

func deleteCachedItem(filename string) error {
	resp, err := sendVsockRequest("DeleteCachedItem", DeleteItemInput{Filename: filename})
	if err != nil {
		return err
	}

	var output StatusOutput
	if err = json.Unmarshal(resp.Data, &output); err != nil {
		return fmt.Errorf("failed to parse DeleteCachedItem response: %v", err)
	}

	if output.Status != "success" {
		return fmt.Errorf("failed to delete item: %s", filename)
	}
	return nil
}

// aesGCMOperation handles AES-GCM encryption or decryption based on the encrypt flag.
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
		nonce := make([]byte, nonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %v", err)
		}
		return append(nonce, gcm.Seal(nil, nonce, data, nil)...), nil
	}
	if len(data) < nonceSize {
		return nil, errors.New("encrypted data too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// encryptAndStoreCacheItem encrypts data and stores it via vsock.
func encryptAndStoreCacheItem(data []byte, filename string, kmsKeyID string) error {
	handle := MustGlobalHandle()
	attestationDoc, err := handle.GenerateAttestation(nil)
	if err != nil {
		return fmt.Errorf("failed to generate attestation: %v", err)
	}

	input := kms.GenerateDataKeyInput{
		KeyId:   aws.String(kmsKeyID),
		KeySpec: "AES_256",
		Recipient: &types.RecipientInfoType{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
		},
	}

	resp, err := sendVsockRequest("GenerateDataKey", input)
	if err != nil {
		return err
	}

	var output kms.GenerateDataKeyOutput
	if err = json.Unmarshal(resp.Data, &output); err != nil {
		return fmt.Errorf("failed to parse KMS output: %v", err)
	}

	plaintextKey, err := cms.DecryptEnvelopedKey(handle.PrivateKey(), output.CiphertextForRecipient)
	if err != nil {
		return fmt.Errorf("failed to decrypt KMS data key: %v", err)
	}

	encryptedData, err := aesGCMOperation(plaintextKey, data, true)
	if err != nil {
		return err
	}

	storeInput := StoreItemInput{Data: encryptedData, Key: output.CiphertextBlob, Filename: filename}
	resp, err = sendVsockRequest("StoreEncryptedItem", storeInput)
	if err != nil {
		return err
	}

	var status StatusOutput
	if err = json.Unmarshal(resp.Data, &status); err != nil {
		return fmt.Errorf("failed to parse StoreEncryptedItem response: %v", err)
	}

	if status.Status != "success" {
		return fmt.Errorf("failed to store item: %s", filename)
	}
	return nil
}

// decryptItem decrypts item data.
func decryptItem(encryptedData, ciphertextBlob []byte, kmsKeyID string) ([]byte, error) {
	handle := MustGlobalHandle()
	attestationDoc, err := handle.GenerateAttestation(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation: %v", err)
	}

	input := kms.DecryptInput{
		KeyId:               aws.String(kmsKeyID),
		CiphertextBlob:      ciphertextBlob,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		Recipient: &types.RecipientInfoType{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
		},
	}

	resp, err := sendVsockRequest("Decrypt", input)
	if err != nil {
		return nil, err
	}

	var output kms.DecryptOutput
	if err = json.Unmarshal(resp.Data, &output); err != nil {
		return nil, fmt.Errorf("failed to parse KMS output: %v", err)
	}

	plaintextKey, err := cms.DecryptEnvelopedKey(handle.PrivateKey(), output.CiphertextForRecipient)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt KMS ciphertext for recipient: %v", err)
	}

	return aesGCMOperation(plaintextKey, encryptedData, false)
}

func NewMemoryCache(kmsKeyID string) *MemoryCache {
	return &MemoryCache{items: make(map[string][]byte), kmsKeyID: kmsKeyID}
}

func (c *MemoryCache) Get(ctx context.Context, key string) ([]byte, error) {
	c.mu.RLock()
	data, ok := c.items[key]
	c.mu.RUnlock()
	if !ok {
		if err := loadCachedItem(ctx, c, key, c.kmsKeyID); err != nil {
			if errors.Is(err, autocert.ErrCacheMiss) {
				return nil, autocert.ErrCacheMiss
			}
			return nil, fmt.Errorf("failed to load item: %v", err)
		}
		c.mu.RLock()
		data, ok = c.items[key]
		c.mu.RUnlock()
		if !ok {
			return nil, autocert.ErrCacheMiss
		}
	}
	return data, nil
}

func (c *MemoryCache) Put(ctx context.Context, key string, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = data
	log.Printf("Stored item in cache for key: %s, data length: %d bytes", key, len(data))
	if err := encryptAndStoreCacheItem(data, key, c.kmsKeyID); err != nil {
		log.Printf("Failed to encrypt and store item: %v", err)
	}
	return nil
}

func (c *MemoryCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	log.Printf("Deleting item from cache for key: %s", key)
	delete(c.items, key)
	if err := deleteCachedItem(key); err != nil {
		log.Printf("Failed to delete item from vsock: %v", err)
	}
	return nil
}

func (e *EnclaveHandle) Attest(args AttestationOptions) ([]byte, error) {
	var publicKey []byte
	var err error
	if args.PublicKey != nil && !args.NoPublicKey {
		if publicKey, err = x509.MarshalPKIXPublicKey(args.PublicKey); err != nil {
			return nil, err
		}
	} else if !args.NoPublicKey {
		if publicKey, err = x509.MarshalPKIXPublicKey(e.PublicKey()); err != nil {
			return nil, err
		}
	}

	res, err := e.nsm.Send(&request.Attestation{Nonce: args.Nonce, UserData: args.UserData, PublicKey: publicKey})
	if err != nil {
		return nil, err
	}
	if res.Error != "" {
		return nil, errors.New(string(res.Error))
	}
	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, errors.New("attestation response missing attestation document")
	}
	return res.Attestation.Document, nil
}

func (e *EnclaveHandle) GenerateAttestation(userData []byte) ([]byte, error) {
	// Use "Reclaim Protocol" as default user data if none provided
	if userData == nil {
		userData = []byte("Reclaim Protocol")
	}

	// Generate cache key based on userData
	cacheKey := string(userData)

	// Check cache
	attestationMu.RLock()
	entry, found := attestationCache[cacheKey]
	if found && time.Since(entry.createdAt) < attestationTTL {
		log.Printf("Using cached attestation for userData: %s", cacheKey)
		attestationMu.RUnlock()
		return entry.doc, nil
	}
	attestationMu.RUnlock()

	// Generate 32-byte random nonce
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	attestationDoc, err := e.Attest(AttestationOptions{
		Nonce:    []byte(hex.EncodeToString(nonce)),
		UserData: userData,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to request attestation: %v", err)
	}

	// Store in cache
	attestationMu.Lock()
	attestationCache[cacheKey] = attestationCacheEntry{
		doc:       attestationDoc,
		createdAt: time.Now(),
	}
	attestationMu.Unlock()
	log.Printf("Stored new attestation in cache for userData: %s", cacheKey)

	return attestationDoc, nil
}
