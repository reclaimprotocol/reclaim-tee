//go:build enclave

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/austinast/nitro-enclaves-sdk-go/crypto/cms"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/joho/godotenv"
	"github.com/mdlayher/vsock"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const (
	enclaveVsockHTTPPort, enclaveVsockHTTPSPort, enclaveVsockForwardPort = 8080, 8443, 8444
	enclaveVsockParentCID                                                = 3
	eRetryDelay                                                          = 2 * time.Second
	attestationTTL                                                       = 4*time.Minute + 50*time.Second
	maxConnectionRetries, circuitBreakerThreshold                        = 5, 5
	initialBackoffDelay, maxBackoffDelay                                 = 100 * time.Millisecond, 10 * time.Second
	connectionTimeout, readWriteTimeout                                  = 10 * time.Second, 30 * time.Second
	circuitBreakerTimeout                                                = 60 * time.Second
)

var (
	// Environment variables
	enclaveDomain string
	kmsKeyID      string
	acmeURL       string
)

type CircuitState int32

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
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
	EnclaveHandle struct {
		nsm *nsm.Session
		key *rsa.PrivateKey
	}
	memoryCache struct {
		mu    sync.RWMutex
		items map[string][]byte
	}
)

var (
	globalConnectionManager *VSockConnectionManager
	connectionManagerOnce   sync.Once
	globalHandle            *EnclaveHandle
	initializationError     error
	initMutex               sync.Mutex
	attestationCache        = make(map[string]attestationCacheEntry)
	attestationMu           sync.RWMutex
)

func loadEnvVariables() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
	}

	// Load environment variables - fail if any are missing
	var missing []string

	enclaveDomain = os.Getenv("ENCLAVE_DOMAIN")
	if enclaveDomain == "" {
		missing = append(missing, "ENCLAVE_DOMAIN")
	}

	kmsKeyID = os.Getenv("KMS_KEY_ID")
	if kmsKeyID == "" {
		missing = append(missing, "KMS_KEY_ID")
	}

	acmeURL = os.Getenv("ACME_URL")
	if acmeURL == "" {
		missing = append(missing, "ACME_URL")
	}

	if len(missing) > 0 {
		log.Fatalf("Required environment variables not set: %v", missing)
	}

	log.Printf("Loaded configuration: domain=%s, acmeURL=%s", enclaveDomain, acmeURL)
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

func main() {
	// Load environment variables first
	loadEnvVariables()

	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		log.Fatalf("failed to open NSM session for nonce: %v", err)
	}
	defer sess.Close()
	rand.Reader = sess
	startServer()
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
		} else {
			log.Printf("First attempt for VSock request: %s", operation)
		}

		attemptStartTime := time.Now()
		resp, err := executeSingleRequest(ctx, manager, operation, input)
		if err == nil {
			log.Printf("VSock request succeeded for %s on attempt %d/%d in %v (total: %v)", operation, attempt+1, maxConnectionRetries, time.Since(attemptStartTime), time.Since(overallStartTime))
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
	log.Printf("Marshaled input for %s: %d bytes", operation, len(inputBytes))

	req := Request{Operation: operation, Input: inputBytes}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		log.Printf("Failed to marshal request for %s: %v", operation, err)
		return Response{}, fmt.Errorf("failed to marshal request: %v", err)
	}
	log.Printf("Marshaled request for %s: %d bytes", operation, len(reqBytes))

	connStartTime := time.Now()
	conn, err := manager.pool.Get(ctx)
	if err != nil {
		log.Printf("Failed to get connection for %s after %v: %v", operation, time.Since(connStartTime), err)
		return Response{}, fmt.Errorf("failed to get connection: %v", err)
	}
	log.Printf("Got connection for %s after %v, remote addr: %s", operation, time.Since(connStartTime), conn.RemoteAddr())

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

func loadCachedItem(ctx context.Context, cache *memoryCache, filename string) error {
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

	data, err := decryptItem(output.Data, output.Key)
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
func encryptAndStoreCacheItem(data []byte, filename string) error {
	handle := MustGlobalHandle()
	attestationDoc, err := generateAttestation(handle, nil)
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
func decryptItem(encryptedData, ciphertextBlob []byte) ([]byte, error) {
	handle := MustGlobalHandle()
	attestationDoc, err := generateAttestation(handle, nil)
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

// retryListen attempts to start a vsock listener with retries.
func retryListen(ctx context.Context, port uint32, name string) (net.Listener, error) {
	for {
		listener, err := vsock.Listen(port, nil)
		if err == nil {
			log.Printf("Started vsock %s listener on port %d", name, port)
			return listener, nil
		}
		log.Printf("Failed to listen on vsock port %d: %v, retrying in %v", port, err, eRetryDelay)
		select {
		case <-ctx.Done():
			log.Printf("Stopping %s listener retry due to shutdown", name)
			return nil, nil
		case <-time.After(eRetryDelay):
		}
	}
}

// startListeners starts HTTP and HTTPS listeners on vsock ports.
func startListeners(ctx context.Context, httpServer, httpsServer *http.Server) (chan error, chan error) {
	httpErrChan := make(chan error, 1)
	httpsErrChan := make(chan error, 1)

	listen := func(port uint32, server *http.Server, errChan chan error, name string) {
		for {
			listener, err := retryListen(ctx, port, name)
			if listener == nil {
				errChan <- nil
				return
			}
			if name == "HTTPS" {
				err = server.ServeTLS(listener, "", "")
			} else {
				err = server.Serve(listener)
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("%s server error on vsock port %d: %v, restarting", name, port, err)
				listener.Close()
				errChan <- err
				continue
			}
			log.Printf("%s server stopped on vsock port %d", name, port)
			errChan <- nil
			return
		}
	}

	go listen(enclaveVsockHTTPPort, httpServer, httpErrChan, "HTTP")
	go listen(enclaveVsockHTTPSPort, httpsServer, httpsErrChan, "HTTPS")

	return httpErrChan, httpsErrChan
}

func getCertificateFingerprint(ctx context.Context, cache *memoryCache) ([]byte, error) {
	data, err := cache.Get(ctx, enclaveDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to get item from cache: %v", err)
	}

	// Parse PEM blocks
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Printf("Failed to parse certificate: %v", err)
				data = rest
				continue
			}
			// Check if certificate matches domain
			if cert.Subject.CommonName == enclaveDomain {
				fingerprint := sha256.Sum256(cert.Raw)
				return fingerprint[:], nil
			}
			for _, san := range cert.DNSNames {
				if san == enclaveDomain {
					fingerprint := sha256.Sum256(cert.Raw)
					return fingerprint[:], nil
				}
			}
			certs = append(certs, cert)
		}
		data = rest
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates found in cache")
	}
	return nil, fmt.Errorf("no certificate matching domain %s found", enclaveDomain)
}

func startServer() {
	log.Printf("Configuring autocert for domain: %s", enclaveDomain)

	vsockTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			log.Printf("Attempting vsock connection to parent CID %d port %d for %s", enclaveVsockParentCID, enclaveVsockForwardPort, addr)
			var conn net.Conn
			var err error
			for attempt := 1; attempt <= 3; attempt++ {
				conn, err = vsock.Dial(enclaveVsockParentCID, enclaveVsockForwardPort, nil)
				if err == nil {
					break
				}
				log.Printf("Attempt %d/3: Failed to dial vsock for %s: %v", attempt, addr, err)
				if attempt < 3 {
					time.Sleep(eRetryDelay)
				}
			}
			if err != nil {
				log.Printf("Failed to connect to vsock after retries: %v", err)
				return nil, err
			}
			log.Printf("Sending target %s to proxy", addr)
			_, err = fmt.Fprintf(conn, "%s\n", addr)
			if err != nil {
				log.Printf("Failed to send target %s to proxy: %v", addr, err)
				conn.Close()
				return nil, err
			}
			return conn, nil
		},
		IdleConnTimeout: 30 * time.Second,
	}

	client := &http.Client{Transport: vsockTransport}
	cache := NewMemoryCache()

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(enclaveDomain),
		Cache:      cache,
		Client: &acme.Client{
			HTTPClient:   client,
			DirectoryURL: acmeURL,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received %s request for %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		response := fmt.Sprintf("Hello from enclave server! Received %s request for %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Enclave", "Nitro")
		fmt.Fprintln(w, response)
	})

	mux.HandleFunc("/attest", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received attestation request from %s", r.RemoteAddr)
		fingerprint, err := getCertificateFingerprint(r.Context(), cache)
		if err != nil {
			log.Printf("Failed to get certificate fingerprint: %v", err)
			http.Error(w, "Failed to generate attestation", http.StatusInternalServerError)
			return
		}

		// Convert fingerprint to hex
		fingerprintHex := hex.EncodeToString(fingerprint)

		handle := MustGlobalHandle()
		attestationDoc, err := generateAttestation(handle, []byte(fingerprintHex))
		if err != nil {
			log.Printf("Failed to generate attestation: %v", err)
			http.Error(w, "Failed to generate attestation", http.StatusInternalServerError)
			return
		}

		encoded := base64.StdEncoding.EncodeToString(attestationDoc)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, encoded)
	})

	// Add connection metrics endpoint
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		manager := getConnectionManager()
		total, successful, failed, avgTime := manager.metrics.GetStats()

		metrics := map[string]interface{}{
			"total_requests":        total,
			"successful_requests":   successful,
			"failed_requests":       failed,
			"avg_response_time_ns":  avgTime.Nanoseconds(),
			"avg_response_time_ms":  avgTime.Nanoseconds() / 1e6,
			"circuit_breaker_state": atomic.LoadInt32(&manager.circuitBreaker.state),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metrics)
	})

	// Add simple status endpoint
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		manager := getConnectionManager()
		circuitState := CircuitState(atomic.LoadInt32(&manager.circuitBreaker.state))

		status := map[string]interface{}{
			"status":                 "healthy",
			"circuit_breaker_closed": circuitState == CircuitClosed,
		}

		if circuitState != CircuitClosed {
			status["status"] = "degraded"
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	})

	httpServer := &http.Server{
		Handler:           manager.HTTPHandler(mux),
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		// Enable connection reuse for TCP reverse proxy
		DisableGeneralOptionsHandler: false,
	}

	tlsConfig := manager.TLSConfig()
	tlsConfig.MinVersion = tls.VersionTLS12
	tlsConfig.MaxVersion = tls.VersionTLS13
	tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		log.Printf("TLS handshake from %s with SNI: %s, ALPN: %v, TLS version: 0x%x", hello.Conn.RemoteAddr(), hello.ServerName, hello.SupportedProtos, hello.SupportedVersions)
		return nil, nil
	}
	httpsServer := &http.Server{
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		// Enable connection reuse for TCP reverse proxy
		DisableGeneralOptionsHandler: false,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpErrChan, httpsErrChan := startListeners(ctx, httpServer, httpsServer)

	log.Printf("Attempting to load or issue certificate for %s", enclaveDomain)
	_, err := manager.GetCertificate(&tls.ClientHelloInfo{ServerName: enclaveDomain})
	if err != nil {
		log.Printf("Failed to load or issue certificate on startup: %v", err)
	} else {
		log.Printf("Successfully loaded or issued certificate for %s", enclaveDomain)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err = <-httpErrChan:
		if err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	case err = <-httpsErrChan:
		if err != nil {
			log.Fatalf("HTTPS server failed: %v", err)
		}
	case <-sigChan:
		log.Println("Received shutdown signal, stopping enclave server...")
		cancel()

		// Gracefully close connection manager
		if globalConnectionManager != nil {
			log.Println("Closing connection pool...")
			globalConnectionManager.pool.Close()
		}

		httpServer.Close()
		httpsServer.Close()
	}
}

func generateAttestation(handle *EnclaveHandle, userData []byte) ([]byte, error) {
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

	attestationDoc, err := handle.Attest(AttestationOptions{
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

const (
	defaultKeyBits = 2048
)

func (e *EnclaveHandle) initialize() error {
	var err error
	if e.nsm, err = nsm.OpenDefaultSession(); err != nil {
		return err
	}
	if e.key, err = rsa.GenerateKey(e.nsm, defaultKeyBits); err != nil {
		return err
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

func (e *EnclaveHandle) PublicKey() *rsa.PublicKey   { return &e.key.PublicKey }
func (e *EnclaveHandle) PrivateKey() *rsa.PrivateKey { return e.key }

func GetOrInitializeHandle() (*EnclaveHandle, error) {
	initMutex.Lock()
	defer initMutex.Unlock()
	if globalHandle == nil && initializationError == nil {
		enclave := &EnclaveHandle{}
		if err := enclave.initialize(); err != nil {
			initializationError = err
			return nil, err
		}
		globalHandle = enclave
	}
	return globalHandle, initializationError
}

func MustGlobalHandle() *EnclaveHandle {
	handle, err := GetOrInitializeHandle()
	if err != nil {
		panic(err)
	}
	return handle
}

func NewMemoryCache() *memoryCache { return &memoryCache{items: make(map[string][]byte)} }

func (c *memoryCache) Get(ctx context.Context, key string) ([]byte, error) {
	c.mu.RLock()
	data, ok := c.items[key]
	c.mu.RUnlock()
	if !ok {
		if err := loadCachedItem(ctx, c, key); err != nil {
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

func (c *memoryCache) Put(ctx context.Context, key string, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = data
	log.Printf("Stored item in cache for key: %s, data length: %d bytes", key, len(data))
	if err := encryptAndStoreCacheItem(data, key); err != nil {
		log.Printf("Failed to encrypt and store item: %v", err)
	}
	return nil
}

func (c *memoryCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	log.Printf("Deleting item from cache for key: %s", key)
	delete(c.items, key)
	if err := deleteCachedItem(key); err != nil {
		log.Printf("Failed to delete item from vsock: %v", err)
	}
	return nil
}

func NewVSockPool(maxIdle, maxActive int) *VSockPool {
	log.Printf("Creating new VSock connection pool: maxIdle=%d, maxActive=%d", maxIdle, maxActive)
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
	poolSize := len(p.connections)
	log.Printf("Getting connection from pool (current pool size: %d/%d)", poolSize, p.maxIdle)

	select {
	case conn := <-p.connections:
		log.Printf("Retrieved connection from pool, remote addr: %s (pool size was %d)", conn.RemoteAddr(), poolSize)
		// Quick validation - try to set deadline
		if err := conn.SetDeadline(time.Now().Add(1 * time.Second)); err != nil {
			log.Printf("Pool connection validation failed, closing and creating new: %v", err)
			conn.Close()
			// Connection is bad, create new one
			return p.factory()
		}
		conn.SetDeadline(time.Time{}) // Clear deadline
		log.Printf("Pool connection validated successfully")
		return conn, nil
	default:
		log.Printf("No idle connections available (pool was empty), creating new connection")
		// No idle connections available, create new one
		return p.factory()
	}
}

func (p *VSockPool) Put(conn net.Conn) {
	if conn == nil {
		log.Printf("Attempted to return nil connection to pool")
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
