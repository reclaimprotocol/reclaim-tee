package enclave

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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
	"strings"
	"sync"
	"sync/atomic"
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
	EnclaveVsockHTTPPort, EnclaveVsockHTTPSPort, EnclaveVsockForwardPort = 8080, 8443, 8444
	EnclaveVsockParentCID                                                = 3
	ERetryDelay                                                          = 2 * time.Second
	AttestationTTL                                                       = 4*time.Minute + 50*time.Second
	MaxConnectionRetries, CircuitBreakerThreshold                        = 5, 5
	InitialBackoffDelay, MaxBackoffDelay                                 = 100 * time.Millisecond, 10 * time.Second
	ConnectionTimeout, ReadWriteTimeout                                  = 10 * time.Second, 30 * time.Second
	CircuitBreakerTimeout                                                = 60 * time.Second
	DefaultKeyBits                                                       = 2048
)

var (
	// Environment variables
	EnclaveDomain string
	KmsKeyID      string
	AcmeURL       string
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
	MemoryCache struct {
		mu    sync.RWMutex
		items map[string][]byte
	}

	// ServerConfig holds configuration for the enclave server
	ServerConfig struct {
		HTTPServer  *http.Server
		HTTPSServer *http.Server
		Cache       *MemoryCache
		Manager     *autocert.Manager
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

// LoadEnvVariables loads environment variables required for the enclave
func LoadEnvVariables() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
	}

	// Load environment variables - fail if any are missing
	var missing []string

	EnclaveDomain = os.Getenv("ENCLAVE_DOMAIN")
	if EnclaveDomain == "" {
		missing = append(missing, "ENCLAVE_DOMAIN")
	}

	KmsKeyID = os.Getenv("KMS_KEY_ID")
	if KmsKeyID == "" {
		missing = append(missing, "KMS_KEY_ID")
	}

	AcmeURL = os.Getenv("ACME_URL")
	if AcmeURL == "" {
		missing = append(missing, "ACME_URL")
	}

	if len(missing) > 0 {
		log.Fatalf("Required environment variables not set: %v", missing)
	}

	log.Printf("Loaded configuration: domain=%s, acmeURL=%s", EnclaveDomain, AcmeURL)
}

// InitializeNSM initializes the NSM session for crypto operations
func InitializeNSM() error {
	sess, err := nsm.OpenDefaultSession()
	if err != nil {
		return fmt.Errorf("failed to open NSM session for nonce: %v", err)
	}
	defer sess.Close()
	rand.Reader = sess
	return nil
}

// GetConnectionManager returns the global VSock connection manager
func GetConnectionManager() *VSockConnectionManager {
	connectionManagerOnce.Do(func() {
		globalConnectionManager = &VSockConnectionManager{
			pool: NewVSockPool(10, 50), circuitBreaker: &CircuitBreaker{state: int32(CircuitClosed)}, metrics: &ConnectionMetrics{},
		}
	})
	return globalConnectionManager
}

// Circuit breaker methods
func (cb *CircuitBreaker) CanExecute() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	state := CircuitState(atomic.LoadInt32(&cb.state))
	switch state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		if time.Since(cb.lastStateChange) >= CircuitBreakerTimeout {
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
	if failures >= CircuitBreakerThreshold {
		cb.setState(CircuitOpen)
	}
}

func (cb *CircuitBreaker) setState(state CircuitState) {
	atomic.StoreInt32(&cb.state, int32(state))
	cb.lastStateChange = time.Now()
	log.Printf("Circuit breaker state changed to: %d", state)
}

// Connection metrics methods
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

// Close gracefully closes the VSock connection manager
func (vcm *VSockConnectionManager) Close() {
	log.Println("Closing VSock connection manager...")
	if vcm.pool != nil {
		vcm.pool.Close()
	}
}

// SendVsockRequest sends a request over VSock
func SendVsockRequest(operation string, input interface{}) (Response, error) {
	return SendVsockRequestWithContext(context.Background(), operation, input)
}

// SendVsockRequestWithContext sends a request over VSock with context
func SendVsockRequestWithContext(ctx context.Context, operation string, input interface{}) (Response, error) {
	manager := GetConnectionManager()
	if !manager.circuitBreaker.CanExecute() {
		log.Printf("Circuit breaker is open for operation: %s", operation)
		manager.metrics.recordFailure()
		return Response{}, errors.New("circuit breaker is open")
	}

	overallStartTime := time.Now()
	log.Printf("Starting VSock request sequence for operation: %s", operation)
	var lastErr error
	for attempt := 0; attempt < MaxConnectionRetries; attempt++ {
		if attempt > 0 {
			backoffDelay := calculateBackoff(attempt)
			log.Printf("Retrying vsock request for %s (attempt %d/%d) after %v", operation, attempt+1, MaxConnectionRetries, backoffDelay)
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
			log.Printf("VSock request succeeded for %s on attempt %d/%d in %v (total: %v)", operation, attempt+1, MaxConnectionRetries, time.Since(attemptStartTime), time.Since(overallStartTime))
			manager.circuitBreaker.OnSuccess()
			manager.metrics.recordSuccess(time.Since(overallStartTime))
			return resp, nil
		}
		lastErr = err
		log.Printf("VSock request failed for %s (attempt %d/%d) in %v: %v", operation, attempt+1, MaxConnectionRetries, time.Since(attemptStartTime), err)
		if isNonRetryableError(err) {
			log.Printf("Non-retryable error for %s, stopping attempts: %v", operation, err)
			break
		}
	}
	log.Printf("All VSock request attempts failed for %s after %v", operation, time.Since(overallStartTime))
	manager.circuitBreaker.OnFailure()
	manager.metrics.recordFailure()
	return Response{}, fmt.Errorf("vsock request failed after %d attempts: %v", MaxConnectionRetries, lastErr)
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
			_ = conn.Close()
		} else {
			log.Printf("Returning connection to pool for %s after %v", operation, time.Since(startTime))
			manager.pool.Put(conn)
		}
	}()

	writeStartTime := time.Now()
	_ = conn.SetWriteDeadline(time.Now().Add(ReadWriteTimeout))
	if _, err = conn.Write(reqBytes); err != nil {
		log.Printf("Failed to write request for %s after %v (conn age: %v): %v", operation, time.Since(writeStartTime), time.Since(startTime), err)
		return Response{}, fmt.Errorf("failed to send request: %v", err)
	}
	log.Printf("Wrote request for %s in %v", operation, time.Since(writeStartTime))

	readStartTime := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(ReadWriteTimeout))
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
		return InitialBackoffDelay
	}
	delay := time.Duration(float64(InitialBackoffDelay) * math.Pow(2, float64(attempt-1)))
	if delay > MaxBackoffDelay {
		delay = MaxBackoffDelay
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

// CreateServerConfig creates and configures the HTTP/HTTPS servers with autocert
func CreateServerConfig(businessMux *http.ServeMux) *ServerConfig {
	log.Printf("Configuring autocert for domain: %s", EnclaveDomain)

	vsockTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			log.Printf("Attempting vsock connection to parent CID %d port %d for %s", EnclaveVsockParentCID, EnclaveVsockForwardPort, addr)
			var conn net.Conn
			var err error
			for attempt := 1; attempt <= 3; attempt++ {
				conn, err = vsock.Dial(EnclaveVsockParentCID, EnclaveVsockForwardPort, nil)
				if err == nil {
					break
				}
				log.Printf("Attempt %d/3: Failed to dial vsock for %s: %v", attempt, addr, err)
				if attempt < 3 {
					time.Sleep(ERetryDelay)
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
		HostPolicy: autocert.HostWhitelist(EnclaveDomain),
		Cache:      cache,
		Client: &acme.Client{
			HTTPClient:   client,
			DirectoryURL: AcmeURL,
		},
	}

	// Create a combined mux that includes infrastructure endpoints
	mux := http.NewServeMux()

	// Add infrastructure endpoints
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		manager := GetConnectionManager()
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

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		manager := GetConnectionManager()
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

	// Add business logic routes from the provided mux
	if businessMux != nil {
		// Extract all patterns from businessMux and add them to our mux
		// Note: This is a simple approach. In Go 1.22+, you could use a more sophisticated mux merger
		mux.Handle("/", businessMux)
	}

	httpServer := &http.Server{
		Handler:                      manager.HTTPHandler(mux),
		ReadTimeout:                  5 * time.Second,
		WriteTimeout:                 10 * time.Second,
		IdleTimeout:                  30 * time.Second,
		ReadHeaderTimeout:            5 * time.Second,
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
		Handler:                      mux,
		TLSConfig:                    tlsConfig,
		ReadTimeout:                  5 * time.Second,
		WriteTimeout:                 10 * time.Second,
		IdleTimeout:                  30 * time.Second,
		ReadHeaderTimeout:            5 * time.Second,
		DisableGeneralOptionsHandler: false,
	}

	return &ServerConfig{
		HTTPServer:  httpServer,
		HTTPSServer: httpsServer,
		Cache:       cache,
		Manager:     manager,
	}
}

// GetCertificateFingerprint gets the fingerprint of the current certificate
func GetCertificateFingerprint(ctx context.Context, cache *MemoryCache) ([]byte, error) {
	data, err := cache.Get(ctx, EnclaveDomain)
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
			if cert.Subject.CommonName == EnclaveDomain {
				fingerprint := sha256.Sum256(cert.Raw)
				return fingerprint[:], nil
			}
			for _, san := range cert.DNSNames {
				if san == EnclaveDomain {
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
	return nil, fmt.Errorf("no certificate matching domain %s found", EnclaveDomain)
}

// retryListen attempts to start a vsock listener with retries.
func retryListen(ctx context.Context, port uint32, name string) (net.Listener, error) {
	for {
		listener, err := vsock.Listen(port, nil)
		if err == nil {
			log.Printf("Started vsock %s listener on port %d", name, port)
			return listener, nil
		}
		log.Printf("Failed to listen on vsock port %d: %v, retrying in %v", port, err, ERetryDelay)
		select {
		case <-ctx.Done():
			log.Printf("Stopping %s listener retry due to shutdown", name)
			return nil, nil
		case <-time.After(ERetryDelay):
		}
	}
}

// StartListeners starts HTTP and HTTPS listeners on vsock ports.
func StartListeners(ctx context.Context, httpServer, httpsServer *http.Server) (chan error, chan error) {
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
				_ = listener.Close()
				errChan <- err
				continue
			}
			log.Printf("%s server stopped on vsock port %d", name, port)
			errChan <- nil
			return
		}
	}

	go listen(EnclaveVsockHTTPPort, httpServer, httpErrChan, "HTTP")
	go listen(EnclaveVsockHTTPSPort, httpsServer, httpsErrChan, "HTTPS")

	return httpErrChan, httpsErrChan
}

// GenerateAttestation generates an attestation document
func GenerateAttestation(handle *EnclaveHandle, userData []byte) ([]byte, error) {
	// Use "Reclaim Protocol" as default user data if none provided
	if userData == nil {
		userData = []byte("Reclaim Protocol")
	}

	// Generate cache key based on userData
	cacheKey := string(userData)

	// Check cache
	attestationMu.RLock()
	entry, found := attestationCache[cacheKey]
	if found && time.Since(entry.createdAt) < AttestationTTL {
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

// EnclaveHandle methods
func (e *EnclaveHandle) initialize() error {
	var err error
	if e.nsm, err = nsm.OpenDefaultSession(); err != nil {
		return err
	}
	if e.key, err = rsa.GenerateKey(e.nsm, DefaultKeyBits); err != nil {
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

// GetOrInitializeHandle returns the global enclave handle
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

// MustGlobalHandle returns the global handle or panics
func MustGlobalHandle() *EnclaveHandle {
	handle, err := GetOrInitializeHandle()
	if err != nil {
		panic(err)
	}
	return handle
}

// Memory cache implementation
func NewMemoryCache() *MemoryCache { return &MemoryCache{items: make(map[string][]byte)} }

func (c *MemoryCache) Get(ctx context.Context, key string) ([]byte, error) {
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

func (c *MemoryCache) Put(ctx context.Context, key string, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = data
	log.Printf("Stored item in cache for key: %s, data length: %d bytes", key, len(data))
	if err := encryptAndStoreCacheItem(data, key); err != nil {
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

func loadCachedItem(ctx context.Context, cache *MemoryCache, filename string) error {
	resp, err := SendVsockRequest("GetCachedItem", GetItemInput{Filename: filename})
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
	resp, err := SendVsockRequest("DeleteCachedItem", DeleteItemInput{Filename: filename})
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
	attestationDoc, err := GenerateAttestation(handle, nil)
	if err != nil {
		return fmt.Errorf("failed to generate attestation: %v", err)
	}

	input := kms.GenerateDataKeyInput{
		KeyId:   aws.String(KmsKeyID),
		KeySpec: "AES_256",
		Recipient: &types.RecipientInfoType{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
		},
	}

	resp, err := SendVsockRequest("GenerateDataKey", input)
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
	resp, err = SendVsockRequest("StoreEncryptedItem", storeInput)
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
	attestationDoc, err := GenerateAttestation(handle, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate attestation: %v", err)
	}

	input := kms.DecryptInput{
		KeyId:               aws.String(KmsKeyID),
		CiphertextBlob:      ciphertextBlob,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecSymmetricDefault,
		Recipient: &types.RecipientInfoType{
			AttestationDocument:    attestationDoc,
			KeyEncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
		},
	}

	resp, err := SendVsockRequest("Decrypt", input)
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

// VSock pool implementation
func NewVSockPool(maxIdle, maxActive int) *VSockPool {
	log.Printf("Creating new VSock connection pool: maxIdle=%d, maxActive=%d", maxIdle, maxActive)
	pool := &VSockPool{
		connections: make(chan net.Conn, maxIdle),
		maxIdle:     maxIdle,
		maxActive:   maxActive,
		idleTimeout: 5 * time.Minute,
		stopCh:      make(chan struct{}),
		factory: func() (net.Conn, error) {
			ctx, cancel := context.WithTimeout(context.Background(), ConnectionTimeout)
			defer cancel()

			log.Printf("Creating new VSock connection to CID %d port 5000", EnclaveVsockParentCID)
			startTime := time.Now()
			conn, err := vsock.Dial(EnclaveVsockParentCID, 5000, nil)
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
			_ = conn.Close()
			// Connection is bad, create new one
			return p.factory()
		}
		_ = conn.SetDeadline(time.Time{}) // Clear deadline
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
		_ = conn.Close()
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
				_ = conn.Close()
				continue
			}
			_ = conn.SetDeadline(time.Time{}) // Clear deadline
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
			_ = conn.Close()
		}
	}
}

func (p *VSockPool) Close() {
	close(p.stopCh)

	// Close all idle connections
	close(p.connections)
	for conn := range p.connections {
		_ = conn.Close()
	}
}
