package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/mdlayher/vsock"
)

const (
	// TCP reverse proxy constants
	listenAddressHTTP, listenAddressHTTPS           = ":80", ":443"
	vsockHTTPPort, vsockHTTPSPort, vsockForwardPort = 8080, 8443, 8444
	vsockCID                                        = 16
	retryDelay, keepAliveInterval                   = 1 * time.Second, 15 * time.Second
	maxConnectionRetries, circuitBreakerThreshold   = 5, 5
	initialBackoffDelay, maxBackoffDelay            = 100 * time.Millisecond, 10 * time.Second
	connectionTimeout, readWriteTimeout             = 10 * time.Second, 30 * time.Second
	circuitBreakerTimeout                           = 60 * time.Second

	// VSock proxy constants
	defaultVsockPort      = 5000
	defaultTimeout        = 30 * time.Second
	defaultMaxRequestSize = 40960
)

type CircuitState int32

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

// Common types
type (
	VSockConnectionFactory struct {
		factory   func() (net.Conn, error)
		vsockCID  uint32
		vsockPort uint32
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
	ProxyManager struct {
		httpFactory, httpsFactory *VSockConnectionFactory
		circuitBreaker            *CircuitBreaker
		metrics                   *ConnectionMetrics
	}
)

// VSock proxy types
type (
	EnclaveRequest struct {
		Operation string          `json:"operation"`
		Input     json.RawMessage `json:"input"`
	}
	EnclaveResponse struct {
		Output json.RawMessage `json:"output,omitempty"`
		Error  string          `json:"error"`
	}
	VSockProxyConfig struct {
		VsockPort      uint32
		Timeout        time.Duration
		MaxRequestSize int64
	}
	ProxyStoreItemInput struct {
		Data     []byte `json:"data"`
		Key      []byte `json:"key"`
		Filename string `json:"filename"`
	}
	ProxyGetItemInput struct {
		Filename string `json:"filename"`
	}
	ProxyGetItemOutput struct {
		Data []byte `json:"data"`
		Key  []byte `json:"key"`
	}
	ProxyDeleteItemInput struct {
		Filename string `json:"filename"`
	}
	ProxyStatusOutput struct {
		Status string `json:"status"`
	}
)

var (
	globalProxyManager *ProxyManager
	proxyManagerOnce   sync.Once
	domainRouter       *DomainRouter
	connectionRouter   *ConnectionRouter
)

func main() {
	log.Println("Starting unified proxy server...")

	// Initialize domain routing
	initializeDomainRouting()

	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup

	// Start TCP reverse proxy
	wg.Add(1)
	go func() {
		defer wg.Done()
		startTCPReverseProxy(ctx)
	}()

	// Start VSock proxy
	wg.Add(1)
	go func() {
		defer wg.Done()
		startVSockProxy(ctx)
	}()

	// Wait for shutdown signal
	<-sigChan
	log.Println("Received shutdown signal, stopping proxy server...")
	cancel()

	wg.Wait()
	log.Println("Proxy server shut down gracefully")
}

// initializeDomainRouting sets up domain routing configuration
func initializeDomainRouting() {
	domainRouter = NewDomainRouter()

	// Configure domain routes from environment variables
	teeKDomain := os.Getenv("TEE_K_DOMAIN")
	if teeKDomain == "" {
		teeKDomain = "tee-k.reclaimprotocol.org" // fallback
	}

	teeTDomain := os.Getenv("TEE_T_DOMAIN")
	if teeTDomain == "" {
		teeTDomain = "tee-t.reclaimprotocol.org" // fallback
	}

	// Get enclave CIDs from environment (you'll set these)
	teeKCID := getEnvValueUint32("TEE_K_CID", 16) // Default CID 16 for TEE_K
	teeTCID := getEnvValueUint32("TEE_T_CID", 17) // Default CID 17 for TEE_T

	// Add domain routes with CIDs
	domainRouter.AddRoute(teeKDomain, teeKCID, 8001) // TEE_K: CID and HTTPS vsock port
	domainRouter.AddRoute(teeTDomain, teeTCID, 8003) // TEE_T: CID and HTTPS vsock port

	connectionRouter = NewConnectionRouter(domainRouter)

	log.Printf("Domain routing initialized:")
	log.Printf("  %s -> CID %d, HTTPS:8001, HTTP:8000", teeKDomain, teeKCID)
	log.Printf("  %s -> CID %d, HTTPS:8003, HTTP:8002", teeTDomain, teeTCID)
}

// TCP Reverse Proxy Implementation
func startTCPReverseProxy(ctx context.Context) {
	log.Println("Starting TCP reverse proxy...")

	httpListener, err := net.Listen("tcp", listenAddressHTTP)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", listenAddressHTTP, err)
	}
	log.Printf("Successfully started TCP listener on %s", listenAddressHTTP)

	httpsListener, err := net.Listen("tcp", listenAddressHTTPS)
	if err != nil {
		_ = httpListener.Close()
		log.Fatalf("Failed to listen on %s: %v", listenAddressHTTPS, err)
	}
	log.Printf("Successfully started TCP listener on %s", listenAddressHTTPS)

	vsockListener, err := vsock.Listen(vsockForwardPort, nil)
	if err != nil {
		_ = httpListener.Close()
		_ = httpsListener.Close()
		log.Fatalf("Failed to listen on vsock port %d: %v", vsockForwardPort, err)
	}
	log.Printf("Successfully started vsock listener on port %d", vsockForwardPort)

	defer func() {
		_ = httpListener.Close()
		_ = httpsListener.Close()
		_ = vsockListener.Close()
		log.Println("TCP reverse proxy stopped")
	}()

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		log.Printf("Accepting HTTP connections on %s (with domain routing)", listenAddressHTTP)
		acceptHTTPConnections(ctx, httpListener)
	}()

	go func() {
		defer wg.Done()
		log.Printf("Accepting HTTPS connections on %s (with SNI routing)", listenAddressHTTPS)
		acceptHTTPSConnections(ctx, httpsListener)
	}()

	go func() {
		defer wg.Done()
		log.Printf("Accepting vsock connections on port %d for outbound traffic", vsockForwardPort)
		acceptForwardConnections(ctx, vsockListener)
	}()

	<-ctx.Done()
	wg.Wait()
}

// VSock Proxy Implementation
func startVSockProxy(ctx context.Context) {
	log.Println("Starting VSock proxy...")

	cfg := VSockProxyConfig{
		VsockPort:      getEnvValueUint32("VSOCK_PORT", defaultVsockPort),
		Timeout:        getEnvDuration("TIMEOUT", defaultTimeout),
		MaxRequestSize: getEnvInt64("MAX_REQUEST_SIZE", defaultMaxRequestSize),
	}

	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithClientLogMode(aws.LogRequestWithBody|aws.LogResponseWithBody),
		config.WithRegion("ap-south-1"),
	)
	if err != nil {
		log.Fatalf("Failed to load AWS config: %v", err)
	}
	kmsClient := kms.NewFromConfig(awsCfg)

	listener, err := vsock.Listen(cfg.VsockPort, nil)
	if err != nil {
		log.Fatalf("Failed to listen on vsock port %d: %v", cfg.VsockPort, err)
	}
	defer listener.Close()

	log.Printf("VSock proxy started on port %d", cfg.VsockPort)

	var wg sync.WaitGroup

	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Println("VSock proxy accept loop shutting down")
				return
			default:
				conn, err := listener.Accept()
				if err != nil {
					select {
					case <-ctx.Done():
						log.Println("VSock proxy accept loop stopped due to shutdown")
						return
					default:
						log.Printf("VSock proxy accept error: %v", err)
						continue
					}
				}
				wg.Add(1)
				go handleVSockConnection(conn, kmsClient, cfg, &wg)
			}
		}
	}()

	<-ctx.Done()
	log.Println("Shutting down VSock proxy")

	// Give accept loop a moment to process cancellation before closing listener
	time.Sleep(100 * time.Millisecond)
	_ = listener.Close()
	wg.Wait()
	log.Println("VSock proxy shut down gracefully")
}

// TCP Reverse Proxy Functions
func getProxyManager() *ProxyManager {
	proxyManagerOnce.Do(func() {
		globalProxyManager = &ProxyManager{
			httpFactory:    NewVSockFactory(16, 8000), // TEE_K default CID and HTTP port
			httpsFactory:   NewVSockFactory(16, 8001), // TEE_K default CID and HTTPS port
			circuitBreaker: &CircuitBreaker{state: int32(CircuitClosed)},
			metrics:        &ConnectionMetrics{},
		}
	})
	return globalProxyManager
}

func NewVSockFactory(vsockCID, vsockPort uint32) *VSockConnectionFactory {
	return &VSockConnectionFactory{
		vsockCID:  vsockCID,
		vsockPort: vsockPort,
		factory: func() (net.Conn, error) {
			ctx, cancel := context.WithTimeout(context.Background(), connectionTimeout)
			defer cancel()
			log.Printf("Creating new VSock connection to enclave CID %d port %d", vsockCID, vsockPort)
			startTime := time.Now()
			conn, err := vsock.Dial(vsockCID, vsockPort, nil)
			if err != nil {
				log.Printf("Failed to dial VSock to enclave after %v: %v", time.Since(startTime), err)
				return nil, err
			}
			log.Printf("Successfully connected to enclave %s in %v", conn.RemoteAddr(), time.Since(startTime))
			if deadline, ok := ctx.Deadline(); ok {
				_ = conn.SetDeadline(deadline)
			}
			return conn, nil
		},
	}
}

func (f *VSockConnectionFactory) Create(ctx context.Context) (net.Conn, error) {
	return f.factory()
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

func acceptReverseConnections(ctx context.Context, listener net.Listener, vsockPort uint32) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				log.Printf("Listener on %s stopped", listener.Addr())
				return
			default:
				log.Printf("Accept error on %s: %v, retrying in %v", listener.Addr(), err, retryDelay)
				time.Sleep(retryDelay)
				continue
			}
		}
		log.Printf("Accepted connection on %s from %s, forwarding to vsock port %d", listener.Addr(), conn.RemoteAddr(), vsockPort)
		go handleReverseConnection(ctx, conn, vsockPort)
	}
}

func handleReverseConnection(ctx context.Context, clientConn net.Conn, vsockPort uint32) {
	defer clientConn.Close()

	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(keepAliveInterval)
	}

	manager := getProxyManager()
	if !manager.circuitBreaker.CanExecute() {
		manager.metrics.recordFailure()
		log.Printf("Circuit breaker is open, rejecting connection to vsock port %d", vsockPort)
		return
	}

	startTime := time.Now()
	var factory *VSockConnectionFactory
	if vsockPort == vsockHTTPPort {
		factory = manager.httpFactory
	} else {
		factory = manager.httpsFactory
	}

	var enclaveConn net.Conn
	var lastErr error
	for attempt := 0; attempt < maxConnectionRetries; attempt++ {
		if attempt > 0 {
			backoffDelay := calculateBackoff(attempt)
			log.Printf("Retrying vsock connection (attempt %d/%d) after %v", attempt+1, maxConnectionRetries, backoffDelay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoffDelay):
			}
		}

		conn, err := factory.Create(ctx)
		if err == nil {
			enclaveConn = conn
			break
		}
		lastErr = err
		log.Printf("VSock connection failed (attempt %d/%d): %v", attempt+1, maxConnectionRetries, err)
	}

	if enclaveConn == nil {
		manager.circuitBreaker.OnFailure()
		manager.metrics.recordFailure()
		log.Printf("Exhausted retries for enclave on port %d: %v", vsockPort, lastErr)
		return
	}

	defer func() {
		log.Printf("Closing HTTP connection to enclave port %d: %s", vsockPort, enclaveConn.RemoteAddr())
		_ = enclaveConn.Close()
	}()

	manager.circuitBreaker.OnSuccess()
	manager.metrics.recordSuccess(time.Since(startTime))

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_ = enclaveConn.SetWriteDeadline(time.Now().Add(readWriteTimeout))
		_, err := io.Copy(enclaveConn, clientConn)
		if err != nil && !errors.Is(err, io.EOF) && ctx.Err() == nil {
			log.Printf("Error copying from client to enclave on vsock port %d: %v", vsockPort, err)
		}
	}()

	go func() {
		defer wg.Done()
		_ = clientConn.SetWriteDeadline(time.Now().Add(readWriteTimeout))
		_, err := io.Copy(clientConn, enclaveConn)
		if err != nil && !errors.Is(err, io.EOF) && ctx.Err() == nil {
			log.Printf("Error copying from enclave to client on vsock port %d: %v", vsockPort, err)
		}
	}()

	wg.Wait()
}

// handleReverseConnectionWithCID handles reverse connections to a specific enclave CID and port
func handleReverseConnectionWithCID(ctx context.Context, clientConn net.Conn, enclaveCID, vsockPort uint32) {
	defer clientConn.Close()

	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(keepAliveInterval)
	}

	manager := getProxyManager()
	if !manager.circuitBreaker.CanExecute() {
		manager.metrics.recordFailure()
		log.Printf("Circuit breaker is open, rejecting connection to CID %d port %d", enclaveCID, vsockPort)
		return
	}

	startTime := time.Now()

	// Create a CID-specific connection factory
	factory := NewVSockFactory(enclaveCID, vsockPort)

	var enclaveConn net.Conn
	var lastErr error
	for attempt := 0; attempt < maxConnectionRetries; attempt++ {
		if attempt > 0 {
			backoffDelay := calculateBackoff(attempt)
			log.Printf("Retrying vsock connection (attempt %d/%d) after %v", attempt+1, maxConnectionRetries, backoffDelay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoffDelay):
			}
		}

		conn, err := factory.Create(ctx)
		if err == nil {
			enclaveConn = conn
			break
		}
		lastErr = err
		log.Printf("VSock connection failed (attempt %d/%d): %v", attempt+1, maxConnectionRetries, err)
	}

	if enclaveConn == nil {
		manager.circuitBreaker.OnFailure()
		manager.metrics.recordFailure()
		log.Printf("Exhausted retries for enclave CID %d port %d: %v", enclaveCID, vsockPort, lastErr)
		return
	}

	defer func() {
		log.Printf("Closing connection to enclave CID %d port %d: %s", enclaveCID, vsockPort, enclaveConn.RemoteAddr())
		_ = enclaveConn.Close()
	}()

	manager.circuitBreaker.OnSuccess()
	manager.metrics.recordSuccess(time.Since(startTime))

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_ = enclaveConn.SetWriteDeadline(time.Now().Add(readWriteTimeout))
		_, err := io.Copy(enclaveConn, clientConn)
		if err != nil && !errors.Is(err, io.EOF) && ctx.Err() == nil {
			log.Printf("Error copying from client to enclave CID %d port %d: %v", enclaveCID, vsockPort, err)
		}
	}()

	go func() {
		defer wg.Done()
		_ = clientConn.SetWriteDeadline(time.Now().Add(readWriteTimeout))
		_, err := io.Copy(clientConn, enclaveConn)
		if err != nil && !errors.Is(err, io.EOF) && ctx.Err() == nil {
			log.Printf("Error copying from enclave to client CID %d port %d: %v", enclaveCID, vsockPort, err)
		}
	}()

	wg.Wait()
}

func acceptForwardConnections(ctx context.Context, listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				log.Printf("Vsock listener on port %d stopped", vsockForwardPort)
				return
			default:
				log.Printf("Accept error on vsock port %d: %v, retrying in %v", vsockForwardPort, err, retryDelay)
				time.Sleep(retryDelay)
				continue
			}
		}
		log.Printf("Accepted vsock connection on port %d", vsockForwardPort)
		go handleForwardConnection(ctx, conn)
	}
}

func handleForwardConnection(ctx context.Context, enclaveConn net.Conn) {
	defer enclaveConn.Close()

	reader := bufio.NewReader(enclaveConn)
	target, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Failed to read target from enclave: %v", err)
		return
	}
	target = strings.TrimSpace(target)
	log.Printf("Received forward request to %s", target)

	var externalConn net.Conn
	var lastErr error
	for attempt := 0; attempt < maxConnectionRetries; attempt++ {
		if attempt > 0 {
			backoffDelay := calculateBackoff(attempt)
			log.Printf("Retrying external connection (attempt %d/%d) after %v", attempt+1, maxConnectionRetries, backoffDelay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoffDelay):
			}
		}

		conn, err := net.DialTimeout("tcp", target, connectionTimeout)
		if err == nil {
			externalConn = conn
			break
		}
		lastErr = err
		log.Printf("External connection failed (attempt %d/%d): %v", attempt+1, maxConnectionRetries, err)
	}

	if externalConn == nil {
		log.Printf("Exhausted retries for external target %s: %v", target, lastErr)
		return
	}
	defer externalConn.Close()

	if tcpConn, ok := externalConn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(keepAliveInterval)
	}
	log.Printf("Connected to external target %s", target)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_ = externalConn.SetWriteDeadline(time.Now().Add(readWriteTimeout))
		_, err := io.Copy(externalConn, reader)
		if err != nil && !errors.Is(err, io.EOF) && ctx.Err() == nil {
			log.Printf("Error copying enclave to external: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		_ = enclaveConn.SetWriteDeadline(time.Now().Add(readWriteTimeout))
		_, err := io.Copy(enclaveConn, externalConn)
		if err != nil && !errors.Is(err, io.EOF) && ctx.Err() == nil {
			log.Printf("Error copying external to enclave: %v", err)
		}
	}()

	wg.Wait()
}

// acceptHTTPConnections handles HTTP connections with Host header routing
func acceptHTTPConnections(ctx context.Context, listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				log.Printf("HTTP listener on %s stopped", listener.Addr())
				return
			default:
				log.Printf("Accept error on %s: %v, retrying in %v", listener.Addr(), err, retryDelay)
				time.Sleep(retryDelay)
				continue
			}
		}

		log.Printf("Accepted HTTP connection from %s", conn.RemoteAddr())
		go handleHTTPConnection(ctx, conn)
	}
}

// acceptHTTPSConnections handles HTTPS connections with SNI routing
func acceptHTTPSConnections(ctx context.Context, listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				log.Printf("HTTPS listener on %s stopped", listener.Addr())
				return
			default:
				log.Printf("Accept error on %s: %v, retrying in %v", listener.Addr(), err, retryDelay)
				time.Sleep(retryDelay)
				continue
			}
		}

		log.Printf("Accepted HTTPS connection from %s", conn.RemoteAddr())
		go handleHTTPSConnection(ctx, conn)
	}
}

// handleHTTPConnection routes HTTP connections based on Host header
func handleHTTPConnection(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(keepAliveInterval)
	}

	// Get the route target using domain router
	target := domainRouter.RouteHTTPConnection(ctx, clientConn)

	// Create a connection that replays the buffered data
	replayConn := &HTTPReplayConnection{
		Conn:      clientConn,
		reader:    bufio.NewReader(clientConn),
		firstLine: nil,
	}

	handleReverseConnectionWithCID(ctx, replayConn, target.CID, target.HttpVsockPort)
}

// handleHTTPSConnection routes HTTPS connections based on SNI
func handleHTTPSConnection(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	if tcpConn, ok := clientConn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(keepAliveInterval)
	}

	// Use SNI routing to determine the target
	target, wrappedConn := connectionRouter.RouteHTTPSConnection(ctx, clientConn)

	handleReverseConnectionWithCID(ctx, wrappedConn, target.CID, target.HttpsVsockPort)
}

// HTTPReplayConnection replays buffered HTTP data
type HTTPReplayConnection struct {
	net.Conn
	reader    *bufio.Reader
	firstLine []byte
	replayed  bool
}

func (hrc *HTTPReplayConnection) Read(b []byte) (n int, err error) {
	if !hrc.replayed {
		// First read: return the buffered data
		hrc.replayed = true
		return hrc.reader.Read(b)
	}
	return hrc.Conn.Read(b)
}

// VSock Proxy Functions
func handleVSockConnection(conn net.Conn, kmsClient *kms.Client, config VSockProxyConfig, wg *sync.WaitGroup) {
	defer conn.Close()
	defer wg.Done()

	log.Printf("VSock connection established: %s", conn.RemoteAddr().String())

	// Handle multiple requests on the same connection
	for {
		// Set read timeout for each request
		_ = conn.SetReadDeadline(time.Now().Add(config.Timeout))

		buf := make([]byte, config.MaxRequestSize)
		n, err := conn.Read(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				log.Println("VSock connection idle timeout, closing")
			}
			return
		}

		log.Printf("VSock received request: %d bytes", n)

		var req EnclaveRequest
		if err := json.Unmarshal(buf[:n], &req); err != nil {
			log.Printf("Invalid VSock request format: %v", err)
			sendVSockResponse(conn, EnclaveResponse{Error: fmt.Sprintf("invalid request: %v", err)})
			continue
		}

		if !isValidOperation(req.Operation) {
			log.Printf("Unsupported VSock operation: %s", req.Operation)
			sendVSockResponse(conn, EnclaveResponse{Error: fmt.Sprintf("unsupported operation: %s", req.Operation)})
			continue
		}

		log.Printf("Processing VSock operation: %s", req.Operation)
		ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)

		resp, err := processVSockOperation(ctx, req, kmsClient)
		if err != nil {
			log.Printf("VSock operation failed %s: %v", req.Operation, err)
			sendVSockResponse(conn, EnclaveResponse{Error: err.Error()})
		} else {
			log.Printf("VSock operation completed: %s", req.Operation)
			sendVSockResponse(conn, EnclaveResponse{Output: resp})
		}
		cancel()

		// Clear read deadline after successful request
		_ = conn.SetReadDeadline(time.Time{})
	}
}

func processVSockOperation(ctx context.Context, req EnclaveRequest, kmsClient *kms.Client) ([]byte, error) {
	switch req.Operation {
	case "GenerateDataKey":
		var input kms.GenerateDataKeyInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid input: %v", err)
		}
		output, err := kmsClient.GenerateDataKey(ctx, &input)
		if err != nil {
			return nil, fmt.Errorf("KMS GenerateDataKey failed: %v", err)
		}
		return json.Marshal(output)
	case "Encrypt":
		var input kms.EncryptInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid input: %v", err)
		}
		output, err := kmsClient.Encrypt(ctx, &input)
		if err != nil {
			return nil, fmt.Errorf("KMS Encrypt failed: %v", err)
		}
		return json.Marshal(output)
	case "Decrypt":
		var input kms.DecryptInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid input: %v", err)
		}
		output, err := kmsClient.Decrypt(ctx, &input)
		if err != nil {
			return nil, fmt.Errorf("KMS Decrypt failed: %v", err)
		}
		return json.Marshal(output)
	case "StoreEncryptedItem":
		var input ProxyStoreItemInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid input: %v", err)
		}
		cacheFilename := "item-" + input.Filename
		if err := os.WriteFile(cacheFilename, input.Data, 0600); err != nil {
			return nil, fmt.Errorf("failed to store item: %v", err)
		}
		if err := os.WriteFile(cacheFilename+".key", input.Key, 0600); err != nil {
			return nil, fmt.Errorf("failed to store key: %v", err)
		}
		return json.Marshal(ProxyStatusOutput{Status: "success"})
	case "GetCachedItem":
		var input ProxyGetItemInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid input: %v", err)
		}
		cacheFilename := "item-" + input.Filename
		data, err := os.ReadFile(cacheFilename)
		if err != nil {
			log.Printf("Item file not found: %s", cacheFilename)
			return json.Marshal(ProxyStatusOutput{Status: "not_found"})
		}
		key, err := os.ReadFile(cacheFilename + ".key")
		if err != nil {
			log.Printf("Key file not found: %s.key", cacheFilename)
			return json.Marshal(ProxyStatusOutput{Status: "not_found"})
		}
		resp := ProxyGetItemOutput{Data: data, Key: key}
		return json.Marshal(resp)
	case "DeleteCachedItem":
		var input ProxyDeleteItemInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid input: %v", err)
		}
		cacheFilename := "item-" + input.Filename
		if err := os.Remove(cacheFilename); err != nil {
			return nil, fmt.Errorf("failed to delete item file: %v", err)
		}
		if err := os.Remove(cacheFilename + ".key"); err != nil {
			return nil, fmt.Errorf("failed to delete key file: %v", err)
		}
		return json.Marshal(ProxyStatusOutput{Status: "success"})
	}
	return nil, fmt.Errorf("unknown operation: %s", req.Operation)
}

func sendVSockResponse(conn net.Conn, resp EnclaveResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		log.Printf("Failed to encode VSock response: %v", err)
		return
	}
	if _, err := conn.Write(data); err != nil {
		log.Printf("Failed to write VSock response: %v", err)
	}
}

func isValidOperation(op string) bool {
	validOps := map[string]bool{
		"GenerateDataKey":    true,
		"Encrypt":            true,
		"Decrypt":            true,
		"StoreEncryptedItem": true,
		"GetCachedItem":      true,
		"DeleteCachedItem":   true,
	}
	return validOps[op]
}

// Utility Functions
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

func getEnvValueUint32(key string, defaultValue uint32) uint32 {
	if value, exists := os.LookupEnv(key); exists {
		if v, err := strconv.ParseUint(value, 10, 32); err == nil {
			return uint32(v)
		}
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value, exists := os.LookupEnv(key); exists {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}

func getEnvInt64(key string, defaultValue int64) int64 {
	if value, exists := os.LookupEnv(key); exists {
		if v, err := strconv.ParseInt(value, 10, 64); err == nil {
			return v
		}
	}
	return defaultValue
}
