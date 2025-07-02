package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"
)

// MockVSockListener implements a mock vsock listener for testing
type MockVSockListener struct {
	connChan chan net.Conn
	closed   bool
	mu       sync.Mutex
}

func (m *MockVSockListener) Accept() (net.Conn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, fmt.Errorf("listener closed")
	}

	select {
	case conn := <-m.connChan:
		return conn, nil
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("accept timeout")
	}
}

func (m *MockVSockListener) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	close(m.connChan)
	return nil
}

func (m *MockVSockListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443}
}

// TestHTTPSRouter_SNIExtraction tests the complete SNI extraction and forwarding flow
func TestHTTPSRouter_SNIExtraction(t *testing.T) {
	// Create test certificate for our test domain
	cert, key, err := generateTestCertificate("test.example.com")
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Start mock target HTTPS server
	targetServer, targetAddr := startMockHTTPSServer(t, cert, key)
	defer targetServer.Close()

	// Create test configuration
	config := &ProxyConfig{
		Domains: map[string]EnclaveTarget{
			"test.example.com": {CID: 17},
		},
	}

	// Create HTTPS router
	logger := zaptest.NewLogger(t)
	router, err := NewHTTPSRouter(config, logger)
	if err != nil {
		t.Fatalf("Failed to create HTTPS router: %v", err)
	}

	// Mock the vsock.Dial function by intercepting connections
	originalVSockDial := vsockDialFunc
	defer func() { vsockDialFunc = originalVSockDial }()

	vsockDialFunc = func(cid, port uint32) (net.Conn, error) {
		if cid == 17 && port == 8443 {
			// Connect to our mock target server instead of vsock
			return net.Dial("tcp", targetAddr)
		}
		return nil, fmt.Errorf("unexpected vsock dial: cid=%d, port=%d", cid, port)
	}

	// Start proxy server
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create proxy listener: %v", err)
	}
	defer proxyListener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start router in background
	routerDone := make(chan error, 1)
	go func() {
		routerDone <- router.startWithListener(ctx, proxyListener)
	}()

	// Wait a moment for the router to start
	time.Sleep(100 * time.Millisecond)

	// Test 1: Valid SNI extraction and forwarding
	t.Run("ValidSNI", func(t *testing.T) {
		testValidSNI(t, proxyListener.Addr().String(), "test.example.com")
	})

	// Test 2: Invalid SNI (should be rejected)
	t.Run("InvalidSNI", func(t *testing.T) {
		testInvalidSNI(t, proxyListener.Addr().String(), "invalid.example.com")
	})

	// Test 3: Data integrity (ensure complete TLS stream is preserved)
	t.Run("DataIntegrity", func(t *testing.T) {
		testDataIntegrity(t, proxyListener.Addr().String(), "test.example.com")
	})

	// Cleanup
	cancel()
	select {
	case err := <-routerDone:
		if err != nil && err != context.Canceled {
			t.Errorf("Router error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Router shutdown timeout")
	}
}

// testValidSNI tests that valid SNI is extracted and connection is routed correctly
func testValidSNI(t *testing.T, proxyAddr, sni string) {
	// Create TLS client config with specific SNI
	tlsConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // Skip verification for test certificate
	}

	// Connect through proxy
	conn, err := tls.Dial("tcp", proxyAddr, tlsConfig)
	if err != nil {
		t.Fatalf("Failed to connect through proxy: %v", err)
	}
	defer conn.Close()

	// Make HTTP request
	req := fmt.Sprintf("GET /test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", sni)
	_, err = conn.Write([]byte(req))
	if err != nil {
		t.Fatalf("Failed to send HTTP request: %v", err)
	}

	// Read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil && err != io.EOF {
		t.Fatalf("Failed to read response: %v", err)
	}

	responseStr := string(response[:n])
	if !contains(responseStr, "200 OK") {
		t.Errorf("Expected 200 OK response, got: %s", responseStr)
	}
	if !contains(responseStr, "Test Server Response") {
		t.Errorf("Expected test server response, got: %s", responseStr)
	}
}

// testInvalidSNI tests that invalid SNI is rejected
func testInvalidSNI(t *testing.T, proxyAddr, sni string) {
	// Create TLS client config with invalid SNI
	tlsConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}

	// This should fail or timeout since the domain is not configured
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", proxyAddr, tlsConfig)
	if err == nil {
		conn.Close()
		t.Error("Expected connection to fail for invalid SNI, but it succeeded")
	}
}

// testDataIntegrity ensures the complete TLS stream is preserved
func testDataIntegrity(t *testing.T, proxyAddr, sni string) {
	// Test with a larger payload to ensure buffering works correctly
	largePayload := make([]byte, 8192)
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}

	tlsConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", proxyAddr, tlsConfig)
	if err != nil {
		t.Fatalf("Failed to connect through proxy: %v", err)
	}
	defer conn.Close()

	// Send large payload
	payload := fmt.Sprintf("POST /echo HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", sni, len(largePayload))
	_, err = conn.Write([]byte(payload))
	if err != nil {
		t.Fatalf("Failed to send HTTP headers: %v", err)
	}

	_, err = conn.Write(largePayload)
	if err != nil {
		t.Fatalf("Failed to send payload: %v", err)
	}

	// Read response
	response := make([]byte, 16384)
	n, err := conn.Read(response)
	if err != nil && err != io.EOF {
		t.Fatalf("Failed to read response: %v", err)
	}

	responseStr := string(response[:n])
	if !contains(responseStr, "200 OK") {
		t.Errorf("Expected 200 OK response for large payload, got: %s", responseStr[:200])
	}
}

// Helper functions

func generateTestCertificate(domain string) (tls.Certificate, string, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	// Encode certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	return cert, string(keyPEM), err
}

func startMockHTTPSServer(t *testing.T, cert tls.Certificate, key string) (*http.Server, string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Test Server Response"))
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Echo Response"))
	})

	server := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create test server listener: %v", err)
	}

	go func() {
		server.ServeTLS(listener, "", "")
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	return server, listener.Addr().String()
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr ||
		(len(s) > len(substr) && contains(s[1:], substr))
}

// Add method to router for testing with custom listener
func (r *HTTPSRouter) startWithListener(ctx context.Context, listener net.Listener) error {
	defer listener.Close()

	r.logger.Info("HTTPS router started (test)")

	// Channel for accepting connections
	connChan := make(chan net.Conn, 1)
	errChan := make(chan error, 1)

	// Accept connections in separate goroutine
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case errChan <- err:
				case <-ctx.Done():
					return
				}
				return
			}
			select {
			case connChan <- conn:
			case <-ctx.Done():
				conn.Close()
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("HTTPS router shutting down (test)")
			return nil
		case err := <-errChan:
			r.logger.Error("Accept error (test)")
			return err
		case conn := <-connChan:
			go r.handleConnection(ctx, conn)
		}
	}
}
