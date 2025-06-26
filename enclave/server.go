package enclave

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/mdlayher/vsock"
)

// TEEServer represents a TEE service server
type TEEServer struct {
	config             *ServiceConfig
	certManager        *CertManager
	attestationService *AttestationService
	httpServer         *http.Server
	httpsServer        *http.Server
}

// NewTEEServer creates a new TEE server instance
func NewTEEServer(config *ServiceConfig) (*TEEServer, error) {
	// Create certificate manager
	certManager := NewCertManager(config.ToCertConfig())

	// Create attestation service
	attestationService, err := NewAttestationService(certManager, config.ServiceName)
	if err != nil {
		return nil, err
	}

	return &TEEServer{
		config:             config,
		certManager:        certManager,
		attestationService: attestationService,
	}, nil
}

// SetupServers configures HTTP and HTTPS servers with common infrastructure endpoints
func (ts *TEEServer) SetupServers(businessMux *http.ServeMux) error {
	// Create a combined mux that includes infrastructure endpoints
	mux := http.NewServeMux()

	// Add infrastructure endpoints
	ts.addInfrastructureEndpoints(mux)

	// Add attestation endpoint
	mux.HandleFunc("/attest", ts.attestationService.CreateAttestationHandler())

	// Add business logic routes from the provided mux
	if businessMux != nil {
		mux.Handle("/", businessMux)
	}

	// Setup HTTP server
	ts.httpServer = &http.Server{
		Addr:                         ":" + ts.config.HTTPPort,
		Handler:                      ts.certManager.GetManager().HTTPHandler(mux),
		ReadTimeout:                  5 * time.Second,
		WriteTimeout:                 10 * time.Second,
		IdleTimeout:                  30 * time.Second,
		ReadHeaderTimeout:            5 * time.Second,
		DisableGeneralOptionsHandler: false,
	}

	// Setup HTTPS server
	tlsConfig := ts.certManager.GetManager().TLSConfig()
	tlsConfig.MinVersion = tls.VersionTLS12
	tlsConfig.MaxVersion = tls.VersionTLS13
	tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		log.Printf("TLS handshake from %s with SNI: %s, ALPN: %v, TLS version: 0x%x",
			hello.Conn.RemoteAddr(), hello.ServerName, hello.SupportedProtos, hello.SupportedVersions)
		return nil, nil
	}

	ts.httpsServer = &http.Server{
		Addr:                         ":" + ts.config.HTTPSPort,
		Handler:                      mux,
		TLSConfig:                    tlsConfig,
		ReadTimeout:                  5 * time.Second,
		WriteTimeout:                 10 * time.Second,
		IdleTimeout:                  30 * time.Second,
		ReadHeaderTimeout:            5 * time.Second,
		DisableGeneralOptionsHandler: false,
	}

	return nil
}

// addInfrastructureEndpoints adds common infrastructure endpoints
func (ts *TEEServer) addInfrastructureEndpoints(mux *http.ServeMux) {
	// Metrics endpoint
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		manager := GetConnectionManager()
		total, successful, failed, avgTime := manager.metrics.GetStats()

		metrics := map[string]interface{}{
			"service":               ts.config.ServiceName,
			"domain":                ts.config.Domain,
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

	// Health/status endpoint
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		manager := GetConnectionManager()
		circuitState := CircuitState(atomic.LoadInt32(&manager.circuitBreaker.state))

		status := map[string]interface{}{
			"service":                ts.config.ServiceName,
			"domain":                 ts.config.Domain,
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
}

// StartListeners starts HTTP and HTTPS listeners on vsock ports
func (ts *TEEServer) StartListeners(ctx context.Context) (chan error, chan error) {
	httpErrChan := make(chan error, 1)
	httpsErrChan := make(chan error, 1)

	// Start HTTP listener
	go func() {
		defer close(httpErrChan)

		listener, err := ts.retryListen(ctx, ts.config.VsockPort, "HTTP")
		if err != nil {
			httpErrChan <- err
			return
		}
		if listener == nil {
			return // Shutdown requested
		}
		defer listener.Close()

		log.Printf("Starting %s HTTP server on vsock port %d", ts.config.ServiceName, ts.config.VsockPort)
		if err := ts.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
			httpErrChan <- err
		}
	}()

	// Start HTTPS listener
	go func() {
		defer close(httpsErrChan)

		listener, err := ts.retryListen(ctx, ts.config.VsockPort+1, "HTTPS")
		if err != nil {
			httpsErrChan <- err
			return
		}
		if listener == nil {
			return // Shutdown requested
		}
		defer listener.Close()

		log.Printf("Starting %s HTTPS server on vsock port %d", ts.config.ServiceName, ts.config.VsockPort+1)
		if err := ts.httpsServer.ServeTLS(listener, "", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTPS server error: %v", err)
			httpsErrChan <- err
		}
	}()

	return httpErrChan, httpsErrChan
}

// retryListen attempts to start a vsock listener with retries
func (ts *TEEServer) retryListen(ctx context.Context, port uint32, name string) (net.Listener, error) {
	for {
		listener, err := vsock.Listen(port, nil)
		if err == nil {
			log.Printf("Started %s vsock %s listener on port %d", ts.config.ServiceName, name, port)
			return listener, nil
		}
		log.Printf("Failed to listen on vsock port %d: %v, retrying in %v", port, err, ERetryDelay)
		select {
		case <-ctx.Done():
			log.Printf("Stopping %s %s listener retry due to shutdown", ts.config.ServiceName, name)
			return nil, nil
		case <-time.After(ERetryDelay):
		}
	}
}

// LoadOrIssueCertificate loads or issues a certificate for the service
func (ts *TEEServer) LoadOrIssueCertificate() error {
	return ts.certManager.LoadOrIssueCertificate()
}

// Close shuts down the server
func (ts *TEEServer) Close() error {
	if ts.httpServer != nil {
		ts.httpServer.Close()
	}
	if ts.httpsServer != nil {
		ts.httpsServer.Close()
	}
	return nil
}
