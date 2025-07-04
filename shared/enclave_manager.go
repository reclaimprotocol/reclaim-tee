package shared

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/mdlayher/vsock"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// EnclaveManager provides production-ready enclave functionality
type EnclaveManager struct {
	config          *EnclaveConfig
	handle          *EnclaveHandle
	connectionMgr   *VSockConnectionManager
	autocertManager *autocert.Manager
	cache           *EnclaveCache
	mu              sync.RWMutex
}

type EnclaveConfig struct {
	Domain      string `json:"domain"`       // e.g., "tee-k.reclaimprotocol.org"
	KMSKey      string `json:"kms_key"`      // AWS KMS key ARN
	ParentCID   uint32 `json:"parent_cid"`   // VSock parent CID (usually 3)
	ServiceName string `json:"service_name"` // "tee_k" or "tee_t"

	// Ports
	HTTPPort     uint32 `json:"http_port"`     // 8080 for HTTP
	HTTPSPort    uint32 `json:"https_port"`    // 8443 for HTTPS
	InternetPort uint32 `json:"internet_port"` // 8444 for internet proxy
	KMSPort      uint32 `json:"kms_port"`      // 5000 for KMS proxy
}

type EnclaveHandle struct {
	nsm              *nsm.Session
	key              *rsa.PrivateKey
	mu               sync.RWMutex
	attestationCache map[string]attestationCacheEntry
}

type attestationCacheEntry struct {
	doc       []byte
	createdAt time.Time
}

type AttestationOptions struct {
	Nonce, UserData []byte
	NoPublicKey     bool
	PublicKey       any
}

// VSockHTTPServer provides HTTP server functionality over VSock
type VSockHTTPServer struct {
	Handler      http.Handler
	Port         uint32
	ParentCID    uint32
	ServiceName  string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	server   *http.Server
	listener net.Listener
}

// ListenAndServeVSock starts the VSock HTTP server
func (vs *VSockHTTPServer) ListenAndServeVSock(ctx context.Context) error {
	listener, err := vsock.Listen(vs.Port, nil)
	if err != nil {
		return fmt.Errorf("failed to listen on VSock port %d: %v", vs.Port, err)
	}
	vs.listener = listener

	vs.server = &http.Server{
		Handler:      vs.Handler,
		ReadTimeout:  vs.ReadTimeout,
		WriteTimeout: vs.WriteTimeout,
		IdleTimeout:  vs.IdleTimeout,
	}

	log.Printf("[%s] HTTP server listening on VSock port %d", vs.ServiceName, vs.Port)

	return vs.server.Serve(listener)
}

// Shutdown gracefully shuts down the VSock HTTP server
func (vs *VSockHTTPServer) Shutdown(ctx context.Context) error {
	if vs.server != nil {
		return vs.server.Shutdown(ctx)
	}
	return nil
}

// VSockHTTPSServer provides HTTPS server functionality over VSock
type VSockHTTPSServer struct {
	Handler      http.Handler
	TLSConfig    *tls.Config
	Port         uint32
	ParentCID    uint32
	ServiceName  string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration

	server   *http.Server
	listener net.Listener
}

// ListenAndServeTLS starts the VSock HTTPS server
func (vs *VSockHTTPSServer) ListenAndServeTLS(ctx context.Context) error {
	listener, err := vsock.Listen(vs.Port, nil)
	if err != nil {
		return fmt.Errorf("failed to listen on VSock port %d: %v", vs.Port, err)
	}
	vs.listener = listener

	vs.server = &http.Server{
		Handler:           vs.Handler,
		TLSConfig:         vs.TLSConfig,
		ReadTimeout:       vs.ReadTimeout,
		WriteTimeout:      vs.WriteTimeout,
		IdleTimeout:       vs.IdleTimeout,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("[%s] HTTPS server listening on VSock port %d", vs.ServiceName, vs.Port)

	// Create TLS listener
	tlsListener := tls.NewListener(listener, vs.TLSConfig)
	return vs.server.Serve(tlsListener)
}

// Shutdown gracefully shuts down the VSock HTTPS server
func (vs *VSockHTTPSServer) Shutdown(ctx context.Context) error {
	if vs.server != nil {
		return vs.server.Shutdown(ctx)
	}
	return nil
}

// NewEnclaveManager creates a new enclave manager with production configuration
func NewEnclaveManager(config *EnclaveConfig, kmsKeyID string) (*EnclaveManager, error) {
	// CRITICAL: Use global singleton handle to ensure RSA key is generated only once
	handle, err := SafeGetEnclaveHandle()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize global enclave handle: %v", err)
	}

	// Initialize VSock connection manager
	connectionMgr := NewVSockConnectionManager(config.ParentCID, config.KMSPort, config.InternetPort)

	// Initialize encrypted cache with service-specific KMS key and service name prefix
	cache := NewEnclaveCache(connectionMgr, kmsKeyID, config.ServiceName)

	// Initialize ACME manager
	autocertManager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(config.Domain),
		Cache:      cache,
		Client: &acme.Client{
			HTTPClient:   createVSockHTTPClient(config.ParentCID, config.InternetPort),
			DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		},
	}

	return &EnclaveManager{
		config:          config,
		handle:          handle,
		connectionMgr:   connectionMgr,
		autocertManager: autocertManager,
		cache:           cache,
	}, nil
}

// BootstrapCertificates ensures certificates are available before starting HTTPS server
func (em *EnclaveManager) BootstrapCertificates(ctx context.Context) error {
	log.Printf("[%s] Bootstrapping certificates for domain: %s", em.config.ServiceName, em.config.Domain)

	log.Printf("[%s] Starting ACME challenge for %s", em.config.ServiceName, em.config.Domain)

	// Create VSock HTTP server for ACME challenges
	httpServer := em.createVSockHTTPServer(em.autocertManager.HTTPHandler(nil), em.config.HTTPPort)

	// Start HTTP server in background
	serverErrChan := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServeVSock(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[%s] VSock HTTP server error: %v", em.config.ServiceName, err)
			serverErrChan <- err
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	log.Printf("[%s] Starting ACME certificate request for %s...", em.config.ServiceName, em.config.Domain)
	log.Printf("[%s] ACME Client Directory URL: %s", em.config.ServiceName, em.autocertManager.Client.DirectoryURL)
	log.Printf("[%s] HTTP server running on port %d for ACME challenges", em.config.ServiceName, em.config.HTTPPort)

	// Create a timeout context for the certificate request
	certCtx, certCancel := context.WithTimeout(ctx, 5*time.Minute)
	defer certCancel()

	// Channel to handle the GetCertificate call with timeout
	certResult := make(chan error, 1)
	go func() {
		log.Printf("[%s] Calling GetCertificate for %s...", em.config.ServiceName, em.config.Domain)
		_, certErr := em.autocertManager.GetCertificate(&tls.ClientHelloInfo{
			ServerName: em.config.Domain,
		})
		log.Printf("[%s] GetCertificate completed for %s", em.config.ServiceName, em.config.Domain)
		certResult <- certErr
	}()

	// Wait for certificate request to complete or timeout
	var err error
	select {
	case err = <-certResult:
		if err != nil {
			log.Printf("[%s] ACME certificate request failed: %v", em.config.ServiceName, err)
		} else {
			log.Printf("[%s] ACME certificate request succeeded!", em.config.ServiceName)

			// Force certificate to be cached immediately after ACME success
			log.Printf("[%s] DEBUG: Forcing certificate storage after ACME success...", em.config.ServiceName)

			// Trigger GetCertificate to force certificate generation and caching
			if testCert, testErr := em.autocertManager.GetCertificate(&tls.ClientHelloInfo{
				ServerName: em.config.Domain,
			}); testErr == nil {
				log.Printf("[%s] DEBUG: Forced GetCertificate successful, cert chain length: %d", em.config.ServiceName, len(testCert.Certificate))

				// Verify it's now cached
				if cachedCert, cacheErr := em.cache.Get(ctx, em.config.Domain); cacheErr == nil {
					log.Printf("[%s] DEBUG: Certificate now cached (%d bytes) - ready for TLS!", em.config.ServiceName, len(cachedCert))
				} else {
					log.Printf("[%s] DEBUG: WARNING: Certificate still not cached: %v", em.config.ServiceName, cacheErr)
				}
			} else {
				log.Printf("[%s] DEBUG: Forced GetCertificate failed: %v", em.config.ServiceName, testErr)
			}
		}
	case <-certCtx.Done():
		err = fmt.Errorf("certificate request timed out after 5 minutes")
		log.Printf("[%s] ACME certificate request TIMED OUT", em.config.ServiceName)
	}

	// Shutdown HTTP server
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	httpServer.Shutdown(shutdownCtx)

	// Check for server errors
	select {
	case serverErr := <-serverErrChan:
		if err == nil {
			err = fmt.Errorf("VSock HTTP server failed: %v", serverErr)
		}
	default:
		// No server error
	}

	if err != nil {
		return fmt.Errorf("failed to bootstrap certificate for %s: %v", em.config.Domain, err)
	}

	log.Printf("[%s] Successfully bootstrapped certificate for domain: %s", em.config.ServiceName, em.config.Domain)
	return nil
}

// CreateHTTPSServer creates an HTTPS server with enhanced TLS configuration and debugging
func (em *EnclaveManager) CreateHTTPSServer(handler http.Handler) *VSockHTTPSServer {
	tlsConfig := em.autocertManager.TLSConfig()
	tlsConfig.MinVersion = tls.VersionTLS12
	tlsConfig.MaxVersion = tls.VersionTLS13

	// Wrap the GetCertificate function to add debugging
	originalGetCertificate := tlsConfig.GetCertificate
	tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		log.Printf("[%s] TLS GetCertificate called for SNI: %s", em.config.ServiceName, hello.ServerName)

		cert, err := originalGetCertificate(hello)
		if err != nil {
			log.Printf("[%s] TLS GetCertificate FAILED for %s: %v", em.config.ServiceName, hello.ServerName, err)
		} else {
			log.Printf("[%s] TLS GetCertificate SUCCESS for %s (cert chain length: %d)",
				em.config.ServiceName, hello.ServerName, len(cert.Certificate))
		}

		return cert, err
	}

	// Add connection logging
	tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		log.Printf("[%s] TLS handshake from %s with SNI: %s",
			em.config.ServiceName, hello.Conn.RemoteAddr(), hello.ServerName)
		return nil, nil
	}

	// Create VSock HTTPS server for enclave mode
	return em.createVSockHTTPSServer(handler, tlsConfig, em.config.HTTPSPort)
}

// createVSockHTTPServer creates an HTTP server that listens on VSock
func (em *EnclaveManager) createVSockHTTPServer(handler http.Handler, port uint32) *VSockHTTPServer {
	return &VSockHTTPServer{
		Handler:      handler,
		Port:         port,
		ParentCID:    em.config.ParentCID,
		ServiceName:  em.config.ServiceName,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// createVSockHTTPSServer creates an HTTPS server that listens on VSock
func (em *EnclaveManager) createVSockHTTPSServer(handler http.Handler, tlsConfig *tls.Config, port uint32) *VSockHTTPSServer {
	return &VSockHTTPSServer{
		Handler:      handler,
		TLSConfig:    tlsConfig,
		Port:         port,
		ParentCID:    em.config.ParentCID,
		ServiceName:  em.config.ServiceName,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// GenerateAttestation creates an attestation document with certificate fingerprint
func (em *EnclaveManager) GenerateAttestation(ctx context.Context) ([]byte, error) {
	// Get certificate fingerprint
	fingerprint, err := em.getCertificateFingerprint(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate fingerprint: %v", err)
	}

	// Generate attestation with fingerprint as user data
	userData := []byte(hex.EncodeToString(fingerprint))

	em.handle.mu.RLock()
	defer em.handle.mu.RUnlock()

	return em.handle.generateAttestation(userData)
}

// GetConnectionMetrics returns connection pool metrics
func (em *EnclaveManager) GetConnectionMetrics() map[string]interface{} {
	return em.connectionMgr.GetMetrics()
}

// GetConnectionManager returns the VSock connection manager for KMS operations
func (em *EnclaveManager) GetConnectionManager() *VSockConnectionManager {
	return em.connectionMgr
}

// GetConfig returns the enclave configuration
func (em *EnclaveManager) GetConfig() *EnclaveConfig {
	em.mu.RLock()
	defer em.mu.RUnlock()
	return em.config
}

// Shutdown gracefully closes all connections and resources
func (em *EnclaveManager) Shutdown(ctx context.Context) error {
	log.Printf("[%s] Shutting down enclave manager", em.config.ServiceName)

	if em.connectionMgr != nil {
		em.connectionMgr.Close()
	}

	if em.handle != nil && em.handle.nsm != nil {
		em.handle.nsm.Close()
	}

	return nil
}

// Private helper methods
func (em *EnclaveManager) getCertificateFingerprint(ctx context.Context) ([]byte, error) {
	// Get current certificate from cache
	cert, err := em.autocertManager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: em.config.Domain,
	})
	if err != nil {
		return nil, err
	}

	// Parse certificate and return fingerprint
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate available")
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	return x509Cert.Raw, nil
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

const attestationTTL = 4*time.Minute + 50*time.Second

func (e *EnclaveHandle) generateAttestation(userData []byte) ([]byte, error) {
	// Use "Reclaim Protocol" as default user data if none provided
	if userData == nil {
		userData = []byte("Reclaim Protocol")
	}

	// Generate cache key based on userData
	cacheKey := string(userData)

	// Check cache
	e.mu.RLock()
	entry, found := e.attestationCache[cacheKey]
	if found && time.Since(entry.createdAt) < attestationTTL {
		log.Printf("Using cached attestation for userData: %s", cacheKey)
		e.mu.RUnlock()
		return entry.doc, nil
	}
	e.mu.RUnlock()

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
	e.mu.Lock()
	e.attestationCache[cacheKey] = attestationCacheEntry{
		doc:       attestationDoc,
		createdAt: time.Now(),
	}
	e.mu.Unlock()
	log.Printf("Stored new attestation in cache for userData: %s", cacheKey)

	return attestationDoc, nil
}

// PrivateKey returns the enclave's private key for cryptographic operations
func (e *EnclaveHandle) PrivateKey() *rsa.PrivateKey {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.key
}

func createVSockHTTPClient(parentCID, internetPort uint32) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := vsock.Dial(parentCID, internetPort, nil)
				if err != nil {
					return nil, err
				}

				// Send target address to internet proxy
				_, err = fmt.Fprintf(conn, "%s\n", addr)
				if err != nil {
					conn.Close()
					return nil, err
				}

				return conn, nil
			},
			IdleConnTimeout: 30 * time.Second,
		},
		Timeout: 30 * time.Second,
	}
}

// generateRSAKey generates a new RSA private key
func generateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
