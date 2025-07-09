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
)

// EnclaveManager provides production-ready enclave functionality
type EnclaveManager struct {
	config        *EnclaveConfig
	connectionMgr *VSockConnectionManager
	certManager   *VSockLegoManager
	cache         *EnclaveCache
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
func NewEnclaveManager(ctx context.Context, config *EnclaveConfig, kmsKeyID string) (*EnclaveManager, error) {

	// Initialize VSock connection manager
	connectionMgr := NewVSockConnectionManager(&VSockConfig{
		ParentCID:    config.ParentCID,
		KMSPort:      config.KMSPort,
		InternetPort: config.InternetPort,
		KMSKeyID:     kmsKeyID, // Use the kmsKeyID parameter instead of config.KMSKey
	})

	err := connectionMgr.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start VSockConnectionManager: %v", err)
	}

	// Initialize encrypted cache with service-specific KMS key and service name prefix
	cache := NewEnclaveCache(connectionMgr, kmsKeyID, config.ServiceName)

	// Get ACME directory URL from environment
	acmeDirectoryURL := GetEnvOrDefault("ACME_DIRECTORY_URL", ZeroSSLProduction)

	certManager, err := NewVSockLegoManager(ctx, &LegoVSockConfig{
		Domain:       config.Domain,
		Email:        "alex@reclaimprotocol.org",
		CADirURL:     acmeDirectoryURL,
		ServiceName:  config.ServiceName,
		HTTPPort:     config.HTTPPort,
		HTTPSPort:    config.HTTPSPort,
		ParentCID:    config.ParentCID,
		InternetPort: config.InternetPort,
		Cache:        cache,
		HTTPClient:   createVSockHTTPClient(config.ParentCID, config.InternetPort),
	})

	if err != nil {
		return nil, fmt.Errorf("failed to start VSockConnectionManager: %v", err)
	}

	return &EnclaveManager{
		config:        config,
		connectionMgr: connectionMgr,
		certManager:   certManager,
		cache:         cache,
	}, nil
}

// BootstrapCertificates ensures certificates are available before starting HTTPS server
func (em *EnclaveManager) BootstrapCertificates(ctx context.Context) error {
	log.Printf("[%s] Bootstrapping certificates for domain: %s", em.config.ServiceName, em.config.Domain)

	// First check if we already have a valid certificate
	cert, err := em.certManager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: em.config.Domain,
	})
	if err == nil && cert != nil {
		log.Printf("[%s] Found valid certificate - skipping ACME process", em.config.ServiceName)
		return nil
	}

	log.Printf("[%s] Starting ACME challenge for %s", em.config.ServiceName, em.config.Domain)

	// Create VSock HTTP server for ACME challenges
	httpServer := em.createVSockHTTPServer(em.certManager.CreateVSockHTTPHandler(nil), em.config.HTTPPort)

	// Start HTTP server in background
	serverErrChan := make(chan error, 1)
	go func() {
		if err := httpServer.ListenAndServeVSock(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[%s] VSock HTTP server error: %v", em.config.ServiceName, err)
			serverErrChan <- err
		}
	}()

	// Wait for HTTP server to start
	time.Sleep(200 * time.Millisecond)

	log.Printf("[%s] Starting ACME certificate request for %s...", em.config.ServiceName, em.config.Domain)
	log.Printf("[%s] ACME Client Directory URL: %s", em.config.ServiceName, em.certManager.config.CADirURL)

	err = em.certManager.BootstrapCertificates(ctx)
	if err != nil {
		return err
	}

	// Create a timeout context for the certificate request
	certCtx, certCancel := context.WithTimeout(ctx, 5*time.Minute)
	defer certCancel()

	// Channel to handle the GetCertificate call with timeout
	certResult := make(chan error, 1)
	go func() {
		log.Printf("[%s] Calling GetCertificate for %s...", em.config.ServiceName, em.config.Domain)
		_, certErr := em.certManager.GetCertificate(&tls.ClientHelloInfo{
			ServerName: em.config.Domain,
		})
		log.Printf("[%s] GetCertificate completed for %s", em.config.ServiceName, em.config.Domain)
		certResult <- certErr
	}()

	// Wait for certificate request to complete or timeout
	select {
	case err = <-certResult:
		if err != nil {
			log.Printf("[%s] ACME certificate request failed: %v", em.config.ServiceName, err)
		} else {
			log.Printf("[%s] ACME certificate request succeeded!", em.config.ServiceName)

			// Force certificate to be cached immediately after ACME success
			log.Printf("[%s] DEBUG: Forcing certificate storage after ACME success...", em.config.ServiceName)

			// Trigger GetCertificate to force certificate generation and caching
			if testCert, testErr := em.certManager.GetCertificate(&tls.ClientHelloInfo{
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

// CreateHTTPSServer creates an HTTPS server with TLS configuration and debugging
func (em *EnclaveManager) CreateHTTPSServer(handler http.Handler) *VSockHTTPSServer {
	tlsConfig := &tls.Config{
		GetCertificate: em.certManager.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}

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

// GenerateAttestation creates an attestation document with optional user data
func (em *EnclaveManager) GenerateAttestation(ctx context.Context, userData ...[]byte) ([]byte, error) {

	handle, err := SafeGetEnclaveHandle()
	if err != nil {
		return nil, fmt.Errorf("failed to get enclave handle: %v", err)

	}

	// Use provided userData if available, otherwise nil for default
	var userDataToUse []byte
	if len(userData) > 0 {
		userDataToUse = userData[0]
	}

	return handle.generateAttestation(userDataToUse)
}

// GetConnectionManager returns the VSock connection manager for KMS operations
func (em *EnclaveManager) GetConnectionManager() *VSockConnectionManager {
	return em.connectionMgr
}

// GetConfig returns the enclave configuration
func (em *EnclaveManager) GetConfig() *EnclaveConfig {
	return em.config
}

// Shutdown gracefully closes all connections and resources
func (em *EnclaveManager) Shutdown(ctx context.Context) error {
	log.Printf("[%s] Shutting down enclave manager", em.config.ServiceName)

	if em.connectionMgr != nil {
		em.connectionMgr.Shutdown(ctx)
	}

	handle, err := SafeGetEnclaveHandle()
	if err != nil {
		return err
	}
	handle.nsm.Close()

	return nil
}

// Private helper methods
func (em *EnclaveManager) getCertificateFingerprint(ctx context.Context) ([]byte, error) {
	// Get current certificate from cache
	cert, err := em.certManager.GetCertificate(&tls.ClientHelloInfo{
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

// createVSockHTTPClient creates an HTTP client that uses VSock for internet connections
func createVSockHTTPClient(parentCID, internetPort uint32) *http.Client {
	manager := &VSockConnectionManager{
		parentCID:    parentCID,
		internetPort: internetPort,
	}

	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return manager.CreateInternetConnection(ctx, addr)
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
