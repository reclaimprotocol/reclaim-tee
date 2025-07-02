package shared

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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
	nsm *nsm.Session
	key *rsa.PrivateKey
	mu  sync.RWMutex
}

// NewEnclaveManager creates a new enclave manager with production configuration
func NewEnclaveManager(config *EnclaveConfig, kmsKeyID string) (*EnclaveManager, error) {
	// CRITICAL: Use global singleton handle to ensure RSA key is generated only once
	handle, err := GetOrInitializeHandle()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize global enclave handle: %v", err)
	}

	// Initialize VSock connection manager
	connectionMgr := NewVSockConnectionManager(config.ParentCID, config.KMSPort, config.InternetPort)

	// Initialize encrypted cache with service-specific KMS key
	cache := NewEnclaveCache(connectionMgr, kmsKeyID)

	// Initialize ACME manager
	autocertManager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(config.Domain),
		Cache:      cache,
		Client: &acme.Client{
			HTTPClient:   createVSockHTTPClient(config.ParentCID, config.InternetPort),
			DirectoryURL: "https://acme-v02.api.letsencrypt.org/directory",
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

	// Start temporary HTTP server for ACME challenges
	httpServer := &http.Server{
		Handler: em.autocertManager.HTTPHandler(nil),
		Addr:    fmt.Sprintf(":%d", em.config.HTTPPort),
	}

	// Start HTTP server in background
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[%s] HTTP server error: %v", em.config.ServiceName, err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Request certificate (this will trigger ACME challenge)
	_, err := em.autocertManager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: em.config.Domain,
	})

	// Shutdown HTTP server
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	httpServer.Shutdown(shutdownCtx)

	if err != nil {
		return fmt.Errorf("failed to bootstrap certificate for %s: %v", em.config.Domain, err)
	}

	log.Printf("[%s] Successfully bootstrapped certificate for domain: %s", em.config.ServiceName, em.config.Domain)
	return nil
}

// CreateHTTPSServer creates an HTTPS server with proper TLS configuration
func (em *EnclaveManager) CreateHTTPSServer(handler http.Handler) *http.Server {
	tlsConfig := em.autocertManager.TLSConfig()
	tlsConfig.MinVersion = tls.VersionTLS12
	tlsConfig.MaxVersion = tls.VersionTLS13

	// Add connection logging
	tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		log.Printf("[%s] TLS handshake from %s with SNI: %s",
			em.config.ServiceName, hello.Conn.RemoteAddr(), hello.ServerName)
		return nil, nil
	}

	return &http.Server{
		Addr:              fmt.Sprintf(":%d", em.config.HTTPSPort),
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
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

// NOTE: initializeEnclaveHandle removed - using global singleton pattern from global_enclave_handle.go

func (eh *EnclaveHandle) generateAttestation(userData []byte) ([]byte, error) {
	// Generate attestation using NSM
	res, err := eh.nsm.Send(&request.Attestation{
		UserData:  userData,
		Nonce:     nil,
		PublicKey: nil,
	})
	if err != nil {
		return nil, fmt.Errorf("NSM attestation request failed: %v", err)
	}

	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, fmt.Errorf("NSM returned empty attestation document")
	}

	return res.Attestation.Document, nil
}

// PrivateKey returns the enclave's private key for cryptographic operations
func (eh *EnclaveHandle) PrivateKey() *rsa.PrivateKey {
	eh.mu.RLock()
	defer eh.mu.RUnlock()
	return eh.key
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
