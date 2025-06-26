package enclave

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/mdlayher/vsock"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// CertConfig holds certificate configuration for a TEE service
type CertConfig struct {
	Domain    string
	AcmeURL   string
	KmsKeyID  string
	VsockPort uint32
}

// CertManager handles certificate operations for TEE services
type CertManager struct {
	config  *CertConfig
	manager *autocert.Manager
	cache   *MemoryCache
	client  *http.Client
}

// NewCertManager creates a new certificate manager for a TEE service
func NewCertManager(config *CertConfig) *CertManager {
	cache := NewMemoryCache()

	// Create vsock transport for ACME challenges
	vsockTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			log.Printf("Attempting vsock connection to parent CID %d port %d for %s",
				EnclaveVsockParentCID, config.VsockPort, addr)
			var conn net.Conn
			var err error
			for attempt := 1; attempt <= 3; attempt++ {
				conn, err = vsock.Dial(EnclaveVsockParentCID, config.VsockPort, nil)
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

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(config.Domain),
		Cache:      cache,
		Client: &acme.Client{
			HTTPClient:   client,
			DirectoryURL: config.AcmeURL,
		},
	}

	return &CertManager{
		config:  config,
		manager: manager,
		cache:   cache,
		client:  client,
	}
}

// GetManager returns the autocert manager
func (cm *CertManager) GetManager() *autocert.Manager {
	return cm.manager
}

// GetCache returns the certificate cache
func (cm *CertManager) GetCache() *MemoryCache {
	return cm.cache
}

// GetCertificateFingerprint gets the fingerprint of the current certificate
func (cm *CertManager) GetCertificateFingerprint(ctx context.Context) ([]byte, error) {
	data, err := cm.cache.Get(ctx, cm.config.Domain)
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
			if cert.Subject.CommonName == cm.config.Domain {
				fingerprint := sha256.Sum256(cert.Raw)
				return fingerprint[:], nil
			}
			for _, san := range cert.DNSNames {
				if san == cm.config.Domain {
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
	return nil, fmt.Errorf("no certificate matching domain %s found", cm.config.Domain)
}

// LoadOrIssueCertificate attempts to load or issue a certificate for the domain
func (cm *CertManager) LoadOrIssueCertificate() error {
	log.Printf("Attempting to load or issue certificate for %s", cm.config.Domain)
	_, err := cm.manager.GetCertificate(&tls.ClientHelloInfo{ServerName: cm.config.Domain})
	if err != nil {
		log.Printf("Failed to load or issue certificate for %s: %v", cm.config.Domain, err)
		return err
	}
	log.Printf("Successfully loaded or issued certificate for %s", cm.config.Domain)
	return nil
}

// AttestationService handles attestation operations for TEE services
type AttestationService struct {
	handle      *EnclaveHandle
	certManager *CertManager
	serviceName string
}

// NewAttestationService creates a new attestation service
func NewAttestationService(certManager *CertManager, serviceName string) (*AttestationService, error) {
	handle, err := GetOrInitializeHandle()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize enclave handle: %v", err)
	}

	return &AttestationService{
		handle:      handle,
		certManager: certManager,
		serviceName: serviceName,
	}, nil
}

// GenerateAttestation generates an attestation document with certificate fingerprint
func (as *AttestationService) GenerateAttestation(ctx context.Context) (string, error) {
	fingerprint, err := as.certManager.GetCertificateFingerprint(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get certificate fingerprint: %v", err)
	}

	fingerprintHex := hex.EncodeToString(fingerprint)
	attestationDoc, err := GenerateAttestation(as.handle, []byte(fingerprintHex))
	if err != nil {
		return "", fmt.Errorf("failed to generate attestation: %v", err)
	}

	return base64.StdEncoding.EncodeToString(attestationDoc), nil
}

// CreateAttestationHandler creates an HTTP handler for attestation endpoints
func (as *AttestationService) CreateAttestationHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received attestation request from %s for service %s", r.RemoteAddr, as.serviceName)

		encoded, err := as.GenerateAttestation(r.Context())
		if err != nil {
			log.Printf("Failed to generate attestation for %s: %v", as.serviceName, err)
			http.Error(w, "Failed to generate attestation", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Service", as.serviceName)
		fmt.Fprint(w, encoded)
	}
}
