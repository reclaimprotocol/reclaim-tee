package shared

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// VSockLegoManager integrates Lego with VSock infrastructure for enclaves
type VSockLegoManager struct {
	config          *LegoVSockConfig
	client          *lego.Client
	cache           *EnclaveCache
	challengeServer *VSockChallengeServer
	mu              sync.RWMutex
	certificates    map[string]*tls.Certificate
}

type LegoVSockConfig struct {
	Domain       string        `json:"domain"`
	Email        string        `json:"email"`
	CADirURL     string        `json:"ca_dir_url"`
	ServiceName  string        `json:"service_name"`
	HTTPPort     uint32        `json:"http_port"`
	HTTPSPort    uint32        `json:"https_port"`
	ParentCID    uint32        `json:"parent_cid"`
	InternetPort uint32        `json:"internet_port"`
	Cache        *EnclaveCache `json:"-"`
	HTTPClient   *http.Client  `json:"-"`
}

// VSockChallengeServer handles HTTP-01 challenges over VSock
type VSockChallengeServer struct {
	httpProvider *http01.ProviderServer
	challenges   map[string]string // token -> keyAuth
	mu           sync.RWMutex
}

// Supported ACME CAs
const (
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	ZeroSSLProduction     = "https://acme.zerossl.com/v2/DV90"
	BuyPassProduction     = "https://api.buypass.com/acme/directory"
	BuyPassStaging        = "https://api.buypass.com/acme-v02/directory"
)

// LegoUser implements the required User interface for Lego
type LegoUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *LegoUser) GetEmail() string {
	return u.Email
}

func (u *LegoUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *LegoUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// isValidCachedCertificate checks if a cached certificate is valid and not expiring soon
// This is a standalone version of isValidCertificate for use before creating a manager
func isValidCachedCertificate(cert *tls.Certificate) bool {
	if len(cert.Certificate) == 0 {
		return false
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}

	// Check if certificate expires within 7 days
	timeUntilExpiry := time.Until(x509Cert.NotAfter)
	isValid := timeUntilExpiry > 7*24*time.Hour

	if isValid {
		log.Printf("Certificate validation: expires in %v (valid)", timeUntilExpiry.Round(time.Hour))
	} else {
		log.Printf("Certificate validation: expires in %v (needs renewal)", timeUntilExpiry.Round(time.Hour))
	}

	return isValid
}

// NewVSockLegoManager creates a new Lego manager that works with VSock
func NewVSockLegoManager(ctx context.Context, config *LegoVSockConfig) (*VSockLegoManager, error) {
	log.Printf("[%s] Initializing Lego certificate manager with VSock support", config.ServiceName)
	log.Printf("[%s] CA Directory: %s", config.ServiceName, config.CADirURL)
	log.Printf("[%s] Domain: %s", config.ServiceName, config.Domain)

	// PRIORITY: Check if valid certificate exists in cache BEFORE any ACME operations
	log.Printf("[%s] Checking cache for existing certificate...", config.ServiceName)
	if config.Cache != nil {
		// Try to load certificate from cache
		cacheKey := config.Domain
		cachedData, err := config.Cache.Get(ctx, cacheKey)
		if err == nil {
			log.Printf("[%s] Found cached certificate data (%d bytes)", config.ServiceName, len(cachedData))

			// Try to parse the cached certificate
			cert, err := tls.X509KeyPair(cachedData, cachedData)
			if err == nil {
				// Validate the certificate
				if isValidCachedCertificate(&cert) {
					log.Printf("[%s] Valid certificate found in cache - skipping ACME operations!", config.ServiceName)

					// Create a minimal manager that uses the cached certificate
					manager := &VSockLegoManager{
						config:       config,
						client:       nil, // No ACME client needed for cached certificates
						cache:        config.Cache,
						certificates: make(map[string]*tls.Certificate),
					}

					// Store the valid certificate in memory
					manager.mu.Lock()
					manager.certificates[config.Domain] = &cert
					manager.mu.Unlock()

					return manager, nil
				} else {
					log.Printf("[%s] Cached certificate expired or invalid, will request new one", config.ServiceName)
				}
			} else {
				log.Printf("[%s] Failed to parse cached certificate: %v", config.ServiceName, err)
			}
		} else {
			log.Printf("[%s] No cached certificate found: %v", config.ServiceName, err)
		}
	}

	log.Printf("[%s] No valid cached certificate - proceeding with ACME operations", config.ServiceName)

	// Create or load user private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	user := &LegoUser{
		Email: config.Email,
		key:   privateKey,
	}

	// Create Lego configuration
	legoConfig := lego.NewConfig(user)
	legoConfig.CADirURL = config.CADirURL
	legoConfig.Certificate.KeyType = certcrypto.EC256

	// Use custom HTTP client if provided (for VSock internet connectivity)
	if config.HTTPClient != nil {
		legoConfig.HTTPClient = config.HTTPClient
		log.Printf("[%s] Using VSock HTTP client for ACME requests", config.ServiceName)
	}

	// Create Lego client
	legoClient, err := lego.NewClient(legoConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Lego client: %v", err)
	}

	// Register user account
	log.Printf("[%s] Registering ACME user account...", config.ServiceName)
	reg, err := legoClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("failed to register user: %v", err)
	}
	user.Registration = reg

	log.Printf("[%s] ACME account registered successfully", config.ServiceName)

	manager := &VSockLegoManager{
		config:       config,
		client:       legoClient,
		cache:        config.Cache,
		certificates: make(map[string]*tls.Certificate),
	}

	// Setup VSock-compatible HTTP-01 challenge solver
	err = manager.setupVSockHTTPChallenge()
	if err != nil {
		return nil, fmt.Errorf("failed to setup VSock HTTP challenge: %v", err)
	}

	return manager, nil
}

// setupVSockHTTPChallenge configures HTTP-01 challenge to work with VSock
func (m *VSockLegoManager) setupVSockHTTPChallenge() error {
	log.Printf("[%s] Setting up VSock-compatible HTTP-01 challenge provider", m.config.ServiceName)

	// Create a custom challenge server that integrates with VSock infrastructure
	m.challengeServer = &VSockChallengeServer{
		challenges: make(map[string]string),
	}

	// Create a custom HTTP-01 provider that uses our challenge server
	httpProvider := &VSockHTTP01Provider{
		challengeServer: m.challengeServer,
		serviceName:     m.config.ServiceName,
	}

	err := m.client.Challenge.SetHTTP01Provider(httpProvider)
	if err != nil {
		return fmt.Errorf("failed to set VSock HTTP-01 provider: %v", err)
	}

	log.Printf("[%s] VSock HTTP-01 challenge provider configured", m.config.ServiceName)
	return nil
}

// VSockHTTP01Provider implements the HTTP-01 challenge provider interface for VSock
type VSockHTTP01Provider struct {
	challengeServer *VSockChallengeServer
	serviceName     string
}

// Present implements the challenge.Provider interface
func (p *VSockHTTP01Provider) Present(domain, token, keyAuth string) error {
	log.Printf("[%s] VSock HTTP-01 challenge: Presenting token for domain %s", p.serviceName, domain)

	p.challengeServer.mu.Lock()
	p.challengeServer.challenges[token] = keyAuth
	p.challengeServer.mu.Unlock()

	log.Printf("[%s] Challenge token stored: %s", p.serviceName, token[:8]+"...")
	return nil
}

// CleanUp implements the challenge.Provider interface
func (p *VSockHTTP01Provider) CleanUp(domain, token, keyAuth string) error {
	log.Printf("[%s] VSock HTTP-01 challenge: Cleaning up token for domain %s", p.serviceName, domain)

	p.challengeServer.mu.Lock()
	delete(p.challengeServer.challenges, token)
	p.challengeServer.mu.Unlock()

	return nil
}

// CreateVSockHTTPHandler creates an HTTP handler for ACME challenges that works with VSock
func (m *VSockLegoManager) CreateVSockHTTPHandler(fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log all incoming requests for debugging
		log.Printf("[%s] VSock HTTP request: %s %s from %s", m.config.ServiceName, r.Method, r.URL.Path, r.RemoteAddr)

		// Check if this is an ACME challenge request
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")

			log.Printf("[%s] VSock ACME challenge request for token: %s", m.config.ServiceName, token[:8]+"...")

			m.challengeServer.mu.RLock()
			keyAuth, exists := m.challengeServer.challenges[token]
			m.challengeServer.mu.RUnlock()

			if exists {
				log.Printf("[%s] VSock ACME challenge: Serving keyAuth for token (length: %d)", m.config.ServiceName, len(keyAuth))
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(keyAuth))
				return
			}

			log.Printf("[%s] VSock ACME challenge: Token not found in challenge store", m.config.ServiceName)
			log.Printf("[%s] Available tokens: %d", m.config.ServiceName, len(m.challengeServer.challenges))
			http.NotFound(w, r)
			return
		}

		// Fall back to default handler for non-ACME requests
		if fallback != nil {
			log.Printf("[%s] VSock HTTP request: Falling back to default handler", m.config.ServiceName)
			fallback.ServeHTTP(w, r)
		} else {
			log.Printf("[%s] VSock HTTP request: No fallback handler, returning 404", m.config.ServiceName)
			http.NotFound(w, r)
		}
	})
}

// BootstrapCertificates obtains certificates for the configured domain using VSock
func (m *VSockLegoManager) BootstrapCertificates(ctx context.Context) error {
	log.Printf("[%s] Bootstrapping certificates for domain: %s via VSock", m.config.ServiceName, m.config.Domain)

	// Check if we already have a valid certificate loaded (from cache)
	if m.client == nil {
		log.Printf("[%s] Certificate manager has no ACME client - checking for cached certificate...", m.config.ServiceName)

		// Check if we have a valid cached certificate in memory
		m.mu.RLock()
		if cert, exists := m.certificates[m.config.Domain]; exists {
			if m.IsValidCertificate(cert) {
				m.mu.RUnlock()
				log.Printf("[%s] Valid cached certificate already loaded - skipping bootstrap", m.config.ServiceName)
				return nil
			}
		}
		m.mu.RUnlock()

		return fmt.Errorf("no ACME client available and no valid cached certificate found")
	}

	// Request new certificate
	request := certificate.ObtainRequest{
		Domains: []string{m.config.Domain},
		Bundle:  true,
	}

	log.Printf("[%s] Requesting certificate from %s via VSock", m.config.ServiceName, GetCAName(m.config.CADirURL))
	certificates, err := m.client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate via VSock: %v", err)
	}

	// Store certificate in cache
	err = m.storeCertificate(ctx, m.config.Domain, certificates)
	if err != nil {
		log.Printf("[%s] Warning: failed to cache certificate: %v", m.config.ServiceName, err)
	}

	log.Printf("[%s] Certificate successfully obtained and cached via VSock", m.config.ServiceName)
	return nil
}

// GetCertificate returns a certificate for TLS configuration
func (m *VSockLegoManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := hello.ServerName
	if domain == "" {
		domain = m.config.Domain
	}

	// First try in-memory cache
	m.mu.RLock()
	if cert, exists := m.certificates[domain]; exists {
		if m.IsValidCertificate(cert) {
			m.mu.RUnlock()
			return cert, nil
		}
	}
	m.mu.RUnlock()

	// Then try persistent cache
	cert, err := m.getCachedCertificate(context.Background(), domain)
	if err == nil && m.IsValidCertificate(cert) {
		m.mu.Lock()
		m.certificates[domain] = cert
		m.mu.Unlock()
		return cert, nil
	}

	// No valid certificate found - attempt renewal
	log.Printf("[%s] No valid certificate found for %s, attempting renewal", m.config.ServiceName, domain)

	if m.client == nil {
		return nil, fmt.Errorf("no ACME client available for certificate renewal")
	}

	// Request new certificate
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := m.client.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("failed to renew certificate: %v", err)
	}

	// Store in persistent cache
	err = m.storeCertificate(context.Background(), domain, certificates)
	if err != nil {
		log.Printf("[%s] Warning: failed to cache renewed certificate: %v", m.config.ServiceName, err)
	}

	// Parse and store in memory
	certPEM := certificates.Certificate
	keyPEM := certificates.PrivateKey
	newCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse renewed certificate: %v", err)
	}

	m.mu.Lock()
	m.certificates[domain] = &newCert
	m.mu.Unlock()

	log.Printf("[%s] Successfully renewed certificate for %s", m.config.ServiceName, domain)
	return &newCert, nil
}

// CreateTLSConfig creates a TLS configuration with certificate management
func (m *VSockLegoManager) CreateTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: m.GetCertificate,
		MinVersion:     tls.VersionTLS12,
		MaxVersion:     tls.VersionTLS13,
	}
}

// getCachedCertificate retrieves a certificate from cache
func (m *VSockLegoManager) getCachedCertificate(ctx context.Context, domain string) (*tls.Certificate, error) {
	cacheKey := domain
	data, err := m.cache.Get(ctx, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("certificate cache miss: %v", err)
	}

	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cached certificate: %v", err)
	}

	return &cert, nil
}

// storeCertificate stores a certificate in cache
func (m *VSockLegoManager) storeCertificate(ctx context.Context, domain string, certificates *certificate.Resource) error {
	// Combine certificate and private key like autocert does
	certPEM := certificates.Certificate
	keyPEM := certificates.PrivateKey
	combined := append(certPEM, keyPEM...)

	cacheKey := domain
	return m.cache.Put(ctx, cacheKey, combined)
}

// IsValidCertificate checks if a certificate is valid and not expiring soon
func (m *VSockLegoManager) IsValidCertificate(cert *tls.Certificate) bool {
	if len(cert.Certificate) == 0 {
		return false
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}

	// Check if certificate expires within 7 days
	timeUntilExpiry := time.Until(x509Cert.NotAfter)
	return timeUntilExpiry > 7*24*time.Hour
}

// GetCAName Helper function to get CA name from directory URL
func GetCAName(dirURL string) string {
	switch dirURL {
	case LetsEncryptProduction:
		return "Let's Encrypt Production"
	case LetsEncryptStaging:
		return "Let's Encrypt Staging"
	case ZeroSSLProduction:
		return "ZeroSSL Production"
	case BuyPassProduction:
		return "BuyPass Production"
	case BuyPassStaging:
		return "BuyPass Staging"
	default:
		return "Custom CA"
	}
}
