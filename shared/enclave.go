package shared

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/hf/nsm"
	"github.com/hf/nsm/request"
	"github.com/mdlayher/vsock"
	"golang.org/x/crypto/acme/autocert"
)

type EnclaveServices struct {
	Handle      *EnclaveHandle
	Cache       *MemoryCache
	CertManager *autocert.Manager
	KMSClient   *KMSClient

	config *EnclaveConfig
}

type EnclaveConfig struct {
	Domain    string
	KMSKey    string
	ParentCID uint32
	ACMEURL   string
}

type EnclaveHandle struct {
	nsm *nsm.Session
	key *rsa.PrivateKey
}

type MemoryCache struct {
	mu    sync.RWMutex
	items map[string][]byte
}

func NewEnclaveServices(config *EnclaveConfig) (*EnclaveServices, error) {
	// Initialize NSM handle
	handle, err := GetOrInitializeHandle()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize NSM handle: %v", err)
	}

	// Initialize memory cache
	cache := NewMemoryCache()

	// Initialize KMS client
	kmsClient := NewKMSClient(config.ParentCID, config.KMSKey)

	// Initialize certificate manager
	certManager := createCertManager(config, cache)

	return &EnclaveServices{
		Handle:      handle,
		Cache:       cache,
		CertManager: certManager,
		KMSClient:   kmsClient,
		config:      config,
	}, nil
}

// VSock connection to parent for internet access
func (e *EnclaveServices) DialInternet(target string) (net.Conn, error) {
	conn, err := vsock.Dial(e.config.ParentCID, 8444, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to dial vsock for internet: %v", err)
	}

	// Send target address
	if _, err := fmt.Fprintf(conn, "%s\n", target); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send target to proxy: %v", err)
	}

	return conn, nil
}

func createCertManager(config *EnclaveConfig, cache *MemoryCache) *autocert.Manager {
	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(config.Domain),
		Cache:      cache,
	}

	return manager
}

// NSM Handle management
func GetOrInitializeHandle() (*EnclaveHandle, error) {
	session, err := nsm.OpenDefaultSession()
	if err != nil {
		return nil, fmt.Errorf("failed to open NSM session: %v", err)
	}

	// Generate RSA key pair for attestation
	key, err := rsa.GenerateKey(nil, 2048) // Using nil for random reader in enclave
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %v", err)
	}

	return &EnclaveHandle{
		nsm: session,
		key: key,
	}, nil
}

func (e *EnclaveHandle) PublicKey() *rsa.PublicKey {
	return &e.key.PublicKey
}

func (e *EnclaveHandle) PrivateKey() *rsa.PrivateKey {
	return e.key
}

func (e *EnclaveHandle) GenerateAttestation(userData []byte) ([]byte, error) {
	// Generate NSM attestation document with user data
	res, err := e.nsm.Send(&request.Attestation{
		Nonce:     nil,
		UserData:  userData,
		PublicKey: nil,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to send attestation request: %v", err)
	}

	if res.Error != "" {
		return nil, errors.New(string(res.Error))
	}

	if res.Attestation == nil || res.Attestation.Document == nil {
		return nil, errors.New("attestation response missing attestation document")
	}

	return res.Attestation.Document, nil
}

// Memory Cache implementation for autocert
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		items: make(map[string][]byte),
	}
}

func (c *MemoryCache) Get(ctx context.Context, key string) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	data, exists := c.items[key]
	if !exists {
		return nil, autocert.ErrCacheMiss
	}

	return data, nil
}

func (c *MemoryCache) Put(ctx context.Context, key string, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[key] = data
	return nil
}

func (c *MemoryCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.items, key)
	return nil
}
