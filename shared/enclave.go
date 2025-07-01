package shared

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hf/nsm"
	"github.com/mdlayher/vsock"
	"golang.org/x/crypto/acme"
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
	mu       sync.RWMutex
	items    map[string][]byte
	kmsKeyID string
}

func NewEnclaveServices(config *EnclaveConfig) (*EnclaveServices, error) {
	// Initialize NSM handle
	handle := MustGlobalHandle()

	// Initialize memory cache
	cache := NewMemoryCache(config.KMSKey)

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

	vsockTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			log.Printf("Attempting vsock connection to parent CID %d port %d for %s", enclaveVsockParentCID, enclaveVsockForwardPort, addr)
			var conn net.Conn
			var err error
			for attempt := 1; attempt <= 3; attempt++ {
				conn, err = vsock.Dial(enclaveVsockParentCID, uint32(enclaveVsockForwardPort), nil)
				if err == nil {
					break
				}
				log.Printf("Attempt %d/3: Failed to dial vsock for %s: %v", attempt, addr, err)
				if attempt < 3 {
					time.Sleep(eRetryDelay)
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
			DirectoryURL: config.ACMEURL,
		},
	}

	return manager
}

const (
	defaultKeyBits = 2048
)

func (e *EnclaveHandle) initialize() error {
	var err error
	if e.nsm, err = nsm.OpenDefaultSession(); err != nil {
		return err
	}
	if e.key, err = rsa.GenerateKey(e.nsm, defaultKeyBits); err != nil {
		return err
	}
	return nil
}

// NSM Handle management
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

func (e *EnclaveHandle) PublicKey() *rsa.PublicKey {
	return &e.key.PublicKey
}

func (e *EnclaveHandle) PrivateKey() *rsa.PrivateKey {
	return e.key
}

func MustGlobalHandle() *EnclaveHandle {
	handle, err := GetOrInitializeHandle()
	if err != nil {
		panic(err)
	}
	return handle
}
