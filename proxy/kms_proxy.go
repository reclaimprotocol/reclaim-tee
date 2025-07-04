package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/mdlayher/vsock"
	"go.uber.org/zap"
)

// KMS Operation Constants
const (
	OpGenerateDataKey     = "GenerateDataKey"
	OpEncrypt             = "Encrypt"
	OpDecrypt             = "Decrypt"
	OpStoreEncryptedItem  = "StoreEncryptedItem"
	OpGetEncryptedItem    = "GetEncryptedItem"
	OpDeleteEncryptedItem = "DeleteEncryptedItem"
)

// Cache file constants
const (
	CacheFileName  = "kms_cache.json"
	CacheFilePerms = 0600
)

// CacheItem represents a single cached item
type CacheItem struct {
	Data []byte `json:"data"`
	Key  []byte `json:"key"`
}

// ServiceCache represents all cache items for a specific service
type ServiceCache map[string]*CacheItem

// CacheData represents the entire cache structure grouped by service
type CacheData struct {
	Services map[string]ServiceCache `json:"services"`
	mutex    sync.RWMutex            `json:"-"`
}

// NewCacheData creates a new cache data structure
func NewCacheData() *CacheData {
	return &CacheData{
		Services: make(map[string]ServiceCache),
	}
}

// LoadCache loads the cache from disk, creating it if it doesn't exist
func (cd *CacheData) LoadCache() error {
	cd.mutex.Lock()
	defer cd.mutex.Unlock()

	if _, err := os.Stat(CacheFileName); os.IsNotExist(err) {
		// Cache file doesn't exist, initialize empty cache
		cd.Services = make(map[string]ServiceCache)
		return cd.saveToFile()
	}

	data, err := os.ReadFile(CacheFileName)
	if err != nil {
		return fmt.Errorf("failed to read cache file: %v", err)
	}

	var fileData struct {
		Services map[string]ServiceCache `json:"services"`
	}

	if err := json.Unmarshal(data, &fileData); err != nil {
		return fmt.Errorf("failed to parse cache file: %v", err)
	}

	cd.Services = fileData.Services
	if cd.Services == nil {
		cd.Services = make(map[string]ServiceCache)
	}

	return nil
}

// saveToFile saves the cache to disk (must be called with write lock held)
func (cd *CacheData) saveToFile() error {
	fileData := struct {
		Services map[string]ServiceCache `json:"services"`
	}{
		Services: cd.Services,
	}

	data, err := json.MarshalIndent(fileData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache data: %v", err)
	}

	return os.WriteFile(CacheFileName, data, CacheFilePerms)
}

// StoreItem stores a cache item for a specific service
func (cd *CacheData) StoreItem(serviceName, filename string, data, key []byte) error {
	cd.mutex.Lock()
	defer cd.mutex.Unlock()

	if cd.Services[serviceName] == nil {
		cd.Services[serviceName] = make(ServiceCache)
	}

	cd.Services[serviceName][filename] = &CacheItem{
		Data: data,
		Key:  key,
	}

	return cd.saveToFile()
}

// GetItem retrieves a cache item for a specific service
func (cd *CacheData) GetItem(serviceName, filename string) (*CacheItem, error) {
	cd.mutex.RLock()
	defer cd.mutex.RUnlock()

	serviceCache, exists := cd.Services[serviceName]
	if !exists {
		return nil, fmt.Errorf("service not found: %s", serviceName)
	}

	item, exists := serviceCache[filename]
	if !exists {
		return nil, fmt.Errorf("item not found: %s", filename)
	}

	// Return a copy to avoid race conditions
	return &CacheItem{
		Data: append([]byte(nil), item.Data...),
		Key:  append([]byte(nil), item.Key...),
	}, nil
}

// DeleteItem removes a cache item for a specific service
func (cd *CacheData) DeleteItem(serviceName, filename string) error {
	cd.mutex.Lock()
	defer cd.mutex.Unlock()

	serviceCache, exists := cd.Services[serviceName]
	if !exists {
		return nil // Item doesn't exist, consider it deleted
	}

	delete(serviceCache, filename)

	// Clean up empty service cache
	if len(serviceCache) == 0 {
		delete(cd.Services, serviceName)
	}

	return cd.saveToFile()
}

// LoggingHTTPTransport wraps http.Transport to log all requests and responses
type LoggingHTTPTransport struct {
	Transport http.RoundTripper
	Logger    *zap.Logger
}

// RoundTrip implements http.RoundTripper interface with simple request/response logging
func (t *LoggingHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Log simple request
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body)) // Reset body
	}

	t.Logger.Info("KMS Request",
		zap.String("method", req.Method),
		zap.String("url", req.URL.String()),
		zap.String("body", string(body)),
	)

	// Execute request
	start := time.Now()
	resp, err := t.Transport.RoundTrip(req)
	duration := time.Since(start)

	if err != nil {
		t.Logger.Error("KMS Request failed",
			zap.Error(err),
			zap.Duration("duration", duration),
		)
		return resp, err
	}

	// Log simple response
	var respBody []byte
	if resp.Body != nil {
		respBody, _ = io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewReader(respBody)) // Reset body
	}

	t.Logger.Info("KMS Response",
		zap.Int("status", resp.StatusCode),
		zap.Duration("duration", duration),
		zap.String("body", string(respBody)),
	)

	return resp, err
}

type KMSProxy struct {
	config    *ProxyConfig
	logger    *zap.Logger
	kmsClient *kms.Client
	cache     *CacheData
}

type KMSRequest struct {
	Operation   string          `json:"operation"`
	ServiceName string          `json:"service_name,omitempty"` // Optional service name for cache grouping
	Input       json.RawMessage `json:"input"`
}

type KMSResponse struct {
	Output json.RawMessage `json:"output,omitempty"`
	Error  string          `json:"error,omitempty"`
}

type ProxyStoreItemInput struct {
	Data     []byte `json:"data"`
	Key      []byte `json:"key"`
	Filename string `json:"filename"`
}

type ProxyGetItemInput struct {
	Filename string `json:"filename"`
}

type ProxyGetItemOutput struct {
	Data []byte `json:"data"`
	Key  []byte `json:"key"`
}

type ProxyDeleteItemInput struct {
	Filename string `json:"filename"`
}

type ProxyStatusOutput struct {
	Status string `json:"status"`
}

func NewKMSProxy(proxyConfig *ProxyConfig, logger *zap.Logger) (*KMSProxy, error) {
	// Create HTTP transport with logging
	transport := &http.Transport{
		MaxIdleConns:       100,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: false,
	}

	// Initialize AWS KMS client with logging enabled
	awsConfig, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(proxyConfig.AWS.Region),
		config.WithHTTPClient(&http.Client{
			Transport: transport,
			Timeout:   60 * time.Second,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %v", err)
	}

	kmsClient := kms.NewFromConfig(awsConfig)

	// Initialize cache
	cache := NewCacheData()
	if err := cache.LoadCache(); err != nil {
		logger.Warn("Failed to load cache, starting with empty cache", zap.Error(err))
	}

	return &KMSProxy{
		config:    proxyConfig,
		logger:    logger.With(zap.String("component", "kms_proxy")),
		kmsClient: kmsClient,
		cache:     cache,
	}, nil
}

func (p *KMSProxy) Start(ctx context.Context, port int) error {
	listener, err := vsock.Listen(uint32(port), nil)
	if err != nil {
		return fmt.Errorf("failed to listen on vsock port %d: %v", port, err)
	}
	defer listener.Close()

	p.logger.Info("KMS proxy started", zap.Int("port", port))

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
			p.logger.Info("KMS proxy shutting down")
			return nil
		case err := <-errChan:
			p.logger.Error("Accept error", zap.Error(err))
			return err
		case conn := <-connChan:
			go p.handleConnection(ctx, conn)
		}
	}
}

func (p *KMSProxy) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	p.logger.Info("KMS connection established", zap.String("remote", conn.RemoteAddr().String()))

	// Handle multiple requests on the same connection
	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Set read timeout for each request
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))

			buf := make([]byte, 64*1024) // 64KB buffer for KMS requests
			n, err := conn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					p.logger.Info("KMS connection idle timeout")
				} else {
					p.logger.Info("KMS connection closed", zap.Error(err))
				}
				return
			}

			p.logger.Info("Received KMS request", zap.Int("size", n))

			var req KMSRequest
			if err := json.Unmarshal(buf[:n], &req); err != nil {
				p.logger.Error("Invalid KMS request format", zap.Error(err))
				p.sendResponse(conn, KMSResponse{Error: fmt.Sprintf("invalid request: %v", err)})
				continue
			}

			p.logger.Info("Processing KMS operation", zap.String("operation", req.Operation))

			requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			resp, err := p.processOperation(requestCtx, req)
			cancel()

			if err != nil {
				p.logger.Error("KMS operation failed",
					zap.String("operation", req.Operation),
					zap.Error(err))
				p.sendResponse(conn, KMSResponse{Error: err.Error()})
			} else {
				p.logger.Info("KMS operation completed", zap.String("operation", req.Operation))
				p.sendResponse(conn, KMSResponse{Output: resp})
			}

			// Clear read deadline after successful request
			conn.SetReadDeadline(time.Time{})
		}
	}
}

func (p *KMSProxy) processOperation(ctx context.Context, req KMSRequest) ([]byte, error) {
	// Auto-detect service name if not provided (for backward compatibility)
	serviceName := req.ServiceName
	if serviceName == "" {
		// Try to detect from operation context or use a default
		serviceName = "unknown_service"
		p.logger.Warn("No service name provided in KMS request, using default",
			zap.String("operation", req.Operation),
			zap.String("default_service", serviceName))
	}

	switch req.Operation {
	case OpGenerateDataKey:
		var input kms.GenerateDataKeyInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid GenerateDataKey input: %v", err)
		}

		// Log detailed KMS GenerateDataKey request info
		p.logger.Info("KMS GenerateDataKey request details",
			zap.String("KeyId", aws.ToString(input.KeyId)),
			zap.String("KeySpec", string(input.KeySpec)),
			zap.Bool("HasRecipient", input.Recipient != nil),
		)

		if input.Recipient != nil {
			p.logger.Info("KMS GenerateDataKey recipient info",
				zap.Int("AttestationDocument_size", len(input.Recipient.AttestationDocument)),
				zap.String("KeyEncryptionAlgorithm", string(input.Recipient.KeyEncryptionAlgorithm)),
			)
		}

		output, err := p.kmsClient.GenerateDataKey(ctx, &input)
		if err != nil {
			p.logger.Error("KMS GenerateDataKey failed - detailed error",
				zap.Error(err),
				zap.String("ErrorType", fmt.Sprintf("%T", err)),
				zap.String("KeyId", aws.ToString(input.KeyId)),
			)
			return nil, fmt.Errorf("KMS GenerateDataKey failed: %v", err)
		}

		p.logger.Info("KMS GenerateDataKey success",
			zap.Int("CiphertextBlob_size", len(output.CiphertextBlob)),
			zap.Int("CiphertextForRecipient_size", len(output.CiphertextForRecipient)),
			zap.String("KeyId", aws.ToString(output.KeyId)),
		)

		out, err := json.Marshal(output)
		if err != nil {
			return nil, fmt.Errorf("KMS GenerateDataKey failed - detailed error: %v", err)
		}

		fmt.Printf("KMS GenerateDataKey output:\n%s\n", out)

		return out, err

	case OpEncrypt:
		var input kms.EncryptInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid Encrypt input: %v", err)
		}
		output, err := p.kmsClient.Encrypt(ctx, &input)
		if err != nil {
			return nil, fmt.Errorf("KMS Encrypt failed: %v", err)
		}
		return json.Marshal(output)

	case OpDecrypt:
		var input kms.DecryptInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid Decrypt input: %v", err)
		}

		// Log detailed KMS Decrypt request info
		p.logger.Info("KMS Decrypt request details",
			zap.String("KeyId", aws.ToString(input.KeyId)),
			zap.Int("CiphertextBlob_size", len(input.CiphertextBlob)),
			zap.String("EncryptionAlgorithm", string(input.EncryptionAlgorithm)),
			zap.Bool("HasRecipient", input.Recipient != nil),
		)

		if input.Recipient != nil {
			p.logger.Info("KMS Decrypt recipient info",
				zap.Int("AttestationDocument_size", len(input.Recipient.AttestationDocument)),
				zap.String("KeyEncryptionAlgorithm", string(input.Recipient.KeyEncryptionAlgorithm)),
			)
		}

		output, err := p.kmsClient.Decrypt(ctx, &input)
		if err != nil {
			p.logger.Error("KMS Decrypt failed - detailed error",
				zap.Error(err),
				zap.String("ErrorType", fmt.Sprintf("%T", err)),
				zap.String("KeyId", aws.ToString(input.KeyId)),
				zap.Int("CiphertextBlob_size", len(input.CiphertextBlob)),
			)
			return nil, fmt.Errorf("KMS Decrypt failed: %v", err)
		}

		p.logger.Info("KMS Decrypt success",
			zap.Int("CiphertextForRecipient_size", len(output.CiphertextForRecipient)),
			zap.String("KeyId", aws.ToString(output.KeyId)),
			zap.String("EncryptionAlgorithm", string(output.EncryptionAlgorithm)),
		)

		return json.Marshal(output)
	case OpStoreEncryptedItem:
		var input ProxyStoreItemInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid input: %v", err)
		}

		p.logger.Info("Storing encrypted item",
			zap.String("service", serviceName),
			zap.String("filename", input.Filename),
			zap.Int("data_size", len(input.Data)),
			zap.Int("key_size", len(input.Key)))

		// Store in new cache system grouped by service
		if err := p.cache.StoreItem(serviceName, input.Filename, input.Data, input.Key); err != nil {
			return nil, fmt.Errorf("failed to store cache item: %v", err)
		}

		return json.Marshal(ProxyStatusOutput{Status: "success"})
	case OpGetEncryptedItem:
		var input ProxyGetItemInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid GetEncryptedItem input: %v", err)
		}

		p.logger.Info("Getting encrypted item",
			zap.String("service", serviceName),
			zap.String("filename", input.Filename))

		// Get from new cache system grouped by service
		item, err := p.cache.GetItem(serviceName, input.Filename)
		if err != nil {
			p.logger.Debug("Encrypted item not found",
				zap.String("service", serviceName),
				zap.String("filename", input.Filename),
				zap.Error(err))
			return nil, fmt.Errorf("encrypted item not found: %s", input.Filename)
		}

		resp := ProxyGetItemOutput{Data: item.Data, Key: item.Key}
		return json.Marshal(resp)

	case OpDeleteEncryptedItem:
		var input ProxyDeleteItemInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid DeleteEncryptedItem input: %v", err)
		}

		p.logger.Info("Deleting encrypted item",
			zap.String("service", serviceName),
			zap.String("filename", input.Filename))

		// Delete from new cache system grouped by service
		if err := p.cache.DeleteItem(serviceName, input.Filename); err != nil {
			p.logger.Error("Failed to delete cache item",
				zap.String("service", serviceName),
				zap.String("filename", input.Filename),
				zap.Error(err))
			return nil, fmt.Errorf("failed to delete cache item: %v", err)
		}

		return json.Marshal(ProxyStatusOutput{Status: "success"})

	default:
		return nil, fmt.Errorf("unsupported operation: %s", req.Operation)
	}
}

func (p *KMSProxy) sendResponse(conn net.Conn, resp KMSResponse) {
	respBytes, err := json.Marshal(resp)
	if err != nil {
		p.logger.Error("Failed to marshal KMS response", zap.Error(err))
		return
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(respBytes); err != nil {
		p.logger.Error("Failed to send KMS response", zap.Error(err))
	}
	conn.SetWriteDeadline(time.Time{})
}
