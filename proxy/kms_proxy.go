package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
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

// CacheItem represents a single cached item
type CacheItem struct {
	Data []byte `json:"data"`
	Key  []byte `json:"key"`
}

type KMSProxy struct {
	config    *ProxyConfig
	logger    *zap.Logger
	kmsClient *kms.Client
	cache     *S3CacheData
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

// Custom types matching the simple JSON structures from shared code
type SharedRecipientInfo struct {
	AttestationDocument    []byte `json:"attestation_document"`
	KeyEncryptionAlgorithm string `json:"key_encryption_algorithm"`
}

type SharedGenerateDataKeyInput struct {
	KeyId     string               `json:"key_id"`
	KeySpec   string               `json:"key_spec"`
	Recipient *SharedRecipientInfo `json:"recipient"`
}

type SharedDecryptInput struct {
	KeyId               string               `json:"key_id"`
	CiphertextBlob      []byte               `json:"ciphertext_blob"`
	EncryptionAlgorithm string               `json:"encryption_algorithm"`
	Recipient           *SharedRecipientInfo `json:"recipient"`
}

// Conversion functions to AWS SDK types
func (s *SharedRecipientInfo) toAWSType() *types.RecipientInfo {
	if s == nil {
		return nil
	}
	return &types.RecipientInfo{
		AttestationDocument:    s.AttestationDocument,
		KeyEncryptionAlgorithm: types.KeyEncryptionMechanism(s.KeyEncryptionAlgorithm),
	}
}

func (s *SharedGenerateDataKeyInput) toAWSType() *kms.GenerateDataKeyInput {
	return &kms.GenerateDataKeyInput{
		KeyId:     aws.String(s.KeyId),
		KeySpec:   types.DataKeySpec(s.KeySpec),
		Recipient: s.Recipient.toAWSType(),
	}
}

func (s *SharedDecryptInput) toAWSType() *kms.DecryptInput {
	return &kms.DecryptInput{
		KeyId:               aws.String(s.KeyId),
		CiphertextBlob:      s.CiphertextBlob,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpec(s.EncryptionAlgorithm),
		Recipient:           s.Recipient.toAWSType(),
	}
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

	// Initialize S3 cache backend
	s3Bucket := proxyConfig.AWS.S3CacheBucket
	if s3Bucket == "" {
		return nil, fmt.Errorf("s3_cache_bucket is required in AWS configuration")
	}

	logger.Info("Initializing S3 cache storage", zap.String("bucket", s3Bucket))

	cache, err := NewS3CacheData(context.Background(), awsConfig, s3Bucket, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize S3 cache: %v", err)
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
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					p.logger.Info("KMS connection idle timeout")
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
		var input SharedGenerateDataKeyInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid GenerateDataKey input: %v", err)
		}

		// Log detailed KMS GenerateDataKey request info
		p.logger.Info("KMS GenerateDataKey request details",
			zap.String("KeyId", input.KeyId),
			zap.String("KeySpec", input.KeySpec),
			zap.Bool("HasRecipient", input.Recipient != nil),
		)

		if input.Recipient != nil {
			p.logger.Info("KMS GenerateDataKey recipient info",
				zap.Int("AttestationDocument_size", len(input.Recipient.AttestationDocument)),
				zap.String("KeyEncryptionAlgorithm", input.Recipient.KeyEncryptionAlgorithm),
			)
		}

		output, err := p.kmsClient.GenerateDataKey(ctx, input.toAWSType())
		if err != nil {
			p.logger.Error("KMS GenerateDataKey failed - detailed error",
				zap.Error(err),
				zap.String("ErrorType", fmt.Sprintf("%T", err)),
				zap.String("KeyId", input.KeyId),
			)
			return nil, fmt.Errorf("KMS GenerateDataKey failed: %v", err)
		}

		p.logger.Info("KMS GenerateDataKey success",
			zap.Int("CiphertextBlob_size", len(output.CiphertextBlob)),
			zap.Int("CiphertextForRecipient_size", len(output.CiphertextForRecipient)),
			zap.String("KeyId", aws.ToString(output.KeyId)),
		)

		// Convert AWS response to shared code expected format
		sharedResponse := struct {
			CiphertextBlob         []byte `json:"ciphertext_blob"`
			CiphertextForRecipient []byte `json:"ciphertext_for_recipient"`
		}{
			CiphertextBlob:         output.CiphertextBlob,
			CiphertextForRecipient: output.CiphertextForRecipient,
		}

		out, err := json.Marshal(sharedResponse)
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
		var input SharedDecryptInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid Decrypt input: %v", err)
		}

		// Log detailed KMS Decrypt request info
		p.logger.Info("KMS Decrypt request details",
			zap.String("KeyId", input.KeyId),
			zap.Int("CiphertextBlob_size", len(input.CiphertextBlob)),
			zap.String("EncryptionAlgorithm", input.EncryptionAlgorithm),
			zap.Bool("HasRecipient", input.Recipient != nil),
		)

		if input.Recipient != nil {
			p.logger.Info("KMS Decrypt recipient info",
				zap.Int("AttestationDocument_size", len(input.Recipient.AttestationDocument)),
				zap.String("KeyEncryptionAlgorithm", input.Recipient.KeyEncryptionAlgorithm),
			)
		}

		output, err := p.kmsClient.Decrypt(ctx, input.toAWSType())
		if err != nil {
			p.logger.Error("KMS Decrypt failed - detailed error",
				zap.Error(err),
				zap.String("ErrorType", fmt.Sprintf("%T", err)),
				zap.String("KeyId", input.KeyId),
				zap.Int("CiphertextBlob_size", len(input.CiphertextBlob)),
			)
			return nil, fmt.Errorf("KMS Decrypt failed: %v", err)
		}

		p.logger.Info("KMS Decrypt success",
			zap.Int("CiphertextForRecipient_size", len(output.CiphertextForRecipient)),
			zap.String("KeyId", aws.ToString(output.KeyId)),
			zap.String("EncryptionAlgorithm", string(output.EncryptionAlgorithm)),
		)

		// Convert AWS response to shared code expected format
		sharedResponse := struct {
			CiphertextForRecipient []byte `json:"ciphertext_for_recipient"`
		}{
			CiphertextForRecipient: output.CiphertextForRecipient,
		}

		return json.Marshal(sharedResponse)
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
