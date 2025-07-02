package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/mdlayher/vsock"
	"go.uber.org/zap"
)

type KMSProxy struct {
	config    *ProxyConfig
	logger    *zap.Logger
	kmsClient *kms.Client
}

type KMSRequest struct {
	Operation string          `json:"operation"`
	Input     json.RawMessage `json:"input"`
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
	// Initialize AWS KMS client
	awsConfig, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(proxyConfig.AWS.Region),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %v", err)
	}

	return &KMSProxy{
		config:    proxyConfig,
		logger:    logger.With(zap.String("component", "kms_proxy")),
		kmsClient: kms.NewFromConfig(awsConfig),
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
	switch req.Operation {
	case "GenerateDataKey":
		var input kms.GenerateDataKeyInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid GenerateDataKey input: %v", err)
		}
		output, err := p.kmsClient.GenerateDataKey(ctx, &input)
		if err != nil {
			return nil, fmt.Errorf("KMS GenerateDataKey failed: %v", err)
		}
		return json.Marshal(output)

	case "Encrypt":
		var input kms.EncryptInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid Encrypt input: %v", err)
		}
		output, err := p.kmsClient.Encrypt(ctx, &input)
		if err != nil {
			return nil, fmt.Errorf("KMS Encrypt failed: %v", err)
		}
		return json.Marshal(output)

	case "Decrypt":
		var input kms.DecryptInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid Decrypt input: %v", err)
		}
		output, err := p.kmsClient.Decrypt(ctx, &input)
		if err != nil {
			return nil, fmt.Errorf("KMS Decrypt failed: %v", err)
		}
		return json.Marshal(output)
	case "StoreEncryptedItem":
		var input ProxyStoreItemInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid input: %v", err)
		}

		// Store encrypted data and key in combined format for atomic operations
		// Format: [encrypted_key_256_bytes][encrypted_data_remaining_bytes]
		const kmsKeySize = 256 // Fixed size for KMS encrypted keys

		// Pad or truncate key to fixed size for consistent parsing
		paddedKey := make([]byte, kmsKeySize)
		copy(paddedKey, input.Key)

		// Create combined storage: fixed-size key + variable-size data
		combined := make([]byte, kmsKeySize+len(input.Data))
		copy(combined[:kmsKeySize], paddedKey)
		copy(combined[kmsKeySize:], input.Data)

		cacheFilename := "cache-" + input.Filename
		if err := os.WriteFile(cacheFilename, combined, 0600); err != nil {
			return nil, fmt.Errorf("failed to store encrypted item: %v", err)
		}
		return json.Marshal(ProxyStatusOutput{Status: "success"})
	case "GetEncryptedItem":
		var input ProxyGetItemInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid GetEncryptedItem input: %v", err)
		}

		cacheFilename := "cache-" + input.Filename
		combined, err := os.ReadFile(cacheFilename)
		if err != nil {
			p.logger.Debug("Encrypted item not found", zap.String("filename", cacheFilename))
			return nil, fmt.Errorf("encrypted item not found: %s", input.Filename)
		}

		// Combined format: first part is encrypted key, remaining is encrypted data
		// We need to determine the key size (typically 256 bytes for KMS-encrypted keys)
		const kmsKeySize = 256 // Typical KMS encrypted key size
		if len(combined) < kmsKeySize {
			return nil, fmt.Errorf("invalid cached data format")
		}

		encryptedKey := combined[:kmsKeySize]
		encryptedData := combined[kmsKeySize:]

		resp := ProxyGetItemOutput{Data: encryptedData, Key: encryptedKey}
		return json.Marshal(resp)

	case "DeleteEncryptedItem":
		var input ProxyDeleteItemInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid DeleteEncryptedItem input: %v", err)
		}

		cacheFilename := "cache-" + input.Filename
		if err := os.Remove(cacheFilename); err != nil {
			// Don't error if file doesn't exist
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to delete encrypted item: %v", err)
			}
		}

		// Also remove legacy key file if it exists
		os.Remove(cacheFilename + ".key")

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
