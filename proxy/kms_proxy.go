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

	kmsClient := kms.NewFromConfig(awsConfig)

	return &KMSProxy{
		config:    proxyConfig,
		logger:    logger.With(zap.String("component", "kms_proxy")),
		kmsClient: kmsClient,
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
				return
			}

			var req KMSRequest
			if err := json.Unmarshal(buf[:n], &req); err != nil {
				p.logger.Error("Invalid KMS request format", zap.Error(err))
				p.sendResponse(conn, KMSResponse{Error: fmt.Sprintf("invalid request: %v", err)})
				continue
			}

			requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			resp, err := p.processOperation(requestCtx, req)
			cancel()

			if err != nil {
				p.sendResponse(conn, KMSResponse{Error: err.Error()})
			} else {
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

		// Simple approach - separate files for key and data
		keyFilename := "cache-" + input.Filename + ".key"
		dataFilename := "cache-" + input.Filename + ".data"

		// Store exact KMS key data (no modifications)
		if err := os.WriteFile(keyFilename, input.Key, 0600); err != nil {
			return nil, fmt.Errorf("failed to store key: %v", err)
		}

		// Store encrypted data
		if err := os.WriteFile(dataFilename, input.Data, 0600); err != nil {
			return nil, fmt.Errorf("failed to store data: %v", err)
		}

		return json.Marshal(ProxyStatusOutput{Status: "success"})
	case "GetEncryptedItem":
		var input ProxyGetItemInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid GetEncryptedItem input: %v", err)
		}

		keyFilename := "cache-" + input.Filename + ".key"
		dataFilename := "cache-" + input.Filename + ".data"

		// Read key file
		encryptedKey, err := os.ReadFile(keyFilename)
		if err != nil {
			return nil, fmt.Errorf("encrypted item not found: %s", input.Filename)
		}

		// Read data file
		encryptedData, err := os.ReadFile(dataFilename)
		if err != nil {
			return nil, fmt.Errorf("encrypted item not found: %s", input.Filename)
		}

		resp := ProxyGetItemOutput{Data: encryptedData, Key: encryptedKey}
		return json.Marshal(resp)

	case "DeleteEncryptedItem":
		var input ProxyDeleteItemInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid DeleteEncryptedItem input: %v", err)
		}

		keyFilename := "cache-" + input.Filename + ".key"
		dataFilename := "cache-" + input.Filename + ".data"

		// Remove both files (ignore errors if files don't exist)
		os.Remove(keyFilename)
		os.Remove(dataFilename)

		return json.Marshal(ProxyStatusOutput{Status: "success"})

	default:
		return nil, fmt.Errorf("unsupported operation: %s", req.Operation)
	}
}

func (p *KMSProxy) sendResponse(conn net.Conn, resp KMSResponse) {
	respBytes, err := json.Marshal(resp)
	if err != nil {
		return
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	conn.Write(respBytes)
	conn.SetWriteDeadline(time.Time{})
}
