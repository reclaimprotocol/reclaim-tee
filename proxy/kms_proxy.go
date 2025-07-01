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

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("KMS proxy shutting down")
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return nil
				default:
					p.logger.Error("Failed to accept vsock connection", zap.Error(err))
					continue
				}
			}

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
		cacheFilename := "item-" + input.Filename
		if err := os.WriteFile(cacheFilename, input.Data, 0600); err != nil {
			return nil, fmt.Errorf("failed to store item: %v", err)
		}
		if err := os.WriteFile(cacheFilename+".key", input.Key, 0600); err != nil {
			return nil, fmt.Errorf("failed to store key: %v", err)
		}
		return json.Marshal(ProxyStatusOutput{Status: "success"})
	case "GetCachedItem":
		var input ProxyGetItemInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid input: %v", err)
		}
		cacheFilename := "item-" + input.Filename
		data, err := os.ReadFile(cacheFilename)
		if err != nil {
			fmt.Println("item file not found", zap.String("filename", cacheFilename))
			return json.Marshal(ProxyStatusOutput{Status: "not_found"})
		}
		key, err := os.ReadFile(cacheFilename + ".key")
		if err != nil {
			fmt.Println("key file not found", zap.String("filename", cacheFilename+".key"))
			return json.Marshal(ProxyStatusOutput{Status: "not_found"})
		}
		resp := ProxyGetItemOutput{Data: data, Key: key}
		return json.Marshal(resp)
	case "DeleteCachedItem":
		var input ProxyDeleteItemInput
		if err := json.Unmarshal(req.Input, &input); err != nil {
			return nil, fmt.Errorf("invalid input: %v", err)
		}
		cacheFilename := "item-" + input.Filename
		if err := os.Remove(cacheFilename); err != nil {
			return nil, fmt.Errorf("failed to delete item file: %v", err)
		}
		if err := os.Remove(cacheFilename + ".key"); err != nil {
			return nil, fmt.Errorf("failed to delete key file: %v", err)
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
