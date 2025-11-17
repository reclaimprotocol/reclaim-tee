package main

import (
	"context"
	"encoding/binary"
	"encoding/json"

	"github.com/mdlayher/vsock"
	"go.uber.org/zap"
)

const configPort = 5555

func ServeEnclaveConfig(ctx context.Context, config *EnclaveRuntimeConfig, logger *zap.Logger) error {
	listener, err := vsock.Listen(configPort, nil)
	if err != nil {
		return err
	}
	defer listener.Close()

	logger.Info("Config server listening", zap.Uint32("port", configPort))

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				continue
			}

			go func() {
				defer conn.Close()

				// Marshal config to JSON
				configJSON, err := json.Marshal(config)
				if err != nil {
					logger.Error("Failed to marshal config", zap.Error(err))
					return
				}

				length := uint16(len(configJSON))
				if err := binary.Write(conn, binary.BigEndian, length); err != nil {
					logger.Error("Failed to send length", zap.Error(err))
					return
				}

				if _, err := conn.Write(configJSON); err != nil {
					logger.Error("Failed to send config", zap.Error(err))
					return
				}
				logger.Info("Sent enclave config",
					zap.String("tee_k_domain", config.TEEKDomain),
					zap.String("tee_t_domain", config.TEETDomain))
			}()
		}
	}
}
