package main

import (
	"context"
	"encoding/binary"

	"github.com/mdlayher/vsock"
	"go.uber.org/zap"
)

const configPort = 5555

func ServeEnclaveConfig(ctx context.Context, domain string, logger *zap.Logger) error {
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

				length := uint16(len(domain))
				if err := binary.Write(conn, binary.BigEndian, length); err != nil {
					logger.Error("Failed to send length", zap.Error(err))
					return
				}

				if _, err := conn.Write([]byte(domain)); err != nil {
					logger.Error("Failed to send domain", zap.Error(err))
					return
				}
				logger.Info("Sent TEE_T domain to enclave", zap.String("domain", domain))
			}()
		}
	}
}
