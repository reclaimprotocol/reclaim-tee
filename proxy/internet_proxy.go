package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/mdlayher/vsock"
	"go.uber.org/zap"
)

type InternetProxy struct {
	config *ProxyConfig
	logger *zap.Logger
}

func NewInternetProxy(config *ProxyConfig, logger *zap.Logger) (*InternetProxy, error) {
	return &InternetProxy{
		config: config,
		logger: logger.With(zap.String("component", "internet_proxy")),
	}, nil
}

func (p *InternetProxy) Start(ctx context.Context, port int) error {
	listener, err := vsock.Listen(uint32(port), nil)
	if err != nil {
		return fmt.Errorf("failed to listen on vsock port %d: %v", port, err)
	}
	defer listener.Close()

	p.logger.Info("Internet proxy started", zap.Int("port", port))

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("Internet proxy shutting down")
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

func (p *InternetProxy) handleConnection(ctx context.Context, enclaveConn net.Conn) {
	defer enclaveConn.Close()

	p.logger.Info("Internet proxy connection established",
		zap.String("remote", enclaveConn.RemoteAddr().String()))

	// Read target address from enclave
	// Expected format: "hostname:port\n" or "ip:port\n"
	enclaveConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(enclaveConn)
	targetLine, _, err := reader.ReadLine()
	if err != nil {
		p.logger.Error("Failed to read target address", zap.Error(err))
		return
	}

	target := strings.TrimSpace(string(targetLine))
	if target == "" {
		p.logger.Error("Empty target address received")
		return
	}

	// Validate target format
	if !strings.Contains(target, ":") {
		p.logger.Error("Invalid target format", zap.String("target", target))
		return
	}

	p.logger.Info("Connecting to target", zap.String("target", target))

	// Make outbound connection to target
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		p.logger.Error("Failed to connect to target",
			zap.String("target", target),
			zap.Error(err))
		return
	}
	defer targetConn.Close()

	// Clear read deadline and start bidirectional copy
	enclaveConn.SetReadDeadline(time.Time{})

	// Set reasonable timeouts for both connections
	deadline := time.Now().Add(10 * time.Minute)
	enclaveConn.SetDeadline(deadline)
	targetConn.SetDeadline(deadline)

	p.logger.Info("Starting bidirectional copy", zap.String("target", target))

	// Bidirectional copy between enclave and target
	done := make(chan struct{}, 2)

	// Copy from enclave to target
	go func() {
		defer func() { done <- struct{}{} }()
		written, err := io.Copy(targetConn, enclaveConn)
		if err != nil {
			p.logger.Debug("Enclave->Target copy ended",
				zap.String("target", target),
				zap.Int64("bytes", written),
				zap.Error(err))
		} else {
			p.logger.Debug("Enclave->Target copy completed",
				zap.String("target", target),
				zap.Int64("bytes", written))
		}
	}()

	// Copy from target to enclave
	go func() {
		defer func() { done <- struct{}{} }()
		written, err := io.Copy(enclaveConn, targetConn)
		if err != nil {
			p.logger.Debug("Target->Enclave copy ended",
				zap.String("target", target),
				zap.Int64("bytes", written),
				zap.Error(err))
		} else {
			p.logger.Debug("Target->Enclave copy completed",
				zap.String("target", target),
				zap.Int64("bytes", written))
		}
	}()

	// Wait for either copy to complete or context cancellation
	select {
	case <-done:
		p.logger.Info("Internet proxy connection completed", zap.String("target", target))
	case <-ctx.Done():
		p.logger.Info("Internet proxy connection cancelled", zap.String("target", target))
	case <-time.After(10 * time.Minute):
		p.logger.Info("Internet proxy connection timeout", zap.String("target", target))
	}
}
