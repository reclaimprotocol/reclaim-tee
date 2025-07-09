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
			p.logger.Info("Internet proxy shutting down")
			return nil
		case err := <-errChan:
			p.logger.Error("Accept error", zap.Error(err))
			return err
		case conn := <-connChan:
			go p.handleConnection(ctx, conn)
		}
	}
}

func (p *InternetProxy) handleConnection(ctx context.Context, enclaveConn net.Conn) {
	defer enclaveConn.Close()

	p.logger.Info("Internet proxy connection established",
		zap.String("remote", enclaveConn.RemoteAddr().String()))

	// Read target address with a reasonable timeout
	enclaveConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(enclaveConn)
	targetLine, _, err := reader.ReadLine()
	if err != nil {
		if isTimeoutError(err) {
			p.logger.Info("Connection timed out waiting for target address",
				zap.String("remote", enclaveConn.RemoteAddr().String()))
		} else {
			p.logger.Error("Failed to read target address", zap.Error(err))
		}
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

	// Make outbound connection to target with timeout
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	targetConn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		p.logger.Error("Failed to connect to target",
			zap.String("target", target),
			zap.Error(err))
		return
	}
	defer targetConn.Close()

	// Clear read deadline and set reasonable idle timeouts
	enclaveConn.SetReadDeadline(time.Time{})
	enclaveConn.SetWriteDeadline(time.Time{})
	targetConn.SetReadDeadline(time.Time{})
	targetConn.SetWriteDeadline(time.Time{})

	// Use context for cancellation
	copyCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Bidirectional copy between enclave and target
	done := make(chan error, 2)

	// Copy from enclave to target
	go func() {
		written, err := io.Copy(targetConn, enclaveConn)
		if err != nil && !isConnectionClosed(err) {
			p.logger.Debug("Enclave->Target copy ended",
				zap.String("target", target),
				zap.Int64("bytes", written),
				zap.Error(err))
		} else {
			p.logger.Debug("Enclave->Target copy completed",
				zap.String("target", target),
				zap.Int64("bytes", written))
		}
		done <- err
		cancel() // Cancel context to stop other goroutine
	}()

	// Copy from target to enclave
	go func() {
		written, err := io.Copy(enclaveConn, targetConn)
		if err != nil && !isConnectionClosed(err) {
			p.logger.Debug("Target->Enclave copy ended",
				zap.String("target", target),
				zap.Int64("bytes", written),
				zap.Error(err))
		} else {
			p.logger.Debug("Target->Enclave copy completed",
				zap.String("target", target),
				zap.Int64("bytes", written))
		}
		done <- err
		cancel() // Cancel context to stop other goroutine
	}()

	// Wait for either copy to complete or context cancellation
	select {
	case err := <-done:
		if err != nil && !isConnectionClosed(err) {
			p.logger.Error("Copy error",
				zap.String("target", target),
				zap.Error(err))
		}
	case <-copyCtx.Done():
		p.logger.Info("Connection cancelled", zap.String("target", target))
	case <-time.After(24 * time.Hour): // Maximum connection lifetime
		p.logger.Info("Connection maximum lifetime reached", zap.String("target", target))
	}
}

// Helper functions for error handling
func isTimeoutError(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

func isConnectionClosed(err error) bool {
	if err == io.EOF {
		return true
	}
	if netErr, ok := err.(net.Error); ok {
		return !netErr.Temporary()
	}
	return false
}
