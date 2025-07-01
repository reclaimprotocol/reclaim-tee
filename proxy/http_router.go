package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mdlayher/vsock"
	"go.uber.org/zap"
)

type HTTPRouter struct {
	config *ProxyConfig
	logger *zap.Logger
}

func NewHTTPRouter(config *ProxyConfig, logger *zap.Logger) (*HTTPRouter, error) {
	return &HTTPRouter{
		config: config,
		logger: logger.With(zap.String("component", "http_router")),
	}, nil
}

func (r *HTTPRouter) Start(ctx context.Context, port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %v", port, err)
	}
	defer listener.Close()

	r.logger.Info("HTTP router started", zap.Int("port", port))

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("HTTP router shutting down")
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return nil
				default:
					r.logger.Error("Failed to accept connection", zap.Error(err))
					continue
				}
			}

			go r.handleConnection(ctx, conn)
		}
	}
}

func (r *HTTPRouter) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Set read timeout for Host header extraction
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Read HTTP request to extract Host header
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		r.logger.Error("Failed to read HTTP request", zap.Error(err))
		return
	}

	host := req.Host
	if host == "" {
		r.logger.Error("No Host header found in request")
		return
	}

	r.logger.Info("Routing HTTP request", zap.String("host", host), zap.String("path", req.URL.Path))

	// Find target enclave based on host
	var targetCID uint32
	var found bool
	for domain, target := range r.config.Domains {
		if strings.Contains(host, domain) || host == domain {
			targetCID = target.CID
			found = true
			break
		}
	}

	if !found {
		r.logger.Error("No matching domain found", zap.String("host", host))
		r.sendError(conn, 404, "Domain not found")
		return
	}

	// Connect to target enclave
	enclaveConn, err := vsock.Dial(targetCID, 8080, nil)
	if err != nil {
		r.logger.Error("Failed to connect to enclave",
			zap.Uint32("cid", targetCID),
			zap.Error(err))
		r.sendError(conn, 502, "Service unavailable")
		return
	}
	defer enclaveConn.Close()

	// Reconstruct and forward the HTTP request
	if err := req.Write(enclaveConn); err != nil {
		r.logger.Error("Failed to forward request to enclave", zap.Error(err))
		return
	}

	// Clear read deadline and start bidirectional copy
	conn.SetReadDeadline(time.Time{})
	enclaveConn.SetDeadline(time.Now().Add(30 * time.Second))

	// Copy response from enclave to client
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(conn, enclaveConn)
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(enclaveConn, conn)
	}()

	// Wait for either copy to complete or context cancellation
	select {
	case <-done:
		// Connection completed
	case <-ctx.Done():
		// Context cancelled
	case <-time.After(30 * time.Second):
		// Timeout
		r.logger.Warn("HTTP connection timeout")
	}
}

func (r *HTTPRouter) sendError(conn net.Conn, code int, message string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
		code, http.StatusText(code), len(message), message)
	conn.Write([]byte(response))
}
