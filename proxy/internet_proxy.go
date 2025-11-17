package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
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

	// Check if this is a local domain that should route back to the proxy or to network (TEET network mode)
	if p.isLocalDomain(target) {
		p.logger.Info("Routing to local domain", zap.String("target", target))
		// If local domain is TEE_T and TEETMode == network, route to configured network URL
		if p.shouldRouteTEETOverNetwork(target) {
			p.logger.Info("TEET network mode enabled - routing over network", zap.String("target", target))
			p.handleTEETNetworkRouting(ctx, enclaveConn, target)
			return
		}
		p.handleLocalDomainConnection(ctx, enclaveConn, target)
		return
	}

	p.logger.Info("Connecting to external target", zap.String("target", target))

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

// isLocalDomain checks if the target domain should be routed back to the proxy
func (p *InternetProxy) isLocalDomain(target string) bool {
	// Extract hostname from target (remove port)
	hostname := target
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		hostname = target[:idx]
	}

	// Check if this hostname is configured as a local domain
	for domain := range p.config.Domains {
		if hostname == domain {
			return true
		}
	}
	return false
}

// handleLocalDomainConnection handles connections to local domains by routing directly to target enclave
func (p *InternetProxy) handleLocalDomainConnection(ctx context.Context, enclaveConn net.Conn, target string) {
	// Extract hostname and port
	hostname := target
	port := "443" // Default HTTPS port
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		hostname = target[:idx]
		port = target[idx+1:]
	}

	// Find target enclave CID for direct VSock communication
	targetConfig, exists := p.config.Domains[hostname]
	if !exists {
		p.logger.Error("Local domain not found in configuration",
			zap.String("hostname", hostname))
		return
	}

	// Determine target VSock port based on requested port
	var targetPort uint32
	switch port {
	case "443":
		targetPort = 8443 // HTTPS port in enclave
	case "80":
		targetPort = 8080 // HTTP port in enclave
	default:
		p.logger.Error("Unsupported port for inter-enclave communication",
			zap.String("hostname", hostname),
			zap.String("port", port))
		return
	}

	p.logger.Info("Direct VSock routing to target enclave",
		zap.String("hostname", hostname),
		zap.Uint32("target_cid", targetConfig.CID),
		zap.Uint32("target_port", targetPort))

	// Connect directly to target enclave via VSock
	targetConn, err := vsock.Dial(targetConfig.CID, targetPort, nil)
	if err != nil {
		p.logger.Error("Failed to connect to target enclave via VSock",
			zap.String("hostname", hostname),
			zap.Uint32("target_cid", targetConfig.CID),
			zap.Uint32("target_port", targetPort),
			zap.Error(err))
		return
	}
	defer targetConn.Close()

	p.logger.Info("Direct VSock connection established",
		zap.String("hostname", hostname),
		zap.Uint32("target_cid", targetConfig.CID),
		zap.Uint32("target_port", targetPort))

	// Clear read deadline and set reasonable idle timeouts
	enclaveConn.SetReadDeadline(time.Time{})
	enclaveConn.SetWriteDeadline(time.Time{})
	targetConn.SetReadDeadline(time.Time{})
	targetConn.SetWriteDeadline(time.Time{})

	// Use context for cancellation
	copyCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Direct VSock-to-VSock bidirectional copy
	done := make(chan error, 2)

	// Copy from source enclave to target enclave
	go func() {
		written, err := io.Copy(targetConn, enclaveConn)
		if err != nil && !isConnectionClosed(err) {
			p.logger.Debug("Source->Target VSock copy ended",
				zap.String("hostname", hostname),
				zap.Uint32("target_cid", targetConfig.CID),
				zap.Int64("bytes", written),
				zap.Error(err))
		} else {
			p.logger.Debug("Source->Target VSock copy completed",
				zap.String("hostname", hostname),
				zap.Uint32("target_cid", targetConfig.CID),
				zap.Int64("bytes", written))
		}
		done <- err
		cancel() // Cancel context to stop other goroutine
	}()

	// Copy from target enclave to source enclave
	go func() {
		written, err := io.Copy(enclaveConn, targetConn)
		if err != nil && !isConnectionClosed(err) {
			p.logger.Debug("Target->Source VSock copy ended",
				zap.String("hostname", hostname),
				zap.Uint32("target_cid", targetConfig.CID),
				zap.Int64("bytes", written),
				zap.Error(err))
		} else {
			p.logger.Debug("Target->Source VSock copy completed",
				zap.String("hostname", hostname),
				zap.Uint32("target_cid", targetConfig.CID),
				zap.Int64("bytes", written))
		}
		done <- err
		cancel() // Cancel context to stop other goroutine
	}()

	// Wait for either copy to complete or context cancellation
	select {
	case err := <-done:
		if err != nil && !isConnectionClosed(err) {
			p.logger.Error("VSock-to-VSock copy error",
				zap.String("hostname", hostname),
				zap.Uint32("target_cid", targetConfig.CID),
				zap.Error(err))
		}
	case <-copyCtx.Done():
		p.logger.Info("VSock-to-VSock connection cancelled",
			zap.String("hostname", hostname),
			zap.Uint32("target_cid", targetConfig.CID))
	case <-time.After(1 * time.Hour): // Reasonable timeout for inter-enclave connections
		p.logger.Info("VSock-to-VSock connection timeout",
			zap.String("hostname", hostname),
			zap.Uint32("target_cid", targetConfig.CID))
	}
}

// shouldRouteTEETOverNetwork determines if the target is TEE_T domain and network mode is enabled
func (p *InternetProxy) shouldRouteTEETOverNetwork(target string) bool {
	if p.config == nil {
		return false
	}
	// Extract hostname
	hostname := target
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		hostname = target[:idx]
	}
	// Heuristic: treat domains containing "tee-t" as TEE_T
	if _, exists := p.config.Domains[hostname]; exists && strings.Contains(strings.ToLower(hostname), "tee-t") {
		return true
	}
	return false
}

// handleTEETNetworkRouting routes local TEE_T domain over network to configured TEETDomain
func (p *InternetProxy) handleTEETNetworkRouting(ctx context.Context, enclaveConn net.Conn, originalTarget string) {
	// Determine destination host:port
	destHostPort := p.resolveTEETNetworkHostPort(originalTarget)
	if destHostPort == "" {
		p.logger.Error("TEET network URL not configured; cannot route over network")
		return
	}

	// Make outbound connection to destination
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	targetConn, err := dialer.DialContext(ctx, "tcp", destHostPort)
	if err != nil {
		p.logger.Error("Failed to connect to TEET network destination", zap.String("dest", destHostPort), zap.Error(err))
		return
	}
	defer targetConn.Close()

	// Clear deadlines
	enclaveConn.SetReadDeadline(time.Time{})
	enclaveConn.SetWriteDeadline(time.Time{})
	targetConn.SetReadDeadline(time.Time{})
	targetConn.SetWriteDeadline(time.Time{})

	// Proxy data bidirectionally
	copyCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 2)

	go func() {
		written, err := io.Copy(targetConn, enclaveConn)
		if err != nil && !isConnectionClosed(err) {
			p.logger.Debug("Enclave->TEET copy ended", zap.String("dest", destHostPort), zap.Int64("bytes", written), zap.Error(err))
		}
		done <- err
		cancel()
	}()

	go func() {
		written, err := io.Copy(enclaveConn, targetConn)
		if err != nil && !isConnectionClosed(err) {
			p.logger.Debug("TEET->Enclave copy ended", zap.String("dest", destHostPort), zap.Int64("bytes", written), zap.Error(err))
		}
		done <- err
		cancel()
	}()

	select {
	case <-done:
	case <-copyCtx.Done():
	case <-time.After(24 * time.Hour):
		p.logger.Info("TEET network connection maximum lifetime reached", zap.String("dest", destHostPort))
	}
}

// resolveTEETNetworkHostPort parses TEETDomain or falls back to original target host:port
func (p *InternetProxy) resolveTEETNetworkHostPort(originalTarget string) string {
	if p.config != nil && p.config.TEETDomain != "" {
		if u, err := url.Parse("wss://" + p.config.TEETDomain); err == nil {
			host := u.Host
			if !strings.Contains(host, ":") {
				// default port
				if u.Scheme == "wss" || u.Scheme == "https" {
					host = host + ":443"
				} else if u.Scheme == "ws" || u.Scheme == "http" {
					host = host + ":80"
				}
			}
			return host
		}
	}
	return originalTarget
}

// Helper functions for error handling
func isTimeoutError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

func isConnectionClosed(err error) bool {
	if err == io.EOF {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return !netErr.Temporary()
	}
	return false
}
