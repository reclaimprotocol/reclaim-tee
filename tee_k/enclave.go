package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tee-mpc/shared"

	"github.com/gorilla/websocket"
	"github.com/mdlayher/vsock"
)

type TEEKEnclave struct {
	config   *TEEKConfig
	services *shared.EnclaveServices
	teek     *TEEK

	// Server instances
	httpServer  *http.Server
	httpsServer *http.Server

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
}

func NewTEEKEnclave(config *TEEKConfig, services *shared.EnclaveServices) *TEEKEnclave {
	ctx, cancel := context.WithCancel(context.Background())

	return &TEEKEnclave{
		config:   config,
		services: services,
		teek:     NewTEEK(config.HTTPSPort),
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (t *TEEKEnclave) Start() error {
	log.Printf("[TEE_K Enclave] Starting on domain %s", t.config.Domain)

	// Start HTTP server for ACME challenges
	if err := t.startHTTPServer(); err != nil {
		return fmt.Errorf("failed to start HTTP server: %v", err)
	}

	// Start HTTPS server for client connections
	if err := t.startHTTPSServer(); err != nil {
		return fmt.Errorf("failed to start HTTPS server: %v", err)
	}

	// Connect to TEE_T
	go t.connectToTEET()

	log.Printf("[TEE_K Enclave] Started successfully")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-t.ctx.Done():
		return nil
	case <-sigChan:
		log.Println("[TEE_K Enclave] Received shutdown signal")
		return t.Stop()
	}
}

func (t *TEEKEnclave) startHTTPServer() error {
	mux := http.NewServeMux()

	// ACME challenge handler
	mux.Handle("/.well-known/acme-challenge/", t.services.CertManager.HTTPHandler(nil))

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "TEE_K Enclave Healthy")
	})

	t.httpServer = &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	listener, err := vsock.Listen(uint32(t.config.HTTPPort), nil)
	if err != nil {
		return fmt.Errorf("failed to listen on VSock port %d: %v", t.config.HTTPPort, err)
	}

	go func() {
		log.Printf("[TEE_K Enclave] HTTP server listening on VSock port %d", t.config.HTTPPort)
		if err := t.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("[TEE_K Enclave] HTTP server error: %v", err)
		}
	}()

	return nil
}

func (t *TEEKEnclave) startHTTPSServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", t.teek.handleWebSocket)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "TEE_K Enclave HTTPS Healthy")
	})

	t.httpsServer = &http.Server{
		Handler:      mux,
		TLSConfig:    t.services.CertManager.TLSConfig(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	listener, err := vsock.Listen(uint32(t.config.HTTPSPort), nil)
	if err != nil {
		return fmt.Errorf("failed to listen on VSock port %d: %v", t.config.HTTPSPort, err)
	}

	go func() {
		log.Printf("[TEE_K Enclave] HTTPS server listening on VSock port %d", t.config.HTTPSPort)
		if err := t.httpsServer.ServeTLS(listener, "", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("[TEE_K Enclave] HTTPS server error: %v", err)
		}
	}()

	return nil
}

func (t *TEEKEnclave) connectToTEET() {
	for {
		select {
		case <-t.ctx.Done():
			return
		default:
		}

		log.Printf("[TEE_K Enclave] Attempting to connect to TEE_T...")

		// Use proxy internet service to reach TEE_T domain
		conn, err := t.services.DialInternet("tee-t.reclaimprotocol.org:443")
		if err != nil {
			log.Printf("[TEE_K Enclave] Failed to connect to TEE_T: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Perform TLS handshake
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: "tee-t.reclaimprotocol.org",
		})

		if err := tlsConn.Handshake(); err != nil {
			log.Printf("[TEE_K Enclave] TLS handshake failed: %v", err)
			conn.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		// Create WebSocket dialer that uses our TLS connection
		dialer := &websocket.Dialer{
			HandshakeTimeout: 45 * time.Second,
			NetDial: func(network, addr string) (net.Conn, error) {
				return tlsConn, nil
			},
		}

		// Upgrade to WebSocket over TLS
		wsURL := &url.URL{
			Scheme: "wss",
			Host:   "tee-t.reclaimprotocol.org",
			Path:   "/teek",
		}

		headers := http.Header{
			"Origin": {"https://tee-k.reclaimprotocol.org"},
		}

		wsConn, _, err := dialer.Dial(wsURL.String(), headers)
		if err != nil {
			log.Printf("[TEE_K Enclave] WebSocket upgrade failed: %v", err)
			tlsConn.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		log.Printf("[TEE_K Enclave] Connected to TEE_T successfully")

		// Update TEEK instance with connection
		t.teek.teetConn = wsConn

		// Handle connection (this will block until connection is lost)
		t.handleTEETConnection(wsConn)

		log.Printf("[TEE_K Enclave] TEE_T connection lost, retrying...")
		time.Sleep(5 * time.Second)
	}
}

func (t *TEEKEnclave) handleTEETConnection(conn *websocket.Conn) {
	defer conn.Close()

	// Start the existing TEE_T message handler
	go t.teek.handleTEETMessages()

	// Wait for connection to close or context to be cancelled
	select {
	case <-t.ctx.Done():
		return
	}
}

func (t *TEEKEnclave) Stop() error {
	log.Printf("[TEE_K Enclave] Shutting down...")

	t.cancel()

	// Close TEE_T connection
	if t.teek.teetConn != nil {
		t.teek.teetConn.Close()
	}

	// Shutdown servers
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if t.httpServer != nil {
		t.httpServer.Shutdown(ctx)
	}

	if t.httpsServer != nil {
		t.httpsServer.Shutdown(ctx)
	}

	log.Printf("[TEE_K Enclave] Shutdown complete")
	return nil
}
