package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"tee-mpc/shared"

	"github.com/gorilla/websocket"
	"github.com/mdlayher/vsock"
)

type TEETEnclave struct {
	config   *TEETConfig
	services *shared.EnclaveServices

	// Session management
	clientSessions sync.Map // map[string]*ClientSession
	teekSessions   sync.Map // map[string]*TEEKSession

	// Server instances
	httpServer  *http.Server
	httpsServer *http.Server

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
}

type ClientSession struct {
	conn     *websocket.Conn
	teet     *TEET
	clientID string
	mutex    sync.Mutex
}

type TEEKSession struct {
	conn   *websocket.Conn
	teekID string
	mutex  sync.Mutex
}

func NewTEETEnclave(config *TEETConfig, services *shared.EnclaveServices) *TEETEnclave {
	ctx, cancel := context.WithCancel(context.Background())

	return &TEETEnclave{
		config:   config,
		services: services,
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (t *TEETEnclave) Start() error {
	log.Printf("[TEE_T Enclave] Starting on domain %s", t.config.Domain)

	// Start HTTP server for ACME challenges
	if err := t.startHTTPServer(); err != nil {
		return fmt.Errorf("failed to start HTTP server: %v", err)
	}

	// Start HTTPS server for connections
	if err := t.startHTTPSServer(); err != nil {
		return fmt.Errorf("failed to start HTTPS server: %v", err)
	}

	log.Printf("[TEE_T Enclave] Started successfully")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-t.ctx.Done():
		return nil
	case <-sigChan:
		log.Println("[TEE_T Enclave] Received shutdown signal")
		return t.Stop()
	}
}

func (t *TEETEnclave) startHTTPServer() error {
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "TEE_T Enclave Healthy")
	})

	t.httpServer = &http.Server{
		Handler:           t.services.CertManager.HTTPHandler(mux),
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		// Enable connection reuse for TCP reverse proxy
		DisableGeneralOptionsHandler: false,
	}

	listener, err := vsock.Listen(uint32(t.config.HTTPPort), nil)
	if err != nil {
		return fmt.Errorf("failed to listen on VSock port %d: %v", t.config.HTTPPort, err)
	}

	go func() {
		log.Printf("[TEE_T Enclave] HTTP server listening on VSock port %d", t.config.HTTPPort)
		if err := t.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[TEE_T Enclave] HTTP server error: %v", err)
		}
	}()

	return nil
}

func (t *TEETEnclave) startHTTPSServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", t.handleClientWebSocket) // Client connections
	mux.HandleFunc("/teek", t.handleTEEKWebSocket) // TEE_K connections
	mux.HandleFunc("/attest", t.handleAttestation) // Attestation endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "TEE_T Enclave HTTPS Healthy")
	})

	t.httpsServer = &http.Server{
		Handler:           mux,
		TLSConfig:         t.services.CertManager.TLSConfig(),
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	listener, err := vsock.Listen(uint32(t.config.HTTPSPort), nil)
	if err != nil {
		return fmt.Errorf("failed to listen on VSock port %d: %v", t.config.HTTPSPort, err)
	}

	go func() {
		log.Printf("[TEE_T Enclave] HTTPS server listening on VSock port %d", t.config.HTTPSPort)
		if err := t.httpsServer.ServeTLS(listener, "", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("[TEE_T Enclave] HTTPS server error: %v", err)
		}
	}()

	return nil
}

func (t *TEETEnclave) handleClientWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := teetUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[TEE_T Enclave] Failed to upgrade client websocket: %v", err)
		return
	}
	defer conn.Close()

	clientID := fmt.Sprintf("client_%d", time.Now().UnixNano())
	log.Printf("[TEE_T Enclave] Client %s connected from %s", clientID, r.RemoteAddr)

	// Create session-specific TEET instance
	sessionTEET := NewTEET(t.config.HTTPSPort)
	sessionTEET.clientConn = conn

	session := &ClientSession{
		conn:     conn,
		teet:     sessionTEET,
		clientID: clientID,
	}

	t.clientSessions.Store(clientID, session)
	defer t.clientSessions.Delete(clientID)

	// Handle client messages using existing TEET logic
	t.handleClientSession(session)

	log.Printf("[TEE_T Enclave] Client %s disconnected", clientID)
}

func (t *TEETEnclave) handleTEEKWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := teetUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[TEE_T Enclave] Failed to upgrade TEE_K websocket: %v", err)
		return
	}
	defer conn.Close()

	teekID := fmt.Sprintf("teek_%d", time.Now().UnixNano())
	log.Printf("[TEE_T Enclave] TEE_K %s connected from %s", teekID, r.RemoteAddr)

	session := &TEEKSession{
		conn:   conn,
		teekID: teekID,
	}

	t.teekSessions.Store(teekID, session)
	defer t.teekSessions.Delete(teekID)

	// Handle TEE_K messages
	t.handleTEEKSession(session)

	log.Printf("[TEE_T Enclave] TEE_K %s disconnected", teekID)
}

func (t *TEETEnclave) handleAttestation(w http.ResponseWriter, r *http.Request) {
	log.Printf("[TEE_T Enclave] Attestation request from %s", r.RemoteAddr)

	// Get certificate fingerprint
	cert, err := t.services.CertManager.GetCertificate(&tls.ClientHelloInfo{
		ServerName: t.config.Domain,
	})
	if err != nil {
		log.Printf("[TEE_T Enclave] Failed to get certificate: %v", err)
		http.Error(w, "Failed to get certificate", http.StatusInternalServerError)
		return
	}

	fingerprint := sha256.Sum256(cert.Certificate[0])

	// Generate NSM attestation document with certificate fingerprint
	attestationDoc, err := t.services.Handle.GenerateAttestation(fingerprint[:])
	if err != nil {
		log.Printf("[TEE_T Enclave] Failed to generate attestation: %v", err)
		http.Error(w, "Failed to generate attestation", http.StatusInternalServerError)
		return
	}

	encoded := base64.StdEncoding.EncodeToString(attestationDoc)

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, encoded)

	log.Printf("[TEE_T Enclave] Attestation provided to %s", r.RemoteAddr)
}

func (t *TEETEnclave) handleClientSession(session *ClientSession) {
	for {
		_, msgBytes, err := session.conn.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("[TEE_T Enclave] Client %s read error: %v", session.clientID, err)
			}
			return
		}

		// Parse and route message using existing TEET logic
		msg, err := shared.ParseMessage(msgBytes)
		if err != nil {
			log.Printf("[TEE_T Enclave] Client %s parse error: %v", session.clientID, err)
			continue
		}

		// Route to existing TEET handlers with session isolation
		session.mutex.Lock()
		switch msg.Type {
		case shared.MsgTEETReady:
			session.teet.handleTEETReady(session.conn, msg)
		case shared.MsgRedactionStreams:
			session.teet.handleRedactionStreams(session.conn, msg)
		case shared.MsgEncryptedResponse:
			session.teet.handleEncryptedResponse(session.conn, msg)
		default:
			log.Printf("[TEE_T Enclave] Client %s unknown message: %s", session.clientID, msg.Type)
		}
		session.mutex.Unlock()
	}
}

func (t *TEETEnclave) handleTEEKSession(session *TEEKSession) {
	for {
		_, msgBytes, err := session.conn.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("[TEE_T Enclave] TEE_K %s read error: %v", session.teekID, err)
			}
			return
		}

		// Parse TEE_K messages
		msg, err := shared.ParseMessage(msgBytes)
		if err != nil {
			log.Printf("[TEE_T Enclave] TEE_K %s parse error: %v", session.teekID, err)
			continue
		}

		// Route messages to appropriate client sessions
		session.mutex.Lock()
		t.routeMessageToClients(msg, session)
		session.mutex.Unlock()
	}
}

func (t *TEETEnclave) routeMessageToClients(msg *shared.Message, teekSession *TEEKSession) {
	// For now, route to all client sessions (simplified approach)
	// In production, this would need proper session correlation
	t.clientSessions.Range(func(key, value interface{}) bool {
		clientSession := value.(*ClientSession)

		clientSession.mutex.Lock()
		defer clientSession.mutex.Unlock()

		// Set the TEE_K connection for this client's TEET instance
		clientSession.teet.teekConn = teekSession.conn

		// Route to existing TEET handlers
		switch msg.Type {
		case shared.MsgKeyShareRequest:
			clientSession.teet.handleKeyShareRequest(teekSession.conn, msg)
		case shared.MsgEncryptedRequest:
			clientSession.teet.handleEncryptedRequest(teekSession.conn, msg)
		case shared.MsgResponseTagSecrets:
			clientSession.teet.handleResponseTagSecrets(teekSession.conn, msg)
		default:
			log.Printf("[TEE_T Enclave] TEE_K %s unknown message: %s", teekSession.teekID, msg.Type)
		}

		return true // Continue iteration
	})
}

func (t *TEETEnclave) Stop() error {
	log.Printf("[TEE_T Enclave] Shutting down...")

	t.cancel()

	// Close all client sessions
	t.clientSessions.Range(func(key, value interface{}) bool {
		session := value.(*ClientSession)
		session.conn.Close()
		return true
	})

	// Close all TEE_K sessions
	t.teekSessions.Range(func(key, value interface{}) bool {
		session := value.(*TEEKSession)
		session.conn.Close()
		return true
	})

	// Shutdown servers
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if t.httpServer != nil {
		t.httpServer.Shutdown(ctx)
	}

	if t.httpsServer != nil {
		t.httpsServer.Shutdown(ctx)
	}

	log.Printf("[TEE_T Enclave] Shutdown complete")
	return nil
}
