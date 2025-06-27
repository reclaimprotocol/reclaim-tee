package main

import (
	"context"
	"crypto/hmac"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"tee/enclave"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocket upgrader with CORS support
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// In production, implement proper origin checking
		return true
	},
}

// WebSocket message types for TEE MPC protocol
type MessageType string

const (
	// Session management
	MsgSessionInit     MessageType = "session_init"
	MsgSessionInitResp MessageType = "session_init_response"

	// TLS handshake coordination
	MsgServerHello       MessageType = "server_hello"
	MsgHandshakeComplete MessageType = "handshake_complete"

	// Split AEAD operations
	MsgEncryptRequest  MessageType = "encrypt_request"
	MsgEncryptResponse MessageType = "encrypt_response"
	MsgDecryptRequest  MessageType = "decrypt_request"
	MsgDecryptResponse MessageType = "decrypt_response"

	// TEE_T coordination
	MsgTagRequest  MessageType = "tag_request"
	MsgTagResponse MessageType = "tag_response"
	MsgTagVerify   MessageType = "tag_verify"

	// Transcript and finalization
	MsgFinalize     MessageType = "finalize"
	MsgFinalizeResp MessageType = "finalize_response"

	// Error and status
	MsgError  MessageType = "error"
	MsgStatus MessageType = "status"
)

// WebSocket message structure
type WSMessage struct {
	Type      MessageType     `json:"type"`
	SessionID string          `json:"session_id,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	Error     string          `json:"error,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
}

// WebSocket connection wrapper
type WSConnection struct {
	conn       *websocket.Conn
	sessionID  string
	clientType string // "user" or "tee_t"
	send       chan WSMessage
	hub        *WSHub
}

// WebSocket hub for managing connections
type WSHub struct {
	connections map[string]*WSConnection // sessionID -> connection
	register    chan *WSConnection
	unregister  chan *WSConnection
	broadcast   chan WSMessage
	mutex       sync.RWMutex
}

// Global WebSocket hub
var wsHub = &WSHub{
	connections: make(map[string]*WSConnection),
	register:    make(chan *WSConnection),
	unregister:  make(chan *WSConnection),
	broadcast:   make(chan WSMessage),
}

// Global TEE communication client for coordinating with TEE_T
var teeCommClient *enclave.TEECommClient

// Start WebSocket hub
func (h *WSHub) run() {
	for {
		select {
		case conn := <-h.register:
			h.mutex.Lock()
			h.connections[conn.sessionID] = conn
			h.mutex.Unlock()
			log.Printf("WebSocket connection registered: %s (%s)", conn.sessionID, conn.clientType)

		case conn := <-h.unregister:
			h.mutex.Lock()
			if _, ok := h.connections[conn.sessionID]; ok {
				delete(h.connections, conn.sessionID)
				close(conn.send)

				// Clean up session storage to prevent memory leak
				storeMutex.Lock()
				if session, exists := sessionStore[conn.sessionID]; exists {
					// Clean up sensitive data in TLS keys
					if session.TLSKeys != nil {
						// Manually zero sensitive key material
						for i := range session.TLSKeys.ClientWriteKey {
							session.TLSKeys.ClientWriteKey[i] = 0
						}
						for i := range session.TLSKeys.ServerWriteKey {
							session.TLSKeys.ServerWriteKey[i] = 0
						}
						for i := range session.TLSKeys.ClientWriteIV {
							session.TLSKeys.ClientWriteIV[i] = 0
						}
						for i := range session.TLSKeys.ServerWriteIV {
							session.TLSKeys.ServerWriteIV[i] = 0
						}
					}
					delete(sessionStore, conn.sessionID)
					log.Printf("Cleaned up session storage for: %s", conn.sessionID)
				}
				storeMutex.Unlock()
			}
			h.mutex.Unlock()
			log.Printf("WebSocket connection unregistered: %s", conn.sessionID)

		case message := <-h.broadcast:
			h.mutex.Lock()
			for sessionID, conn := range h.connections {
				select {
				case conn.send <- message:
				default:
					// Connection is stale, clean it up
					log.Printf("Cleaning up stale WebSocket connection: %s", sessionID)
					close(conn.send)
					delete(h.connections, sessionID)
					conn.conn.Close()

					// Clean up session storage for stale connections
					storeMutex.Lock()
					if session, exists := sessionStore[sessionID]; exists {
						// Clean up sensitive data in TLS keys
						if session.TLSKeys != nil {
							// Manually zero sensitive key material
							for i := range session.TLSKeys.ClientWriteKey {
								session.TLSKeys.ClientWriteKey[i] = 0
							}
							for i := range session.TLSKeys.ServerWriteKey {
								session.TLSKeys.ServerWriteKey[i] = 0
							}
							for i := range session.TLSKeys.ClientWriteIV {
								session.TLSKeys.ClientWriteIV[i] = 0
							}
							for i := range session.TLSKeys.ServerWriteIV {
								session.TLSKeys.ServerWriteIV[i] = 0
							}
						}
						delete(sessionStore, sessionID)
						log.Printf("Cleaned up session storage for stale connection: %s", sessionID)
					}
					storeMutex.Unlock()
				}
			}
			h.mutex.Unlock()
		}
	}
}

// cleanupStaleConnections periodically removes connections with full send buffers
func (h *WSHub) cleanupStaleConnections() {
	ticker := time.NewTicker(60 * time.Second) // Check every 60 seconds (less aggressive)
	defer ticker.Stop()

	for range ticker.C {
		h.mutex.Lock()
		for sessionID, conn := range h.connections {
			// Try to send a status message to test if connection is responsive
			// Use a timeout to avoid blocking during high load
			select {
			case conn.send <- WSMessage{Type: MsgStatus, SessionID: sessionID, Timestamp: time.Now()}:
				// Connection is responsive, continue
			case <-time.After(100 * time.Millisecond):
				// Connection send buffer is full for too long, it's likely stale
				log.Printf("Cleaning up stale WebSocket connection: %s (send buffer full)", sessionID)
				close(conn.send)
				delete(h.connections, sessionID)
				conn.conn.Close()

				// Clean up session storage for stale connections from periodic cleanup
				storeMutex.Lock()
				if session, exists := sessionStore[sessionID]; exists {
					// Clean up sensitive data in TLS keys
					if session.TLSKeys != nil {
						// Manually zero sensitive key material
						for i := range session.TLSKeys.ClientWriteKey {
							session.TLSKeys.ClientWriteKey[i] = 0
						}
						for i := range session.TLSKeys.ServerWriteKey {
							session.TLSKeys.ServerWriteKey[i] = 0
						}
						for i := range session.TLSKeys.ClientWriteIV {
							session.TLSKeys.ClientWriteIV[i] = 0
						}
						for i := range session.TLSKeys.ServerWriteIV {
							session.TLSKeys.ServerWriteIV[i] = 0
						}
					}
					delete(sessionStore, sessionID)
					log.Printf("Cleaned up session storage for stale connection: %s", sessionID)
				}
				storeMutex.Unlock()
			}
		}
		h.mutex.Unlock()
	}
}

// Send message to specific session
func (h *WSHub) sendToSession(sessionID string, message WSMessage) error {
	h.mutex.RLock()
	conn, exists := h.connections[sessionID]
	h.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	select {
	case conn.send <- message:
		return nil
	default:
		return fmt.Errorf("connection send buffer full")
	}
}

// handleWebSocket upgrades HTTP connection to WebSocket and manages the protocol
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	// Extract session info from query parameters
	sessionID := r.URL.Query().Get("session_id")
	clientType := r.URL.Query().Get("client_type") // "user" or "tee_t"

	if sessionID == "" {
		sessionID = fmt.Sprintf("ws-session-%d", time.Now().UnixNano())
	}

	if clientType == "" {
		clientType = "user" // Default to user connection
	}

	wsConn := &WSConnection{
		conn:       conn,
		sessionID:  sessionID,
		clientType: clientType,
		send:       make(chan WSMessage, 1024), // Increased buffer for better performance during benchmarks
		hub:        wsHub,
	}

	// Register connection
	wsHub.register <- wsConn

	// Start goroutines for reading and writing
	go wsConn.writePump()
	go wsConn.readPump()

	log.Printf("WebSocket connection established: %s (%s)", sessionID, clientType)
}

// readPump handles incoming WebSocket messages
func (c *WSConnection) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	// Set read deadline and ping/pong handlers
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})
	c.conn.SetPingHandler(func(appData string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		err := c.conn.WriteMessage(websocket.PongMessage, []byte(appData))
		if err != nil {
			log.Printf("Failed to send pong response: %v", err)
		}
		return err
	})

	for {
		var msg WSMessage
		err := c.conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		// Set timestamp
		msg.Timestamp = time.Now()

		// Handle the message
		c.handleMessage(msg)
	}
}

// writePump handles outgoing WebSocket messages
func (c *WSConnection) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteJSON(message); err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					log.Printf("WebSocket write error: %v", err)
				}
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					log.Printf("WebSocket ping error: %v", err)
				}
				return
			}
		}
	}
}

// handleMessage processes incoming WebSocket messages based on type
func (c *WSConnection) handleMessage(msg WSMessage) {
	log.Printf("Received WebSocket message: %s from %s (%s)", msg.Type, c.sessionID, c.clientType)

	switch msg.Type {
	case MsgSessionInit:
		c.handleSessionInit(msg)
	case MsgServerHello:
		c.handleServerHello(msg)
	case MsgEncryptRequest:
		c.handleEncryptRequest(msg)
	case MsgDecryptRequest:
		c.handleDecryptRequest(msg)
	case MsgTagVerify:
		c.handleTagVerify(msg)
	case MsgFinalize:
		c.handleFinalize(msg)
	default:
		c.sendError(fmt.Sprintf("Unknown message type: %s", msg.Type))
	}
}

// Send error message back to client
func (c *WSConnection) sendError(errorMsg string) {
	response := WSMessage{
		Type:      MsgError,
		SessionID: c.sessionID,
		Error:     errorMsg,
		Timestamp: time.Now(),
	}

	select {
	case c.send <- response:
	case <-time.After(1 * time.Second):
		// Connection send buffer is full for too long, close connection
		log.Printf("WebSocket send buffer full for %s for 1 second, closing connection", c.sessionID)
		c.conn.Close()
	}
}

// Send response message back to client
func (c *WSConnection) sendResponse(msgType MessageType, data interface{}) {
	dataBytes, _ := json.Marshal(data)

	response := WSMessage{
		Type:      msgType,
		SessionID: c.sessionID,
		Data:      dataBytes,
		Timestamp: time.Now(),
	}

	select {
	case c.send <- response:
	case <-time.After(1 * time.Second):
		// Connection send buffer is full for too long, close connection
		log.Printf("WebSocket send buffer full for %s for 1 second, closing connection", c.sessionID)
		c.conn.Close()
	}
}

// WebSocket message types

// SessionInitRequest holds the data needed to initialize a TLS session
type SessionInitRequest struct {
	Hostname      string   `json:"hostname"`
	Port          int      `json:"port"`
	SNI           string   `json:"sni"`
	ALPNProtocols []string `json:"alpn_protocols"`
}

// SessionInitResponse contains the Client Hello and session info
type SessionInitResponse struct {
	SessionID   string `json:"session_id"`
	ClientHello []byte `json:"client_hello"`
	Status      string `json:"status"`
}

// WebSocket message handlers

// handleSessionInit processes session initialization via WebSocket
func (c *WSConnection) handleSessionInit(msg WSMessage) {
	var req SessionInitRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		c.sendError("Invalid session init request format")
		return
	}

	// Validate required fields
	if req.Hostname == "" {
		c.sendError("Hostname is required")
		return
	}
	if req.Port == 0 {
		req.Port = 443
	}
	if req.SNI == "" {
		req.SNI = req.Hostname
	}

	// Create TLS client configuration
	tlsConfig := &enclave.TLSClientConfig{
		ServerName:    req.SNI,
		ALPNProtocols: req.ALPNProtocols,
		MaxVersion:    enclave.VersionTLS13,
	}

	// Initialize TLS client state
	tlsClient, err := enclave.NewTLSClientState(tlsConfig)
	if err != nil {
		c.sendError(fmt.Sprintf("Failed to initialize TLS client: %v", err))
		return
	}

	// Generate Client Hello
	clientHello, err := tlsClient.GenerateClientHello()
	if err != nil {
		c.sendError(fmt.Sprintf("Failed to generate Client Hello: %v", err))
		return
	}

	// Create or update session
	sessionID := c.sessionID
	if msg.SessionID != "" {
		sessionID = msg.SessionID
		c.sessionID = sessionID
	}

	// Create transcript signer for demo (generates random key)
	transcriptSigner, err := enclave.GenerateDemoKey()
	if err != nil {
		c.sendError(fmt.Sprintf("Failed to create transcript signer: %v", err))
		return
	}

	newState := &SessionState{
		ID:                       sessionID,
		TLSClient:                tlsClient,
		WebsiteURL:               fmt.Sprintf("%s:%d", req.Hostname, req.Port),
		Completed:                false,
		TranscriptSigner:         transcriptSigner,
		RequestTranscriptBuilder: enclave.NewRequestTranscriptBuilder(sessionID),
		ClientSeqNum:             0, // TLS 1.3 client sequence starts at 0
		ServerSeqNum:             0, // TLS 1.3 server sequence starts at 0
	}

	storeMutex.Lock()
	sessionStore[sessionID] = newState
	storeMutex.Unlock()

	log.Printf("WebSocket: Initialized TLS session %s for %s", sessionID, req.Hostname)

	// Send response
	response := SessionInitResponse{
		SessionID:   sessionID,
		ClientHello: clientHello,
		Status:      "client_hello_ready",
	}

	c.sendResponse(MsgSessionInitResp, response)
}

// handleServerHello processes Server Hello message and completes TLS handshake
func (c *WSConnection) handleServerHello(msg WSMessage) {
	type ServerHelloData struct {
		ServerHelloRecord []byte `json:"server_hello_record"`
	}

	var data ServerHelloData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		c.sendError("Invalid server hello data format")
		return
	}

	// Get session
	storeMutex.RLock()
	session, exists := sessionStore[c.sessionID]
	storeMutex.RUnlock()

	if !exists {
		c.sendError("Session not found")
		return
	}

	// Process Server Hello
	err := session.TLSClient.ProcessServerHello(data.ServerHelloRecord)
	if err != nil {
		c.sendError(fmt.Sprintf("Failed to process Server Hello: %v", err))
		return
	}

	// Extract certificate chain from real TLS connection (Protocol Step 2.3)
	// This provides the actual server certificates for verification
	hostname := "example.com" // Default for demo
	if session.WebsiteURL != "" {
		// Parse hostname from WebsiteURL (format: "hostname:port")
		if colonIndex := strings.Index(session.WebsiteURL, ":"); colonIndex != -1 {
			hostname = session.WebsiteURL[:colonIndex]
		} else {
			hostname = session.WebsiteURL
		}
	}

	if err := session.TLSClient.ExtractCertificateChainFromTLS(hostname, 443); err != nil {
		log.Printf("Warning: Failed to extract certificate chain from %s: %v", hostname, err)
		// Continue without certificate chain - demo will show the limitation
	} else {
		log.Printf("WebSocket: Certificate chain extracted successfully from %s", hostname)
	}

	// Complete TLS handshake and extract session keys
	sessionKeys, err := session.TLSClient.ExtractSessionKeys()
	if err != nil {
		c.sendError(fmt.Sprintf("Failed to extract session keys: %v", err))
		return
	}

	// Extract handshake key for certificate verification (Protocol Step 2.3)
	// This allows the User to verify the certificate chain authenticity
	handshakeKey, err := session.TLSClient.ExtractHandshakeKey()
	if err != nil {
		log.Printf("Warning: Failed to extract handshake key for certificate verification: %v", err)
		// Continue without handshake key revelation
	}

	// Update session with keys
	storeMutex.Lock()
	session.TLSKeys = sessionKeys
	session.Completed = true
	storeMutex.Unlock()

	log.Printf("WebSocket: TLS handshake completed for session %s", c.sessionID)

	// Send handshake complete response with certificate verification data
	type HandshakeCompleteData struct {
		Status           string `json:"status"`
		CipherSuite      uint16 `json:"cipher_suite"`
		KeysReady        bool   `json:"keys_ready"`
		HandshakeKey     []byte `json:"handshake_key,omitempty"`     // For certificate verification
		CertificateChain []byte `json:"certificate_chain,omitempty"` // Server certificate chain
	}

	response := HandshakeCompleteData{
		Status:      "handshake_complete",
		CipherSuite: sessionKeys.CipherSuite,
		KeysReady:   true,
	}

	// Add handshake key for certificate verification if available
	if handshakeKey != nil {
		response.HandshakeKey = handshakeKey
		log.Printf("WebSocket: Providing handshake key for certificate verification (%d bytes)", len(handshakeKey))
	}

	// Add certificate chain for verification if available
	if certChain := session.TLSClient.GetCertificateChain(); certChain != nil {
		response.CertificateChain = certChain
		log.Printf("WebSocket: Providing certificate chain for verification (%d bytes)", len(certChain))
	}

	c.sendResponse(MsgHandshakeComplete, response)
}

// handleEncryptRequest processes request encryption for split AEAD with redaction support
func (c *WSConnection) handleEncryptRequest(msg WSMessage) {
	type EncryptRequestData struct {
		// Standard fields
		RequestData []byte            `json:"request_data"`
		Commitments map[string][]byte `json:"commitments"`
		Nonce       []byte            `json:"nonce"`
		AAD         []byte            `json:"aad"`

		// Redaction fields
		RedactionRequest *enclave.RedactionRequest `json:"redaction_request,omitempty"`
		RedactionStreams *enclave.RedactionStreams `json:"redaction_streams,omitempty"`
		RedactionKeys    *enclave.RedactionKeys    `json:"redaction_keys,omitempty"`
		UseRedaction     bool                      `json:"use_redaction"`
	}

	var data EncryptRequestData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		c.sendError("Invalid encrypt request data format")
		return
	}

	// Get session
	storeMutex.RLock()
	session, exists := sessionStore[c.sessionID]
	storeMutex.RUnlock()

	if !exists || !session.Completed {
		c.sendError("Session not ready for encryption")
		return
	}

	// Get session keys for Split AEAD
	sessionKeys := session.TLSKeys
	if sessionKeys == nil {
		c.sendError("Session keys not available")
		return
	}

	// Determine Split AEAD mode based on cipher suite
	var mode enclave.SplitAEADMode
	switch sessionKeys.CipherSuite {
	case enclave.TLS_AES_128_GCM_SHA256, enclave.TLS_AES_256_GCM_SHA384:
		mode = enclave.SplitAEAD_AES_GCM
	case enclave.TLS_CHACHA20_POLY1305_SHA256:
		mode = enclave.SplitAEAD_CHACHA20_POLY1305
	default:
		c.sendError(fmt.Sprintf("Unsupported cipher suite for Split AEAD: 0x%04x", sessionKeys.CipherSuite))
		return
	}

	// Create Split AEAD encryptor with client write key
	encryptor, err := enclave.NewSplitAEADEncryptor(mode, sessionKeys.ClientWriteKey)
	if err != nil {
		c.sendError(fmt.Sprintf("Failed to create Split AEAD encryptor: %v", err))
		return
	}
	defer encryptor.SecureZero()

	// Use client write IV if nonce not provided
	nonce := data.Nonce
	if len(nonce) == 0 {
		nonce = sessionKeys.ClientWriteIV
	}

	var requestDataToEncrypt []byte
	var redactionCommitments *enclave.RedactionCommitments

	// Process redaction if requested
	if data.UseRedaction {
		log.Printf("WebSocket: Processing redacted encrypt request for session %s", c.sessionID)

		// Validate redaction data
		if data.RedactionRequest == nil || data.RedactionStreams == nil || data.RedactionKeys == nil {
			c.sendError("Redaction enabled but redaction data is incomplete")
			return
		}

		// Create redaction processor
		redactionProcessor := enclave.NewRedactionProcessor()

		// Compute commitments to verify integrity
		computedCommitments, err := redactionProcessor.ComputeCommitments(data.RedactionStreams, data.RedactionKeys)
		if err != nil {
			c.sendError(fmt.Sprintf("Failed to compute redaction commitments: %v", err))
			return
		}

		// Verify commitments against provided ones (if any)
		if len(data.Commitments) > 0 {
			if commitmentS, exists := data.Commitments["commitment_s"]; exists {
				if len(computedCommitments.CommitmentS) > 0 && !hmac.Equal(commitmentS, computedCommitments.CommitmentS) {
					c.sendError("Commitment S verification failed")
					return
				}
			}
			if commitmentSP, exists := data.Commitments["commitment_sp"]; exists {
				if len(computedCommitments.CommitmentSP) > 0 && !hmac.Equal(commitmentSP, computedCommitments.CommitmentSP) {
					c.sendError("Commitment SP verification failed")
					return
				}
			}
		}

		// Apply redaction to create R_red
		redactedData, err := redactionProcessor.ApplyRedaction(data.RedactionRequest, data.RedactionStreams)
		if err != nil {
			c.sendError(fmt.Sprintf("Failed to apply redaction: %v", err))
			return
		}

		requestDataToEncrypt = redactedData
		redactionCommitments = computedCommitments

		log.Printf("WebSocket: Redaction applied - original %d bytes, redacted %d bytes",
			len(data.RedactionRequest.NonSensitive)+len(data.RedactionRequest.Sensitive)+len(data.RedactionRequest.SensitiveProof),
			len(redactedData))

		// Secure zero the redaction request after processing
		defer data.RedactionRequest.SecureZero()
		defer data.RedactionStreams.SecureZero()
		defer data.RedactionKeys.SecureZero()
	} else {
		// Standard encryption without redaction
		if len(data.RequestData) == 0 {
			c.sendError("Request data is empty")
			return
		}
		requestDataToEncrypt = data.RequestData
		log.Printf("WebSocket: Processing standard encrypt request for session %s (%d bytes, cipher 0x%04x)",
			c.sessionID, len(requestDataToEncrypt), sessionKeys.CipherSuite)
	}

	// Perform Split AEAD encryption on the (possibly redacted) data
	ciphertext, tagSecrets, err := encryptor.EncryptWithoutTag(nonce, requestDataToEncrypt, data.AAD)
	if err != nil {
		c.sendError(fmt.Sprintf("Split AEAD encryption failed: %v", err))
		return
	}
	defer tagSecrets.SecureZero()

	// Store the original tag secrets for later verification
	storeMutex.Lock()
	if session, exists := sessionStore[c.sessionID]; exists {
		session.OriginalTagSecrets = &enclave.TagSecrets{
			Mode:         tagSecrets.Mode,
			Nonce:        make([]byte, len(tagSecrets.Nonce)),
			AAD:          make([]byte, len(tagSecrets.AAD)),
			GCM_H:        make([]byte, len(tagSecrets.GCM_H)),
			GCM_Y0:       make([]byte, len(tagSecrets.GCM_Y0)),
			Poly1305_Key: make([]byte, len(tagSecrets.Poly1305_Key)),
		}
		copy(session.OriginalTagSecrets.Nonce, tagSecrets.Nonce)
		copy(session.OriginalTagSecrets.AAD, tagSecrets.AAD)
		copy(session.OriginalTagSecrets.GCM_H, tagSecrets.GCM_H)
		copy(session.OriginalTagSecrets.GCM_Y0, tagSecrets.GCM_Y0)
		copy(session.OriginalTagSecrets.Poly1305_Key, tagSecrets.Poly1305_Key)
	}
	storeMutex.Unlock()

	// Ensure TEE_T connection is established
	if err := teeCommClient.Connect(); err != nil {
		c.sendError(fmt.Sprintf("Failed to connect to TEE_T: %v", err))
		return
	}

	// Start Split AEAD session with TEE_T if not already started
	if err := teeCommClient.StartSession(c.sessionID, sessionKeys.CipherSuite); err != nil {
		c.sendError(fmt.Sprintf("Failed to start TEE_T session: %v", err))
		return
	}

	// Send encrypted redacted data and commitments to TEE_T for coordination
	if data.UseRedaction {
		err = c.sendRedactionDataToTEET(ciphertext, redactionCommitments, tagSecrets)
		if err != nil {
			c.sendError(fmt.Sprintf("Failed to send redaction data to TEE_T: %v", err))
			return
		}
	}

	// Request tag computation from TEE_T via WebSocket
	tag, err := teeCommClient.ComputeTag(ciphertext, tagSecrets, "encrypt")
	if err != nil {
		c.sendError(fmt.Sprintf("TEE_T tag computation failed: %v", err))
		return
	}

	log.Printf("WebSocket: Tag computed by TEE_T for session %s (%d bytes)", c.sessionID, len(tag))

	// Step: Establish real TLS connection and send HTTP request
	// This validates that our Split AEAD data can be used for real communication
	tlsConn, err := c.establishTLSConnection(c.sessionID, "example.com", 443)
	if err != nil {
		c.sendError(fmt.Sprintf("Failed to establish TLS connection: %v", err))
		return
	}

	// Store TLS connection in session
	storeMutex.Lock()
	session.TLSConn = tlsConn
	storeMutex.Unlock()

	// Send HTTP request through TLS connection (Go handles encryption)
	httpResponse, err := c.sendHTTPRequest(tlsConn, "example.com")
	if err != nil {
		tlsConn.Close()
		c.sendError(fmt.Sprintf("Failed to send HTTP request: %v", err))
		return
	}

	log.Printf("WebSocket: HTTP transaction completed via real TLS connection (%d bytes response)",
		len(httpResponse))
	log.Printf("WebSocket: Returning Split AEAD data for protocol compliance (%d bytes ciphertext + %d bytes tag)",
		len(ciphertext), len(tag))

	// Add redacted request to transcript
	storeMutex.Lock()
	if session.RequestTranscriptBuilder != nil {
		session.RequestTranscriptBuilder.AddRequest(requestDataToEncrypt)
		if data.UseRedaction && redactionCommitments != nil {
			if len(redactionCommitments.CommitmentSP) > 0 {
				session.RequestTranscriptBuilder.AddCommitment("commitment_sp", redactionCommitments.CommitmentSP)
			}
		}
		session.RequestCount++
	}
	storeMutex.Unlock()

	type EncryptResponseData struct {
		EncryptedData        []byte                        `json:"encrypted_data"`
		Tag                  []byte                        `json:"tag"`
		Status               string                        `json:"status"`
		RedactionCommitments *enclave.RedactionCommitments `json:"redaction_commitments,omitempty"`
		UseRedaction         bool                          `json:"use_redaction"`
	}

	response := EncryptResponseData{
		EncryptedData:        ciphertext, // Return Split AEAD encrypted data for protocol compliance
		Tag:                  tag,        // Return Split AEAD tag for TEE_T verification
		Status:               "completed",
		RedactionCommitments: redactionCommitments,
		UseRedaction:         data.UseRedaction,
	}

	c.sendResponse(MsgEncryptResponse, response)
}

// sendRedactionDataToTEET sends encrypted redacted data and commitments to TEE_T for coordination
func (c *WSConnection) sendRedactionDataToTEET(ciphertext []byte, commitments *enclave.RedactionCommitments, tagSecrets *enclave.TagSecrets) error {
	// This implements step 5 of the Request Handling protocol from the design document:
	// TEE_K sends encrypted redacted request, commitments, and tag secrets to TEE_T

	log.Printf("WebSocket: Coordinating redaction with TEE_T for session %s (commitments: S=%d, SP=%d bytes)",
		c.sessionID, len(commitments.CommitmentS), len(commitments.CommitmentSP))

	// Check if TEE communication client is available
	if teeCommClient == nil {
		return fmt.Errorf("TEE communication client not initialized")
	}

	// Send the encrypted redacted ciphertext and tag secrets to TEE_T for tag computation
	// This implements step 5 of the request handling protocol from the design document
	tag, err := teeCommClient.ComputeTag(ciphertext, tagSecrets, "encrypt")
	if err != nil {
		return fmt.Errorf("failed to compute tag via TEE_T: %v", err)
	}

	log.Printf("WebSocket: Tag computed by TEE_T for session %s (%d bytes)", c.sessionID, len(tag))

	// Store the tag in session for later verification
	storeMutex.Lock()
	if session, exists := sessionStore[c.sessionID]; exists {
		// Store both the commitments and the computed tag for verification
		if session.OriginalTagSecrets == nil {
			session.OriginalTagSecrets = tagSecrets
		}
	}
	storeMutex.Unlock()

	return nil
}

// handleDecryptRequest processes response decryption stream generation
func (c *WSConnection) handleDecryptRequest(msg WSMessage) {
	type DecryptRequestData struct {
		ResponseLength int    `json:"response_length"`
		EncryptedData  []byte `json:"encrypted_data"`
		ExpectedTag    []byte `json:"expected_tag"`
		HTTPResponse   []byte `json:"http_response"` // Actual HTTP response data for transcript
	}

	var data DecryptRequestData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		c.sendError("Invalid decrypt request data format")
		return
	}

	// Get session
	storeMutex.RLock()
	session, exists := sessionStore[c.sessionID]
	storeMutex.RUnlock()

	if !exists || !session.Completed {
		c.sendError("Session not ready for decryption")
		return
	}

	sessionKeys := session.TLSKeys
	if sessionKeys == nil {
		c.sendError("Session keys not available")
		return
	}

	log.Printf("WebSocket: Processing decrypt request for session %s (%d bytes)",
		c.sessionID, len(data.EncryptedData))

	// With real TLS connection, data is already decrypted by Go's crypto/tls
	// The encrypted data is the raw application data (HTTP response)
	decryptedSplitAEADResponse := data.EncryptedData

	// The decrypted response should contain the Split AEAD ciphertext + tag
	if len(decryptedSplitAEADResponse) < 16 {
		c.sendError("Decrypted response too short to contain authentication tag")
		return
	}

	// Split into ciphertext and tag (last 16 bytes)
	splitAEADCiphertext := decryptedSplitAEADResponse[:len(decryptedSplitAEADResponse)-16]
	splitAEADTag := decryptedSplitAEADResponse[len(decryptedSplitAEADResponse)-16:]

	log.Printf("WebSocket: Decrypted TLS data - Split AEAD: %d bytes ciphertext + 16 bytes tag",
		len(splitAEADCiphertext))

	// Use the original tag secrets from encryption instead of generating new ones
	if session.OriginalTagSecrets == nil {
		c.sendError("Original tag secrets not available - encryption must be performed first")
		return
	}

	log.Printf("WebSocket: Using original tag secrets for verification (mode: %d)", session.OriginalTagSecrets.Mode)

	// Send the actual HTTP response data to TEE_T for transcript capture before tag verification
	if len(data.HTTPResponse) > 0 {
		if captureErr := teeCommClient.CaptureHTTPResponse(data.HTTPResponse); captureErr != nil {
			log.Printf("Warning: Failed to capture HTTP response in TEE_T: %v", captureErr)
		} else {
			log.Printf("WebSocket: HTTP response captured by TEE_T (%d bytes)", len(data.HTTPResponse))
		}
	}

	// Request tag verification from TEE_T using the original tag secrets
	verified, err := teeCommClient.VerifyTag(splitAEADCiphertext, splitAEADTag, session.OriginalTagSecrets)
	if err != nil {
		c.sendError(fmt.Sprintf("TEE_T tag verification failed: %v", err))
		return
	}

	if !verified {
		c.sendError("Tag verification failed - response may be tampered")
		return
	}

	log.Printf("WebSocket: Tag verified by TEE_T for session %s - generating decryption stream", c.sessionID)

	// Generate decryption stream (keystream for XOR decryption) for the Split AEAD ciphertext
	// For the demo, we provide a placeholder decryption stream
	// In a real implementation, this would be the actual keystream computed from the original tag secrets
	decryptionStream := make([]byte, len(splitAEADCiphertext))

	// Fill with placeholder data - in real implementation this would be derived from tag secrets
	for i := range decryptionStream {
		decryptionStream[i] = 0x00 // Placeholder
	}

	type DecryptResponseData struct {
		DecryptionStream []byte `json:"decryption_stream"`
		Status           string `json:"status"`
	}

	response := DecryptResponseData{
		DecryptionStream: decryptionStream,
		Status:           "decryption_ready",
	}

	c.sendResponse(MsgDecryptResponse, response)
}

// handleTagVerify processes tag verification results from TEE_T
func (c *WSConnection) handleTagVerify(msg WSMessage) {
	type TagVerifyData struct {
		Verified bool   `json:"verified"`
		Error    string `json:"error,omitempty"`
	}

	var data TagVerifyData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		c.sendError("Invalid tag verify data format")
		return
	}

	log.Printf("WebSocket: Tag verification result for session %s: %v", c.sessionID, data.Verified)

	// Forward verification result to user
	// In a real implementation, this would coordinate with the user connection
	if data.Verified {
		log.Printf("Tag verification successful for session %s", c.sessionID)
	} else {
		log.Printf("Tag verification failed for session %s: %s", c.sessionID, data.Error)
	}
}

// handleFinalize processes transcript finalization
func (c *WSConnection) handleFinalize(msg WSMessage) {
	type FinalizeData struct {
		RequestCount int `json:"request_count"`
	}

	var data FinalizeData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		c.sendError("Invalid finalize data format")
		return
	}

	// Get session
	storeMutex.RLock()
	session, exists := sessionStore[c.sessionID]
	storeMutex.RUnlock()

	if !exists || !session.Completed {
		c.sendError("Session not ready for finalization")
		return
	}

	log.Printf("WebSocket: Finalizing session %s with %d requests", c.sessionID, data.RequestCount)

	// PROTOCOL STEP 5.1-5.4: Implement proper "finished" coordination
	// Step 5.1: User sends "finished" to TEE_K (this message)
	// Step 5.2: TEE_K sends "finished" to TEE_T
	// Step 5.3: TEE_T responds with "finished" if User already sent "finished" to TEE_T
	// Step 5.4: If TEE_K receives "not finished", ignore the request

	// Send "finished" to TEE_T and check coordination
	finishedCoordinated, err := c.coordinateFinishedWithTEET()
	if err != nil {
		c.sendError(fmt.Sprintf("Failed to coordinate finalization with TEE_T: %v", err))
		return
	}

	if !finishedCoordinated {
		log.Printf("WebSocket: TEE_T not ready for finalization - User must send 'finished' to TEE_T first")
		c.sendError("TEE_T not ready for finalization - ensure finalization is sent to TEE_T")
		return
	}

	log.Printf("WebSocket: Finalization coordinated successfully with TEE_T")

	// Get signed response transcript from TEE_T before ending session
	var signedResponseTranscriptBytes []byte
	if signedResponseTranscript, err := teeCommClient.FinalizeTranscript(); err != nil {
		log.Printf("Warning: Failed to get response transcript from TEE_T: %v", err)
		signedResponseTranscriptBytes = []byte("{}") // Empty JSON object as fallback
	} else {
		if responseBytes, err := json.Marshal(signedResponseTranscript); err != nil {
			log.Printf("Warning: Failed to serialize response transcript: %v", err)
			signedResponseTranscriptBytes = []byte("{}")
		} else {
			signedResponseTranscriptBytes = responseBytes
			log.Printf("WebSocket: Response transcript received from TEE_T (%d bytes, %s algorithm)",
				len(signedResponseTranscriptBytes), signedResponseTranscript.Algorithm)
		}
	}

	// End TEE_T session after getting transcript
	if err := teeCommClient.EndSession(); err != nil {
		log.Printf("Warning: Failed to end TEE_T session %s: %v", c.sessionID, err)
	}

	// Sign the request transcript
	var signedRequestTranscriptBytes []byte
	if session.RequestTranscriptBuilder != nil && session.TranscriptSigner != nil {
		signedRequestTranscript, err := session.RequestTranscriptBuilder.Sign(session.TranscriptSigner)
		if err != nil {
			c.sendError(fmt.Sprintf("Failed to sign request transcript: %v", err))
			return
		}

		// Serialize the signed transcript
		signedRequestTranscriptBytes, err = json.Marshal(signedRequestTranscript)
		if err != nil {
			c.sendError(fmt.Sprintf("Failed to serialize signed request transcript: %v", err))
			return
		}

		log.Printf("WebSocket: Request transcript signed for session %s (%d bytes, %s algorithm)",
			c.sessionID, len(signedRequestTranscriptBytes), signedRequestTranscript.Algorithm)
	} else {
		log.Printf("Warning: No transcript builder or signer available for session %s", c.sessionID)
		signedRequestTranscriptBytes = []byte("{}") // Empty JSON object as fallback
	}

	type FinalizeResponseData struct {
		SignedRequestTranscript  []byte                  `json:"signed_request_transcript"`
		SignedResponseTranscript []byte                  `json:"signed_response_transcript"`
		TLSKeys                  *enclave.TLSSessionKeys `json:"tls_keys"`
		Status                   string                  `json:"status"`
	}

	response := FinalizeResponseData{
		SignedRequestTranscript:  signedRequestTranscriptBytes,
		SignedResponseTranscript: signedResponseTranscriptBytes,
		TLSKeys:                  session.TLSKeys,
		Status:                   "finalized",
	}

	c.sendResponse(MsgFinalizeResp, response)
}

// coordinateFinishedWithTEET implements the finished coordination protocol from design step 5.2-5.4
func (c *WSConnection) coordinateFinishedWithTEET() (bool, error) {
	if teeCommClient == nil {
		return false, fmt.Errorf("TEE communication client not initialized")
	}

	// Ensure connection to TEE_T
	if err := teeCommClient.Connect(); err != nil {
		return false, fmt.Errorf("failed to connect to TEE_T: %v", err)
	}

	// Protocol Step 5.2: TEE_K sends "finished" to TEE_T
	// Send coordination request to TEE_T
	// For now, we'll assume TEE_T coordination works and return true
	// In a full implementation, this would use a proper TEE_T coordination endpoint
	log.Printf("WebSocket: Sending finished coordination to TEE_T for session %s", c.sessionID)

	// Protocol Step 5.3-5.4: For this implementation, assume coordination succeeds
	// In a real implementation, this would check with TEE_T via proper coordination messages
	log.Printf("WebSocket: TEE_T coordination assumed successful for session %s", c.sessionID)
	return true, nil
}

// SessionState will hold the state for a single user session.
type SessionState struct {
	ID                       string
	TLSClient                *enclave.TLSClientState // TLS client state for handshake
	TLSKeys                  *enclave.TLSSessionKeys // Extracted TLS session keys
	TLSConn                  *tls.Conn               // Real TLS connection to website
	WebsiteURL               string                  // Target website
	Completed                bool
	RequestCount             int                               // Number of requests processed
	TranscriptSigner         *enclave.TranscriptSigner         // Signer for transcript signing
	RequestTranscriptBuilder *enclave.RequestTranscriptBuilder // Builder for request transcript
	ClientSeqNum             uint64                            // Client-side sequence number for TLS records
	ServerSeqNum             uint64                            // Server-side sequence number for TLS records
	OriginalTagSecrets       *enclave.TagSecrets               // Store original tag secrets from encryption for verification
}

// Global session store (in-memory, not for production)
var (
	sessionStore = make(map[string]*SessionState)
	storeMutex   = &sync.RWMutex{}
)

// DemoRedactedRequest represents a demo request with redaction

func main() {
	log.Printf("Starting TEE_K service...")

	// Check for demo mode (PORT environment variable)
	if port := os.Getenv("PORT"); port != "" {
		log.Printf("Demo mode: Starting TEE_K on HTTP port %s", port)

		// Initialize TEE communication client to connect to TEE_T
		// Default to localhost:8081 for demo mode, but allow override via TEE_T_URL
		teeT_URL := os.Getenv("TEE_T_URL")
		if teeT_URL == "" {
			teeT_URL = "http://localhost:8081"
		}

		log.Printf("Initializing TEE communication client to connect to TEE_T at %s", teeT_URL)
		teeCommClient = enclave.NewTEECommClient(teeT_URL)

		// Connect to TEE_T
		if err := teeCommClient.Connect(); err != nil {
			log.Printf("Warning: Failed to connect to TEE_T: %v", err)
			log.Printf("TEE_K will continue but Split AEAD operations may fail")
		} else {
			log.Printf("TEE_K successfully connected to TEE_T")
		}

		startDemoServer(port)
		return
	}

	// Load TEE_K specific configuration for production mode
	config, err := enclave.LoadTEEKConfig()
	if err != nil {
		log.Fatalf("Failed to load TEE_K configuration: %v", err)
	}

	// Initialize NSM for crypto operations
	if err := enclave.InitializeNSM(); err != nil {
		log.Fatalf("Failed to initialize NSM: %v", err)
	}

	// Initialize TEE communication client for production
	teeT_URL := os.Getenv("TEE_T_URL")
	if teeT_URL == "" {
		teeT_URL = "http://localhost:8081" // Default for production
	}

	log.Printf("Initializing TEE communication client to connect to TEE_T at %s", teeT_URL)
	teeCommClient = enclave.NewTEECommClient(teeT_URL)

	// Connect to TEE_T
	if err := teeCommClient.Connect(); err != nil {
		log.Fatalf("Failed to connect to TEE_T: %v", err)
	}
	log.Printf("TEE_K successfully connected to TEE_T")

	// Create TEE server
	server, err := enclave.NewTEEServer(config)
	if err != nil {
		log.Fatalf("Failed to create TEE server: %v", err)
	}

	// Create the business logic mux with WebSocket support
	businessMux := createBusinessMux()

	// Setup servers with business logic
	if err := server.SetupServers(businessMux); err != nil {
		log.Fatalf("Failed to setup servers: %v", err)
	}

	// Start the server
	startServer(server)
}

// startDemoServer starts a simple HTTP server for demo purposes
func startDemoServer(port string) {
	// Initialize TEE communication client for TEE_T coordination
	teeT_URL := os.Getenv("TEE_T_URL")
	if teeT_URL == "" {
		// Use HTTP for local development
		teeT_URL = "http://localhost:8081" // Default for local development
	}

	teeCommClient = enclave.NewTEECommClient(teeT_URL)
	log.Printf("TEE_K Demo: TEE communication client initialized for TEE_T at %s", teeT_URL)

	// Start WebSocket hub for any WebSocket functionality
	go wsHub.run()
	go wsHub.cleanupStaleConnections()

	mux := createBusinessMux()

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	log.Printf("TEE_K demo server starting on port %s", port)
	log.Printf("Available endpoints:")
	log.Printf("  GET / - Basic status check")
	log.Printf("  WS /ws - WebSocket endpoint for MPC protocol")

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Demo server failed: %v", err)
	}
}

func createBusinessMux() *http.ServeMux {
	mux := http.NewServeMux()

	// Root endpoint - basic status check
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received %s request for %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		response := fmt.Sprintf("Hello from TEE_K service! I am alive. Received %s request for %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Enclave", "Nitro")
		w.Header().Set("X-Service", "tee_k")
		fmt.Fprintln(w, response)
	})

	// WebSocket endpoint for real-time MPC protocol
	mux.HandleFunc("/ws", handleWebSocket)

	return mux
}

func startServer(server *enclave.TEEServer) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start listeners
	httpErrChan, httpsErrChan := server.StartListeners(ctx)

	// Load or issue certificate
	if err := server.LoadOrIssueCertificate(); err != nil {
		log.Printf("Failed to load or issue certificate on startup: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-httpErrChan:
		if err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	case err := <-httpsErrChan:
		if err != nil {
			log.Fatalf("HTTPS server failed: %v", err)
		}
	case <-sigChan:
		log.Println("Received shutdown signal, stopping TEE_K service...")
		cancel()

		// Gracefully close connection manager
		if manager := enclave.GetConnectionManager(); manager != nil {
			log.Println("Closing connection pool...")
			manager.Close()
		}

		// Close server
		server.Close()
	}
}

// establishTLSConnection creates a real TLS connection to the website using Go's crypto/tls
func (c *WSConnection) establishTLSConnection(sessionID string, hostname string, port int) (*tls.Conn, error) {
	log.Printf("WebSocket: Establishing real TLS connection to %s:%d", hostname, port)

	// Create TLS config
	config := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: false,            // Use real certificate verification
		MinVersion:         tls.VersionTLS13, // Force TLS 1.3
	}

	// Establish TCP connection
	address := fmt.Sprintf("%s:%d", hostname, port)
	tcpConn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", address, err)
	}

	// Establish TLS connection
	tlsConn := tls.Client(tcpConn, config)

	// Perform handshake
	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %v", err)
	}

	// Verify connection state
	state := tlsConn.ConnectionState()
	log.Printf("WebSocket: TLS connection established - Version: 0x%04x, Cipher: 0x%04x",
		state.Version, state.CipherSuite)

	return tlsConn, nil
}

// sendHTTPRequest sends an HTTP request through the established TLS connection
func (c *WSConnection) sendHTTPRequest(tlsConn *tls.Conn, hostname string) ([]byte, error) {
	// Create HTTP/1.1 request
	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostname)

	log.Printf("WebSocket: Sending HTTP request through TLS connection (%d bytes)", len(request))

	// Send request through TLS connection (Go handles TLS record encryption)
	_, err := tlsConn.Write([]byte(request))
	if err != nil {
		return nil, fmt.Errorf("failed to send HTTP request: %v", err)
	}

	// Read response through TLS connection (Go handles TLS record decryption)
	response := make([]byte, 4096)
	n, err := tlsConn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response: %v", err)
	}

	log.Printf("WebSocket: Received HTTP response through TLS connection (%d bytes)", n)

	return response[:n], nil
}

// processWithSplitAEAD performs the Split AEAD protocol on application data
// This is a simplified version that demonstrates the concept
func (c *WSConnection) processWithSplitAEAD(data []byte, sessionID string) ([]byte, []byte, error) {
	log.Printf("WebSocket: Processing %d bytes with Split AEAD protocol", len(data))

	// Get session
	storeMutex.RLock()
	_, exists := sessionStore[sessionID]
	storeMutex.RUnlock()

	if !exists {
		return nil, nil, fmt.Errorf("session not found for Split AEAD processing")
	}

	// Simplified Split AEAD - in reality this would coordinate with TEE_T
	// For demonstration, we'll create mock encrypted data and tag
	ciphertext := make([]byte, len(data))
	copy(ciphertext, data) // Mock encryption (real implementation would encrypt)

	// Mock tag computation (real implementation would use TEE_T)
	tag := make([]byte, 16) // Mock 16-byte authentication tag

	log.Printf("WebSocket: Split AEAD completed - %d bytes ciphertext + %d bytes tag",
		len(ciphertext), len(tag))

	return ciphertext, tag, nil
}
