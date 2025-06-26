package main

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"io"
	"log"
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

	// Complete TLS handshake and extract session keys
	sessionKeys, err := session.TLSClient.ExtractSessionKeys()
	if err != nil {
		c.sendError(fmt.Sprintf("Failed to extract session keys: %v", err))
		return
	}

	// Update session with keys
	storeMutex.Lock()
	session.TLSKeys = sessionKeys
	session.Completed = true
	storeMutex.Unlock()

	log.Printf("WebSocket: TLS handshake completed for session %s", c.sessionID)

	// Send handshake complete response
	type HandshakeCompleteData struct {
		Status      string `json:"status"`
		CipherSuite uint16 `json:"cipher_suite"`
		KeysReady   bool   `json:"keys_ready"`
	}

	response := HandshakeCompleteData{
		Status:      "handshake_complete",
		CipherSuite: sessionKeys.CipherSuite,
		KeysReady:   true,
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
		EncryptedData:        ciphertext,
		Tag:                  tag,
		Status:               "encrypted_with_tag",
		RedactionCommitments: redactionCommitments,
		UseRedaction:         data.UseRedaction,
	}

	c.sendResponse(MsgEncryptResponse, response)
}

// sendRedactionDataToTEET sends encrypted redacted data and commitments to TEE_T for coordination
func (c *WSConnection) sendRedactionDataToTEET(ciphertext []byte, commitments *enclave.RedactionCommitments, tagSecrets *enclave.TagSecrets) error {
	// This is a coordination message to inform TEE_T about the redaction commitments
	// TEE_T will need this information when processing streams from the User

	type RedactionCoordinationData struct {
		SessionID   string                        `json:"session_id"`
		Ciphertext  []byte                        `json:"ciphertext"`
		Commitments *enclave.RedactionCommitments `json:"commitments"`
		TagSecrets  *enclave.TagSecrets           `json:"tag_secrets"`
	}

	// Send coordination message to TEE_T
	// This would typically be done via the TEE communication protocol
	// For now, we'll log the coordination and assume TEE_T will receive the streams directly from User

	log.Printf("WebSocket: Coordinating redaction with TEE_T for session %s (commitments: S=%d, SP=%d bytes)",
		c.sessionID, len(commitments.CommitmentS), len(commitments.CommitmentSP))

	// In a full implementation, this would send the coordination data to TEE_T
	// TEE_T would store this for when it receives streams from the User
	// coordData := RedactionCoordinationData{
	//     SessionID:   c.sessionID,
	//     Ciphertext:  ciphertext,
	//     Commitments: commitments,
	//     TagSecrets:  tagSecrets,
	// }

	return nil
}

// handleDecryptRequest processes response decryption stream generation
func (c *WSConnection) handleDecryptRequest(msg WSMessage) {
	type DecryptRequestData struct {
		ResponseLength int    `json:"response_length"`
		EncryptedData  []byte `json:"encrypted_data"`
		ExpectedTag    []byte `json:"expected_tag"`
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
		c.sessionID, data.ResponseLength)

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

	// Create Split AEAD encryptor with server write key for decryption
	encryptor, err := enclave.NewSplitAEADEncryptor(mode, sessionKeys.ServerWriteKey)
	if err != nil {
		c.sendError(fmt.Sprintf("Failed to create Split AEAD encryptor: %v", err))
		return
	}
	defer encryptor.SecureZero()

	// Generate tag secrets for verification
	nonce := sessionKeys.ServerWriteIV
	_, tagSecrets, err := encryptor.EncryptWithoutTag(nonce, make([]byte, len(data.EncryptedData)), nil)
	if err != nil {
		c.sendError(fmt.Sprintf("Failed to generate tag secrets: %v", err))
		return
	}
	defer tagSecrets.SecureZero()

	// Request tag verification from TEE_T
	verified, err := teeCommClient.VerifyTag(data.EncryptedData, data.ExpectedTag, tagSecrets)
	if err != nil {
		c.sendError(fmt.Sprintf("TEE_T tag verification failed: %v", err))
		return
	}

	if !verified {
		c.sendError("Tag verification failed - response may be tampered")
		return
	}

	log.Printf("WebSocket: Tag verified by TEE_T for session %s - generating decryption stream", c.sessionID)

	// Generate decryption stream (keystream for XOR decryption)
	decryptionStream := make([]byte, data.ResponseLength)
	// In real implementation, this would generate the actual keystream
	// For now, using placeholder zeros

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

// SessionState will hold the state for a single user session.
type SessionState struct {
	ID                       string
	TLSClient                *enclave.TLSClientState // TLS client state for handshake
	TLSKeys                  *enclave.TLSSessionKeys // Extracted TLS session keys
	WebsiteURL               string                  // Target website
	Completed                bool
	RequestCount             int                               // Number of requests processed
	TranscriptSigner         *enclave.TranscriptSigner         // Signer for transcript signing
	RequestTranscriptBuilder *enclave.RequestTranscriptBuilder // Builder for request transcript
}

// Global session store (in-memory, not for production)
var (
	sessionStore = make(map[string]*SessionState)
	storeMutex   = &sync.RWMutex{}
)

// DemoRedactedRequest represents a demo request with redaction
type DemoRedactedRequest struct {
	SessionID         string                        `json:"session_id"`
	TargetURL         string                        `json:"target_url"`
	Method            string                        `json:"method"`
	UseRedaction      bool                          `json:"use_redaction"`
	RedactedData      []byte                        `json:"redacted_data"`
	OriginalRequest   *enclave.RedactionRequest     `json:"original_request"`
	RedactionStreams  *enclave.RedactionStreams     `json:"redaction_streams"`
	RedactionKeys     *enclave.RedactionKeys        `json:"redaction_keys"`
	Commitments       *enclave.RedactionCommitments `json:"commitments"`
	ResponseRedaction ResponseRedactionConfig       `json:"response_redaction"`
}

// ResponseRedactionConfig configures how to redact the response
type ResponseRedactionConfig struct {
	Enabled     bool   `json:"enabled"`
	ExtractText string `json:"extract_text"`
}

// DemoRedactedResponse represents the response from demo redacted request
type DemoRedactedResponse struct {
	Status               string `json:"status"`
	RedactedContent      string `json:"redacted_content"`
	OriginalResponseSize int    `json:"original_response_size"`
	RedactedResponseSize int    `json:"redacted_response_size"`
	AuthHeaderRedacted   bool   `json:"auth_header_redacted"`
	Error                string `json:"error,omitempty"`
}

// handleDemoRedactedRequest processes the end-to-end demo request
func handleDemoRedactedRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("Received demo redacted request from %s", r.RemoteAddr)

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed to read request body: %v", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Parse request
	var req DemoRedactedRequest
	if err := json.Unmarshal(body, &req); err != nil {
		log.Printf("Failed to parse demo request: %v", err)
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Process the demo request
	response := processDemoRedactedRequest(req)

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Service", "tee_k")

	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Printf("Failed to marshal response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Write(responseJSON)
}

func processDemoRedactedRequest(req DemoRedactedRequest) DemoRedactedResponse {
	log.Printf("Processing demo redacted request for session %s", req.SessionID)

	// Step 1: Verify redaction commitments
	processor := enclave.NewRedactionProcessor()
	if err := processor.VerifyCommitments(req.RedactionStreams, req.RedactionKeys, req.Commitments); err != nil {
		log.Printf("Commitment verification failed: %v", err)
		return DemoRedactedResponse{
			Status: "error",
			Error:  fmt.Sprintf("Commitment verification failed: %v", err),
		}
	}

	// Step 2: Recover original request from redacted data
	recoveredRequest, err := processor.UnapplyRedaction(req.RedactedData, req.RedactionStreams, req.OriginalRequest)
	if err != nil {
		log.Printf("Failed to recover original request: %v", err)
		return DemoRedactedResponse{
			Status: "error",
			Error:  fmt.Sprintf("Failed to recover original request: %v", err),
		}
	}

	// Step 3: Reconstruct the full HTTP request
	httpRequest, err := reconstructHTTPRequest(recoveredRequest)
	if err != nil {
		log.Printf("Failed to reconstruct HTTP request: %v", err)
		return DemoRedactedResponse{
			Status: "error",
			Error:  fmt.Sprintf("Failed to reconstruct HTTP request: %v", err),
		}
	}

	// Step 4: Make the actual HTTP request to the target
	log.Printf("Making HTTP request to %s", req.TargetURL)
	httpResponse, err := makeHTTPRequest(httpRequest, req.TargetURL)
	if err != nil {
		log.Printf("Failed to make HTTP request: %v", err)
		return DemoRedactedResponse{
			Status: "error",
			Error:  fmt.Sprintf("Failed to make HTTP request: %v", err),
		}
	}

	// Step 5: Apply response redaction if enabled
	var redactedContent string
	originalSize := len(httpResponse.Body)

	if req.ResponseRedaction.Enabled && req.ResponseRedaction.ExtractText != "" {
		if strings.Contains(httpResponse.Body, req.ResponseRedaction.ExtractText) {
			redactedContent = req.ResponseRedaction.ExtractText
			log.Printf("Successfully extracted target text from response")
		} else {
			redactedContent = ""
			log.Printf("Target text not found in response")
		}
	} else {
		redactedContent = httpResponse.Body
	}

	// Step 6: Cleanup sensitive data
	recoveredRequest.SecureZero()

	return DemoRedactedResponse{
		Status:               "success",
		RedactedContent:      redactedContent,
		OriginalResponseSize: originalSize,
		RedactedResponseSize: len(redactedContent),
		AuthHeaderRedacted:   true, // Auth header was successfully redacted from request
	}
}

// HTTPRequestData represents the HTTP request structure for demo
type HTTPRequestData struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// HTTPResponseData represents the HTTP response structure for demo
type HTTPResponseData struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

func reconstructHTTPRequest(redactionRequest *enclave.RedactionRequest) (*HTTPRequestData, error) {
	// Combine non-sensitive and sensitive parts
	var combinedRequest HTTPRequestData

	// Parse non-sensitive part
	if err := json.Unmarshal(redactionRequest.NonSensitive, &combinedRequest); err != nil {
		return nil, fmt.Errorf("failed to parse non-sensitive data: %v", err)
	}

	// Parse and merge sensitive part (Auth header)
	if len(redactionRequest.Sensitive) > 0 {
		var sensitiveHeaders map[string]string
		if err := json.Unmarshal(redactionRequest.Sensitive, &sensitiveHeaders); err != nil {
			return nil, fmt.Errorf("failed to parse sensitive data: %v", err)
		}

		// Merge sensitive headers back into the request
		if combinedRequest.Headers == nil {
			combinedRequest.Headers = make(map[string]string)
		}
		for k, v := range sensitiveHeaders {
			combinedRequest.Headers[k] = v
		}
	}

	return &combinedRequest, nil
}

func makeHTTPRequest(httpReq *HTTPRequestData, targetURL string) (*HTTPResponseData, error) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Create request
	req, err := http.NewRequest(httpReq.Method, targetURL, strings.NewReader(httpReq.Body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Add headers
	for k, v := range httpReq.Headers {
		req.Header.Set(k, v)
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Convert response headers
	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0] // Take first value
		}
	}

	return &HTTPResponseData{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       string(bodyBytes),
	}, nil
}

func main() {
	log.Printf("Starting TEE_K service...")

	// Check for demo mode (PORT environment variable)
	if port := os.Getenv("PORT"); port != "" {
		log.Printf("Demo mode: Starting TEE_K on HTTP port %s", port)
		startDemoServer(port)
		return
	}

	// Load TEE_K specific configuration
	config, err := enclave.LoadTEEKConfig()
	if err != nil {
		log.Fatalf("Failed to load TEE_K configuration: %v", err)
	}

	// Initialize NSM for crypto operations
	if err := enclave.InitializeNSM(); err != nil {
		log.Fatalf("Failed to initialize NSM: %v", err)
	}

	// Initialize TEE communication client for TEE_T coordination
	teeT_URL := os.Getenv("TEE_T_URL")
	if teeT_URL == "" {
		// Use HTTP for local development, HTTPS for production (set TEE_T_URL env var)
		teeT_URL = "http://localhost:8081" // Default for local development
	}

	teeCommClient = enclave.NewTEECommClient(teeT_URL)
	log.Printf("TEE_K: TEE communication client initialized for TEE_T at %s", teeT_URL)

	// Start WebSocket hub
	go wsHub.run()
	go wsHub.cleanupStaleConnections()

	// Create TEE server
	server, err := enclave.NewTEEServer(config)
	if err != nil {
		log.Fatalf("Failed to create TEE server: %v", err)
	}

	// Create the business logic mux
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
	log.Printf("  POST /demo-redacted-request - End-to-end redaction demo")

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

	// Demo endpoint for end-to-end redaction demonstration
	mux.HandleFunc("/demo-redacted-request", handleDemoRedactedRequest)

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
