package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
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
			}
			h.mutex.Unlock()
			log.Printf("WebSocket connection unregistered: %s", conn.sessionID)

		case message := <-h.broadcast:
			h.mutex.RLock()
			for _, conn := range h.connections {
				select {
				case conn.send <- message:
				default:
					close(conn.send)
					delete(h.connections, conn.sessionID)
				}
			}
			h.mutex.RUnlock()
		}
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
		send:       make(chan WSMessage, 256),
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
				log.Printf("WebSocket write error: %v", err)
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
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
	default:
		log.Printf("Failed to send error message to %s", c.sessionID)
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
	default:
		log.Printf("Failed to send response message to %s", c.sessionID)
	}
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

	newState := &SessionState{
		ID:         sessionID,
		TLSClient:  tlsClient,
		WebsiteURL: fmt.Sprintf("%s:%d", req.Hostname, req.Port),
		Completed:  false,
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

// handleEncryptRequest processes request encryption for split AEAD
func (c *WSConnection) handleEncryptRequest(msg WSMessage) {
	type EncryptRequestData struct {
		RequestData []byte            `json:"request_data"`
		Commitments map[string][]byte `json:"commitments"`
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

	// TODO: Implement split AEAD encryption
	// For now, send placeholder response
	log.Printf("WebSocket: Processing encrypt request for session %s (%d bytes)",
		c.sessionID, len(data.RequestData))

	type EncryptResponseData struct {
		EncryptedData []byte `json:"encrypted_data"`
		TagSecrets    []byte `json:"tag_secrets"`
		Status        string `json:"status"`
	}

	// Placeholder - in real implementation, this would do split AEAD
	response := EncryptResponseData{
		EncryptedData: data.RequestData, // Placeholder
		TagSecrets:    []byte("tag_secrets_placeholder"),
		Status:        "encryption_ready",
	}

	c.sendResponse(MsgEncryptResponse, response)
}

// handleDecryptRequest processes response decryption stream generation
func (c *WSConnection) handleDecryptRequest(msg WSMessage) {
	type DecryptRequestData struct {
		ResponseLength int    `json:"response_length"`
		EncryptedData  []byte `json:"encrypted_data"`
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

	// TODO: Implement decryption stream generation
	log.Printf("WebSocket: Processing decrypt request for session %s (%d bytes)",
		c.sessionID, data.ResponseLength)

	type DecryptResponseData struct {
		DecryptionStream []byte `json:"decryption_stream"`
		Status           string `json:"status"`
	}

	// Placeholder - in real implementation, this would generate decryption stream
	response := DecryptResponseData{
		DecryptionStream: make([]byte, data.ResponseLength), // Placeholder zeros
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

	// TODO: Implement transcript signing
	log.Printf("WebSocket: Finalizing session %s with %d requests", c.sessionID, data.RequestCount)

	type FinalizeResponseData struct {
		SignedTranscript []byte                  `json:"signed_transcript"`
		TLSKeys          *enclave.TLSSessionKeys `json:"tls_keys"`
		Status           string                  `json:"status"`
	}

	// Placeholder - in real implementation, this would sign the transcript
	response := FinalizeResponseData{
		SignedTranscript: []byte("signed_transcript_placeholder"),
		TLSKeys:          session.TLSKeys,
		Status:           "finalized",
	}

	c.sendResponse(MsgFinalizeResp, response)
}

// SessionState will hold the state for a single user session.
type SessionState struct {
	ID           string
	TLSClient    *enclave.TLSClientState // TLS client state for handshake
	TLSKeys      *enclave.TLSSessionKeys // Extracted TLS session keys
	WebsiteURL   string                  // Target website
	Completed    bool
	RequestCount int // Number of requests processed
}

// Global session store (in-memory, not for production)
var (
	sessionStore = make(map[string]*SessionState)
	storeMutex   = &sync.RWMutex{}
)

func main() {
	// Load environment variables first
	enclave.LoadEnvVariables()

	// Initialize NSM for crypto operations
	if err := enclave.InitializeNSM(); err != nil {
		log.Fatalf("Failed to initialize NSM: %v", err)
	}

	// Start WebSocket hub
	go wsHub.run()

	// Create server configuration with the TEE_K business mux
	config := enclave.CreateServerConfig(createBusinessMux())

	// Start the server
	startServer(config)
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

	// Protocol endpoints for TEE_K (HTTP fallback)
	mux.HandleFunc("/session/init", handleSessionInit)
	mux.HandleFunc("/encrypt", handleEncrypt)
	mux.HandleFunc("/decrypt-stream", handleDecryptStream)
	mux.HandleFunc("/finalize", handleFinalize)

	return mux
}

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

// handleSessionInit initializes a new TLS session and generates Client Hello
func handleSessionInit(w http.ResponseWriter, r *http.Request) {
	var req SessionInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Hostname == "" {
		http.Error(w, "Hostname is required", http.StatusBadRequest)
		return
	}
	if req.Port == 0 {
		req.Port = 443 // Default HTTPS port
	}
	if req.SNI == "" {
		req.SNI = req.Hostname // Default SNI to hostname
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
		log.Printf("Failed to create TLS client state: %v", err)
		http.Error(w, "Failed to initialize TLS client", http.StatusInternalServerError)
		return
	}

	// Generate Client Hello
	clientHello, err := tlsClient.GenerateClientHello()
	if err != nil {
		log.Printf("Failed to generate Client Hello: %v", err)
		http.Error(w, "Failed to generate Client Hello", http.StatusInternalServerError)
		return
	}

	// Create session
	sessionID := fmt.Sprintf("session-%d-%d", len(sessionStore)+1, time.Now().Unix())
	newState := &SessionState{
		ID:         sessionID,
		TLSClient:  tlsClient,
		WebsiteURL: fmt.Sprintf("%s:%d", req.Hostname, req.Port),
		Completed:  false,
	}

	storeMutex.Lock()
	sessionStore[sessionID] = newState
	storeMutex.Unlock()

	log.Printf("Initialized new TLS session: %s for %s", sessionID, req.Hostname)

	// Return Client Hello to user
	response := SessionInitResponse{
		SessionID:   sessionID,
		ClientHello: clientHello,
		Status:      "client_hello_ready",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleEncrypt is a placeholder for the request encryption logic.
func handleEncrypt(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement the split AEAD encryption.
	// 1. Receive R_red, comm_s, comm_sp from the User.
	// 2. Perform request verifications.
	// 3. Encrypt R_red using the derived TLS key to get R_red_Enc.
	// 4. Compute Tag Secrets for TEE_T.
	// 5. Send R_red_Enc to User and TEE_T.
	// 6. Send Tag Secrets and commitments to TEE_T.
	log.Println("Placeholder: /encrypt endpoint called")
	http.Error(w, "Not Implemented: Request encryption", http.StatusNotImplemented)
}

// handleDecryptStream is a placeholder for generating the decryption stream for the response.
func handleDecryptStream(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement response decryption stream generation.
	// 1. Receive the length of the response from the User.
	// 2. Wait for a "success" message from TEE_T (indicating tag verification passed).
	// 3. Compute the decryption keystream (Str_Dec).
	// 4. Send Str_Dec to the User.
	log.Println("Placeholder: /decrypt-stream endpoint called")
	http.Error(w, "Not Implemented: Decryption stream generation", http.StatusNotImplemented)
}

// handleFinalize is a placeholder for signing the transcript.
func handleFinalize(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement transcript finalization.
	// 1. Receive "final" message from the User.
	// 2. Concatenate redacted requests and commitments.
	// 3. Sign the concatenated transcript.
	// 4. Send the signed transcript and the *real* TLS keys to the User.
	log.Println("Placeholder: /finalize endpoint called")
	http.Error(w, "Not Implemented: Transcript finalization", http.StatusNotImplemented)
}

func startServer(serverConfig *enclave.ServerConfig) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpErrChan, httpsErrChan := enclave.StartListeners(ctx, serverConfig.HTTPServer, serverConfig.HTTPSServer)

	log.Printf("Attempting to load or issue certificate for %s", enclave.EnclaveDomain)
	_, err := serverConfig.Manager.GetCertificate(&tls.ClientHelloInfo{ServerName: enclave.EnclaveDomain})
	if err != nil {
		log.Printf("Failed to load or issue certificate on startup: %v", err)
	} else {
		log.Printf("Successfully loaded or issued certificate for %s", enclave.EnclaveDomain)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err = <-httpErrChan:
		if err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	case err = <-httpsErrChan:
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

		_ = serverConfig.HTTPServer.Close()
		_ = serverConfig.HTTPSServer.Close()
	}
}
