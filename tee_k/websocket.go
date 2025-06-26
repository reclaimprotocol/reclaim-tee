package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"tee/enclave"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocket upgrader with proper configuration
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// In production, implement proper origin checking
		return true
	},
}

// Message types for the MPC protocol
const (
	// Client to TEE_K messages
	MsgTypeSessionInit = "session_init"
	MsgTypeEncryptReq  = "encrypt_request"
	MsgTypeDecryptReq  = "decrypt_request"
	MsgTypeFinalizeReq = "finalize_request"
	MsgTypeClose       = "close"

	// TEE_K to Client responses
	MsgTypeSessionInitResp = "session_init_response"
	MsgTypeEncryptResp     = "encrypt_response"
	MsgTypeDecryptResp     = "decrypt_response"
	MsgTypeFinalizeResp    = "finalize_response"
	MsgTypeError           = "error"
	MsgTypeStatus          = "status"
)

// WebSocket message structure
type WSMessage struct {
	Type      string          `json:"type"`
	SessionID string          `json:"session_id,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	Error     string          `json:"error,omitempty"`
	Timestamp int64           `json:"timestamp"`
}

// Protocol message payloads
type SessionInitData struct {
	Hostname      string   `json:"hostname"`
	Port          int      `json:"port"`
	SNI           string   `json:"sni"`
	ALPNProtocols []string `json:"alpn_protocols"`
}

type WSSessionInitResponse struct {
	SessionID   string `json:"session_id"`
	ClientHello []byte `json:"client_hello"`
	Status      string `json:"status"`
}

type EncryptRequestData struct {
	RedactedRequest []byte `json:"redacted_request"`
	CommitmentS     []byte `json:"commitment_s"`
	CommitmentSP    []byte `json:"commitment_sp"`
	Nonce           []byte `json:"nonce"`
}

type EncryptResponseData struct {
	EncryptedRequest []byte `json:"encrypted_request"`
	TagSecrets       []byte `json:"tag_secrets"`
	Status           string `json:"status"`
}

type DecryptRequestData struct {
	ResponseLength int    `json:"response_length"`
	TEETSuccess    bool   `json:"tee_t_success"`
	TEETMessage    string `json:"tee_t_message,omitempty"`
}

type DecryptResponseData struct {
	DecryptionStream []byte `json:"decryption_stream"`
	Status           string `json:"status"`
}

type FinalizeRequestData struct {
	FinalMessage string `json:"final_message"`
}

type FinalizeResponseData struct {
	SignedTranscript []byte `json:"signed_transcript"`
	TLSKeys          []byte `json:"tls_keys"`
	Status           string `json:"status"`
}

// WebSocket connection wrapper with session management
type WSConnection struct {
	conn      *websocket.Conn
	sessionID string
	mutex     sync.Mutex
	closed    bool
}

// Active WebSocket connections
var (
	wsConnections = make(map[string]*WSConnection)
	wsConnMutex   = &sync.RWMutex{}
)

// handleWebSocket upgrades HTTP to WebSocket and manages the connection
func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("New WebSocket connection from %s", r.RemoteAddr)

	// Create connection wrapper
	wsConn := &WSConnection{
		conn:   conn,
		closed: false,
	}

	// Handle messages in a loop
	for {
		var msg WSMessage
		err := conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		// Process the message
		if err := handleWSMessage(wsConn, &msg); err != nil {
			log.Printf("Error handling WebSocket message: %v", err)
			sendError(wsConn, msg.SessionID, fmt.Sprintf("Message processing failed: %v", err))
		}
	}

	// Clean up connection
	if wsConn.sessionID != "" {
		wsConnMutex.Lock()
		delete(wsConnections, wsConn.sessionID)
		wsConnMutex.Unlock()
		log.Printf("Cleaned up WebSocket connection for session %s", wsConn.sessionID)
	}
}

// handleWSMessage processes incoming WebSocket messages
func handleWSMessage(wsConn *WSConnection, msg *WSMessage) error {
	switch msg.Type {
	case MsgTypeSessionInit:
		return handleWSSessionInit(wsConn, msg)
	case MsgTypeEncryptReq:
		return handleWSEncryptRequest(wsConn, msg)
	case MsgTypeDecryptReq:
		return handleWSDecryptRequest(wsConn, msg)
	case MsgTypeFinalizeReq:
		return handleWSFinalizeRequest(wsConn, msg)
	case MsgTypeClose:
		return handleWSClose(wsConn, msg)
	default:
		return fmt.Errorf("unknown message type: %s", msg.Type)
	}
}

// handleWSSessionInit initializes a new TLS session
func handleWSSessionInit(wsConn *WSConnection, msg *WSMessage) error {
	var data SessionInitData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		return fmt.Errorf("invalid session init data: %v", err)
	}

	// Validate required fields
	if data.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}
	if data.Port == 0 {
		data.Port = 443 // Default HTTPS port
	}
	if data.SNI == "" {
		data.SNI = data.Hostname // Default SNI to hostname
	}

	// Create TLS client configuration
	tlsConfig := &enclave.TLSClientConfig{
		ServerName:    data.SNI,
		ALPNProtocols: data.ALPNProtocols,
		MaxVersion:    enclave.VersionTLS13,
	}

	// Initialize TLS client state
	tlsClient, err := enclave.NewTLSClientState(tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to create TLS client state: %v", err)
	}

	// Generate Client Hello
	clientHello, err := tlsClient.GenerateClientHello()
	if err != nil {
		return fmt.Errorf("failed to generate Client Hello: %v", err)
	}

	// Create session
	sessionID := fmt.Sprintf("ws-session-%d-%d", len(sessionStore)+1, time.Now().Unix())
	newState := &SessionState{
		ID:         sessionID,
		TLSClient:  tlsClient,
		WebsiteURL: fmt.Sprintf("%s:%d", data.Hostname, data.Port),
		Completed:  false,
	}

	storeMutex.Lock()
	sessionStore[sessionID] = newState
	storeMutex.Unlock()

	// Register WebSocket connection
	wsConn.sessionID = sessionID
	wsConnMutex.Lock()
	wsConnections[sessionID] = wsConn
	wsConnMutex.Unlock()

	log.Printf("Initialized WebSocket TLS session: %s for %s", sessionID, data.Hostname)

	// Send response
	response := WSSessionInitResponse{
		SessionID:   sessionID,
		ClientHello: clientHello,
		Status:      "client_hello_ready",
	}

	return sendMessage(wsConn, MsgTypeSessionInitResp, sessionID, response)
}

// handleWSEncryptRequest handles request encryption
func handleWSEncryptRequest(wsConn *WSConnection, msg *WSMessage) error {
	var data EncryptRequestData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		return fmt.Errorf("invalid encrypt request data: %v", err)
	}

	sessionID := msg.SessionID
	if sessionID == "" {
		return fmt.Errorf("session ID is required")
	}

	// Get session state
	storeMutex.RLock()
	session, exists := sessionStore[sessionID]
	storeMutex.RUnlock()

	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// TODO: Implement actual split AEAD encryption
	// For now, return placeholder response
	log.Printf("Processing encrypt request for session %s (requests: %d)", sessionID, session.RequestCount)

	// Simulate encryption processing
	time.Sleep(100 * time.Millisecond)

	// Update session state
	storeMutex.Lock()
	session.RequestCount++
	storeMutex.Unlock()

	response := EncryptResponseData{
		EncryptedRequest: append([]byte("encrypted:"), data.RedactedRequest...),
		TagSecrets:       []byte("tag_secrets_placeholder"),
		Status:           "encrypted",
	}

	return sendMessage(wsConn, MsgTypeEncryptResp, sessionID, response)
}

// handleWSDecryptRequest handles response decryption stream generation
func handleWSDecryptRequest(wsConn *WSConnection, msg *WSMessage) error {
	var data DecryptRequestData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		return fmt.Errorf("invalid decrypt request data: %v", err)
	}

	sessionID := msg.SessionID
	if sessionID == "" {
		return fmt.Errorf("session ID is required")
	}

	// Get session state
	storeMutex.RLock()
	session, exists := sessionStore[sessionID]
	storeMutex.RUnlock()

	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// TODO: Implement actual decryption stream generation
	log.Printf("Processing decrypt request for session %s (website: %s), response length: %d",
		sessionID, session.WebsiteURL, data.ResponseLength)

	// Simulate decryption stream generation
	time.Sleep(100 * time.Millisecond)

	// Generate placeholder decryption stream
	decryptionStream := make([]byte, data.ResponseLength)
	for i := range decryptionStream {
		decryptionStream[i] = byte(i % 256)
	}

	response := DecryptResponseData{
		DecryptionStream: decryptionStream,
		Status:           "decryption_stream_ready",
	}

	return sendMessage(wsConn, MsgTypeDecryptResp, sessionID, response)
}

// handleWSFinalizeRequest handles transcript finalization
func handleWSFinalizeRequest(wsConn *WSConnection, msg *WSMessage) error {
	var data FinalizeRequestData
	if err := json.Unmarshal(msg.Data, &data); err != nil {
		return fmt.Errorf("invalid finalize request data: %v", err)
	}

	sessionID := msg.SessionID
	if sessionID == "" {
		return fmt.Errorf("session ID is required")
	}

	// Get session state
	storeMutex.Lock()
	session, exists := sessionStore[sessionID]
	if exists {
		session.Completed = true
	}
	storeMutex.Unlock()

	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// TODO: Implement actual transcript signing
	log.Printf("Finalizing session %s with message: %s", sessionID, data.FinalMessage)

	// Simulate transcript signing
	time.Sleep(100 * time.Millisecond)

	response := FinalizeResponseData{
		SignedTranscript: []byte("signed_transcript_placeholder"),
		TLSKeys:          []byte("tls_keys_placeholder"),
		Status:           "finalized",
	}

	return sendMessage(wsConn, MsgTypeFinalizeResp, sessionID, response)
}

// handleWSClose handles connection close
func handleWSClose(wsConn *WSConnection, msg *WSMessage) error {
	log.Printf("WebSocket close requested for session %s", msg.SessionID)
	wsConn.mutex.Lock()
	wsConn.closed = true
	wsConn.mutex.Unlock()
	return nil
}

// sendMessage sends a WebSocket message
func sendMessage(wsConn *WSConnection, msgType, sessionID string, data interface{}) error {
	wsConn.mutex.Lock()
	defer wsConn.mutex.Unlock()

	if wsConn.closed {
		return fmt.Errorf("connection is closed")
	}

	dataBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %v", err)
	}

	msg := WSMessage{
		Type:      msgType,
		SessionID: sessionID,
		Data:      dataBytes,
		Timestamp: time.Now().Unix(),
	}

	return wsConn.conn.WriteJSON(msg)
}

// sendError sends an error message
func sendError(wsConn *WSConnection, sessionID, errorMsg string) {
	wsConn.mutex.Lock()
	defer wsConn.mutex.Unlock()

	if wsConn.closed {
		return
	}

	msg := WSMessage{
		Type:      MsgTypeError,
		SessionID: sessionID,
		Error:     errorMsg,
		Timestamp: time.Now().Unix(),
	}

	if err := wsConn.conn.WriteJSON(msg); err != nil {
		log.Printf("Failed to send error message: %v", err)
	}
}

// sendStatus sends a status update
func sendStatus(wsConn *WSConnection, sessionID, status string) error {
	statusData := map[string]string{"status": status}
	return sendMessage(wsConn, MsgTypeStatus, sessionID, statusData)
}
