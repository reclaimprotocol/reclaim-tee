// Package enclave implements TEE-to-TEE communication via WebSockets
// This enables the Split AEAD protocol coordination between TEE_K and TEE_T
package enclave

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// TEE Communication Message Types
type TEEMessageType string

const (
	// TEE_K → TEE_T Messages
	TEEMsgTagCompute         TEEMessageType = "tag_compute"
	TEEMsgTagVerify          TEEMessageType = "tag_verify"
	TEEMsgSessionStart       TEEMessageType = "session_start"
	TEEMsgSessionEnd         TEEMessageType = "session_end"
	TEEMsgTranscriptFinalize TEEMessageType = "transcript_finalize"

	// TEE_T → TEE_K Messages
	TEEMsgTagComputeResp         TEEMessageType = "tag_compute_response"
	TEEMsgTagVerifyResp          TEEMessageType = "tag_verify_response"
	TEEMsgSessionStartResp       TEEMessageType = "session_start_response"
	TEEMsgSessionEndResp         TEEMessageType = "session_end_response"
	TEEMsgTranscriptFinalizeResp TEEMessageType = "transcript_finalize_response"

	// Bidirectional Messages
	TEEMsgPing   TEEMessageType = "ping"
	TEEMsgPong   TEEMessageType = "pong"
	TEEMsgError  TEEMessageType = "error"
	TEEMsgStatus TEEMessageType = "status"

	// New message types
	TEEMsgHTTPResponseCapture TEEMessageType = "http_response_capture"
)

// TEE WebSocket Message Structure
type TEEMessage struct {
	Type      TEEMessageType  `json:"type"`
	SessionID string          `json:"session_id,omitempty"`
	RequestID string          `json:"request_id,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	Error     string          `json:"error,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
}

// Tag Compute Request (TEE_K → TEE_T)
type TagComputeRequest struct {
	Ciphertext          []byte            `json:"ciphertext"`
	TagSecrets          *TagSecrets       `json:"tag_secrets"`
	RequestType         string            `json:"request_type"` // "encrypt" or "decrypt"
	UseRedaction        bool              `json:"use_redaction,omitempty"`
	RedactedCiphertext  []byte            `json:"redacted_ciphertext,omitempty"`
	OriginalRequestInfo *RedactionRequest `json:"original_request_info,omitempty"`
}

// Tag Compute Response (TEE_T → TEE_K)
type TagComputeResponse struct {
	RequestID string `json:"request_id"`
	Tag       []byte `json:"tag"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

// Tag Verify Request (TEE_K → TEE_T)
type TagVerifyRequest struct {
	Ciphertext  []byte      `json:"ciphertext"`
	ExpectedTag []byte      `json:"expected_tag"`
	TagSecrets  *TagSecrets `json:"tag_secrets"`
}

// Tag Verify Response (TEE_T → TEE_K)
type TagVerifyResponse struct {
	RequestID string `json:"request_id"`
	Verified  bool   `json:"verified"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

// Session Start Request (TEE_K → TEE_T)
type SessionStartRequest struct {
	SessionID   string `json:"session_id"`
	CipherSuite uint16 `json:"cipher_suite"`
	Protocol    string `json:"protocol"` // "split_aead"
}

// Session Start Response (TEE_T → TEE_K)
type SessionStartResponse struct {
	SessionID string `json:"session_id"`
	Ready     bool   `json:"ready"`
	Error     string `json:"error,omitempty"`
}

// Transcript Finalize Request (TEE_K → TEE_T)
type TranscriptFinalizeRequest struct {
	SessionID string `json:"session_id"`
}

// Transcript Finalize Response (TEE_T → TEE_K)
type TranscriptFinalizeResponse struct {
	SessionID                string            `json:"session_id"`
	SignedResponseTranscript *SignedTranscript `json:"signed_response_transcript"`
	Success                  bool              `json:"success"`
	Error                    string            `json:"error,omitempty"`
}

// TEE Communication Client (runs in TEE_K)
type TEECommClient struct {
	conn        *websocket.Conn
	url         string
	mu          sync.RWMutex
	connected   bool
	sessionID   string
	requestMap  map[string]chan TEEMessage
	requestMu   sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
	reconnectCh chan struct{}
}

// TEE Communication Server (runs in TEE_T)
type TEECommServer struct {
	clients    map[string]*TEECommConnection
	clientsMu  sync.RWMutex
	upgrader   websocket.Upgrader
	sessions   map[string]*TEESessionData
	sessionsMu sync.RWMutex
}

// TEE Communication Connection (represents a TEE_K connection to TEE_T)
type TEECommConnection struct {
	conn      *websocket.Conn
	sessionID string
	mu        sync.Mutex
}

// TEESessionData stores session-specific data for redaction processing
type TEESessionData struct {
	RedactionStreams *RedactionStreams
	CipherSuite      uint16
	Started          bool
}

// Callback function types for external dependencies
var GetRedactionSessionData func(sessionID string) interface{}

// NewTEECommClient creates a new TEE communication client for TEE_K
func NewTEECommClient(teeT_URL string) *TEECommClient {
	ctx, cancel := context.WithCancel(context.Background())

	return &TEECommClient{
		url:         teeT_URL,
		requestMap:  make(map[string]chan TEEMessage),
		ctx:         ctx,
		cancel:      cancel,
		reconnectCh: make(chan struct{}, 1),
	}
}

// Connect establishes WebSocket connection to TEE_T
func (c *TEECommClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	// Parse URL and add WebSocket path
	u, err := url.Parse(c.url)
	if err != nil {
		return fmt.Errorf("invalid TEE_T URL: %v", err)
	}

	// Use /tee-comm WebSocket endpoint
	u.Path = "/tee-comm"
	// Convert HTTP/HTTPS to WS/WSS
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}

	log.Printf("TEE_K: Connecting to TEE_T at %s", u.String())

	// Connect with custom headers
	headers := http.Header{}
	headers.Set("X-TEE-Type", "tee_k")
	headers.Set("X-Protocol", "split_aead")

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), headers)
	if err != nil {
		return fmt.Errorf("failed to connect to TEE_T: %v", err)
	}

	c.conn = conn
	c.connected = true

	// Start message handler
	go c.messageHandler()

	// Start ping handler
	go c.pingHandler()

	log.Printf("TEE_K: Successfully connected to TEE_T")
	return nil
}

// Disconnect closes the WebSocket connection
func (c *TEECommClient) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return
	}

	c.cancel()

	if c.conn != nil {
		c.conn.Close()
	}

	c.connected = false
	log.Printf("TEE_K: Disconnected from TEE_T")
}

// StartSession starts a new session with specified cipher suite and redaction streams
func (c *TEECommClient) StartSession(sessionID string, cipherSuite uint16) error {
	if !c.connected {
		return fmt.Errorf("not connected to TEE_T")
	}

	// Set the session ID for this client
	c.sessionID = sessionID

	// Send session start request to TEE_T
	request := SessionStartRequest{
		SessionID:   sessionID,
		CipherSuite: cipherSuite,
		Protocol:    "split_aead",
	}

	response, err := c.sendRequestWithResponse(TEEMsgSessionStart, request, 15*time.Second)
	if err != nil {
		c.sessionID = "" // Clear on failure
		return fmt.Errorf("failed to start session with TEE_T: %v", err)
	}

	var startResp SessionStartResponse
	if err := json.Unmarshal(response.Data, &startResp); err != nil {
		c.sessionID = "" // Clear on failure
		return fmt.Errorf("failed to parse session start response: %v", err)
	}

	if !startResp.Ready {
		c.sessionID = "" // Clear on failure
		return fmt.Errorf("TEE_T session start failed: %s", startResp.Error)
	}

	log.Printf("TEE_K: Session %s started with TEE_T (cipher suite 0x%04x)", sessionID, cipherSuite)
	return nil
}

// ComputeTag requests tag computation from TEE_T (core Split AEAD operation)
func (c *TEECommClient) ComputeTag(ciphertext []byte, tagSecrets *TagSecrets, requestType string) ([]byte, error) {
	if !c.connected {
		return nil, fmt.Errorf("not connected to TEE_T")
	}

	request := TagComputeRequest{
		Ciphertext:  ciphertext,
		TagSecrets:  tagSecrets,
		RequestType: requestType,
	}

	response, err := c.sendRequestWithResponse(TEEMsgTagCompute, request, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("tag computation failed: %v", err)
	}

	var computeResp TagComputeResponse
	if err := json.Unmarshal(response.Data, &computeResp); err != nil {
		return nil, fmt.Errorf("failed to parse tag compute response: %v", err)
	}

	if !computeResp.Success {
		return nil, fmt.Errorf("TEE_T tag computation failed: %s", computeResp.Error)
	}

	log.Printf("TEE_K: Tag computed by TEE_T (%d bytes)", len(computeResp.Tag))
	return computeResp.Tag, nil
}

// VerifyTag requests tag verification from TEE_T
func (c *TEECommClient) VerifyTag(ciphertext, expectedTag []byte, tagSecrets *TagSecrets) (bool, error) {
	if !c.connected {
		return false, fmt.Errorf("not connected to TEE_T")
	}

	request := TagVerifyRequest{
		Ciphertext:  ciphertext,
		ExpectedTag: expectedTag,
		TagSecrets:  tagSecrets,
	}

	response, err := c.sendRequestWithResponse(TEEMsgTagVerify, request, 30*time.Second)
	if err != nil {
		return false, fmt.Errorf("tag verification failed: %v", err)
	}

	var verifyResp TagVerifyResponse
	if err := json.Unmarshal(response.Data, &verifyResp); err != nil {
		return false, fmt.Errorf("failed to parse tag verify response: %v", err)
	}

	if !verifyResp.Success {
		return false, fmt.Errorf("TEE_T tag verification failed: %s", verifyResp.Error)
	}

	log.Printf("TEE_K: Tag verification result: %v", verifyResp.Verified)
	return verifyResp.Verified, nil
}

// EndSession terminates the Split AEAD session
func (c *TEECommClient) EndSession() error {
	if !c.connected || c.sessionID == "" {
		return nil
	}

	request := map[string]string{
		"session_id": c.sessionID,
	}

	_, err := c.sendRequestWithResponse(TEEMsgSessionEnd, request, 10*time.Second)
	if err != nil {
		log.Printf("TEE_K: Warning - session end failed: %v", err)
		// Don't return error as this is cleanup
	}

	c.sessionID = ""
	log.Printf("TEE_K: Session ended with TEE_T")
	return nil
}

// FinalizeTranscript requests the signed response transcript from TEE_T
func (c *TEECommClient) FinalizeTranscript() (*SignedTranscript, error) {
	if !c.connected || c.sessionID == "" {
		return nil, fmt.Errorf("no active session with TEE_T")
	}

	request := TranscriptFinalizeRequest{
		SessionID: c.sessionID,
	}

	response, err := c.sendRequestWithResponse(TEEMsgTranscriptFinalize, request, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to request transcript from TEE_T: %v", err)
	}

	var finalizeResp TranscriptFinalizeResponse
	if err := json.Unmarshal(response.Data, &finalizeResp); err != nil {
		return nil, fmt.Errorf("failed to parse transcript finalize response: %v", err)
	}

	if !finalizeResp.Success {
		return nil, fmt.Errorf("TEE_T transcript finalization failed: %s", finalizeResp.Error)
	}

	log.Printf("TEE_K: Received signed response transcript from TEE_T")
	return finalizeResp.SignedResponseTranscript, nil
}

// CaptureHTTPResponse sends HTTP response data to TEE_T for transcript capture
func (c *TEECommClient) CaptureHTTPResponse(httpResponse []byte) error {
	if !c.connected || c.sessionID == "" {
		return fmt.Errorf("no active session with TEE_T")
	}

	request := map[string]interface{}{
		"session_id":    c.sessionID,
		"http_response": httpResponse,
	}

	_, err := c.sendRequestWithResponse(TEEMsgHTTPResponseCapture, request, 15*time.Second)
	if err != nil {
		return fmt.Errorf("failed to capture HTTP response in TEE_T: %v", err)
	}

	log.Printf("TEE_K: HTTP response captured by TEE_T (%d bytes)", len(httpResponse))
	return nil
}

// sendRequestWithResponse sends a request and waits for response
func (c *TEECommClient) sendRequestWithResponse(msgType TEEMessageType, data interface{}, timeout time.Duration) (TEEMessage, error) {
	requestID := generateRequestID()

	// Create response channel
	responseCh := make(chan TEEMessage, 1)
	c.requestMu.Lock()
	c.requestMap[requestID] = responseCh
	c.requestMu.Unlock()

	// Cleanup
	defer func() {
		c.requestMu.Lock()
		delete(c.requestMap, requestID)
		c.requestMu.Unlock()
		close(responseCh)
	}()

	// Marshal data
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return TEEMessage{}, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Send message
	msg := TEEMessage{
		Type:      msgType,
		SessionID: c.sessionID,
		RequestID: requestID,
		Data:      dataBytes,
		Timestamp: time.Now(),
	}

	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return TEEMessage{}, fmt.Errorf("no connection to TEE_T")
	}

	if err := conn.WriteJSON(msg); err != nil {
		return TEEMessage{}, fmt.Errorf("failed to send message: %v", err)
	}

	// Wait for response
	select {
	case response := <-responseCh:
		if response.Error != "" {
			return response, fmt.Errorf("TEE_T error: %s", response.Error)
		}
		return response, nil
	case <-time.After(timeout):
		return TEEMessage{}, fmt.Errorf("timeout waiting for TEE_T response")
	case <-c.ctx.Done():
		return TEEMessage{}, fmt.Errorf("client context cancelled")
	}
}

// messageHandler processes incoming messages from TEE_T
func (c *TEECommClient) messageHandler() {
	defer func() {
		c.mu.Lock()
		c.connected = false
		c.mu.Unlock()

		// Signal reconnection if context not cancelled
		select {
		case c.reconnectCh <- struct{}{}:
		case <-c.ctx.Done():
		default:
		}
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		c.mu.RLock()
		conn := c.conn
		c.mu.RUnlock()

		if conn == nil {
			return
		}

		var msg TEEMessage
		err := conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("TEE_K: WebSocket error from TEE_T: %v", err)
			}
			return
		}

		c.handleMessage(msg)
	}
}

// handleMessage processes individual messages from TEE_T
func (c *TEECommClient) handleMessage(msg TEEMessage) {
	switch msg.Type {
	case TEEMsgTagComputeResp, TEEMsgTagVerifyResp, TEEMsgSessionStartResp, TEEMsgSessionEndResp, TEEMsgTranscriptFinalizeResp:
		// Route response to waiting request
		if msg.RequestID != "" {
			c.requestMu.RLock()
			responseCh, exists := c.requestMap[msg.RequestID]
			c.requestMu.RUnlock()

			if exists {
				select {
				case responseCh <- msg:
				default:
					log.Printf("TEE_K: Warning - response channel full for request %s", msg.RequestID)
				}
			} else {
				log.Printf("TEE_K: Warning - no handler for response %s", msg.RequestID)
			}
		}

	case TEEMsgPing:
		// Respond to ping
		pong := TEEMessage{
			Type:      TEEMsgPong,
			Timestamp: time.Now(),
		}
		c.mu.RLock()
		if c.conn != nil {
			c.conn.WriteJSON(pong)
		}
		c.mu.RUnlock()

	case TEEMsgPong:
		// Handle pong (connection alive)
		log.Printf("TEE_K: Received pong from TEE_T")

	case TEEMsgError:
		log.Printf("TEE_K: Error from TEE_T: %s", msg.Error)

	case TEEMsgStatus:
		// Handle status messages (including HTTP response capture confirmations)
		if msg.RequestID != "" {
			// Route to waiting request if this is a response to a request
			c.requestMu.RLock()
			responseCh, exists := c.requestMap[msg.RequestID]
			c.requestMu.RUnlock()

			if exists {
				select {
				case responseCh <- msg:
				default:
					log.Printf("TEE_K: Warning - response channel full for request %s", msg.RequestID)
				}
			}
		} else {
			log.Printf("TEE_K: Status from TEE_T: %s", string(msg.Data))
		}

	default:
		log.Printf("TEE_K: Unknown message type from TEE_T: %s", msg.Type)
	}
}

// pingHandler sends periodic pings to keep connection alive
func (c *TEECommClient) pingHandler() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mu.RLock()
			connected := c.connected
			conn := c.conn
			c.mu.RUnlock()

			if connected && conn != nil {
				ping := TEEMessage{
					Type:      TEEMsgPing,
					Timestamp: time.Now(),
				}
				if err := conn.WriteJSON(ping); err != nil {
					log.Printf("TEE_K: Failed to send ping to TEE_T: %v", err)
				}
			}

		case <-c.ctx.Done():
			return
		}
	}
}

// generateRequestID creates a unique request ID
func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}

// NewTEECommServer creates a new TEE communication server for TEE_T
func NewTEECommServer() *TEECommServer {
	return &TEECommServer{
		clients: make(map[string]*TEECommConnection),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				// In production, implement proper origin checking
				// For now, allow all connections from TEE_K
				return r.Header.Get("X-TEE-Type") == "tee_k"
			},
		},
		sessions: make(map[string]*TEESessionData),
	}
}

// HandleWebSocket handles incoming WebSocket connections from TEE_K
func (s *TEECommServer) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	log.Printf("TEE_T: Incoming WebSocket connection from %s", r.RemoteAddr)

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("TEE_T: WebSocket upgrade failed: %v", err)
		return
	}

	// Create connection wrapper
	teeConn := &TEECommConnection{
		conn: conn,
	}

	// Start message handler
	go s.handleConnection(teeConn)
}

// handleConnection processes messages from a TEE_K connection
func (s *TEECommServer) handleConnection(teeConn *TEECommConnection) {
	defer func() {
		teeConn.conn.Close()

		// Remove from clients map
		if teeConn.sessionID != "" {
			s.clientsMu.Lock()
			delete(s.clients, teeConn.sessionID)
			s.clientsMu.Unlock()
			log.Printf("TEE_T: TEE_K session %s disconnected", teeConn.sessionID)
		}
	}()

	for {
		var msg TEEMessage
		err := teeConn.conn.ReadJSON(&msg)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("TEE_T: WebSocket error from TEE_K: %v", err)
			}
			return
		}

		s.handleMessage(teeConn, msg)
	}
}

// handleMessage processes individual messages from TEE_K
func (s *TEECommServer) handleMessage(teeConn *TEECommConnection, msg TEEMessage) {
	switch msg.Type {
	case TEEMsgSessionStart:
		s.handleSessionStart(teeConn, msg)
	case TEEMsgTagCompute:
		s.handleTagCompute(teeConn, msg)
	case TEEMsgTagVerify:
		s.handleTagVerify(teeConn, msg)
	case TEEMsgSessionEnd:
		s.handleSessionEnd(teeConn, msg)
	case TEEMsgTranscriptFinalize:
		s.handleTranscriptFinalize(teeConn, msg)
	case TEEMsgHTTPResponseCapture:
		s.handleHTTPResponseCapture(teeConn, msg)
	case TEEMsgPing:
		s.handlePing(teeConn, msg)
	case TEEMsgPong:
		// Connection alive confirmation
		log.Printf("TEE_T: Received pong from TEE_K")
	default:
		log.Printf("TEE_T: Unknown message type from TEE_K: %s", msg.Type)
	}
}

// handleSessionStart processes session start requests
func (s *TEECommServer) handleSessionStart(teeConn *TEECommConnection, msg TEEMessage) {
	var req SessionStartRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		s.sendError(teeConn, msg.RequestID, fmt.Sprintf("Invalid session start request: %v", err))
		return
	}

	// Validate session
	if req.SessionID == "" {
		s.sendError(teeConn, msg.RequestID, "Session ID required")
		return
	}

	if req.Protocol != "split_aead" {
		s.sendError(teeConn, msg.RequestID, "Only split_aead protocol supported")
		return
	}

	// Register session
	teeConn.sessionID = req.SessionID
	s.clientsMu.Lock()
	s.clients[req.SessionID] = teeConn
	s.clientsMu.Unlock()

	// Create session data for transcript building
	if err := CreateSessionDataForWebSocket(req.SessionID); err != nil {
		log.Printf("TEE_T: Failed to create session data for %s: %v", req.SessionID, err)
		s.sendError(teeConn, msg.RequestID, fmt.Sprintf("Failed to initialize session: %v", err))
		return
	}

	// Send success response
	response := SessionStartResponse{
		SessionID: req.SessionID,
		Ready:     true,
	}

	s.sendResponse(teeConn, TEEMsgSessionStartResp, msg.RequestID, response)
	log.Printf("TEE_T: Session %s started with TEE_K", req.SessionID)
}

// handleTagCompute processes tag computation requests
func (s *TEECommServer) handleTagCompute(teeConn *TEECommConnection, msg TEEMessage) {
	var req TagComputeRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		s.sendError(teeConn, msg.RequestID, fmt.Sprintf("Invalid tag compute request: %v", err))
		return
	}

	var tag []byte
	var err error

	if req.UseRedaction && teeConn.sessionID != "" {
		// Handle redacted request using session data
		tag, err = s.handleRedactedTagComputation(req, teeConn.sessionID)
	} else {
		// Standard tag computation
		tagComputer := NewSplitAEADTagComputer()
		tag, err = tagComputer.ComputeTag(req.Ciphertext, req.TagSecrets)
	}

	var response TagComputeResponse
	response.RequestID = msg.RequestID

	if err != nil {
		response.Success = false
		response.Error = fmt.Sprintf("Tag computation failed: %v", err)
		log.Printf("TEE_T: Tag computation failed for session %s: %v", teeConn.sessionID, err)
	} else {
		response.Success = true
		response.Tag = tag
		log.Printf("TEE_T: Tag computed for session %s (%d bytes)", teeConn.sessionID, len(tag))
	}

	s.sendResponse(teeConn, TEEMsgTagComputeResp, msg.RequestID, response)
}

// handleRedactedTagComputation processes tag computation for redacted data
func (s *TEECommServer) handleRedactedTagComputation(req TagComputeRequest, sessionID string) ([]byte, error) {
	// CRITICAL: Protocol Step 3.7 - TEE_T must apply redaction streams to recover original data
	// before computing the tag, as specified in the design document

	if req.OriginalRequestInfo == nil {
		return nil, fmt.Errorf("original request info required for redaction processing")
	}

	// Get session data containing redaction streams from WebSocket sessions
	s.sessionsMu.RLock()
	sessionData, exists := s.sessions[sessionID]
	s.sessionsMu.RUnlock()

	var redactionStreams *RedactionStreams

	if exists && sessionData.RedactionStreams != nil {
		// Use WebSocket session redaction streams
		redactionStreams = sessionData.RedactionStreams
		log.Printf("TEE_T: Using WebSocket session redaction streams for session %s", sessionID)
	} else {
		// For now, we'll require redaction streams to be set via the SetRedactionStreams method
		// In a full implementation, this would coordinate with the global redaction session store
		log.Printf("TEE_T: No redaction streams found in WebSocket session %s", sessionID)
		return nil, fmt.Errorf("redaction streams not available in session - step 3.6 must be completed first")
	}

	// Verify session has redaction streams (Protocol Step 3.6 prerequisite)
	if redactionStreams == nil {
		return nil, fmt.Errorf("redaction streams not available in session - step 3.6 must be completed first")
	}

	// Protocol Step 3.7: Apply redaction streams to recover original data from redacted ciphertext
	// TEE_K sends the redacted ciphertext, but TEE_T needs to recover the original data
	// before computing the authentication tag

	redactionProcessor := NewRedactionProcessor()

	// Recover the original data by applying redaction streams to the redacted ciphertext
	// This is the critical step that was missing - TEE_T must recover R_Enc from R_red_Enc
	recoveredOriginalData, err := redactionProcessor.UnapplyRedaction(
		req.Ciphertext, // This is the redacted ciphertext from TEE_K
		redactionStreams,
		req.OriginalRequestInfo,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to recover original data from redacted ciphertext: %v", err)
	}

	// Reconstruct the original ciphertext by concatenating recovered parts
	originalCiphertext := make([]byte, 0, len(req.Ciphertext))
	originalCiphertext = append(originalCiphertext, recoveredOriginalData.NonSensitive...)
	originalCiphertext = append(originalCiphertext, recoveredOriginalData.Sensitive...)
	originalCiphertext = append(originalCiphertext, recoveredOriginalData.SensitiveProof...)

	// Now compute the tag on the recovered original data (not the redacted data)
	tagComputer := NewSplitAEADTagComputer()
	tag, err := tagComputer.ComputeTag(originalCiphertext, req.TagSecrets)
	if err != nil {
		return nil, fmt.Errorf("failed to compute tag on recovered original data: %v", err)
	}

	log.Printf("TEE_T: Successfully recovered original data (%d bytes) and computed tag for redacted session %s",
		len(originalCiphertext), sessionID)
	log.Printf("TEE_T: Original data breakdown - NS:%d, S:%d, SP:%d bytes",
		len(recoveredOriginalData.NonSensitive), len(recoveredOriginalData.Sensitive), len(recoveredOriginalData.SensitiveProof))

	// Secure cleanup of recovered sensitive data
	defer recoveredOriginalData.SecureZero()

	return tag, nil
}

// handleTagVerify processes tag verification requests
func (s *TEECommServer) handleTagVerify(teeConn *TEECommConnection, msg TEEMessage) {
	var req TagVerifyRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		s.sendError(teeConn, msg.RequestID, fmt.Sprintf("Invalid tag verify request: %v", err))
		return
	}

	// Create tag computer
	tagComputer := NewSplitAEADTagComputer()

	// Verify tag
	err := tagComputer.VerifyTag(req.Ciphertext, req.ExpectedTag, req.TagSecrets)

	response := TagVerifyResponse{
		RequestID: msg.RequestID,
		Success:   true,
		Verified:  err == nil,
	}

	if err != nil && err.Error() != "authentication tag verification failed" {
		// System error vs verification failure
		response.Success = false
		response.Error = fmt.Sprintf("Tag verification error: %v", err)
		log.Printf("TEE_T: Tag verification error for session %s: %v", teeConn.sessionID, err)
	} else {
		log.Printf("TEE_T: Tag verification for session %s: %v", teeConn.sessionID, response.Verified)

		// Note: HTTP response data is now captured through dedicated CaptureHTTPResponse message
		// instead of capturing the Split AEAD ciphertext here
	}

	s.sendResponse(teeConn, TEEMsgTagVerifyResp, msg.RequestID, response)
}

// handleSessionEnd processes session end requests
func (s *TEECommServer) handleSessionEnd(teeConn *TEECommConnection, msg TEEMessage) {
	sessionID := teeConn.sessionID

	// Remove from clients
	s.clientsMu.Lock()
	delete(s.clients, sessionID)
	s.clientsMu.Unlock()

	// Send acknowledgment
	response := map[string]string{
		"session_id": sessionID,
		"status":     "ended",
	}

	s.sendResponse(teeConn, TEEMsgSessionEndResp, msg.RequestID, response)
	log.Printf("TEE_T: Session %s ended", sessionID)
}

// handleTranscriptFinalize processes transcript finalization requests
func (s *TEECommServer) handleTranscriptFinalize(teeConn *TEECommConnection, msg TEEMessage) {
	var req TranscriptFinalizeRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		s.sendError(teeConn, msg.RequestID, fmt.Sprintf("Invalid transcript finalize request: %v", err))
		return
	}

	sessionID := req.SessionID
	if sessionID == "" {
		sessionID = teeConn.sessionID
	}

	// Get response transcript from session data
	signedTranscript, err := GetResponseTranscriptForSession(sessionID)
	if err != nil {
		s.sendError(teeConn, msg.RequestID, fmt.Sprintf("Failed to get response transcript: %v", err))
		return
	}

	response := TranscriptFinalizeResponse{
		SessionID:                sessionID,
		SignedResponseTranscript: signedTranscript,
		Success:                  true,
	}

	s.sendResponse(teeConn, TEEMsgTranscriptFinalizeResp, msg.RequestID, response)
	log.Printf("TEE_T: Sent signed response transcript for session %s", sessionID)
}

// handleHTTPResponseCapture processes HTTP response capture requests
func (s *TEECommServer) handleHTTPResponseCapture(teeConn *TEECommConnection, msg TEEMessage) {
	var req map[string]interface{}
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		s.sendError(teeConn, msg.RequestID, fmt.Sprintf("Invalid HTTP response capture request: %v", err))
		return
	}

	sessionID, ok := req["session_id"].(string)
	if !ok {
		s.sendError(teeConn, msg.RequestID, "Session ID required")
		return
	}

	httpResponseData, ok := req["http_response"].([]byte)
	if !ok {
		// Handle base64 encoded data
		if httpResponseStr, ok := req["http_response"].(string); ok {
			var err error
			httpResponseData, err = base64.StdEncoding.DecodeString(httpResponseStr)
			if err != nil {
				s.sendError(teeConn, msg.RequestID, fmt.Sprintf("Failed to decode HTTP response data: %v", err))
				return
			}
		} else {
			s.sendError(teeConn, msg.RequestID, "HTTP response data required")
			return
		}
	}

	// Capture the HTTP response data for transcript
	if captureErr := CaptureEncryptedResponseForSession(sessionID, httpResponseData); captureErr != nil {
		s.sendError(teeConn, msg.RequestID, fmt.Sprintf("Failed to capture HTTP response: %v", captureErr))
		return
	}

	// Send success response
	response := map[string]interface{}{
		"session_id": sessionID,
		"status":     "captured",
		"size":       len(httpResponseData),
	}

	s.sendResponse(teeConn, TEEMsgStatus, msg.RequestID, response)
	log.Printf("TEE_T: Captured HTTP response for session %s (%d bytes)", sessionID, len(httpResponseData))
}

// GetResponseTranscriptForSession is a placeholder that should be overridden by the TEE_T service
var GetResponseTranscriptForSession func(string) (*SignedTranscript, error) = func(sessionID string) (*SignedTranscript, error) {
	return nil, fmt.Errorf("GetResponseTranscriptForSession not implemented - needs to be set by TEE_T service")
}

// CreateSessionDataForWebSocket creates session data for WebSocket sessions
var CreateSessionDataForWebSocket func(string) error = func(sessionID string) error {
	return fmt.Errorf("CreateSessionDataForWebSocket not implemented - needs to be set by TEE_T service")
}

// CaptureEncryptedResponseForSession captures encrypted responses for transcript building
var CaptureEncryptedResponseForSession func(string, []byte) error = func(sessionID string, ciphertext []byte) error {
	return fmt.Errorf("CaptureEncryptedResponseForSession not implemented - needs to be set by TEE_T service")
}

// handlePing responds to ping messages
func (s *TEECommServer) handlePing(teeConn *TEECommConnection, msg TEEMessage) {
	pong := TEEMessage{
		Type:      TEEMsgPong,
		Timestamp: time.Now(),
	}
	teeConn.conn.WriteJSON(pong)
}

// sendResponse sends a response message to TEE_K
func (s *TEECommServer) sendResponse(teeConn *TEECommConnection, msgType TEEMessageType, requestID string, data interface{}) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		log.Printf("TEE_T: Failed to marshal response: %v", err)
		return
	}

	response := TEEMessage{
		Type:      msgType,
		RequestID: requestID,
		Data:      dataBytes,
		Timestamp: time.Now(),
	}

	teeConn.mu.Lock()
	err = teeConn.conn.WriteJSON(response)
	teeConn.mu.Unlock()

	if err != nil {
		log.Printf("TEE_T: Failed to send response: %v", err)
	}
}

// sendError sends an error response to TEE_K
func (s *TEECommServer) sendError(teeConn *TEECommConnection, requestID, errorMsg string) {
	response := TEEMessage{
		Type:      TEEMsgError,
		RequestID: requestID,
		Error:     errorMsg,
		Timestamp: time.Now(),
	}

	teeConn.mu.Lock()
	err := teeConn.conn.WriteJSON(response)
	teeConn.mu.Unlock()

	if err != nil {
		log.Printf("TEE_T: Failed to send error: %v", err)
	}
}

// SetRedactionStreams stores redaction streams for a session (implements Protocol Step 3.6)
func (s *TEECommServer) SetRedactionStreams(sessionID string, streams *RedactionStreams) error {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	if _, exists := s.sessions[sessionID]; !exists {
		s.sessions[sessionID] = &TEESessionData{
			Started: false,
		}
	}

	s.sessions[sessionID].RedactionStreams = streams
	log.Printf("TEE_T: Redaction streams set for session %s", sessionID)
	return nil
}

// GetSessionData retrieves session data for redaction processing
func (s *TEECommServer) GetSessionData(sessionID string) (*TEESessionData, bool) {
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()

	sessionData, exists := s.sessions[sessionID]
	return sessionData, exists
}
