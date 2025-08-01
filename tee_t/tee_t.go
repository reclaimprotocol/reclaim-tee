package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"tee-mpc/minitls"
	"tee-mpc/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

var teetUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connections from any origin
	},
}

// TEET represents the TEE_T (Execution Environment for Transcript generation)
type TEET struct {
	port int

	// Session management
	sessionManager shared.SessionManagerInterface

	// Logging and error handling
	logger            *shared.Logger
	sessionTerminator *shared.SessionTerminator

	ready bool

	// Single Session Mode: ECDSA signing keys
	signingKeyPair *shared.SigningKeyPair // ECDSA key pair for signing transcripts

	// Enclave manager for attestation generation
	enclaveManager *shared.EnclaveManager
}

func NewTEET(port int) *TEET {
	return NewTEETWithEnclaveManager(port, nil)
}

func NewTEETWithEnclaveManager(port int, enclaveManager *shared.EnclaveManager) *TEET {
	// Generate ECDSA signing key pair
	signingKeyPair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		// Critical failure - cannot operate without signing capability
		shared.GetTEETLogger().Critical("CRITICAL: Failed to generate signing key pair", zap.Error(err))
		log.Fatalf("[TEE_T] CRITICAL: Failed to generate signing key pair: %v", err)
	}
	shared.GetTEETLogger().InfoIf("Generated ECDSA signing key pair (P-256 curve)")

	return &TEET{
		port:              port,
		sessionManager:    shared.NewSessionManager(),
		logger:            shared.GetTEETLogger(),
		sessionTerminator: shared.NewSessionTerminator(shared.GetTEETLogger()),
		signingKeyPair:    signingKeyPair,
		enclaveManager:    enclaveManager,
	}
}

// NewTEETWithLogger creates a TEET with a specific logger
func NewTEETWithLogger(port int, logger *shared.Logger) *TEET {
	return NewTEETWithEnclaveManagerAndLogger(port, nil, logger)
}

// NewTEETWithEnclaveManagerAndLogger creates a TEET with enclave manager and logger
func NewTEETWithEnclaveManagerAndLogger(port int, enclaveManager *shared.EnclaveManager, logger *shared.Logger) *TEET {
	sessionTerminator := shared.NewSessionTerminator(logger)

	// Generate ECDSA signing key pair
	signingKeyPair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		// Critical failure - cannot operate without signing capability
		if logger != nil {
			logger.Critical("CRITICAL: Failed to generate signing key pair", zap.Error(err))
		}
		log.Fatalf("[TEE_T] CRITICAL: Failed to generate signing key pair: %v", err)
	}
	if logger != nil {
		logger.InfoIf("Generated ECDSA signing key pair", zap.String("curve", "P-256"))
	}

	return &TEET{
		port:              port,
		sessionManager:    shared.NewSessionManager(),
		logger:            logger,
		sessionTerminator: sessionTerminator,
		signingKeyPair:    signingKeyPair,
		enclaveManager:    enclaveManager,
	}
}

// NewTEETWithSessionManager creates a TEET with a specific session manager
func NewTEETWithSessionManager(port int, sessionManager shared.SessionManagerInterface) *TEET {
	return NewTEETWithSessionManagerAndEnclaveManager(port, sessionManager, nil)
}

func NewTEETWithSessionManagerAndEnclaveManager(port int, sessionManager shared.SessionManagerInterface, enclaveManager *shared.EnclaveManager) *TEET {
	// Generate ECDSA signing key pair
	signingKeyPair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		// Critical failure - cannot operate without signing capability
		shared.GetTEETLogger().Critical("CRITICAL: Failed to generate signing key pair", zap.Error(err))
		log.Fatalf("[TEE_T] CRITICAL: Failed to generate signing key pair: %v", err)
	}
	shared.GetTEETLogger().InfoIf("Generated ECDSA signing key pair (P-256 curve)")

	logger := shared.GetTEETLogger()

	return &TEET{
		port:              port,
		sessionManager:    sessionManager,
		logger:            logger,
		sessionTerminator: shared.NewSessionTerminator(logger),
		signingKeyPair:    signingKeyPair,
		enclaveManager:    enclaveManager,
	}
}

// Helper functions to access session state
func (t *TEET) getSessionRedactionState(sessionID string) (*shared.RedactionSessionState, error) {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return nil, err
	}
	if session.RedactionState == nil {
		session.RedactionState = &shared.RedactionSessionState{}
	}
	return session.RedactionState, nil
}

// Start method removed - now handled by main.go with proper graceful shutdown

func (t *TEET) handleClientWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := teetUpgrader.Upgrade(w, r, nil)
	if err != nil {
		t.logger.Error("Failed to upgrade client websocket",
			zap.Error(err),
			zap.String("remote_addr", r.RemoteAddr))
		return
	}

	t.logger.DebugIf("Client WebSocket connection established",
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("local_addr", conn.LocalAddr().String()))

	var sessionID string

	t.logger.DebugIf("Client connection stored, starting message loop")

	for {
		t.logger.DebugIf("Waiting for next client message...")

		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				t.logger.DebugIf("Client connection closed normally", zap.Error(err))
			} else if !isNetworkShutdownError(err) {
				// This is potentially a protocol violation or network issue
				if t.sessionTerminator.ProtocolError(sessionID, shared.ReasonConnectionLost, err,
					zap.String("remote_addr", r.RemoteAddr)) {
					break // Terminate session due to repeated errors
				}
			}
			break
		}

		t.logger.DebugIf("Received raw message from client",
			zap.Int("bytes", len(msgBytes)),
			zap.String("preview", string(msgBytes[:min(100, len(msgBytes))])))

		msg, err := shared.ParseMessage(msgBytes)
		if err != nil {
			// Message parsing failure is a protocol violation
			if t.sessionTerminator.ProtocolError(sessionID, shared.ReasonMessageParsingFailed, err,
				zap.String("remote_addr", r.RemoteAddr),
				zap.Int("message_size", len(msgBytes))) {
				t.sendErrorToClient(conn, fmt.Sprintf("Failed to parse message: %v", err))
				break // Terminate session
			}
			// Protocol errors now always terminate - no more continue
			t.sendErrorToClient(conn, fmt.Sprintf("Failed to parse message: %v", err))
			break
		}

		t.logger.DebugIf("Received message from client",
			zap.String("message_type", string(msg.Type)),
			zap.String("session_id", msg.SessionID))

		// Handle session ID for client messages
		if msg.SessionID != "" {
			if sessionID == "" {
				// First message with session ID - activate the session
				sessionID = msg.SessionID
				wsConn := shared.NewWSConnection(conn)
				if err := t.sessionManager.ActivateSession(sessionID, wsConn); err != nil {
					// Session activation failure is critical - always terminate
					t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionManagerFailure, err,
						zap.String("remote_addr", r.RemoteAddr))
					t.sendErrorToClient(conn, "Failed to activate session")
					break // Terminate session
				}
				t.logger.InfoIf("Activated session for client",
					zap.String("session_id", sessionID),
					zap.String("remote_addr", conn.RemoteAddr().String()))
			} else if msg.SessionID != sessionID {
				// Session ID mismatch is a security violation
				// Session ID mismatch is always a security violation - terminate immediately
				t.sessionTerminator.SecurityViolation(sessionID, shared.ReasonSessionIDMismatch,
					fmt.Errorf("expected %s, got %s", sessionID, msg.SessionID),
					zap.String("expected_session", sessionID),
					zap.String("received_session", msg.SessionID),
					zap.String("remote_addr", r.RemoteAddr))
				t.sendErrorToClient(conn, "Session ID mismatch")
				break // Terminate session
			}
		}

		switch msg.Type {
		case shared.MsgTEETReady:
			t.logger.DebugIf("Handling MsgTEETReady", zap.String("session_id", sessionID))
			t.handleTEETReadySession(sessionID, msg)
		case shared.MsgRedactionStreams:
			t.logger.DebugIf("Handling MsgRedactionStreams", zap.String("session_id", sessionID))
			t.handleRedactionStreamsSession(sessionID, msg)
		case shared.MsgAttestationRequest:
			t.logger.DebugIf("Handling MsgAttestationRequest", zap.String("session_id", sessionID))
			t.handleAttestationRequestSession(sessionID, msg)
		case shared.MsgFinished:
			t.logger.DebugIf("Handling MsgFinished from client", zap.String("session_id", sessionID))
			t.handleFinishedFromClientSession(sessionID, msg)

		case shared.MsgBatchedEncryptedResponses:
			t.logger.DebugIf("Handling MsgBatchedEncryptedResponses", zap.String("session_id", sessionID))
			t.handleBatchedEncryptedResponsesSession(sessionID, msg)

		default:
			// Unknown message type is a protocol violation
			if t.sessionTerminator.ProtocolError(sessionID, shared.ReasonUnknownMessageType,
				fmt.Errorf("unknown message type: %s", string(msg.Type)),
				zap.String("message_type", string(msg.Type)),
				zap.String("remote_addr", r.RemoteAddr)) {
				t.sendErrorToClient(conn, fmt.Sprintf("Unknown message type: %s", msg.Type))
				break // Terminate session if too many unknown messages
			}
			t.sendErrorToClient(conn, fmt.Sprintf("Unknown message type: %s", msg.Type))
		}
	}

	// Clean up session when client disconnects
	if sessionID != "" {
		t.logger.InfoIf("Cleaning up session", zap.String("session_id", sessionID))
		t.sessionManager.CloseSession(sessionID)
		t.sessionTerminator.CleanupSession(sessionID)
	}
}

func (t *TEET) handleTEEKWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := teetUpgrader.Upgrade(w, r, nil)
	if err != nil {
		t.logger.Error("Failed to upgrade TEE_K websocket",
			zap.Error(err),
			zap.String("remote_addr", r.RemoteAddr))
		return
	}

	var sessionID string

	t.logger.InfoIf("TEE_K connection established", zap.String("remote_addr", conn.RemoteAddr().String()))

	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				t.logger.InfoIf("TEE_K disconnected normally", zap.String("session_id", sessionID))
			} else if !isNetworkShutdownError(err) {
				// Network error from TEE_K connection
				if t.sessionTerminator.ProtocolError(sessionID, shared.ReasonConnectionLost, err,
					zap.String("remote_addr", r.RemoteAddr),
					zap.String("connection_type", "teek")) {
					break // Terminate session due to repeated errors
				}
			}
			break
		}

		msg, err := shared.ParseMessage(msgBytes)
		if err != nil {
			// Message parsing failure from TEE_K is critical - always terminate
			t.sessionTerminator.ProtocolError(sessionID, shared.ReasonMessageParsingFailed, err,
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("connection_type", "teek"),
				zap.Int("message_size", len(msgBytes)))
			t.sendErrorToTEEKForSession("", conn, fmt.Sprintf("Failed to parse message: %v", err))
			break // Terminate session
		}

		// For the first message (session creation), store the session ID
		if msg.Type == shared.MsgSessionCreated && sessionID == "" {
			sessionID = msg.SessionID
			t.logger.InfoIf("Received session creation from TEE_K", zap.String("session_id", sessionID))
		}

		// Ensure subsequent messages have the correct session ID
		if sessionID != "" && msg.SessionID != sessionID {
			// Session ID mismatch from TEE_K is a security violation
			if t.sessionTerminator.SecurityViolation(sessionID, shared.ReasonSessionIDMismatch,
				fmt.Errorf("expected %s, got %s", sessionID, msg.SessionID),
				zap.String("expected_session", sessionID),
				zap.String("received_session", msg.SessionID),
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("connection_type", "teek")) {
				break // Terminate session
			}
			continue
		}

		t.logger.DebugIf("Received message from TEE_K",
			zap.String("message_type", string(msg.Type)),
			zap.String("session_id", sessionID))

		switch msg.Type {
		case shared.MsgSessionCreated:
			// First create the session
			t.handleSessionCreation(msg)
			// Then associate the TEE_K connection with the session
			if sessionID != "" {
				session, err := t.sessionManager.GetSession(sessionID)
				if err != nil {
					// Session manager failure is critical
					if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionManagerFailure, err,
						zap.String("remote_addr", r.RemoteAddr),
						zap.String("connection_type", "teek")) {
						break // Terminate session
					}
					continue
				}
				session.TEEKConn = shared.NewWSConnection(conn)
				t.logger.InfoIf("Associated TEE_K connection with session", zap.String("session_id", sessionID))
			}
		case shared.MsgKeyShareRequest:
			t.handleKeyShareRequestSession(msg)
		case shared.MsgEncryptedRequest:
			t.handleEncryptedRequestSession(msg)
		case shared.MsgFinished:
			t.handleFinishedFromTEEKSession(msg)

		case shared.MsgBatchedTagSecrets:
			t.handleBatchedTagSecretsSession(msg)

		default:
			// Unknown message type from TEE_K is a protocol violation
			if t.sessionTerminator.ProtocolError(sessionID, shared.ReasonUnknownMessageType,
				fmt.Errorf("unknown message type: %s", string(msg.Type)),
				zap.String("message_type", string(msg.Type)),
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("connection_type", "teek")) {
				t.sendErrorToTEEKForSession(sessionID, conn, fmt.Sprintf("Unknown message type: %s", msg.Type))
				break // Terminate session if too many unknown messages
			}
			t.sendErrorToTEEKForSession(sessionID, conn, fmt.Sprintf("Unknown message type: %s", msg.Type))
		}
	}

	// Clean up session association when TEE_K disconnects
	if sessionID != "" {
		t.logger.InfoIf("Cleaning up session due to TEE_K disconnect", zap.String("session_id", sessionID))
		// Note: we don't close the session here as the client may still be connected
		// The session cleanup will be handled when the client disconnects
		t.sessionTerminator.CleanupSession(sessionID)
	}
}

// Session-aware client handler methods

func (t *TEET) handleTEETReadySession(sessionID string, msg *shared.Message) {
	if sessionID == "" {
		if t.sessionTerminator.ProtocolError("", shared.ReasonMissingSessionID,
			fmt.Errorf("TEE_T ready message missing session ID")) {
			return
		}
		return
	}

	t.logger.InfoIf("Handling TEE_T ready for session", zap.String("session_id", sessionID))

	// Delegate to handler with the client connection
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionNotFound, err) {
			return
		}
		return
	}

	wsConn := session.ClientConn.(*shared.WSConnection)
	t.handleTEETReady(wsConn.GetWebSocketConn(), msg)
}

func (t *TEET) handleRedactionStreamsSession(sessionID string, msg *shared.Message) {
	if sessionID == "" {
		if t.sessionTerminator.ProtocolError("", shared.ReasonMissingSessionID,
			fmt.Errorf("redaction streams message missing session ID")) {
			return
		}
		return
	}

	t.logger.InfoIf("Handling redaction streams for session", zap.String("session_id", sessionID))

	var streamsData shared.RedactionStreamsData
	if err := msg.UnmarshalData(&streamsData); err != nil {
		if t.sessionTerminator.ProtocolError(sessionID, shared.ReasonMessageParsingFailed, err,
			zap.String("data_type", "redaction_streams")) {
			return
		}
		return
	}

	t.logger.InfoIf("Received redaction streams for session",
		zap.String("session_id", sessionID),
		zap.Int("streams_count", len(streamsData.Streams)),
		zap.Int("keys_count", len(streamsData.CommitmentKeys)))

	// Get session to store streams and keys (defer commitment verification)
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionNotFound, err) {
			return
		}
		return
	}

	// Initialize RedactionState if needed
	if session.RedactionState == nil {
		session.RedactionState = &shared.RedactionSessionState{}
	}

	// Store streams and keys in session for later use when encrypted request arrives
	session.RedactionState.RedactionStreams = streamsData.Streams
	session.RedactionState.CommitmentKeys = streamsData.CommitmentKeys

	t.logger.InfoIf("Redaction streams stored for session", zap.String("session_id", sessionID))

	// Note: Commitment verification will happen when encrypted request arrives from TEE_K
	// Do not verify commitments here as they may not be available yet

	// Process pending encrypted request if available
	if session.ResponseState != nil && session.ResponseState.PendingEncryptedRequest != nil {
		t.logger.InfoIf("Processing pending encrypted request with newly received streams", zap.String("session_id", sessionID))
		// Get the stored TEE_K connection from session state
		if session.ResponseState.TEETConnForPending != nil {
			if teekConn, ok := session.ResponseState.TEETConnForPending.(*websocket.Conn); ok {
				t.processEncryptedRequestWithStreamsForSession(sessionID, session.ResponseState.PendingEncryptedRequest, teekConn)
			}
		}

		// Clear pending request
		session.ResponseState.PendingEncryptedRequest = nil
		session.ResponseState.TEETConnForPending = nil
	}

	// Send verification response to client using session routing
	verificationResponse := shared.RedactionVerificationData{
		Success: true,
		Message: "Redaction streams verified and stored",
	}

	verificationMsg := shared.CreateMessage(shared.MsgRedactionVerification, verificationResponse)
	if err := t.sessionManager.RouteToClient(sessionID, verificationMsg); err != nil {
		t.logger.Error("Failed to send verification message",
			zap.String("session_id", sessionID),
			zap.Error(err))
	}

	t.logger.DebugIf("handleRedactionStreamsSession completed for session",
		zap.String("session_id", sessionID))
}

// handleEncryptedResponseSession function removed - now using batched approach

func (t *TEET) handleBatchedEncryptedResponsesSession(sessionID string, msg *shared.Message) {
	t.logger.InfoIf("BATCHING: Handling batched encrypted responses for session", zap.String("session_id", sessionID))

	var batchedResponses shared.BatchedEncryptedResponseData
	if err := msg.UnmarshalData(&batchedResponses); err != nil {
		if t.sessionTerminator.ProtocolError(sessionID, shared.ReasonMessageParsingFailed, err,
			zap.String("data_type", "batched_encrypted_responses")) {
			return
		}
		return
	}

	t.logger.InfoIf("BATCHING: Received batch of encrypted responses",
		zap.String("session_id", sessionID),
		zap.Int("total_count", batchedResponses.TotalCount))

	// Get session to access response state
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionNotFound, err) {
			return
		}
		return
	}

	// Initialize ResponseState if needed
	if session.ResponseState == nil {
		session.ResponseState = &shared.ResponseSessionState{
			PendingEncryptedResponses: make(map[uint64]*shared.EncryptedResponseData),
		}
	}

	// Process each response in the batch and collect lengths for TEE_K
	var responseLengths []struct {
		Length       int    `json:"length"`
		RecordHeader []byte `json:"record_header"`
		SeqNum       uint64 `json:"seq_num"`
		CipherSuite  uint16 `json:"cipher_suite"`
		ExplicitIV   []byte `json:"explicit_iv,omitempty"`
	}

	session.ResponseState.ResponsesMutex.Lock()
	for _, encryptedResp := range batchedResponses.Responses {
		// Store response for later tag verification
		session.ResponseState.PendingEncryptedResponses[encryptedResp.SeqNum] = &encryptedResp

		// Add to transcript (preserve existing logic)
		t.addSingleResponseToTranscript(sessionID, &encryptedResp)

		// Create length data for TEE_K
		lengthData := struct {
			Length       int    `json:"length"`
			RecordHeader []byte `json:"record_header"`
			SeqNum       uint64 `json:"seq_num"`
			CipherSuite  uint16 `json:"cipher_suite"`
			ExplicitIV   []byte `json:"explicit_iv,omitempty"`
		}{
			Length:       len(encryptedResp.EncryptedData),
			RecordHeader: encryptedResp.RecordHeader,
			SeqNum:       encryptedResp.SeqNum,
			CipherSuite:  encryptedResp.CipherSuite,
			ExplicitIV:   encryptedResp.ExplicitIV,
		}
		responseLengths = append(responseLengths, lengthData)
	}
	session.ResponseState.ResponsesMutex.Unlock()

	t.logger.InfoIf("BATCHING: Processed encrypted responses",
		zap.String("session_id", sessionID),
		zap.Int("total_count", len(batchedResponses.Responses)))

	// Send batched lengths to TEE_K
	batchedLengths := shared.BatchedResponseLengthData{
		Lengths:    responseLengths,
		SessionID:  sessionID,
		TotalCount: len(responseLengths),
	}

	lengthsMsg := shared.CreateSessionMessage(shared.MsgBatchedResponseLengths, sessionID, batchedLengths)

	if err := t.sendMessageToTEEKForSession(sessionID, lengthsMsg); err != nil {
		t.logger.Error("Failed to send batched lengths to TEE_K",
			zap.String("session_id", sessionID),
			zap.Error(err))
		return
	}

	t.logger.InfoIf("BATCHING: Successfully sent batch of response lengths to TEE_K",
		zap.String("session_id", sessionID),
		zap.Int("total_count", len(responseLengths)))
}

func (t *TEET) addSingleResponseToTranscript(sessionID string, encryptedResp *shared.EncryptedResponseData) {
	// Session-aware transcript collection
	// For TLS 1.2 AES-GCM, we need to include the explicit IV in the response record too

	// Check if this is TLS 1.2 AES-GCM cipher suite
	isTLS12AESGCMCipher := shared.IsTLS12AESGCMCipherSuite(encryptedResp.CipherSuite)

	var payload []byte
	if isTLS12AESGCMCipher && encryptedResp.ExplicitIV != nil && len(encryptedResp.ExplicitIV) == 8 {
		// TLS 1.2 AES-GCM: explicit_iv(8) + encrypted_data + auth_tag(16)
		// Use the explicit IV provided by the client
		payload = make([]byte, 8+len(encryptedResp.EncryptedData)+len(encryptedResp.Tag))
		copy(payload[0:8], encryptedResp.ExplicitIV)
		copy(payload[8:8+len(encryptedResp.EncryptedData)], encryptedResp.EncryptedData)
		copy(payload[8+len(encryptedResp.EncryptedData):], encryptedResp.Tag)

		t.logger.DebugIf("Added explicit IV to TLS 1.2 AES-GCM response transcript record",
			zap.String("session_id", sessionID),
			zap.Binary("explicit_iv", encryptedResp.ExplicitIV))
	} else {
		// TLS 1.3 or ChaCha20: encrypted_data + auth_tag (no explicit IV)
		payload = make([]byte, len(encryptedResp.EncryptedData)+len(encryptedResp.Tag))
		copy(payload, encryptedResp.EncryptedData)
		copy(payload[len(encryptedResp.EncryptedData):], encryptedResp.Tag)
	}

	recordLength := len(payload)
	if recordLength > 0xFFFF {
		t.logger.WarnIf("TLS record too large, truncating length",
			zap.String("session_id", sessionID),
			zap.Int("original_length", recordLength),
			zap.Int("truncated_length", 0xFFFF))
		recordLength = 0xFFFF
	}

	record := make([]byte, 5+recordLength)
	// Use original record type from client's captured header (preserves 0x15 for alerts, etc.)
	if len(encryptedResp.RecordHeader) >= 1 {
		record[0] = encryptedResp.RecordHeader[0] // Preserve original record type
	} else {
		record[0] = 0x17 // Default to ApplicationData if header missing
	}
	record[1] = 0x03                      // TLS version major
	record[2] = 0x03                      // TLS version minor
	record[3] = byte(recordLength >> 8)   // Length high byte
	record[4] = byte(recordLength & 0xFF) // Length low byte
	copy(record[5:], payload)             // Complete payload with explicit IV if needed

	// Add to session transcript
	t.addToTranscriptForSessionWithType(sessionID, record, shared.TranscriptPacketTypeTLSRecord)

	t.logger.DebugIf("Added response packet to session transcript",
		zap.String("session_id", sessionID),
		zap.Uint64("seq_num", encryptedResp.SeqNum),
		zap.Int("record_length", len(record)))
}

func (t *TEET) handleSessionCreation(msg *shared.Message) {
	var sessionData map[string]interface{}
	if err := msg.UnmarshalData(&sessionData); err != nil {
		t.logger.Error("Failed to unmarshal session creation data", zap.Error(err))
		return
	}

	sessionID, ok := sessionData["session_id"].(string)
	if !ok {
		t.logger.Error("Invalid session_id in session creation message")
		return
	}

	// Register the session in our session manager
	if err := t.sessionManager.RegisterSession(sessionID); err != nil {
		// Session registration failure is critical
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionManagerFailure, err) {
			return
		}
		return
	}

	t.logger.InfoIf("Registered session from TEE_K", zap.String("session_id", sessionID))
}

func (t *TEET) handleKeyShareRequestSession(msg *shared.Message) {
	sessionID := msg.SessionID
	if sessionID == "" {
		if t.sessionTerminator.ProtocolError("", shared.ReasonMissingSessionID,
			fmt.Errorf("key share request missing session ID")) {
			return
		}
		return
	}

	t.logger.InfoIf("Handling key share request for session", zap.String("session_id", sessionID))

	// Get session to access TEE_K connection
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionNotFound, err) {
			return
		}
		return
	}

	var keyReq shared.KeyShareRequestData
	if err := msg.UnmarshalData(&keyReq); err != nil {
		if t.sessionTerminator.ProtocolError(sessionID, shared.ReasonMessageParsingFailed, err,
			zap.String("data_type", "key_share_request")) {
			t.sendErrorToTEEKForSession(sessionID, session.TEEKConn.(*shared.WSConnection).GetWebSocketConn(), fmt.Sprintf("Failed to unmarshal key share request: %v", err))
			return
		}
		return
	}

	// Generate random key share
	keyShare := make([]byte, keyReq.KeyLength)
	if _, err := rand.Read(keyShare); err != nil {
		// Key generation failure is a critical cryptographic error
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonCryptoKeyGenerationFailed, err,
			zap.Int("key_length", keyReq.KeyLength)) {
			t.sendErrorToTEEKForSession(sessionID, session.TEEKConn.(*shared.WSConnection).GetWebSocketConn(), fmt.Sprintf("Failed to generate key share: %v", err))
			return
		}
		return
	}

	// Store in session state
	redactionState, err := t.getSessionRedactionState(sessionID)
	if err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionManagerFailure, err) {
			return
		}
		return
	}
	redactionState.KeyShare = keyShare
	redactionState.CipherSuite = keyReq.CipherSuite

	// Global state removed - using session state only

	t.logger.InfoIf("Generated key share for session",
		zap.String("session_id", sessionID),
		zap.Int("key_length", len(keyShare)),
		zap.Uint16("cipher_suite", keyReq.CipherSuite))

	// Send key share response
	response := shared.KeyShareResponseData{
		KeyShare: keyShare,
		Success:  true,
	}

	responseMsg := shared.CreateMessage(shared.MsgKeyShareResponse, response)
	msgBytes, err := json.Marshal(responseMsg)
	if err != nil {
		t.logger.Error("Failed to marshal key share response",
			zap.String("session_id", sessionID),
			zap.Error(err))
		return
	}

	wsConn := session.TEEKConn.(*shared.WSConnection)
	if err := wsConn.GetWebSocketConn().WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		t.logger.Error("Failed to send key share response",
			zap.String("session_id", sessionID),
			zap.Error(err))
	}
}

func (t *TEET) handleEncryptedRequestSession(msg *shared.Message) {
	sessionID := msg.SessionID
	if sessionID == "" {
		if t.sessionTerminator.ProtocolError("", shared.ReasonMissingSessionID,
			fmt.Errorf("encrypted request missing session ID")) {
			return
		}
		return
	}

	t.logger.InfoIf("Handling encrypted request for session", zap.String("session_id", sessionID))

	var encReq shared.EncryptedRequestData
	if err := msg.UnmarshalData(&encReq); err != nil {
		if t.sessionTerminator.ProtocolError(sessionID, shared.ReasonMessageParsingFailed, err,
			zap.String("data_type", "encrypted_request")) {
			return
		}
		return
	}

	t.logger.InfoIf("Computing tag for encrypted request",
		zap.String("session_id", sessionID),
		zap.Int("ciphertext_bytes", len(encReq.EncryptedData)),
		zap.Uint64("seq_num", encReq.SeqNum),
		zap.Int("redaction_ranges", len(encReq.RedactionRanges)))

	// Get session to access redaction state
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionNotFound, err) {
			return
		}
		return
	}

	// Initialize states if needed
	if session.RedactionState == nil {
		session.RedactionState = &shared.RedactionSessionState{}
	}
	if session.ResponseState == nil {
		session.ResponseState = &shared.ResponseSessionState{
			PendingEncryptedResponses: make(map[uint64]*shared.EncryptedResponseData),
		}
	}

	// Store redaction ranges for stream application
	session.RedactionState.Ranges = encReq.RedactionRanges

	// Store expected commitments from TEE_K for verification
	session.RedactionState.ExpectedCommitments = encReq.Commitments
	t.logger.InfoIf("Stored expected commitments from TEE_K",
		zap.String("session_id", sessionID),
		zap.Int("commitment_count", len(encReq.Commitments)))

	// Verify commitments if redaction streams are already available from Client
	if err := t.verifyCommitmentsIfReady(sessionID); err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonCryptoCommitmentFailed, err,
			zap.Int("commitment_count", len(encReq.Commitments))) {
			return
		}
		return
	}

	// Check if redaction streams are available
	if len(session.RedactionState.RedactionStreams) == 0 {
		// No redaction streams available yet - store request and wait
		session.ResponseState.PendingEncryptedRequest = &encReq

		// Store TEE_K connection for pending request in session state
		wsConn := session.TEEKConn.(*shared.WSConnection)
		session.ResponseState.TEETConnForPending = wsConn.GetWebSocketConn()
		t.logger.InfoIf("Storing encrypted request for session, waiting for redaction streams...",
			zap.String("session_id", sessionID))
		return
	}

	// Process immediately if streams are already available
	// Get underlying websocket connection
	wsConn := session.TEEKConn.(*shared.WSConnection)
	t.processEncryptedRequestWithStreamsForSession(sessionID, &encReq, wsConn.GetWebSocketConn())
}

// handleResponseTagSecretsSession function removed - now using batched approach

func (t *TEET) handleBatchedTagSecretsSession(msg *shared.Message) {
	sessionID := msg.SessionID
	if sessionID == "" {
		if t.sessionTerminator.ProtocolError("", shared.ReasonMissingSessionID,
			fmt.Errorf("batched tag secrets missing session ID")) {
			return
		}
		return
	}

	t.logger.InfoIf("Handling batched tag secrets for session",
		zap.String("session_id", sessionID))

	var batchedTagSecrets shared.BatchedTagSecretsData
	if err := msg.UnmarshalData(&batchedTagSecrets); err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonMessageParsingFailed, err,
			zap.String("message_type", "batched_tag_secrets")) {
			return
		}
		return
	}

	t.logger.InfoIf("Received batch of tag secrets",
		zap.String("session_id", sessionID),
		zap.Int("batch_count", batchedTagSecrets.TotalCount))

	// Get session to access pending responses
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionNotFound, err) {
			return
		}
		return
	}

	if session.ResponseState == nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionStateCorrupted,
			fmt.Errorf("no response state for session")) {
			return
		}
		return
	}

	// Process tag verification for each response in the batch
	var verifications []shared.ResponseTagVerificationData
	allSuccessful := true
	totalCount := len(batchedTagSecrets.TagSecrets)

	session.ResponseState.ResponsesMutex.Lock()
	for _, tagSecretsData := range batchedTagSecrets.TagSecrets {
		// Get the corresponding encrypted response
		encryptedResp := session.ResponseState.PendingEncryptedResponses[tagSecretsData.SeqNum]
		if encryptedResp == nil {
			// CRITICAL SECURITY: Missing encrypted response compromises protocol integrity
			if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionStateCorrupted,
				fmt.Errorf("critical security failure: missing encrypted response for seq %d", tagSecretsData.SeqNum),
				zap.Uint64("seq_num", tagSecretsData.SeqNum)) {
				session.ResponseState.ResponsesMutex.Unlock()
				return // Terminate session on missing critical data
			}
			session.ResponseState.ResponsesMutex.Unlock()
			return
		}

		// Verify tag for this response - THIS IS CRITICAL
		verificationResult := t.verifyTagForResponse(sessionID, encryptedResp, &tagSecretsData)

		if !verificationResult.Success {
			// Tag verification failure is CRITICAL - compromises protocol integrity
			if t.sessionTerminator.CriticalError(sessionID, shared.ReasonCryptoTagVerificationFailed,
				fmt.Errorf("tag verification failed for seq %d", tagSecretsData.SeqNum),
				zap.Uint64("seq_num", tagSecretsData.SeqNum)) {
				session.ResponseState.ResponsesMutex.Unlock()
				return // Terminate session on crypto failure
			}
			allSuccessful = false
			// Only collect failed verifications for detailed reporting
			verifications = append(verifications, verificationResult)
		}

		t.logger.DebugIf("Tag verification completed",
			zap.String("session_id", sessionID),
			zap.Uint64("seq_num", tagSecretsData.SeqNum),
			zap.Bool("success", verificationResult.Success))
	}
	session.ResponseState.ResponsesMutex.Unlock()

	t.logger.InfoIf("Completed batch tag verification",
		zap.String("session_id", sessionID),
		zap.Int("total_count", totalCount),
		zap.Bool("all_successful", allSuccessful))

	// Only include detailed verification results if there are failures
	batchedVerification := shared.BatchedTagVerificationData{
		Verifications: verifications, // Empty if all successful, contains only failures otherwise
		SessionID:     sessionID,
		TotalCount:    totalCount,
		AllSuccessful: allSuccessful,
	}

	verificationMsg := shared.CreateSessionMessage(shared.MsgBatchedTagVerifications, sessionID, batchedVerification)

	if err := t.sendMessageToClientSession(sessionID, verificationMsg); err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonNetworkFailure, err,
			zap.String("target", "client")) {
			return
		}
		return
	}

	// Also send batched verification results to TEE_K for decryption stream generation
	if err := t.sendMessageToTEEKForSession(sessionID, verificationMsg); err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonNetworkFailure, err,
			zap.String("target", "tee_k")) {
			return
		}
		return
	}

	t.logger.InfoIf("Successfully sent batch verification results",
		zap.String("session_id", sessionID))
}

func (t *TEET) verifyTagForResponse(sessionID string, encryptedResp *shared.EncryptedResponseData, tagSecretsData *struct {
	TagSecrets  []byte `json:"tag_secrets"`
	SeqNum      uint64 `json:"seq_num"`
	CipherSuite uint16 `json:"cipher_suite"`
}) shared.ResponseTagVerificationData {
	var additionalData []byte
	cipherSuite := tagSecretsData.CipherSuite

	// Determine TLS version based on cipher suite and construct appropriate AAD
	if cipherSuite == 0x1301 || cipherSuite == 0x1302 || cipherSuite == 0x1303 {
		// TLS 1.3: AAD = record header with ciphertext+tag length (5 bytes)
		tagSize := 16
		ciphertextLength := len(encryptedResp.EncryptedData) + tagSize

		var recordType byte = 0x17 // Default to ApplicationData
		if len(encryptedResp.RecordHeader) >= 1 {
			recordType = encryptedResp.RecordHeader[0] // Use actual record type
		}

		additionalData = []byte{
			recordType,                    // Use actual record type (0x17 for data, 0x15 for alerts, etc.)
			0x03,                          // TLS version major (compatibility)
			0x03,                          // TLS version minor (compatibility)
			byte(ciphertextLength >> 8),   // Length high byte (includes tag)
			byte(ciphertextLength & 0xFF), // Length low byte (includes tag)
		}

		t.logger.DebugIf("Constructed TLS 1.3 AAD for tag verification",
			zap.String("session_id", sessionID),
			zap.Uint64("seq_num", tagSecretsData.SeqNum),
			zap.Uint8("record_type", recordType),
			zap.Int("ciphertext_tag_len", ciphertextLength))
	} else {
		// TLS 1.2: AAD = seq_num + record header (13 bytes)
		additionalData = make([]byte, 13)
		// Sequence number (8 bytes, big-endian)
		for i := 0; i < 8; i++ {
			additionalData[i] = byte(encryptedResp.SeqNum >> (8 * (7 - i)))
		}
		// Record header (5 bytes) - use actual record type and plaintext length
		if len(encryptedResp.RecordHeader) >= 1 {
			additionalData[8] = encryptedResp.RecordHeader[0] // Use actual record type (0x17 for data, 0x15 for alerts, etc.)
		} else {
			additionalData[8] = 0x17 // Fallback to ApplicationData
		}
		additionalData[9] = 0x03                                           // TLS version major
		additionalData[10] = 0x03                                          // TLS version minor
		additionalData[11] = byte(len(encryptedResp.EncryptedData) >> 8)   // plaintext length high byte
		additionalData[12] = byte(len(encryptedResp.EncryptedData) & 0xFF) // plaintext length low byte

		t.logger.DebugIf("Constructed TLS 1.2 AAD for tag verification",
			zap.String("session_id", sessionID),
			zap.Uint64("seq_num", encryptedResp.SeqNum),
			zap.Uint8("record_type", additionalData[8]),
			zap.Int("plaintext_len", len(encryptedResp.EncryptedData)))
	}

	// Compute authentication tag using consolidated crypto functions
	computedTag, err := minitls.ComputeTagFromSecrets(
		encryptedResp.EncryptedData,
		tagSecretsData.TagSecrets,
		cipherSuite,
		additionalData,
	)

	var success bool
	if err != nil {
		// Cryptographic computation failure is critical
		t.logger.Error("Failed to compute authentication tag",
			zap.String("session_id", sessionID),
			zap.Uint64("seq_num", encryptedResp.SeqNum),
			zap.Error(err))
		success = false
	} else {
		// Compare tags
		success = len(computedTag) == len(encryptedResp.Tag)
		if success {
			for i := 0; i < len(computedTag); i++ {
				if computedTag[i] != encryptedResp.Tag[i] {
					success = false
					break
				}
			}
		}

		// Log detailed verification result
		if success {
			t.logger.DebugIf("Tag verification succeeded",
				zap.String("session_id", sessionID),
				zap.Uint64("seq_num", encryptedResp.SeqNum))
		} else {
			t.logger.Error("Tag verification failed - computed tag does not match",
				zap.String("session_id", sessionID),
				zap.Uint64("seq_num", encryptedResp.SeqNum),
				zap.Binary("computed_tag", computedTag),
				zap.Binary("expected_tag", encryptedResp.Tag))
		}
	}

	// Create verification result
	verificationData := shared.ResponseTagVerificationData{
		Success: success,
		SeqNum:  tagSecretsData.SeqNum,
	}

	if !success {
		verificationData.Message = "Authentication tag verification failed"
	}

	return verificationData
}

// processEncryptedRequestWithStreamsForSession is session-aware version
func (t *TEET) processEncryptedRequestWithStreamsForSession(sessionID string, encReq *shared.EncryptedRequestData, conn *websocket.Conn) {
	t.logger.InfoIf("Processing encrypted request with available redaction streams for session",
		zap.String("session_id", sessionID))

	// Get session to access redaction streams
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionNotFound, err) {
			t.sendErrorToTEEK(conn, fmt.Sprintf("Failed to get session: %v", err))
			return
		}
		return
	}

	if session.RedactionState == nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionStateCorrupted,
			fmt.Errorf("no redaction state available for session")) {
			t.sendErrorToTEEK(conn, "No redaction state available")
			return
		}
		return
	}

	// Apply redaction streams to reconstruct the full request for tag computation
	reconstructedData, err := t.reconstructFullRequestWithStreams(encReq.EncryptedData, encReq.RedactionRanges, session.RedactionState.RedactionStreams)
	if err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonCryptoTagComputationFailed, err) {
			t.sendErrorToTEEK(conn, fmt.Sprintf("Failed to reconstruct full request: %v", err))
			return
		}
		return
	}

	t.logger.InfoIf("Successfully reconstructed original request data",
		zap.String("session_id", sessionID))

	// Create AAD for tag computation based on TLS version
	var additionalData []byte
	if encReq.CipherSuite == 0x1301 || encReq.CipherSuite == 0x1302 || encReq.CipherSuite == 0x1303 {
		// TLS 1.3: AAD = record header with ciphertext+tag length (5 bytes)
		tagSize := 16                                    // GCM tag size
		recordLength := len(reconstructedData) + tagSize // encrypted data + authentication tag
		additionalData = []byte{
			0x17,                      // ApplicationData
			0x03,                      // TLS version major (compatibility)
			0x03,                      // TLS version minor (compatibility)
			byte(recordLength >> 8),   // Length high byte (includes tag)
			byte(recordLength & 0xFF), // Length low byte (includes tag)
		}
	} else {
		// TLS 1.2: AAD = seq_num + record header (13 bytes)
		plaintextLength := len(reconstructedData) // For TLS 1.2 AAD, use plaintext length
		additionalData = make([]byte, 13)         // 8 bytes seq_num + 5 bytes record header

		// Sequence number (8 bytes, big-endian)
		for i := 0; i < 8; i++ {
			additionalData[i] = byte(encReq.SeqNum >> (8 * (7 - i)))
		}

		// Record header (5 bytes)
		additionalData[8] = 0x17                          // Application data content type
		additionalData[9] = 0x03                          // TLS version major
		additionalData[10] = 0x03                         // TLS version minor
		additionalData[11] = byte(plaintextLength >> 8)   // Plaintext length high byte
		additionalData[12] = byte(plaintextLength & 0xFF) // Plaintext length low byte
	}

	// Use consolidated minitls function for tag computation - THIS IS CRITICAL
	authTag, err := minitls.ComputeTagFromSecrets(reconstructedData, encReq.TagSecrets, encReq.CipherSuite, additionalData)
	if err != nil {
		// Cryptographic computation failure is CRITICAL and should terminate session
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonCryptoTagComputationFailed, err) {
			t.sendErrorToTEEK(conn, fmt.Sprintf("Failed to compute authentication tag: %v", err))
			return
		}
		return
	}

	t.logger.InfoIf("Computed split AEAD tag",
		zap.String("session_id", sessionID),
		zap.Binary("tag", authTag),
		zap.Int("data_length", len(reconstructedData)))

	// Construct the complete TLS record that will be sent to the server
	// For TLS 1.2 AES-GCM, we need to include the explicit IV

	// Check if this is TLS 1.2 AES-GCM cipher suite
	isTLS12AESGCMCipher := shared.IsTLS12AESGCMCipherSuite(encReq.CipherSuite)

	var payload []byte
	if isTLS12AESGCMCipher {
		// TLS 1.2 AES-GCM: explicit_iv(8) + encrypted_data + auth_tag(16)
		// Explicit IV = sequence number (big-endian, 8 bytes)
		seqNum := encReq.SeqNum
		explicitIV := make([]byte, 8)
		explicitIV[0] = byte(seqNum >> 56)
		explicitIV[1] = byte(seqNum >> 48)
		explicitIV[2] = byte(seqNum >> 40)
		explicitIV[3] = byte(seqNum >> 32)
		explicitIV[4] = byte(seqNum >> 24)
		explicitIV[5] = byte(seqNum >> 16)
		explicitIV[6] = byte(seqNum >> 8)
		explicitIV[7] = byte(seqNum)

		payload = make([]byte, 8+len(reconstructedData)+len(authTag))
		copy(payload[0:8], explicitIV)
		copy(payload[8:8+len(reconstructedData)], reconstructedData)
		copy(payload[8+len(reconstructedData):], authTag)

		t.logger.DebugIf("Constructed TLS 1.2 AES-GCM record with explicit IV",
			zap.String("session_id", sessionID),
			zap.Binary("explicit_iv", explicitIV))
	} else {
		// TLS 1.3 or ChaCha20: encrypted_data + auth_tag (no explicit IV)
		payload = make([]byte, len(reconstructedData)+len(authTag))
		copy(payload, reconstructedData)
		copy(payload[len(reconstructedData):], authTag)
	}

	recordLength := len(payload)
	tlsRecord := make([]byte, 5+recordLength)
	tlsRecord[0] = 0x17                      // ApplicationData
	tlsRecord[1] = 0x03                      // TLS version major
	tlsRecord[2] = 0x03                      // TLS version minor
	tlsRecord[3] = byte(recordLength >> 8)   // Length high byte
	tlsRecord[4] = byte(recordLength & 0xFF) // Length low byte
	copy(tlsRecord[5:], payload)             // Complete payload with explicit IV if needed

	// Add the complete TLS record to TEE_T's transcript
	t.addToTranscriptForSessionWithType(sessionID, tlsRecord, shared.TranscriptPacketTypeTLSRecord)
	t.logger.InfoIf("Added complete TLS request record to session transcript",
		zap.String("session_id", sessionID),
		zap.Int("record_length", len(tlsRecord)))

	// Send the RECONSTRUCTED encrypted data with tag to client using session routing
	response := shared.EncryptedDataResponse{
		EncryptedData: reconstructedData, // Send the full reconstructed encrypted request
		AuthTag:       authTag,           // Tag computed on full reconstructed request
		Success:       true,
	}

	t.logger.InfoIf("Sending reconstructed encrypted data to client session",
		zap.String("session_id", sessionID),
		zap.Int("data_length", len(reconstructedData)),
		zap.Binary("first_32_bytes", reconstructedData[:min(32, len(reconstructedData))]))

	responseMsg := shared.CreateMessage(shared.MsgEncryptedData, response)
	if err := t.sessionManager.RouteToClient(sessionID, responseMsg); err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonNetworkFailure, err,
			zap.String("target", "client")) {
			return
		}
		return
	}

}

// Note: computeAuthenticationTag function has been consolidated into minitls.ComputeTagFromSecrets

// sendMessageToClient removed - use sendMessageToClientSession instead

// sendMessageToClientSession sends a message to a specific client by session ID
func (t *TEET) sendMessageToClientSession(sessionID string, msg *shared.Message) error {
	if sessionID == "" {
		return fmt.Errorf("session ID is required")
	}

	// Add session ID to message
	msg.SessionID = sessionID

	if err := t.sessionManager.RouteToClient(sessionID, msg); err != nil {
		return fmt.Errorf("failed to route message to session %s: %v", sessionID, err)
	}

	return nil
}

func (t *TEET) sendMessageToTEEKForSession(sessionID string, msg *shared.Message) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session %s: %v", sessionID, err)
	}

	if session.TEEKConn == nil {
		return fmt.Errorf("no TEE_K connection in session %s", sessionID)
	}

	msg.SessionID = sessionID

	// Use the thread-safe WriteJSON method instead of bypassing the mutex
	return session.TEEKConn.WriteJSON(msg)
}

func (t *TEET) sendErrorToTEEKForSession(sessionID string, conn *websocket.Conn, errMsg string) {
	errorMsg := shared.CreateSessionMessage(shared.MsgError, sessionID, shared.ErrorData{Message: errMsg})
	msgBytes, err := json.Marshal(errorMsg)
	if err != nil {
		t.logger.Error("Failed to marshal error message for TEE_K",
			zap.String("session_id", sessionID),
			zap.Error(err))
		return
	}

	if err := conn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		t.logger.Error("Failed to send error message to TEE_K",
			zap.String("session_id", sessionID),
			zap.Error(err))
	}
}

func (t *TEET) sendErrorToClient(conn *websocket.Conn, errMsg string) {
	errorMsg := shared.CreateMessage(shared.MsgError, shared.ErrorData{Message: errMsg})
	msgBytes, err := json.Marshal(errorMsg)
	if err != nil {
		t.logger.Error("Failed to marshal error message", zap.Error(err))
		return
	}

	if err := conn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		t.logger.Error("Failed to send error message to client", zap.Error(err))
	}
}

func (t *TEET) sendErrorToTEEK(conn *websocket.Conn, errMsg string) {
	errorMsg := shared.CreateMessage(shared.MsgError, shared.ErrorData{Message: errMsg})
	msgBytes, err := json.Marshal(errorMsg)
	if err != nil {
		t.logger.Error("Failed to marshal error message for TEE_K", zap.Error(err))
		return
	}

	if err := conn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		t.logger.Error("Failed to send error message to TEE_K", zap.Error(err))
	}
}

// Phase 3: Redaction system implementation

// verifyCommitmentsIfReady checks if both stream collections (from Client) and expected commitments (from TEE_K) are available, then verifies them
func (t *TEET) verifyCommitmentsIfReady(sessionID string) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session: %v", err)
	}

	if session.RedactionState == nil {
		return fmt.Errorf("critical security failure: no redaction state available for commitment verification in session %s", sessionID)
	}

	// Check if both streams and expected commitments are available
	hasStreams := len(session.RedactionState.RedactionStreams) > 0 && len(session.RedactionState.CommitmentKeys) > 0
	hasCommitments := len(session.RedactionState.ExpectedCommitments) > 0

	if !hasStreams {
		return fmt.Errorf("critical security failure: redaction streams not available for commitment verification in session %s", sessionID)
	}

	if !hasCommitments {
		return fmt.Errorf("critical security failure: expected commitments from TEE_K not available for verification in session %s", sessionID)
	}

	// Both collections available - perform verification
	t.logger.InfoIf("Stream collections and expected commitments both available - verifying commitments",
		zap.String("session_id", sessionID),
		zap.Int("streams_count", len(session.RedactionState.RedactionStreams)),
		zap.Int("expected_commitments_count", len(session.RedactionState.ExpectedCommitments)))

	if err := t.verifyCommitments(session.RedactionState.RedactionStreams, session.RedactionState.CommitmentKeys, session.RedactionState.ExpectedCommitments); err != nil {
		return fmt.Errorf("commitment verification failed: %v", err)
	}

	t.logger.InfoIf("Commitment verification completed successfully", zap.String("session_id", sessionID))
	return nil
}

// verifyCommitments verifies that HMAC(stream, key) matches the expected commitments
func (t *TEET) verifyCommitments(streams, keys, expectedCommitments [][]byte) error {
	if len(streams) != len(keys) {
		return fmt.Errorf("streams and keys length mismatch: %d vs %d", len(streams), len(keys))
	}

	if len(expectedCommitments) != len(streams) {
		return fmt.Errorf("expected commitments length mismatch: expected %d, got %d", len(streams), len(expectedCommitments))
	}

	for i := 0; i < len(streams); i++ {
		// Compute HMAC(stream, key)
		h := hmac.New(sha256.New, keys[i])
		h.Write(streams[i])
		computedCommitment := h.Sum(nil)

		t.logger.DebugIf("Computed stream commitment",
			zap.Int("stream_index", i),
			zap.Binary("computed_commitment", computedCommitment),
			zap.Binary("expected_commitment", expectedCommitments[i]))

		// Compare computed commitment with expected commitment from TEE_K
		if len(computedCommitment) != len(expectedCommitments[i]) {
			return fmt.Errorf("commitment %d length mismatch: computed %d bytes, expected %d bytes",
				i, len(computedCommitment), len(expectedCommitments[i]))
		}

		// Use constant time comparison to prevent timing attacks
		if !hmac.Equal(computedCommitment, expectedCommitments[i]) {
			return fmt.Errorf("commitment %d verification failed: HMAC(stream_%d, key_%d) does not match expected commitment from TEE_K", i, i, i)
		}

		t.logger.InfoIf("Stream commitment verified successfully",
			zap.Int("stream_index", i),
			zap.Int("commitment_length", len(computedCommitment)))
	}

	t.logger.InfoIf("All redaction commitments verified successfully",
		zap.Int("total_commitments", len(streams)))
	return nil
}

// reconstructFullRequestWithStreams is session-aware version that accepts redaction streams as parameter
func (t *TEET) reconstructFullRequestWithStreams(encryptedRedacted []byte, ranges []shared.RequestRedactionRange, redactionStreams [][]byte) ([]byte, error) {
	// Make a copy of the encrypted redacted data
	reconstructed := make([]byte, len(encryptedRedacted))
	copy(reconstructed, encryptedRedacted)

	t.logger.DebugIf("Starting redaction stream application with provided streams",
		zap.Binary("redacted_preview", encryptedRedacted[:min(64, len(encryptedRedacted))]),
		zap.Int("redaction_ranges", len(ranges)),
		zap.Int("available_streams", len(redactionStreams)))

	// Apply streams to redacted ranges (this reverses the XOR redaction)
	for i, r := range ranges {
		if i >= len(redactionStreams) {
			continue
		}

		stream := redactionStreams[i]

		t.logger.DebugIf("Applying redaction stream to range",
			zap.Int("stream_index", i),
			zap.Int("range_start", r.Start),
			zap.Int("range_end", r.Start+r.Length),
			zap.Binary("stream_preview", stream[:min(16, len(stream))]))

		// Apply XOR stream to undo redaction (this gives us back the original sensitive data)
		for j := 0; j < r.Length && r.Start+j < len(reconstructed) && j < len(stream); j++ {
			reconstructed[r.Start+j] ^= stream[j]
		}
	}

	t.logger.DebugIf("Completed redaction stream application",
		zap.Binary("reconstructed_preview", reconstructed[:min(64, len(reconstructed))]),
		zap.Int("total_bytes", len(reconstructed)))
	return reconstructed, nil
}

// Phase 4: Response handling methods (moved to session-aware versions)

func (t *TEET) handleTEETReady(conn *websocket.Conn, msg *shared.Message) {
	var readyData shared.TEETReadyData
	if err := msg.UnmarshalData(&readyData); err != nil {
		t.logger.Error("Failed to unmarshal TEE_T ready data", zap.Error(err))
		t.sendErrorToClient(conn, fmt.Sprintf("Failed to unmarshal TEE_T ready data: %v", err))
		return
	}

	t.ready = readyData.Success

	// Send confirmation back to client
	response := shared.TEETReadyData{Success: true}
	responseMsg := shared.CreateMessage(shared.MsgTEETReady, response)

	// Use direct websocket connection since this is not session-based
	msgBytes, err := json.Marshal(responseMsg)
	if err != nil {
		t.logger.Error("Failed to marshal TEE_T ready response", zap.Error(err))
		return
	}

	if err := conn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		t.logger.Error("Failed to send TEE_T ready response", zap.Error(err))
	}
}

// handleAttestationRequestSession handles attestation requests from clients over WebSocket
func (t *TEET) handleAttestationRequestSession(sessionID string, msg *shared.Message) {
	var attestReq shared.AttestationRequestData
	if err := msg.UnmarshalData(&attestReq); err != nil {
		t.logger.Error("Failed to unmarshal attestation request",
			zap.String("session_id", sessionID),
			zap.Error(err))
		t.sendErrorToClientSession(sessionID, "Failed to parse attestation request")
		return
	}

	// Use the session ID from the message itself as the primary source of truth
	// This fixes the race condition where the parameter might be empty
	actualSessionID := msg.SessionID
	if actualSessionID == "" {
		t.logger.WarnIf("No session ID in attestation message, using parameter",
			zap.String("session_id", sessionID))
		actualSessionID = sessionID
	}

	t.logger.InfoIf("Processing attestation request",
		zap.String("session_id", actualSessionID))

	// Get attestation from enclave manager if available
	if t.signingKeyPair == nil {
		t.logger.Error("No signing key pair available for attestation",
			zap.String("session_id", actualSessionID))
		t.sendAttestationResponseToClient(actualSessionID, nil, false, "No signing key pair available")
		return
	}

	// Generate attestation document using enclave manager
	publicKeyDER, err := t.signingKeyPair.GetPublicKeyDER()
	if err != nil {
		t.logger.Error("Failed to get public key DER for attestation",
			zap.String("session_id", actualSessionID),
			zap.Error(err))
		t.sendAttestationResponseToClient(actualSessionID, nil, false, "Failed to get public key")
		return
	}

	// Create user data containing the hex-encoded ECDSA public key
	userData := fmt.Sprintf("tee_t_public_key:%x", publicKeyDER)
	t.logger.InfoIf("Including ECDSA public key in attestation",
		zap.String("session_id", actualSessionID),
		zap.Int("public_key_der_bytes", len(publicKeyDER)))

	// Generate attestation document using enclave manager
	if t.enclaveManager == nil {
		t.logger.Error("No enclave manager available for attestation",
			zap.String("session_id", actualSessionID))
		t.sendAttestationResponseToClient(actualSessionID, nil, false, "No enclave manager available")
		return
	}

	attestationDoc, err := t.enclaveManager.GenerateAttestation(context.Background(), []byte(userData))
	if err != nil {
		t.logger.Error("Failed to generate attestation document",
			zap.String("session_id", actualSessionID),
			zap.Error(err))
		t.sendAttestationResponseToClient(actualSessionID, nil, false, fmt.Sprintf("Failed to generate attestation: %v", err))
		return
	}

	t.logger.InfoIf("Generated attestation document",
		zap.String("session_id", actualSessionID),
		zap.Int("attestation_bytes", len(attestationDoc)))

	// Send successful response
	t.sendAttestationResponseToClient(actualSessionID, attestationDoc, true, "")
}

// sendAttestationResponseToClient sends attestation response to client (request ID removed)
func (t *TEET) sendAttestationResponseToClient(sessionID string, attestationDoc []byte, success bool, errorMessage string) {
	response := shared.AttestationResponseData{
		AttestationDoc: attestationDoc,
		Success:        success,
		ErrorMessage:   errorMessage,
	}

	msg := shared.CreateSessionMessage(shared.MsgAttestationResponse, sessionID, response)
	if err := t.sendMessageToClientSession(sessionID, msg); err != nil {
		t.logger.Error("Failed to send attestation response",
			zap.String("session_id", sessionID),
			zap.Error(err))
	}
}

// sendErrorToClientSession sends an error message to a client session
func (t *TEET) sendErrorToClientSession(sessionID, errMsg string) {
	errorData := shared.ErrorData{Message: errMsg}
	errorMsg := shared.CreateSessionMessage(shared.MsgError, sessionID, errorData)
	if err := t.sessionManager.RouteToClient(sessionID, errorMsg); err != nil {
		t.logger.Error("Failed to send error message to client session",
			zap.String("session_id", sessionID),
			zap.Error(err))
	}
}

// Helper function to detect network errors that occur during normal shutdown
func isNetworkShutdownError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "broken pipe")
}

// Single Session Mode: Transcript collection methods

// addToTranscriptForSessionWithType safely adds a packet with explicit type to the session's transcript.
func (t *TEET) addToTranscriptForSessionWithType(sessionID string, packet []byte, packetType string) {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.logger.Error("Failed to get session for transcript",
			zap.String("session_id", sessionID),
			zap.Error(err))
		return
	}

	session.TranscriptMutex.Lock()
	defer session.TranscriptMutex.Unlock()

	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)

	session.TranscriptPackets = append(session.TranscriptPackets, pktCopy)
	session.TranscriptPacketTypes = append(session.TranscriptPacketTypes, packetType)

	t.logger.DebugIf("Added packet to session transcript",
		zap.String("session_id", sessionID),
		zap.Int("packet_bytes", len(packet)),
		zap.String("packet_type", packetType),
		zap.Int("total_packets", len(session.TranscriptPackets)))
}

// addToTranscriptForSession safely adds a packet to the session's transcript collection
func (t *TEET) addToTranscriptForSession(sessionID string, packet []byte) {
	t.addToTranscriptForSessionWithType(sessionID, packet, shared.TranscriptPacketTypeTLSRecord)
}

// getTranscriptForSession safely returns a copy of the session's transcript
func (t *TEET) getTranscriptForSession(sessionID string) [][]byte {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.logger.Error("Failed to get session for transcript retrieval",
			zap.String("session_id", sessionID),
			zap.Error(err))
		return nil
	}

	session.TranscriptMutex.Lock()
	defer session.TranscriptMutex.Unlock()

	// Return a copy to avoid external modification
	transcriptCopy := make([][]byte, len(session.TranscriptPackets))
	for i, packet := range session.TranscriptPackets {
		packetCopy := make([]byte, len(packet))
		copy(packetCopy, packet)
		transcriptCopy[i] = packetCopy
	}

	return transcriptCopy
}

// Single Session Mode: Finished command tracking

// handleFinishedFromClientSession handles finished messages from clients
func (t *TEET) handleFinishedFromClientSession(sessionID string, msg *shared.Message) {
	t.logger.InfoIf("Handling finished message from client",
		zap.String("session_id", sessionID))

	var finishedMsg shared.FinishedMessage
	if err := msg.UnmarshalData(&finishedMsg); err != nil {
		t.logger.Error("Failed to unmarshal finished message from client",
			zap.String("session_id", sessionID),
			zap.Error(err))
		return
	}

	// Note: Source field removed - message context determines source

	t.logger.InfoIf("Received finished command from client",
		zap.String("session_id", sessionID))

	// Update finished state for this session
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.logger.Error("Failed to get session for finished tracking",
			zap.String("session_id", sessionID),
			zap.Error(err))
		return
	}

	session.FinishedStateMutex.Lock()
	session.ClientFinished = true
	session.FinishedStateMutex.Unlock()

	// Check if we should process the finished command
	t.checkFinishedCondition(sessionID)
}

// handleFinishedFromTEEKSession handles finished messages from TEE_K
func (t *TEET) handleFinishedFromTEEKSession(msg *shared.Message) {
	t.logger.InfoIf("Handling finished message from TEE_K",
		zap.String("session_id", msg.SessionID))

	var finishedMsg shared.FinishedMessage
	if err := msg.UnmarshalData(&finishedMsg); err != nil {
		t.logger.Error("Failed to unmarshal finished message from TEE_K",
			zap.String("session_id", msg.SessionID),
			zap.Error(err))
		return
	}

	// Note: Source field removed - message context determines source

	t.logger.InfoIf("Received finished command from TEE_K",
		zap.String("session_id", msg.SessionID))

	sessionID := msg.SessionID

	// Update finished state for this session
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.logger.Error("Failed to get session for TEE_K finished tracking",
			zap.String("session_id", sessionID),
			zap.Error(err))
		return
	}

	session.FinishedStateMutex.Lock()
	session.TEEKFinished = true
	session.FinishedStateMutex.Unlock()

	// Check if we should process the finished command
	t.checkFinishedCondition(sessionID)
}

// checkFinishedCondition checks if both client and TEE_K have sent finished messages
func (t *TEET) checkFinishedCondition(sessionID string) {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.logger.Error("Failed to get session for finished condition check",
			zap.String("session_id", sessionID),
			zap.Error(err))
		return
	}

	session.FinishedStateMutex.Lock()
	clientFinished := session.ClientFinished
	teekFinished := session.TEEKFinished
	session.FinishedStateMutex.Unlock()

	if teekFinished {
		t.logger.InfoIf("TEE_K has sent finished - starting transcript signing",
			zap.String("session_id", sessionID))

		// Generate and sign transcript from session
		transcript := t.getTranscriptForSession(sessionID)
		if len(transcript) == 0 {
			t.logger.WarnIf("No transcript packets to sign for session",
				zap.String("session_id", sessionID))
			return
		}

		if t.signingKeyPair == nil {
			t.logger.Error("No signing key pair available for transcript signing",
				zap.String("session_id", sessionID))
			return
		}

		signature, err := t.signingKeyPair.SignTranscript(transcript)
		if err != nil {
			t.logger.Error("Failed to sign transcript",
				zap.String("session_id", sessionID),
				zap.Error(err))
			return
		}

		t.logger.InfoIf("Successfully signed transcript",
			zap.String("session_id", sessionID),
			zap.Int("total_packets", len(transcript)),
			zap.Int("signature_bytes", len(signature)))

		// Send "finished" response to TEE_K
		responseMsg := shared.FinishedMessage{}

		finishedResponse := shared.CreateSessionMessage(shared.MsgFinished, sessionID, responseMsg)
		if err := t.sendMessageToTEEKForSession(sessionID, finishedResponse); err != nil {
			t.logger.Error("Failed to send finished response to TEE_K",
				zap.String("session_id", sessionID),
				zap.Error(err))
			return
		}

		t.logger.InfoIf("Sent finished response to TEE_K",
			zap.String("session_id", sessionID))

		// Get public key in DER format
		publicKeyDER, err := t.signingKeyPair.GetPublicKeyDER()
		if err != nil {
			t.logger.Error("Failed to get public key DER for signed transcript",
				zap.String("session_id", sessionID),
				zap.Error(err))
			return
		}

		signedTranscript := shared.SignedTranscript{
			Packets:   transcript,
			Signature: signature,
			PublicKey: publicKeyDER,
		}

		// Send signed transcript to client
		transcriptMsg := shared.CreateSessionMessage(shared.MsgSignedTranscript, sessionID, signedTranscript)
		if err := t.sendMessageToClientSession(sessionID, transcriptMsg); err != nil {
			t.logger.Error("Failed to send signed transcript to client",
				zap.String("session_id", sessionID),
				zap.Error(err))
			return
		}

		t.logger.InfoIf("Sent signed transcript to client",
			zap.String("session_id", sessionID))

		// No need to clean up finished state - it will be cleaned up when session is closed
	} else {
		t.logger.DebugIf("Waiting for finished from both parties",
			zap.String("session_id", sessionID),
			zap.Bool("client_finished", clientFinished),
			zap.Bool("teek_finished", teekFinished))
	}
}

// Handler methods
