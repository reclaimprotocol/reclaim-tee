package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"tee-mpc/minitls"
	teeproto "tee-mpc/proto"
	"tee-mpc/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

var teetUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connections from any origin
	},
}

// TEETSessionState holds TEE_T specific session state
type TEETSessionState struct {
	// TEE_T specific connection state
	TEETClientConn *websocket.Conn

	// TEE_T specific redaction state
	KeyShare    []byte
	CipherSuite uint16

	// TEE_T specific pending request state
	PendingEncryptedRequest *shared.EncryptedRequestData
	TEETConnForPending      *websocket.Conn
}

// TEETSessionManager extends shared session manager with TEE_T specific state
type TEETSessionManager struct {
	*shared.SessionManager
	teetStates map[string]*TEETSessionState
	stateMutex sync.Mutex
}

// NewTEETSessionManager creates a new TEE_T session manager
func NewTEETSessionManager() *TEETSessionManager {
	return &TEETSessionManager{
		SessionManager: shared.NewSessionManager(),
		teetStates:     make(map[string]*TEETSessionState),
	}
}

// GetTEETSessionState gets TEE_T specific state for a session
func (t *TEETSessionManager) GetTEETSessionState(sessionID string) (*TEETSessionState, error) {
	t.stateMutex.Lock()
	defer t.stateMutex.Unlock()

	state, exists := t.teetStates[sessionID]
	if !exists {
		return nil, fmt.Errorf("TEE_T session state not found for session %s", sessionID)
	}
	return state, nil
}

// SetTEETSessionState sets TEE_T specific state for a session
func (t *TEETSessionManager) SetTEETSessionState(sessionID string, state *TEETSessionState) {
	t.stateMutex.Lock()
	defer t.stateMutex.Unlock()
	t.teetStates[sessionID] = state
}

// RemoveTEETSessionState removes TEE_T specific state for a session
func (t *TEETSessionManager) RemoveTEETSessionState(sessionID string) {
	t.stateMutex.Lock()
	defer t.stateMutex.Unlock()
	delete(t.teetStates, sessionID)
}

// Override CloseSession to also clean up TEE_T state
func (t *TEETSessionManager) CloseSession(sessionID string) error {
	t.RemoveTEETSessionState(sessionID)
	return t.SessionManager.CloseSession(sessionID)
}

// TEET represents the TEE_T (Execution Environment for Transcript generation)
type TEET struct {
	port int

	// Session management
	sessionManager *TEETSessionManager

	// Logging and error handling
	logger            *shared.Logger
	sessionTerminator *shared.SessionTerminator

	ready bool

	// Single Session Mode: ECDSA signing keys
	signingKeyPair *shared.SigningKeyPair // ECDSA key pair for signing transcripts

	// Enclave manager for attestation generation
	enclaveManager *shared.EnclaveManager
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
			logger.Fatal("CRITICAL: Failed to generate signing key pair", zap.Error(err))
		}
		// Fallback if logger is nil
		log.Fatalf("[TEE_T] CRITICAL: Failed to generate signing key pair: %v", err)
	}
	if logger != nil {
		logger.InfoIf("Generated ECDSA signing key pair", zap.String("curve", "P-256"))
	}

	return &TEET{
		port:              port,
		sessionManager:    NewTEETSessionManager(),
		logger:            logger,
		sessionTerminator: sessionTerminator,
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

func (t *TEET) getTEETSessionState(sessionID string) (*TEETSessionState, error) {
	return t.sessionManager.GetTEETSessionState(sessionID)
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

		var env teeproto.Envelope
		if err := proto.Unmarshal(msgBytes, &env); err != nil {
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
		// Map to shared message for existing handlers
		var msg *shared.Message
		switch p := env.Payload.(type) {
		case *teeproto.Envelope_TeetReady:
			msg = &shared.Message{SessionID: env.GetSessionId(), Type: shared.MsgTEETReady, Data: shared.TEETReadyData{Success: p.TeetReady.GetSuccess()}}
		case *teeproto.Envelope_RedactionStreams:
			msg = &shared.Message{SessionID: env.GetSessionId(), Type: shared.MsgRedactionStreams, Data: shared.RedactionStreamsData{Streams: p.RedactionStreams.GetStreams(), CommitmentKeys: p.RedactionStreams.GetCommitmentKeys()}}
		case *teeproto.Envelope_AttestationRequest:
			msg = &shared.Message{SessionID: env.GetSessionId(), Type: shared.MsgAttestationRequest, Data: shared.AttestationRequestData{}}
		case *teeproto.Envelope_Finished:
			msg = &shared.Message{SessionID: env.GetSessionId(), Type: shared.MsgFinished, Data: shared.FinishedMessage{}}
		case *teeproto.Envelope_BatchedEncryptedResponses:
			var arr []shared.EncryptedResponseData
			for _, r := range p.BatchedEncryptedResponses.GetResponses() {
				arr = append(arr, shared.EncryptedResponseData{EncryptedData: r.GetEncryptedData(), Tag: r.GetTag(), RecordHeader: r.GetRecordHeader(), SeqNum: r.GetSeqNum(), CipherSuite: uint16(r.GetCipherSuite()), ExplicitIV: r.GetExplicitIv()})
			}
			msg = &shared.Message{SessionID: env.GetSessionId(), Type: shared.MsgBatchedEncryptedResponses, Data: shared.BatchedEncryptedResponseData{Responses: arr, SessionID: p.BatchedEncryptedResponses.GetSessionId(), TotalCount: int(p.BatchedEncryptedResponses.GetTotalCount())}}
		default:
			t.sendErrorToClient(conn, "Unknown message type")
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

				// Initialize TEE_T session state
				teetState := &TEETSessionState{
					TEETClientConn: conn,
				}
				t.sessionManager.SetTEETSessionState(sessionID, teetState)
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
			// Attestation requests no longer supported - attestations are included in SignedMessage
			t.logger.InfoIf("Ignoring legacy attestation request - attestations now included in SignedMessage", zap.String("session_id", sessionID))
			t.sendErrorToClientSession(sessionID, "Attestation requests deprecated - use SignedMessage")
		case shared.MsgFinished:
			t.logger.DebugIf("Handling MsgFinished from TEE_K", zap.String("session_id", sessionID))
			t.handleFinishedFromTEEKSession(msg)

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

	t.logger.InfoIf("TEE_K connection established", zap.String("remote_addr", conn.RemoteAddr().String()))

	// Track active sessions on this connection for cleanup
	activeSessions := make(map[string]bool)
	var activeSessionsMutex sync.RWMutex

	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				t.logger.InfoIf("TEE_K disconnected normally")
			} else if !isNetworkShutdownError(err) {
				t.logger.Error("TEE_K connection error", zap.Error(err), zap.String("remote_addr", r.RemoteAddr))
			}
			break
		}

		var env teeproto.Envelope
		if err := proto.Unmarshal(msgBytes, &env); err != nil {
			t.logger.Error("Failed to parse message from TEE_K",
				zap.Error(err),
				zap.String("remote_addr", r.RemoteAddr),
				zap.Int("message_size", len(msgBytes)))
			t.sendErrorToTEEKForSession("", conn, fmt.Sprintf("Failed to parse message: %v", err))
			continue // Skip invalid messages instead of terminating connection
		}

		// Get session ID from envelope - this supports multiple concurrent sessions
		sessionID := env.GetSessionId()
		if sessionID == "" {
			t.logger.Error("Missing session ID in message from TEE_K", zap.String("remote_addr", r.RemoteAddr))
			t.sendErrorToTEEKForSession("", conn, "Missing session ID")
			continue
		}

		var msg *shared.Message
		switch p := env.Payload.(type) {
		case *teeproto.Envelope_SessionCreated:
			msg = &shared.Message{SessionID: sessionID, Type: shared.MsgSessionCreated, Data: map[string]interface{}{"session_id": sessionID}}
			// Track this session on this connection
			activeSessionsMutex.Lock()
			activeSessions[sessionID] = true
			activeSessionsMutex.Unlock()
			t.logger.InfoIf("New session started on TEE_K connection", zap.String("session_id", sessionID))
		case *teeproto.Envelope_KeyShareRequest:
			msg = &shared.Message{SessionID: sessionID, Type: shared.MsgKeyShareRequest, Data: shared.KeyShareRequestData{CipherSuite: uint16(p.KeyShareRequest.GetCipherSuite()), KeyLength: int(p.KeyShareRequest.GetKeyLength()), IVLength: int(p.KeyShareRequest.GetIvLength())}}
		case *teeproto.Envelope_EncryptedRequest:
			var rr []shared.RequestRedactionRange
			for _, r := range p.EncryptedRequest.GetRedactionRanges() {
				rr = append(rr, shared.RequestRedactionRange{Start: int(r.GetStart()), Length: int(r.GetLength()), Type: r.GetType(), RedactionBytes: r.GetRedactionBytes()})
			}
			msg = &shared.Message{SessionID: sessionID, Type: shared.MsgEncryptedRequest, Data: shared.EncryptedRequestData{EncryptedData: p.EncryptedRequest.GetEncryptedData(), TagSecrets: p.EncryptedRequest.GetTagSecrets(), Commitments: p.EncryptedRequest.GetCommitments(), CipherSuite: uint16(p.EncryptedRequest.GetCipherSuite()), SeqNum: p.EncryptedRequest.GetSeqNum(), RedactionRanges: rr}}
		case *teeproto.Envelope_Finished:
			msg = &shared.Message{SessionID: sessionID, Type: shared.MsgFinished, Data: shared.FinishedMessage{}}
		case *teeproto.Envelope_BatchedTagSecrets:
			var ts []struct {
				TagSecrets []byte `json:"tag_secrets"`
				SeqNum     uint64 `json:"seq_num"`
			}
			for _, tsec := range p.BatchedTagSecrets.GetTagSecrets() {
				ts = append(ts, struct {
					TagSecrets []byte `json:"tag_secrets"`
					SeqNum     uint64 `json:"seq_num"`
				}{TagSecrets: tsec.GetTagSecrets(), SeqNum: tsec.GetSeqNum()})
			}
			msg = &shared.Message{SessionID: sessionID, Type: shared.MsgBatchedTagSecrets, Data: shared.BatchedTagSecretsData{TagSecrets: ts, SessionID: sessionID, TotalCount: int(p.BatchedTagSecrets.GetTotalCount())}}
		default:
			t.logger.Error("Unknown message type from TEE_K",
				zap.String("session_id", sessionID),
				zap.String("remote_addr", r.RemoteAddr))
			t.sendErrorToTEEKForSession(sessionID, conn, "Unknown message type from TEE_K")
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

	// Clean up all active sessions when TEE_K disconnects
	activeSessionsMutex.RLock()
	sessionCount := len(activeSessions)
	activeSessionsMutex.RUnlock()

	if sessionCount > 0 {
		t.logger.InfoIf("Cleaning up sessions due to TEE_K disconnect", zap.Int("session_count", sessionCount))
		activeSessionsMutex.RLock()
		for sessionID := range activeSessions {
			// Note: we don't close the session here as the client may still be connected
			// The session cleanup will be handled when the client disconnects
			t.sessionTerminator.CleanupSession(sessionID)
		}
		activeSessionsMutex.RUnlock()
	}
}

// Session-aware client handler methods

func (t *TEET) handleTEETReadySession(sessionID string, msg *shared.Message) {
	if sessionID == "" {
		if t.sessionTerminator.ProtocolViolation("", shared.ReasonMissingSessionID,
			fmt.Errorf("TEE_T ready message missing session ID")) {
			return
		}
		return
	}

	t.logger.InfoIf("Handling TEE_T ready for session", zap.String("session_id", sessionID))

	// Delegate to handler with the client connection
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		if t.sessionTerminator.ZeroToleranceError(sessionID, shared.ReasonSessionNotFound, err) {
			return
		}
		return
	}

	wsConn := session.ClientConn.(*shared.WSConnection)
	t.handleTEETReady(wsConn.GetWebSocketConn(), msg)
}

func (t *TEET) handleRedactionStreamsSession(sessionID string, msg *shared.Message) {
	if sessionID == "" {
		if t.sessionTerminator.ProtocolViolation("", shared.ReasonMissingSessionID,
			fmt.Errorf("redaction streams message missing session ID")) {
			return
		}
		return
	}

	t.logger.InfoIf("Handling redaction streams for session", zap.String("session_id", sessionID))

	var streamsData shared.RedactionStreamsData
	if err := msg.UnmarshalData(&streamsData); err != nil {
		if t.sessionTerminator.ProtocolViolation(sessionID, shared.ReasonMessageParsingFailed, err,
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
		if t.sessionTerminator.ZeroToleranceError(sessionID, shared.ReasonSessionNotFound, err) {
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
	teetState, err := t.getTEETSessionState(sessionID)
	if err == nil && teetState.PendingEncryptedRequest != nil {
		t.logger.InfoIf("Processing pending encrypted request with newly received streams", zap.String("session_id", sessionID))

		// Process pending request if available
		if teetState.TEETConnForPending != nil {
			t.processEncryptedRequestWithStreamsForSession(sessionID, teetState.PendingEncryptedRequest, teetState.TEETConnForPending)
		}

		// Clear pending request
		teetState.PendingEncryptedRequest = nil
		teetState.TEETConnForPending = nil
	}

	// Send verification response to client using session routing
	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_RedactionVerification{RedactionVerification: &teeproto.RedactionVerification{Success: true, Message: "Redaction streams verified and stored"}},
	}
	if err := t.sessionManager.RouteToClient(sessionID, env); err != nil {
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
			ExplicitIV   []byte `json:"explicit_iv,omitempty"`
		}{
			Length:       len(encryptedResp.EncryptedData),
			RecordHeader: encryptedResp.RecordHeader,
			SeqNum:       encryptedResp.SeqNum,
			ExplicitIV:   encryptedResp.ExplicitIV,
		}
		responseLengths = append(responseLengths, lengthData)
	}
	session.ResponseState.ResponsesMutex.Unlock()

	t.logger.InfoIf("BATCHING: Processed encrypted responses",
		zap.String("session_id", sessionID),
		zap.Int("total_count", len(batchedResponses.Responses)))

	// Send batched lengths to TEE_K
	// Convert lengths to protobuf format
	var lengths []*teeproto.BatchedResponseLengths_Length
	for _, l := range responseLengths {
		lengths = append(lengths, &teeproto.BatchedResponseLengths_Length{
			Length:       int32(l.Length),
			RecordHeader: l.RecordHeader,
			SeqNum:       l.SeqNum,
			ExplicitIv:   l.ExplicitIV,
		})
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_BatchedResponseLengths{
			BatchedResponseLengths: &teeproto.BatchedResponseLengths{
				Lengths:    lengths,
				SessionId:  sessionID,
				TotalCount: int32(len(responseLengths)),
			},
		},
	}

	if err := t.sessionManager.RouteToTEEK(sessionID, env); err != nil {
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

	// Store in TEE_T session state
	// Get TEE_T session state
	teetState, err := t.getTEETSessionState(sessionID)
	if err != nil {
		t.logger.Error("Failed to get TEE_T session state", zap.String("session_id", sessionID), zap.Error(err))
		return
	}

	teetState.KeyShare = keyShare
	teetState.CipherSuite = keyReq.CipherSuite

	// Global state removed - using session state only

	t.logger.InfoIf("Generated key share for session",
		zap.String("session_id", sessionID),
		zap.Int("key_length", len(keyShare)),
		zap.Uint16("cipher_suite", keyReq.CipherSuite))

	// Send key share response
	// Send protobuf key share response to TEE_K
	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_KeyShareResponse{KeyShareResponse: &teeproto.KeyShareResponse{KeyShare: keyShare, Success: true}},
	}
	if data, err := proto.Marshal(env); err == nil {
		wsConn := session.TEEKConn.(*shared.WSConnection)
		if err := wsConn.GetWebSocketConn().WriteMessage(websocket.BinaryMessage, data); err != nil {
			t.logger.Error("Failed to send key share response",
				zap.String("session_id", sessionID),
				zap.Error(err))
		}
	} else {
		t.logger.Error("Failed to marshal key share response envelope",
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
		teetState, err := t.getTEETSessionState(sessionID)
		if err != nil {
			t.logger.Error("Failed to get TEE_T session state", zap.String("session_id", sessionID), zap.Error(err))
			return
		}

		teetState.PendingEncryptedRequest = &encReq

		// Store TEE_K connection for pending request in session state
		wsConn := session.TEEKConn.(*shared.WSConnection)
		teetState.TEETConnForPending = wsConn.GetWebSocketConn()
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
	// Convert verifications to protobuf format
	var pbVerifications []*teeproto.BatchedTagVerifications_Verification
	for _, v := range verifications {
		pbVerifications = append(pbVerifications, &teeproto.BatchedTagVerifications_Verification{
			Success: v.Success,
			SeqNum:  v.SeqNum,
			Message: v.Message,
		})
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_BatchedTagVerifications{
			BatchedTagVerifications: &teeproto.BatchedTagVerifications{
				Verifications: pbVerifications,
				SessionId:     sessionID,
				TotalCount:    int32(totalCount),
				AllSuccessful: allSuccessful,
			},
		},
	}

	// Send batched verification results to TEE_K for decryption stream generation
	// Note: Client no longer receives this redundant message - success is implied when decryption streams arrive
	if err := t.sessionManager.RouteToTEEK(sessionID, env); err != nil {
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
	TagSecrets []byte `json:"tag_secrets"`
	SeqNum     uint64 `json:"seq_num"`
}) shared.ResponseTagVerificationData {
	var additionalData []byte
	cipherSuite := encryptedResp.CipherSuite

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
	t.logger.InfoIf("Sending reconstructed encrypted data to client session",
		zap.String("session_id", sessionID),
		zap.Int("data_length", len(reconstructedData)),
		zap.Binary("first_32_bytes", reconstructedData[:min(32, len(reconstructedData))]))

	envResp := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_EncryptedData{EncryptedData: &teeproto.EncryptedDataResponse{EncryptedData: reconstructedData, AuthTag: authTag, Success: true}},
	}
	if err := t.sessionManager.RouteToClient(sessionID, envResp); err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonNetworkFailure, err,
			zap.String("target", "client")) {
			return
		}
		return
	}

}

// sendMessageToClientSession sends a message to a specific client by session ID
func (t *TEET) sendMessageToClientSession(sessionID string, msg *shared.Message) error {
	if sessionID == "" {
		return fmt.Errorf("session ID is required")
	}
	// Only used for attestation and transcripts here; map manually as needed
	switch msg.Type {
	case shared.MsgAttestationResponse:
		var d shared.AttestationResponseData
		if err := msg.UnmarshalData(&d); err != nil {
			return err
		}
		env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
			Payload: &teeproto.Envelope_AttestationResponse{AttestationResponse: &teeproto.AttestationResponse{AttestationDoc: d.AttestationDoc, Success: d.Success, ErrorMessage: d.ErrorMessage, Source: d.Source}},
		}
		return t.sessionManager.RouteToClient(sessionID, env)
	case shared.MsgSignedTranscript:
		// Legacy path still used in some flows; skip mapping for now
		return fmt.Errorf("MsgSignedTranscript route should be migrated to SignedMessage")
	default:
		return fmt.Errorf("unsupported message type for client routing: %s", msg.Type)
	}
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

	// Send via protobuf envelope (build directly for supported types)
	if ws, ok := session.TEEKConn.(*shared.WSConnection); ok {
		var env *teeproto.Envelope
		switch msg.Type {
		case shared.MsgBatchedResponseLengths:
			var d shared.BatchedResponseLengthData
			if err := msg.UnmarshalData(&d); err != nil {
				return err
			}
			var lens []*teeproto.BatchedResponseLengths_Length
			for _, l := range d.Lengths {
				lens = append(lens, &teeproto.BatchedResponseLengths_Length{Length: int32(l.Length), RecordHeader: l.RecordHeader, SeqNum: l.SeqNum, ExplicitIv: l.ExplicitIV})
			}
			env = &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(), Payload: &teeproto.Envelope_BatchedResponseLengths{BatchedResponseLengths: &teeproto.BatchedResponseLengths{Lengths: lens, SessionId: d.SessionID, TotalCount: int32(d.TotalCount)}}}
		case shared.MsgBatchedTagSecrets:
			var d shared.BatchedTagSecretsData
			if err := msg.UnmarshalData(&d); err != nil {
				return err
			}
			var tags []*teeproto.BatchedTagSecrets_TagSecret
			for _, tsec := range d.TagSecrets {
				tags = append(tags, &teeproto.BatchedTagSecrets_TagSecret{TagSecrets: tsec.TagSecrets, SeqNum: tsec.SeqNum})
			}
			env = &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(), Payload: &teeproto.Envelope_BatchedTagSecrets{BatchedTagSecrets: &teeproto.BatchedTagSecrets{TagSecrets: tags, SessionId: d.SessionID, TotalCount: int32(d.TotalCount)}}}
		case shared.MsgBatchedTagVerifications:
			var d shared.BatchedTagVerificationData
			if err := msg.UnmarshalData(&d); err != nil {
				return err
			}
			var vers []*teeproto.BatchedTagVerifications_Verification
			for _, v := range d.Verifications {
				vers = append(vers, &teeproto.BatchedTagVerifications_Verification{Success: v.Success, SeqNum: v.SeqNum, Message: v.Message})
			}
			env = &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(), Payload: &teeproto.Envelope_BatchedTagVerifications{BatchedTagVerifications: &teeproto.BatchedTagVerifications{Verifications: vers, SessionId: d.SessionID, TotalCount: int32(d.TotalCount), AllSuccessful: d.AllSuccessful}}}
		default:
			return fmt.Errorf("unsupported TEEK send type: %s", msg.Type)
		}
		data, err := proto.Marshal(env)
		if err != nil {
			return err
		}
		return ws.GetWebSocketConn().WriteMessage(websocket.BinaryMessage, data)
	}
	return fmt.Errorf("unsupported TEE_K connection type")
}

func (t *TEET) sendErrorToTEEKForSession(sessionID string, conn *websocket.Conn, errMsg string) {
	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Error{Error: &teeproto.ErrorData{Message: errMsg}},
	}
	data, err := proto.Marshal(env)
	if err == nil {
		if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
			t.logger.Error("Failed to send error message to TEE_K",
				zap.String("session_id", sessionID),
				zap.Error(err))
		}
	} else {
		t.logger.Error("Failed to send error message to TEE_K",
			zap.String("session_id", sessionID),
			zap.Error(err))
	}
}

func (t *TEET) sendErrorToClient(conn *websocket.Conn, errMsg string) {
	env := &teeproto.Envelope{TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Error{Error: &teeproto.ErrorData{Message: errMsg}},
	}
	if data, err := proto.Marshal(env); err == nil {
		if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
			t.logger.Error("Failed to send error message to client", zap.Error(err))
		}
	} else {
		t.logger.Error("Failed to send error message to client", zap.Error(err))
	}
}

func (t *TEET) sendErrorToTEEK(conn *websocket.Conn, errMsg string) {
	env := &teeproto.Envelope{TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Error{Error: &teeproto.ErrorData{Message: errMsg}},
	}
	if data, err := proto.Marshal(env); err == nil {
		if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
			t.logger.Error("Failed to send error message to TEE_K", zap.Error(err))
		}
	} else {
		t.logger.Error("Failed to marshal error envelope to TEE_K", zap.Error(err))
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
// This is a critical security function - any failure must terminate the session
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
	// Send protobuf envelope back to client
	env := &teeproto.Envelope{TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_TeetReady{TeetReady: &teeproto.TEETReady{Success: true}},
	}
	if data, err := proto.Marshal(env); err == nil {
		if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
			t.logger.Error("Failed to send TEE_T ready response", zap.Error(err))
		}
	} else {
		t.logger.Error("Failed to marshal TEE_T ready envelope", zap.Error(err))
	}
}

// DEPRECATED: Attestation requests removed - attestations now included in SignedMessage

// DEPRECATED: Attestation response functions removed - attestations now included in SignedMessage

// sendErrorToClientSession sends an error message to a client session
func (t *TEET) sendErrorToClientSession(sessionID, errMsg string) {
	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Error{Error: &teeproto.ErrorData{Message: errMsg}},
	}
	if err := t.sessionManager.RouteToClient(sessionID, env); err != nil {
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

// checkFinishedCondition checks if TEE_K has sent finished message
func (t *TEET) checkFinishedCondition(sessionID string) {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.logger.Error("Failed to get session for finished condition check",
			zap.String("session_id", sessionID),
			zap.Error(err))
		return
	}

	session.FinishedStateMutex.Lock()
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

		// Get public key in DER format
		publicKeyDER, err := t.signingKeyPair.GetPublicKeyDER()
		if err != nil {
			t.logger.Error("Failed to get public key DER for signed transcript",
				zap.String("session_id", sessionID),
				zap.Error(err))
			return
		}

		// SECURITY FIX: Create protobuf body and sign it directly
		tOutput := &teeproto.TOutputPayload{Packets: transcript}
		body, err := proto.Marshal(tOutput)
		if err != nil {
			t.logger.Error("Failed to marshal TOutputPayload",
				zap.String("session_id", sessionID),
				zap.Error(err))
			return
		}

		// Sign the exact protobuf body bytes
		signature, err := t.signingKeyPair.SignData(body)
		if err != nil {
			t.logger.Error("Failed to sign protobuf body",
				zap.String("session_id", sessionID),
				zap.Error(err))
			return
		}

		t.logger.InfoIf("Successfully signed protobuf body",
			zap.String("session_id", sessionID),
			zap.Int("total_packets", len(transcript)),
			zap.Int("body_bytes", len(body)),
			zap.Int("signature_bytes", len(signature)))

		// Generate attestation report for enclave mode, or use public key for standalone
		var attestationReport *teeproto.AttestationReport
		var publicKeyForStandalone []byte

		if t.enclaveManager != nil {
			// Enclave mode: include attestation report
			var err error
			attestationReport, err = t.generateAttestationReport(sessionID)
			if err != nil {
				t.logger.Error("Failed to generate attestation report",
					zap.String("session_id", sessionID),
					zap.Error(err))
				return
			}
			t.logger.InfoIf("Including attestation report in SignedMessage", zap.String("session_id", sessionID))
		} else {
			// Standalone mode: include public key
			publicKeyForStandalone = publicKeyDER
			t.logger.InfoIf("Including public key in SignedMessage (standalone mode)", zap.String("session_id", sessionID))
		}

		sm := &teeproto.SignedMessage{
			BodyType:          teeproto.BodyType_BODY_TYPE_T_OUTPUT,
			Body:              body,
			PublicKey:         publicKeyForStandalone,
			Signature:         signature,
			AttestationReport: attestationReport,
		}
		env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
			Payload: &teeproto.Envelope_SignedMessage{SignedMessage: sm},
		}
		if err := t.sessionManager.RouteToClient(sessionID, env); err != nil {
			t.logger.Error("Failed to send SignedMessage (T_OUTPUT) to client",
				zap.String("session_id", sessionID),
				zap.Error(err))
			return
		}

		t.logger.InfoIf("Sent SignedMessage (T_OUTPUT) to client",
			zap.String("session_id", sessionID))

		// No need to clean up finished state - it will be cleaned up when session is closed
	} else {
		t.logger.DebugIf("Waiting for finished from TEE_K",
			zap.String("session_id", sessionID),
			zap.Bool("teek_finished", teekFinished))
	}
}

// generateAttestationReport generates an AttestationReport for enclave mode
func (t *TEET) generateAttestationReport(sessionID string) (*teeproto.AttestationReport, error) {
	// Skip in standalone mode
	if t.enclaveManager == nil {
		return nil, nil
	}

	// Get public key
	publicKeyDER, err := t.signingKeyPair.GetPublicKeyDER()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key DER: %v", err)
	}

	// Create user data containing the hex-encoded ECDSA public key
	userData := fmt.Sprintf("tee_t_public_key:%x", publicKeyDER)
	t.logger.InfoIf("Including ECDSA public key in attestation",
		zap.String("session_id", sessionID),
		zap.Int("der_bytes", len(publicKeyDER)))

	// Check attestation provider and generate accordingly
	provider := os.Getenv("ATTESTATION_PROVIDER")
	if provider == "gcp" {
		raw, err := t.enclaveManager.GenerateAttestation(context.Background(), []byte(userData))
		if err != nil {
			return nil, fmt.Errorf("failed to generate GCP attestation: %v", err)
		}

		t.logger.InfoIf("Generated GCP attestation",
			zap.String("session_id", sessionID),
			zap.Int("bytes", len(raw)))

		return &teeproto.AttestationReport{
			Type:   "gcp",
			Report: raw,
			// Public key will be extracted from report during verification
		}, nil
	} else {
		// Default to Nitro
		attestationDoc, err := t.enclaveManager.GenerateAttestation(context.Background(), []byte(userData))
		if err != nil {
			return nil, fmt.Errorf("failed to generate Nitro attestation: %v", err)
		}

		t.logger.InfoIf("Generated Nitro attestation document",
			zap.String("session_id", sessionID),
			zap.Int("bytes", len(attestationDoc)))

		return &teeproto.AttestationReport{
			Type:   "nitro",
			Report: attestationDoc,
			// Public key will be extracted from report during verification
		}, nil
	}
}

// Handler methods
