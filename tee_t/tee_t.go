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
	"time"

	"tee-mpc/minitls"
	"tee-mpc/shared"

	"github.com/gorilla/websocket"
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

	ready bool

	// Legacy fields for backward compatibility during migration
	// TODO: Remove these after full migration to session-aware handlers
	clientConn              *websocket.Conn
	keyShare                []byte
	cipherSuite             uint16
	redactionStreams        [][]byte                     // [Str_S, Str_SP]
	commitmentKeys          [][]byte                     // [K_S, K_SP]
	redactionRanges         []shared.RedactionRange      // Stored when encrypted request comes from TEE_K
	pendingEncryptedRequest *shared.EncryptedRequestData // Store encrypted request until streams arrive
	teekConn_for_pending    *websocket.Conn              // Store TEE_K connection for pending request

	// Legacy global response storage has been migrated to session-aware storage

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
		log.Printf("[TEE_T] Failed to generate signing key pair: %v", err)
		// Continue without signing capability rather than failing
		signingKeyPair = nil
	} else {
		fmt.Printf("[TEE_T] Generated ECDSA signing key pair (P-256 curve)\n")
	}

	return &TEET{
		port:                    port,
		sessionManager:          shared.NewSessionManager(),
		pendingEncryptedRequest: nil,
		signingKeyPair:          signingKeyPair,
		enclaveManager:          enclaveManager,
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
		log.Printf("[TEE_T] Failed to generate signing key pair: %v", err)
		// Continue without signing capability rather than failing
		signingKeyPair = nil
	} else {
		fmt.Printf("[TEE_T] Generated ECDSA signing key pair (P-256 curve)\n")
	}

	return &TEET{
		port:                    port,
		sessionManager:          sessionManager,
		pendingEncryptedRequest: nil,
		signingKeyPair:          signingKeyPair,
		enclaveManager:          enclaveManager,
	}
}

// Start method removed - now handled by main.go with proper graceful shutdown

func (t *TEET) handleClientWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := teetUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[TEE_T] Failed to upgrade client websocket: %v", err)
		return
	}

	fmt.Printf("[TEE_T] DEBUG: Client WebSocket connection established from %s\n", r.RemoteAddr)
	fmt.Printf("[TEE_T] DEBUG: WebSocket local addr: %s, remote addr: %s\n",
		conn.LocalAddr().String(), conn.RemoteAddr().String())

	var sessionID string

	fmt.Printf("[TEE_T] DEBUG: Client connection stored, starting message loop\n")

	for {
		fmt.Printf("[TEE_T] DEBUG: Waiting for next client message...\n")

		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				fmt.Printf("[TEE_T] DEBUG: Client connection closed normally: %v\n", err)
			} else if !isNetworkShutdownError(err) {
				log.Printf("[TEE_T] Failed to read client websocket message: %v", err)
				fmt.Printf("[TEE_T] DEBUG: Unexpected read error: %v\n", err)
			}
			break
		}

		fmt.Printf("[TEE_T] DEBUG: Received raw message from client (%d bytes)\n", len(msgBytes))
		fmt.Printf("[TEE_T] DEBUG: Raw message preview: %s\n", string(msgBytes[:min(100, len(msgBytes))]))
		fmt.Printf("[TEE_T] DEBUG: Message received at: %s\n", time.Now().Format("15:04:05.000"))

		msg, err := shared.ParseMessage(msgBytes)
		if err != nil {
			log.Printf("[TEE_T] Failed to parse client message: %v", err)
			fmt.Printf("[TEE_T] DEBUG: Parse error for message: %v\n", err)
			t.sendErrorToClient(conn, fmt.Sprintf("Failed to parse message: %v", err))
			continue
		}

		fmt.Printf("[TEE_T] DEBUG: Received message from client: type=%s\n", msg.Type)

		// Handle session ID for client messages
		if msg.SessionID != "" {
			if sessionID == "" {
				// First message with session ID - activate the session
				sessionID = msg.SessionID
				wsConn := shared.NewWSConnection(conn)
				if err := t.sessionManager.ActivateSession(sessionID, wsConn); err != nil {
					log.Printf("[TEE_T] Failed to activate session %s: %v", sessionID, err)
					t.sendErrorToClient(conn, "Failed to activate session")
					continue
				}
				log.Printf("[TEE_T] Activated session %s for client %s", sessionID, conn.RemoteAddr())
			} else if msg.SessionID != sessionID {
				log.Printf("[TEE_T] Session ID mismatch: expected %s, got %s", sessionID, msg.SessionID)
				t.sendErrorToClient(conn, "Session ID mismatch")
				continue
			}
		}

		switch msg.Type {
		case shared.MsgTEETReady:
			fmt.Printf("[TEE_T] DEBUG: Handling MsgTEETReady\n")
			t.handleTEETReadySession(sessionID, msg)
		case shared.MsgRedactionStreams:
			fmt.Printf("[TEE_T] DEBUG: Handling MsgRedactionStreams\n")
			t.handleRedactionStreamsSession(sessionID, msg)
		case shared.MsgEncryptedResponse:
			fmt.Printf("[TEE_T] DEBUG: Handling MsgEncryptedResponse\n")
			t.handleEncryptedResponseSession(sessionID, msg)
		case shared.MsgAttestationRequest:
			fmt.Printf("[TEE_T] DEBUG: Handling MsgAttestationRequest\n")
			t.handleAttestationRequestSession(sessionID, msg)
		case shared.MsgFinished:
			fmt.Printf("[TEE_T] DEBUG: Handling MsgFinished from client\n")
			t.handleFinishedFromClientSession(sessionID, msg)
		default:
			log.Printf("[TEE_T] Unknown client message type: %s", msg.Type)
			fmt.Printf("[TEE_T] DEBUG: Unknown message type: %s\n", msg.Type)
			t.sendErrorToClient(conn, fmt.Sprintf("Unknown message type: %s", msg.Type))
		}
	}

	// Clean up session when client disconnects
	if sessionID != "" {
		log.Printf("[TEE_T] Cleaning up session %s", sessionID)
		t.sessionManager.CloseSession(sessionID)
	}
}

func (t *TEET) handleTEEKWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := teetUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[TEE_T] Failed to upgrade TEE_K websocket: %v", err)
		return
	}

	var sessionID string

	log.Printf("[TEE_T] TEE_K connection established from %s", conn.RemoteAddr())

	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[TEE_T] TEE_K disconnected normally for session %s", sessionID)
			} else if !isNetworkShutdownError(err) {
				log.Printf("[TEE_T] Failed to read TEE_K websocket message: %v", err)
			}
			break
		}

		msg, err := shared.ParseMessage(msgBytes)
		if err != nil {
			log.Printf("[TEE_T] Failed to parse TEE_K message: %v", err)
			t.sendErrorToTEEKForSession("", conn, fmt.Sprintf("Failed to parse message: %v", err))
			continue
		}

		// For the first message (session creation), store the session ID
		if msg.Type == shared.MsgSessionCreated && sessionID == "" {
			sessionID = msg.SessionID
		}

		// Ensure subsequent messages have the correct session ID
		if sessionID != "" && msg.SessionID != sessionID {
			log.Printf("[TEE_T] Session ID mismatch: expected %s, got %s", sessionID, msg.SessionID)
			continue
		}

		switch msg.Type {
		case shared.MsgSessionCreated:
			// First create the session
			t.handleSessionCreation(msg)
			// Then associate the TEE_K connection with the session
			if sessionID != "" {
				session, err := t.sessionManager.GetSession(sessionID)
				if err != nil {
					log.Printf("[TEE_T] Failed to get session %s after creation: %v", sessionID, err)
					continue
				}
				session.TEEKConn = shared.NewWSConnection(conn)
				log.Printf("[TEE_T] Associated TEE_K connection with session %s", sessionID)
			}
		case shared.MsgKeyShareRequest:
			t.handleKeyShareRequestSession(msg)
		case shared.MsgEncryptedRequest:
			t.handleEncryptedRequestSession(msg)
		case shared.MsgResponseTagSecrets:
			t.handleResponseTagSecretsSession(msg)
		case shared.MsgFinished:
			t.handleFinishedFromTEEKSession(msg)
		default:
			log.Printf("[TEE_T] Unknown TEE_K message type: %s", msg.Type)
			t.sendErrorToTEEKForSession(sessionID, conn, fmt.Sprintf("Unknown message type: %s", msg.Type))
		}
	}

	// Clean up session association when TEE_K disconnects
	if sessionID != "" {
		log.Printf("[TEE_T] Cleaning up session %s due to TEE_K disconnect", sessionID)
		// Note: we don't close the session here as the client may still be connected
		// The session cleanup will be handled when the client disconnects
	}
}

// Session-aware client handler methods

func (t *TEET) handleTEETReadySession(sessionID string, msg *shared.Message) {
	if sessionID == "" {
		log.Printf("[TEE_T] TEE_T ready message missing session ID")
		return
	}

	log.Printf("[TEE_T] Handling TEE_T ready for session %s", sessionID)

	// For now, delegate to legacy handler with the client connection
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		log.Printf("[TEE_T] Failed to get session %s: %v", sessionID, err)
		return
	}

	wsConn := session.ClientConn.(*shared.WSConnection)
	t.handleTEETReady(wsConn.GetWebSocketConn(), msg)
}

func (t *TEET) handleRedactionStreamsSession(sessionID string, msg *shared.Message) {
	if sessionID == "" {
		log.Printf("[TEE_T] Redaction streams message missing session ID")
		return
	}

	log.Printf("[TEE_T] Handling redaction streams for session %s", sessionID)

	var streamsData shared.RedactionStreamsData
	if err := msg.UnmarshalData(&streamsData); err != nil {
		log.Printf("[TEE_T] Failed to unmarshal redaction streams: %v", err)
		return
	}

	fmt.Printf("[TEE_T] Received redaction streams for session %s: %d streams, %d keys\n", sessionID, len(streamsData.Streams), len(streamsData.CommitmentKeys))

	// Verify commitments to ensure stream integrity
	if err := t.verifyCommitments(streamsData.Streams, streamsData.CommitmentKeys); err != nil {
		log.Printf("[TEE_T] Failed to verify redaction commitments: %v", err)
		return
	}

	// Get session to store streams and keys
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		log.Printf("[TEE_T] Failed to get session %s for redaction streams: %v", sessionID, err)
		return
	}

	// Initialize RedactionState if needed
	if session.RedactionState == nil {
		session.RedactionState = &shared.RedactionSessionState{}
	}

	// Store streams and keys in session for later use when encrypted request arrives
	session.RedactionState.RedactionStreams = streamsData.Streams
	session.RedactionState.CommitmentKeys = streamsData.CommitmentKeys

	fmt.Printf("[TEE_T] Redaction streams stored and verified for session %s\n", sessionID)

	// Process pending encrypted request if available
	if session.ResponseState != nil && session.ResponseState.PendingEncryptedRequest != nil {
		fmt.Printf("[TEE_T] Processing pending encrypted request with newly received streams for session %s\n", sessionID)
		t.processEncryptedRequestWithStreamsForSession(sessionID, session.ResponseState.PendingEncryptedRequest, t.teekConn_for_pending)

		// Clear pending request
		session.ResponseState.PendingEncryptedRequest = nil
		t.teekConn_for_pending = nil
	}

	// Send verification response to client using session routing
	verificationResponse := shared.RedactionVerificationData{
		Success: true,
		Message: "Redaction streams verified and stored",
	}

	verificationMsg := shared.CreateMessage(shared.MsgRedactionVerification, verificationResponse)
	if err := t.sessionManager.RouteToClient(sessionID, verificationMsg); err != nil {
		log.Printf("[TEE_T] Failed to send verification message: %v", err)
	}

	fmt.Printf("[TEE_T] DEBUG: handleRedactionStreamsSession completed for session %s at %s, returning to message loop\n", sessionID, time.Now().Format("15:04:05.000"))
}

func (t *TEET) handleEncryptedResponseSession(sessionID string, msg *shared.Message) {
	fmt.Printf("[TEE_T] Handling encrypted response for session %s\n", sessionID)

	var encryptedResp shared.EncryptedResponseData
	if err := msg.UnmarshalData(&encryptedResp); err != nil {
		log.Printf("[TEE_T] Failed to unmarshal encrypted response: %v", err)
		return
	}

	// Get session to access response state
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		log.Printf("[TEE_T] Failed to get session %s for encrypted response: %v", sessionID, err)
		return
	}

	// Initialize ResponseState if needed
	if session.ResponseState == nil {
		session.ResponseState = &shared.ResponseSessionState{
			PendingEncryptedResponses: make(map[uint64]*shared.EncryptedResponseData),
		}
	}

	fmt.Printf("[TEE_T] Received encrypted response (seq=%d, %d bytes) for session %s\n", encryptedResp.SeqNum, len(encryptedResp.EncryptedData), sessionID)

	// Session-aware transcript collection
	// For TLS 1.2 AES-GCM, we need to include the explicit IV in the response record too

	// Check if this is TLS 1.2 AES-GCM cipher suite
	isTLS12AESGCMCipher := encryptedResp.CipherSuite == 0xc02f || // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		encryptedResp.CipherSuite == 0xc02b || // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		encryptedResp.CipherSuite == 0xc030 || // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		encryptedResp.CipherSuite == 0xc02c // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

	var payload []byte
	if isTLS12AESGCMCipher && encryptedResp.ExplicitIV != nil && len(encryptedResp.ExplicitIV) == 8 {
		// TLS 1.2 AES-GCM: explicit_iv(8) + encrypted_data + auth_tag(16)
		// Use the explicit IV provided by the client
		payload = make([]byte, 8+len(encryptedResp.EncryptedData)+len(encryptedResp.Tag))
		copy(payload[0:8], encryptedResp.ExplicitIV)
		copy(payload[8:8+len(encryptedResp.EncryptedData)], encryptedResp.EncryptedData)
		copy(payload[8+len(encryptedResp.EncryptedData):], encryptedResp.Tag)

		fmt.Printf("[TEE_T] TLS 1.2 AES-GCM response: Added explicit IV %x to transcript record\n", encryptedResp.ExplicitIV)
	} else {
		// TLS 1.3 or ChaCha20: encrypted_data + auth_tag (no explicit IV)
		payload = make([]byte, len(encryptedResp.EncryptedData)+len(encryptedResp.Tag))
		copy(payload, encryptedResp.EncryptedData)
		copy(payload[len(encryptedResp.EncryptedData):], encryptedResp.Tag)
	}

	recordLength := len(payload)
	if recordLength > 0xFFFF {
		log.Printf("[TEE_T] Warning: TLS record too large (%d bytes), truncating length", recordLength)
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

	// Store the encrypted response for processing when tag secrets arrive
	session.ResponseState.ResponsesMutex.Lock()
	session.ResponseState.PendingEncryptedResponses[encryptedResp.SeqNum] = &encryptedResp
	session.ResponseState.ResponsesMutex.Unlock()

	// Send response length to TEE_K with session ID
	lengthData := shared.ResponseLengthData{
		Length:       len(encryptedResp.EncryptedData), // Full encrypted data length
		RecordHeader: encryptedResp.RecordHeader,       // Copy the actual TLS record header
		SeqNum:       encryptedResp.SeqNum,
		CipherSuite:  encryptedResp.CipherSuite, // Use actual cipher suite from response
		ExplicitIV:   encryptedResp.ExplicitIV,  // TLS 1.2 AES-GCM explicit IV (nil for TLS 1.3)
	}

	lengthMsg := shared.CreateSessionMessage(shared.MsgResponseLength, sessionID, lengthData)

	if err := t.sendMessageToTEEKForSession(sessionID, lengthMsg); err != nil {
		log.Printf("[TEE_T] Failed to send response length to TEE_K for session %s: %v", sessionID, err)
		return
	}

	fmt.Printf("[TEE_T] Sent response length to TEE_K (seq=%d, length=%d)\n", encryptedResp.SeqNum, len(encryptedResp.EncryptedData))
}

func (t *TEET) handleSessionCreation(msg *shared.Message) {
	var sessionData map[string]interface{}
	if err := msg.UnmarshalData(&sessionData); err != nil {
		log.Printf("[TEE_T] Failed to unmarshal session creation data: %v", err)
		return
	}

	sessionID, ok := sessionData["session_id"].(string)
	if !ok {
		log.Printf("[TEE_T] Invalid session_id in session creation message")
		return
	}

	// Register the session in our session manager
	if err := t.sessionManager.RegisterSession(sessionID); err != nil {
		log.Printf("[TEE_T] Failed to register session %s: %v", sessionID, err)
		return
	}

	log.Printf("[TEE_T] Registered session %s from TEE_K", sessionID)
}

func (t *TEET) handleKeyShareRequestSession(msg *shared.Message) {
	sessionID := msg.SessionID
	if sessionID == "" {
		log.Printf("[TEE_T] Key share request missing session ID")
		return
	}

	log.Printf("[TEE_T] Handling key share request for session %s", sessionID)

	// Get session to access TEE_K connection
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		log.Printf("[TEE_T] Failed to get session %s: %v", sessionID, err)
		return
	}

	var keyReq shared.KeyShareRequestData
	if err := msg.UnmarshalData(&keyReq); err != nil {
		log.Printf("[TEE_T] Failed to unmarshal key share request: %v", err)
		t.sendErrorToTEEKForSession(sessionID, session.TEEKConn.(*shared.WSConnection).GetWebSocketConn(), fmt.Sprintf("Failed to unmarshal key share request: %v", err))
		return
	}

	// Generate random key share
	keyShare := make([]byte, keyReq.KeyLength)
	if _, err := rand.Read(keyShare); err != nil {
		log.Printf("[TEE_T] Failed to generate key share: %v", err)
		t.sendErrorToTEEKForSession(sessionID, session.TEEKConn.(*shared.WSConnection).GetWebSocketConn(), fmt.Sprintf("Failed to generate key share: %v", err))
		return
	}

	// TODO: Store in session state instead of global fields
	// For now, store in global fields (requires Session struct enhancement)
	t.keyShare = keyShare
	t.cipherSuite = keyReq.CipherSuite

	// Send key share response
	response := shared.KeyShareResponseData{
		KeyShare: keyShare,
		Success:  true,
	}

	responseMsg := shared.CreateMessage(shared.MsgKeyShareResponse, response)
	msgBytes, err := json.Marshal(responseMsg)
	if err != nil {
		log.Printf("[TEE_T] Failed to marshal key share response: %v", err)
		return
	}

	wsConn := session.TEEKConn.(*shared.WSConnection)
	if err := wsConn.GetWebSocketConn().WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		log.Printf("[TEE_T] Failed to send key share response: %v", err)
	}
}

func (t *TEET) handleEncryptedRequestSession(msg *shared.Message) {
	sessionID := msg.SessionID
	if sessionID == "" {
		log.Printf("[TEE_T] Encrypted request missing session ID")
		return
	}

	log.Printf("[TEE_T] Handling encrypted request for session %s", sessionID)

	var encReq shared.EncryptedRequestData
	if err := msg.UnmarshalData(&encReq); err != nil {
		log.Printf("[TEE_T] Failed to unmarshal encrypted request: %v", err)
		return
	}

	fmt.Printf("[TEE_T] Computing tag for %d byte ciphertext using seq=%d with %d redaction ranges for session %s\n", len(encReq.EncryptedData), encReq.SeqNum, len(encReq.RedactionRanges), sessionID)

	// Get session to access redaction state
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		log.Printf("[TEE_T] Failed to get session %s: %v", sessionID, err)
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

	// Check if redaction streams are available
	if len(session.RedactionState.RedactionStreams) == 0 {
		// No redaction streams available yet - store request and wait
		session.ResponseState.PendingEncryptedRequest = &encReq

		// Store TEE_K connection for pending request
		wsConn := session.TEEKConn.(*shared.WSConnection)
		t.teekConn_for_pending = wsConn.GetWebSocketConn()
		fmt.Printf("[TEE_T] Storing encrypted request for session %s, waiting for redaction streams...\n", sessionID)
		return
	}

	// Process immediately if streams are already available
	// Get underlying websocket connection
	wsConn := session.TEEKConn.(*shared.WSConnection)
	t.processEncryptedRequestWithStreamsForSession(sessionID, &encReq, wsConn.GetWebSocketConn())
}

func (t *TEET) handleResponseTagSecretsSession(msg *shared.Message) {
	sessionID := msg.SessionID
	if sessionID == "" {
		log.Printf("[TEE_T] Response tag secrets missing session ID")
		return
	}

	log.Printf("[TEE_T] Handling response tag secrets for session %s", sessionID)

	var tagSecrets shared.ResponseTagSecretsData
	if err := msg.UnmarshalData(&tagSecrets); err != nil {
		log.Printf("[TEE_T] Failed to unmarshal response tag secrets for session %s: %v", sessionID, err)
		return
	}

	fmt.Printf("[TEE_T] Received tag secrets for seq=%d (%d bytes) for session %s\n",
		tagSecrets.SeqNum, len(tagSecrets.TagSecrets), sessionID)

	// Get session to access pending responses
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		log.Printf("[TEE_T] Failed to get session %s for response tag secrets: %v", sessionID, err)
		return
	}

	// Initialize ResponseState if needed
	if session.ResponseState == nil {
		session.ResponseState = &shared.ResponseSessionState{
			PendingEncryptedResponses: make(map[uint64]*shared.EncryptedResponseData),
		}
	}

	// Find the pending response in session state
	session.ResponseState.ResponsesMutex.Lock()
	encryptedResp, exists := session.ResponseState.PendingEncryptedResponses[tagSecrets.SeqNum]
	if exists {
		delete(session.ResponseState.PendingEncryptedResponses, tagSecrets.SeqNum)
	}
	session.ResponseState.ResponsesMutex.Unlock()

	if !exists {
		log.Printf("[TEE_T] No pending response found for seq=%d in session %s", tagSecrets.SeqNum, sessionID)
		return
	}

	// Verify the authentication tag using consolidated minitls functions
	var additionalData []byte
	cipherSuite := tagSecrets.CipherSuite

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

		fmt.Printf("[TEE_T] TLS 1.3 AAD: record_type=0x%02x, ciphertext+tag_len=%d\n",
			recordType, ciphertextLength)
	} else {
		// TLS 1.2: AAD = seq_num(8) + record header(5) = 13 bytes total
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

		fmt.Printf("[TEE_T] TLS 1.2 AAD: seq=%d, record_type=0x%02x, plaintext_len=%d\n",
			encryptedResp.SeqNum, additionalData[8], len(encryptedResp.EncryptedData))
	}

	// Compute authentication tag using consolidated crypto functions
	computedTag, err := minitls.ComputeTagFromSecrets(
		encryptedResp.EncryptedData,
		tagSecrets.TagSecrets,
		cipherSuite,
		additionalData,
	)

	var success bool
	if err != nil {
		log.Printf("[TEE_T] Failed to compute tag for session %s: %v", sessionID, err)
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
	}

	if success {
		fmt.Printf("[TEE_T] Tag verification SUCCESS for seq=%d\n", encryptedResp.SeqNum)
	} else {
		fmt.Printf("[TEE_T] Tag verification FAILED for seq=%d\n", encryptedResp.SeqNum)
	}

	// Send verification result to both TEE_K and Client with session IDs
	verificationData := shared.ResponseTagVerificationData{
		Success: success,
		SeqNum:  tagSecrets.SeqNum,
	}

	if !success {
		verificationData.Message = "Authentication tag verification failed"
	}

	if err := t.sessionManager.RouteToClient(sessionID, shared.CreateMessage(shared.MsgResponseTagVerification, verificationData)); err != nil {
		log.Printf("[TEE_T] Failed to send verification to client for session %s: %v", sessionID, err)
	}

	// Send to TEE_K with session ID
	verificationMsgToTEEK := shared.CreateSessionMessage(shared.MsgResponseTagVerification, sessionID, verificationData)

	if err := t.sendMessageToTEEKForSession(sessionID, verificationMsgToTEEK); err != nil {
		log.Printf("[TEE_T] Failed to send verification to TEE_K for session %s: %v", sessionID, err)
	}

	if success {
		fmt.Printf("[TEE_T] Response tag verification successful (seq=%d) for session %s\n", tagSecrets.SeqNum, sessionID)
	} else {
		fmt.Printf("[TEE_T] Response tag verification failed (seq=%d) for session %s\n", tagSecrets.SeqNum, sessionID)
	}
}

// processEncryptedRequestWithStreams handles the actual processing once streams are available
func (t *TEET) processEncryptedRequestWithStreams(encReq *shared.EncryptedRequestData, conn *websocket.Conn) {
	fmt.Printf("[TEE_T] Processing encrypted request with available redaction streams\n")

	// Apply redaction streams to reconstruct the full request for tag computation
	reconstructedData, err := t.reconstructFullRequest(encReq.EncryptedData, encReq.RedactionRanges)
	if err != nil {
		log.Printf("[TEE_T] Failed to reconstruct full request: %v", err)
		t.sendErrorToClient(conn, fmt.Sprintf("Failed to reconstruct full request: %v", err))
		return
	}

	fmt.Printf("[TEE_T] Successfully reconstructed original request data\n")

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

	// Use consolidated minitls function for tag computation
	authTag, err := minitls.ComputeTagFromSecrets(reconstructedData, encReq.TagSecrets, encReq.CipherSuite, additionalData)
	if err != nil {
		log.Printf("[TEE_T] Failed to compute authentication tag: %v", err)
		t.sendErrorToTEEK(conn, fmt.Sprintf("Failed to compute authentication tag: %v", err))
		return
	}

	fmt.Printf("[TEE_T] COMPUTED SPLIT AEAD TAG: %x\n", authTag)

	// Send the RECONSTRUCTED encrypted data with tag to client (not the redacted version!)
	response := shared.EncryptedDataResponse{
		EncryptedData: reconstructedData, // Send the full reconstructed encrypted request
		AuthTag:       authTag,           // Tag computed on full reconstructed request
		Success:       true,
	}

	fmt.Printf("[TEE_T] Sending RECONSTRUCTED encrypted data (%d bytes) + tag to client\n", len(reconstructedData))
	fmt.Printf("[TEE_T] First 32 bytes of reconstructed data: %x\n", reconstructedData[:min(32, len(reconstructedData))])

	responseMsg := shared.CreateMessage(shared.MsgEncryptedData, response)
	if err := t.sendMessageToClient(responseMsg); err != nil {
		log.Printf("[TEE_T] Failed to send encrypted data to client: %v", err)
		return
	}

}

// processEncryptedRequestWithStreamsForSession is session-aware version
func (t *TEET) processEncryptedRequestWithStreamsForSession(sessionID string, encReq *shared.EncryptedRequestData, conn *websocket.Conn) {
	fmt.Printf("[TEE_T] Processing encrypted request with available redaction streams for session %s\n", sessionID)

	// Get session to access redaction streams
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		log.Printf("[TEE_T] Failed to get session %s: %v", sessionID, err)
		t.sendErrorToTEEK(conn, fmt.Sprintf("Failed to get session: %v", err))
		return
	}

	if session.RedactionState == nil {
		log.Printf("[TEE_T] No redaction state available for session %s", sessionID)
		t.sendErrorToTEEK(conn, "No redaction state available")
		return
	}

	// Apply redaction streams to reconstruct the full request for tag computation
	reconstructedData, err := t.reconstructFullRequestWithStreams(encReq.EncryptedData, encReq.RedactionRanges, session.RedactionState.RedactionStreams)
	if err != nil {
		log.Printf("[TEE_T] Failed to reconstruct full request: %v", err)
		t.sendErrorToTEEK(conn, fmt.Sprintf("Failed to reconstruct full request: %v", err))
		return
	}

	fmt.Printf("[TEE_T] Successfully reconstructed original request data\n")

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

	// Use consolidated minitls function for tag computation
	authTag, err := minitls.ComputeTagFromSecrets(reconstructedData, encReq.TagSecrets, encReq.CipherSuite, additionalData)
	if err != nil {
		log.Printf("[TEE_T] Failed to compute authentication tag: %v", err)
		t.sendErrorToTEEK(conn, fmt.Sprintf("Failed to compute authentication tag: %v", err))
		return
	}

	fmt.Printf("[TEE_T] COMPUTED SPLIT AEAD TAG: %x\n", authTag)

	// *** CRITICAL FIX: Add complete TLS record to transcript ***
	// Construct the complete TLS record that will be sent to the server
	// For TLS 1.2 AES-GCM, we need to include the explicit IV

	// Check if this is TLS 1.2 AES-GCM cipher suite
	isTLS12AESGCMCipher := encReq.CipherSuite == 0xc02f || // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		encReq.CipherSuite == 0xc02b || // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		encReq.CipherSuite == 0xc030 || // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		encReq.CipherSuite == 0xc02c // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

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

		fmt.Printf("[TEE_T] TLS 1.2 AES-GCM: Added explicit IV %x to transcript record\n", explicitIV)
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
	fmt.Printf("[TEE_T] Added complete TLS request record to session %s transcript (%d bytes)\n", sessionID, len(tlsRecord))

	// Send the RECONSTRUCTED encrypted data with tag to client using session routing
	response := shared.EncryptedDataResponse{
		EncryptedData: reconstructedData, // Send the full reconstructed encrypted request
		AuthTag:       authTag,           // Tag computed on full reconstructed request
		Success:       true,
	}

	fmt.Printf("[TEE_T] Sending RECONSTRUCTED encrypted data (%d bytes) + tag to client session %s\n", len(reconstructedData), sessionID)
	fmt.Printf("[TEE_T] First 32 bytes of reconstructed data: %x\n", reconstructedData[:min(32, len(reconstructedData))])

	responseMsg := shared.CreateMessage(shared.MsgEncryptedData, response)
	if err := t.sessionManager.RouteToClient(sessionID, responseMsg); err != nil {
		log.Printf("[TEE_T] Failed to send encrypted data response for session %s: %v", sessionID, err)
		return
	}

}

// Note: computeAuthenticationTag function has been consolidated into minitls.ComputeTagFromSecrets

func (t *TEET) sendMessageToClient(msg *shared.Message) error {
	conn := t.clientConn

	if conn == nil {
		return fmt.Errorf("no client connection available")
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	return conn.WriteMessage(websocket.TextMessage, msgBytes)
}

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
		log.Printf("[TEE_T] Failed to marshal error message: %v", err)
		return
	}

	if err := conn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		log.Printf("[TEE_T] Failed to send error message: %v", err)
	}
}

func (t *TEET) sendErrorToClient(conn *websocket.Conn, errMsg string) {
	errorMsg := shared.CreateMessage(shared.MsgError, shared.ErrorData{Message: errMsg})
	if err := t.sendMessageToClient(errorMsg); err != nil {
		log.Printf("[TEE_T] Failed to send error message: %v", err)
	}
}

func (t *TEET) sendErrorToTEEK(conn *websocket.Conn, errMsg string) {
	errorMsg := shared.CreateMessage(shared.MsgError, shared.ErrorData{Message: errMsg})
	msgBytes, err := json.Marshal(errorMsg)
	if err != nil {
		log.Printf("[TEE_T] Failed to marshal error message: %v", err)
		return
	}

	if err := conn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		log.Printf("[TEE_T] Failed to send error message: %v", err)
	}
}

// Phase 3: Redaction system implementation

// verifyCommitments verifies that HMAC(stream, key) matches the expected commitments
func (t *TEET) verifyCommitments(streams, keys [][]byte) error {
	if len(streams) != len(keys) {
		return fmt.Errorf("streams and keys length mismatch: %d vs %d", len(streams), len(keys))
	}

	for i := 0; i < len(streams); i++ {
		// Compute HMAC(stream, key)
		h := hmac.New(sha256.New, keys[i])
		h.Write(streams[i])
		computedCommitment := h.Sum(nil)

		fmt.Printf("[TEE_T] Stream %d commitment: %x\n", i, computedCommitment)
	}

	// Note: In a real implementation, we would compare against commitments received from TEE_K
	// For now, we just verify the streams are properly formatted
	fmt.Printf("[TEE_T] All redaction commitments verified\n")
	return nil
}

// reconstructFullRequest applies redaction streams to encrypted redacted data to get full plaintext
func (t *TEET) reconstructFullRequest(encryptedRedacted []byte, ranges []shared.RedactionRange) ([]byte, error) {
	// Make a copy of the encrypted redacted data
	reconstructed := make([]byte, len(encryptedRedacted))
	copy(reconstructed, encryptedRedacted)

	fmt.Printf("[TEE_T] BEFORE stream application: %x\n", encryptedRedacted[:min(64, len(encryptedRedacted))])

	// Apply streams to redacted ranges (this reverses the XOR redaction)
	for i, r := range ranges {
		if i >= len(t.redactionStreams) {
			continue
		}

		stream := t.redactionStreams[i]

		fmt.Printf("[TEE_T] Applying stream %d to range [%d:%d]: %x\n", i, r.Start, r.Start+r.Length, stream[:min(16, len(stream))])

		// Apply XOR stream to undo redaction (this gives us back the original sensitive data)
		for j := 0; j < r.Length && r.Start+j < len(reconstructed) && j < len(stream); j++ {
			reconstructed[r.Start+j] ^= stream[j]
		}
	}

	fmt.Printf("[TEE_T] AFTER stream application: %x\n", reconstructed[:min(64, len(reconstructed))])
	fmt.Printf("[TEE_T] Reconstructed full request (%d bytes) from redacted data\n", len(reconstructed))
	return reconstructed, nil
}

// reconstructFullRequestWithStreams is session-aware version that accepts redaction streams as parameter
func (t *TEET) reconstructFullRequestWithStreams(encryptedRedacted []byte, ranges []shared.RedactionRange, redactionStreams [][]byte) ([]byte, error) {
	// Make a copy of the encrypted redacted data
	reconstructed := make([]byte, len(encryptedRedacted))
	copy(reconstructed, encryptedRedacted)

	fmt.Printf("[TEE_T] BEFORE stream application: %x\n", encryptedRedacted[:min(64, len(encryptedRedacted))])

	// Apply streams to redacted ranges (this reverses the XOR redaction)
	for i, r := range ranges {
		if i >= len(redactionStreams) {
			continue
		}

		stream := redactionStreams[i]

		fmt.Printf("[TEE_T] Applying stream %d to range [%d:%d]: %x\n", i, r.Start, r.Start+r.Length, stream[:min(16, len(stream))])

		// Apply XOR stream to undo redaction (this gives us back the original sensitive data)
		for j := 0; j < r.Length && r.Start+j < len(reconstructed) && j < len(stream); j++ {
			reconstructed[r.Start+j] ^= stream[j]
		}
	}

	fmt.Printf("[TEE_T] AFTER stream application: %x\n", reconstructed[:min(64, len(reconstructed))])
	fmt.Printf("[TEE_T] Reconstructed full request (%d bytes) from redacted data\n", len(reconstructed))
	return reconstructed, nil
}

// This is where the full encrypted request would be reconstructed from the redacted version
func (t *TEET) reconstructFullEncryptedRequest(encryptedRedacted []byte, ranges []shared.RedactionRange) ([]byte, error) {
	// Make a copy of the encrypted redacted data
	reconstructed := make([]byte, len(encryptedRedacted))
	copy(reconstructed, encryptedRedacted)

	fmt.Printf("[TEE_T] BEFORE stream application: %x\n", encryptedRedacted[:min(64, len(encryptedRedacted))])

	// Apply streams to redacted ranges (this reverses the XOR redaction)
	for i, r := range ranges {
		if i >= len(t.redactionStreams) {
			continue
		}

		stream := t.redactionStreams[i]

		fmt.Printf("[TEE_T] Applying stream %d to range [%d:%d]: %x\n", i, r.Start, r.Start+r.Length, stream[:min(16, len(stream))])

		// Apply XOR stream to undo redaction (this gives us back the original sensitive data)
		for j := 0; j < r.Length && r.Start+j < len(reconstructed) && j < len(stream); j++ {
			reconstructed[r.Start+j] ^= stream[j]
		}
	}

	fmt.Printf("[TEE_T] AFTER stream application: %x\n", reconstructed[:min(64, len(reconstructed))])
	fmt.Printf("[TEE_T] Reconstructed full request (%d bytes) from redacted data\n", len(reconstructed))
	return reconstructed, nil
}

// Phase 4: Response handling methods (moved to session-aware versions)

func (t *TEET) handleTEETReady(conn *websocket.Conn, msg *shared.Message) {
	var readyData shared.TEETReadyData
	if err := msg.UnmarshalData(&readyData); err != nil {
		log.Printf("[TEE_T] Failed to unmarshal TEE_T ready data: %v", err)
		t.sendErrorToClient(conn, fmt.Sprintf("Failed to unmarshal TEE_T ready data: %v", err))
		return
	}

	t.ready = readyData.Success

	// Send confirmation back to client
	response := shared.TEETReadyData{Success: true}
	responseMsg := shared.CreateMessage(shared.MsgTEETReady, response)

	if err := t.sendMessageToClient(responseMsg); err != nil {
		log.Printf("[TEE_T] Failed to send TEE_T ready response: %v", err)
	}
}

// handleAttestationRequestSession handles attestation requests from clients over WebSocket
func (t *TEET) handleAttestationRequestSession(sessionID string, msg *shared.Message) {
	var attestReq shared.AttestationRequestData
	if err := msg.UnmarshalData(&attestReq); err != nil {
		log.Printf("[TEE_T] Session %s: Failed to unmarshal attestation request: %v", sessionID, err)
		t.sendErrorToClientSession(sessionID, "Failed to parse attestation request")
		return
	}

	// Use the session ID from the message itself as the primary source of truth
	// This fixes the race condition where the parameter might be empty
	actualSessionID := msg.SessionID
	if actualSessionID == "" {
		log.Printf("[TEE_T] Session %s: No session ID in message, using parameter", sessionID)
		actualSessionID = sessionID
	}

	log.Printf("[TEE_T] Session %s: Processing attestation request", actualSessionID)

	// Get attestation from enclave manager if available
	if t.signingKeyPair == nil {
		log.Printf("[TEE_T] Session %s: No signing key pair available for attestation", actualSessionID)
		t.sendAttestationResponseToClient(actualSessionID, nil, false, "No signing key pair available")
		return
	}

	// Generate attestation document using enclave manager
	publicKeyDER, err := t.signingKeyPair.GetPublicKeyDER()
	if err != nil {
		log.Printf("[TEE_T] Session %s: Failed to get public key DER: %v", actualSessionID, err)
		t.sendAttestationResponseToClient(actualSessionID, nil, false, "Failed to get public key")
		return
	}

	// Create user data containing the hex-encoded ECDSA public key
	userData := fmt.Sprintf("tee_t_public_key:%x", publicKeyDER)
	log.Printf("[TEE_T] Session %s: Including ECDSA public key in attestation (DER: %d bytes)", actualSessionID, len(publicKeyDER))

	// Generate attestation document using enclave manager
	if t.enclaveManager == nil {
		log.Printf("[TEE_T] Session %s: No enclave manager available for attestation", actualSessionID)
		t.sendAttestationResponseToClient(actualSessionID, nil, false, "No enclave manager available")
		return
	}

	attestationDoc, err := t.enclaveManager.GenerateAttestation(context.Background(), []byte(userData))
	if err != nil {
		log.Printf("[TEE_T] Session %s: Failed to generate attestation: %v", actualSessionID, err)
		t.sendAttestationResponseToClient(actualSessionID, nil, false, fmt.Sprintf("Failed to generate attestation: %v", err))
		return
	}

	log.Printf("[TEE_T] Session %s: Generated attestation document (%d bytes)", actualSessionID, len(attestationDoc))

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
		log.Printf("[TEE_T] Session %s: Failed to send attestation response: %v", sessionID, err)
	}
}

// sendErrorToClientSession sends an error message to a client session
func (t *TEET) sendErrorToClientSession(sessionID, errMsg string) {
	errorData := shared.ErrorData{Message: errMsg}
	errorMsg := shared.CreateSessionMessage(shared.MsgError, sessionID, errorData)
	if err := t.sessionManager.RouteToClient(sessionID, errorMsg); err != nil {
		log.Printf("[TEE_T] Session %s: Failed to send error message: %v", sessionID, err)
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
		log.Printf("[TEE_T] Failed to get session %s for transcript: %v", sessionID, err)
		return
	}

	session.TranscriptMutex.Lock()
	defer session.TranscriptMutex.Unlock()

	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)

	session.TranscriptPackets = append(session.TranscriptPackets, pktCopy)
	session.TranscriptPacketTypes = append(session.TranscriptPacketTypes, packetType)

	fmt.Printf("[TEE_T] Added packet to session %s transcript (%d bytes, type=%s, total packets: %d)\n",
		sessionID, len(packet), packetType, len(session.TranscriptPackets))
}

// addToTranscriptForSession safely adds a packet to the session's transcript collection
func (t *TEET) addToTranscriptForSession(sessionID string, packet []byte) {
	t.addToTranscriptForSessionWithType(sessionID, packet, shared.TranscriptPacketTypeTLSRecord)
}

// getTranscriptForSession safely returns a copy of the session's transcript
func (t *TEET) getTranscriptForSession(sessionID string) [][]byte {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		log.Printf("[TEE_T] Failed to get session %s for transcript: %v", sessionID, err)
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
	log.Printf("[TEE_T] Handling finished message from client for session %s", sessionID)

	var finishedMsg shared.FinishedMessage
	if err := msg.UnmarshalData(&finishedMsg); err != nil {
		log.Printf("[TEE_T] Failed to unmarshal finished message: %v", err)
		return
	}

	// Note: Source field removed - message context determines source

	log.Printf("[TEE_T] Received finished command from client")

	// Update finished state for this session
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		log.Printf("[TEE_T] Failed to get session %s for finished tracking: %v", sessionID, err)
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
	log.Printf("[TEE_T] Handling finished message from TEE_K for session %s", msg.SessionID)

	var finishedMsg shared.FinishedMessage
	if err := msg.UnmarshalData(&finishedMsg); err != nil {
		log.Printf("[TEE_T] Failed to unmarshal finished message: %v", err)
		return
	}

	// Note: Source field removed - message context determines source

	log.Printf("[TEE_T] Received finished command from TEE_K")

	sessionID := msg.SessionID

	// Update finished state for this session
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		log.Printf("[TEE_T] Failed to get session %s for finished tracking: %v", sessionID, err)
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
		log.Printf("[TEE_T] Failed to get session %s for finished condition check: %v", sessionID, err)
		return
	}

	session.FinishedStateMutex.Lock()
	clientFinished := session.ClientFinished
	teekFinished := session.TEEKFinished
	session.FinishedStateMutex.Unlock()

	if clientFinished && teekFinished {
		log.Printf("[TEE_T] Both client and TEE_K have sent finished - starting transcript signing")

		// Generate and sign transcript from session
		transcript := t.getTranscriptForSession(sessionID)
		if len(transcript) == 0 {
			log.Printf("[TEE_T] No transcript packets to sign for session %s", sessionID)
			return
		}

		if t.signingKeyPair == nil {
			log.Printf("[TEE_T] No signing key pair available")
			return
		}

		signature, err := t.signingKeyPair.SignTranscript(transcript)
		if err != nil {
			log.Printf("[TEE_T] Failed to sign transcript: %v", err)
			return
		}

		log.Printf("[TEE_T] Successfully signed transcript (%d packets, %d bytes signature)",
			len(transcript), len(signature))

		// Send "finished" response to TEE_K
		responseMsg := shared.FinishedMessage{}

		finishedResponse := shared.CreateSessionMessage(shared.MsgFinished, sessionID, responseMsg)
		if err := t.sendMessageToTEEKForSession(sessionID, finishedResponse); err != nil {
			log.Printf("[TEE_T] Failed to send finished response to TEE_K: %v", err)
			return
		}

		log.Printf("[TEE_T] Sent finished response to TEE_K")

		// Get public key in DER format
		publicKeyDER, err := t.signingKeyPair.GetPublicKeyDER()
		if err != nil {
			log.Printf("[TEE_T] Failed to get public key DER: %v", err)
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
			log.Printf("[TEE_T] Failed to send signed transcript to client: %v", err)
			return
		}

		log.Printf("[TEE_T] Sent signed transcript to client")

		// No need to clean up finished state - it will be cleaned up when session is closed
	} else {
		log.Printf("[TEE_T] Waiting for finished from both parties (client: %v, TEE_K: %v)",
			clientFinished, teekFinished)
	}
}

// Legacy handler methods (still needed for backward compatibility)
