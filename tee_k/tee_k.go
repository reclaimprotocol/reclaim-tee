package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"tee-mpc/minitls"
	"tee-mpc/shared"

	"github.com/gorilla/websocket"
	"github.com/mdlayher/vsock"
	"go.uber.org/zap"
)

var teekUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connections from any origin
	},
}

type TEEK struct {
	port int

	// Session management
	sessionManager    shared.SessionManagerInterface
	sessionTerminator *shared.SessionTerminator

	// TEE_T connection settings
	teetURL string

	// TLS configuration
	forceTLSVersion  string // Force specific TLS version: "1.2", "1.3", or "" for auto
	forceCipherSuite string // Force specific cipher suite: hex ID (e.g. "0xc02f") or name, or "" for auto

	// Session state only - global state removed

	// Single Session Mode: ECDSA signing keys
	signingKeyPair *shared.SigningKeyPair // ECDSA key pair for signing transcripts

	// Enclave manager for attestation generation
	enclaveManager *shared.EnclaveManager
}

// WebSocketConn adapts websocket to net.Conn interface for miniTLS
type WebSocketConn struct {
	wsConn      *websocket.Conn
	readBuffer  []byte
	readOffset  int
	pendingData chan []byte
	teek        *TEEK  // Reference to TEEK for transcript collection
	sessionID   string // Session ID for per-session transcript collection
}

func NewTEEK(port int) *TEEK {
	return NewTEEKWithEnclaveManager(port, nil)
}

func NewTEEKWithConfig(config *TEEKConfig) *TEEK {
	teek := NewTEEKWithEnclaveManager(config.Port, nil)
	teek.SetTEETURL(config.TEETURL)
	teek.SetForceTLSVersion(config.ForceTLSVersion)
	teek.SetForceCipherSuite(config.ForceCipherSuite)
	return teek
}

func NewTEEKWithEnclaveManager(port int, enclaveManager *shared.EnclaveManager) *TEEK {
	// Generate ECDSA signing key pair
	signingKeyPair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		// Critical failure - cannot operate without signing capability
		log.Fatalf("[TEE_K] CRITICAL: Failed to generate signing key pair: %v", err)
	}
	fmt.Printf("[TEE_K] Generated ECDSA signing key pair (P-256 curve)\n")

	return &TEEK{
		port:              port,
		sessionManager:    shared.NewSessionManager(),
		sessionTerminator: shared.NewSessionTerminator(shared.GetTEEKLogger()),
		teetURL:           "ws://localhost:8081/teek", // Default TEE_T URL
		signingKeyPair:    signingKeyPair,
		enclaveManager:    enclaveManager,
	}
}

// SetTEETURL sets the TEE_T connection URL
func (t *TEEK) SetTEETURL(url string) {
	t.teetURL = url
}

// SetForceTLSVersion sets the forced TLS version
func (t *TEEK) SetForceTLSVersion(version string) {
	t.forceTLSVersion = version
}

// SetForceCipherSuite sets the forced cipher suite
func (t *TEEK) SetForceCipherSuite(cipherSuite string) {
	t.forceCipherSuite = cipherSuite
}

// createVSockWebSocketDialer creates a custom WebSocket dialer for enclave mode
// that connects via vsock internet proxy (CID 3, port 8444)
func createVSockWebSocketDialer() *websocket.Dialer {
	return &websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			log.Printf("[TEE_K] VSock WebSocket dial: connecting to proxy (CID=3, Port=8444) for target: %s", addr)

			// Connect to internet proxy via vsock
			conn, err := vsock.Dial(3, 8444, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to connect to internet proxy: %v", err)
			}

			// Send target address to internet proxy
			log.Printf("[TEE_K] Sending target address to internet proxy: %s", addr)
			_, err = fmt.Fprintf(conn, "%s\n", addr)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("failed to send target address to proxy: %v", err)
			}

			log.Printf("[TEE_K] VSock connection established to %s via internet proxy", addr)
			return conn, nil
		},
		HandshakeTimeout: 30 * time.Second,
	}
}

// connectToTEETForSession establishes a per-session connection to TEE_T
func (t *TEEK) connectToTEETForSession(sessionID string) (*websocket.Conn, error) {
	log.Printf("[TEE_K] Session %s: Attempting WebSocket connection to TEE_T at: %s", sessionID, t.teetURL)

	// Check if using TLS (wss://)
	if strings.HasPrefix(t.teetURL, "wss://") {
		log.Printf("[TEE_K] Using secure WebSocket (WSS) connection")
	} else if strings.HasPrefix(t.teetURL, "ws://") {
		log.Printf("[TEE_K] Using plain WebSocket (WS) connection")
	}

	// Determine if we're in enclave mode based on the URL
	var conn *websocket.Conn
	var err error

	if strings.HasPrefix(t.teetURL, "wss://") && strings.Contains(t.teetURL, "reclaimprotocol.org") {
		// Enclave mode: use custom vsock dialer
		log.Printf("[TEE_K] Enclave mode detected - using VSock dialer via internet proxy")
		dialer := createVSockWebSocketDialer()
		conn, _, err = dialer.Dial(t.teetURL, nil)
	} else {
		// Standalone mode: use default dialer
		log.Printf("[TEE_K] Standalone mode detected - using default WebSocket dialer")
		conn, _, err = websocket.DefaultDialer.Dial(t.teetURL, nil)
	}

	if err != nil {
		log.Printf("[TEE_K] Session %s: WebSocket dial failed for %s: %v", sessionID, t.teetURL, err)
		return nil, fmt.Errorf("failed to connect to TEE_T: %v", err)
	}

	log.Printf("[TEE_K] Session %s: WebSocket connection established successfully to %s", sessionID, t.teetURL)
	return conn, nil
}

// handleTEETMessagesForSession handles messages from TEE_T for a specific session
func (t *TEEK) handleTEETMessagesForSession(sessionID string, conn *websocket.Conn) {
	defer conn.Close()

	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[TEE_K] Session %s: TEE_T disconnected normally", sessionID)
			} else if !isNetworkShutdownError(err) {
				log.Printf("[TEE_K] Session %s: Failed to read TEE_T message: %v", sessionID, err)
			}
			break
		}

		msg, err := shared.ParseMessage(msgBytes)
		if err != nil {
			log.Printf("[TEE_K] Session %s: Failed to parse TEE_T message: %v", sessionID, err)
			continue
		}

		// Ensure message has the correct session ID
		if msg.SessionID != sessionID {
			log.Printf("[TEE_K] Session %s: Message has wrong session ID: %s", sessionID, msg.SessionID)
			continue
		}

		// Route session-aware messages
		switch msg.Type {
		case shared.MsgFinished:
			t.handleFinishedFromTEETSession(msg.SessionID, msg)

		case shared.MsgBatchedResponseLengths:
			t.handleBatchedResponseLengthsSession(msg.SessionID, msg)

		case shared.MsgBatchedTagVerifications:
			t.handleBatchedTagVerificationsSession(msg.SessionID, msg)

		default:
			log.Printf("[TEE_K] Session %s: Unknown TEE_T message type: %s", sessionID, msg.Type)
		}
	}

	log.Printf("[TEE_K] Session %s: TEE_T message handler stopped", sessionID)
}

// sendMessageToTEETForSession sends a message to TEE_T for a specific session
func (t *TEEK) sendMessageToTEETForSession(sessionID string, msg *shared.Message) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("session %s not found: %v", sessionID, err)
	}

	if session.TEETConn == nil {
		return fmt.Errorf("no TEE_T connection available for session %s", sessionID)
	}

	// Add session ID to message
	msg.SessionID = sessionID

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	// Use the underlying websocket connection
	wsConn := session.TEETConn.(*shared.WSConnection)
	return wsConn.GetWebSocketConn().WriteMessage(websocket.TextMessage, msgBytes)
}

func (t *TEEK) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := teekUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[TEE_K] Failed to upgrade websocket: %v", err)
		return
	}

	// Create session for this client connection
	wsConn := shared.NewWSConnection(conn)
	sessionID, err := t.sessionManager.CreateSession(wsConn)
	if err != nil {
		log.Printf("[TEE_K] Failed to create session: %v", err)
		conn.Close()
		return
	}

	log.Printf("[TEE_K] Created session %s for client %s", sessionID, conn.RemoteAddr())

	// Notify TEE_T about the new session
	if err := t.notifyTEETNewSession(sessionID); err != nil {
		log.Printf("[TEE_K] Failed to notify TEE_T about session %s: %v", sessionID, err)
		t.sessionManager.CloseSession(sessionID)
		return
	}

	// Send session ready message to client
	sessionMsg := shared.CreateSessionMessage(shared.MsgSessionReady, sessionID, map[string]interface{}{
		"session_id": sessionID,
		"ready":      true,
	})
	if err := wsConn.WriteJSON(sessionMsg); err != nil {
		log.Printf("[TEE_K] Failed to send session ready to client: %v", err)
		t.sessionManager.CloseSession(sessionID)
		return
	}

	// shared.Message handling loop
	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[TEE_K] Client disconnected normally for session %s", sessionID)
			} else if !isNetworkShutdownError(err) {
				log.Printf("[TEE_K] Failed to read websocket message for session %s: %v", sessionID, err)
			}
			break
		}

		msg, err := shared.ParseMessage(msgBytes)
		if err != nil {
			t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to parse client message")
			return
		}

		// Verify session ID matches
		if msg.SessionID != sessionID {
			sessionErr := fmt.Errorf("session ID mismatch: expected %s, got %s", sessionID, msg.SessionID)
			t.terminateSessionWithError(sessionID, shared.ReasonSessionIDMismatch, sessionErr, "Session ID mismatch")
			return
		}

		// Handle message based on type
		switch msg.Type {
		case shared.MsgRequestConnection:
			t.handleRequestConnectionSession(sessionID, msg)
		case shared.MsgTCPReady:
			t.handleTCPReadySession(sessionID, msg)
		case shared.MsgTCPData:
			t.handleTCPDataSession(sessionID, msg)
		case shared.MsgRedactedRequest:
			t.handleRedactedRequestSession(sessionID, msg)
		case shared.MsgRedactionSpec:
			t.handleRedactionSpecSession(sessionID, msg)
		case shared.MsgFinished:
			t.handleFinishedFromClientSession(sessionID, msg)
		case shared.MsgAttestationRequest:
			t.handleAttestationRequestSession(sessionID, msg)
		default:
			unknownMsgErr := fmt.Errorf("unknown message type: %s", msg.Type)
			t.terminateSessionWithError(sessionID, shared.ReasonUnknownMessageType, unknownMsgErr, "Unknown message type")
		}
	}

	// Clean up session when connection closes
	log.Printf("[TEE_K] Cleaning up session %s", sessionID)
	t.sessionManager.CloseSession(sessionID)
}

// notifyTEETNewSession creates per-session connection and sends session registration to TEE_T
func (t *TEEK) notifyTEETNewSession(sessionID string) error {
	// Create per-session connection to TEE_T
	teetConn, err := t.connectToTEETForSession(sessionID)
	if err != nil {
		return fmt.Errorf("failed to create TEE_T connection for session %s: %v", sessionID, err)
	}

	// Store the connection in the session
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		teetConn.Close()
		return fmt.Errorf("session %s not found: %v", sessionID, err)
	}

	session.TEETConn = shared.NewWSConnection(teetConn)

	// Start message handler for this session
	go t.handleTEETMessagesForSession(sessionID, teetConn)

	// Send session registration to TEE_T
	msg := shared.CreateSessionMessage(shared.MsgSessionCreated, sessionID, map[string]interface{}{
		"session_id": sessionID,
	})

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal session notification: %v", err)
	}

	if err := teetConn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		return fmt.Errorf("failed to send session notification: %v", err)
	}

	log.Printf("[TEE_K] Session %s: Successfully created TEE_T connection and sent session registration", sessionID)
	return nil
}

// terminateSessionWithError terminates a session due to a critical error
func (t *TEEK) terminateSessionWithError(sessionID string, reason shared.TerminationReason, err error, message string) {
	// Log the critical error and determine if session should terminate
	if t.sessionTerminator.CriticalError(sessionID, reason, err) {
		// Cleanup session resources
		t.cleanupSession(sessionID)
	}
}

// cleanupSession performs complete cleanup of session resources
func (t *TEEK) cleanupSession(sessionID string) {
	// Close the session in session manager (handles connections and state cleanup)
	if err := t.sessionManager.CloseSession(sessionID); err != nil {
		// Log cleanup failure but don't continue with broken session
		log.Printf("[TEE_K] Failed to cleanup session %s: %v", sessionID, err)
	}

	// Cleanup session terminator tracking
	t.sessionTerminator.CleanupSession(sessionID)

	log.Printf("[TEE_K] Session %s terminated and cleaned up", sessionID)
}

// Session-aware handler methods

// Helper functions to access session state
func (t *TEEK) getSessionTLSState(sessionID string) (*shared.TLSSessionState, error) {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return nil, err
	}
	if session.TLSState == nil {
		session.TLSState = &shared.TLSSessionState{
			TCPReady: make(chan bool, 1),
		}
	}
	return session.TLSState, nil
}

func (t *TEEK) getSessionResponseState(sessionID string) (*shared.ResponseSessionState, error) {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return nil, err
	}
	if session.ResponseState == nil {
		session.ResponseState = &shared.ResponseSessionState{
			PendingResponses:          make(map[string][]byte),
			ResponseLengthBySeq:       make(map[uint64]uint32),
			ResponseLengthBySeqInt:    make(map[uint64]int),
			ExplicitIVBySeq:           make(map[uint64][]byte),
			PendingEncryptedResponses: make(map[uint64]*shared.EncryptedResponseData),
		}
	}
	return session.ResponseState, nil
}

func (t *TEEK) handleRequestConnectionSession(sessionID string, msg *shared.Message) {
	log.Printf("[TEE_K] Session %s: Handling connection request", sessionID)

	var reqData shared.RequestConnectionData
	if err := msg.UnmarshalData(&reqData); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to parse connection request")
		return
	}

	log.Printf("[TEE_K] Session %s: Connection request to %s:%d", sessionID, reqData.Hostname, reqData.Port)

	// Store connection data in session
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionNotFound, err, "Session not found")
		return
	}
	session.ConnectionData = &reqData

	// Send connection ready message to client (was missing!)
	readyMsg := shared.CreateSessionMessage(shared.MsgConnectionReady, sessionID, shared.ConnectionReadyData{Success: true})
	if err := t.sessionManager.RouteToClient(sessionID, readyMsg); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonNetworkFailure, err, "Failed to send connection ready message")
		return
	}

	log.Printf("[TEE_K] Session %s: Connection ready message sent, waiting for TCP ready", sessionID)
	// Now wait for client to send MsgTCPReady - the TLS handshake will start in handleTCPReadySession
}

func (t *TEEK) handleTCPReadySession(sessionID string, msg *shared.Message) {
	var tcpData shared.TCPReadyData
	if err := msg.UnmarshalData(&tcpData); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to unmarshal TCP ready data")
		return
	}

	if !tcpData.Success {
		tcpErr := fmt.Errorf("TCP connection failed")
		t.terminateSessionWithError(sessionID, shared.ReasonNetworkFailure, tcpErr, "TCP connection failed")
		return
	}

	fmt.Printf("[TEE_K] Session %s: TCP connection ready, starting TLS handshake\n", sessionID)

	// Start TLS handshake for this session
	go t.performTLSHandshakeAndHTTPForSession(sessionID)
}

// performTLSHandshakeAndHTTPForSession performs TLS handshake for a specific session
func (t *TEEK) performTLSHandshakeAndHTTPForSession(sessionID string) {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		log.Printf("[TEE_K] Failed to get session %s for TLS handshake: %v", sessionID, err)
		return
	}

	// Get connection data
	reqData, ok := session.ConnectionData.(*shared.RequestConnectionData)
	if !ok {
		log.Printf("[TEE_K] Session %s: Missing connection data for TLS handshake", sessionID)
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, fmt.Errorf("missing connection data"), "Missing connection data")
		return
	}

	// Create session-specific TLS client
	wsConn := session.ClientConn.(*shared.WSConnection)
	tlsConn := &WebSocketConn{
		wsConn:      wsConn.GetWebSocketConn(),
		pendingData: make(chan []byte, 10),
		teek:        t,         // Add TEEK reference for transcript collection
		sessionID:   sessionID, // Add session ID for per-session transcript collection
	}

	// Initialize TLS client for this session
	tlsClient := minitls.NewClient(tlsConn)

	// Configure TLS version based on client request or server setting
	config := &minitls.Config{}

	// Prefer client-requested TLS version over server default
	effectiveTLSVersion := reqData.ForceTLSVersion
	if effectiveTLSVersion == "" {
		effectiveTLSVersion = t.forceTLSVersion
	}

	// Prefer client-requested cipher suite over server default
	effectiveCipherSuite := reqData.ForceCipherSuite
	if effectiveCipherSuite == "" {
		effectiveCipherSuite = t.forceCipherSuite
	}

	switch effectiveTLSVersion {
	case "1.2":
		config.MinVersion = minitls.VersionTLS12
		config.MaxVersion = minitls.VersionTLS12
		fmt.Printf("[TEE_K] Session %s: Forcing TLS 1.2\n", sessionID)
	case "1.3":
		config.MinVersion = minitls.VersionTLS13
		config.MaxVersion = minitls.VersionTLS13
		fmt.Printf("[TEE_K] Session %s: Forcing TLS 1.3\n", sessionID)
	default:
		// Auto-negotiate (default behavior)
		config.MinVersion = minitls.VersionTLS12
		config.MaxVersion = minitls.VersionTLS13
		fmt.Printf("[TEE_K] Session %s: TLS version auto-negotiation enabled\n", sessionID)
	}

	// Configure cipher suite restrictions if specified
	if err := configureCipherSuites(config, effectiveCipherSuite, effectiveTLSVersion); err != nil {
		log.Printf("[TEE_K] Session %s: Cipher suite configuration error: %v", sessionID, err)
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Invalid cipher suite configuration: %v", err))
		return
	}

	if effectiveCipherSuite != "" {
		fmt.Printf("[TEE_K] Session %s: Forcing cipher suite %s\n", sessionID, effectiveCipherSuite)
	} else {
		fmt.Printf("[TEE_K] Session %s: Cipher suite auto-negotiation enabled\n", sessionID)
	}

	tlsClient = minitls.NewClientWithConfig(tlsConn, config)

	// Store in session state instead of global fields
	tlsState, err := t.getSessionTLSState(sessionID)
	if err != nil {
		log.Printf("[TEE_K] Session %s: Failed to get TLS state: %v", sessionID, err)
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to get TLS state: %v", err))
		return
	}
	tlsState.TLSClient = tlsClient
	tlsState.WSConn2TLS = tlsConn
	tlsState.CurrentConn = wsConn.GetWebSocketConn()
	tlsState.CurrentRequest = reqData

	// Global state removed - using session state only

	if err := tlsClient.Handshake(reqData.Hostname); err != nil {
		log.Printf("[TEE_K] Session %s: TLS handshake failed: %v", sessionID, err)
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("TLS handshake failed: %v", err))
		return
	}

	// Store TLS state in session
	if session.TLSState == nil {
		session.TLSState = &shared.TLSSessionState{}
	}
	session.TLSState.HandshakeComplete = true

	// Get crypto material for certificate verification
	hsKey := tlsClient.GetHandshakeKey()
	hsIV := tlsClient.GetHandshakeIV()
	certPacket := tlsClient.GetCertificatePacket()
	cipherSuite := tlsClient.GetCipherSuite()
	algorithm := getCipherSuiteAlgorithm(cipherSuite)

	// Send handshake key disclosure to Client
	disclosureMsg := shared.CreateSessionMessage(shared.MsgHandshakeKeyDisclosure, sessionID, shared.HandshakeKeyDisclosureData{
		HandshakeKey:      hsKey,
		HandshakeIV:       hsIV,
		CertificatePacket: certPacket,
		CipherSuite:       cipherSuite,
		Algorithm:         algorithm,
		Success:           true,
	})
	if err := t.sessionManager.RouteToClient(sessionID, disclosureMsg); err != nil {
		log.Printf("[TEE_K] Failed to send handshake key disclosure to session %s: %v", sessionID, err)
		return
	}

	fmt.Printf("[TEE_K] Session %s: Handshake finished - ready for split AEAD\n", sessionID)

	// Send handshake complete message
	handshakeMsg := shared.CreateSessionMessage(shared.MsgHandshakeComplete, sessionID, shared.HandshakeCompleteData{
		Success: true,
	})

	if err := t.sessionManager.RouteToClient(sessionID, handshakeMsg); err != nil {
		log.Printf("[TEE_K] Failed to send handshake complete to session %s: %v", sessionID, err)
	}

	fmt.Printf("[TEE_K] Session %s: TLS handshake complete, cipher suite 0x%04x\n", sessionID, cipherSuite)
	fmt.Printf("[TEE_K] Session %s: Ready for Phase 4 split AEAD response handling\n", sessionID)
}

func (t *TEEK) handleTCPDataSession(sessionID string, msg *shared.Message) {
	var tcpData shared.TCPData
	if err := msg.UnmarshalData(&tcpData); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal TCP data: %v", err)
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to unmarshal TCP data: %v", err))
		return
	}

	// Handle incoming data from Client (TLS handshake data or encrypted application data)
	// Use session state for TCP data handling
	tlsState, err := t.getSessionTLSState(sessionID)
	if err != nil {
		log.Printf("[TEE_K] Session %s: Failed to get TLS state: %v", sessionID, err)
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to get TLS state: %v", err))
		return
	}

	if wsConn2TLS, ok := tlsState.WSConn2TLS.(*WebSocketConn); ok && wsConn2TLS != nil {
		// Forward data to TLS client for processing
		wsConn2TLS.pendingData <- tcpData.Data
	} else {
		log.Printf("[TEE_K] Session %s: No WebSocket-to-TLS adapter available", sessionID)
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, fmt.Errorf("no WebSocket-to-TLS adapter available"), "No WebSocket-to-TLS adapter available")
	}
}

func (t *TEEK) handleRedactedRequestSession(sessionID string, msg *shared.Message) {
	var redactedRequest shared.RedactedRequestData
	if err := msg.UnmarshalData(&redactedRequest); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal redacted request: %v", err)
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to unmarshal redacted request: %v", err))
		return
	}

	fmt.Printf("[TEE_K] Session %s: Validating redacted request (%d bytes, %d ranges)\n", sessionID, len(redactedRequest.RedactedRequest), len(redactedRequest.RedactionRanges))

	// Validate redacted request format and positions
	if err := t.validateHTTPRequestFormat(redactedRequest.RedactedRequest, redactedRequest.RedactionRanges); err != nil {
		log.Printf("[TEE_K] Failed to validate redacted request format: %v", err)
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to validate redacted request format: %v", err))
		return
	}

	if err := t.validateRedactionPositions(redactedRequest.RedactionRanges, len(redactedRequest.RedactedRequest)); err != nil {
		log.Printf("[TEE_K] Failed to validate redaction positions: %v", err)
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to validate redaction positions: %v", err))
		return
	}

	// --- Add redacted request, comm_sp, and redaction ranges to transcript before encryption ---
	t.addToTranscriptForSessionWithType(sessionID, redactedRequest.RedactedRequest, shared.TranscriptPacketTypeHTTPRequestRedacted)

	// Store redaction ranges in transcript for signing
	redactionRangesBytes, err := json.Marshal(redactedRequest.RedactionRanges)
	if err != nil {
		log.Printf("[TEE_K] Failed to marshal redaction ranges: %v", err)
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to marshal redaction ranges: %v", err))
		return
	}
	t.addToTranscriptForSessionWithType(sessionID, redactionRangesBytes, "redaction_ranges")
	log.Printf("[TEE_K] Session %s: Stored %d redaction ranges in transcript (%d bytes)", sessionID, len(redactedRequest.RedactionRanges), len(redactionRangesBytes))

	// Note: Commitments are verified by TEE_T and not included in TEE_K transcript
	// TEE_T signs the proof stream, providing sufficient cryptographic proof

	fmt.Printf("[TEE_K] Session %s: Added redaction ranges to transcript for signing\n", sessionID)

	fmt.Printf("[TEE_K] Session %s: Split AEAD: encrypting redacted request %d bytes\n", sessionID, len(redactedRequest.RedactedRequest))

	// Get TLS state from session
	tlsState, err := t.getSessionTLSState(sessionID)
	if err != nil {
		log.Printf("[TEE_K] Session %s: Failed to get TLS state: %v", sessionID, err)
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to get TLS state: %v", err))
		return
	}

	tlsClient, ok := tlsState.TLSClient.(*minitls.Client)
	if tlsClient == nil || !ok {
		log.Printf("[TEE_K] Session %s: No TLS client available for encryption", sessionID)
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, fmt.Errorf("no tls client available for encryption"), "no tls client available for encryption")
		return
	}

	// Get cipher suite and encryption parameters
	cipherSuite := tlsClient.GetCipherSuite()

	// Prepare data for encryption based on TLS version
	var dataToEncrypt []byte
	var clientAppKey, clientAppIV []byte
	var actualSeqNum uint64

	tlsVersion := tlsClient.GetNegotiatedVersion()
	fmt.Printf("🔍 TEE_K Session %s: TLS version 0x%04x, cipher 0x%04x\n", sessionID, tlsVersion, cipherSuite)

	if tlsVersion == 0x0303 { // TLS 1.2
		// TLS 1.2: encrypt raw application data directly, no inner content type
		dataToEncrypt = redactedRequest.RedactedRequest
		fmt.Printf("[TEE_K] Session %s: TLS 1.2 - Encrypting raw HTTP data (%d bytes)\n", sessionID, len(dataToEncrypt))

		tls12AEAD := tlsClient.GetTLS12AEAD()
		if tls12AEAD == nil {
			log.Printf("[TEE_K] No TLS 1.2 AEAD available")
			t.terminateSessionWithError(sessionID, shared.ReasonInternalError, fmt.Errorf("no tls 1.2 aead available"), "no tls 1.2 aead available")
			return
		}

		clientAppKey = tls12AEAD.GetWriteKey()
		clientAppIV = tls12AEAD.GetWriteIV()
		actualSeqNum = tls12AEAD.GetWriteSequence()

		fmt.Printf("🔍 TEE_K Session %s TLS 1.2 Key Material:\n", sessionID)
		fmt.Printf("  Write Key (%d bytes): %x\n", len(clientAppKey), clientAppKey)
		fmt.Printf("  Write IV (%d bytes): %x\n", len(clientAppIV), clientAppIV)
		fmt.Printf("  Write Sequence: %d\n", actualSeqNum)

	} else { // TLS 1.3
		// TLS 1.3: Add inner content type byte + padding (RFC 8446)
		dataToEncrypt = make([]byte, len(redactedRequest.RedactedRequest)+2) // +2 for content type + padding
		copy(dataToEncrypt, redactedRequest.RedactedRequest)
		dataToEncrypt[len(redactedRequest.RedactedRequest)] = 0x17   // ApplicationData content type
		dataToEncrypt[len(redactedRequest.RedactedRequest)+1] = 0x00 // Required TLS 1.3 padding byte
		fmt.Printf("[TEE_K] Session %s: TLS 1.3 - Added inner content type + padding (%d bytes)\n", sessionID, len(dataToEncrypt))

		clientAEAD := tlsClient.GetClientApplicationAEAD()
		if clientAEAD == nil {
			log.Printf("[TEE_K] No client application AEAD available")
			t.terminateSessionWithError(sessionID, shared.ReasonInternalError, fmt.Errorf("no client application aead available"), "no client application aead available")
			return
		}

		actualSeqNum = clientAEAD.GetSequence()

		// Get encryption keys
		keySchedule := tlsClient.GetKeySchedule()
		if keySchedule == nil {
			log.Printf("[TEE_K] No key schedule available")
			t.terminateSessionWithError(sessionID, shared.ReasonInternalError, fmt.Errorf("no key schedule available"), "no key schedule available")
			return
		}

		clientAppKey = keySchedule.GetClientApplicationKey()
		clientAppIV = keySchedule.GetClientApplicationIV()

		if len(clientAppKey) == 0 || len(clientAppIV) == 0 {
			log.Printf("[TEE_K] No application keys available")
			t.terminateSessionWithError(sessionID, shared.ReasonInternalError, fmt.Errorf("no application keys available"), "no application keys available")
			return
		}
	}

	// Use consolidated crypto functions from minitls
	splitAEAD := minitls.NewSplitAEAD(clientAppKey, clientAppIV, cipherSuite)
	splitAEAD.SetSequence(actualSeqNum)

	// Create AAD based on TLS version
	var additionalData []byte
	if tlsVersion == 0x0303 { // TLS 1.2
		// TLS 1.2: AAD = seq_num(8) + record header(5)
		additionalData = make([]byte, 13)
		// Sequence number (8 bytes, big-endian)
		for i := 0; i < 8; i++ {
			additionalData[i] = byte(actualSeqNum >> (8 * (7 - i)))
		}
		// Record header (5 bytes) - use plaintext length
		additionalData[8] = 0x17                             // ApplicationData
		additionalData[9] = 0x03                             // TLS version major
		additionalData[10] = 0x03                            // TLS version minor
		additionalData[11] = byte(len(dataToEncrypt) >> 8)   // plaintext length high byte
		additionalData[12] = byte(len(dataToEncrypt) & 0xFF) // plaintext length low byte
	} else { // TLS 1.3
		// TLS 1.3: AAD = record header with ciphertext+tag length (5 bytes)
		tagSize := 16                                // GCM tag size
		recordLength := len(dataToEncrypt) + tagSize // encrypted data + authentication tag
		additionalData = []byte{
			0x17,                      // ApplicationData
			0x03,                      // TLS version major (compatibility)
			0x03,                      // TLS version minor (compatibility)
			byte(recordLength >> 8),   // Length high byte (includes tag)
			byte(recordLength & 0xFF), // Length low byte (includes tag)
		}
	}

	encryptedData, tagSecrets, err := splitAEAD.EncryptWithoutTag(dataToEncrypt, additionalData)
	if err != nil {
		log.Printf("[TEE_K] Failed to encrypt data: %v", err)
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to encrypt data: %v", err))
		return
	}

	fmt.Printf("[TEE_K] Session %s: Generated client application tag secrets for sequence %d\n", sessionID, actualSeqNum)
	fmt.Printf("[TEE_K] Session %s: Encrypted %d bytes using split AEAD\n", sessionID, len(encryptedData))

	// Send encrypted request and tag secrets to TEE_T with session ID
	if err := t.sendEncryptedRequestToTEETWithSession(sessionID, encryptedData, tagSecrets, cipherSuite, actualSeqNum, redactedRequest.RedactionRanges, redactedRequest.Commitments); err != nil {
		log.Printf("[TEE_K] Failed to send encrypted request to TEE_T: %v", err)
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to send encrypted request to TEE_T: %v", err))
		return
	}

	fmt.Printf("[TEE_K] Session %s: Encrypted request sent to TEE_T successfully\n", sessionID)
}

// validateHTTPRequestFormat validates that the redacted request maintains proper HTTP format
func (t *TEEK) validateHTTPRequestFormat(redactedRequest []byte, ranges []shared.RedactionRange) error {
	// Convert to string for easier parsing
	reqStr := string(redactedRequest)

	// Check basic HTTP request format
	if !strings.HasPrefix(reqStr, "GET ") && !strings.HasPrefix(reqStr, "POST ") {
		return fmt.Errorf("request does not start with valid HTTP method")
	}

	// Check for HTTP version
	if !strings.Contains(reqStr, " HTTP/1.1") {
		return fmt.Errorf("request does not contain HTTP/1.1 version")
	}

	// Check for proper line endings
	if !strings.Contains(reqStr, "\r\n") {
		return fmt.Errorf("request does not contain proper CRLF line endings")
	}

	// Check that request ends with double CRLF
	if !strings.HasSuffix(reqStr, "\r\n\r\n") {
		return fmt.Errorf("request does not end with proper double CRLF")
	}

	// Validate that critical parts aren't fully redacted
	lines := strings.Split(reqStr, "\r\n")
	if len(lines) < 2 {
		return fmt.Errorf("request has insufficient lines")
	}

	// First line should contain method, path, and version
	firstLine := lines[0]
	parts := strings.Split(firstLine, " ")
	if len(parts) < 3 {
		return fmt.Errorf("invalid HTTP request line format")
	}

	fmt.Printf("[TEE_K] Redacted request format validation passed\n")
	return nil
}

// validateRedactionPositions validates that redaction ranges are within bounds and non-overlapping
func (t *TEEK) validateRedactionPositions(ranges []shared.RedactionRange, requestLen int) error {
	for i, r := range ranges {
		// Check bounds
		if r.Start < 0 || r.Length <= 0 || r.Start+r.Length > requestLen {
			return fmt.Errorf("range %d out of bounds: [%d:%d] for request length %d", i, r.Start, r.Start+r.Length, requestLen)
		}

		// Check for valid type
		if r.Type != "sensitive" && r.Type != "sensitive_proof" {
			return fmt.Errorf("range %d has invalid type: %s", i, r.Type)
		}

		// Check for overlaps with other ranges
		for j := i + 1; j < len(ranges); j++ {
			other := ranges[j]
			if !(r.Start+r.Length <= other.Start || other.Start+other.Length <= r.Start) {
				return fmt.Errorf("ranges %d and %d overlap: [%d:%d] and [%d:%d]", i, j, r.Start, r.Start+r.Length, other.Start, other.Start+other.Length)
			}
		}
	}

	fmt.Printf("[TEE_K] Redaction position validation passed for %d ranges\n", len(ranges))
	return nil
}

func (t *TEEK) sendMessage(conn *websocket.Conn, msg *shared.Message) error {
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return conn.WriteMessage(websocket.TextMessage, msgBytes)
}

func (t *TEEK) sendError(conn *websocket.Conn, errMsg string) {
	errorMsg := shared.CreateMessage(shared.MsgError, shared.ErrorData{Message: errMsg})
	if err := t.sendMessage(conn, errorMsg); err != nil {
		log.Printf("[TEE_K] Failed to send error message: %v", err)
	}
}

// WebSocketConn implementation of net.Conn interface

func (w *WebSocketConn) Read(p []byte) (int, error) {
	// If we have data in the buffer, read from it first
	if w.readOffset < len(w.readBuffer) {
		n := copy(p, w.readBuffer[w.readOffset:])
		w.readOffset += n

		// If we've consumed all buffer data, reset
		if w.readOffset >= len(w.readBuffer) {
			w.readBuffer = nil
			w.readOffset = 0
		}

		return n, nil
	}

	// Wait for new data from websocket
	select {
	case data := <-w.pendingData:
		// Single Session Mode: Collect all incoming handshake packets for transcript
		// TEE_K only sees handshake packets - application data goes directly to TEE_T
		if w.teek != nil && w.sessionID != "" {
			w.teek.addToTranscriptForSession(w.sessionID, data)
		}

		w.readBuffer = data
		w.readOffset = 0

		n := copy(p, w.readBuffer)
		w.readOffset = n

		// If we've consumed all buffer data, reset
		if w.readOffset >= len(w.readBuffer) {
			w.readBuffer = nil
			w.readOffset = 0
		}

		return n, nil
	case <-time.After(2 * time.Second):
		return 0, fmt.Errorf("timeout reading from websocket")
	}
}

func (w *WebSocketConn) Write(p []byte) (int, error) {
	// Single Session Mode: Collect outgoing packets for transcript
	if w.teek != nil && w.sessionID != "" {
		w.teek.addToTranscriptForSession(w.sessionID, p)
	}

	fmt.Println("WRITE CALLED")

	msg := shared.CreateMessage(shared.MsgSendTCPData, shared.TCPData{Data: p})

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal message: %v", err)
	}

	if err := w.wsConn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		return 0, fmt.Errorf("failed to send TCP data: %v", err)
	}

	return len(p), nil
}

func (w *WebSocketConn) Close() error {
	return nil // WebSocket connection is managed by TEEK
}

func (w *WebSocketConn) LocalAddr() net.Addr {
	return &dummyAddr{network: "websocket", address: "local"}
}

func (w *WebSocketConn) RemoteAddr() net.Addr {
	return &dummyAddr{network: "websocket", address: "remote"}
}

func (w *WebSocketConn) SetDeadline(t time.Time) error {
	return nil // Not implemented for WebSocket adapter
}

func (w *WebSocketConn) SetReadDeadline(t time.Time) error {
	return nil // Not implemented for WebSocket adapter
}

func (w *WebSocketConn) SetWriteDeadline(t time.Time) error {
	return nil // Not implemented for WebSocket adapter
}

// Dummy network address implementation
type dummyAddr struct {
	network string
	address string
}

func (d *dummyAddr) Network() string {
	return d.network
}

func (d *dummyAddr) String() string {
	return d.address
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

// getCipherSuiteAlgorithm maps TLS cipher suite numbers to algorithm names
func getCipherSuiteAlgorithm(cipherSuite uint16) string {
	return shared.GetAlgorithmName(cipherSuite)
}

// Phase 2: Split AEAD handlers for TEE_T communication

func (t *TEEK) handleKeyShareResponse(msg *shared.Message) {
	// Use global state for backward compatibility during migration
	t.handleKeyShareResponseWithSession("", msg)
}

func (t *TEEK) handleKeyShareResponseWithSession(sessionID string, msg *shared.Message) {
	var keyShareResp shared.KeyShareResponseData
	if err := msg.UnmarshalData(&keyShareResp); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal key share response: %v", err)
		return
	}

	if keyShareResp.Success {
		if sessionID != "" {
			// Store in session state
			tlsState, err := t.getSessionTLSState(sessionID)
			if err != nil {
				t.terminateSessionWithError(sessionID, shared.ReasonSessionStateCorrupted, err, "Failed to get TLS state")
				return
			}
			tlsState.KeyShare = keyShareResp.KeyShare
			fmt.Printf("[TEE_K] Session %s: Received key share from TEE_T (%d bytes): %x\n", sessionID, len(tlsState.KeyShare), tlsState.KeyShare)
		}

		// Global state removed - using session state only
		fmt.Printf("[TEE_K] Received key share from TEE_T (%d bytes): %x\n", len(keyShareResp.KeyShare), keyShareResp.KeyShare)
	} else {
		// Key share generation failure is critical - terminate session
		keyShareErr := fmt.Errorf("TEE_T key share generation failed")
		if sessionID != "" {
			t.terminateSessionWithError(sessionID, shared.ReasonCryptoKeyGenerationFailed, keyShareErr, "TEE_T key share generation failed")
		} else {
			log.Fatalf("[TEE_K] CRITICAL: TEE_T key share generation failed without session context")
		}
	}
}

func (t *TEEK) handleTEETError(msg *shared.Message) {
	var errorData shared.ErrorData
	if err := msg.UnmarshalData(&errorData); err != nil {
		// Cannot parse TEE_T error - critical failure
		log.Fatalf("[TEE_K] CRITICAL: Failed to unmarshal TEE_T error: %v", err)
		return
	}

	// Any TEE_T error is critical and should terminate all sessions
	teetErr := fmt.Errorf("TEE_T error: %s", errorData.Message)
	log.Fatalf("[TEE_K] CRITICAL: %v", teetErr)
}

func (t *TEEK) requestKeyShareFromTEET(cipherSuite uint16) error {
	keyLen, ivLen, err := shared.GetKeyAndIVLengths(cipherSuite)
	if err != nil {
		return fmt.Errorf("unsupported cipher suite: %v", err)
	}

	fmt.Printf(" TEE_K requesting key share from TEE_T for cipher suite 0x%04x\n", cipherSuite)

	keyReq := shared.KeyShareRequestData{
		CipherSuite: cipherSuite,
		KeyLength:   keyLen,
		IVLength:    ivLen,
	}

	msg := shared.CreateMessage(shared.MsgKeyShareRequest, keyReq)
	return t.sendMessageToTEETForSession("", msg)
}

// requestKeyShareFromTEETWithSession requests a key share from TEE_T for split AEAD with session ID
func (t *TEEK) requestKeyShareFromTEETWithSession(sessionID string, cipherSuite uint16) error {
	keyLen, ivLen, err := shared.GetKeyAndIVLengths(cipherSuite)
	if err != nil {
		return fmt.Errorf("unsupported cipher suite: %v", err)
	}

	fmt.Printf(" TEE_K requesting key share from TEE_T for session %s, cipher suite 0x%04x\n", sessionID, cipherSuite)

	keyReq := shared.KeyShareRequestData{
		CipherSuite: cipherSuite,
		KeyLength:   keyLen,
		IVLength:    ivLen,
	}

	msg := shared.CreateMessage(shared.MsgKeyShareRequest, keyReq)
	return t.sendMessageToTEETForSession(sessionID, msg)
}

func (t *TEEK) sendEncryptedRequestToTEET(encryptedData, tagSecrets []byte, cipherSuite uint16, seqNum uint64, redactionRanges []shared.RedactionRange) error {
	fmt.Printf(" TEE_K sending encrypted request to TEE_T (%d bytes, %d ranges)\n", len(encryptedData), len(redactionRanges))

	encReq := shared.EncryptedRequestData{
		EncryptedData:   encryptedData,
		TagSecrets:      tagSecrets,
		CipherSuite:     cipherSuite,
		SeqNum:          seqNum,
		RedactionRanges: redactionRanges,
	}

	msg := shared.CreateMessage(shared.MsgEncryptedRequest, encReq)
	return t.sendMessageToTEETForSession("", msg)
}

// sendEncryptedRequestToTEETWithSession sends encrypted request data and tag secrets to TEE_T with session ID
func (t *TEEK) sendEncryptedRequestToTEETWithSession(sessionID string, encryptedData, tagSecrets []byte, cipherSuite uint16, seqNum uint64, redactionRanges []shared.RedactionRange, commitments [][]byte) error {
	fmt.Printf(" TEE_K sending encrypted request to TEE_T for session %s (%d bytes, %d ranges, %d commitments)\n", sessionID, len(encryptedData), len(redactionRanges), len(commitments))

	encReq := shared.EncryptedRequestData{
		EncryptedData:   encryptedData,
		TagSecrets:      tagSecrets,
		Commitments:     commitments,
		CipherSuite:     cipherSuite,
		SeqNum:          seqNum,
		RedactionRanges: redactionRanges,
	}

	msg := shared.CreateMessage(shared.MsgEncryptedRequest, encReq)
	return t.sendMessageToTEETForSession(sessionID, msg)
}

// Session-aware response handling methods
// Response handler functions - using batched approach

// generateDecryptionStream generates cipher-agnostic keystream for decryption
// Note: generateDecryptionStream functions have been consolidated into minitls.GenerateDecryptionStream

func (t *TEEK) generateResponseTagSecretsWithSession(sessionID string, responseLength int, seqNum uint64, cipherSuite uint16, recordHeader []byte, explicitIV []byte) ([]byte, error) {
	// Get TLS client from session state
	var tlsClient *minitls.Client
	if sessionID != "" {
		tlsState, err := t.getSessionTLSState(sessionID)
		if err != nil {
			return nil, fmt.Errorf("failed to get TLS state: %v", err)
		}
		if tlsClientInterface, ok := tlsState.TLSClient.(*minitls.Client); ok {
			tlsClient = tlsClientInterface
		}
	}

	if tlsClient == nil {
		return nil, fmt.Errorf("no TLS client available")
	}

	// Get server application keys based on TLS version
	var serverAppKey, serverAppIV []byte

	tlsVersion := tlsClient.GetNegotiatedVersion()
	if tlsVersion == 0x0303 { // TLS 1.2
		// Get server keys from TLS 1.2 AEAD context
		tls12AEAD := tlsClient.GetTLS12AEAD()
		if tls12AEAD == nil {
			return nil, fmt.Errorf("no TLS 1.2 AEAD available for response tag secrets")
		}

		serverAppKey = tls12AEAD.GetReadKey()
		serverAppIV = tls12AEAD.GetReadIV()

		fmt.Printf("[TEE_K] Using TLS 1.2 server keys for response tag secrets\n")
		fmt.Printf("[TEE_K] 🔑 Server Read Key: %x\n", serverAppKey)
		fmt.Printf("[TEE_K] 🔑 Server Read IV:  %x\n", serverAppIV)
	} else { // TLS 1.3
		// Get server application AEAD for tag secret generation
		serverAEAD := tlsClient.GetServerApplicationAEAD()
		if serverAEAD == nil {
			return nil, fmt.Errorf("no server application AEAD available")
		}

		// Get key schedule to access server application keys
		keySchedule := tlsClient.GetKeySchedule()
		if keySchedule == nil {
			return nil, fmt.Errorf("no key schedule available")
		}

		serverAppKey = keySchedule.GetServerApplicationKey()
		serverAppIV = keySchedule.GetServerApplicationIV()

		fmt.Printf("[TEE_K] Using TLS 1.3 server keys for response tag secrets\n")
	}

	if serverAppKey == nil || serverAppIV == nil {
		return nil, fmt.Errorf("missing server application key or IV")
	}

	// Construct version-specific AAD for tag secret generation (must match TEE_T's verification)
	var additionalData []byte

	if tlsVersion == 0x0303 { // TLS 1.2
		// TLS 1.2: AAD = seq_num(8) + record header(5) = 13 bytes total
		if len(recordHeader) != 5 {
			return nil, fmt.Errorf("invalid TLS 1.2 record header length: expected 5, got %d", len(recordHeader))
		}

		// Construct TLS 1.2 AAD: sequence_number(8) + record_header(5)
		additionalData = make([]byte, 13)

		// Sequence number (8 bytes, big-endian)
		additionalData[0] = byte(seqNum >> 56)
		additionalData[1] = byte(seqNum >> 48)
		additionalData[2] = byte(seqNum >> 40)
		additionalData[3] = byte(seqNum >> 32)
		additionalData[4] = byte(seqNum >> 24)
		additionalData[5] = byte(seqNum >> 16)
		additionalData[6] = byte(seqNum >> 8)
		additionalData[7] = byte(seqNum)

		// Record header (5 bytes) - use PLAINTEXT length for TLS 1.2 AAD
		additionalData[8] = recordHeader[0]              // content type (0x17)
		additionalData[9] = recordHeader[1]              // version major (0x03)
		additionalData[10] = recordHeader[2]             // version minor (0x03)
		additionalData[11] = byte(responseLength >> 8)   // plaintext length high byte
		additionalData[12] = byte(responseLength & 0xFF) // plaintext length low byte

		fmt.Printf("[TEE_K] TLS 1.2 tag secret AAD: seq=%d, plaintext_len=%d, aad=%x\n",
			seqNum, responseLength, additionalData)
	} else {
		// TLS 1.3: AAD = record header with ciphertext+tag length (5 bytes)
		tagSize := 16                                // GCM tag size
		ciphertextLength := responseLength + tagSize // encrypted data + authentication tag
		additionalData = []byte{
			0x17,                          // ApplicationData
			0x03,                          // TLS version major (compatibility)
			0x03,                          // TLS version minor (compatibility)
			byte(ciphertextLength >> 8),   // Length high byte (includes tag)
			byte(ciphertextLength & 0xFF), // Length low byte (includes tag)
		}

		fmt.Printf("[TEE_K] TLS 1.3 tag secret AAD: %x (ciphertext+tag length: %d)\n", additionalData, ciphertextLength)
	}

	// For TLS 1.2, server sequence matches client sequence (both start at 1 after handshake)
	// For TLS 1.3, server sequence = client sequence - 1 (server starts at 0)
	var actualSeqToUse uint64
	if tlsVersion == 0x0303 { // TLS 1.2
		actualSeqToUse = seqNum // Server sequence matches client sequence
		fmt.Printf("[TEE_K] TLS 1.2: Using server sequence %d (same as client sequence)\n", actualSeqToUse)
	} else { // TLS 1.3
		actualSeqToUse = seqNum - 1
		fmt.Printf("[TEE_K] TLS 1.3: Using server sequence %d (client sequence %d - 1)\n", actualSeqToUse, seqNum)
	}

	if tlsVersion == 0x0303 { // TLS 1.2
		if len(explicitIV) > 0 && shared.IsTLS12AESGCMCipherSuite(cipherSuite) {
			// TLS 1.2 AES-GCM with explicit IV
			if len(explicitIV) != 8 {
				return nil, fmt.Errorf("TLS 1.2 explicit IV must be 8 bytes, got %d", len(explicitIV))
			}

			// Parse explicit IV as uint64 (like minitls does)
			explicitIVUint64 := binary.BigEndian.Uint64(explicitIV)

			// Construct nonce: implicit_iv(4) || explicit_nonce(8)
			nonce := make([]byte, 12)                                 // GCM nonce is 12 bytes
			copy(nonce[0:4], serverAppIV[0:4])                        // 4-byte implicit IV
			binary.BigEndian.PutUint64(nonce[4:12], explicitIVUint64) // 8-byte explicit IV as uint64

			fmt.Printf("[TEE_K] TLS 1.2 AES-GCM nonce construction: implicit_iv=%x + explicit_iv_uint64=%d = nonce=%x\n",
				serverAppIV[0:4], explicitIVUint64, nonce)

			// Generate AES-GCM tag secrets using the constructed nonce
			block, err := aes.NewCipher(serverAppKey)
			if err != nil {
				return nil, fmt.Errorf("failed to create AES cipher: %v", err)
			}

			// Generate tag secrets: E_K(0^128) || E_K(nonce||1)
			tagSecrets := make([]byte, 32)

			// E_K(0^128) - first 16 bytes
			zeros := make([]byte, 16)
			block.Encrypt(tagSecrets[0:16], zeros)

			// E_K(nonce||1) - last 16 bytes
			nonceWith1 := make([]byte, 16)
			copy(nonceWith1, nonce)
			nonceWith1[15] = 1
			block.Encrypt(tagSecrets[16:32], nonceWith1)

			fmt.Printf("[TEE_K] Generated TLS 1.2 AES-GCM tag secrets: E_K(0^128)=%x, E_K(nonce||1)=%x\n",
				tagSecrets[0:16], tagSecrets[16:32])

			return tagSecrets, nil
		} else if shared.IsTLS12ChaCha20Poly1305CipherSuite(cipherSuite) {
			// TLS 1.2 ChaCha20-Poly1305 (no explicit IV)
			// Use TLS 1.2 ChaCha20 nonce construction: IV XOR sequence number
			nonce := make([]byte, len(serverAppIV))
			copy(nonce, serverAppIV)
			for i := 0; i < 8; i++ {
				nonce[len(nonce)-1-i] ^= byte(actualSeqToUse >> (8 * i))
			}

			fmt.Printf("[TEE_K] TLS 1.2 ChaCha20 nonce construction: iv=%x XOR seq=%d = nonce=%x\n",
				serverAppIV, actualSeqToUse, nonce)

			// Use consolidated minitls function for ChaCha20-Poly1305 tag secrets
			splitAEAD := minitls.NewSplitAEAD(serverAppKey, serverAppIV, cipherSuite)
			splitAEAD.SetSequence(actualSeqToUse)

			// Create dummy encrypted data to generate tag secrets
			dummyEncrypted := make([]byte, responseLength)

			// Generate tag secrets using the same method as requests
			_, tagSecrets, err := splitAEAD.EncryptWithoutTag(dummyEncrypted, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to generate tag secrets: %v", err)
			}

			return tagSecrets, nil
		} else {
			return nil, fmt.Errorf("unsupported TLS 1.2 cipher suite: 0x%04x", cipherSuite)
		}
	} else {
		// TLS 1.3 or TLS 1.2 without explicit IV (use standard SplitAEAD)
		splitAEAD := minitls.NewSplitAEAD(serverAppKey, serverAppIV, cipherSuite)

		// Set sequence number to match server's current state
		splitAEAD.SetSequence(actualSeqToUse)

		// Create dummy encrypted data to generate tag secrets
		dummyEncrypted := make([]byte, responseLength)

		// Generate tag secrets using the same method as requests
		_, tagSecrets, err := splitAEAD.EncryptWithoutTag(dummyEncrypted, additionalData)
		if err != nil {
			return nil, fmt.Errorf("failed to generate tag secrets: %v", err)
		}

		return tagSecrets, nil
	}
}

// All response handler functions use batched approach

// Single Session Mode: Transcript collection methods

// addToTranscriptForSessionWithType safely adds a packet with explicit type to the session's transcript.
func (t *TEEK) addToTranscriptForSessionWithType(sessionID string, packet []byte, packetType string) {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		log.Printf("[TEE_K] Failed to get session %s for transcript: %v", sessionID, err)
		return
	}

	session.TranscriptMutex.Lock()
	defer session.TranscriptMutex.Unlock()

	// Copy buffer to avoid unexpected mutation
	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)

	session.TranscriptPackets = append(session.TranscriptPackets, pktCopy)
	session.TranscriptPacketTypes = append(session.TranscriptPacketTypes, packetType)

	fmt.Printf("[TEE_K] Added packet to session %s transcript (%d bytes, type=%s, total packets: %d)\n",
		sessionID, len(packet), packetType, len(session.TranscriptPackets))
}

// addToTranscriptForSession safely adds a packet to the session's transcript collection
func (t *TEEK) addToTranscriptForSession(sessionID string, packet []byte) {
	// Default to TLS record type for backwards compatibility
	t.addToTranscriptForSessionWithType(sessionID, packet, shared.TranscriptPacketTypeTLSRecord)
}

// getTranscriptForSession safely returns a copy of the session's transcript
func (t *TEEK) getTranscriptForSession(sessionID string) [][]byte {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		log.Printf("[TEE_K] Failed to get session %s for transcript: %v", sessionID, err)
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

// handleFinishedFromTEETSession handles finished messages from TEE_T
func (t *TEEK) handleFinishedFromTEETSession(sessionID string, msg *shared.Message) {
	log.Printf("[TEE_K] Handling finished response from TEE_T for session %s", sessionID)

	var finishedMsg shared.FinishedMessage
	if err := msg.UnmarshalData(&finishedMsg); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal finished message from TEE_T: %v", err)
		return
	}

	// Note: Source field removed - message context determines source

	log.Printf("[TEE_K] Received finished confirmation from TEE_T, preparing transcript data")

	// Get session for transcript data
	sessionForSigned, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		log.Printf("[TEE_K] Failed to get session %s: %v", sessionID, err)
		return
	}

	sessionForSigned.TranscriptMutex.Lock()
	defer sessionForSigned.TranscriptMutex.Unlock()

	if len(sessionForSigned.TranscriptPackets) == 0 {
		log.Printf("[TEE_K] No transcript packets to sign for session %s", sessionID)
		return
	}

	// Separate TLS packets from metadata
	tlsPackets := make([][]byte, 0)
	tlsPacketTypes := make([]string, 0)
	var requestMetadata *shared.RequestMetadata

	for i, packet := range sessionForSigned.TranscriptPackets {
		packetType := ""
		if i < len(sessionForSigned.TranscriptPacketTypes) {
			packetType = sessionForSigned.TranscriptPacketTypes[i]
		}

		switch packetType {
		case shared.TranscriptPacketTypeTLSRecord:
			tlsPackets = append(tlsPackets, packet)
			tlsPacketTypes = append(tlsPacketTypes, packetType)
		case shared.TranscriptPacketTypeHTTPRequestRedacted:
			if requestMetadata == nil {
				requestMetadata = &shared.RequestMetadata{}
			}
			requestMetadata.RedactedRequest = packet
		// Note: Commitments are no longer included in TEE_K transcript
		// TEE_T verifies commitments and signs the proof stream
		case "redaction_ranges":
			if requestMetadata == nil {
				requestMetadata = &shared.RequestMetadata{}
			}
			// Unmarshal the redaction ranges from JSON
			var ranges []shared.RedactionRange
			if err := json.Unmarshal(packet, &ranges); err != nil {
				log.Printf("[TEE_K] Failed to unmarshal redaction ranges from transcript: %v", err)
			} else {
				requestMetadata.RedactionRanges = ranges
				log.Printf("[TEE_K] Loaded %d redaction ranges from transcript", len(ranges))
			}
		default:
			// Default to TLS record for unknown types
			tlsPackets = append(tlsPackets, packet)
			tlsPacketTypes = append(tlsPacketTypes, shared.TranscriptPacketTypeTLSRecord)
		}
	}

	if t.signingKeyPair == nil {
		log.Printf("[TEE_K] No signing key pair available")
		return
	}

	// Just log that transcript is ready, but wait for redaction processing to complete
	log.Printf("[TEE_K] Session %s: Transcript prepared with %d TLS packets, waiting for redaction processing to complete before sending signature", sessionID, len(tlsPackets))

	// Check if all processing is complete and we can send signature
	if err := t.checkAndSendSignatureIfReady(sessionID); err != nil {
		log.Printf("[TEE_K] Failed to check signature readiness: %v", err)
		return
	}
}

// handleFinishedFromClientSession handles finished messages from clients
func (t *TEEK) handleFinishedFromClientSession(sessionID string, msg *shared.Message) {
	log.Printf("[TEE_K] Handling finished message from client for session %s", sessionID)

	var finishedMsg shared.FinishedMessage
	if err := msg.UnmarshalData(&finishedMsg); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal finished message: %v", err)
		return
	}

	// Note: Source field removed - message context determines source

	log.Printf("[TEE_K] Received finished command from client, forwarding to TEE_T")

	// Forward finished message to TEE_T
	teekFinishedMsg := shared.FinishedMessage{}

	forwardMsg := shared.CreateSessionMessage(shared.MsgFinished, sessionID, teekFinishedMsg)
	if err := t.sendMessageToTEETForSession(sessionID, forwardMsg); err != nil {
		log.Printf("[TEE_K] Failed to forward finished message to TEE_T: %v", err)
		return
	}

	log.Printf("[TEE_K] Forwarded finished message to TEE_T, waiting for response")

	// The response from TEE_T will come through handleTEETMessages
	// and will trigger transcript generation and signing
}

// handleRedactionSpecSession handles redaction specification from client
func (t *TEEK) handleRedactionSpecSession(sessionID string, msg *shared.Message) {
	log.Printf("[TEE_K] Session %s: Handling redaction specification", sessionID)

	var redactionSpec shared.RedactionSpec
	if err := msg.UnmarshalData(&redactionSpec); err != nil {
		log.Printf("[TEE_K] Session %s: Failed to unmarshal redaction spec: %v", sessionID, err)
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, fmt.Errorf("failed to parse redaction specification"), "failed to parse redaction specification")
		return
	}

	log.Printf("[TEE_K] Session %s: Received redaction spec with %d ranges", sessionID, len(redactionSpec.Ranges))

	// Validate redaction ranges
	if err := t.validateRedactionSpec(redactionSpec); err != nil {
		log.Printf("[TEE_K] Session %s: Invalid redaction spec: %v", sessionID, err)
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Invalid redaction specification: %v", err))
		return
	}

	// Generate and send redacted decryption streams
	if err := t.generateAndSendRedactedDecryptionStream(sessionID, redactionSpec); err != nil {
		log.Printf("[TEE_K] Session %s: Failed to generate redacted streams: %v", sessionID, err)
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to generate redacted streams: %v", err))
		return
	}

	log.Printf("[TEE_K] Session %s: Successfully processed redaction specification", sessionID)
}

// validateRedactionSpec validates the redaction specification from client
func (t *TEEK) validateRedactionSpec(spec shared.RedactionSpec) error {
	// Validate ranges don't overlap and are within bounds
	for i, range1 := range spec.Ranges {
		// Check if range has redaction bytes
		if len(range1.RedactionBytes) != range1.Length {
			return fmt.Errorf("range %d: redaction bytes length (%d) doesn't match range length (%d)",
				i, len(range1.RedactionBytes), range1.Length)
		}

		// Check for overlaps with other ranges
		for j := i + 1; j < len(spec.Ranges); j++ {
			range2 := spec.Ranges[j]
			if rangesOverlap(range1, range2) {
				return fmt.Errorf("ranges %d and %d overlap", i, j)
			}
		}

		// Basic bounds check (we'll validate against actual packet boundaries later)
		if range1.Start < 0 || range1.Length <= 0 {
			return fmt.Errorf("range %d: invalid bounds (start=%d, length=%d)", i, range1.Start, range1.Length)
		}
	}

	return nil
}

// rangesOverlap checks if two redaction ranges overlap
func rangesOverlap(r1, r2 shared.RedactionRange) bool {
	return r1.Start < r2.Start+r2.Length && r2.Start < r1.Start+r1.Length
}

// generateAndSendRedactedDecryptionStream creates redacted decryption streams but defers signature sending until all processing is complete
func (t *TEEK) generateAndSendRedactedDecryptionStream(sessionID string, spec shared.RedactionSpec) error {
	log.Printf("[TEE_K] Session %s: Generating redacted decryption stream with %d ranges", sessionID, len(spec.Ranges))

	// Get session to access response state
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("session %s not found: %v", sessionID, err)
	}

	// Get response state for this session
	if session.ResponseState == nil {
		return fmt.Errorf("no response state available for session %s", sessionID)
	}

	// Get all response lengths for this session
	totalLength := 0
	seqNumbers := make([]uint64, 0)

	for seqNum, length := range session.ResponseState.ResponseLengthBySeq {
		totalLength += int(length) // Convert from uint32 to int
		seqNumbers = append(seqNumbers, seqNum)
	}

	sort.Slice(seqNumbers, func(i, j int) bool {
		return seqNumbers[i] < seqNumbers[j]
	})

	if totalLength == 0 {
		return fmt.Errorf("no response data available for redaction in session %s", sessionID)
	}

	log.Printf("[TEE_K] Session %s: Total response length: %d bytes across %d sequences",
		sessionID, totalLength, len(seqNumbers))

	// Clear any existing redacted streams for this session
	session.StreamsMutex.Lock()
	session.RedactedStreams = make([]shared.SignedRedactedDecryptionStream, 0)
	session.StreamsMutex.Unlock()

	// Create redacted decryption stream for each sequence
	currentOffset := 0
	for _, seqNum := range seqNumbers {
		length := int(session.ResponseState.ResponseLengthBySeq[seqNum])

		// Get server application key and IV for response decryption
		tlsState, err := t.getSessionTLSState(sessionID)
		if err != nil {
			return fmt.Errorf("failed to get TLS state: %v", err)
		}

		tlsClient, ok := tlsState.TLSClient.(*minitls.Client)
		if tlsClient == nil || !ok {
			return fmt.Errorf("no TLS client available for decryption key")
		}

		// Get server application keys based on TLS version
		var serverAppKey, serverAppIV []byte

		tlsVersion := tlsClient.GetNegotiatedVersion()
		if tlsVersion == 0x0303 { // TLS 1.2
			// Get server keys from TLS 1.2 AEAD context
			tls12AEAD := tlsClient.GetTLS12AEAD()
			if tls12AEAD == nil {
				return fmt.Errorf("no TLS 1.2 AEAD available for redacted decryption")
			}

			serverAppKey = tls12AEAD.GetReadKey()
			serverAppIV = tls12AEAD.GetReadIV()

			fmt.Printf("[TEE_K] Session %s: Using TLS 1.2 server keys for redacted decryption stream\n", sessionID)
		} else { // TLS 1.3
			keySchedule := tlsClient.GetKeySchedule()
			if keySchedule == nil {
				return fmt.Errorf("no key schedule available")
			}

			serverAppKey = keySchedule.GetServerApplicationKey()
			serverAppIV = keySchedule.GetServerApplicationIV()

			fmt.Printf("[TEE_K] Session %s: Using TLS 1.3 server keys for redacted decryption stream\n", sessionID)
		}

		if serverAppKey == nil || serverAppIV == nil {
			return fmt.Errorf("missing server application key or IV")
		}

		// Get cipher suite from TLS client
		cipherSuite := tlsClient.GetCipherSuite()

		// Generate original decryption stream for this sequence using server application key
		// For TLS 1.2 AES-GCM, retrieve the stored explicit IV for this sequence
		var explicitIV []byte
		responseState, err := t.getSessionResponseState(sessionID)
		if err == nil && responseState.ExplicitIVBySeq != nil {
			explicitIV = responseState.ExplicitIVBySeq[seqNum]
		}

		// Use same sequence logic as tag generation for consistency
		var serverSeqNum uint64
		if tlsVersion == 0x0303 { // TLS 1.2
			serverSeqNum = seqNum // Server sequence matches client sequence
			fmt.Printf("[TEE_K] TLS 1.2 redacted decryption: Using server sequence %d (same as client)\n", serverSeqNum)
		} else { // TLS 1.3
			serverSeqNum = seqNum - 1
			fmt.Printf("[TEE_K] TLS 1.3 redacted decryption: Using server sequence %d (client - 1)\n", serverSeqNum)
		}
		originalStream, err := minitls.GenerateDecryptionStream(serverAppKey, serverAppIV, serverSeqNum, length, cipherSuite, explicitIV)
		if err != nil {
			return fmt.Errorf("failed to generate original decryption stream for seq %d: %v", seqNum, err)
		}

		// Apply redaction to this stream
		redactedStream := make([]byte, len(originalStream))
		copy(redactedStream, originalStream)

		// Apply redaction ranges that fall within this sequence
		for _, redactionRange := range spec.Ranges {
			rangeStart := redactionRange.Start
			rangeEnd := redactionRange.Start + redactionRange.Length

			// The explicit IV is part of the TLS record but NOT part of the encrypted data
			// The keystream only decrypts the actual encrypted data, not the explicit IV
			// So redaction ranges should NOT be offset for TLS 1.2
			log.Printf("[TEE_K] DEBUG: Redaction range [%d:%d] (no offset adjustment)", rangeStart, rangeEnd)

			// Check if this range overlaps with current sequence
			seqStart := currentOffset
			seqEnd := currentOffset + length

			if rangeStart < seqEnd && rangeEnd > seqStart {
				// Calculate overlap
				overlapStart := max(rangeStart, seqStart) - seqStart
				overlapEnd := min(rangeEnd, seqEnd) - seqStart
				overlapLength := overlapEnd - overlapStart

				if overlapLength > 0 {
					// Calculate offset within the redaction range
					redactionOffset := max(0, seqStart-rangeStart)

					// Copy redaction bytes for this overlap
					for i := 0; i < overlapLength; i++ {
						if overlapStart+i < len(redactedStream) && redactionOffset+i < len(redactionRange.RedactionBytes) {
							redactedStream[overlapStart+i] = redactionRange.RedactionBytes[redactionOffset+i]
						}
					}

					log.Printf("[TEE_K] Session %s: Applied redaction to seq %d at offset %d-%d (type: %s)",
						sessionID, seqNum, overlapStart, overlapStart+overlapLength-1, redactionRange.Type)
				}
			}
		}

		// Store redacted stream in session for master signature generation
		streamData := shared.SignedRedactedDecryptionStream{
			RedactedStream: redactedStream,
			SeqNum:         seqNum,
		}

		session.StreamsMutex.Lock()
		session.RedactedStreams = append(session.RedactedStreams, streamData)
		session.StreamsMutex.Unlock()

		log.Printf("[TEE_K] Session %s: Generated redacted decryption stream for seq %d (%d bytes)",
			sessionID, seqNum, len(redactedStream))

		currentOffset += length
	}

	// Instead of immediately sending signature, mark redaction processing as complete
	session.StreamsMutex.Lock()
	session.RedactionProcessingComplete = true
	session.StreamsMutex.Unlock()

	log.Printf("[TEE_K] Session %s: Redaction processing complete, checking if ready to send signature", sessionID)

	// Check if all processing is complete and we can send signature
	if err := t.checkAndSendSignatureIfReady(sessionID); err != nil {
		return fmt.Errorf("failed to check signature readiness: %v", err)
	}

	return nil
}

// checkAndSendSignatureIfReady checks if all processing is complete and sends signature if ready
func (t *TEEK) checkAndSendSignatureIfReady(sessionID string) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("session %s not found: %v", sessionID, err)
	}

	// Check if all required processing is complete
	session.TranscriptMutex.Lock()
	transcriptReady := len(session.TranscriptPackets) > 0
	session.TranscriptMutex.Unlock()

	session.StreamsMutex.Lock()
	redactionComplete := session.RedactionProcessingComplete
	hasRedactedStreams := len(session.RedactedStreams) > 0
	session.StreamsMutex.Unlock()

	// All processing is complete when:
	// 1. We have transcript data (from finished message)
	// 2. Redaction processing is complete
	// 3. We have redacted streams
	allProcessingComplete := transcriptReady && redactionComplete && hasRedactedStreams

	if allProcessingComplete {
		log.Printf("[TEE_K] Session %s: All processing complete, generating and sending signature", sessionID)
		return t.generateComprehensiveSignatureAndSendTranscript(sessionID)
	} else {
		log.Printf("[TEE_K] Session %s: Not ready to send signature yet - transcript:%v redaction:%v streams:%v",
			sessionID, transcriptReady, redactionComplete, hasRedactedStreams)
	}

	return nil
}

// generateComprehensiveSignatureAndSendTranscript creates comprehensive signature and sends all verification data to client
func (t *TEEK) generateComprehensiveSignatureAndSendTranscript(sessionID string) error {
	log.Printf("[TEE_K] Session %s: Generating comprehensive signature", sessionID)

	// Get session
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("session %s not found: %v", sessionID, err)
	}

	if t.signingKeyPair == nil {
		return fmt.Errorf("no signing key pair available")
	}

	// Get transcript data
	session.TranscriptMutex.Lock()
	defer session.TranscriptMutex.Unlock()

	// Get redacted streams
	session.StreamsMutex.Lock()
	defer session.StreamsMutex.Unlock()

	// Separate TLS packets from metadata
	tlsPackets := make([][]byte, 0)
	var requestMetadata *shared.RequestMetadata

	for i, packet := range session.TranscriptPackets {
		packetType := ""
		if i < len(session.TranscriptPacketTypes) {
			packetType = session.TranscriptPacketTypes[i]
		}

		switch packetType {
		case shared.TranscriptPacketTypeTLSRecord:
			tlsPackets = append(tlsPackets, packet)
		case shared.TranscriptPacketTypeHTTPRequestRedacted:
			if requestMetadata == nil {
				requestMetadata = &shared.RequestMetadata{}
			}
			requestMetadata.RedactedRequest = packet
		// Note: Commitments are no longer included in TEE_K transcript
		// TEE_T verifies commitments and signs the proof stream
		case "redaction_ranges":
			if requestMetadata == nil {
				requestMetadata = &shared.RequestMetadata{}
			}
			// Unmarshal the redaction ranges from JSON
			var ranges []shared.RedactionRange
			if err := json.Unmarshal(packet, &ranges); err != nil {
				log.Printf("[TEE_K] Failed to unmarshal redaction ranges from transcript: %v", err)
			} else {
				requestMetadata.RedactionRanges = ranges
				log.Printf("[TEE_K] Session %s: Loaded %d redaction ranges from transcript", sessionID, len(ranges))
			}
		default:
			// Default to TLS record for unknown types
			tlsPackets = append(tlsPackets, packet)
		}
	}

	// Generate master signature over: request metadata + redacted streams + TLS packets
	var masterBuffer bytes.Buffer

	// Add request metadata
	if requestMetadata != nil {
		masterBuffer.Write(requestMetadata.RedactedRequest)
		// Note: Commitments are no longer included in signature
		// TEE_T verifies commitments and signs the proof stream
		// Include redaction ranges in signature to prevent manipulation
		if len(requestMetadata.RedactionRanges) > 0 {
			redactionRangesBytes, err := json.Marshal(requestMetadata.RedactionRanges)
			if err != nil {
				return fmt.Errorf("failed to marshal redaction ranges for signature: %v", err)
			}
			masterBuffer.Write(redactionRangesBytes)
		}
	}

	// Add redacted streams
	for _, stream := range session.RedactedStreams {
		masterBuffer.Write(stream.RedactedStream)
	}

	// Add TLS packets
	for _, packet := range tlsPackets {
		masterBuffer.Write(packet)
	}

	comprehensiveSignature, err := t.signingKeyPair.SignData(masterBuffer.Bytes())
	if err != nil {
		return fmt.Errorf("failed to generate comprehensive signature: %v", err)
	}

	// Get public key in DER format
	publicKeyDER, err := t.signingKeyPair.GetPublicKeyDER()
	if err != nil {
		return fmt.Errorf("failed to get public key DER: %v", err)
	}

	// Create signed transcript with comprehensive signature
	signedTranscript := shared.SignedTranscript{
		Packets:         tlsPackets,
		RequestMetadata: requestMetadata,
		Signature:       comprehensiveSignature,
		PublicKey:       publicKeyDER,
	}

	log.Printf("[TEE_K] Session %s: Generated comprehensive signature over %d TLS packets, %d redacted streams, metadata present: %v",
		sessionID, len(tlsPackets), len(session.RedactedStreams), requestMetadata != nil)

	// Debug: Check what we're sending
	log.Printf("[TEE_K] DEBUG: Sending transcript with comprehensive signature: %d bytes",
		len(signedTranscript.Signature))

	// Send signed transcript to client
	transcriptMsg := shared.CreateSessionMessage(shared.MsgSignedTranscript, sessionID, signedTranscript)
	if err := session.ClientConn.WriteJSON(transcriptMsg); err != nil {
		return fmt.Errorf("failed to send signed transcript: %v", err)
	}

	// Send batched redacted streams to client (constant message count, not data-dependent)
	if len(session.RedactedStreams) > 0 {
		batchedRedactedStreams := shared.BatchedSignedRedactedDecryptionStreamData{
			SignedRedactedStreams: session.RedactedStreams,
			SessionID:             sessionID,
			TotalCount:            len(session.RedactedStreams),
		}

		batchedStreamMsg := shared.CreateSessionMessage(shared.MsgBatchedSignedRedactedDecryptionStreams, sessionID, batchedRedactedStreams)
		if err := session.ClientConn.WriteJSON(batchedStreamMsg); err != nil {
			return fmt.Errorf("failed to send batched redacted streams: %v", err)
		}

		log.Printf("[TEE_K] Session %s: Sent signed transcript and batched %d redacted streams to client", sessionID, len(session.RedactedStreams))
	} else {
		log.Printf("[TEE_K] Session %s: Sent signed transcript (no redacted streams to send)", sessionID)
	}
	return nil
}

// handleAttestationRequestSession handles attestation requests from clients over WebSocket
func (t *TEEK) handleAttestationRequestSession(sessionID string, msg *shared.Message) {
	var attestReq shared.AttestationRequestData
	if err := msg.UnmarshalData(&attestReq); err != nil {
		log.Printf("[TEE_K] Session %s: Failed to unmarshal attestation request: %v", sessionID, err)
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, fmt.Errorf("failed to parse attestation request"), "failed to parse attestation request")
		return
	}

	log.Printf("[TEE_K] Session %s: Processing attestation request", sessionID)

	// Get attestation from enclave manager if available
	if t.signingKeyPair == nil {
		log.Printf("[TEE_K] Session %s: No signing key pair available for attestation", sessionID)
		t.sendAttestationResponse(sessionID, nil, false, "No signing key pair available")
		return
	}

	// Generate attestation document using enclave manager
	publicKeyDER, err := t.signingKeyPair.GetPublicKeyDER()
	if err != nil {
		log.Printf("[TEE_K] Session %s: Failed to get public key DER: %v", sessionID, err)
		t.sendAttestationResponse(sessionID, nil, false, "Failed to get public key")
		return
	}

	// Create user data containing the hex-encoded ECDSA public key
	userData := fmt.Sprintf("tee_k_public_key:%x", publicKeyDER)
	log.Printf("[TEE_K] Session %s: Including ECDSA public key in attestation (DER: %d bytes)", sessionID, len(publicKeyDER))

	// Generate attestation document using enclave manager
	if t.enclaveManager == nil {
		log.Printf("[TEE_K] Session %s: No enclave manager available for attestation", sessionID)
		t.sendAttestationResponse(sessionID, nil, false, "No enclave manager available")
		return
	}

	attestationDoc, err := t.enclaveManager.GenerateAttestation(context.Background(), []byte(userData))
	if err != nil {
		log.Printf("[TEE_K] Session %s: Failed to generate attestation: %v", sessionID, err)
		t.sendAttestationResponse(sessionID, nil, false, fmt.Sprintf("Failed to generate attestation: %v", err))
		return
	}

	log.Printf("[TEE_K] Session %s: Generated attestation document (%d bytes)", sessionID, len(attestationDoc))

	// Send successful response
	t.sendAttestationResponse(sessionID, attestationDoc, true, "")
}

// sendAttestationResponse sends attestation response to client (request ID removed)
func (t *TEEK) sendAttestationResponse(sessionID string, attestationDoc []byte, success bool, errorMessage string) {
	response := shared.AttestationResponseData{
		AttestationDoc: attestationDoc,
		Success:        success,
		ErrorMessage:   errorMessage,
	}

	msg := shared.CreateSessionMessage(shared.MsgAttestationResponse, sessionID, response)
	if err := t.sessionManager.RouteToClient(sessionID, msg); err != nil {
		log.Printf("[TEE_K] Session %s: Failed to send attestation response: %v", sessionID, err)
	}
}

// constructNonce creates the appropriate nonce for a given cipher suite and sequence number
// Following RFC specifications and minitls implementation exactly
func (t *TEEK) constructNonce(iv []byte, seqNum uint64, cipherSuite uint16) []byte {
	switch cipherSuite {
	// TLS 1.3 cipher suites - IV XOR sequence number (RFC 8446)
	case 0x1301, 0x1302, 0x1303: // All TLS 1.3 cipher suites
		nonce := make([]byte, len(iv))
		copy(nonce, iv)
		for i := 0; i < 8; i++ {
			nonce[len(nonce)-1-i] ^= byte(seqNum >> (8 * i))
		}
		return nonce

	// TLS 1.2 AES-GCM - explicit nonce format (RFC 5288)
	case shared.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, shared.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, shared.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, shared.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: // TLS 1.2 AES-GCM cipher suites
		// 12-byte nonce = implicit_iv(4) || explicit_nonce(8)
		nonce := make([]byte, 12)
		copy(nonce[0:4], iv) // 4-byte implicit IV
		// 8-byte explicit nonce = sequence number (big-endian)
		nonce[4] = byte(seqNum >> 56)
		nonce[5] = byte(seqNum >> 48)
		nonce[6] = byte(seqNum >> 40)
		nonce[7] = byte(seqNum >> 32)
		nonce[8] = byte(seqNum >> 24)
		nonce[9] = byte(seqNum >> 16)
		nonce[10] = byte(seqNum >> 8)
		nonce[11] = byte(seqNum)
		return nonce

	// TLS 1.2 ChaCha20 - IV XOR sequence number (RFC 7905)
	case shared.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, shared.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: // TLS 1.2 ChaCha20-Poly1305 cipher suites
		nonce := make([]byte, len(iv))
		copy(nonce, iv)
		for i := 0; i < 8; i++ {
			nonce[len(nonce)-1-i] ^= byte(seqNum >> (8 * i))
		}
		return nonce

	default:
		// Fallback to TLS 1.3 style for unknown cipher suites
		nonce := make([]byte, len(iv))
		copy(nonce, iv)
		for i := 0; i < 8; i++ {
			nonce[len(nonce)-1-i] ^= byte(seqNum >> (8 * i))
		}
		return nonce
	}
}

// Note: All crypto functions have been consolidated into minitls package
// This eliminates code duplication and ensures consistent behavior

func (t *TEEK) handleBatchedResponseLengthsSession(sessionID string, msg *shared.Message) {
	var batchedLengths shared.BatchedResponseLengthData
	if err := msg.UnmarshalData(&batchedLengths); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal batched response lengths for session %s: %v", sessionID, err)
		return
	}

	fmt.Printf("[TEE_K] BATCHING: Received batch of %d response lengths for session %s\n",
		batchedLengths.TotalCount, sessionID)

	// Get session to store response lengths
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		log.Printf("[TEE_K] Failed to get session %s for batched lengths: %v", sessionID, err)
		return
	}

	// Initialize ResponseState if needed
	if session.ResponseState == nil {
		session.ResponseState = &shared.ResponseSessionState{
			PendingEncryptedResponses: make(map[uint64]*shared.EncryptedResponseData),
			ResponseLengthBySeq:       make(map[uint64]uint32),
			ResponseLengthBySeqInt:    make(map[uint64]int),
			ExplicitIVBySeq:           make(map[uint64][]byte),
		}
	}

	// Process each length in the batch and generate tag secrets
	var tagSecrets []struct {
		TagSecrets  []byte `json:"tag_secrets"`
		SeqNum      uint64 `json:"seq_num"`
		CipherSuite uint16 `json:"cipher_suite"`
	}

	session.ResponseState.ResponsesMutex.Lock()
	for _, lengthData := range batchedLengths.Lengths {
		// Store response lengths in session state for later decryption stream generation
		session.ResponseState.ResponseLengthBySeqInt[lengthData.SeqNum] = lengthData.Length
		session.ResponseState.ResponseLengthBySeq[lengthData.SeqNum] = uint32(lengthData.Length)

		// Store explicit IV for TLS 1.2 AES-GCM decryption stream generation
		if lengthData.ExplicitIV != nil {
			session.ResponseState.ExplicitIVBySeq[lengthData.SeqNum] = lengthData.ExplicitIV
		}

		// Global state removed - using session state only

		// Global state removed - using session state only

		// Generate tag secrets for this response
		tagSecretsBytes, err := t.generateResponseTagSecretsWithSession(
			sessionID,
			lengthData.Length,
			lengthData.SeqNum,
			lengthData.CipherSuite,
			lengthData.RecordHeader,
			lengthData.ExplicitIV,
		)
		if err != nil {
			log.Printf("[TEE_K] Failed to generate tag secrets for seq %d in batch: %v", lengthData.SeqNum, err)
			continue
		}

		tagSecrets = append(tagSecrets, struct {
			TagSecrets  []byte `json:"tag_secrets"`
			SeqNum      uint64 `json:"seq_num"`
			CipherSuite uint16 `json:"cipher_suite"`
		}{
			TagSecrets:  tagSecretsBytes,
			SeqNum:      lengthData.SeqNum,
			CipherSuite: lengthData.CipherSuite,
		})
	}
	session.ResponseState.ResponsesMutex.Unlock()

	fmt.Printf("[TEE_K] BATCHING: Generated %d tag secrets for session %s\n", len(tagSecrets), sessionID)

	// Send all tag secrets as a batch to TEE_T
	batchedTagSecrets := shared.BatchedTagSecretsData{
		TagSecrets: tagSecrets,
		SessionID:  sessionID,
		TotalCount: len(tagSecrets),
	}

	tagSecretsMsg := shared.CreateSessionMessage(shared.MsgBatchedTagSecrets, sessionID, batchedTagSecrets)

	if err := t.sendMessageToTEETForSession(sessionID, tagSecretsMsg); err != nil {
		log.Printf("[TEE_K] Failed to send batched tag secrets to TEE_T for session %s: %v", sessionID, err)
		return
	}

	fmt.Printf("[TEE_K] BATCHING: Successfully sent batch of %d tag secrets to TEE_T\n", len(tagSecrets))
}

// Helper function logic inlined in batched handler

func (t *TEEK) handleBatchedTagVerificationsSession(sessionID string, msg *shared.Message) {
	var batchedVerification shared.BatchedTagVerificationData
	if err := msg.UnmarshalData(&batchedVerification); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal batched tag verification for session %s: %v", sessionID, err)
		return
	}

	fmt.Printf("[TEE_K] BATCHING: Received batch tag verification for session %s (%d verifications, all successful: %v)\n",
		sessionID, batchedVerification.TotalCount, batchedVerification.AllSuccessful)

	if !batchedVerification.AllSuccessful {
		log.Printf("[TEE_K] BATCHING: Some tag verifications failed - not sending decryption streams")
		return
	}

	// Generate decryption streams based on verification results
	var decryptionStreams []shared.ResponseDecryptionStreamData

	if batchedVerification.AllSuccessful {
		// All verifications passed - generate streams for all responses
		responseState, err := t.getSessionResponseState(sessionID)
		if err != nil {
			log.Printf("[TEE_K] Session %s: Failed to get response state: %v", sessionID, err)
			return
		}

		// Generate decryption streams for all response sequences
		for seqNum, responseLength := range responseState.ResponseLengthBySeqInt {
			// Generate decryption stream using session-aware logic
			decryptionStream, err := t.generateSingleDecryptionStreamWithSession(sessionID, responseLength, seqNum)
			if err != nil {
				log.Printf("[TEE_K] Failed to generate decryption stream for seq %d: %v", seqNum, err)
				continue
			}

			// Create decryption stream data
			streamData := shared.ResponseDecryptionStreamData{
				DecryptionStream: decryptionStream,
				SeqNum:           seqNum,
				Length:           responseLength,
			}

			decryptionStreams = append(decryptionStreams, streamData)
		}
	} else {
		// Some failures - CRITICAL SECURITY: Any verification failure must terminate protocol
		for _, verification := range batchedVerification.Verifications {
			if !verification.Success {
				// Use proper structured error handling with session termination and cleanup
				if t.sessionTerminator.CriticalError(sessionID, shared.ReasonCryptoTagVerificationFailed,
					fmt.Errorf("critical security failure: tag verification failed for seq %d", verification.SeqNum),
					zap.Uint64("seq_num", verification.SeqNum),
					zap.String("verification_message", verification.Message)) {
					// Clean up session resources on critical crypto failure
					t.cleanupSession(sessionID)
				}
				return // Terminate session immediately on any crypto failure
			}

			// Get the stored response length for this sequence number
			responseState, err := t.getSessionResponseState(sessionID)
			if err != nil {
				log.Printf("[TEE_K] Session %s: Failed to get response state: %v", sessionID, err)
				continue
			}
			responseLength, exists := responseState.ResponseLengthBySeqInt[verification.SeqNum]
			if !exists {
				log.Printf("[TEE_K] No response length found for seq %d", verification.SeqNum)
				continue
			}

			// Generate decryption stream using session-aware logic
			decryptionStream, err := t.generateSingleDecryptionStreamWithSession(sessionID, responseLength, verification.SeqNum)
			if err != nil {
				log.Printf("[TEE_K] Failed to generate decryption stream for seq %d: %v", verification.SeqNum, err)
				continue
			}

			// Create decryption stream data
			streamData := shared.ResponseDecryptionStreamData{
				DecryptionStream: decryptionStream,
				SeqNum:           verification.SeqNum,
				Length:           responseLength,
			}

			decryptionStreams = append(decryptionStreams, streamData)
		}
	}

	fmt.Printf("[TEE_K] BATCHING: Generated %d decryption streams for session %s\n", len(decryptionStreams), sessionID)

	// Send all decryption streams as a batch to client
	batchedStreams := shared.BatchedDecryptionStreamData{
		DecryptionStreams: decryptionStreams,
		SessionID:         sessionID,
		TotalCount:        len(decryptionStreams),
	}

	streamsMsg := shared.CreateSessionMessage(shared.MsgBatchedDecryptionStreams, sessionID, batchedStreams)

	// Use the existing working method to send message to client
	if err := t.sessionManager.RouteToClient(sessionID, streamsMsg); err != nil {
		log.Printf("[TEE_K] Failed to send batched decryption streams to client for session %s: %v", sessionID, err)
		return
	}

	fmt.Printf("[TEE_K] BATCHING: Successfully sent batch of %d decryption streams to client\n", len(decryptionStreams))
}

func (t *TEEK) generateSingleDecryptionStreamWithSession(sessionID string, responseLength int, seqNum uint64) ([]byte, error) {
	// Get TLS client from session state
	var tlsClient *minitls.Client
	if sessionID != "" {
		tlsState, err := t.getSessionTLSState(sessionID)
		if err != nil {
			return nil, fmt.Errorf("failed to get TLS state: %v", err)
		}
		if tlsClientInterface, ok := tlsState.TLSClient.(*minitls.Client); ok {
			tlsClient = tlsClientInterface
		}
	}

	if tlsClient == nil {
		return nil, fmt.Errorf("no TLS client available")
	}

	// Use the provided responseLength parameter
	streamLength := responseLength

	// Get server application keys based on TLS version (same as existing working code)
	var serverAppKey, serverAppIV []byte

	tlsVersion := tlsClient.GetNegotiatedVersion()
	if tlsVersion == 0x0303 { // TLS 1.2
		// Get server keys from TLS 1.2 AEAD context
		tls12AEAD := tlsClient.GetTLS12AEAD()
		if tls12AEAD == nil {
			return nil, fmt.Errorf("no TLS 1.2 AEAD available for decryption")
		}

		serverAppKey = tls12AEAD.GetReadKey()
		serverAppIV = tls12AEAD.GetReadIV()

		fmt.Printf("[TEE_K] Using TLS 1.2 server keys for batched decryption stream\n")
	} else { // TLS 1.3
		// Get key schedule to access server application keys
		keySchedule := tlsClient.GetKeySchedule()
		if keySchedule == nil {
			return nil, fmt.Errorf("no key schedule available")
		}

		serverAppKey = keySchedule.GetServerApplicationKey()
		serverAppIV = keySchedule.GetServerApplicationIV()

		fmt.Printf("[TEE_K] Using TLS 1.3 server keys for batched decryption stream\n")
	}

	if serverAppKey == nil || serverAppIV == nil {
		return nil, fmt.Errorf("missing server application key or IV")
	}

	// Get cipher suite from TLS client
	cipherSuite := tlsClient.GetCipherSuite()

	// Get stored explicit IV for TLS 1.2 AES-GCM
	var explicitIV []byte
	if sessionID != "" {
		// Use session state
		responseState, err := t.getSessionResponseState(sessionID)
		if err != nil {
			return nil, fmt.Errorf("failed to get session response state: %v", err)
		}
		explicitIV = responseState.ExplicitIVBySeq[seqNum]
	}

	// Generate cipher-agnostic decryption stream
	// Use same sequence logic as tag generation for consistency
	var serverSeqNum uint64
	if tlsVersion == 0x0303 { // TLS 1.2
		serverSeqNum = seqNum // Server sequence matches client sequence
		fmt.Printf("[TEE_K] TLS 1.2 batched decryption: Using server sequence %d (same as client)\n", serverSeqNum)
	} else { // TLS 1.3
		serverSeqNum = seqNum - 1
		fmt.Printf("[TEE_K] TLS 1.3 batched decryption: Using server sequence %d (client - 1)\n", serverSeqNum)
	}

	decryptionStream, err := minitls.GenerateDecryptionStream(serverAppKey, serverAppIV, serverSeqNum, streamLength, cipherSuite, explicitIV)
	if err != nil {
		return nil, fmt.Errorf("failed to generate decryption stream: %v", err)
	}

	fmt.Printf("[TEE_K] Generated batched decryption stream (seq=%d, %d bytes)\n", seqNum, len(decryptionStream))
	return decryptionStream, nil
}
