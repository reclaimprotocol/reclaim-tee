package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
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
)

var teekUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connections from any origin
	},
}

type TEEK struct {
	port int

	// Session management
	sessionManager shared.SessionManagerInterface

	// TEE_T connection settings
	teetURL string

	tlsClient      *minitls.Client
	wsConn2TLS     *WebSocketConn
	currentConn    *websocket.Conn
	currentRequest *shared.RequestConnectionData
	tcpReady       chan bool

	// Phase 2: Split AEAD
	keyShare    []byte
	combinedKey []byte

	// Response handling
	responseLengthBySeq map[uint64]int // Store response lengths by sequence number
	serverSequenceNum   uint64         // Track server's actual sequence number manually

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

func NewTEEKWithEnclaveManager(port int, enclaveManager *shared.EnclaveManager) *TEEK {
	// Generate ECDSA signing key pair
	signingKeyPair, err := shared.GenerateSigningKeyPair()
	if err != nil {
		log.Printf("[TEE_K] Failed to generate signing key pair: %v", err)
		// Continue without signing capability rather than failing
		signingKeyPair = nil
	} else {
		fmt.Printf("[TEE_K] Generated ECDSA signing key pair (P-256 curve)\n")
	}

	return &TEEK{
		port:                port,
		sessionManager:      shared.NewSessionManager(),
		teetURL:             "ws://localhost:8081/teek", // Default TEE_T URL
		tcpReady:            make(chan bool, 1),
		responseLengthBySeq: make(map[uint64]int),
		signingKeyPair:      signingKeyPair,
		enclaveManager:      enclaveManager,
	}
}

// SetTEETURL sets the TEE_T connection URL
func (t *TEEK) SetTEETURL(url string) {
	t.teetURL = url
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
		case shared.MsgResponseLength:
			t.handleResponseLengthSession(msg.SessionID, msg)
		case shared.MsgResponseTagVerification:
			t.handleResponseTagVerificationSession(msg.SessionID, msg)
		case shared.MsgFinished:
			t.handleFinishedFromTEETSession(msg.SessionID, msg)
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
			log.Printf("[TEE_K] Failed to parse client message: %v", err)
			t.sendErrorToSession(sessionID, fmt.Sprintf("Failed to parse message: %v", err))
			continue
		}

		// Verify session ID matches
		if msg.SessionID != sessionID {
			log.Printf("[TEE_K] Session ID mismatch: expected %s, got %s", sessionID, msg.SessionID)
			t.sendErrorToSession(sessionID, "Session ID mismatch")
			continue
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
			log.Printf("[TEE_K] Unknown message type for session %s: %s", sessionID, msg.Type)
			t.sendErrorToSession(sessionID, fmt.Sprintf("Unknown message type: %s", msg.Type))
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

// sendErrorToSession sends an error message to a specific session
func (t *TEEK) sendErrorToSession(sessionID string, errMsg string) {
	errorMsg := shared.CreateSessionMessage(shared.MsgError, sessionID, shared.ErrorData{
		Message: errMsg,
	})

	if err := t.sessionManager.RouteToClient(sessionID, errorMsg); err != nil {
		log.Printf("[TEE_K] Failed to send error to session %s: %v", sessionID, err)
	}
}

// Session-aware handler methods (wrappers for legacy handlers during migration)

func (t *TEEK) handleRequestConnectionSession(sessionID string, msg *shared.Message) {
	log.Printf("[TEE_K] Session %s: Handling connection request", sessionID)

	var reqData shared.RequestConnectionData
	if err := msg.UnmarshalData(&reqData); err != nil {
		log.Printf("[TEE_K] Session %s: Failed to unmarshal connection request: %v", sessionID, err)
		t.sendErrorToSession(sessionID, "Failed to parse connection request")
		return
	}

	log.Printf("[TEE_K] Session %s: Connection request to %s:%d", sessionID, reqData.Hostname, reqData.Port)

	// Store connection data in session
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		log.Printf("[TEE_K] Session %s not found: %v", sessionID, err)
		t.sendErrorToSession(sessionID, "Session not found")
		return
	}
	session.ConnectionData = &reqData

	// Send connection ready message to client (was missing!)
	readyMsg := shared.CreateSessionMessage(shared.MsgConnectionReady, sessionID, shared.ConnectionReadyData{Success: true})
	if err := t.sessionManager.RouteToClient(sessionID, readyMsg); err != nil {
		log.Printf("[TEE_K] Failed to send connection ready to session %s: %v", sessionID, err)
		t.sendErrorToSession(sessionID, "Failed to send connection ready message")
		return
	}

	log.Printf("[TEE_K] Session %s: Connection ready message sent, waiting for TCP ready", sessionID)
	// Now wait for client to send MsgTCPReady - the TLS handshake will start in handleTCPReadySession
}

func (t *TEEK) handleTCPReadySession(sessionID string, msg *shared.Message) {
	var tcpData shared.TCPReadyData
	if err := msg.UnmarshalData(&tcpData); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal TCP ready data: %v", err)
		t.sendErrorToSession(sessionID, fmt.Sprintf("Failed to unmarshal TCP ready data: %v", err))
		return
	}

	if !tcpData.Success {
		log.Printf("[TEE_K] Session %s: TCP connection failed", sessionID)
		t.sendErrorToSession(sessionID, "TCP connection failed")
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
		t.sendErrorToSession(sessionID, "Missing connection data")
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

	// For backward compatibility with TCP data handler, store in global fields
	t.tlsClient = tlsClient
	t.wsConn2TLS = tlsConn
	t.currentConn = wsConn.GetWebSocketConn()
	t.currentRequest = reqData

	if err := tlsClient.Handshake(reqData.Hostname); err != nil {
		log.Printf("[TEE_K] Session %s: TLS handshake failed: %v", sessionID, err)
		t.sendErrorToSession(sessionID, fmt.Sprintf("TLS handshake failed: %v", err))
		return
	}

	// Store TLS state in session
	if session.TLSState == nil {
		session.TLSState = &shared.TLSSessionState{}
	}
	session.TLSState.HandshakeComplete = true

	// Get crypto material for certificate verification (matching legacy handler)
	hsKey := tlsClient.GetHandshakeKey()
	hsIV := tlsClient.GetHandshakeIV()
	certPacket := tlsClient.GetCertificatePacket()
	cipherSuite := tlsClient.GetCipherSuite()
	algorithm := getCipherSuiteAlgorithm(cipherSuite)

	// Send handshake key disclosure to Client (matching legacy behavior)
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
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		log.Printf("[TEE_K] Failed to get session %s: %v", sessionID, err)
		return
	}

	var tcpData shared.TCPData
	if err := msg.UnmarshalData(&tcpData); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal TCP data: %v", err)
		t.sendErrorToSession(sessionID, fmt.Sprintf("Failed to unmarshal TCP data: %v", err))
		return
	}

	// Handle incoming data from Client - for now, use legacy method with the underlying connection from session
	wsConn := session.ClientConn.(*shared.WSConnection)
	t.handleTCPData(wsConn.GetWebSocketConn(), msg)
}

func (t *TEEK) handleRedactedRequestSession(sessionID string, msg *shared.Message) {
	var redactedRequest shared.RedactedRequestData
	if err := msg.UnmarshalData(&redactedRequest); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal redacted request: %v", err)
		t.sendErrorToSession(sessionID, fmt.Sprintf("Failed to unmarshal redacted request: %v", err))
		return
	}

	fmt.Printf("[TEE_K] Session %s: Validating redacted request (%d bytes, %d ranges)\n", sessionID, len(redactedRequest.RedactedRequest), len(redactedRequest.RedactionRanges))

	// Validate redacted request format and positions
	if err := t.validateHTTPRequestFormat(redactedRequest.RedactedRequest, redactedRequest.RedactionRanges); err != nil {
		log.Printf("[TEE_K] Failed to validate redacted request format: %v", err)
		t.sendErrorToSession(sessionID, fmt.Sprintf("Failed to validate redacted request format: %v", err))
		return
	}

	if err := t.validateRedactionPositions(redactedRequest.RedactionRanges, len(redactedRequest.RedactedRequest)); err != nil {
		log.Printf("[TEE_K] Failed to validate redaction positions: %v", err)
		t.sendErrorToSession(sessionID, fmt.Sprintf("Failed to validate redaction positions: %v", err))
		return
	}

	// --- Add redacted request, comm_sp, and redaction ranges to transcript before encryption ---
	t.addToTranscriptForSessionWithType(sessionID, redactedRequest.RedactedRequest, shared.TranscriptPacketTypeHTTPRequestRedacted)

	// Store redaction ranges in transcript for signing
	redactionRangesBytes, err := json.Marshal(redactedRequest.RedactionRanges)
	if err != nil {
		log.Printf("[TEE_K] Failed to marshal redaction ranges: %v", err)
		t.sendErrorToSession(sessionID, fmt.Sprintf("Failed to marshal redaction ranges: %v", err))
		return
	}
	t.addToTranscriptForSessionWithType(sessionID, redactionRangesBytes, "redaction_ranges")
	log.Printf("[TEE_K] Session %s: Stored %d redaction ranges in transcript (%d bytes)", sessionID, len(redactedRequest.RedactionRanges), len(redactionRangesBytes))

	for idx, r := range redactedRequest.RedactionRanges {
		if strings.Contains(r.Type, "proof") && idx < len(redactedRequest.Commitments) {
			t.addToTranscriptForSessionWithType(sessionID, redactedRequest.Commitments[idx], shared.TranscriptPacketTypeCommitment)
			fmt.Printf("[TEE_K] Added comm_sp to transcript (len=%d)\n", len(redactedRequest.Commitments[idx]))
			break
		}
	}

	fmt.Printf("[TEE_K] Session %s: Added redaction ranges to transcript for signing\n", sessionID)

	fmt.Printf("[TEE_K] Session %s: Split AEAD: encrypting redacted request %d bytes\n", sessionID, len(redactedRequest.RedactedRequest))

	if t.tlsClient == nil {
		log.Printf("[TEE_K] No TLS client available for encryption")
		t.sendErrorToSession(sessionID, "No TLS client available for encryption")
		return
	}

	// Get cipher suite and encryption parameters
	cipherSuite := t.tlsClient.GetCipherSuite()
	clientAEAD := t.tlsClient.GetClientApplicationAEAD()
	if clientAEAD == nil {
		log.Printf("[TEE_K] No client application AEAD available")
		t.sendErrorToSession(sessionID, "No client application AEAD available")
		return
	}

	actualSeqNum := clientAEAD.GetSequence()

	// Prepare request with TLS content type
	redactedWithContentType := make([]byte, len(redactedRequest.RedactedRequest)+2)
	copy(redactedWithContentType, redactedRequest.RedactedRequest)
	redactedWithContentType[len(redactedRequest.RedactedRequest)] = 0x17   // shared.ApplicationData content type
	redactedWithContentType[len(redactedRequest.RedactedRequest)+1] = 0x00 // TLS 1.3 padding

	// Get encryption keys
	keySchedule := t.tlsClient.GetKeySchedule()
	if keySchedule == nil {
		log.Printf("[TEE_K] No key schedule available")
		t.sendErrorToSession(sessionID, "No key schedule available")
		return
	}

	clientAppKey := keySchedule.GetClientApplicationKey()
	clientAppIV := keySchedule.GetClientApplicationIV()

	// Create nonce and encrypt
	nonce := make([]byte, len(clientAppIV))
	copy(nonce, clientAppIV)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(actualSeqNum >> (8 * i))
	}

	// Encrypt using AES-CTR
	block, err := aes.NewCipher(clientAppKey)
	if err != nil {
		log.Printf("[TEE_K] Failed to create AES cipher: %v", err)
		t.sendErrorToSession(sessionID, fmt.Sprintf("Failed to create AES cipher: %v", err))
		return
	}

	ctrNonce := make([]byte, 16)
	copy(ctrNonce, nonce)
	ctrNonce[15] = 2
	stream := cipher.NewCTR(block, ctrNonce)
	encryptedData := make([]byte, len(redactedWithContentType))
	stream.XORKeyStream(encryptedData, redactedWithContentType)

	// Generate tag secrets for TEE_T
	tagSecrets := make([]byte, 32)
	zeros := make([]byte, 16)
	block.Encrypt(tagSecrets[0:16], zeros)
	counterBlock := make([]byte, 16)
	copy(counterBlock[:12], nonce)
	counterBlock[15] = 1
	block.Encrypt(tagSecrets[16:32], counterBlock)

	fmt.Printf("[TEE_K] Session %s: Generated client application tag secrets for sequence %d\n", sessionID, actualSeqNum)
	fmt.Printf("[TEE_K] Session %s: Encrypted %d bytes using split AEAD\n", sessionID, len(encryptedData))

	// Send encrypted request and tag secrets to TEE_T with session ID
	if err := t.sendEncryptedRequestToTEETWithSession(sessionID, encryptedData, tagSecrets, cipherSuite, actualSeqNum, redactedRequest.RedactionRanges); err != nil {
		log.Printf("[TEE_K] Failed to send encrypted request to TEE_T: %v", err)
		t.sendErrorToSession(sessionID, fmt.Sprintf("Failed to send encrypted request to TEE_T: %v", err))
		return
	}

	fmt.Printf("[TEE_K] Session %s: Encrypted request sent to TEE_T successfully\n", sessionID)
}

func (t *TEEK) handleRequestConnection(conn *websocket.Conn, msg *shared.Message) {
	var reqData shared.RequestConnectionData
	if err := msg.UnmarshalData(&reqData); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal connection request: %v", err)
		t.sendError(conn, fmt.Sprintf("Failed to unmarshal connection request: %v", err))
		return
	}

	fmt.Printf("[TEE_K] Connection request to %s:%d\n", reqData.Hostname, reqData.Port)

	// Store request data for later use
	t.currentRequest = &reqData
	t.currentConn = conn

	// Send connection ready message to client
	readyMsg := shared.CreateMessage(shared.MsgConnectionReady, shared.ConnectionReadyData{Success: true})
	if err := t.sendMessage(conn, readyMsg); err != nil {
		log.Printf("[TEE_K] Failed to send connection ready message: %v", err)
		return
	}

}

func (t *TEEK) handleTCPReady(conn *websocket.Conn, msg *shared.Message) {
	var tcpReadyData shared.TCPReadyData
	if err := msg.UnmarshalData(&tcpReadyData); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal TCP ready data: %v", err)
		t.sendError(conn, fmt.Sprintf("Failed to unmarshal TCP ready data: %v", err))
		return
	}

	if tcpReadyData.Success && t.currentRequest != nil {

		go t.performTLSHandshakeAndHTTP()
	} else {
		log.Printf("[TEE_K] Client not ready or no current request")
		t.sendError(conn, "Client not ready or no current request")
	}
}

func (t *TEEK) performTLSHandshakeAndHTTP() {
	if t.currentRequest == nil {
		log.Printf("[TEE_K] No current request available")
		return
	}

	fmt.Printf("[TEE_K] TLS handshake to %s:%d via Client proxy\n", t.currentRequest.Hostname, t.currentRequest.Port)

	// Create WebSocket-to-TLS adapter for TLS handshake through Client
	t.wsConn2TLS = &WebSocketConn{
		wsConn:      t.currentConn,
		pendingData: make(chan []byte, 10),
		teek:        t, // Add TEEK reference for transcript collection
	}

	// Create TLS client using WebSocket proxy through Client
	t.tlsClient = minitls.NewClient(t.wsConn2TLS)

	fmt.Println(" TEE_K starting TLS handshake over direct connection")

	// Perform TLS handshake directly to website
	if err := t.tlsClient.Handshake(t.currentRequest.Hostname); err != nil {
		log.Printf("[TEE_K] TLS handshake failed: %v", err)
		t.sendError(t.currentConn, fmt.Sprintf("TLS handshake failed: %v", err))
		return
	}

	// Get crypto material for certificate verification
	hsKey := t.tlsClient.GetHandshakeKey()
	hsIV := t.tlsClient.GetHandshakeIV()
	certPacket := t.tlsClient.GetCertificatePacket()

	// Get cipher suite information
	cipherSuite := t.tlsClient.GetCipherSuite()
	algorithm := getCipherSuiteAlgorithm(cipherSuite)

	// Send handshake key disclosure to Client
	disclosureMsg := shared.CreateMessage(shared.MsgHandshakeKeyDisclosure, shared.HandshakeKeyDisclosureData{
		HandshakeKey:      hsKey,
		HandshakeIV:       hsIV,
		CertificatePacket: certPacket,
		CipherSuite:       cipherSuite,
		Algorithm:         algorithm,
		Success:           true,
	})
	if err := t.sendMessage(t.currentConn, disclosureMsg); err != nil {
		log.Printf("[TEE_K] Failed to send handshake key disclosure: %v", err)
		return
	}

	// Phase 2: Complete TLS handshake setup for split AEAD protocol
	fmt.Printf("[TEE_K] TLS handshake complete, cipher suite 0x%04x\n", cipherSuite)
	fmt.Printf("[TEE_K] Ready for Phase 4 split AEAD response handling\n")
}

func (t *TEEK) handleTCPData(conn *websocket.Conn, msg *shared.Message) {
	var tcpData shared.TCPData
	if err := msg.UnmarshalData(&tcpData); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal TCP data: %v", err)
		t.sendError(conn, fmt.Sprintf("Failed to unmarshal TCP data: %v", err))
		return
	}

	// Handle incoming data from Client (could be TLS handshake data or encrypted application data)
	if t.wsConn2TLS != nil {
		// Forward data to TLS client for processing (handshake or application data)
		t.wsConn2TLS.pendingData <- tcpData.Data
	} else {
		log.Printf("[TEE_K] No WebSocket-to-TLS adapter available")
		t.sendError(conn, "No WebSocket-to-TLS adapter available")
	}
}

// handleRedactedRequest processes redacted request data from client for split AEAD encryption
func (t *TEEK) handleRedactedRequest(conn *websocket.Conn, msg *shared.Message) {
	var redactedRequest shared.RedactedRequestData
	if err := msg.UnmarshalData(&redactedRequest); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal redacted request: %v", err)
		t.sendError(conn, fmt.Sprintf("Failed to unmarshal redacted request: %v", err))
		return
	}

	fmt.Printf("[TEE_K] Validating redacted request (%d bytes, %d ranges)\n", len(redactedRequest.RedactedRequest), len(redactedRequest.RedactionRanges))

	// Validate redacted request format and positions
	if err := t.validateHTTPRequestFormat(redactedRequest.RedactedRequest, redactedRequest.RedactionRanges); err != nil {
		log.Printf("[TEE_K] Failed to validate redacted request format: %v", err)
		t.sendError(conn, fmt.Sprintf("Failed to validate redacted request format: %v", err))
		return
	}

	if err := t.validateRedactionPositions(redactedRequest.RedactionRanges, len(redactedRequest.RedactedRequest)); err != nil {
		log.Printf("[TEE_K] Failed to validate redaction positions: %v", err)
		t.sendError(conn, fmt.Sprintf("Failed to validate redaction positions: %v", err))
		return
	}

	fmt.Printf("[TEE_K] Split AEAD: encrypting redacted request %d bytes\n", len(redactedRequest.RedactedRequest))

	if t.tlsClient == nil {
		log.Printf("[TEE_K] No TLS client available for encryption")
		t.sendError(conn, "No TLS client available for encryption")
		return
	}

	// Phase 2: Split AEAD Protocol Implementation using proper TLS 1.3 application keys
	cipherSuite := t.tlsClient.GetCipherSuite()

	// Step 1: Add TLS 1.3 content type byte to redacted request (0x17 for shared.ApplicationData inner content)
	// RFC 8446: plaintext = content || content_type || zero_padding
	redactedWithContentType := make([]byte, len(redactedRequest.RedactedRequest)+2) // +2 for content type + padding
	copy(redactedWithContentType, redactedRequest.RedactedRequest)
	redactedWithContentType[len(redactedRequest.RedactedRequest)] = 0x17   // shared.ApplicationData content type (0x17, not 0x16!)
	redactedWithContentType[len(redactedRequest.RedactedRequest)+1] = 0x00 // Required TLS 1.3 padding byte

	// Step 2: Get client application AEAD
	clientAEAD := t.tlsClient.GetClientApplicationAEAD()
	if clientAEAD == nil {
		log.Printf("[TEE_K] No client application AEAD available")
		t.sendError(conn, fmt.Sprintf("No client application AEAD available"))
		return
	}

	actualSeqNum := clientAEAD.GetSequence()
	fmt.Printf("[TEE_K] DEBUG: Using sequence number %d (not hardcoded 0)\n", actualSeqNum)

	// Create TLS record header for shared.ApplicationData
	tagSize := 16 // GCM tag size
	recordLength := len(redactedWithContentType) + tagSize
	recordHeader := []byte{0x17, 0x03, 0x03, byte(recordLength >> 8), byte(recordLength & 0xFF)}

	fmt.Printf("[TEE_K] DEBUG: TLS record header: %x (length includes %d-byte tag)\n", recordHeader, tagSize)

	// Step 3: For split AEAD, use proper AES-CTR encryption + provide GCM authentication material
	// Get the raw key and IV from TLS client for manual GCM operations
	keySchedule := t.tlsClient.GetKeySchedule()
	if keySchedule == nil {
		log.Printf("[TEE_K] No key schedule available")
		t.sendError(conn, fmt.Sprintf("No key schedule available"))
		return
	}

	clientAppKey := keySchedule.GetClientApplicationKey()
	clientAppIV := keySchedule.GetClientApplicationIV()

	if len(clientAppKey) == 0 || len(clientAppIV) == 0 {
		log.Printf("[TEE_K] No application keys available")
		t.sendError(conn, fmt.Sprintf("No application keys available"))
		return
	}

	// Create nonce: IV XOR with sequence number
	nonce := make([]byte, len(clientAppIV))
	copy(nonce, clientAppIV)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(actualSeqNum >> (8 * i))
	}

	fmt.Printf("[TEE_K] DEBUG: Key (%d bytes): %x\n", len(clientAppKey), clientAppKey)
	fmt.Printf("[TEE_K] DEBUG: IV (%d bytes): %x\n", len(clientAppIV), clientAppIV)
	fmt.Printf("[TEE_K] DEBUG: Nonce (IV ⊕ seq=%d): %x\n", actualSeqNum, nonce)

	// Step 4: Encrypt redacted request using AES-CTR (encryption part of GCM)
	block, err := aes.NewCipher(clientAppKey)
	if err != nil {
		log.Printf("[TEE_K] Failed to create AES cipher: %v", err)
		t.sendError(conn, fmt.Sprintf("Failed to create AES cipher: %v", err))
		return
	}

	// Create CTR stream with GCM counter format: nonce (12 bytes) + counter (4 bytes)
	ctrNonce := make([]byte, 16)
	copy(ctrNonce, nonce) // 12-byte nonce
	ctrNonce[15] = 2      // FIXED: Set initial counter to 2 (GCM data encryption starts at 2, not 1)

	stream := cipher.NewCTR(block, ctrNonce)
	encryptedData := make([]byte, len(redactedWithContentType))
	stream.XORKeyStream(encryptedData, redactedWithContentType)

	// Step 5: Generate tag secrets for TEE_T: E_K(0^128) and E_K(IV || 0^31 || 1)
	tagSecrets := make([]byte, 32) // 16 bytes for each value

	// E_K(0^128) - GHASH key H
	zeros := make([]byte, 16)
	block.Encrypt(tagSecrets[0:16], zeros)

	// E_K(IV || 0^31 || 1) - encrypted counter block for final XOR
	counterBlock := make([]byte, 16)
	copy(counterBlock[:12], nonce) // Copy nonce (IV)
	counterBlock[15] = 1           // Set counter to 1
	block.Encrypt(tagSecrets[16:32], counterBlock)

	fmt.Printf("[TEE_K] Generated client application tag secrets for sequence %d\n", actualSeqNum)
	fmt.Printf("[TEE_K] Encrypted %d bytes using split AEAD\n", len(encryptedData))

	// Step 6: Send encrypted request and tag secrets to TEE_T
	if err := t.sendEncryptedRequestToTEET(encryptedData, tagSecrets, cipherSuite, actualSeqNum, redactedRequest.RedactionRanges); err != nil {
		log.Printf("[TEE_K] Failed to send encrypted request to TEE_T: %v", err)
		t.sendError(conn, fmt.Sprintf("Failed to send encrypted request to TEE_T: %v", err))
		return
	}

	// Step 7: Create what TEE_K WOULD send as a complete TLS record (for debugging comparison)
	// TLS shared.ApplicationData record format: [type(1)] [version(2)] [length(2)] [encrypted_payload]
	// completeRecord := make([]byte, 5+len(encryptedData))
	// completeRecord[0] = 0x17                            // shared.ApplicationData record type
	// completeRecord[1] = 0x03                            // TLS version major
	// completeRecord[2] = 0x03                            // TLS version minor
	// completeRecord[3] = byte(len(encryptedData) >> 8)   // Length high byte
	// completeRecord[4] = byte(len(encryptedData) & 0xFF) // Length low byte
	// copy(completeRecord[5:], encryptedData)             // Encrypted payload
	//
	// fmt.Printf("[TEE_K] DEBUG: Complete TLS record that WOULD be sent (%d bytes):\n", len(completeRecord))
	// previewLen := 64
	// if len(completeRecord) < previewLen {
	// 	previewLen = len(completeRecord)
	// }
	// fmt.Printf(" Would-send record: %x\n", completeRecord[:previewLen])
	// fmt.Printf(" Record header: type=0x%02x version=0x%04x length=%d\n",
	// 	completeRecord[0], uint16(completeRecord[1])<<8|uint16(completeRecord[2]), len(encryptedData))

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
	switch cipherSuite {
	case 0x1301: // TLS_AES_128_GCM_SHA256
		return "AES-128-GCM"
	case 0x1302: // TLS_AES_256_GCM_SHA384
		return "AES-256-GCM"
	case 0x1303: // TLS_CHACHA20_POLY1305_SHA256
		return "ChaCha20-Poly1305"
	default:
		return fmt.Sprintf("Unknown-0x%04x", cipherSuite)
	}
}

// Phase 2: Split AEAD handlers for TEE_T communication

func (t *TEEK) handleKeyShareResponse(msg *shared.Message) {
	var keyShareResp shared.KeyShareResponseData
	if err := msg.UnmarshalData(&keyShareResp); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal key share response: %v", err)
		return
	}

	if keyShareResp.Success {
		t.keyShare = keyShareResp.KeyShare
		fmt.Printf(" TEE_K received key share from TEE_T (%d bytes): %x\n", len(t.keyShare), t.keyShare)
	} else {
		log.Printf("[TEE_K] TEE_T key share generation failed")
	}
}

func (t *TEEK) handleTEETError(msg *shared.Message) {
	var errorData shared.ErrorData
	if err := msg.UnmarshalData(&errorData); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal TEE_T error: %v", err)
		return
	}

	log.Printf("[TEE_K] TEE_T error: %s", errorData.Message)
}

// requestKeyShareFromTEET requests a key share from TEE_T for split AEAD
func (t *TEEK) requestKeyShareFromTEET(cipherSuite uint16) error {
	var keyLen, ivLen int

	// Determine key and IV lengths based on cipher suite
	switch cipherSuite {
	case 0x1301: // TLS_AES_128_GCM_SHA256
		keyLen, ivLen = 16, 12
	case 0x1302: // TLS_AES_256_GCM_SHA384
		keyLen, ivLen = 32, 12
	case 0x1303: // TLS_CHACHA20_POLY1305_SHA256
		keyLen, ivLen = 32, 12
	default:
		return fmt.Errorf("unsupported cipher suite: 0x%04x", cipherSuite)
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
	var keyLen, ivLen int

	// Determine key and IV lengths based on cipher suite
	switch cipherSuite {
	case 0x1301: // TLS_AES_128_GCM_SHA256
		keyLen, ivLen = 16, 12
	case 0x1302: // TLS_AES_256_GCM_SHA384
		keyLen, ivLen = 32, 12
	case 0x1303: // TLS_CHACHA20_POLY1305_SHA256
		keyLen, ivLen = 32, 12
	default:
		return fmt.Errorf("unsupported cipher suite: 0x%04x", cipherSuite)
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

// sendEncryptedRequestToTEET sends encrypted request data and tag secrets to TEE_T
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
func (t *TEEK) sendEncryptedRequestToTEETWithSession(sessionID string, encryptedData, tagSecrets []byte, cipherSuite uint16, seqNum uint64, redactionRanges []shared.RedactionRange) error {
	fmt.Printf(" TEE_K sending encrypted request to TEE_T for session %s (%d bytes, %d ranges)\n", sessionID, len(encryptedData), len(redactionRanges))

	encReq := shared.EncryptedRequestData{
		EncryptedData:   encryptedData,
		TagSecrets:      tagSecrets,
		CipherSuite:     cipherSuite,
		SeqNum:          seqNum,
		RedactionRanges: redactionRanges,
	}

	msg := shared.CreateMessage(shared.MsgEncryptedRequest, encReq)
	return t.sendMessageToTEETForSession(sessionID, msg)
}

// Session-aware response handling methods
func (t *TEEK) handleResponseLengthSession(sessionID string, msg *shared.Message) {
	var lengthData shared.ResponseLengthData
	if err := msg.UnmarshalData(&lengthData); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal response length for session %s: %v", sessionID, err)
		return
	}

	// Get session to store response length
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		log.Printf("[TEE_K] Failed to get session %s for response length storage: %v", sessionID, err)
		return
	}

	// Initialize response state if needed
	if session.ResponseState == nil {
		session.ResponseState = &shared.ResponseSessionState{
			ResponseLengthBySeq:       make(map[uint64]uint32),
			PendingEncryptedResponses: make(map[uint64]*shared.EncryptedResponseData),
		}
	}

	// Store response length for this sequence number in session state
	session.ResponseState.ResponseLengthBySeq[lengthData.SeqNum] = uint32(lengthData.Length)

	// Also store in global map for backward compatibility with legacy methods
	if t.responseLengthBySeq == nil {
		t.responseLengthBySeq = make(map[uint64]int)
	}
	t.responseLengthBySeq[lengthData.SeqNum] = lengthData.Length

	fmt.Printf("[TEE_K] Received response length from TEE_T (seq=%d, length=%d)\n",
		lengthData.SeqNum, lengthData.Length)

	// Generate tag secrets for the response
	tagSecrets, err := t.generateResponseTagSecrets(lengthData.Length, lengthData.SeqNum, lengthData.CipherSuite, lengthData.RecordHeader)
	if err != nil {
		log.Printf("[TEE_K] Failed to generate response tag secrets for session %s: %v", sessionID, err)
		return
	}

	// Send tag secrets to TEE_T with session ID
	secretsData := shared.ResponseTagSecretsData{
		TagSecrets:  tagSecrets,
		SeqNum:      lengthData.SeqNum,
		CipherSuite: lengthData.CipherSuite,
	}

	secretsMsg := shared.CreateSessionMessage(shared.MsgResponseTagSecrets, sessionID, secretsData)

	if err := t.sendMessageToTEETForSession(sessionID, secretsMsg); err != nil {
		log.Printf("[TEE_K] Failed to send tag secrets to TEE_T for session %s: %v", sessionID, err)
		return
	}

	fmt.Printf("[TEE_K] Sent response tag secrets to TEE_T (seq=%d)\n", lengthData.SeqNum)
}

func (t *TEEK) handleResponseTagVerificationSession(sessionID string, msg *shared.Message) {
	var verificationData shared.ResponseTagVerificationData
	if err := msg.UnmarshalData(&verificationData); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal response tag verification for session %s: %v", sessionID, err)
		return
	}

	if verificationData.Success {
		fmt.Printf("[TEE_K] Session %s: Response tag verification successful (seq=%d), generating decryption stream", sessionID, verificationData.SeqNum)
		t.generateAndSendDecryptionStreamSession(sessionID, verificationData.SeqNum)
	} else {
		fmt.Printf("[TEE_K] Session %s: Response tag verification failed (seq=%d): %s\n",
			verificationData.SeqNum, verificationData.SeqNum, verificationData.Message)
	}
}

// Session-aware decryption stream generation
func (t *TEEK) generateAndSendDecryptionStreamSession(sessionID string, seqNum uint64) error {
	if t.tlsClient == nil {
		return fmt.Errorf("no TLS client available")
	}

	// Get the actual response length from stored data
	streamLength, exists := t.responseLengthBySeq[seqNum]
	if !exists {
		return fmt.Errorf("no response length found for seq=%d", seqNum)
	}

	// DON'T delete the stored length - we need it later for redaction processing
	// delete(t.responseLengthBySeq, seqNum)

	// Get key schedule to access server application keys
	keySchedule := t.tlsClient.GetKeySchedule()
	if keySchedule == nil {
		return fmt.Errorf("no key schedule available")
	}

	// Get server application key and IV from key schedule
	serverAppKey := keySchedule.GetServerApplicationKey()
	serverAppIV := keySchedule.GetServerApplicationIV()

	if serverAppKey == nil || serverAppIV == nil {
		return fmt.Errorf("missing server application key or IV")
	}

	// Generate AES-CTR decryption stream
	decryptionStream, err := t.generateAESCTRStream(serverAppKey, serverAppIV, seqNum, streamLength)
	if err != nil {
		return fmt.Errorf("failed to generate decryption stream: %v", err)
	}

	// Send decryption stream to client via session routing
	streamData := shared.ResponseDecryptionStreamData{
		DecryptionStream: decryptionStream,
		SeqNum:           seqNum,
		Length:           streamLength,
	}

	streamMsg := shared.CreateSessionMessage(shared.MsgResponseDecryptionStream, sessionID, streamData)

	if err := t.sessionManager.RouteToClient(sessionID, streamMsg); err != nil {
		return fmt.Errorf("failed to send decryption stream to client: %v", err)
	}

	fmt.Printf("[TEE_K] Sent decryption stream to client (seq=%d, %d bytes) for session %s\n", seqNum, len(decryptionStream), sessionID)
	return nil
}

// generateAESCTRStream generates AES-CTR keystream for decryption
func (t *TEEK) generateAESCTRStream(key, iv []byte, seqNum uint64, length int) ([]byte, error) {
	// Create nonce by XORing IV with sequence number (TLS 1.3 nonce construction)
	nonce := make([]byte, len(iv))
	copy(nonce, iv)

	// XOR the last 8 bytes of the nonce with the sequence number
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(seqNum >> (8 * i))
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// *** FIX: Create 16-byte counter block for CTR mode (GCM format: nonce + 4-byte counter) ***
	counterBlock := make([]byte, 16)
	copy(counterBlock[:12], nonce) // Copy 12-byte nonce
	counterBlock[15] = 2           // FIXED: Set initial counter to 2 (GCM data encryption starts at 2, not 1)

	// Create CTR mode cipher with proper 16-byte counter block
	stream := cipher.NewCTR(block, counterBlock)

	// Generate keystream by encrypting zeros
	keystream := make([]byte, length)
	stream.XORKeyStream(keystream, make([]byte, length))

	return keystream, nil
}

func (t *TEEK) generateResponseTagSecrets(responseLength int, seqNum uint64, cipherSuite uint16, recordHeader []byte) ([]byte, error) {
	if t.tlsClient == nil {
		return nil, fmt.Errorf("no TLS client available")
	}

	// Get server application AEAD for tag secret generation
	serverAEAD := t.tlsClient.GetServerApplicationAEAD()
	if serverAEAD == nil {
		return nil, fmt.Errorf("no server application AEAD available")
	}

	// Get key schedule to access server application keys
	keySchedule := t.tlsClient.GetKeySchedule()
	if keySchedule == nil {
		return nil, fmt.Errorf("no key schedule available")
	}

	// Get server application key and IV from key schedule
	serverAppKey := keySchedule.GetServerApplicationKey()
	serverAppIV := keySchedule.GetServerApplicationIV()

	if serverAppKey == nil || serverAppIV == nil {
		return nil, fmt.Errorf("missing server application key or IV")
	}

	// Use the actual TLS record header from the server instead of constructing our own
	additionalData := recordHeader
	if len(additionalData) != 5 {
		return nil, fmt.Errorf("invalid record header length: expected 5, got %d", len(additionalData))
	}

	// *** CRITICAL FIX: Use client's sequence directly ***
	// The client correctly tracks response order (0, 1, 2, ...) which matches server sequence
	// Don't use serverAEAD.GetSequence() because it's corrupted by comparison decrypts
	actualSeqToUse := seqNum
	fmt.Printf("[TEE_K] Using client sequence %d (matches actual server sequence)\n", actualSeqToUse)

	splitAEAD := minitls.NewSplitAEAD(serverAppKey, serverAppIV, cipherSuite)

	// Set sequence number to match serverAEAD's current state
	splitAEAD.SetSequence(actualSeqToUse)

	// Create dummy encrypted data to generate tag secrets
	dummyEncrypted := make([]byte, responseLength)

	// Generate tag secrets using the same method as requests
	_, tagSecrets, err := splitAEAD.EncryptWithoutTag(dummyEncrypted, additionalData)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tag secrets: %v", err)
	}

	fmt.Printf("[TEE_K] Generated tag secrets for sequence %d\n", actualSeqToUse)

	return tagSecrets, nil
}

// Legacy handlers for backward compatibility
func (t *TEEK) handleResponseLength(msg *shared.Message) {
	var lengthData shared.ResponseLengthData
	if err := msg.UnmarshalData(&lengthData); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal response length: %v", err)
		return
	}

	// Store response length for later decryption stream generation
	if t.responseLengthBySeq == nil {
		t.responseLengthBySeq = make(map[uint64]int)
	}
	t.responseLengthBySeq[lengthData.SeqNum] = lengthData.Length

	fmt.Printf("[TEE_K] Received response length from TEE_T (seq=%d, length=%d)\n",
		lengthData.SeqNum, lengthData.Length)

	// Generate tag secrets for the response
	tagSecrets, err := t.generateResponseTagSecrets(lengthData.Length, lengthData.SeqNum, lengthData.CipherSuite, lengthData.RecordHeader)
	if err != nil {
		log.Printf("[TEE_K] Failed to generate response tag secrets: %v", err)
		return
	}

	// Send tag secrets to TEE_T
	secretsData := shared.ResponseTagSecretsData{
		TagSecrets:  tagSecrets,
		SeqNum:      lengthData.SeqNum,
		CipherSuite: lengthData.CipherSuite,
	}

	secretsMsg := shared.CreateMessage(shared.MsgResponseTagSecrets, secretsData)

	if err := t.sendMessageToTEETForSession("", secretsMsg); err != nil {
		log.Printf("[TEE_K] Failed to send tag secrets to TEE_T: %v", err)
		return
	}

	fmt.Printf("[TEE_K] Sent response tag secrets to TEE_T (seq=%d)\n", lengthData.SeqNum)
}

func (t *TEEK) handleResponseTagVerification(msg *shared.Message) {
	var verificationData shared.ResponseTagVerificationData
	if err := msg.UnmarshalData(&verificationData); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal response tag verification: %v", err)
		return
	}

	if verificationData.Success {
		fmt.Printf("[TEE_K] Response tag verification successful (seq=%d), generating decryption stream\n",
			verificationData.SeqNum)

		// Generate decryption stream and send to client
		if err := t.generateAndSendDecryptionStream(verificationData.SeqNum); err != nil {
			log.Printf("[TEE_K] Failed to generate decryption stream: %v", err)
		}
	} else {
		fmt.Printf("[TEE_K] Response tag verification failed (seq=%d): %s\n",
			verificationData.SeqNum, verificationData.Message)
	}
}

func (t *TEEK) generateAndSendDecryptionStream(seqNum uint64) error {
	if t.tlsClient == nil {
		return fmt.Errorf("no TLS client available")
	}

	// Get server application AEAD
	serverAEAD := t.tlsClient.GetServerApplicationAEAD()
	if serverAEAD == nil {
		return fmt.Errorf("no server application AEAD available")
	}

	// Get the actual response length from stored data
	streamLength, exists := t.responseLengthBySeq[seqNum]
	if !exists {
		return fmt.Errorf("no response length found for seq=%d", seqNum)
	}

	// DON'T delete the stored length - we need it later for redaction processing
	// delete(t.responseLengthBySeq, seqNum)

	// Get key schedule to access server application keys
	keySchedule := t.tlsClient.GetKeySchedule()
	if keySchedule == nil {
		return fmt.Errorf("no key schedule available")
	}

	// Get server application key and IV from key schedule
	serverAppKey := keySchedule.GetServerApplicationKey()
	serverAppIV := keySchedule.GetServerApplicationIV()

	if serverAppKey == nil || serverAppIV == nil {
		return fmt.Errorf("missing server application key or IV")
	}

	// Generate AES-CTR decryption stream
	decryptionStream, err := t.generateAESCTRStream(serverAppKey, serverAppIV, seqNum, streamLength)
	if err != nil {
		return fmt.Errorf("failed to generate decryption stream: %v", err)
	}

	// Send decryption stream to client
	streamData := shared.ResponseDecryptionStreamData{
		DecryptionStream: decryptionStream,
		SeqNum:           seqNum,
		Length:           streamLength,
	}

	streamMsg := shared.CreateMessage(shared.MsgResponseDecryptionStream, streamData)

	if err := t.sendMessage(t.currentConn, streamMsg); err != nil {
		return fmt.Errorf("failed to send decryption stream to client: %v", err)
	}

	fmt.Printf("[TEE_K] Sent decryption stream to client (seq=%d, %d bytes)\n", seqNum, len(decryptionStream))
	return nil
}

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
		case shared.TranscriptPacketTypeCommitment:
			if requestMetadata == nil {
				requestMetadata = &shared.RequestMetadata{}
			}
			requestMetadata.CommSP = packet
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

	// *** CRITICAL CHANGE: Don't send signature immediately ***
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
		t.sendErrorToSession(sessionID, "Failed to parse redaction specification")
		return
	}

	log.Printf("[TEE_K] Session %s: Received redaction spec with %d ranges", sessionID, len(redactionSpec.Ranges))

	// Validate redaction ranges
	if err := t.validateRedactionSpec(redactionSpec); err != nil {
		log.Printf("[TEE_K] Session %s: Invalid redaction spec: %v", sessionID, err)
		t.sendErrorToSession(sessionID, fmt.Sprintf("Invalid redaction specification: %v", err))
		return
	}

	// Generate and send redacted decryption streams
	if err := t.generateAndSendRedactedDecryptionStream(sessionID, redactionSpec); err != nil {
		log.Printf("[TEE_K] Session %s: Failed to generate redacted streams: %v", sessionID, err)
		t.sendErrorToSession(sessionID, fmt.Sprintf("Failed to generate redacted streams: %v", err))
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

	// *** CRITICAL FIX: Sort sequence numbers to ensure correct order ***
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
		if t.tlsClient == nil {
			return fmt.Errorf("no TLS client available for decryption key")
		}

		keySchedule := t.tlsClient.GetKeySchedule()
		if keySchedule == nil {
			return fmt.Errorf("no key schedule available")
		}

		serverAppKey := keySchedule.GetServerApplicationKey()
		serverAppIV := keySchedule.GetServerApplicationIV()

		if serverAppKey == nil || serverAppIV == nil {
			return fmt.Errorf("missing server application key or IV")
		}

		// Generate original decryption stream for this sequence using server application key
		originalStream, err := t.generateAESCTRStream(serverAppKey, serverAppIV, seqNum, length)
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

	// *** CRITICAL CHANGE: Mark processing as complete and check if we can send signature ***
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
		case shared.TranscriptPacketTypeCommitment:
			if requestMetadata == nil {
				requestMetadata = &shared.RequestMetadata{}
			}
			requestMetadata.CommSP = packet
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
		masterBuffer.Write(requestMetadata.CommSP)
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

	// Send redacted streams to client
	for _, stream := range session.RedactedStreams {
		streamMsg := shared.CreateSessionMessage(shared.MsgSignedRedactedDecryptionStream, sessionID, stream)
		if err := session.ClientConn.WriteJSON(streamMsg); err != nil {
			return fmt.Errorf("failed to send redacted stream seq %d: %v", stream.SeqNum, err)
		}
	}

	log.Printf("[TEE_K] Session %s: Sent signed transcript and %d redacted streams to client", sessionID, len(session.RedactedStreams))
	return nil
}

// handleAttestationRequestSession handles attestation requests from clients over WebSocket
func (t *TEEK) handleAttestationRequestSession(sessionID string, msg *shared.Message) {
	var attestReq shared.AttestationRequestData
	if err := msg.UnmarshalData(&attestReq); err != nil {
		log.Printf("[TEE_K] Session %s: Failed to unmarshal attestation request: %v", sessionID, err)
		t.sendErrorToSession(sessionID, "Failed to parse attestation request")
		return
	}

	log.Printf("[TEE_K] Session %s: Processing attestation request %s", sessionID, attestReq.RequestID)

	// Get attestation from enclave manager if available
	if t.signingKeyPair == nil {
		log.Printf("[TEE_K] Session %s: No signing key pair available for attestation", sessionID)
		t.sendAttestationResponse(sessionID, attestReq.RequestID, nil, false, "No signing key pair available")
		return
	}

	// Generate attestation document using enclave manager
	publicKeyDER, err := t.signingKeyPair.GetPublicKeyDER()
	if err != nil {
		log.Printf("[TEE_K] Session %s: Failed to get public key DER: %v", sessionID, err)
		t.sendAttestationResponse(sessionID, attestReq.RequestID, nil, false, "Failed to get public key")
		return
	}

	// Create user data containing the hex-encoded ECDSA public key
	userData := fmt.Sprintf("tee_k_public_key:%x", publicKeyDER)
	log.Printf("[TEE_K] Session %s: Including ECDSA public key in attestation (DER: %d bytes)", sessionID, len(publicKeyDER))

	// Generate attestation document using enclave manager
	if t.enclaveManager == nil {
		log.Printf("[TEE_K] Session %s: No enclave manager available for attestation", sessionID)
		t.sendAttestationResponse(sessionID, attestReq.RequestID, nil, false, "No enclave manager available")
		return
	}

	attestationDoc, err := t.enclaveManager.GenerateAttestation(context.Background(), []byte(userData))
	if err != nil {
		log.Printf("[TEE_K] Session %s: Attestation generation failed: %v", sessionID, err)
		t.sendAttestationResponse(sessionID, attestReq.RequestID, nil, false, "Failed to generate attestation")
		return
	}
	log.Printf("[TEE_K] Session %s: Generated attestation document (%d bytes)", sessionID, len(attestationDoc))

	t.sendAttestationResponse(sessionID, attestReq.RequestID, attestationDoc, true, "")
}

// sendAttestationResponse sends an attestation response to the client
func (t *TEEK) sendAttestationResponse(sessionID, requestID string, attestationDoc []byte, success bool, errorMessage string) {
	response := shared.AttestationResponseData{
		RequestID:      requestID,
		AttestationDoc: attestationDoc,
		Success:        success,
		ErrorMessage:   errorMessage,
	}

	responseMsg := shared.CreateSessionMessage(shared.MsgAttestationResponse, sessionID, response)
	if err := t.sessionManager.RouteToClient(sessionID, responseMsg); err != nil {
		log.Printf("[TEE_K] Session %s: Failed to send attestation response: %v", sessionID, err)
	}
}
