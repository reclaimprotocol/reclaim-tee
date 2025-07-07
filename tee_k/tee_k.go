package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"tee-mpc/minitls"
	"tee-mpc/shared" //  Keep shared for session management

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

	// TEE_T connection (shared across all sessions)
	teetConn *websocket.Conn
	teetURL  string

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
}

// WebSocketConn adapts websocket to net.Conn interface for miniTLS
type WebSocketConn struct {
	wsConn      *websocket.Conn
	readBuffer  []byte
	readOffset  int
	pendingData chan []byte
}

func NewTEEK(port int) *TEEK {
	return &TEEK{
		port:                port,
		sessionManager:      shared.NewSessionManager(),
		teetURL:             "ws://localhost:8081/teek", // Default TEE_T URL
		tcpReady:            make(chan bool, 1),
		responseLengthBySeq: make(map[uint64]int),
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

// ConnectToTEET establishes connection to TEE_T
func (t *TEEK) ConnectToTEET() error {
	log.Printf("[TEE_K] Attempting WebSocket connection to TEE_T at: %s", t.teetURL)

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
		log.Printf("[TEE_K] WebSocket dial failed for %s: %v", t.teetURL, err)
		return fmt.Errorf("failed to connect to TEE_T: %v", err)
	}

	t.teetConn = conn
	log.Printf("[TEE_K] WebSocket connection established successfully to %s", t.teetURL)

	// Start message handling
	go t.handleTEETMessages()
	return nil
}

// handleTEETMessages handles messages from TEE_T
func (t *TEEK) handleTEETMessages() {
	for {
		if t.teetConn == nil {
			break
		}

		_, msgBytes, err := t.teetConn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
			} else if !isNetworkShutdownError(err) {
				log.Printf("[TEE_K] Failed to read TEE_T message: %v", err)
			}
			break
		}

		msg, err := shared.ParseMessage(msgBytes)
		if err != nil {
			log.Printf("[TEE_K] Failed to parse TEE_T message: %v", err)
			continue
		}

		// Route based on whether message has session ID (session-aware vs legacy)
		if msg.SessionID != "" {
			// Session-aware message routing
			switch msg.Type {
			case shared.MsgResponseLength:
				t.handleResponseLengthSession(msg.SessionID, msg)
			case shared.MsgResponseTagVerification:
				t.handleResponseTagVerificationSession(msg.SessionID, msg)
			default:
				log.Printf("[TEE_K] Unknown session-aware TEE_T message type: %s", msg.Type)
			}
		} else {
			log.Printf("[TEE_K] MEWSSAGE WITHOUT SESSION ID: %s", msg)
			continue
		}
	}
}

// sendMessageToTEET sends a message to TEE_T
func (t *TEEK) sendMessageToTEET(msg *shared.Message) error {
	if t.teetConn == nil {
		return fmt.Errorf("no TEE_T connection available")
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	return t.teetConn.WriteMessage(websocket.TextMessage, msgBytes)
}

// sendMessageToTEETWithSession sends a message to TEE_T with session ID
func (t *TEEK) sendMessageToTEETWithSession(sessionID string, msg *shared.Message) error {
	if t.teetConn == nil {
		return fmt.Errorf("no TEE_T connection available")
	}

	// Add session ID to message
	msg.SessionID = sessionID

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	return t.teetConn.WriteMessage(websocket.TextMessage, msgBytes)
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
		default:
			log.Printf("[TEE_K] Unknown message type for session %s: %s", sessionID, msg.Type)
			t.sendErrorToSession(sessionID, fmt.Sprintf("Unknown message type: %s", msg.Type))
		}
	}

	// Clean up session when connection closes
	log.Printf("[TEE_K] Cleaning up session %s", sessionID)
	t.sessionManager.CloseSession(sessionID)
}

// notifyTEETNewSession sends session registration to TEE_T
func (t *TEEK) notifyTEETNewSession(sessionID string) error {
	if t.teetConn == nil {
		return fmt.Errorf("no TEE_T connection available")
	}

	msg := shared.CreateSessionMessage(shared.MsgSessionCreated, sessionID, map[string]interface{}{
		"session_id": sessionID,
	})

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal session notification: %v", err)
	}

	return t.teetConn.WriteMessage(websocket.TextMessage, msgBytes)
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

func (t *TEEK) handleTagComputationReady(msg *shared.Message) {
	var readyData shared.TagComputationReadyData
	if err := msg.UnmarshalData(&readyData); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal tag computation ready: %v", err)
		return
	}

	if readyData.Success {
	} else {
		log.Printf("[TEE_K] TEE_T tag computation failed")
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
	return t.sendMessageToTEET(msg)
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
	return t.sendMessageToTEETWithSession(sessionID, msg)
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
	return t.sendMessageToTEET(msg)
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
	return t.sendMessageToTEETWithSession(sessionID, msg)
}

// Session-aware response handling methods
func (t *TEEK) handleResponseLengthSession(sessionID string, msg *shared.Message) {
	var lengthData shared.ResponseLengthData
	if err := msg.UnmarshalData(&lengthData); err != nil {
		log.Printf("[TEE_K] Failed to unmarshal response length for session %s: %v", sessionID, err)
		return
	}

	// Store response length for this sequence number
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

	if err := t.sendMessageToTEETWithSession(sessionID, secretsMsg); err != nil {
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
		fmt.Printf("[TEE_K] Response tag verification successful (seq=%d), generating decryption stream for session %s\n",
			verificationData.SeqNum, sessionID)

		// Generate decryption stream and send to client
		if err := t.generateAndSendDecryptionStreamSession(sessionID, verificationData.SeqNum); err != nil {
			log.Printf("[TEE_K] Failed to generate decryption stream for session %s: %v", sessionID, err)
		}
	} else {
		fmt.Printf("[TEE_K] Response tag verification failed (seq=%d): %s for session %s\n",
			verificationData.SeqNum, verificationData.Message, sessionID)
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

	// Clean up stored length after use
	delete(t.responseLengthBySeq, seqNum)

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

	if err := t.sendMessageToTEET(secretsMsg); err != nil {
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

	// Clean up stored length after use
	delete(t.responseLengthBySeq, seqNum)

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
