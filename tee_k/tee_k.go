package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"tee-mpc/minitls"
	teeproto "tee-mpc/proto"
	"tee-mpc/shared"

	"github.com/gorilla/websocket"
	"github.com/mdlayher/vsock"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

var teekUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow connections from any origin
	},
}

type RedactionOperation struct {
	SeqNum uint64
	Start  int    // Start offset within the sequence
	End    int    // End offset within the sequence
	Bytes  []byte // Redaction bytes to apply
}

// TEEKSessionState holds TEE_K specific session state
type TEEKSessionState struct {
	// TLS handshake data
	HandshakeComplete bool
	ClientHello       []byte
	ServerHello       []byte
	MasterSecret      []byte
	KeyBlock          []byte
	KeyShare          []byte
	CipherSuite       uint16

	// TLS client and connection state
	TLSClient         *minitls.Client
	WSConn2TLS        *WebSocketConn
	CurrentConn       *websocket.Conn
	CurrentRequest    *shared.RequestConnectionData
	TCPReady          chan bool
	CombinedKey       []byte
	ServerSequenceNum uint64
}

// TEEKSessionManager extends shared session manager with TEE_K specific state
type TEEKSessionManager struct {
	*shared.SessionManager
	teekStates map[string]*TEEKSessionState
	stateMutex sync.Mutex
}

// NewTEEKSessionManager creates a new TEE_K session manager
func NewTEEKSessionManager() *TEEKSessionManager {
	return &TEEKSessionManager{
		SessionManager: shared.NewSessionManager(),
		teekStates:     make(map[string]*TEEKSessionState),
	}
}

// GetTEEKSessionState gets TEE_K specific state for a session
func (t *TEEKSessionManager) GetTEEKSessionState(sessionID string) (*TEEKSessionState, error) {
	t.stateMutex.Lock()
	defer t.stateMutex.Unlock()

	state, exists := t.teekStates[sessionID]
	if !exists {
		return nil, fmt.Errorf("TEE_K session state not found for session %s", sessionID)
	}
	return state, nil
}

// SetTEEKSessionState sets TEE_K specific state for a session
func (t *TEEKSessionManager) SetTEEKSessionState(sessionID string, state *TEEKSessionState) {
	t.stateMutex.Lock()
	defer t.stateMutex.Unlock()
	t.teekStates[sessionID] = state
}

// RemoveTEEKSessionState removes TEE_K specific state for a session
func (t *TEEKSessionManager) RemoveTEEKSessionState(sessionID string) {
	t.stateMutex.Lock()
	defer t.stateMutex.Unlock()
	delete(t.teekStates, sessionID)
}

// Override CloseSession to also clean up TEE_K state
func (t *TEEKSessionManager) CloseSession(sessionID string) error {
	t.RemoveTEEKSessionState(sessionID)
	return t.SessionManager.CloseSession(sessionID)
}

type TEEK struct {
	port int

	// Session management
	sessionManager    *TEEKSessionManager
	sessionTerminator *shared.SessionTerminator

	// Logging
	logger *shared.Logger

	// TEE_T connection settings
	teetURL string

	// Shared persistent connection to TEE_T
	sharedTEETConn *websocket.Conn
	teetConnMutex  sync.RWMutex

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

	// Get logger
	logger := shared.GetTEEKLogger()
	logger.Info("Generated ECDSA signing key pair", zap.String("curve", "P-256"))

	return &TEEK{
		port:              port,
		sessionManager:    NewTEEKSessionManager(),
		sessionTerminator: shared.NewSessionTerminator(logger),
		logger:            logger,
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
func createVSockWebSocketDialer(logger *shared.Logger) *websocket.Dialer {
	return &websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			logger.Info("VSock WebSocket dial: connecting to proxy",
				zap.String("target", addr),
				zap.Int("proxy_cid", 3),
				zap.Int("proxy_port", 8444))

			// Connect to internet proxy via vsock
			conn, err := vsock.Dial(3, 8444, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to connect to internet proxy: %v", err)
			}

			// Send target address to internet proxy
			logger.Info("Sending target address to internet proxy", zap.String("target", addr))
			_, err = fmt.Fprintf(conn, "%s\n", addr)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("failed to send target address to proxy: %v", err)
			}

			logger.Info("VSock connection established via internet proxy", zap.String("target", addr))
			return conn, nil
		},
		HandshakeTimeout: 30 * time.Second,
	}
}

// establishSharedTEETConnection establishes the single persistent connection to TEE_T
func (t *TEEK) establishSharedTEETConnection() {
	t.logger.Info("Establishing shared persistent connection to TEE_T", zap.String("teet_url", t.teetURL))

	for {
		conn, err := t.attemptTEETConnection("shared", 1)
		if err != nil {
			t.logger.Error("Failed to establish shared TEE_T connection, retrying immediately", zap.Error(err))
			time.Sleep(1 * time.Second)
			continue
		}

		t.teetConnMutex.Lock()
		t.sharedTEETConn = conn
		t.teetConnMutex.Unlock()

		t.logger.Info("Shared persistent connection to TEE_T established successfully")

		// Start monitoring the connection and auto-reconnect on failure
		go t.monitorSharedTEETConnection()
		break
	}
}

// monitorSharedTEETConnection monitors the shared connection and handles all incoming messages
func (t *TEEK) monitorSharedTEETConnection() {
	t.teetConnMutex.RLock()
	conn := t.sharedTEETConn
	t.teetConnMutex.RUnlock()

	t.logger.Info("Starting shared TEE_T connection message handler")

	// Handle all incoming messages from TEE_T
	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				t.logger.Info("Shared TEE_T connection closed normally")
			} else {
				t.logger.Error("Shared TEE_T connection lost, reconnecting", zap.Error(err))
			}

			// Clear the broken connection
			t.teetConnMutex.Lock()
			t.sharedTEETConn = nil
			t.teetConnMutex.Unlock()

			// Reconnect
			t.establishSharedTEETConnection()
			break
		}

		// Parse and route the message to the appropriate session
		t.handleSharedTEETMessage(msgBytes)
	}
}

// handleSharedTEETMessage processes messages from TEE_T and routes them to sessions
func (t *TEEK) handleSharedTEETMessage(msgBytes []byte) {
	var env teeproto.Envelope
	if err := proto.Unmarshal(msgBytes, &env); err != nil {
		t.logger.Error("Failed to parse TEE_T message", zap.Error(err))
		return
	}

	sessionID := env.GetSessionId()
	if sessionID == "" {
		t.logger.Error("Received TEE_T message without session ID")
		return
	}

	// Route session-aware messages
	switch p := env.Payload.(type) {
	case *teeproto.Envelope_Finished:
		// Protocol specification: TEE_T no longer sends finished responses to TEE_K
		t.logger.WithSession(sessionID).Info("Ignoring finished message from TEE_T (not needed in single session mode)")

	case *teeproto.Envelope_BatchedResponseLengths:
		// Build minimal shared message wrapper for existing handler
		msg := &shared.Message{SessionID: sessionID, Type: shared.MsgBatchedResponseLengths,
			Data: func() shared.BatchedResponseLengthData {
				var out shared.BatchedResponseLengthData
				out.SessionID = p.BatchedResponseLengths.GetSessionId()
				out.TotalCount = int(p.BatchedResponseLengths.GetTotalCount())
				for _, l := range p.BatchedResponseLengths.GetLengths() {
					out.Lengths = append(out.Lengths, struct {
						Length       int    `json:"length"`
						RecordHeader []byte `json:"record_header"`
						SeqNum       uint64 `json:"seq_num"`
						CipherSuite  uint16 `json:"cipher_suite"`
						ExplicitIV   []byte `json:"explicit_iv,omitempty"`
					}{Length: int(l.GetLength()), RecordHeader: l.GetRecordHeader(), SeqNum: l.GetSeqNum(), CipherSuite: uint16(l.GetCipherSuite()), ExplicitIV: l.GetExplicitIv()})
				}
				return out
			}(),
		}
		t.handleBatchedResponseLengthsSession(sessionID, msg)

	case *teeproto.Envelope_BatchedTagVerifications:
		msg := &shared.Message{SessionID: sessionID, Type: shared.MsgBatchedTagVerifications,
			Data: func() shared.BatchedTagVerificationData {
				var out shared.BatchedTagVerificationData
				out.SessionID = p.BatchedTagVerifications.GetSessionId()
				out.TotalCount = int(p.BatchedTagVerifications.GetTotalCount())
				out.AllSuccessful = p.BatchedTagVerifications.GetAllSuccessful()
				for _, v := range p.BatchedTagVerifications.GetVerifications() {
					out.Verifications = append(out.Verifications, shared.ResponseTagVerificationData{Success: v.GetSuccess(), SeqNum: v.GetSeqNum(), Message: v.GetMessage()})
				}
				return out
			}(),
		}
		t.handleBatchedTagVerificationsSession(sessionID, msg)

	default:
		t.logger.WithSession(sessionID).Error("Unknown TEE_T message type")
	}
}

// getSharedTEETConnection returns the shared connection, establishing it if needed
func (t *TEEK) getSharedTEETConnection() *websocket.Conn {
	t.teetConnMutex.RLock()
	conn := t.sharedTEETConn
	t.teetConnMutex.RUnlock()

	if conn == nil {
		t.logger.Warn("Shared TEE_T connection not available, this should not happen in normal operation")
		return nil
	}

	return conn
}

// attemptTEETConnection performs a single connection attempt to TEE_T
func (t *TEEK) attemptTEETConnection(sessionID string, attempt int) (*websocket.Conn, error) {
	logger := t.logger.WithSession(sessionID)

	logger.Info("Starting connection attempt",
		zap.Int("attempt", attempt),
		zap.String("teet_url", t.teetURL))

	// Check if using TLS (wss://)
	if strings.HasPrefix(t.teetURL, "wss://") {
		logger.Debug("Using secure WebSocket (WSS) connection")
	} else if strings.HasPrefix(t.teetURL, "ws://") {
		logger.Debug("Using plain WebSocket (WS) connection")
	}

	// Determine if we're in enclave mode based on the URL
	var conn *websocket.Conn
	var err error

	if strings.HasPrefix(t.teetURL, "wss://") && strings.Contains(t.teetURL, "reclaimprotocol.org") {
		// Enclave mode: use custom vsock dialer
		logger.Debug("Enclave mode detected - using VSock dialer via internet proxy")
		dialer := createVSockWebSocketDialer(t.logger)
		conn, _, err = dialer.Dial(t.teetURL, nil)
	} else {
		// Standalone mode: use default dialer
		logger.Debug("Standalone mode detected - using default WebSocket dialer")
		conn, _, err = websocket.DefaultDialer.Dial(t.teetURL, nil)
	}

	if err != nil {
		logger.Debug("WebSocket dial failed for attempt",
			zap.Int("attempt", attempt),
			zap.String("teet_url", t.teetURL),
			zap.Error(err))
		return nil, err
	}

	logger.Debug("WebSocket connection attempt successful",
		zap.Int("attempt", attempt),
		zap.String("teet_url", t.teetURL))

	return conn, nil
}

// connectToTEETForSession now uses the shared connection instead of creating new ones
func (t *TEEK) connectToTEETForSession(sessionID string) (*websocket.Conn, error) {
	t.logger.WithSession(sessionID).Debug("Using shared persistent connection to TEE_T")

	conn := t.getSharedTEETConnection()
	if conn == nil {
		return nil, fmt.Errorf("shared TEE_T connection not available")
	}

	t.logger.WithSession(sessionID).Debug("Shared connection to TEE_T available for session")
	return conn, nil
}

// Note: handleTEETMessagesForSession removed - replaced by centralized handleSharedTEETMessage

// sendMessageToTEETForSession sends a message to TEE_T for a specific session
func (t *TEEK) sendMessageToTEETForSession(sessionID string, msg *shared.Message) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("session %s not found: %v", sessionID, err)
	}

	if session.TEETConn == nil {
		return fmt.Errorf("no TEE_T connection available for session %s", sessionID)
	}

	// Build protobuf envelope for supported message types
	var env *teeproto.Envelope
	switch msg.Type {
	case shared.MsgSessionCreated:
		env = &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
			Payload: &teeproto.Envelope_SessionCreated{SessionCreated: &teeproto.SessionCreated{}},
		}
	case shared.MsgKeyShareRequest:
		var d shared.KeyShareRequestData
		if err := msg.UnmarshalData(&d); err != nil {
			return fmt.Errorf("failed to unmarshal key share request: %v", err)
		}
		env = &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
			Payload: &teeproto.Envelope_KeyShareRequest{KeyShareRequest: &teeproto.KeyShareRequest{CipherSuite: uint32(d.CipherSuite), KeyLength: int32(d.KeyLength), IvLength: int32(d.IVLength)}},
		}
	case shared.MsgEncryptedRequest:
		var d shared.EncryptedRequestData
		if err := msg.UnmarshalData(&d); err != nil {
			return fmt.Errorf("failed to unmarshal encrypted request: %v", err)
		}
		// map ranges
		var rr []*teeproto.RequestRedactionRange
		for _, r := range d.RedactionRanges {
			rr = append(rr, &teeproto.RequestRedactionRange{Start: int32(r.Start), Length: int32(r.Length), Type: r.Type, RedactionBytes: r.RedactionBytes})
		}
		env = &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
			Payload: &teeproto.Envelope_EncryptedRequest{EncryptedRequest: &teeproto.EncryptedRequest{EncryptedData: d.EncryptedData, TagSecrets: d.TagSecrets, Commitments: d.Commitments, CipherSuite: uint32(d.CipherSuite), SeqNum: d.SeqNum, RedactionRanges: rr}},
		}
	case shared.MsgFinished:
		env = &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
			Payload: &teeproto.Envelope_Finished{Finished: &teeproto.FinishedMessage{}},
		}
	case shared.MsgBatchedTagSecrets:
		var d shared.BatchedTagSecretsData
		if err := msg.UnmarshalData(&d); err != nil {
			return fmt.Errorf("failed to unmarshal batched tag secrets: %v", err)
		}
		var tags []*teeproto.BatchedTagSecrets_TagSecret
		for _, ts := range d.TagSecrets {
			tags = append(tags, &teeproto.BatchedTagSecrets_TagSecret{TagSecrets: ts.TagSecrets, SeqNum: ts.SeqNum, CipherSuite: uint32(ts.CipherSuite)})
		}
		env = &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
			Payload: &teeproto.Envelope_BatchedTagSecrets{BatchedTagSecrets: &teeproto.BatchedTagSecrets{TagSecrets: tags, SessionId: d.SessionID, TotalCount: int32(d.TotalCount)}},
		}
	default:
		return fmt.Errorf("unsupported TEE_T send type: %s", msg.Type)
	}

	data, err := proto.Marshal(env)
	if err != nil {
		return err
	}
	wsConn := session.TEETConn.(*shared.WSConnection)
	return wsConn.GetWebSocketConn().WriteMessage(websocket.BinaryMessage, data)
}

// sendEnvelopeToTEETForSession sends a protobuf envelope directly to TEE_T for a specific session
func (t *TEEK) sendEnvelopeToTEETForSession(sessionID string, env *teeproto.Envelope) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("session %s not found: %v", sessionID, err)
	}

	if session.TEETConn == nil {
		return fmt.Errorf("no TEE_T connection available for session %s", sessionID)
	}

	// Ensure session ID is set
	if env.GetSessionId() == "" {
		env.SessionId = sessionID
	}

	data, err := proto.Marshal(env)
	if err != nil {
		return err
	}
	wsConn := session.TEETConn.(*shared.WSConnection)
	return wsConn.GetWebSocketConn().WriteMessage(websocket.BinaryMessage, data)
}

func (t *TEEK) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := teekUpgrader.Upgrade(w, r, nil)
	if err != nil {
		t.logger.Error("Failed to upgrade websocket", zap.Error(err))
		return
	}

	// Create session for this client connection
	wsConn := shared.NewWSConnection(conn)
	sessionID, err := t.sessionManager.CreateSession(wsConn)
	if err != nil {
		t.logger.Error("Failed to create session", zap.Error(err))
		conn.Close()
		return
	}

	t.logger.Info("Created session for client",
		zap.String("session_id", sessionID),
		zap.String("remote_addr", conn.RemoteAddr().String()))

	// Notify TEE_T about the new session (with retry for shared connection)
	if err := t.notifyTEETNewSessionWithRetry(sessionID); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to notify TEE_T about session after retries", zap.Error(err))
		t.sessionManager.CloseSession(sessionID)
		return
	}

	// Send session ready message to client
	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_SessionReady{SessionReady: &teeproto.SessionReady{Ready: true}},
	}
	if data, err := proto.Marshal(env); err != nil || wsConn.GetWebSocketConn().WriteMessage(websocket.BinaryMessage, data) != nil {
		t.logger.WithSession(sessionID).Error("Failed to send session ready to client", zap.Error(err))
		t.sessionManager.CloseSession(sessionID)
		return
	}

	// shared.Message handling loop
	for {
		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				t.logger.WithSession(sessionID).Info("Client disconnected normally")
			} else if !isNetworkShutdownError(err) {
				t.logger.WithSession(sessionID).Error("Failed to read websocket message", zap.Error(err))
			}
			break
		}

		var env teeproto.Envelope
		if err := proto.Unmarshal(msgBytes, &env); err != nil {
			t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to parse client message")
			return
		}
		// Verify session ID matches
		if env.GetSessionId() != sessionID {
			sessionErr := fmt.Errorf("session ID mismatch: expected %s, got %s", sessionID, env.GetSessionId())
			t.terminateSessionWithError(sessionID, shared.ReasonSessionIDMismatch, sessionErr, "Session ID mismatch")
			return
		}

		// Handle message based on type
		switch p := env.Payload.(type) {
		case *teeproto.Envelope_RequestConnection:
			// Inline conversion
			data := shared.RequestConnectionData{Hostname: p.RequestConnection.GetHostname(), Port: int(p.RequestConnection.GetPort()), SNI: p.RequestConnection.GetSni(), ALPN: p.RequestConnection.GetAlpn(), ForceTLSVersion: p.RequestConnection.GetForceTlsVersion(), ForceCipherSuite: p.RequestConnection.GetForceCipherSuite()}
			msg := &shared.Message{SessionID: sessionID, Type: shared.MsgRequestConnection, Data: data}
			t.handleRequestConnectionSession(sessionID, msg)
		case *teeproto.Envelope_TcpReady:
			msg := &shared.Message{SessionID: sessionID, Type: shared.MsgTCPReady, Data: shared.TCPReadyData{Success: p.TcpReady.GetSuccess()}}
			t.handleTCPReadySession(sessionID, msg)
		case *teeproto.Envelope_TcpData:
			msg := &shared.Message{SessionID: sessionID, Type: shared.MsgTCPData, Data: shared.TCPData{Data: p.TcpData.GetData()}}
			t.handleTCPDataSession(sessionID, msg)
		case *teeproto.Envelope_RedactedRequest:
			// Inline conversion
			var ranges []shared.RequestRedactionRange
			for _, r := range p.RedactedRequest.GetRedactionRanges() {
				ranges = append(ranges, shared.RequestRedactionRange{Start: int(r.GetStart()), Length: int(r.GetLength()), Type: r.GetType(), RedactionBytes: r.GetRedactionBytes()})
			}
			rr := shared.RedactedRequestData{RedactedRequest: p.RedactedRequest.GetRedactedRequest(), Commitments: p.RedactedRequest.GetCommitments(), RedactionRanges: ranges}
			msg := &shared.Message{SessionID: sessionID, Type: shared.MsgRedactedRequest, Data: rr}
			t.handleRedactedRequestSession(sessionID, msg)
		case *teeproto.Envelope_ResponseRedactionSpec:
			// Convert to shared type for existing handler logic
			var ranges []shared.ResponseRedactionRange
			for _, rr := range p.ResponseRedactionSpec.GetRanges() {
				ranges = append(ranges, shared.ResponseRedactionRange{Start: int(rr.GetStart()), Length: int(rr.GetLength())})
			}
			spec := shared.ResponseRedactionSpec{Ranges: ranges, AlwaysRedactSessionTickets: p.ResponseRedactionSpec.GetAlwaysRedactSessionTickets()}
			msg := &shared.Message{SessionID: sessionID, Type: shared.MsgRedactionSpec, Data: spec}
			t.handleRedactionSpecSession(sessionID, msg)
		case *teeproto.Envelope_Finished:
			// Protocol specification: No client finished messages in single session mode
			// TEE_K only sends finished to TEE_T, doesn't receive from client
			t.logger.WithSession(sessionID).Info("Ignoring finished message from client (not needed in single session mode)")
		case *teeproto.Envelope_AttestationRequest:
			msg := &shared.Message{SessionID: sessionID, Type: shared.MsgAttestationRequest, Data: shared.AttestationRequestData{}}
			t.handleAttestationRequestSession(sessionID, msg)
		default:
			unknownMsgErr := fmt.Errorf("unknown message type: %T", p)
			t.terminateSessionWithError(sessionID, shared.ReasonUnknownMessageType, unknownMsgErr, "Unknown message type")
		}
	}

	// Clean up session when connection closes
	t.logger.WithSession(sessionID).Info("Cleaning up session")
	t.sessionManager.CloseSession(sessionID)
}

// notifyTEETNewSessionWithRetry retries session notification if shared connection isn't ready
func (t *TEEK) notifyTEETNewSessionWithRetry(sessionID string) error {
	maxRetries := 5
	retryDelay := 100 * time.Millisecond

	for attempt := 1; attempt <= maxRetries; attempt++ {
		err := t.notifyTEETNewSession(sessionID)
		if err == nil {
			return nil
		}

		// If it's a "connection not available" error and we have retries left, wait and retry
		if strings.Contains(err.Error(), "shared TEE_T connection not available") && attempt < maxRetries {
			t.logger.WithSession(sessionID).Warn("Shared TEE_T connection not ready, retrying...",
				zap.Int("attempt", attempt),
				zap.Int("max_retries", maxRetries),
				zap.Duration("retry_delay", retryDelay))
			time.Sleep(retryDelay)
			retryDelay *= 2 // Exponential backoff
			continue
		}

		// For other errors or final attempt, return the error
		return err
	}

	return fmt.Errorf("failed to notify TEE_T after %d attempts", maxRetries)
}

// notifyTEETNewSession creates per-session connection and sends session registration to TEE_T
func (t *TEEK) notifyTEETNewSession(sessionID string) error {
	// Get shared connection to TEE_T
	teetConn, err := t.connectToTEETForSession(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get shared TEE_T connection for session %s: %v", sessionID, err)
	}

	// Store the shared connection in the session
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		// Don't close shared connection on session error
		return fmt.Errorf("session %s not found: %v", sessionID, err)
	}

	session.TEETConn = shared.NewWSConnection(teetConn)

	// No per-session message handler needed - shared connection is monitored centrally

	// Send session registration to TEE_T via protobuf
	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_SessionCreated{SessionCreated: &teeproto.SessionCreated{}},
	}
	if data, err := proto.Marshal(env); err != nil {
		return fmt.Errorf("failed to marshal session registration: %v", err)
	} else if err := teetConn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return fmt.Errorf("failed to send session registration: %v", err)
	}

	t.logger.WithSession(sessionID).Info("Successfully created TEE_T connection and sent session registration")
	return nil
}

// terminateSessionWithError terminates a session due to a critical error
func (t *TEEK) terminateSessionWithError(sessionID string, reason shared.TerminationReason, err error, message string) {
	// Log the critical error and determine if session should terminate
	if t.sessionTerminator.ZeroToleranceError(sessionID, reason, err) {
		// Cleanup session resources
		t.cleanupSession(sessionID)
	}
}

// cleanupSession performs complete cleanup of session resources
func (t *TEEK) cleanupSession(sessionID string) {
	// Close the session in session manager (handles connections and state cleanup)
	if err := t.sessionManager.CloseSession(sessionID); err != nil {
		// Log cleanup failure but don't continue with broken session
		t.logger.WithSession(sessionID).Error("Failed to cleanup session", zap.Error(err))
	}

	// Cleanup session terminator tracking
	t.sessionTerminator.CleanupSession(sessionID)

	t.logger.WithSession(sessionID).Info("Session terminated and cleaned up")
}

// Session-aware handler methods

// Helper functions to access session state
func (t *TEEK) getSessionTLSState(sessionID string) (*TEEKSessionState, error) {
	return t.sessionManager.GetTEEKSessionState(sessionID)
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
	t.logger.WithSession(sessionID).Info("Handling connection request")

	var reqData shared.RequestConnectionData
	if err := msg.UnmarshalData(&reqData); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to parse connection request")
		return
	}

	t.logger.WithSession(sessionID).Info("Connection request received",
		zap.String("hostname", reqData.Hostname),
		zap.Int("port", reqData.Port))

	// Store connection data in session
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionNotFound, err, "Session not found")
		return
	}
	session.ConnectionData = &reqData

	// Send connection ready message to client
	envReady := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_ConnectionReady{ConnectionReady: &teeproto.ConnectionReady{Success: true}},
	}
	if err := t.sessionManager.RouteToClient(sessionID, envReady); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonNetworkFailure, err, "Failed to send connection ready message")
		return
	}

	t.logger.WithSession(sessionID).Info("Connection ready message sent, waiting for TCP ready")
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

	t.logger.WithSession(sessionID).Info("TCP connection ready, starting TLS handshake")

	// Start TLS handshake for this session
	go t.performTLSHandshakeAndHTTPForSession(sessionID)
}

// performTLSHandshakeAndHTTPForSession performs TLS handshake for a specific session
func (t *TEEK) performTLSHandshakeAndHTTPForSession(sessionID string) {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.logger.WithSession(sessionID).Error("Failed to get session for TLS handshake", zap.Error(err))
		return
	}

	// Get connection data
	reqData, ok := session.ConnectionData.(*shared.RequestConnectionData)
	if !ok {
		t.logger.WithSession(sessionID).Error("Missing connection data for TLS handshake")
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, fmt.Errorf("missing connection data"), "Missing connection data")
		return
	}

	// Initialize TEE_K session state first
	initialState := &TEEKSessionState{
		HandshakeComplete: false,
		TCPReady:          make(chan bool, 1),
	}
	t.sessionManager.SetTEEKSessionState(sessionID, initialState)

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
		t.logger.WithSession(sessionID).Info("Forcing TLS 1.2")
	case "1.3":
		config.MinVersion = minitls.VersionTLS13
		config.MaxVersion = minitls.VersionTLS13
		t.logger.WithSession(sessionID).Info("Forcing TLS 1.3")
	default:
		// Auto-negotiate (default behavior)
		config.MinVersion = minitls.VersionTLS12
		config.MaxVersion = minitls.VersionTLS13
		t.logger.WithSession(sessionID).Info("TLS version auto-negotiation enabled")
	}

	// Configure cipher suite restrictions if specified
	if err := configureCipherSuites(config, effectiveCipherSuite, effectiveTLSVersion); err != nil {
		t.logger.WithSession(sessionID).Error("Cipher suite configuration error", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Invalid cipher suite configuration: %v", err))
		return
	}

	if effectiveCipherSuite != "" {
		t.logger.WithSession(sessionID).Info("Forcing cipher suite", zap.String("cipher_suite", effectiveCipherSuite))
	} else {
		t.logger.WithSession(sessionID).Info("Cipher suite auto-negotiation enabled")
	}

	tlsClient = minitls.NewClientWithConfig(tlsConn, config)

	// Store in session state instead of global fields
	tlsState, err := t.getSessionTLSState(sessionID)
	if err != nil {
		t.logger.WithSession(sessionID).Error("Failed to get TLS state", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to get TLS state: %v", err))
		return
	}
	tlsState.TLSClient = tlsClient
	tlsState.WSConn2TLS = tlsConn
	tlsState.CurrentConn = wsConn.GetWebSocketConn()
	tlsState.CurrentRequest = reqData

	// Global state removed - using session state only

	if err := tlsClient.Handshake(reqData.Hostname); err != nil {
		t.logger.WithSession(sessionID).Error("TLS handshake failed", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("TLS handshake failed: %v", err))
		return
	}

	// Update TEE_K session state to mark handshake complete
	tlsState.HandshakeComplete = true

	// Get crypto material for certificate verification
	hsKey := tlsClient.GetHandshakeKey()
	hsIV := tlsClient.GetHandshakeIV()
	certPacket := tlsClient.GetCertificatePacket()
	cipherSuite := tlsClient.GetCipherSuite()
	algorithm := getCipherSuiteAlgorithm(cipherSuite)

	// Send handshake key disclosure to Client
	envDisclosure := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_HandshakeKeyDisclosure{HandshakeKeyDisclosure: &teeproto.HandshakeKeyDisclosure{
			HandshakeKey:      hsKey,
			HandshakeIv:       hsIV,
			CertificatePacket: certPacket,
			CipherSuite:       uint32(cipherSuite),
			Algorithm:         algorithm,
			Success:           true,
		}},
	}
	if err := t.sessionManager.RouteToClient(sessionID, envDisclosure); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to send handshake key disclosure", zap.Error(err))
		return
	}

	t.logger.WithSession(sessionID).Info("Handshake finished - ready for split AEAD")

	// Send handshake complete message
	envHandshake := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_HandshakeComplete{HandshakeComplete: &teeproto.HandshakeComplete{Success: true}},
	}

	if err := t.sessionManager.RouteToClient(sessionID, envHandshake); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to send handshake complete", zap.Error(err))
	}

	t.logger.WithSession(sessionID).Info("TLS handshake complete",
		zap.Uint16("cipher_suite", cipherSuite))
	t.logger.WithSession(sessionID).Info("Ready for Phase 4 split AEAD response handling")
}

func (t *TEEK) handleTCPDataSession(sessionID string, msg *shared.Message) {
	var tcpData shared.TCPData
	if err := msg.UnmarshalData(&tcpData); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to unmarshal TCP data", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to unmarshal TCP data: %v", err))
		return
	}

	// Handle incoming data from Client (TLS handshake data or encrypted application data)
	// Use session state for TCP data handling
	tlsState, err := t.getSessionTLSState(sessionID)
	if err != nil {
		t.logger.WithSession(sessionID).Error("Failed to get TLS state", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to get TLS state: %v", err))
		return
	}

	if tlsState.WSConn2TLS != nil {
		// Forward data to TLS client for processing
		tlsState.WSConn2TLS.pendingData <- tcpData.Data
	} else {
		t.logger.WithSession(sessionID).Error("No WebSocket-to-TLS adapter available")
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, fmt.Errorf("no WebSocket-to-TLS adapter available"), "No WebSocket-to-TLS adapter available")
	}
}

func (t *TEEK) handleRedactedRequestSession(sessionID string, msg *shared.Message) {
	var redactedRequest shared.RedactedRequestData
	if err := msg.UnmarshalData(&redactedRequest); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to unmarshal redacted request", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to unmarshal redacted request: %v", err))
		return
	}

	t.logger.WithSession(sessionID).Info("Validating redacted request",
		zap.Int("request_bytes", len(redactedRequest.RedactedRequest)),
		zap.Int("redaction_ranges", len(redactedRequest.RedactionRanges)),
		zap.Int("commitments", len(redactedRequest.Commitments)))

	// Validate redacted request format and positions
	if err := t.validateHTTPRequestFormat(redactedRequest.RedactedRequest, redactedRequest.RedactionRanges); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to validate redacted request format", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to validate redacted request format: %v", err))
		return
	}

	if err := t.validateRedactionPositions(redactedRequest.RedactionRanges, len(redactedRequest.RedactedRequest)); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to validate redaction positions", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to validate redaction positions: %v", err))
		return
	}

	// --- Add redacted request, comm_sp, and redaction ranges to transcript before encryption ---
	t.addToTranscriptForSessionWithType(sessionID, redactedRequest.RedactedRequest, shared.TranscriptPacketTypeHTTPRequestRedacted)

	// Store redaction ranges in transcript for signing
	redactionRangesBytes, err := json.Marshal(redactedRequest.RedactionRanges)
	if err != nil {
		t.logger.WithSession(sessionID).Error("Failed to marshal redaction ranges", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to marshal redaction ranges: %v", err))
		return
	}
	t.addToTranscriptForSessionWithType(sessionID, redactionRangesBytes, "redaction_ranges")
	t.logger.WithSession(sessionID).Info("Stored redaction ranges in transcript",
		zap.Int("ranges_count", len(redactedRequest.RedactionRanges)),
		zap.Int("bytes", len(redactionRangesBytes)))

	// Note: Commitments are verified by TEE_T and not included in TEE_K transcript
	// TEE_T signs the proof stream, providing sufficient cryptographic proof

	t.logger.WithSession(sessionID).Info("Added redaction ranges to transcript for signing")

	t.logger.WithSession(sessionID).Info("Split AEAD: encrypting redacted request",
		zap.Int("bytes", len(redactedRequest.RedactedRequest)))

	// Get TLS state from session
	tlsState, err := t.getSessionTLSState(sessionID)
	if err != nil {
		t.logger.WithSession(sessionID).Error("Failed to get TLS state", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to get TLS state: %v", err))
		return
	}

	tlsClient := tlsState.TLSClient
	if tlsClient == nil {
		t.logger.WithSession(sessionID).Error("No TLS client available for encryption")
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
	t.logger.WithSession(sessionID).Debug("TLS version and cipher suite",
		zap.Uint16("tls_version", tlsVersion),
		zap.Uint16("cipher_suite", cipherSuite))

	if tlsVersion == 0x0303 { // TLS 1.2
		// TLS 1.2: encrypt raw application data directly, no inner content type
		dataToEncrypt = redactedRequest.RedactedRequest
		t.logger.WithSession(sessionID).Info("TLS 1.2 - Encrypting raw HTTP data",
			zap.Int("bytes", len(dataToEncrypt)))

		tls12AEAD := tlsClient.GetTLS12AEAD()
		if tls12AEAD == nil {
			t.logger.WithSession(sessionID).Error("No TLS 1.2 AEAD available")
			t.terminateSessionWithError(sessionID, shared.ReasonInternalError, fmt.Errorf("no tls 1.2 aead available"), "no tls 1.2 aead available")
			return
		}

		clientAppKey = tls12AEAD.GetWriteKey()
		clientAppIV = tls12AEAD.GetWriteIV()
		actualSeqNum = tls12AEAD.GetWriteSequence()

		t.logger.WithSession(sessionID).Debug("TLS 1.2 Key Material",
			zap.Int("write_key_bytes", len(clientAppKey)),
			zap.Int("write_iv_bytes", len(clientAppIV)),
			zap.Uint64("write_sequence", actualSeqNum))

	} else { // TLS 1.3
		// TLS 1.3: Add inner content type byte + padding (RFC 8446)
		dataToEncrypt = make([]byte, len(redactedRequest.RedactedRequest)+2) // +2 for content type + padding
		copy(dataToEncrypt, redactedRequest.RedactedRequest)
		dataToEncrypt[len(redactedRequest.RedactedRequest)] = 0x17   // ApplicationData content type
		dataToEncrypt[len(redactedRequest.RedactedRequest)+1] = 0x00 // Required TLS 1.3 padding byte
		t.logger.WithSession(sessionID).Info("TLS 1.3 - Added inner content type + padding",
			zap.Int("bytes", len(dataToEncrypt)))

		clientAEAD := tlsClient.GetClientApplicationAEAD()
		if clientAEAD == nil {
			t.logger.WithSession(sessionID).Error("No client application AEAD available")
			t.terminateSessionWithError(sessionID, shared.ReasonInternalError, fmt.Errorf("no client application aead available"), "no client application aead available")
			return
		}

		actualSeqNum = clientAEAD.GetSequence()

		// Get encryption keys
		keySchedule := tlsClient.GetKeySchedule()
		if keySchedule == nil {
			t.logger.WithSession(sessionID).Error("No key schedule available")
			t.terminateSessionWithError(sessionID, shared.ReasonInternalError, fmt.Errorf("no key schedule available"), "no key schedule available")
			return
		}

		clientAppKey = keySchedule.GetClientApplicationKey()
		clientAppIV = keySchedule.GetClientApplicationIV()

		if len(clientAppKey) == 0 || len(clientAppIV) == 0 {
			t.logger.WithSession(sessionID).Error("No application keys available")
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
		t.logger.WithSession(sessionID).Error("Failed to encrypt data", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to encrypt data: %v", err))
		return
	}

	t.logger.WithSession(sessionID).Info("Generated client application tag secrets",
		zap.Uint64("sequence", actualSeqNum))
	t.logger.WithSession(sessionID).Info("Encrypted data using split AEAD",
		zap.Int("bytes", len(encryptedData)))

	// Send encrypted request and tag secrets to TEE_T with session ID
	if err := t.sendEncryptedRequestToTEETWithSession(sessionID, encryptedData, tagSecrets, cipherSuite, actualSeqNum, redactedRequest.RedactionRanges, redactedRequest.Commitments); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to send encrypted request to TEE_T", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to send encrypted request to TEE_T: %v", err))
		return
	}

	t.logger.WithSession(sessionID).Info("Encrypted request sent to TEE_T successfully")
}

// validateHTTPRequestFormat validates that the redacted request maintains proper HTTP format
func (t *TEEK) validateHTTPRequestFormat(redactedRequest []byte, ranges []shared.RequestRedactionRange) error {
	// Create a pretty version with asterisks for redacted ranges
	prettyRequest := make([]byte, len(redactedRequest))
	copy(prettyRequest, redactedRequest)

	// Replace redacted ranges with asterisks for display
	for _, r := range ranges {
		end := r.Start + r.Length
		if r.Start >= 0 && end <= len(prettyRequest) {
			for i := r.Start; i < end; i++ {
				prettyRequest[i] = '*'
			}
		}
	}

	// Log the pretty version that TEE_K sees
	t.logger.Info("TEE_K sees redacted request with asterisks",
		zap.String("redacted_request", string(prettyRequest)),
		zap.Int("redaction_ranges", len(ranges)))

	// Log details of each redaction range
	for i, r := range ranges {
		t.logger.Info("Redaction range for TEE_K",
			zap.Int("index", i),
			zap.Int("start", r.Start),
			zap.Int("length", r.Length),
			zap.String("type", r.Type))
	}

	// Convert to string for easier parsing
	reqStr := string(prettyRequest)

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

	t.logger.Info("Redacted request format validation passed")
	return nil
}

// validateRedactionPositions validates that redaction ranges are within bounds and non-overlapping
func (t *TEEK) validateRedactionPositions(ranges []shared.RequestRedactionRange, requestLen int) error {
	for i, r := range ranges {
		// Check bounds
		if r.Start < 0 || r.Length <= 0 || r.Start+r.Length > requestLen {
			return fmt.Errorf("range %d out of bounds: [%d:%d] for request length %d", i, r.Start, r.Start+r.Length, requestLen)
		}

		// Check for valid type
		if r.Type != shared.RedactionTypeSensitive && r.Type != shared.RedactionTypeSensitiveProof {
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

	t.logger.Info("Redaction position validation passed", zap.Int("ranges", len(ranges)))
	return nil
}

func (t *TEEK) sendMessage(conn *websocket.Conn, msg *shared.Message) error {
	// Support only error messages here
	if msg == nil {
		return fmt.Errorf("nil msg")
	}
	if msg.Type != shared.MsgError {
		return fmt.Errorf("unsupported send type: %s", msg.Type)
	}
	var ed shared.ErrorData
	if err := msg.UnmarshalData(&ed); err != nil {
		return err
	}
	env := &teeproto.Envelope{SessionId: msg.SessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Error{Error: &teeproto.ErrorData{Message: ed.Message}},
	}
	b, _ := proto.Marshal(env)
	return conn.WriteMessage(websocket.BinaryMessage, b)
}

func (t *TEEK) sendError(conn *websocket.Conn, errMsg string) {
	env := &teeproto.Envelope{
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Error{
			Error: &teeproto.ErrorData{Message: errMsg},
		},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		t.logger.Error("Failed to marshal error message", zap.Error(err))
		return
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		t.logger.Error("Failed to send error message", zap.Error(err))
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

	// Build protobuf envelope to forward TCP data to client
	env := &teeproto.Envelope{SessionId: w.sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_TcpData{TcpData: &teeproto.TCPData{Data: p}},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal tcp data envelope: %v", err)
	}
	if err := w.wsConn.WriteMessage(websocket.BinaryMessage, data); err != nil {
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
		t.logger.WithSession(sessionID).Error("Failed to unmarshal key share response", zap.Error(err))
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
			t.logger.WithSession(sessionID).Info("Received key share from TEE_T",
				zap.Int("bytes", len(tlsState.KeyShare)))
		}

		// Global state removed - using session state only
		t.logger.Info("Received key share from TEE_T",
			zap.Int("bytes", len(keyShareResp.KeyShare)))
	} else {
		// Key share generation failure is critical - terminate session
		keyShareErr := fmt.Errorf("TEE_T key share generation failed")
		if sessionID != "" {
			t.terminateSessionWithError(sessionID, shared.ReasonCryptoKeyGenerationFailed, keyShareErr, "TEE_T key share generation failed")
		} else {
			t.logger.Fatal("CRITICAL: TEE_T key share generation failed without session context")
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

	t.logger.Info("Requesting key share from TEE_T",
		zap.Uint16("cipher_suite", cipherSuite))

	env := &teeproto.Envelope{
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_KeyShareRequest{
			KeyShareRequest: &teeproto.KeyShareRequest{
				CipherSuite: uint32(cipherSuite),
				KeyLength:   int32(keyLen),
				IvLength:    int32(ivLen),
			},
		},
	}
	return t.sendEnvelopeToTEETForSession("", env)
}

// requestKeyShareFromTEETWithSession requests a key share from TEE_T for split AEAD with session ID
func (t *TEEK) requestKeyShareFromTEETWithSession(sessionID string, cipherSuite uint16) error {
	keyLen, ivLen, err := shared.GetKeyAndIVLengths(cipherSuite)
	if err != nil {
		return fmt.Errorf("unsupported cipher suite: %v", err)
	}

	t.logger.WithSession(sessionID).Info("Requesting key share from TEE_T",
		zap.Uint16("cipher_suite", cipherSuite))

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_KeyShareRequest{
			KeyShareRequest: &teeproto.KeyShareRequest{
				CipherSuite: uint32(cipherSuite),
				KeyLength:   int32(keyLen),
				IvLength:    int32(ivLen),
			},
		},
	}
	return t.sendEnvelopeToTEETForSession(sessionID, env)
}

func (t *TEEK) sendEncryptedRequestToTEET(encryptedData, tagSecrets []byte, cipherSuite uint16, seqNum uint64, redactionRanges []shared.RequestRedactionRange) error {
	t.logger.Info("Sending encrypted request to TEE_T",
		zap.Int("bytes", len(encryptedData)),
		zap.Int("ranges", len(redactionRanges)))

	// Convert redaction ranges to protobuf format
	var pbRanges []*teeproto.RequestRedactionRange
	for _, r := range redactionRanges {
		pbRanges = append(pbRanges, &teeproto.RequestRedactionRange{
			Start:          int32(r.Start),
			Length:         int32(r.Length),
			Type:           r.Type,
			RedactionBytes: r.RedactionBytes,
		})
	}

	env := &teeproto.Envelope{
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_EncryptedRequest{
			EncryptedRequest: &teeproto.EncryptedRequest{
				EncryptedData:   encryptedData,
				TagSecrets:      tagSecrets,
				CipherSuite:     uint32(cipherSuite),
				SeqNum:          seqNum,
				RedactionRanges: pbRanges,
			},
		},
	}
	return t.sendEnvelopeToTEETForSession("", env)
}

// sendEncryptedRequestToTEETWithSession sends encrypted request data and tag secrets to TEE_T with session ID
func (t *TEEK) sendEncryptedRequestToTEETWithSession(sessionID string, encryptedData, tagSecrets []byte, cipherSuite uint16, seqNum uint64, redactionRanges []shared.RequestRedactionRange, commitments [][]byte) error {
	t.logger.WithSession(sessionID).Info("Sending encrypted request to TEE_T",
		zap.Int("bytes", len(encryptedData)),
		zap.Int("ranges", len(redactionRanges)),
		zap.Int("commitments", len(commitments)))

	// Convert redaction ranges to protobuf format
	var pbRanges []*teeproto.RequestRedactionRange
	for _, r := range redactionRanges {
		pbRanges = append(pbRanges, &teeproto.RequestRedactionRange{
			Start:          int32(r.Start),
			Length:         int32(r.Length),
			Type:           r.Type,
			RedactionBytes: r.RedactionBytes,
		})
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_EncryptedRequest{
			EncryptedRequest: &teeproto.EncryptedRequest{
				EncryptedData:   encryptedData,
				TagSecrets:      tagSecrets,
				Commitments:     commitments,
				CipherSuite:     uint32(cipherSuite),
				SeqNum:          seqNum,
				RedactionRanges: pbRanges,
			},
		},
	}
	return t.sendEnvelopeToTEETForSession(sessionID, env)
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
		tlsClient = tlsState.TLSClient
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

		// fmt.Printf("[TEE_K] Using TLS 1.2 server keys for response tag secrets\n")
		// fmt.Printf("[TEE_K] 🔑 Server Read Key: %x\n", serverAppKey)
		// fmt.Printf("[TEE_K] 🔑 Server Read IV:  %x\n", serverAppIV)
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

		// fmt.Printf("[TEE_K] Using TLS 1.3 server keys for response tag secrets\n")
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

		// fmt.Printf("[TEE_K] TLS 1.2 tag secret AAD: seq=%d, plaintext_len=%d, aad=%x\n",
		// 	seqNum, responseLength, additionalData)
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

		// fmt.Printf("[TEE_K] TLS 1.3 tag secret AAD: %x (ciphertext+tag length: %d)\n", additionalData, ciphertextLength)
	}

	// For TLS 1.2, server sequence matches client sequence (both start at 1 after handshake)
	// For TLS 1.3, server sequence = client sequence - 1 (server starts at 0)
	var actualSeqToUse uint64
	if tlsVersion == 0x0303 { // TLS 1.2
		actualSeqToUse = seqNum // Server sequence matches client sequence
		// fmt.Printf("[TEE_K] TLS 1.2: Using server sequence %d (same as client sequence)\n", actualSeqToUse)
	} else { // TLS 1.3
		actualSeqToUse = seqNum - 1
		// fmt.Printf("[TEE_K] TLS 1.3: Using server sequence %d (client sequence %d - 1)\n", actualSeqToUse, seqNum)
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

			// fmt.Printf("[TEE_K] TLS 1.2 AES-GCM nonce construction: implicit_iv=%x + explicit_iv_uint64=%d = nonce=%x\n",
			// 	serverAppIV[0:4], explicitIVUint64, nonce)

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

			// fmt.Printf("[TEE_K] Generated TLS 1.2 AES-GCM tag secrets: E_K(0^128)=%x, E_K(nonce||1)=%x\n",
			// 	tagSecrets[0:16], tagSecrets[16:32])

			return tagSecrets, nil
		} else if shared.IsTLS12ChaCha20Poly1305CipherSuite(cipherSuite) {
			// TLS 1.2 ChaCha20-Poly1305 (no explicit IV)
			// Use TLS 1.2 ChaCha20 nonce construction: IV XOR sequence number
			nonce := make([]byte, len(serverAppIV))
			copy(nonce, serverAppIV)
			for i := 0; i < 8; i++ {
				nonce[len(nonce)-1-i] ^= byte(actualSeqToUse >> (8 * i))
			}

			// fmt.Printf("[TEE_K] TLS 1.2 ChaCha20 nonce construction: iv=%x XOR seq=%d = nonce=%x\n",
			// 	serverAppIV, actualSeqToUse, nonce)

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
		t.logger.WithSession(sessionID).Error("Failed to get session for transcript", zap.Error(err))
		return
	}

	session.TranscriptMutex.Lock()
	defer session.TranscriptMutex.Unlock()

	// Copy buffer to avoid unexpected mutation
	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)

	session.TranscriptPackets = append(session.TranscriptPackets, pktCopy)
	session.TranscriptPacketTypes = append(session.TranscriptPacketTypes, packetType)

	t.logger.WithSession(sessionID).Info("Added packet to transcript",
		zap.Int("bytes", len(packet)),
		zap.String("type", packetType),
		zap.Int("total_packets", len(session.TranscriptPackets)))
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
		t.logger.WithSession(sessionID).Error("Failed to get session for transcript", zap.Error(err))
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

// handleRedactionSpecSession handles redaction specification from client
func (t *TEEK) handleRedactionSpecSession(sessionID string, msg *shared.Message) {
	t.logger.WithSession(sessionID).Info("Handling redaction specification")

	var redactionSpec shared.ResponseRedactionSpec
	if err := msg.UnmarshalData(&redactionSpec); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to unmarshal redaction spec", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, fmt.Errorf("failed to parse redaction specification"), "failed to parse redaction specification")
		return
	}

	t.logger.WithSession(sessionID).Info("Received redaction spec", zap.Int("ranges", len(redactionSpec.Ranges)))

	// Validate redaction ranges
	if err := t.validateResponseRedactionSpec(redactionSpec); err != nil {
		t.logger.WithSession(sessionID).Error("Invalid redaction spec", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Invalid redaction specification: %v", err))
		return
	}

	// Store response redaction ranges in session state for transcript signature
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.logger.WithSession(sessionID).Error("Failed to get session for storing redaction ranges", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to store redaction ranges: %v", err))
		return
	}

	if session.ResponseState == nil {
		session.ResponseState = &shared.ResponseSessionState{}
	}
	session.ResponseState.ResponseRedactionRanges = redactionSpec.Ranges
	t.logger.WithSession(sessionID).Info("Stored response redaction ranges for transcript signature", zap.Int("ranges", len(redactionSpec.Ranges)))

	// Generate and send redacted decryption streams
	if err := t.generateAndSendRedactedDecryptionStreamResponse(sessionID, redactionSpec); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to generate redacted streams", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to generate redacted streams: %v", err))
		return
	}

	t.logger.WithSession(sessionID).Info("Successfully processed redaction specification")

	// Send "finished" to TEE_T as per protocol specification
	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Finished{
			Finished: &teeproto.FinishedMessage{},
		},
	}
	if err := t.sendEnvelopeToTEETForSession(sessionID, env); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to send finished message to TEE_T", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to send finished message to TEE_T: %v", err))
		return
	}

	t.logger.WithSession(sessionID).Info("Sent finished message to TEE_T")
}

// validateResponseRedactionSpec validates the response redaction specification from client
func (t *TEEK) validateResponseRedactionSpec(spec shared.ResponseRedactionSpec) error {
	// Validate ranges don't overlap and are within bounds
	for i, range1 := range spec.Ranges {
		// Check for overlaps with other ranges
		for j := i + 1; j < len(spec.Ranges); j++ {
			range2 := spec.Ranges[j]
			if rangesOverlapResponse(range1, range2) {
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

// rangesOverlapResponse checks if two response redaction ranges overlap
func rangesOverlapResponse(r1, r2 shared.ResponseRedactionRange) bool {
	return r1.Start < r2.Start+r2.Length && r2.Start < r1.Start+r1.Length
}

// generateAndSendRedactedDecryptionStreamResponse creates redacted decryption streams for response redaction
func (t *TEEK) generateAndSendRedactedDecryptionStreamResponse(sessionID string, spec shared.ResponseRedactionSpec) error {
	// Direct call to the main implementation
	return t.generateAndSendRedactedDecryptionStream(sessionID, spec)
}

// generateAndSendRedactedDecryptionStream creates redacted decryption streams but defers signature sending until all processing is complete
func (t *TEEK) generateAndSendRedactedDecryptionStream(sessionID string, spec shared.ResponseRedactionSpec) error {
	t.logger.WithSession(sessionID).Info("Generating redacted decryption stream", zap.Int("ranges", len(spec.Ranges)))

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

	t.logger.WithSession(sessionID).Info("Total response length",
		zap.Int("total_bytes", totalLength),
		zap.Int("sequences", len(seqNumbers)))

	// Clear any existing redacted streams for this session
	session.StreamsMutex.Lock()
	session.RedactedStreams = make([]shared.SignedRedactedDecryptionStream, 0)
	session.StreamsMutex.Unlock()

	t.logger.WithSession(sessionID).Info("Pre-processing redaction ranges", zap.Int("ranges", len(spec.Ranges)))

	// Map each sequence to its redaction operations
	seqToOperations := make(map[uint64][]RedactionOperation)

	// Process each range exactly once
	for _, redactionRange := range spec.Ranges {
		rangeStart := redactionRange.Start
		rangeEnd := redactionRange.Start + redactionRange.Length

		// Find which sequences this range affects
		seqOffset := 0
		for _, seqNum := range seqNumbers {
			length := int(session.ResponseState.ResponseLengthBySeq[seqNum])
			seqStart := seqOffset
			seqEnd := seqOffset + length

			// Check if this range overlaps with current sequence
			if rangeStart < seqEnd && rangeEnd > seqStart {
				// Calculate overlap
				overlapStart := max(rangeStart, seqStart) - seqStart
				overlapEnd := min(rangeEnd, seqEnd) - seqStart
				overlapLength := overlapEnd - overlapStart

				if overlapLength > 0 {
					// Create redaction operation for this sequence
					operation := RedactionOperation{
						SeqNum: seqNum,
						Start:  overlapStart,
						End:    overlapStart + overlapLength,
						Bytes:  make([]byte, overlapLength),
					}

					// Generate cryptographically secure random bytes for redaction
					_, err := rand.Read(operation.Bytes)
					if err != nil {
						return fmt.Errorf("failed to generate random redaction bytes: %v", err)
					}

					seqToOperations[seqNum] = append(seqToOperations[seqNum], operation)

					// log.Printf("[TEE_K] Session %s: Range %d [%d:%d] affects seq %d at offset %d-%d",
					// 	sessionID, rangeIdx, rangeStart, rangeEnd, seqNum, overlapStart, overlapStart+overlapLength-1)
				}
			}
			seqOffset += length
		}
	}

	totalOperations := func() int {
		total := 0
		for _, ops := range seqToOperations {
			total += len(ops)
		}
		return total
	}()
	t.logger.WithSession(sessionID).Info("Pre-processing complete", zap.Int("total_operations", totalOperations))

	// Create redacted decryption stream for each sequence using pre-computed operations
	for _, seqNum := range seqNumbers {
		length := int(session.ResponseState.ResponseLengthBySeq[seqNum])

		// Get original decryption stream from cache (reuse from Phase 4)
		originalStream, err := t.getCachedDecryptionStream(sessionID, length, seqNum)
		if err != nil {
			return fmt.Errorf("failed to get cached decryption stream for seq %d: %v", seqNum, err)
		}

		// Apply redaction to this stream using pre-computed operations
		redactedStream := make([]byte, len(originalStream))
		copy(redactedStream, originalStream)

		// Apply pre-computed redaction operations for this sequence (O(1) per sequence)
		operations := seqToOperations[seqNum]
		for _, operation := range operations {
			// Apply redaction bytes for this operation
			for i := 0; i < len(operation.Bytes) && operation.Start+i < len(redactedStream); i++ {
				redactedStream[operation.Start+i] = operation.Bytes[i]
			}

			// log.Printf("[TEE_K] Session %s: Applied pre-computed redaction to seq %d at offset %d-%d",
			// 	sessionID, seqNum, operation.Start, operation.End-1)
		}

		// Store redacted stream in session for master signature generation
		streamData := shared.SignedRedactedDecryptionStream{
			RedactedStream: redactedStream,
			SeqNum:         seqNum,
		}

		session.StreamsMutex.Lock()
		session.RedactedStreams = append(session.RedactedStreams, streamData)
		session.StreamsMutex.Unlock()

		// log.Printf("[TEE_K] Session %s: Generated redacted decryption stream for seq %d (%d bytes, %d operations)",
		// 	sessionID, seqNum, len(redactedStream), len(operations))
	}

	// Instead of immediately sending signature, mark redaction processing as complete
	session.StreamsMutex.Lock()
	session.RedactionProcessingComplete = true
	session.StreamsMutex.Unlock()

	t.logger.WithSession(sessionID).Info("Redaction processing complete, checking if ready to send signature")

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

	// Check if all required processing is complete and atomically set signature flag
	session.StreamsMutex.Lock()

	session.TranscriptMutex.Lock()
	transcriptReady := len(session.TranscriptPackets) > 0
	session.TranscriptMutex.Unlock()

	redactionComplete := session.RedactionProcessingComplete
	hasRedactedStreams := len(session.RedactedStreams) > 0
	signatureAlreadySent := session.SignatureSent

	// All processing is complete when:
	// 1. We have transcript data (from finished message)
	// 2. Redaction processing is complete
	// 3. We have redacted streams
	// 4. We haven't already sent a signature
	allProcessingComplete := transcriptReady && redactionComplete && hasRedactedStreams && !signatureAlreadySent

	if allProcessingComplete {
		t.logger.WithSession(sessionID).Info("All processing complete, generating and sending signature")
		// Mark signature as sent to prevent duplicates
		session.SignatureSent = true
		// Release lock before calling generateComprehensiveSignatureAndSendTranscript
		session.StreamsMutex.Unlock()
		return t.generateComprehensiveSignatureAndSendTranscript(sessionID)
	} else {
		t.logger.WithSession(sessionID).Info("Not ready to send signature yet",
			zap.Bool("transcript_ready", transcriptReady),
			zap.Bool("redaction_complete", redactionComplete),
			zap.Bool("has_redacted_streams", hasRedactedStreams),
			zap.Bool("signature_already_sent", signatureAlreadySent))
		// Don't set SignatureSent = true if we're not actually sending a signature
		session.StreamsMutex.Unlock()
	}

	return nil
}

// generateComprehensiveSignatureAndSendTranscript creates comprehensive signature and sends all verification data to client
func (t *TEEK) generateComprehensiveSignatureAndSendTranscript(sessionID string) error {
	t.logger.WithSession(sessionID).Info("Generating comprehensive signature")

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
			var ranges []shared.RequestRedactionRange
			if err := json.Unmarshal(packet, &ranges); err != nil {
				t.logger.WithSession(sessionID).Error("Failed to unmarshal redaction ranges from transcript", zap.Error(err))
			} else {
				requestMetadata.RedactionRanges = ranges
				t.logger.WithSession(sessionID).Info("Loaded redaction ranges from transcript", zap.Int("ranges", len(ranges)))
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

	// Add response redaction ranges to signature
	if session.ResponseState != nil && len(session.ResponseState.ResponseRedactionRanges) > 0 {
		responseRedactionRangesBytes, err := json.Marshal(session.ResponseState.ResponseRedactionRanges)
		if err != nil {
			return fmt.Errorf("failed to marshal response redaction ranges for signature: %v", err)
		}
		masterBuffer.Write(responseRedactionRangesBytes)
		t.logger.WithSession(sessionID).Info("Included response redaction ranges in signature", zap.Int("ranges", len(session.ResponseState.ResponseRedactionRanges)))
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

	// Add response redaction ranges to transcript if available
	if session.ResponseState != nil && len(session.ResponseState.ResponseRedactionRanges) > 0 {
		signedTranscript.ResponseRedactionRanges = session.ResponseState.ResponseRedactionRanges
		t.logger.WithSession(sessionID).Info("Added response redaction ranges to transcript",
			zap.Int("ranges", len(session.ResponseState.ResponseRedactionRanges)))
	}

	t.logger.WithSession(sessionID).Info("Generated comprehensive signature",
		zap.Int("tls_packets", len(tlsPackets)),
		zap.Int("redacted_streams", len(session.RedactedStreams)),
		zap.Bool("metadata_present", requestMetadata != nil))

	// Debug: Check what we're sending
	t.logger.WithSession(sessionID).Debug("Sending transcript with comprehensive signature",
		zap.Int("signature_bytes", len(signedTranscript.Signature)))

	// Send combined signed transcript with streams to client via protobuf
	// Map to teeproto SignedMessage (KOutputPayload)
	// Build KOutputPayload deterministically
	kPayload := &teeproto.KOutputPayload{}
	if signedTranscript.RequestMetadata != nil {
		kPayload.RedactedRequest = signedTranscript.RequestMetadata.RedactedRequest
		for _, r := range signedTranscript.RequestMetadata.RedactionRanges {
			kPayload.RequestRedactionRanges = append(kPayload.RequestRedactionRanges, &teeproto.RequestRedactionRange{Start: int32(r.Start), Length: int32(r.Length), Type: r.Type, RedactionBytes: r.RedactionBytes})
		}
	}
	for _, s := range session.RedactedStreams {
		kPayload.RedactedStreams = append(kPayload.RedactedStreams, &teeproto.SignedRedactedDecryptionStream{RedactedStream: s.RedactedStream, SeqNum: s.SeqNum})
	}
	for _, p := range signedTranscript.Packets {
		kPayload.Packets = append(kPayload.Packets, p)
	}
	for _, rr := range signedTranscript.ResponseRedactionRanges {
		kPayload.ResponseRedactionRanges = append(kPayload.ResponseRedactionRanges, &teeproto.ResponseRedactionRange{Start: int32(rr.Start), Length: int32(rr.Length)})
	}

	// Deterministic serialization
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(kPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal KOutputPayload: %v", err)
	}

	signedMsg := &teeproto.SignedMessage{
		BodyType:  teeproto.BodyType_BODY_TYPE_K_OUTPUT,
		Body:      body,
		PublicKey: signedTranscript.PublicKey,
		Signature: signedTranscript.Signature,
	}

	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_SignedMessage{SignedMessage: signedMsg},
	}
	if err := t.sessionManager.RouteToClient(sessionID, env); err != nil {
		return fmt.Errorf("failed to send signed message to client: %v", err)
	}

	t.logger.WithSession(sessionID).Info("Sent SignedMessage (KOutput) to client",
		zap.Int("packets", len(signedTranscript.Packets)),
		zap.Int("redacted_streams", len(session.RedactedStreams)))
	return nil
}

// handleAttestationRequestSession handles attestation requests from clients over WebSocket
func (t *TEEK) handleAttestationRequestSession(sessionID string, msg *shared.Message) {
	var attestReq shared.AttestationRequestData
	if err := msg.UnmarshalData(&attestReq); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to unmarshal attestation request", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, fmt.Errorf("failed to parse attestation request"), "failed to parse attestation request")
		return
	}

	t.logger.WithSession(sessionID).Info("Processing attestation request")

	// Get attestation from enclave manager if available
	if t.signingKeyPair == nil {
		t.logger.WithSession(sessionID).Error("No signing key pair available for attestation")
		t.sendAttestationResponse(sessionID, nil, false, "No signing key pair available")
		return
	}

	// Generate attestation document using enclave manager
	publicKeyDER, err := t.signingKeyPair.GetPublicKeyDER()
	if err != nil {
		t.logger.WithSession(sessionID).Error("Failed to get public key DER", zap.Error(err))
		t.sendAttestationResponse(sessionID, nil, false, "Failed to get public key")
		return
	}

	// Create user data containing the hex-encoded ECDSA public key
	userData := fmt.Sprintf("tee_k_public_key:%x", publicKeyDER)
	t.logger.WithSession(sessionID).Info("Including ECDSA public key in attestation", zap.Int("der_bytes", len(publicKeyDER)))

	// Generate attestation document using enclave manager
	if t.enclaveManager == nil {
		t.logger.WithSession(sessionID).Error("No enclave manager available for attestation")
		t.sendAttestationResponse(sessionID, nil, false, "No enclave manager available")
		return
	}

	attestationDoc, err := t.enclaveManager.GenerateAttestation(context.Background(), []byte(userData))
	if err != nil {
		t.logger.WithSession(sessionID).Error("Failed to generate attestation", zap.Error(err))
		t.sendAttestationResponse(sessionID, nil, false, fmt.Sprintf("Failed to generate attestation: %v", err))
		return
	}

	t.logger.WithSession(sessionID).Info("Generated attestation document", zap.Int("bytes", len(attestationDoc)))

	// Wrap in structured report for unified client handling (Nitro)
	report := shared.AttestationReport{
		Type:       "nitro",
		Report:     attestationDoc,
		SigningKey: publicKeyDER,
	}
	payload, _ := json.Marshal(report)

	// Send successful response
	t.sendAttestationResponse(sessionID, payload, true, "")
}

// sendAttestationResponse sends attestation response to client (request ID removed)
func (t *TEEK) sendAttestationResponse(sessionID string, attestationDoc []byte, success bool, errorMessage string) {
	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_AttestationResponse{AttestationResponse: &teeproto.AttestationResponse{AttestationDoc: attestationDoc, Success: success, ErrorMessage: errorMessage, Source: "tee_k"}},
	}
	if err := t.sessionManager.RouteToClient(sessionID, env); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to send attestation response", zap.Error(err))
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
		t.logger.WithSession(sessionID).Error("Failed to unmarshal batched response lengths", zap.Error(err))
		return
	}

	t.logger.WithSession(sessionID).Info("Received batched response lengths",
		zap.Int("total_count", batchedLengths.TotalCount))

	// Get session to store response lengths
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.logger.WithSession(sessionID).Error("Failed to get session for batched lengths", zap.Error(err))
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
			t.logger.WithSession(sessionID).Error("Failed to generate tag secrets for sequence in batch",
				zap.Uint64("seq_num", lengthData.SeqNum), zap.Error(err))
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

	t.logger.WithSession(sessionID).Info("Generated batched tag secrets",
		zap.Int("count", len(tagSecrets)))

	// Send all tag secrets as a batch to TEE_T
	// Convert tag secrets to protobuf format
	var pbTagSecrets []*teeproto.BatchedTagSecrets_TagSecret
	for _, ts := range tagSecrets {
		pbTagSecrets = append(pbTagSecrets, &teeproto.BatchedTagSecrets_TagSecret{
			TagSecrets:  ts.TagSecrets,
			SeqNum:      ts.SeqNum,
			CipherSuite: uint32(ts.CipherSuite),
		})
	}

	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_BatchedTagSecrets{
			BatchedTagSecrets: &teeproto.BatchedTagSecrets{
				TagSecrets: pbTagSecrets,
				SessionId:  sessionID,
				TotalCount: int32(len(tagSecrets)),
			},
		},
	}

	if err := t.sendEnvelopeToTEETForSession(sessionID, env); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to send batched tag secrets to TEE_T", zap.Error(err))
		return
	}

	t.logger.WithSession(sessionID).Info("Successfully sent batched tag secrets to TEE_T",
		zap.Int("count", len(tagSecrets)))
}

// Helper function logic inlined in batched handler

func (t *TEEK) handleBatchedTagVerificationsSession(sessionID string, msg *shared.Message) {
	var batchedVerification shared.BatchedTagVerificationData
	if err := msg.UnmarshalData(&batchedVerification); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to unmarshal batched tag verification", zap.Error(err))
		return
	}

	t.logger.WithSession(sessionID).Info("Received batched tag verification",
		zap.Int("total_count", batchedVerification.TotalCount),
		zap.Bool("all_successful", batchedVerification.AllSuccessful))

	if !batchedVerification.AllSuccessful {
		t.logger.WithSession(sessionID).Error("Some tag verifications failed - not sending decryption streams")
		return
	}

	// Generate decryption streams based on verification results
	var decryptionStreams []shared.ResponseDecryptionStreamData

	if batchedVerification.AllSuccessful {
		// All verifications passed - generate streams for all responses
		responseState, err := t.getSessionResponseState(sessionID)
		if err != nil {
			t.logger.WithSession(sessionID).Error("Failed to get response state", zap.Error(err))
			return
		}

		// Generate decryption streams for all response sequences
		for seqNum, responseLength := range responseState.ResponseLengthBySeqInt {
			// Generate decryption stream using session-aware logic
			decryptionStream, err := t.generateSingleDecryptionStreamWithSession(sessionID, responseLength, seqNum)
			if err != nil {
				t.logger.WithSession(sessionID).Error("Failed to generate decryption stream for sequence",
					zap.Uint64("seq_num", seqNum), zap.Error(err))
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
				t.logger.WithSession(sessionID).Error("Failed to get response state", zap.Error(err))
				continue
			}
			responseLength, exists := responseState.ResponseLengthBySeqInt[verification.SeqNum]
			if !exists {
				t.logger.WithSession(sessionID).Error("No response length found for sequence", zap.Uint64("seq_num", verification.SeqNum))
				continue
			}

			// Generate decryption stream using session-aware logic
			decryptionStream, err := t.generateSingleDecryptionStreamWithSession(sessionID, responseLength, verification.SeqNum)
			if err != nil {
				t.logger.WithSession(sessionID).Error("Failed to generate decryption stream for sequence",
					zap.Uint64("seq_num", verification.SeqNum), zap.Error(err))
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

	t.logger.WithSession(sessionID).Info("Generated batched decryption streams",
		zap.Int("count", len(decryptionStreams)))

	// Send all decryption streams as a batch to client
	streams := make([]*teeproto.ResponseDecryptionStreamData, 0, len(decryptionStreams))
	for _, s := range decryptionStreams {
		streams = append(streams, &teeproto.ResponseDecryptionStreamData{DecryptionStream: s.DecryptionStream, SeqNum: s.SeqNum, Length: int32(s.Length)})
	}
	envStreams := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_BatchedDecryptionStreams{BatchedDecryptionStreams: &teeproto.BatchedDecryptionStreams{DecryptionStreams: streams, SessionId: sessionID, TotalCount: int32(len(streams))}},
	}

	if err := t.sessionManager.RouteToClient(sessionID, envStreams); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to send batched decryption streams to client", zap.Error(err))
		return
	}

	t.logger.WithSession(sessionID).Info("Successfully sent batched decryption streams to client",
		zap.Int("count", len(decryptionStreams)))
}

// getCachedDecryptionStream retrieves a cached decryption stream, generating it if not cached
func (t *TEEK) getCachedDecryptionStream(sessionID string, responseLength int, seqNum uint64) ([]byte, error) {
	// Get session to access cache
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return nil, fmt.Errorf("session %s not found: %v", sessionID, err)
	}

	// Check cache first
	session.StreamsMutex.Lock()
	if session.CachedDecryptionStreams == nil {
		session.CachedDecryptionStreams = make(map[uint64][]byte)
	}
	if cachedStream, exists := session.CachedDecryptionStreams[seqNum]; exists {
		session.StreamsMutex.Unlock()
		// Return a copy to avoid external modification
		streamCopy := make([]byte, len(cachedStream))
		copy(streamCopy, cachedStream)
		return streamCopy, nil
	}
	session.StreamsMutex.Unlock()

	// If not cached, generate and cache it
	return t.generateSingleDecryptionStreamWithSession(sessionID, responseLength, seqNum)
}

func (t *TEEK) generateSingleDecryptionStreamWithSession(sessionID string, responseLength int, seqNum uint64) ([]byte, error) {
	// Get session to access cache
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return nil, fmt.Errorf("session %s not found: %v", sessionID, err)
	}

	// Get TLS client from session state
	var tlsClient *minitls.Client
	if sessionID != "" {
		tlsState, err := t.getSessionTLSState(sessionID)
		if err != nil {
			return nil, fmt.Errorf("failed to get TLS state: %v", err)
		}
		tlsClient = tlsState.TLSClient
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

		// fmt.Printf("[TEE_K] Using TLS 1.2 server keys for batched decryption stream\n")
	} else { // TLS 1.3
		// Get key schedule to access server application keys
		keySchedule := tlsClient.GetKeySchedule()
		if keySchedule == nil {
			return nil, fmt.Errorf("no key schedule available")
		}

		serverAppKey = keySchedule.GetServerApplicationKey()
		serverAppIV = keySchedule.GetServerApplicationIV()

		// fmt.Printf("[TEE_K] Using TLS 1.3 server keys for batched decryption stream\n")
	}

	if serverAppKey == nil || serverAppIV == nil {
		return nil, fmt.Errorf("missing server application key or IV")
	}

	// Get cipher suite from TLS client
	cipherSuite := tlsClient.GetCipherSuite()

	// Get stored explicit IV for TLS 1.2 AES-GCM
	var explicitIV []byte
	responseState, err := t.getSessionResponseState(sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session response state: %v", err)
	}
	explicitIV = responseState.ExplicitIVBySeq[seqNum]

	// Generate cipher-agnostic decryption stream
	// Use same sequence logic as tag generation for consistency
	var serverSeqNum uint64
	if tlsVersion == 0x0303 { // TLS 1.2
		serverSeqNum = seqNum // Server sequence matches client sequence
		// fmt.Printf("[TEE_K] TLS 1.2 batched decryption: Using server sequence %d (same as client)\n", serverSeqNum)
	} else { // TLS 1.3
		serverSeqNum = seqNum - 1
		// fmt.Printf("[TEE_K] TLS 1.3 batched decryption: Using server sequence %d (client - 1)\n", serverSeqNum)
	}

	decryptionStream, err := minitls.GenerateDecryptionStream(serverAppKey, serverAppIV, serverSeqNum, streamLength, cipherSuite, explicitIV)
	if err != nil {
		return nil, fmt.Errorf("failed to generate decryption stream: %v", err)
	}

	// Cache the generated stream
	session.StreamsMutex.Lock()
	if session.CachedDecryptionStreams == nil {
		session.CachedDecryptionStreams = make(map[uint64][]byte)
	}
	session.CachedDecryptionStreams[seqNum] = decryptionStream
	session.StreamsMutex.Unlock()

	// fmt.Printf("[TEE_K] Generated and cached decryption stream (seq=%d, %d bytes)\n", seqNum, len(decryptionStream))
	return decryptionStream, nil
}
