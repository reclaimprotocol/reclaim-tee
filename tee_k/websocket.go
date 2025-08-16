package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

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

// WebSocketConn adapts websocket to net.Conn interface for miniTLS
type WebSocketConn struct {
	wsConn      *websocket.Conn
	readBuffer  []byte
	readOffset  int
	pendingData chan []byte
	teek        *TEEK  // Reference to TEEK for transcript collection
	sessionID   string // Session ID for per-session transcript collection
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

			return conn, nil
		},
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
						ExplicitIV   []byte `json:"explicit_iv,omitempty"`
					}{Length: int(l.GetLength()), RecordHeader: l.GetRecordHeader(), SeqNum: l.GetSeqNum(), ExplicitIV: l.GetExplicitIv()})
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

// handleWebSocket handles incoming WebSocket connections from clients
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
	if data, err := proto.Marshal(env); err != nil || wsConn.WriteMessage(websocket.BinaryMessage, data) != nil {
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
				ranges = append(ranges, shared.RequestRedactionRange{Start: int(r.GetStart()), Length: int(r.GetLength()), Type: r.GetType()})
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

	wsConn := shared.NewWSConnection(teetConn)
	session.TEETConn = wsConn

	// No per-session message handler needed - shared connection is monitored centrally

	// Send session registration to TEE_T via protobuf
	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_SessionCreated{SessionCreated: &teeproto.SessionCreated{}},
	}
	if data, err := proto.Marshal(env); err != nil {
		return fmt.Errorf("failed to marshal session registration: %v", err)
	} else if err := wsConn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return fmt.Errorf("failed to send session registration: %v", err)
	}

	t.logger.WithSession(sessionID).Info("Successfully created TEE_T connection and sent session registration")
	return nil
}

// WebSocketConn implementation of net.Conn interface with thread-safe writes

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

	// Use thread-safe WriteMessage - this WebSocketConn wraps a raw websocket.Conn
	// so we need to add our own mutex protection
	// For now, use the raw WriteMessage but this could be a race condition source
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
