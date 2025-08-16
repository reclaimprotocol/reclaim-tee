package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	teeproto "tee-mpc/proto"
	"tee-mpc/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// handleClientWebSocket handles WebSocket connections from clients
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
				if t.sessionTerminator.ProtocolError(sessionID, shared.ReasonConnectionLost, err,
					zap.String("remote_addr", r.RemoteAddr)) {
					break
				}
			}
			break
		}

		t.logger.DebugIf("Received raw message from client",
			zap.Int("bytes", len(msgBytes)),
			zap.String("preview", string(msgBytes[:min(100, len(msgBytes))])))

		var env teeproto.Envelope
		if err := proto.Unmarshal(msgBytes, &env); err != nil {
			if t.sessionTerminator.ProtocolError(sessionID, shared.ReasonMessageParsingFailed, err,
				zap.String("remote_addr", r.RemoteAddr),
				zap.Int("message_size", len(msgBytes))) {
				t.sendErrorToClient(sessionID, fmt.Sprintf("Failed to parse message: %v", err))
				break
			}
			t.sendErrorToClient(sessionID, fmt.Sprintf("Failed to parse message: %v", err))
			break
		}
		var msg *shared.Message
		switch p := env.Payload.(type) {
		case *teeproto.Envelope_TeetReady:
			msg = &shared.Message{SessionID: env.GetSessionId(), Type: shared.MsgTEETReady, Data: shared.TEETReadyData{Success: p.TeetReady.GetSuccess()}}
		case *teeproto.Envelope_RedactionStreams:
			msg = &shared.Message{SessionID: env.GetSessionId(), Type: shared.MsgRedactionStreams, Data: shared.RedactionStreamsData{Streams: p.RedactionStreams.GetStreams(), CommitmentKeys: p.RedactionStreams.GetCommitmentKeys()}}
		case *teeproto.Envelope_Finished:
			msg = &shared.Message{SessionID: env.GetSessionId(), Type: shared.MsgFinished, Data: shared.FinishedMessage{}}
		case *teeproto.Envelope_BatchedEncryptedResponses:
			var arr []shared.EncryptedResponseData
			for _, r := range p.BatchedEncryptedResponses.GetResponses() {
				arr = append(arr, shared.EncryptedResponseData{EncryptedData: r.GetEncryptedData(), Tag: r.GetTag(), RecordHeader: r.GetRecordHeader(), SeqNum: r.GetSeqNum(), ExplicitIV: r.GetExplicitIv()})
			}
			msg = &shared.Message{SessionID: env.GetSessionId(), Type: shared.MsgBatchedEncryptedResponses, Data: shared.BatchedEncryptedResponseData{Responses: arr, SessionID: p.BatchedEncryptedResponses.GetSessionId(), TotalCount: int(p.BatchedEncryptedResponses.GetTotalCount())}}
		default:
			t.sendErrorToClient(sessionID, "Unknown message type")
		}

		t.logger.DebugIf("Received message from client",
			zap.String("message_type", string(msg.Type)),
			zap.String("session_id", msg.SessionID))

		if msg.SessionID != "" {
			if sessionID == "" {
				sessionID = msg.SessionID
				wsConn := shared.NewWSConnection(conn)
				if err := t.sessionManager.ActivateSession(sessionID, wsConn); err != nil {
					t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionManagerFailure, err,
						zap.String("remote_addr", r.RemoteAddr))
					t.sendErrorToClient(sessionID, "Failed to activate session")
					break
				}

				teetState, err := t.sessionManager.GetTEETSessionState(sessionID)
				if err != nil {
					teetState = &TEETSessionState{TEETClientConn: conn}
					t.sessionManager.SetTEETSessionState(sessionID, teetState)
				} else {
					teetState.TEETClientConn = conn
				}
				t.logger.InfoIf("Activated session for client",
					zap.String("session_id", sessionID),
					zap.String("remote_addr", conn.RemoteAddr().String()))
			} else if msg.SessionID != sessionID {
				t.sessionTerminator.SecurityViolation(sessionID, shared.ReasonSessionIDMismatch,
					fmt.Errorf("expected %s, got %s", sessionID, msg.SessionID),
					zap.String("expected_session", sessionID),
					zap.String("received_session", msg.SessionID),
					zap.String("remote_addr", r.RemoteAddr))
				t.sendErrorToClient(sessionID, "Session ID mismatch")
				break
			}
		}

		switch msg.Type {
		case shared.MsgTEETReady:
			t.logger.DebugIf("Handling MsgTEETReady", zap.String("session_id", sessionID))
			t.handleTEETReadySession(sessionID, msg)
		case shared.MsgRedactionStreams:
			t.logger.DebugIf("Handling MsgRedactionStreams", zap.String("session_id", sessionID))
			t.handleRedactionStreamsSession(sessionID, msg)
		case shared.MsgFinished:
			t.logger.DebugIf("Handling MsgFinished from TEE_K", zap.String("session_id", sessionID))
			t.handleFinishedFromTEEKSession(msg)
		case shared.MsgBatchedEncryptedResponses:
			t.logger.DebugIf("Handling MsgBatchedEncryptedResponses", zap.String("session_id", sessionID))
			t.handleBatchedEncryptedResponsesSession(sessionID, msg)
		default:
			if t.sessionTerminator.ProtocolError(sessionID, shared.ReasonUnknownMessageType,
				fmt.Errorf("unknown message type: %s", string(msg.Type)),
				zap.String("message_type", string(msg.Type)),
				zap.String("remote_addr", r.RemoteAddr)) {
				t.sendErrorToClient(sessionID, fmt.Sprintf("Unknown message type: %s", msg.Type))
				break
			}
			t.sendErrorToClient(sessionID, fmt.Sprintf("Unknown message type: %s", msg.Type))
		}
	}

	if sessionID != "" {
		t.logger.InfoIf("Cleaning up session", zap.String("session_id", sessionID))
		t.sessionManager.CloseSession(sessionID)
		t.sessionTerminator.CleanupSession(sessionID)
	}
}

// handleTEEKWebSocket handles WebSocket connections from TEE_K
func (t *TEET) handleTEEKWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := teetUpgrader.Upgrade(w, r, nil)
	if err != nil {
		t.logger.Error("Failed to upgrade TEE_K websocket",
			zap.Error(err),
			zap.String("remote_addr", r.RemoteAddr))
		return
	}

	t.logger.InfoIf("TEE_K connection established", zap.String("remote_addr", conn.RemoteAddr().String()))

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
			t.sendErrorToTEEK("", fmt.Sprintf("Failed to parse message: %v", err))
			continue
		}

		sessionID := env.GetSessionId()
		if sessionID == "" {
			t.logger.Error("Missing session ID in message from TEE_K", zap.String("remote_addr", r.RemoteAddr))
			t.sendErrorToTEEK("", "Missing session ID")
			continue
		}

		var msg *shared.Message
		switch p := env.Payload.(type) {
		case *teeproto.Envelope_SessionCreated:
			msg = &shared.Message{SessionID: sessionID, Type: shared.MsgSessionCreated, Data: map[string]interface{}{"session_id": sessionID}}
			activeSessionsMutex.Lock()
			activeSessions[sessionID] = true
			activeSessionsMutex.Unlock()
			t.logger.InfoIf("New session started on TEE_K connection", zap.String("session_id", sessionID))
		case *teeproto.Envelope_KeyShareRequest:
			msg = &shared.Message{SessionID: sessionID, Type: shared.MsgKeyShareRequest, Data: shared.KeyShareRequestData{KeyLength: int(p.KeyShareRequest.GetKeyLength()), IVLength: int(p.KeyShareRequest.GetIvLength())}}
		case *teeproto.Envelope_EncryptedRequest:
			var rr []shared.RequestRedactionRange
			for _, r := range p.EncryptedRequest.GetRedactionRanges() {
				rr = append(rr, shared.RequestRedactionRange{Start: int(r.GetStart()), Length: int(r.GetLength()), Type: r.GetType()})
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
			t.sendErrorToTEEK(sessionID, "Unknown message type from TEE_K")
			continue
		}

		t.logger.DebugIf("Received message from TEE_K",
			zap.String("message_type", string(msg.Type)),
			zap.String("session_id", sessionID))

		switch msg.Type {
		case shared.MsgSessionCreated:
			t.handleSessionCreation(msg)
			if sessionID != "" {
				session, err := t.sessionManager.GetSession(sessionID)
				if err != nil {
					if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionManagerFailure, err,
						zap.String("remote_addr", r.RemoteAddr),
						zap.String("connection_type", "teek")) {
						break
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
			if t.sessionTerminator.ProtocolError(sessionID, shared.ReasonUnknownMessageType,
				fmt.Errorf("unknown message type: %s", string(msg.Type)),
				zap.String("message_type", string(msg.Type)),
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("connection_type", "teek")) {
				t.sendErrorToTEEK(sessionID, fmt.Sprintf("Unknown message type: %s", msg.Type))
				break
			}
			t.sendErrorToTEEK(sessionID, fmt.Sprintf("Unknown message type: %s", msg.Type))
		}
	}

	activeSessionsMutex.RLock()
	sessionCount := len(activeSessions)
	activeSessionsMutex.RUnlock()

	if sessionCount > 0 {
		t.logger.InfoIf("Cleaning up sessions due to TEE_K disconnect", zap.Int("session_count", sessionCount))
		activeSessionsMutex.RLock()
		for sessionID := range activeSessions {
			t.sessionTerminator.CleanupSession(sessionID)
		}
		activeSessionsMutex.RUnlock()
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
