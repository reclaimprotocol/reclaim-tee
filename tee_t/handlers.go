package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net/http"
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

func (t *TEET) handleTEETReadySession(sessionID string, msg *shared.Message) {
	if sessionID == "" {
		if t.sessionTerminator.ProtocolViolation("", shared.ReasonMissingSessionID,
			fmt.Errorf("TEE_T ready message missing session ID")) {
			return
		}
		return
	}

	t.logger.InfoIf("Handling TEE_T ready for session", zap.String("session_id", sessionID))

	var readyData shared.TEETReadyData
	if err := msg.UnmarshalData(&readyData); err != nil {
		t.logger.Error("Failed to unmarshal TEE_T ready data", zap.Error(err))
		t.sendErrorToClient(sessionID, fmt.Sprintf("Failed to unmarshal TEE_T ready data: %v", err))
		return
	}

	t.ready = readyData.Success

	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_TeetReady{TeetReady: &teeproto.TEETReady{Success: true}},
	}
	if err := t.sessionManager.RouteToClient(sessionID, env); err != nil {
		t.logger.Error("Failed to send TEE_T ready response",
			zap.String("session_id", sessionID),
			zap.Error(err))
	}
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

	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		if t.sessionTerminator.ZeroToleranceError(sessionID, shared.ReasonSessionNotFound, err) {
			return
		}
		return
	}

	if session.RedactionState == nil {
		session.RedactionState = &shared.RedactionSessionState{}
	}

	session.RedactionState.RedactionStreams = streamsData.Streams
	session.RedactionState.CommitmentKeys = streamsData.CommitmentKeys

	t.logger.InfoIf("Redaction streams stored for session", zap.String("session_id", sessionID))

	if err := t.verifyCommitmentsIfReady(sessionID); err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonCryptoCommitmentFailed, err,
			zap.Int("commitment_count", len(session.RedactionState.ExpectedCommitments))) {
			return
		}
		return
	}

	teetState, err := t.getTEETSessionState(sessionID)
	if err == nil && teetState.PendingEncryptedRequest != nil {
		t.logger.InfoIf("Processing pending encrypted request with newly received streams", zap.String("session_id", sessionID))
		if teetState.TEETConnForPending != nil {
			t.processEncryptedRequestWithStreamsForSession(sessionID, teetState.PendingEncryptedRequest, teetState.TEETConnForPending)
		}
		teetState.PendingEncryptedRequest = nil
		teetState.TEETConnForPending = nil
	}

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

	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionNotFound, err) {
			return
		}
		return
	}

	if session.ResponseState == nil {
		session.ResponseState = &shared.ResponseSessionState{
			PendingEncryptedResponses: make(map[uint64]*shared.EncryptedResponseData),
		}
	}

	var responseLengths []struct {
		Length       int    `json:"length"`
		RecordHeader []byte `json:"record_header"`
		SeqNum       uint64 `json:"seq_num"`
		ExplicitIV   []byte `json:"explicit_iv,omitempty"`
	}

	session.ResponseState.ResponsesMutex.Lock()
	for _, encryptedResp := range batchedResponses.Responses {
		session.ResponseState.PendingEncryptedResponses[encryptedResp.SeqNum] = &encryptedResp
		t.addSingleResponseToTranscript(sessionID, &encryptedResp)
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
	teetState, err := t.sessionManager.GetTEETSessionState(sessionID)
	if err != nil {
		t.logger.Error("Failed to get TEET session state", zap.Error(err))
		return
	}
	isTLS12AESGCMCipher := shared.IsTLS12AESGCMCipherSuite(teetState.CipherSuite)
	var payload []byte
	if isTLS12AESGCMCipher && encryptedResp.ExplicitIV != nil && len(encryptedResp.ExplicitIV) == 8 {
		payload = make([]byte, 8+len(encryptedResp.EncryptedData)+len(encryptedResp.Tag))
		copy(payload[0:8], encryptedResp.ExplicitIV)
		copy(payload[8:8+len(encryptedResp.EncryptedData)], encryptedResp.EncryptedData)
		copy(payload[8+len(encryptedResp.EncryptedData):], encryptedResp.Tag)
		t.logger.DebugIf("Added explicit IV to TLS 1.2 AES-GCM response transcript record",
			zap.String("session_id", sessionID),
			zap.Binary("explicit_iv", encryptedResp.ExplicitIV))
	} else {
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
	if len(encryptedResp.RecordHeader) >= 1 {
		record[0] = encryptedResp.RecordHeader[0]
	} else {
		record[0] = 0x17
	}
	record[1] = 0x03
	record[2] = 0x03
	record[3] = byte(recordLength >> 8)
	record[4] = byte(recordLength & 0xFF)
	copy(record[5:], payload)
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
	if err := t.sessionManager.RegisterSession(sessionID); err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionManagerFailure, err) {
			return
		}
		return
	}
	teetState := &TEETSessionState{TEETClientConn: nil}
	t.sessionManager.SetTEETSessionState(sessionID, teetState)
	t.logger.InfoIf("Created TEE_T session state for registered session", zap.String("session_id", sessionID))
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
			t.sendErrorToTEEK(sessionID, fmt.Sprintf("Failed to unmarshal key share request: %v", err))
			return
		}
		return
	}
	keyShare := make([]byte, keyReq.KeyLength)
	if _, err := rand.Read(keyShare); err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonCryptoKeyGenerationFailed, err,
			zap.Int("key_length", keyReq.KeyLength)) {
			t.sendErrorToTEEK(sessionID, fmt.Sprintf("Failed to generate key share: %v", err))
			return
		}
		return
	}
	teetState, err := t.getTEETSessionState(sessionID)
	if err != nil {
		t.logger.Error("Failed to get TEE_T session state", zap.String("session_id", sessionID), zap.Error(err))
		return
	}
	teetState.KeyShare = keyShare
	t.logger.InfoIf("Generated key share for session",
		zap.String("session_id", sessionID),
		zap.Int("key_length", len(keyShare)))
	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_KeyShareResponse{KeyShareResponse: &teeproto.KeyShareResponse{KeyShare: keyShare, Success: true}},
	}
	if data, err := proto.Marshal(env); err == nil {
		wsConn := session.TEEKConn.(*shared.WSConnection)
		if err := wsConn.WriteMessage(websocket.BinaryMessage, data); err != nil {
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
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionNotFound, err) {
			return
		}
		return
	}
	if session.RedactionState == nil {
		session.RedactionState = &shared.RedactionSessionState{}
	}
	if session.ResponseState == nil {
		session.ResponseState = &shared.ResponseSessionState{
			PendingEncryptedResponses: make(map[uint64]*shared.EncryptedResponseData),
		}
	}
	session.RedactionState.Ranges = encReq.RedactionRanges
	session.RedactionState.ExpectedCommitments = encReq.Commitments
	t.logger.InfoIf("Stored expected commitments from TEE_K",
		zap.String("session_id", sessionID),
		zap.Int("commitment_count", len(encReq.Commitments)))
	if err := t.verifyCommitmentsIfReady(sessionID); err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonCryptoCommitmentFailed, err,
			zap.Int("commitment_count", len(encReq.Commitments))) {
			return
		}
		return
	}
	if len(session.RedactionState.RedactionStreams) == 0 {
		teetState, err := t.getTEETSessionState(sessionID)
		if err != nil {
			t.logger.Error("Failed to get TEE_T session state", zap.String("session_id", sessionID), zap.Error(err))
			return
		}
		teetState.PendingEncryptedRequest = &encReq
		wsConn := session.TEEKConn.(*shared.WSConnection)
		teetState.TEETConnForPending = wsConn.GetWebSocketConn()
		t.logger.InfoIf("Storing encrypted request for session, waiting for redaction streams...",
			zap.String("session_id", sessionID))
		return
	}
	wsConn := session.TEEKConn.(*shared.WSConnection)
	t.processEncryptedRequestWithStreamsForSession(sessionID, &encReq, wsConn.GetWebSocketConn())
}

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
	var verifications []shared.ResponseTagVerificationData
	allSuccessful := true
	totalCount := len(batchedTagSecrets.TagSecrets)
	session.ResponseState.ResponsesMutex.Lock()
	for _, tagSecretsData := range batchedTagSecrets.TagSecrets {
		encryptedResp := session.ResponseState.PendingEncryptedResponses[tagSecretsData.SeqNum]
		if encryptedResp == nil {
			if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionStateCorrupted,
				fmt.Errorf("critical security failure: missing encrypted response for seq %d", tagSecretsData.SeqNum),
				zap.Uint64("seq_num", tagSecretsData.SeqNum)) {
				session.ResponseState.ResponsesMutex.Unlock()
				return
			}
			session.ResponseState.ResponsesMutex.Unlock()
			return
		}
		verificationResult := t.verifyTagForResponse(sessionID, encryptedResp, &tagSecretsData)
		if !verificationResult.Success {
			if t.sessionTerminator.CriticalError(sessionID, shared.ReasonCryptoTagVerificationFailed,
				fmt.Errorf("tag verification failed for seq %d", tagSecretsData.SeqNum),
				zap.Uint64("seq_num", tagSecretsData.SeqNum)) {
				session.ResponseState.ResponsesMutex.Unlock()
				return
			}
			allSuccessful = false
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
	teetState, err := t.sessionManager.GetTEETSessionState(sessionID)
	if err != nil {
		return shared.ResponseTagVerificationData{Success: false, SeqNum: encryptedResp.SeqNum, Message: fmt.Sprintf("Failed to get TEE_T session state: %v", err)}
	}
	var additionalData []byte
	cipherSuite := teetState.CipherSuite
	if cipherSuite == 0 {
		return shared.ResponseTagVerificationData{Success: false, SeqNum: encryptedResp.SeqNum, Message: "CipherSuite not available in session state"}
	}
	if cipherSuite == 0x1301 || cipherSuite == 0x1302 || cipherSuite == 0x1303 {
		tagSize := 16
		ciphertextLength := len(encryptedResp.EncryptedData) + tagSize
		var recordType byte = 0x17
		if len(encryptedResp.RecordHeader) >= 1 {
			recordType = encryptedResp.RecordHeader[0]
		}
		additionalData = []byte{recordType, 0x03, 0x03, byte(ciphertextLength >> 8), byte(ciphertextLength & 0xFF)}
		t.logger.DebugIf("Constructed TLS 1.3 AAD for tag verification",
			zap.String("session_id", sessionID),
			zap.Uint64("seq_num", tagSecretsData.SeqNum),
			zap.Uint8("record_type", recordType),
			zap.Int("ciphertext_tag_len", ciphertextLength))
	} else {
		additionalData = make([]byte, 13)
		for i := 0; i < 8; i++ {
			additionalData[i] = byte(encryptedResp.SeqNum >> (8 * (7 - i)))
		}
		if len(encryptedResp.RecordHeader) >= 1 {
			additionalData[8] = encryptedResp.RecordHeader[0]
		} else {
			additionalData[8] = 0x17
		}
		additionalData[9] = 0x03
		additionalData[10] = 0x03
		additionalData[11] = byte(len(encryptedResp.EncryptedData) >> 8)
		additionalData[12] = byte(len(encryptedResp.EncryptedData) & 0xFF)
		t.logger.DebugIf("Constructed TLS 1.2 AAD for tag verification",
			zap.String("session_id", sessionID),
			zap.Uint64("seq_num", encryptedResp.SeqNum),
			zap.Uint8("record_type", additionalData[8]),
			zap.Int("plaintext_len", len(encryptedResp.EncryptedData)))
	}
	computedTag, err := minitls.ComputeTagFromSecrets(
		encryptedResp.EncryptedData,
		tagSecretsData.TagSecrets,
		cipherSuite,
		additionalData,
	)
	var success bool
	if err != nil {
		t.logger.Error("Failed to compute authentication tag",
			zap.String("session_id", sessionID),
			zap.Uint64("seq_num", encryptedResp.SeqNum),
			zap.Error(err))
		success = false
	} else {
		success = len(computedTag) == len(encryptedResp.Tag)
		if success {
			for i := 0; i < len(computedTag); i++ {
				if computedTag[i] != encryptedResp.Tag[i] {
					success = false
					break
				}
			}
		}
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
	verificationData := shared.ResponseTagVerificationData{Success: success, SeqNum: tagSecretsData.SeqNum}
	if !success {
		verificationData.Message = "Authentication tag verification failed"
	}
	return verificationData
}

func (t *TEET) processEncryptedRequestWithStreamsForSession(sessionID string, encReq *shared.EncryptedRequestData, conn *websocket.Conn) {
	t.logger.InfoIf("Processing encrypted request with available redaction streams for session",
		zap.String("session_id", sessionID))
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionNotFound, err) {
			t.sendErrorToTEEK(sessionID, fmt.Sprintf("Failed to get session: %v", err))
			return
		}
		return
	}
	teetState, err := t.sessionManager.GetTEETSessionState(sessionID)
	if err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionStateCorrupted, err) {
			t.sendErrorToTEEK(sessionID, fmt.Sprintf("Failed to get TEE_T session state: %v", err))
			return
		}
		return
	}
	teetState.CipherSuite = encReq.CipherSuite
	t.logger.InfoIf("Stored CipherSuite in session state",
		zap.String("session_id", sessionID),
		zap.Uint16("cipher_suite", encReq.CipherSuite))
	if session.RedactionState == nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionStateCorrupted,
			fmt.Errorf("no redaction state available for session")) {
			t.sendErrorToTEEK(sessionID, "No redaction state available")
			return
		}
		return
	}
	reconstructedData, err := t.reconstructFullRequestWithStreams(encReq.EncryptedData, encReq.RedactionRanges, session.RedactionState.RedactionStreams)
	if err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonCryptoTagComputationFailed, err) {
			t.sendErrorToTEEK(sessionID, fmt.Sprintf("Failed to reconstruct full request: %v", err))
			return
		}
		return
	}
	t.logger.InfoIf("Successfully reconstructed original request data",
		zap.String("session_id", sessionID))
	var additionalData []byte
	if encReq.CipherSuite == 0x1301 || encReq.CipherSuite == 0x1302 || encReq.CipherSuite == 0x1303 {
		tagSize := 16
		recordLength := len(reconstructedData) + tagSize
		additionalData = []byte{0x17, 0x03, 0x03, byte(recordLength >> 8), byte(recordLength & 0xFF)}
	} else {
		plaintextLength := len(reconstructedData)
		additionalData = make([]byte, 13)
		for i := 0; i < 8; i++ {
			additionalData[i] = byte(encReq.SeqNum >> (8 * (7 - i)))
		}
		additionalData[8] = 0x17
		additionalData[9] = 0x03
		additionalData[10] = 0x03
		additionalData[11] = byte(plaintextLength >> 8)
		additionalData[12] = byte(plaintextLength & 0xFF)
	}
	authTag, err := minitls.ComputeTagFromSecrets(reconstructedData, encReq.TagSecrets, encReq.CipherSuite, additionalData)
	if err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonCryptoTagComputationFailed, err) {
			t.sendErrorToTEEK(sessionID, fmt.Sprintf("Failed to compute authentication tag: %v", err))
			return
		}
		return
	}
	t.logger.InfoIf("Computed split AEAD tag",
		zap.String("session_id", sessionID),
		zap.Binary("tag", authTag),
		zap.Int("data_length", len(reconstructedData)))
	isTLS12AESGCMCipher := shared.IsTLS12AESGCMCipherSuite(encReq.CipherSuite)
	var payload []byte
	if isTLS12AESGCMCipher {
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
		payload = make([]byte, len(reconstructedData)+len(authTag))
		copy(payload, reconstructedData)
		copy(payload[len(reconstructedData):], authTag)
	}
	recordLength := len(payload)
	tlsRecord := make([]byte, 5+recordLength)
	tlsRecord[0] = 0x17
	tlsRecord[1] = 0x03
	tlsRecord[2] = 0x03
	tlsRecord[3] = byte(recordLength >> 8)
	tlsRecord[4] = byte(recordLength & 0xFF)
	copy(tlsRecord[5:], payload)
	t.addToTranscriptForSessionWithType(sessionID, tlsRecord, shared.TranscriptPacketTypeTLSRecord)
	t.logger.InfoIf("Added complete TLS request record to session transcript",
		zap.String("session_id", sessionID),
		zap.Int("record_length", len(tlsRecord)))
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

func (t *TEET) sendMessageToClientSession(sessionID string, msg *shared.Message) error {
	if sessionID == "" {
		return fmt.Errorf("session ID is required")
	}
	switch msg.Type {
	case shared.MsgSignedTranscript:
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
		return ws.WriteMessage(websocket.BinaryMessage, data)
	}
	return fmt.Errorf("unsupported TEE_K connection type")
}

func (t *TEET) sendErrorToTEEK(sessionID string, errMsg string) {
	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Error{Error: &teeproto.ErrorData{Message: errMsg}},
	}
	if err := t.sessionManager.RouteToTEEK(sessionID, env); err != nil {
		t.logger.Error("Failed to send error message to TEE_K via session manager",
			zap.String("session_id", sessionID),
			zap.Error(err))
	}
}

func (t *TEET) verifyCommitmentsIfReady(sessionID string) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session: %v", err)
	}
	if session.RedactionState == nil {
		return fmt.Errorf("critical security failure: no redaction state available for commitment verification in session %s", sessionID)
	}
	hasStreams := len(session.RedactionState.RedactionStreams) > 0 && len(session.RedactionState.CommitmentKeys) > 0
	hasCommitments := len(session.RedactionState.ExpectedCommitments) > 0
	if !hasStreams {
		t.logger.InfoIf("Redaction streams not yet available for commitment verification, deferring",
			zap.String("session_id", sessionID))
		return nil
	}
	if !hasCommitments {
		t.logger.InfoIf("Expected commitments not yet available for verification, deferring",
			zap.String("session_id", sessionID))
		return nil
	}
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

func (t *TEET) verifyCommitments(streams, keys, expectedCommitments [][]byte) error {
	if len(streams) != len(keys) {
		return fmt.Errorf("streams and keys length mismatch: %d vs %d", len(streams), len(keys))
	}
	if len(expectedCommitments) != len(streams) {
		return fmt.Errorf("expected commitments length mismatch: expected %d, got %d", len(streams), len(expectedCommitments))
	}
	for i := 0; i < len(streams); i++ {
		h := hmac.New(sha256.New, keys[i])
		h.Write(streams[i])
		computedCommitment := h.Sum(nil)
		t.logger.DebugIf("Computed stream commitment",
			zap.Int("stream_index", i),
			zap.Binary("computed_commitment", computedCommitment),
			zap.Binary("expected_commitment", expectedCommitments[i]))
		if len(computedCommitment) != len(expectedCommitments[i]) {
			return fmt.Errorf("commitment %d length mismatch: computed %d bytes, expected %d bytes",
				i, len(computedCommitment), len(expectedCommitments[i]))
		}
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

func (t *TEET) reconstructFullRequestWithStreams(encryptedRedacted []byte, ranges []shared.RequestRedactionRange, redactionStreams [][]byte) ([]byte, error) {
	reconstructed := make([]byte, len(encryptedRedacted))
	copy(reconstructed, encryptedRedacted)
	t.logger.DebugIf("Starting redaction stream application with provided streams",
		zap.Binary("redacted_preview", encryptedRedacted[:min(64, len(encryptedRedacted))]),
		zap.Int("redaction_ranges", len(ranges)),
		zap.Int("available_streams", len(redactionStreams)))
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
		for j := 0; j < r.Length && r.Start+j < len(reconstructed) && j < len(stream); j++ {
			reconstructed[r.Start+j] ^= stream[j]
		}
	}
	t.logger.DebugIf("Completed redaction stream application",
		zap.Binary("reconstructed_preview", reconstructed[:min(64, len(reconstructed))]),
		zap.Int("total_bytes", len(reconstructed)))
	return reconstructed, nil
}

func (t *TEET) sendErrorToClient(sessionID, errMsg string) {
	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Error{Error: &teeproto.ErrorData{Message: errMsg}},
	}
	if err := t.sessionManager.RouteToClient(sessionID, env); err != nil {
		t.logger.Error("Failed to send error message to client session",
			zap.String("session_id", sessionID),
			zap.Error(err))
	}
}

func isNetworkShutdownError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "broken pipe")
}

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

func (t *TEET) addToTranscriptForSession(sessionID string, packet []byte) {
	t.addToTranscriptForSessionWithType(sessionID, packet, shared.TranscriptPacketTypeTLSRecord)
}

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
	transcriptCopy := make([][]byte, len(session.TranscriptPackets))
	for i, packet := range session.TranscriptPackets {
		packetCopy := make([]byte, len(packet))
		copy(packetCopy, packet)
		transcriptCopy[i] = packetCopy
	}
	return transcriptCopy
}

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
	t.logger.InfoIf("Received finished command from TEE_K",
		zap.String("session_id", msg.SessionID))
	sessionID := msg.SessionID
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
	t.checkFinishedCondition(sessionID)
}

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
		ethAddress := t.signingKeyPair.GetEthAddress()
		tOutput := &teeproto.TOutputPayload{Packets: transcript}
		body, err := proto.Marshal(tOutput)
		if err != nil {
			t.logger.Error("Failed to marshal TOutputPayload",
				zap.String("session_id", sessionID),
				zap.Error(err))
			return
		}
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
		var attestationReport *teeproto.AttestationReport
		var publicKeyForStandalone []byte
		if t.enclaveManager != nil {
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
			publicKeyForStandalone = []byte(ethAddress.String())
			t.logger.InfoIf("Including ETH address in SignedMessage (standalone mode)",
				zap.String("session_id", sessionID),
				zap.String("eth_address", ethAddress.Hex()))
		}
		sm := &teeproto.SignedMessage{BodyType: teeproto.BodyType_BODY_TYPE_T_OUTPUT, Body: body, EthAddress: publicKeyForStandalone, Signature: signature, AttestationReport: attestationReport}
		env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(), Payload: &teeproto.Envelope_SignedMessage{SignedMessage: sm}}
		if err := t.sessionManager.RouteToClient(sessionID, env); err != nil {
			t.logger.Error("Failed to send SignedMessage (T_OUTPUT) to client",
				zap.String("session_id", sessionID),
				zap.Error(err))
			return
		}
		t.logger.InfoIf("Sent SignedMessage (T_OUTPUT) to client",
			zap.String("session_id", sessionID))
	} else {
		t.logger.DebugIf("Waiting for finished from TEE_K",
			zap.String("session_id", sessionID),
			zap.Bool("teek_finished", teekFinished))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
