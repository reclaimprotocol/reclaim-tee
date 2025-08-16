package main

import (
	"fmt"
	"time"

	teeproto "tee-mpc/proto"
	"tee-mpc/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// sendMessageToClientSession sends a message to a client session
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

// sendMessageToTEEKForSession sends a message to TEE_K for a specific session
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

// sendErrorToTEEK sends an error message to TEE_K
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

// sendErrorToClient sends an error message to a client
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
