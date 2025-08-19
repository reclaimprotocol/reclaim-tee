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
			Payload: &teeproto.Envelope_KeyShareRequest{KeyShareRequest: &teeproto.KeyShareRequest{KeyLength: int32(d.KeyLength), IvLength: int32(d.IVLength)}},
		}
	case shared.MsgEncryptedRequest:
		var d shared.EncryptedRequestData
		if err := msg.UnmarshalData(&d); err != nil {
			return fmt.Errorf("failed to unmarshal encrypted request: %v", err)
		}
		// map ranges
		var rr []*teeproto.RequestRedactionRange
		for _, r := range d.RedactionRanges {
			rr = append(rr, &teeproto.RequestRedactionRange{Start: int32(r.Start), Length: int32(r.Length), Type: r.Type})
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
			tags = append(tags, &teeproto.BatchedTagSecrets_TagSecret{TagSecrets: ts.TagSecrets, SeqNum: ts.SeqNum})
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
	return wsConn.WriteMessage(websocket.BinaryMessage, data)
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
	return wsConn.WriteMessage(websocket.BinaryMessage, data)
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
			Start:  int32(r.Start),
			Length: int32(r.Length),
			Type:   r.Type,
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
