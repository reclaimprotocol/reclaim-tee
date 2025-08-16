package main

import (
	"time"

	teeproto "tee-mpc/proto"
	"tee-mpc/shared"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// addToTranscriptForSessionWithType safely adds a packet with explicit type to the session's transcript
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

// addToTranscriptForSession safely adds a packet to the session's transcript collection
func (t *TEET) addToTranscriptForSession(sessionID string, packet []byte) {
	t.addToTranscriptForSessionWithType(sessionID, packet, shared.TranscriptPacketTypeTLSRecord)
}

// getTranscriptForSession safely returns a copy of the session's transcript
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

// handleFinishedFromTEEKSession handles finished message from TEE_K and triggers transcript signing
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

// checkFinishedCondition checks if conditions are met for transcript signing and sends signed transcript
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
