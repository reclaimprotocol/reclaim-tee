package main

import (
	"time"

	teeproto "tee-mpc/proto"
	"tee-mpc/shared"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// addToTranscriptForSessionWithType safely adds data with explicit type to the session's transcript
func (t *TEET) addToTranscriptForSessionWithType(sessionID string, data []byte, dataType string) {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.logger.Error("Failed to get session for transcript",
			zap.String("session_id", sessionID),
			zap.Error(err))
		return
	}
	session.TranscriptMutex.Lock()
	defer session.TranscriptMutex.Unlock()
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	session.TranscriptData = append(session.TranscriptData, dataCopy)
	session.TranscriptDataTypes = append(session.TranscriptDataTypes, dataType)
	t.logger.DebugIf("Added data to session transcript",
		zap.String("session_id", sessionID),
		zap.Int("data_bytes", len(data)),
		zap.String("data_type", dataType),
		zap.Int("total_data", len(session.TranscriptData)))
}

// addToTranscriptForSession safely adds data to the session's transcript collection
func (t *TEET) addToTranscriptForSession(sessionID string, data []byte) {
	t.addToTranscriptForSessionWithType(sessionID, data, shared.TranscriptDataTypeTLSRecord)
}

// Transcript handling simplified - using structured data in SignedMessage

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

		// Get TEE_T session state for consolidated ciphertext
		teetState, err := t.sessionManager.GetTEETSessionState(sessionID)
		if err != nil {
			t.logger.Error("Failed to get TEE_T session state for transcript signing",
				zap.String("session_id", sessionID), zap.Error(err))
			return
		}

		if len(teetState.ConsolidatedResponseCiphertext) == 0 {
			t.logger.WarnIf("No consolidated response ciphertext to sign for session",
				zap.String("session_id", sessionID))
			return
		}
		if t.signingKeyPair == nil {
			t.logger.Error("No signing key pair available for transcript signing",
				zap.String("session_id", sessionID))
			return
		}
		ethAddress := t.signingKeyPair.GetEthAddress()

		// teetState already obtained above for consolidated ciphertext check

		timestampMs := time.Now().UnixMilli()
		tOutput := &teeproto.TOutputPayload{
			ConsolidatedResponseCiphertext: teetState.ConsolidatedResponseCiphertext, // NEW: Consolidated response ciphertext
			RequestProofStreams:            teetState.RequestProofStreams,            // ✅ TEE_T signs R_SP streams
			TimestampMs:                    uint64(timestampMs),                      // Include signed timestamp
		}

		t.logger.InfoIf("Including consolidated response ciphertext and R_SP streams in TEE_T signature",
			zap.String("session_id", sessionID),
			zap.Int("consolidated_response_ciphertext_bytes", len(teetState.ConsolidatedResponseCiphertext)),
			zap.Int("proof_streams_count", len(teetState.RequestProofStreams)))

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
			zap.Int("consolidated_response_ciphertext_bytes", len(teetState.ConsolidatedResponseCiphertext)),
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
		// Create signed message (timestamp is now inside signed body)
		sm := &teeproto.SignedMessage{
			BodyType:          teeproto.BodyType_BODY_TYPE_T_OUTPUT,
			Body:              body,
			EthAddress:        publicKeyForStandalone,
			Signature:         signature,
			AttestationReport: attestationReport,
		}
		env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: timestampMs, Payload: &teeproto.Envelope_SignedMessage{SignedMessage: sm}}
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
