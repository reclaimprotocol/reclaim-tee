package main

import (
	"fmt"
	"time"

	teeproto "tee-mpc/proto"
	"tee-mpc/shared"

	"go.uber.org/zap"
)

// handleBatchedResponseLengthsSession handles batched response lengths from TEE_T
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
			ResponseLengthBySeq:       make(map[uint64]int),
			ExplicitIVBySeq:           make(map[uint64][]byte),
		}
	}

	// Process each length in the batch and generate tag secrets
	var tagSecrets []struct {
		TagSecrets []byte `json:"tag_secrets"`
		SeqNum     uint64 `json:"seq_num"`
	}

	session.ResponseState.ResponsesMutex.Lock()
	for _, lengthData := range batchedLengths.Lengths {
		// Store response lengths in session state for later decryption stream generation
		session.ResponseState.ResponseLengthBySeq[lengthData.SeqNum] = lengthData.Length

		// Store explicit IV for TLS 1.2 AES-GCM decryption stream generation
		if lengthData.ExplicitIV != nil {
			session.ResponseState.ExplicitIVBySeq[lengthData.SeqNum] = lengthData.ExplicitIV
		}

		// Generate tag secrets for this response
		tagSecretsBytes, err := t.generateResponseTagSecretsWithSession(
			sessionID,
			lengthData.Length,
			lengthData.SeqNum,
			lengthData.RecordHeader,
			lengthData.ExplicitIV,
		)
		if err != nil {
			t.logger.WithSession(sessionID).Error("Failed to generate tag secrets for sequence in batch",
				zap.Uint64("seq_num", lengthData.SeqNum), zap.Error(err))
			continue
		}

		tagSecrets = append(tagSecrets, struct {
			TagSecrets []byte `json:"tag_secrets"`
			SeqNum     uint64 `json:"seq_num"`
		}{
			TagSecrets: tagSecretsBytes,
			SeqNum:     lengthData.SeqNum,
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
			TagSecrets: ts.TagSecrets,
			SeqNum:     ts.SeqNum,
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

// handleBatchedTagVerificationsSession handles batched tag verifications from TEE_T
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
		for seqNum, responseLength := range responseState.ResponseLengthBySeq {
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
			responseLength, exists := responseState.ResponseLengthBySeq[verification.SeqNum]
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

// checkAndSendSignatureIfReady checks if all processing is complete and sends signature if ready
func (t *TEEK) checkAndSendSignatureIfReady(sessionID string) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("session %s not found: %v", sessionID, err)
	}

	// Check if all required processing is complete and atomically set signature flag
	session.StreamsMutex.Lock()

	session.TranscriptMutex.Lock()
	transcriptReady := len(session.TranscriptData) > 0
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
