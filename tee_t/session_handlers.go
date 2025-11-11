package main

import (
	"crypto/rand"
	"fmt"
	"sort"
	"time"

	"tee-mpc/minitls"
	teeproto "tee-mpc/proto"
	"tee-mpc/shared"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// handleRedactionStreams handles redaction streams from client
func (t *TEET) handleRedactionStreams(sessionID string, msg *shared.Message) error {
	if sessionID == "" {
		err := fmt.Errorf("redaction streams message missing session ID")
		t.terminateSessionWithError("", shared.ReasonMissingSessionID, err, "Redaction streams missing session ID")
		return err
	}

	t.logger.Info("Handling redaction streams for session", zap.String("session_id", sessionID))

	var streamsData shared.RedactionStreamsData
	if err := msg.UnmarshalData(&streamsData); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to unmarshal redaction streams")
		return err
	}

	t.logger.Info("Received redaction streams for session",
		zap.String("session_id", sessionID),
		zap.Int("streams_count", len(streamsData.Streams)),
		zap.Int("keys_count", len(streamsData.CommitmentKeys)))

	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionNotFound, err, "Failed to get session")
		return err
	}

	if session.RedactionState == nil {
		session.RedactionState = &shared.RedactionSessionState{}
	}

	session.RedactionState.RedactionStreams = streamsData.Streams
	session.RedactionState.CommitmentKeys = streamsData.CommitmentKeys

	t.logger.Info("Redaction streams stored for session", zap.String("session_id", sessionID))

	// Capture R_SP (sensitive_proof) streams for cryptographic signing by TEE_T
	teetState, teetErr := t.getTEETSessionState(sessionID)
	if teetErr != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionStateCorrupted, teetErr, "Failed to get TEE_T session state for R_SP capture")
		return teetErr
	}

	teetState.RequestProofStreams = [][]byte{} // Reset proof streams

	// Extract R_SP streams based on redaction ranges (if available)
	if len(streamsData.Ranges) > 0 {
		for i, r := range streamsData.Ranges {
			if r.Type == "sensitive_proof" && i < len(streamsData.Streams) {
				teetState.RequestProofStreams = append(teetState.RequestProofStreams, streamsData.Streams[i])
				t.logger.Info("Captured R_SP stream for TEE_T signing",
					zap.String("session_id", sessionID),
					zap.Int("stream_index", i),
					zap.Int("stream_length", len(streamsData.Streams[i])))
			}
		}
	}

	t.logger.Info("R_SP stream capture completed",
		zap.String("session_id", sessionID),
		zap.Int("proof_streams_count", len(teetState.RequestProofStreams)))

	if err := t.verifyCommitmentsIfReady(sessionID); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonCryptoCommitmentFailed, err, "Commitment verification failed")
		return err
	}

	teetState2, err := t.getTEETSessionState(sessionID)
	if err == nil && teetState2.PendingEncryptedRequest != nil {
		t.logger.Info("Processing pending encrypted request with newly received streams", zap.String("session_id", sessionID))
		if procErr := t.processEncryptedRequestWithStreams(sessionID, teetState2.PendingEncryptedRequest); procErr != nil {
			return procErr
		}
		teetState2.PendingEncryptedRequest = nil
	}

	t.logger.Debug("handleRedactionStreams completed for session",
		zap.String("session_id", sessionID))

	return nil
}

// handleBatchedEncryptedResponses handles batched encrypted responses from client
func (t *TEET) handleBatchedEncryptedResponses(sessionID string, msg *shared.Message) error {
	t.logger.Info("Handling encrypted responses for session", zap.String("session_id", sessionID))

	var batchedResponses shared.BatchedEncryptedResponseData
	if err := msg.UnmarshalData(&batchedResponses); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to unmarshal batched encrypted responses")
		return err
	}

	t.logger.Info("Received batch of encrypted responses",
		zap.String("session_id", sessionID),
		zap.Int("total_count", batchedResponses.TotalCount))

	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionNotFound, err, "Failed to get session")
		return err
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

	// Sort responses by sequence number to ensure deterministic transcript order
	sortedResponses := make([]shared.EncryptedResponseData, len(batchedResponses.Responses))
	copy(sortedResponses, batchedResponses.Responses)
	sort.Slice(sortedResponses, func(i, j int) bool {
		return sortedResponses[i].SeqNum < sortedResponses[j].SeqNum
	})

	for _, encryptedResp := range sortedResponses {
		session.ResponseState.PendingEncryptedResponses[encryptedResp.SeqNum] = &encryptedResp
		if err := t.addSingleResponseToTranscript(sessionID, &encryptedResp); err != nil {
			session.ResponseState.ResponsesMutex.Unlock()
			return err
		}
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

	t.logger.Info("BATCHING: Processed encrypted responses",
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
		t.terminateSessionWithError(sessionID, shared.ReasonNetworkFailure, err, "Failed to send batched lengths to TEE_K")
		return err
	}

	t.logger.Info("BATCHING: Successfully sent batch of response lengths to TEE_K",
		zap.String("session_id", sessionID),
		zap.Int("total_count", len(responseLengths)))

	return nil
}

// handleSessionCreation handles session creation from TEE_K
func (t *TEET) handleSessionCreation(msg *shared.Message) error {
	var sessionData map[string]interface{}
	if err := msg.UnmarshalData(&sessionData); err != nil {
		t.terminateSessionWithError("", shared.ReasonMessageParsingFailed, err, "Failed to unmarshal session creation data")
		return err
	}
	sessionID, ok := sessionData["session_id"].(string)
	if !ok {
		err := fmt.Errorf("invalid session_id in session creation message")
		t.terminateSessionWithError("", shared.ReasonMessageParsingFailed, err, "Invalid session_id in session creation")
		return err
	}
	if err := t.sessionManager.RegisterSession(sessionID); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionManagerFailure, err, "Failed to register session")
		return err
	}
	teetState := &TEETSessionState{TEETClientConn: nil}
	t.sessionManager.SetTEETSessionState(sessionID, teetState)
	t.logger.Info("Created TEE_T session state for registered session", zap.String("session_id", sessionID))
	t.logger.Info("Registered session from TEE_K", zap.String("session_id", sessionID))
	return nil
}

// handleKeyShareRequestSession handles key share request from TEE_K
func (t *TEET) handleKeyShareRequestSession(msg *shared.Message) error {
	sessionID := msg.SessionID
	if sessionID == "" {
		err := fmt.Errorf("key share request missing session ID")
		t.terminateSessionWithError("", shared.ReasonMissingSessionID, err, "Key share request missing session ID")
		return err
	}
	t.logger.Info("Handling key share request for session", zap.String("session_id", sessionID))
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionNotFound, err, "Failed to get session")
		return err
	}
	var keyReq shared.KeyShareRequestData
	if err := msg.UnmarshalData(&keyReq); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to unmarshal key share request")
		return err
	}
	keyShare := make([]byte, keyReq.KeyLength)
	if _, err := rand.Read(keyShare); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonCryptoKeyGenerationFailed, err, "Failed to generate key share")
		return err
	}
	teetState, err := t.getTEETSessionState(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionStateCorrupted, err, "Failed to get TEE_T session state")
		return err
	}
	teetState.KeyShare = keyShare
	t.logger.Info("Generated key share for session",
		zap.String("session_id", sessionID),
		zap.Int("key_length", len(keyShare)))
	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_KeyShareResponse{KeyShareResponse: &teeproto.KeyShareResponse{KeyShare: keyShare, Success: true}},
	}
	data, err := proto.Marshal(env)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to marshal key share response")
		return err
	}
	wsConn := session.TEEKConn.(*shared.WSConnection)
	if err := wsConn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonNetworkFailure, err, "Failed to send key share response")
		return err
	}
	return nil
}

// handleEncryptedRequest handles encrypted request from TEE_K
func (t *TEET) handleEncryptedRequest(msg *shared.Message) error {
	sessionID := msg.SessionID
	if sessionID == "" {
		err := fmt.Errorf("encrypted request missing session ID")
		t.terminateSessionWithError("", shared.ReasonMissingSessionID, err, "Encrypted request missing session ID")
		return err
	}
	t.logger.Info("Handling encrypted request for session", zap.String("session_id", sessionID))
	var encReq shared.EncryptedRequestData
	if err := msg.UnmarshalData(&encReq); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to unmarshal encrypted request")
		return err
	}
	t.logger.Info("Computing tag for encrypted request",
		zap.String("session_id", sessionID),
		zap.Int("ciphertext_bytes", len(encReq.EncryptedData)),
		zap.Uint64("seq_num", encReq.SeqNum),
		zap.Int("redaction_ranges", len(encReq.RedactionRanges)))
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionNotFound, err, "Failed to get session")
		return err
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
	t.logger.Info("Stored expected commitments from TEE_K",
		zap.String("session_id", sessionID),
		zap.Int("commitment_count", len(encReq.Commitments)))
	if err := t.verifyCommitmentsIfReady(sessionID); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonCryptoCommitmentFailed, err, "Commitment verification failed")
		return err
	}
	if len(session.RedactionState.RedactionStreams) == 0 {
		teetState, err := t.getTEETSessionState(sessionID)
		if err != nil {
			t.terminateSessionWithError(sessionID, shared.ReasonSessionStateCorrupted, err, "Failed to get TEE_T session state")
			return err
		}
		teetState.PendingEncryptedRequest = &encReq
		t.logger.Info("Storing encrypted request for session, waiting for redaction streams...",
			zap.String("session_id", sessionID))
		return nil
	}
	return t.processEncryptedRequestWithStreams(sessionID, &encReq)
}

// handleBatchedTagSecrets handles batched tag secrets from TEE_K
func (t *TEET) handleBatchedTagSecrets(msg *shared.Message) error {
	sessionID := msg.SessionID
	if sessionID == "" {
		err := fmt.Errorf("batched tag secrets missing session ID")
		t.terminateSessionWithError("", shared.ReasonMissingSessionID, err, "Batched tag secrets missing session ID")
		return err
	}
	t.logger.Info("Handling batched tag secrets for session",
		zap.String("session_id", sessionID))
	var batchedTagSecrets shared.BatchedTagSecretsData
	if err := msg.UnmarshalData(&batchedTagSecrets); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to unmarshal batched tag secrets")
		return err
	}
	t.logger.Info("Received batch of tag secrets",
		zap.String("session_id", sessionID),
		zap.Int("batch_count", batchedTagSecrets.TotalCount))
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionNotFound, err, "Failed to get session")
		return err
	}
	if session.ResponseState == nil {
		err := fmt.Errorf("no response state for session")
		t.terminateSessionWithError(sessionID, shared.ReasonSessionStateCorrupted, err, "No response state for session")
		return err
	}
	var verifications []shared.ResponseTagVerificationData
	allSuccessful := true
	totalCount := len(batchedTagSecrets.TagSecrets)
	session.ResponseState.ResponsesMutex.Lock()

	// Sort tag secrets by sequence number to ensure deterministic processing order
	type tagSecretWithSeq struct {
		TagSecrets []byte `json:"tag_secrets"`
		SeqNum     uint64 `json:"seq_num"`
	}
	var sortedTagSecrets []tagSecretWithSeq
	for _, ts := range batchedTagSecrets.TagSecrets {
		sortedTagSecrets = append(sortedTagSecrets, tagSecretWithSeq{
			TagSecrets: ts.TagSecrets,
			SeqNum:     ts.SeqNum,
		})
	}
	// Sort by sequence number for deterministic order
	sort.Slice(sortedTagSecrets, func(i, j int) bool {
		return sortedTagSecrets[i].SeqNum < sortedTagSecrets[j].SeqNum
	})

	for _, tagSecretsData := range sortedTagSecrets {
		encryptedResp := session.ResponseState.PendingEncryptedResponses[tagSecretsData.SeqNum]
		if encryptedResp == nil {
			session.ResponseState.ResponsesMutex.Unlock()
			err := fmt.Errorf("critical security failure: missing encrypted response for seq %d", tagSecretsData.SeqNum)
			t.terminateSessionWithError(sessionID, shared.ReasonSessionStateCorrupted, err, "Missing encrypted response in batch")
			return err
		}
		// Convert to the expected struct type for verifyTagForResponse
		tagSecretStruct := &struct {
			TagSecrets []byte `json:"tag_secrets"`
			SeqNum     uint64 `json:"seq_num"`
		}{
			TagSecrets: tagSecretsData.TagSecrets,
			SeqNum:     tagSecretsData.SeqNum,
		}
		verificationResult := t.verifyTagForResponse(sessionID, encryptedResp, tagSecretStruct)
		if !verificationResult.Success {
			allSuccessful = false
			verifications = append(verifications, verificationResult)
			break // Exit loop to send results - this is OK
		}
		t.logger.Info("Tag verification completed",
			zap.String("session_id", sessionID),
			zap.Uint64("seq_num", tagSecretsData.SeqNum),
			zap.Bool("success", verificationResult.Success))
	}
	session.ResponseState.ResponsesMutex.Unlock()
	t.logger.Info("Completed batch tag verification",
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
	if err = t.sessionManager.RouteToTEEK(sessionID, env); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonNetworkFailure, err, "Failed to send batch verification results to TEE_K")
		return err
	}
	t.logger.Info("Successfully sent batch verification results",
		zap.String("session_id", sessionID))
	if !allSuccessful {
		err := fmt.Errorf("tag verification failed for batch")
		t.terminateSessionWithError(sessionID, shared.ReasonCryptoTagVerificationFailed, err, "Tag verification failed")
		return err
	}
	return nil
}

// processEncryptedRequestWithStreams processes encrypted request with available redaction streams
func (t *TEET) processEncryptedRequestWithStreams(sessionID string, encReq *shared.EncryptedRequestData) error {
	t.logger.Info("Processing encrypted request with available redaction streams for session",
		zap.String("session_id", sessionID))
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionNotFound, err, "Failed to get session")
		return err
	}
	teetState, err := t.sessionManager.GetTEETSessionState(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionStateCorrupted, err, "Failed to get TEE_T session state")
		return err
	}
	teetState.CipherSuite = encReq.CipherSuite
	t.logger.Info("Stored CipherSuite in session state",
		zap.String("session_id", sessionID),
		zap.Uint16("cipher_suite", encReq.CipherSuite))
	if session.RedactionState == nil {
		err := fmt.Errorf("no redaction state available for session")
		t.terminateSessionWithError(sessionID, shared.ReasonSessionStateCorrupted, err, "No redaction state available")
		return err
	}
	reconstructedData, err := t.reconstructFullRequestWithStreams(encReq.EncryptedData, encReq.RedactionRanges, session.RedactionState.RedactionStreams)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonCryptoTagComputationFailed, err, "Failed to reconstruct full request")
		return err
	}
	t.logger.Info("Successfully reconstructed original request data",
		zap.String("session_id", sessionID))
	var additionalData []byte
	// Check if TLS 1.3 cipher suite
	cipherInfo := minitls.GetCipherSuiteInfo(uint16(encReq.CipherSuite))
	if cipherInfo != nil && cipherInfo.IsTLS13 {
		tagSize := 16
		recordLength := len(reconstructedData) + tagSize
		additionalData = minitls.CreateAdditionalDataTLS13(recordLength)
	} else {
		plaintextLength := len(reconstructedData)
		additionalData = minitls.CreateAdditionalDataTLS12(encReq.SeqNum, plaintextLength)
	}
	authTag, err := minitls.ComputeTagFromSecrets(reconstructedData, encReq.TagSecrets, encReq.CipherSuite, additionalData)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonCryptoTagComputationFailed, err, "Failed to compute authentication tag")
		return err
	}
	t.logger.Info("Computed split AEAD tag",
		zap.String("session_id", sessionID),
		zap.Binary("tag", authTag),
		zap.Int("data_length", len(reconstructedData)))
	isTLS12AESGCMCipher := minitls.IsTLS12AESGCMCipherSuite(encReq.CipherSuite)
	var payload []byte
	if isTLS12AESGCMCipher {
		payload = minitls.CreateTLS12AEADPayload(encReq.SeqNum, reconstructedData, authTag)
		t.logger.Debug("Constructed TLS 1.2 AES-GCM record with explicit IV",
			zap.String("session_id", sessionID),
			zap.Binary("explicit_iv", payload[:8]))
	} else {
		payload = minitls.CreateTLS13AEADPayload(reconstructedData, authTag)
	}
	tlsRecord := minitls.CreateApplicationDataRecord(payload)
	// for verification against TEE_K's redacted streams
	t.logger.Info("Constructed TLS request record (not added to transcript for verification)",
		zap.String("session_id", sessionID),
		zap.Int("record_length", len(tlsRecord)))
	t.logger.Info("Sending reconstructed encrypted data to client session",
		zap.String("session_id", sessionID),
		zap.Int("data_length", len(reconstructedData)),
		zap.Binary("first_32_bytes", reconstructedData[:min(32, len(reconstructedData))]))
	envResp := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_EncryptedData{EncryptedData: &teeproto.EncryptedDataResponse{EncryptedData: reconstructedData, AuthTag: authTag, Success: true}},
	}
	if err := t.sessionManager.RouteToClient(sessionID, envResp); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonNetworkFailure, err, "Failed to send encrypted data to client")
		return err
	}
	return nil
}

// addSingleResponseToTranscript adds a single response to the session transcript
func (t *TEET) addSingleResponseToTranscript(sessionID string, encryptedResp *shared.EncryptedResponseData) error {
	teetState, err := t.sessionManager.GetTEETSessionState(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionStateCorrupted, err, "Failed to get TEE_T session state")
		return err
	}
	isTLS12AESGCMCipher := minitls.IsTLS12AESGCMCipherSuite(teetState.CipherSuite)
	var payload []byte
	if isTLS12AESGCMCipher && encryptedResp.ExplicitIV != nil && len(encryptedResp.ExplicitIV) == 8 {
		payload = make([]byte, 8+len(encryptedResp.EncryptedData)+len(encryptedResp.Tag))
		copy(payload[0:8], encryptedResp.ExplicitIV)
		copy(payload[8:8+len(encryptedResp.EncryptedData)], encryptedResp.EncryptedData)
		copy(payload[8+len(encryptedResp.EncryptedData):], encryptedResp.Tag)
		t.logger.Debug("Added explicit IV to TLS 1.2 AES-GCM response transcript record",
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
	if err := t.addToTranscript(sessionID, record, shared.TranscriptDataTypeTLSRecord); err != nil {
		return err
	}
	t.logger.Debug("Added response packet to session transcript",
		zap.String("session_id", sessionID),
		zap.Uint64("seq_num", encryptedResp.SeqNum),
		zap.Int("record_length", len(record)))
	return nil
}
