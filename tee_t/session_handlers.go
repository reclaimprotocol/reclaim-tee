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

// handleTEETReadySession handles TEE_T ready message from client
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

// handleRedactionStreamsSession handles redaction streams from client
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

	// Capture R_SP (sensitive_proof) streams for cryptographic signing by TEE_T
	teetState, teetErr := t.getTEETSessionState(sessionID)
	if teetErr != nil {
		t.logger.Error("Failed to get TEE_T session state for R_SP capture", zap.Error(teetErr))
	} else {
		teetState.RequestProofStreams = [][]byte{} // Reset proof streams

		// Extract R_SP streams based on redaction ranges (if available)
		if len(streamsData.Ranges) > 0 {
			for i, r := range streamsData.Ranges {
				if r.Type == "sensitive_proof" && i < len(streamsData.Streams) {
					teetState.RequestProofStreams = append(teetState.RequestProofStreams, streamsData.Streams[i])
					t.logger.InfoIf("Captured R_SP stream for TEE_T signing",
						zap.String("session_id", sessionID),
						zap.Int("stream_index", i),
						zap.Int("stream_length", len(streamsData.Streams[i])))
				}
			}
		}

		t.logger.InfoIf("R_SP stream capture completed",
			zap.String("session_id", sessionID),
			zap.Int("proof_streams_count", len(teetState.RequestProofStreams)))
	}

	if err := t.verifyCommitmentsIfReady(sessionID); err != nil {
		if t.sessionTerminator.CriticalError(sessionID, shared.ReasonCryptoCommitmentFailed, err,
			zap.Int("commitment_count", len(session.RedactionState.ExpectedCommitments))) {
			return
		}
		return
	}

	teetState2, err := t.getTEETSessionState(sessionID)
	if err == nil && teetState2.PendingEncryptedRequest != nil {
		t.logger.InfoIf("Processing pending encrypted request with newly received streams", zap.String("session_id", sessionID))
		if teetState2.TEETConnForPending != nil {
			t.processEncryptedRequestWithStreamsForSession(sessionID, teetState2.PendingEncryptedRequest, teetState2.TEETConnForPending)
		}
		teetState2.PendingEncryptedRequest = nil
		teetState2.TEETConnForPending = nil
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

// handleBatchedEncryptedResponsesSession handles batched encrypted responses from client
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

	// Sort responses by sequence number to ensure deterministic transcript order
	sortedResponses := make([]shared.EncryptedResponseData, len(batchedResponses.Responses))
	copy(sortedResponses, batchedResponses.Responses)
	sort.Slice(sortedResponses, func(i, j int) bool {
		return sortedResponses[i].SeqNum < sortedResponses[j].SeqNum
	})

	for _, encryptedResp := range sortedResponses {
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

// handleSessionCreation handles session creation from TEE_K
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

// handleKeyShareRequestSession handles key share request from TEE_K
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

// handleEncryptedRequestSession handles encrypted request from TEE_K
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

// handleBatchedTagSecretsSession handles batched tag secrets from TEE_K
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
			if t.sessionTerminator.CriticalError(sessionID, shared.ReasonSessionStateCorrupted,
				fmt.Errorf("critical security failure: missing encrypted response for seq %d", tagSecretsData.SeqNum),
				zap.Uint64("seq_num", tagSecretsData.SeqNum)) {
				session.ResponseState.ResponsesMutex.Unlock()
				return
			}
			session.ResponseState.ResponsesMutex.Unlock()
			return
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

// processEncryptedRequestWithStreamsForSession processes encrypted request with available redaction streams
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
	// for verification against TEE_K's redacted streams
	t.logger.InfoIf("Constructed TLS request record (not added to transcript for verification)",
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

// addSingleResponseToTranscript adds a single response to the session transcript
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
