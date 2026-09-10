package main

import (
	"fmt"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"google.golang.org/protobuf/proto"
)

func (s *TEETSessionState) responseCipherSuite() uint16 {
	if suite := s.negotiatedResponseCipher.Load(); suite != 0 {
		return uint16(suite)
	}
	return s.CipherSuite
}
func (s *TEETSessionState) setResponseCipherSuite(suite uint16) error {
	if negotiated := s.negotiatedResponseCipher.Load(); negotiated != 0 {
		if uint16(negotiated) != suite {
			return fmt.Errorf("request cipher differs from negotiated response cipher")
		}
		return nil
	}
	s.CipherSuite = suite
	return nil
}

func (t *TEET) handleResponseModeRequest(identity *teetSessionIdentity, request *teeproto.ResponseModeRequest) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	if request == nil || request.Mode != teeproto.ResponseMode_RESPONSE_MODE_INCREMENTAL_V1 || request.CipherSuite > 65535 || minitls.GetCipherSuiteInfo(uint16(request.CipherSuite)) == nil || minitls.IsTLS12CBCCipherSuite(uint16(request.CipherSuite)) {
		return fmt.Errorf("unsupported response mode or cipher")
	}
	session := identity.session
	state, err := t.sessionManager.stateForSession(session)
	if err != nil {
		return err
	}
	if session.ResponseState == nil {
		return fmt.Errorf("missing response state")
	}
	if state.CBCReadStateReceived.Load() || state.ResponseBatchReceived.Load() {
		return fmt.Errorf("response negotiation after protocol start")
	}
	firstSeq := uint64(1)
	if minitls.IsTLS13CipherSuite(uint16(request.CipherSuite)) {
		firstSeq = 0
	}
	if err := session.ResponseState.Incremental.Configure(session.ID, request.SessionBinding, firstSeq); err != nil {
		return err
	}
	state.negotiatedResponseCipher.Store(request.CipherSuite)
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	return t.routeToTEEKForSession(session, &teeproto.Envelope{SessionId: session.ID, Payload: &teeproto.Envelope_ResponseModeAck{ResponseModeAck: &teeproto.ResponseModeAck{Mode: request.Mode, SessionBinding: request.SessionBinding, Success: true}}})
}

func (t *TEET) handleFinalizeResponse(identity *teetSessionIdentity, request *teeproto.FinalizeResponse) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	session := identity.session
	if session.ResponseState == nil {
		return fmt.Errorf("missing response state")
	}
	if err := session.ResponseState.Incremental.BeginFreeze(request); err != nil {
		return err
	}
	ack := &teeproto.ResponseFrozen{SessionBinding: request.SessionBinding, BatchCount: request.BatchCount, RecordCount: request.RecordCount, PrefixCommitment: request.PrefixCommitment}
	if err := session.ResponseState.Incremental.FinishFreeze(ack); err != nil {
		return err
	}
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	return t.routeToTEEKForSession(session, &teeproto.Envelope{SessionId: session.ID, Payload: &teeproto.Envelope_ResponseFrozen{ResponseFrozen: ack}})
}

func (t *TEET) handleIncrementalEncryptedResponses(identity *teetSessionIdentity, batch shared.BatchedEncryptedResponseData) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	session := identity.session
	response := session.ResponseState
	if response == nil || !response.Incremental.Active() || batch.Metadata == nil || batch.SessionID != session.ID || batch.TotalCount != len(batch.Responses) || batch.TotalCount != int(batch.Metadata.RecordCount) || batch.TotalCount == 0 || batch.TotalCount > shared.MaxIncrementalBatchRecords {
		return fmt.Errorf("invalid incremental encrypted response batch")
	}
	state, err := t.sessionManager.stateForSession(session)
	if err != nil {
		return err
	}
	suite := state.responseCipherSuite()
	tls13 := minitls.IsTLS13CipherSuite(suite)
	gcm := minitls.IsTLS12AESGCMCipherSuite(suite)
	firstSeq := response.Incremental.ExpectedSequence(batch.Metadata.FirstRecord)
	records := make([]shared.EncryptedResponseData, len(batch.Responses))
	var totalBytes uint64
	for i, record := range batch.Responses {
		if len(record.Tag) != 16 {
			return fmt.Errorf("invalid response authentication tag length")
		}
		if err := shared.ValidateIncrementalRecordShape(len(record.EncryptedData), record.RecordHeader, record.ExplicitIV, record.SeqNum, firstSeq+uint64(i), tls13, gcm); err != nil {
			return err
		}
		records[i] = shared.CloneEncryptedResponse(record)
		totalBytes += uint64(5 + len(record.EncryptedData) + 16 + len(record.ExplicitIV))
	}
	computed := proto.Clone(batch.Metadata).(*teeproto.ResponseBatchMetadata)
	if err := response.Incremental.AcceptRecords(computed, records, totalBytes); err != nil {
		return err
	}
	lengths := make([]*teeproto.BatchedResponseLengths_Length, 0, len(records))
	response.ResponsesMutex.Lock()
	for _, record := range records {
		if _, exists := response.PendingEncryptedResponses[record.SeqNum]; exists {
			response.ResponsesMutex.Unlock()
			return fmt.Errorf("duplicate response sequence")
		}
		response.PendingEncryptedResponses[record.SeqNum] = &record
		if err := t.addSingleResponseToTranscript(identity, &record); err != nil {
			response.ResponsesMutex.Unlock()
			return err
		}
		lengths = append(lengths, &teeproto.BatchedResponseLengths_Length{Length: int32(len(record.EncryptedData)), RecordHeader: record.RecordHeader, ExplicitIv: record.ExplicitIV, SeqNum: record.SeqNum})
	}
	response.ResponsesMutex.Unlock()
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	return t.routeToTEEKForSession(session, &teeproto.Envelope{SessionId: session.ID, Payload: &teeproto.Envelope_BatchedResponseLengths{BatchedResponseLengths: &teeproto.BatchedResponseLengths{SessionId: session.ID, Metadata: computed, TotalCount: int32(len(lengths)), Lengths: lengths}}})
}

func (t *TEET) handleIncrementalTagSecrets(identity *teetSessionIdentity, batch shared.BatchedTagSecretsData) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	session := identity.session
	response := session.ResponseState
	if response == nil || batch.Metadata == nil || batch.SessionID != session.ID || batch.TotalCount != len(batch.TagSecrets) || batch.TotalCount != int(batch.Metadata.RecordCount) {
		return fmt.Errorf("invalid incremental tag secrets")
	}
	if err := response.Incremental.ClaimPending(batch.Metadata); err != nil {
		return err
	}
	firstSeq := response.Incremental.ExpectedSequence(batch.Metadata.FirstRecord)
	// Validate the entire batch before authentication appends any ciphertext.
	for i, secret := range batch.TagSecrets {
		if secret.SeqNum != firstSeq+uint64(i) {
			return fmt.Errorf("incremental tag secret sequence mismatch")
		}
	}
	verifications := make([]*teeproto.BatchedTagVerifications_Verification, 0, len(batch.TagSecrets))
	response.ResponsesMutex.Lock()
	for _, secret := range batch.TagSecrets {
		record := response.PendingEncryptedResponses[secret.SeqNum]
		if record == nil {
			response.ResponsesMutex.Unlock()
			return fmt.Errorf("uncommitted response record")
		}
		result := t.verifyTagForResponse(identity, record, &struct {
			TagSecrets []byte `json:"tag_secrets"`
			SeqNum     uint64 `json:"seq_num"`
		}{TagSecrets: secret.TagSecrets, SeqNum: secret.SeqNum})
		if !result.Success {
			response.ResponsesMutex.Unlock()
			return fmt.Errorf("incremental response tag authentication failed")
		}
		verifications = append(verifications, &teeproto.BatchedTagVerifications_Verification{SeqNum: secret.SeqNum, Success: true})
	}
	response.ResponsesMutex.Unlock()
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	if err := response.Incremental.Complete(batch.Metadata); err != nil {
		return err
	}
	return t.routeToTEEKForSession(session, &teeproto.Envelope{SessionId: session.ID, Payload: &teeproto.Envelope_BatchedTagVerifications{BatchedTagVerifications: &teeproto.BatchedTagVerifications{SessionId: session.ID, Metadata: proto.Clone(batch.Metadata).(*teeproto.ResponseBatchMetadata), TotalCount: int32(len(verifications)), AllSuccessful: true, Verifications: verifications}}})
}
