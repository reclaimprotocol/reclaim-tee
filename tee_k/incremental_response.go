package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"google.golang.org/protobuf/proto"
)

func (t *TEEK) negotiateResponseMode(session *shared.Session, state *TEEKSessionState) (teeproto.ResponseMode, []byte, error) {
	legacy := teeproto.ResponseMode_RESPONSE_MODE_LEGACY_EOF
	requested := session.ConnectionData.RequestedResponseMode
	if requested != legacy && requested != teeproto.ResponseMode_RESPONSE_MODE_INCREMENTAL_V1 {
		return legacy, nil, fmt.Errorf("unsupported response mode")
	}
	if requested == legacy || minitls.IsTLS12CBCCipherSuite(state.CipherSuite) {
		return legacy, nil, nil
	}
	identity, err := t.connManager.identityForSession(session)
	if err != nil {
		return legacy, nil, err
	}
	if identity.sessionConn == nil || !identity.sessionConn.supportsIncrementalResponses {
		return legacy, nil, nil
	}
	binding := make([]byte, 32)
	if _, err := rand.Read(binding); err != nil {
		return legacy, nil, err
	}
	initialSeq := uint64(1)
	if minitls.IsTLS13CipherSuite(state.CipherSuite) {
		initialSeq = 0
	}
	if err := session.ResponseState.Incremental.Configure(session.ID, binding, initialSeq); err != nil {
		return legacy, nil, err
	}
	state.responseModeMu.Lock()
	state.responseModeAck = make(chan error, 1)
	ack := state.responseModeAck
	state.responseModeMu.Unlock()
	env := &teeproto.Envelope{SessionId: session.ID, Payload: &teeproto.Envelope_ResponseModeRequest{ResponseModeRequest: &teeproto.ResponseModeRequest{Mode: requested, SessionBinding: binding, CipherSuite: uint32(state.CipherSuite)}}}
	if err := t.connManager.SendOnExactSession(identity, env); err != nil {
		return legacy, nil, err
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case err := <-ack:
		if err != nil {
			return legacy, nil, err
		}
		if err := identity.ensureCurrent(); err != nil {
			return legacy, nil, err
		}
		return requested, bytes.Clone(binding), nil
	case <-session.Context.Done():
		return legacy, nil, fmt.Errorf("response negotiation canceled: %w", session.Context.Err())
	case <-timer.C:
		return legacy, nil, fmt.Errorf("response mode acknowledgment timed out")
	}
}

func (t *TEEK) handleResponseModeAck(identity *teekSessionIdentity, ack *teeproto.ResponseModeAck) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	state, err := t.sessionManager.stateForSession(identity.session)
	if err != nil {
		return err
	}
	state.responseModeMu.Lock()
	defer state.responseModeMu.Unlock()
	if state.responseModeAck == nil || state.responseModeAcked {
		return fmt.Errorf("unexpected response mode acknowledgment")
	}
	state.responseModeAcked = true
	expected := identity.session.ResponseState.Incremental.Snapshot()
	if ack == nil || !ack.Success || ack.Mode != teeproto.ResponseMode_RESPONSE_MODE_INCREMENTAL_V1 || !bytes.Equal(ack.SessionBinding, expected.SessionBinding) {
		err = fmt.Errorf("response mode acknowledgment mismatch")
	}
	state.responseModeAck <- err
	return err
}

func (t *TEEK) handleFinalizeResponse(sessionID string, request *teeproto.FinalizeResponse) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return err
	}
	identity, err := t.connManager.identityForSession(session)
	if err != nil {
		return err
	}
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	if session.ResponseState == nil {
		return fmt.Errorf("missing response transcript")
	}
	if err := session.ResponseState.Incremental.BeginFreeze(request); err != nil {
		return err
	}
	return t.connManager.SendOnExactSession(identity, &teeproto.Envelope{SessionId: sessionID, Payload: &teeproto.Envelope_FinalizeResponse{FinalizeResponse: proto.Clone(request).(*teeproto.FinalizeResponse)}})
}

func (t *TEEK) handleResponseFrozen(identity *teekSessionIdentity, ack *teeproto.ResponseFrozen) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	session := identity.session
	if session.ResponseState == nil {
		return fmt.Errorf("missing response transcript")
	}
	if err := session.ResponseState.Incremental.FinishFreeze(ack); err != nil {
		return err
	}
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	return t.routeToClientForSession(session, &teeproto.Envelope{SessionId: session.ID, Payload: &teeproto.Envelope_ResponseFrozen{ResponseFrozen: proto.Clone(ack).(*teeproto.ResponseFrozen)}})
}

func (t *TEEK) handleIncrementalResponseLengths(identity *teekSessionIdentity, batch shared.BatchedResponseLengthData) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	session := identity.session
	response := session.ResponseState
	if response == nil || !response.Incremental.Active() || batch.Metadata == nil || batch.SessionID != session.ID || batch.TotalCount != len(batch.Lengths) || batch.TotalCount != int(batch.Metadata.RecordCount) {
		return fmt.Errorf("invalid incremental response lengths")
	}
	state, err := t.sessionManager.stateForSession(session)
	if err != nil {
		return err
	}
	if !state.responseCaptureReady.Load() {
		return fmt.Errorf("incremental response capture barrier not acknowledged")
	}
	tls13 := minitls.IsTLS13CipherSuite(state.CipherSuite)
	gcm := minitls.IsTLS12AESGCMCipherSuite(state.CipherSuite)
	firstSeq := response.Incremental.ExpectedSequence(batch.Metadata.FirstRecord)
	var totalBytes uint64
	for i, item := range batch.Lengths {
		if err := shared.ValidateIncrementalRecordShape(item.Length, item.RecordHeader, item.ExplicitIV, item.SeqNum, firstSeq+uint64(i), tls13, gcm); err != nil {
			return err
		}
		totalBytes += uint64(5 + item.Length + 16 + len(item.ExplicitIV))
	}
	if err := response.Incremental.Accept(batch.Metadata, totalBytes); err != nil {
		return err
	}
	secrets := make([]*teeproto.BatchedTagSecrets_TagSecret, 0, len(batch.Lengths))
	response.ResponsesMutex.Lock()
	for _, item := range batch.Lengths {
		if _, exists := response.ResponseLengthBySeq[item.SeqNum]; exists {
			response.ResponsesMutex.Unlock()
			return fmt.Errorf("duplicate response sequence")
		}
		nonceSeq := item.SeqNum
		if tls13 {
			nonceSeq = state.NextResponseTagSeq()
		}
		secret, nonce, err := t.generateResponseTagSecrets(state, item.Length, nonceSeq, item.RecordHeader, item.ExplicitIV)
		if err != nil {
			response.ResponsesMutex.Unlock()
			return err
		}
		response.ResponseLengthBySeq[item.SeqNum] = item.Length
		if response.ExplicitIVBySeq == nil {
			response.ExplicitIVBySeq = make(map[uint64][]byte)
		}
		response.ExplicitIVBySeq[item.SeqNum] = bytes.Clone(item.ExplicitIV)
		if response.NonceBySeq == nil {
			response.NonceBySeq = make(map[uint64][]byte)
		}
		response.NonceBySeq[item.SeqNum] = bytes.Clone(nonce)
		secrets = append(secrets, &teeproto.BatchedTagSecrets_TagSecret{SeqNum: item.SeqNum, TagSecrets: secret})
	}
	response.ResponsesMutex.Unlock()
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	return t.connManager.SendOnExactSession(identity, &teeproto.Envelope{SessionId: session.ID, Payload: &teeproto.Envelope_BatchedTagSecrets{BatchedTagSecrets: &teeproto.BatchedTagSecrets{SessionId: session.ID, TotalCount: int32(len(secrets)), Metadata: batch.Metadata, TagSecrets: secrets}}})
}

func (t *TEEK) handleIncrementalTagVerifications(identity *teekSessionIdentity, batch shared.BatchedTagVerificationData) error {
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	session := identity.session
	response := session.ResponseState
	if response == nil || batch.Metadata == nil || batch.SessionID != session.ID || !batch.AllSuccessful || batch.TotalCount != int(batch.Metadata.RecordCount) || len(batch.Verifications) != batch.TotalCount {
		return fmt.Errorf("invalid incremental tag verification")
	}
	if err := response.Incremental.ClaimPending(batch.Metadata); err != nil {
		return err
	}
	firstSeq := response.Incremental.ExpectedSequence(batch.Metadata.FirstRecord)
	for i, v := range batch.Verifications {
		if !v.Success || v.SeqNum != firstSeq+uint64(i) {
			return fmt.Errorf("incomplete incremental authentication")
		}
	}
	streams := make([]*teeproto.ResponseDecryptionStreamData, 0, batch.TotalCount)
	for _, v := range batch.Verifications {
		response.ResponsesMutex.Lock()
		length, ok := response.ResponseLengthBySeq[v.SeqNum]
		response.ResponsesMutex.Unlock()
		if !ok {
			return fmt.Errorf("response sequence not committed")
		}
		stream, err := t.generateSingleDecryptionStreamForIdentity(identity, length, v.SeqNum)
		if err != nil {
			return err
		}
		streams = append(streams, &teeproto.ResponseDecryptionStreamData{SeqNum: v.SeqNum, Length: int32(length), DecryptionStream: stream})
	}
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	// Move state once before the write; an ambiguous write terminates the session.
	if err := response.Incremental.Complete(batch.Metadata); err != nil {
		return err
	}
	return t.routeToClientForSession(session, &teeproto.Envelope{SessionId: session.ID, Payload: &teeproto.Envelope_BatchedDecryptionStreams{BatchedDecryptionStreams: &teeproto.BatchedDecryptionStreams{SessionId: session.ID, Metadata: batch.Metadata, TotalCount: int32(len(streams)), DecryptionStreams: streams}}})
}

func (t *TEEK) handleResponseCaptureReady(sessionID string, marker *teeproto.ResponseCaptureReady) error {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return err
	}
	identity, err := t.connManager.identityForSession(session)
	if err != nil {
		return err
	}
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	state, err := t.sessionManager.stateForSession(session)
	if err != nil {
		return err
	}
	if session.ResponseState == nil || !session.ResponseState.Incremental.Active() || marker == nil || marker.Acknowledged || !bytes.Equal(marker.SessionBinding, session.ResponseState.Incremental.Snapshot().SessionBinding) {
		return fmt.Errorf("invalid incremental capture barrier")
	}
	if !state.responseCaptureStarted.CompareAndSwap(false, true) {
		return fmt.Errorf("duplicate incremental capture barrier")
	}
	// This handler runs on the same client websocket reader as TCPData. The
	// TCP owner sent this marker after all its earlier record forwards finished.
	// Seal the offset before acknowledging; never consume a record nonce here.
	if minitls.IsTLS13CipherSuite(state.CipherSuite) {
		state.initializeResponseTagSeq()
	}
	state.responseCaptureReady.Store(true)
	if err := identity.ensureCurrent(); err != nil {
		return err
	}
	return t.routeToClientForSession(session, &teeproto.Envelope{SessionId: sessionID, Payload: &teeproto.Envelope_ResponseCaptureReady{ResponseCaptureReady: &teeproto.ResponseCaptureReady{SessionBinding: bytes.Clone(marker.SessionBinding), Acknowledged: true}}})
}
