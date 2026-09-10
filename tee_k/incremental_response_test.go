package main

import (
	"bytes"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"google.golang.org/protobuf/proto"
)

func TestIncrementalKNegotiationPreservesLegacyAndCBC(t *testing.T) {
	for _, tc := range []struct {
		name      string
		requested teeproto.ResponseMode
		suite     uint16
		supports  bool
	}{
		{"old client", 0, minitls.TLS_AES_128_GCM_SHA256, true},
		{"old peer", 1, minitls.TLS_AES_128_GCM_SHA256, false},
		{"CBC fallback", 1, minitls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			teek, _, session, connection, _ := newTEEKPeerLossSession(t)
			connection.supportsIncrementalResponses = tc.supports
			state, err := teek.sessionManager.stateForSession(session)
			if err != nil {
				t.Fatal(err)
			}
			state.CipherSuite = tc.suite
			session.ConnectionData = &shared.RequestConnectionData{RequestedResponseMode: tc.requested}
			mode, binding, err := teek.negotiateResponseMode(session, state)
			if err != nil || mode != 0 || len(binding) != 0 || session.ResponseState.Incremental.Active() {
				t.Fatalf("legacy negotiation = %v,%x,%v", mode, binding, err)
			}
		})
	}
}

func TestIncrementalKNegotiationRequiresExactPeerAck(t *testing.T) {
	teek, cm, session, connection, _ := newTEEKPeerLossSession(t)
	connection.supportsIncrementalResponses = true
	peer, messages := newAckTestWebSocketWithMessages(t)
	connection.conn = peer
	state, err := teek.sessionManager.stateForSession(session)
	if err != nil {
		t.Fatal(err)
	}
	state.CipherSuite = minitls.TLS_AES_128_GCM_SHA256
	session.ConnectionData = &shared.RequestConnectionData{RequestedResponseMode: teeproto.ResponseMode_RESPONSE_MODE_INCREMENTAL_V1}
	identity, err := cm.identityForSession(session)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		mode    teeproto.ResponseMode
		binding []byte
		err     error
	}
	completed := make(chan result, 1)
	go func() {
		mode, binding, err := teek.negotiateResponseMode(session, state)
		completed <- result{mode, binding, err}
	}()
	var envelope teeproto.Envelope
	select {
	case wire := <-messages:
		if err := proto.Unmarshal(wire, &envelope); err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("no response mode request")
	}
	request := envelope.GetResponseModeRequest()
	if request == nil || len(request.SessionBinding) != 32 || request.CipherSuite != uint32(state.CipherSuite) {
		t.Fatal("invalid mode request")
	}
	ack := &teeproto.ResponseModeAck{Mode: request.Mode, SessionBinding: request.SessionBinding, Success: true}
	if err := teek.handleResponseModeAck(identity, ack); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-completed:
		if result.err != nil || result.mode != request.Mode || !bytes.Equal(result.binding, request.SessionBinding) {
			t.Fatalf("negotiation result: %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("negotiation did not complete")
	}
	if err := teek.handleResponseModeAck(identity, ack); err == nil {
		t.Fatal("duplicate negotiation acknowledgment accepted")
	}
}

func TestIncrementalKReleasesOnlyCurrentBatchAndRejectsReplay(t *testing.T) {
	teek, cm, session, _, _ := newTEEKPeerLossSession(t)
	client, messages := newAckTestWebSocketWithMessages(t)
	session.ConnMutex.Lock()
	session.ClientConn = client
	session.ConnMutex.Unlock()
	identity, err := cm.identityForSession(session)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.ResponseState.Incremental.Configure(session.ID, make([]byte, 32), 0); err != nil {
		t.Fatal(err)
	}
	session.ResponseState.ResponseLengthBySeq = map[uint64]int{0: 2, 1: 2}
	session.CachedDecryptionStreams = map[uint64][]byte{0: {1, 2}, 1: {3, 4}}
	for seq := uint64(0); seq < 2; seq++ {
		snapshot := session.ResponseState.Incremental.Snapshot()
		meta, err := shared.BuildResponseBatchMetadata(session.ID, snapshot.SessionBinding, snapshot.PrefixCommitment, snapshot.BatchCount, snapshot.RecordCount, []shared.EncryptedResponseData{{SeqNum: seq, EncryptedData: []byte{1, 2}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := session.ResponseState.Incremental.Accept(meta, 23); err != nil {
			t.Fatal(err)
		}
		verified := shared.BatchedTagVerificationData{SessionID: session.ID, TotalCount: 1, AllSuccessful: true, Metadata: meta, Verifications: []shared.ResponseTagVerificationData{{SeqNum: seq, Success: true}}}
		if err := teek.handleIncrementalTagVerifications(identity, verified); err != nil {
			t.Fatal(err)
		}
		select {
		case wire := <-messages:
			var env teeproto.Envelope
			if err := proto.Unmarshal(wire, &env); err != nil {
				t.Fatal(err)
			}
			batch := env.GetBatchedDecryptionStreams()
			if batch == nil || len(batch.DecryptionStreams) != 1 || batch.DecryptionStreams[0].SeqNum != seq || !shared.EqualResponseBatchMetadata(batch.Metadata, meta) {
				t.Fatal("released streams outside current authenticated batch")
			}
		case <-time.After(time.Second):
			t.Fatal("no decryption batch")
		}
		if err := teek.handleIncrementalTagVerifications(identity, verified); err == nil {
			t.Fatal("replayed authentication released streams")
		}
	}
}

func TestIncrementalKLogicalPositionsPreserveHandshakeNonceOffset(t *testing.T) {
	var state TEEKSessionState
	state.AppRecordsViaTCPData.Store(3)
	var transcript shared.ResponseTranscript
	if err := transcript.Configure("session", make([]byte, 32), 0); err != nil {
		t.Fatal(err)
	}
	for seq := uint64(0); seq < 3; seq++ {
		snapshot := transcript.Snapshot()
		if logical := transcript.ExpectedSequence(snapshot.RecordCount); logical != seq {
			t.Fatalf("logical sequence=%d,want%d", logical, seq)
		}
		meta, err := shared.BuildResponseBatchMetadata("session", snapshot.SessionBinding, snapshot.PrefixCommitment, snapshot.BatchCount, snapshot.RecordCount, []shared.EncryptedResponseData{{SeqNum: seq}})
		if err != nil {
			t.Fatal(err)
		}
		if err := transcript.Accept(meta, 22); err != nil {
			t.Fatal(err)
		}
		if nonce := state.NextResponseTagSeq(); nonce != seq+3 {
			t.Fatalf("nonce=%d,want%d", nonce, seq+3)
		}
		if err := transcript.Accept(meta, 22); err == nil {
			t.Fatal("retry accepted before nonce allocation")
		}
		if err := transcript.ClaimPending(meta); err != nil {
			t.Fatal(err)
		}
		if err := transcript.Complete(meta); err != nil {
			t.Fatal(err)
		}
	}
	if got := state.responseTagSeq.Load(); got != 6 {
		t.Fatalf("nonce sequence=%d,want6", got)
	}
}

func TestIncrementalKFinalizationInputsRequireFrozenTranscript(t *testing.T) {
	teek, _, session, _, _ := newTEEKPeerLossSession(t)
	if err := session.ResponseState.Incremental.Configure(session.ID, make([]byte, 32), 0); err != nil {
		t.Fatal(err)
	}
	state, err := teek.sessionManager.stateForSession(session)
	if err != nil {
		t.Fatal(err)
	}
	if err := teek.handleOPRFRangesFromClient(session.ID, &teeproto.OPRFRangesSubmission{SessionId: session.ID}); err == nil {
		t.Fatal("OPRF submitted before freeze")
	}
	if state.OPRFRangesSubmitted.Load() {
		t.Fatal("rejected OPRF input changed state")
	}
	if err := teek.handleRedactionSpec(session.ID, &shared.Message{SessionID: session.ID, Data: shared.ResponseRedactionSpec{}}); err == nil {
		t.Fatal("redaction accepted before freeze")
	}
	if session.RedactionProcessingComplete || session.FinalSignatureStatus() != shared.FinalSignaturePending {
		t.Fatal("appendable response finalized")
	}
}

func TestIncrementalKCaptureBarrierSealsAllPriorTCPDataBeforeNonceUse(t *testing.T) {
	teek, _, session, _, _ := newTEEKPeerLossSession(t)
	state, err := teek.sessionManager.stateForSession(session)
	if err != nil {
		t.Fatal(err)
	}
	state.CipherSuite = minitls.TLS_AES_128_GCM_SHA256
	state.WSConn2TLS = &WebSocketConn{pendingData: make(chan []byte, 4), done: make(chan struct{})}
	if err := session.ResponseState.Incremental.Configure(session.ID, make([]byte, 32), 0); err != nil {
		t.Fatal(err)
	}
	forwarded := &shared.Message{SessionID: session.ID, Data: shared.TCPData{Data: []byte{23, 3, 3, 0, 1, 0}}}
	// Model FIFO messages from the sole TCP reader after its last stale
	// handshakeComplete=false routing decision has finished sending.
	for range 3 {
		if err := teek.handleTCPData(session.ID, forwarded); err != nil {
			t.Fatal(err)
		}
	}
	marker := &teeproto.ResponseCaptureReady{SessionBinding: make([]byte, 32)}
	if err := teek.handleResponseCaptureReady(session.ID, marker); err != nil {
		t.Fatal(err)
	}
	if !state.responseCaptureReady.Load() || state.responseTagSeq.Load() != 3 {
		t.Fatal("capture barrier consumed a nonce or omitted earlier forwarded records")
	}
	if err := teek.handleTCPData(session.ID, forwarded); err == nil {
		t.Fatal("post-barrier TCPData changed the sealed offset")
	}
	if first := state.NextResponseTagSeq(); first != 3 {
		t.Fatalf("first nonce=%d,want3", first)
	}
	if err := teek.handleResponseCaptureReady(session.ID, marker); err == nil {
		t.Fatal("duplicate barrier accepted")
	}
}

func TestIncrementalKLengthsRequireCaptureBarrier(t *testing.T) {
	teek, cm, session, _, _ := newTEEKPeerLossSession(t)
	state, err := teek.sessionManager.stateForSession(session)
	if err != nil {
		t.Fatal(err)
	}
	state.CipherSuite = minitls.TLS_AES_128_GCM_SHA256
	identity, err := cm.identityForSession(session)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.ResponseState.Incremental.Configure(session.ID, make([]byte, 32), 0); err != nil {
		t.Fatal(err)
	}
	record := shared.EncryptedResponseData{SeqNum: 0, EncryptedData: []byte{1, 2}, Tag: make([]byte, 16), RecordHeader: []byte{23, 3, 3, 0, 18}}
	snapshot := session.ResponseState.Incremental.Snapshot()
	meta, err := shared.BuildResponseBatchMetadata(session.ID, snapshot.SessionBinding, snapshot.PrefixCommitment, 0, 0, []shared.EncryptedResponseData{record})
	if err != nil {
		t.Fatal(err)
	}
	batch := shared.BatchedResponseLengthData{SessionID: session.ID, Metadata: meta, TotalCount: 1}
	batch.Lengths = append(batch.Lengths, struct {
		Length       int    `json:"length"`
		RecordHeader []byte `json:"record_header"`
		SeqNum       uint64 `json:"seq_num"`
		ExplicitIV   []byte `json:"explicit_iv,omitempty"`
	}{Length: 2, RecordHeader: record.RecordHeader})
	if err := teek.handleIncrementalResponseLengths(identity, batch); err == nil {
		t.Fatal("lengths accepted before capture barrier")
	}
	if state.responseTagSeq.Load() != 0 || len(session.ResponseState.ResponseLengthBySeq) != 0 || len(session.ResponseState.NonceBySeq) != 0 {
		t.Fatal("unacknowledged capture consumed key material")
	}
	marker := &teeproto.ResponseCaptureReady{SessionBinding: bytes.Repeat([]byte{1}, 32)}
	if err := teek.handleResponseCaptureReady(session.ID, marker); err == nil {
		t.Fatal("wrong-binding barrier accepted")
	}
	if state.responseCaptureStarted.Load() {
		t.Fatal("wrong barrier consumed the valid marker")
	}
}
