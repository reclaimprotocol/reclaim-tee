package main

import (
	"bytes"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/minitls"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
	"google.golang.org/protobuf/proto"
)

func newIncrementalTEET(t *testing.T) (*TEET, *teetSessionIdentity, *TEETSessionState) {
	t.Helper()
	manager := NewTEETSessionManager()
	manager.SetLogger(shared.NewNopLogger())
	if err := manager.RegisterSession("incremental"); err != nil {
		t.Fatal(err)
	}
	session, err := manager.GetSession("incremental")
	if err != nil {
		t.Fatal(err)
	}
	session.TEEKConn = newReceiverTestWebSocket(t)
	state := &TEETSessionState{session: session}
	manager.SetTEETSessionState(session.ID, state)
	teet := &TEET{sessionManager: manager, logger: shared.NewNopLogger()}
	identity := &teetSessionIdentity{session: session}
	request := &teeproto.ResponseModeRequest{Mode: teeproto.ResponseMode_RESPONSE_MODE_INCREMENTAL_V1, SessionBinding: make([]byte, 32), CipherSuite: minitls.TLS_AES_128_GCM_SHA256}
	if err := teet.handleResponseModeRequest(identity, request); err != nil {
		t.Fatal(err)
	}
	return teet, identity, state
}

func incrementalTEETRecord(t *testing.T, seq uint64, content []byte) (shared.EncryptedResponseData, []byte) {
	t.Helper()
	suite := uint16(minitls.TLS_AES_128_GCM_SHA256)
	engine := minitls.NewSplitAEAD(make([]byte, 16), make([]byte, 12), suite)
	engine.SetSequence(seq)
	header := []byte{23, 3, 3, byte((len(content) + 16) >> 8), byte(len(content) + 16)}
	ciphertext, secrets, err := engine.EncryptWithoutTag(content, header)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := minitls.ComputeTagFromSecrets(ciphertext, secrets, suite, header)
	if err != nil {
		t.Fatal(err)
	}
	return shared.EncryptedResponseData{EncryptedData: ciphertext, Tag: tag, RecordHeader: header, SeqNum: seq}, secrets
}

func incrementalTEETBatch(t *testing.T, identity *teetSessionIdentity, records []shared.EncryptedResponseData) shared.BatchedEncryptedResponseData {
	t.Helper()
	snapshot := identity.session.ResponseState.Incremental.Snapshot()
	meta, err := shared.BuildResponseBatchMetadata(identity.session.ID, snapshot.SessionBinding, snapshot.PrefixCommitment, snapshot.BatchCount, snapshot.RecordCount, records)
	if err != nil {
		t.Fatal(err)
	}
	return shared.BatchedEncryptedResponseData{SessionID: identity.session.ID, TotalCount: len(records), Metadata: meta, Responses: records}
}

func incrementalTEETSecrets(batch shared.BatchedEncryptedResponseData, secrets []byte) shared.BatchedTagSecretsData {
	out := shared.BatchedTagSecretsData{SessionID: batch.SessionID, TotalCount: 1, Metadata: batch.Metadata}
	out.TagSecrets = append(out.TagSecrets, struct {
		TagSecrets []byte `json:"tag_secrets"`
		SeqNum     uint64 `json:"seq_num"`
	}{TagSecrets: secrets, SeqNum: batch.Responses[0].SeqNum})
	return out
}

func TestIncrementalTEETAuthenticatesImmutableBatchesAndFreezes(t *testing.T) {
	teet, identity, state := newIncrementalTEET(t)
	var expected []byte
	for seq, plaintext := range [][]byte{{4, 1, 2, 22}, append([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 23)} {
		record, secrets := incrementalTEETRecord(t, uint64(seq), plaintext)
		expected = append(expected, record.EncryptedData[:len(record.EncryptedData)-1]...)
		batch := incrementalTEETBatch(t, identity, []shared.EncryptedResponseData{record})
		if err := teet.handleIncrementalEncryptedResponses(identity, batch); err != nil {
			t.Fatal(err)
		}
		committed := bytes.Clone(record.EncryptedData)
		batch.Responses[0].EncryptedData[0] ^= 1
		if !bytes.Equal(identity.session.ResponseState.PendingEncryptedResponses[uint64(seq)].EncryptedData, committed) {
			t.Fatal("committed ciphertext aliases client message")
		}
		tagBatch := incrementalTEETSecrets(batch, secrets)
		if err := teet.handleIncrementalTagSecrets(identity, tagBatch); err != nil {
			t.Fatal(err)
		}
		before := bytes.Clone(state.ConsolidatedResponseCiphertext)
		if err := teet.handleIncrementalTagSecrets(identity, tagBatch); err == nil {
			t.Fatal("duplicate authentication accepted")
		}
		if !bytes.Equal(before, state.ConsolidatedResponseCiphertext) {
			t.Fatal("duplicate authentication changed transcript")
		}
	}
	if !bytes.Equal(expected, state.ConsolidatedResponseCiphertext) {
		t.Fatal("cumulative authenticated transcript changed")
	}
	if state.TOutputSigned.Load() {
		t.Fatal("appendable transcript signed")
	}
	request := identity.session.ResponseState.Incremental.Snapshot()
	if err := teet.handleFinalizeResponse(identity, request); err != nil {
		t.Fatal(err)
	}
	if !identity.session.ResponseState.Incremental.Frozen() {
		t.Fatal("freeze acknowledgment sent before freeze")
	}
	next, _ := incrementalTEETRecord(t, 2, []byte{23})
	if err := teet.handleIncrementalEncryptedResponses(identity, incrementalTEETBatch(t, identity, []shared.EncryptedResponseData{next})); err == nil {
		t.Fatal("append after freeze accepted")
	}
	if err := teet.handleFinalizeResponse(identity, request); err == nil {
		t.Fatal("duplicate freeze accepted")
	}
}

func TestIncrementalTEETRejectsMalformedRecordsBeforeCommitment(t *testing.T) {
	for _, kind := range []string{"tag length", "header length", "header version", "header size", "IV", "sequence", "binding", "commitment", "count", "reorder"} {
		t.Run(kind, func(t *testing.T) {
			teet, identity, state := newIncrementalTEET(t)
			record, _ := incrementalTEETRecord(t, 0, []byte{1, 23})
			batch := incrementalTEETBatch(t, identity, []shared.EncryptedResponseData{record})
			switch kind {
			case "tag length":
				batch.Responses[0].Tag = nil
			case "header length":
				batch.Responses[0].RecordHeader = nil
			case "header version":
				batch.Responses[0].RecordHeader[1] = 2
			case "header size":
				batch.Responses[0].RecordHeader[4]++
			case "IV":
				batch.Responses[0].ExplicitIV = make([]byte, 8)
			case "sequence":
				batch.Responses[0].SeqNum = 1
			case "binding":
				batch.Metadata.SessionBinding[0] = 1
			case "commitment":
				batch.Metadata.PrefixCommitment[0]++
			case "count":
				batch.TotalCount++
			case "reorder":
				batch.Metadata.BatchId = 1
			}
			if err := teet.handleIncrementalEncryptedResponses(identity, batch); err == nil {
				t.Fatal("invalid batch accepted")
			}
			if len(identity.session.ResponseState.PendingEncryptedResponses) != 0 || len(identity.session.TranscriptData) != 0 || len(state.ConsolidatedResponseCiphertext) != 0 {
				t.Fatal("invalid batch changed committed transcript")
			}
		})
	}
}

func TestIncrementalTEETAuthenticationFailureCannotFreeze(t *testing.T) {
	teet, identity, state := newIncrementalTEET(t)
	record, secrets := incrementalTEETRecord(t, 0, []byte{1, 23})
	record.Tag[0] ^= 1
	batch := incrementalTEETBatch(t, identity, []shared.EncryptedResponseData{record})
	if err := teet.handleIncrementalEncryptedResponses(identity, batch); err != nil {
		t.Fatal(err)
	}
	if err := teet.handleIncrementalTagSecrets(identity, incrementalTEETSecrets(batch, secrets)); err == nil {
		t.Fatal("invalid tag authenticated")
	}
	if len(state.ConsolidatedResponseCiphertext) != 0 {
		t.Fatal("failed authentication appended ciphertext")
	}
	if err := teet.handleFinalizeResponse(identity, identity.session.ResponseState.Incremental.Snapshot()); err == nil {
		t.Fatal("failed authentication permitted freeze")
	}
}

func TestIncrementalTEETNegotiationCannotChangeCipherOrRepeat(t *testing.T) {
	teet, identity, state := newIncrementalTEET(t)
	if state.responseCipherSuite() != minitls.TLS_AES_128_GCM_SHA256 {
		t.Fatal("response cipher unavailable before request")
	}
	if err := state.setResponseCipherSuite(minitls.TLS_CHACHA20_POLY1305_SHA256); err == nil {
		t.Fatal("request replaced negotiated cipher")
	}
	request := &teeproto.ResponseModeRequest{Mode: teeproto.ResponseMode_RESPONSE_MODE_INCREMENTAL_V1, SessionBinding: make([]byte, 32), CipherSuite: minitls.TLS_AES_128_GCM_SHA256}
	if err := teet.handleResponseModeRequest(identity, request); err == nil {
		t.Fatal("duplicate negotiation accepted")
	}
	for _, mode := range []teeproto.ResponseMode{teeproto.ResponseMode_RESPONSE_MODE_LEGACY_EOF, 99} {
		changed := proto.Clone(request).(*teeproto.ResponseModeRequest)
		changed.Mode = mode
		if err := teet.handleResponseModeRequest(identity, changed); err == nil {
			t.Fatal("unsupported peer mode accepted")
		}
	}
}
