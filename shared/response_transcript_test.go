package shared

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"

	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"google.golang.org/protobuf/proto"
)

func transcriptTestBatch(t *testing.T, state *ResponseTranscript, records []EncryptedResponseData) *teeproto.ResponseBatchMetadata {
	t.Helper()
	snapshot := state.Snapshot()
	meta, err := BuildResponseBatchMetadata("session", snapshot.SessionBinding, snapshot.PrefixCommitment, snapshot.BatchCount, snapshot.RecordCount, records)
	if err != nil {
		t.Fatal(err)
	}
	return meta
}

func TestResponseCommitmentBindsEveryRecordFieldAndSession(t *testing.T) {
	binding := bytes.Repeat([]byte{1}, 32)
	previous, err := ResponseInitialCommitment("session", binding)
	if err != nil {
		t.Fatal(err)
	}
	original := EncryptedResponseData{SeqNum: 7, RecordHeader: []byte{23, 3, 3, 0, 18}, ExplicitIV: []byte{3}, EncryptedData: []byte{1, 2}, Tag: bytes.Repeat([]byte{4}, 16)}
	baseline, err := BuildResponseBatchMetadata("session", binding, previous, 0, 0, []EncryptedResponseData{original})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"seq", "header", "iv", "ciphertext", "tag", "session", "binding", "previous", "batch", "position"} {
		t.Run(field, func(t *testing.T) {
			record := CloneEncryptedResponse(original)
			sid := "session"
			bind := bytes.Clone(binding)
			prev := bytes.Clone(previous)
			var batch, pos uint64
			switch field {
			case "seq":
				record.SeqNum++
			case "header":
				record.RecordHeader[1]++
			case "iv":
				record.ExplicitIV[0]++
			case "ciphertext":
				record.EncryptedData[0]++
			case "tag":
				record.Tag[0]++
			case "session":
				sid = "other"
			case "binding":
				bind[0]++
			case "previous":
				prev[0]++
			case "batch":
				batch++
			case "position":
				pos++
			}
			changed, err := BuildResponseBatchMetadata(sid, bind, prev, batch, pos, []EncryptedResponseData{record})
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(baseline.PrefixCommitment, changed.PrefixCommitment) {
				t.Fatal("changed record or session retained commitment")
			}
		})
	}
}

func TestResponseTranscriptAuthenticatesOnceThenFreezesExactPrefix(t *testing.T) {
	var state ResponseTranscript
	if err := state.Configure("session", make([]byte, 32), 0); err != nil {
		t.Fatal(err)
	}
	for seq := uint64(0); seq < 2; seq++ {
		meta := transcriptTestBatch(t, &state, []EncryptedResponseData{{SeqNum: seq, EncryptedData: []byte{1}}})
		if err := state.Accept(meta, 22); err != nil {
			t.Fatal(err)
		}
		if err := state.Accept(meta, 22); err == nil {
			t.Fatal("duplicate batch accepted")
		}
		if err := state.BeginFreeze(state.Snapshot()); err == nil {
			t.Fatal("pending prefix frozen")
		}
		if err := state.ClaimPending(meta); err != nil {
			t.Fatal(err)
		}
		if err := state.ClaimPending(meta); err == nil {
			t.Fatal("duplicate key-release work accepted")
		}
		if err := state.Complete(meta); err != nil {
			t.Fatal(err)
		}
		if err := state.Complete(meta); err == nil {
			t.Fatal("duplicate batch completion accepted")
		}
	}
	if err := state.RequireFrozen(); err == nil {
		t.Fatal("appendable transcript permitted finalization")
	}
	request := state.Snapshot()
	wrong := proto.Clone(request).(*teeproto.FinalizeResponse)
	wrong.RecordCount--
	if err := state.BeginFreeze(wrong); err == nil {
		t.Fatal("older authenticated prefix accepted")
	}
	if err := state.BeginFreeze(request); err != nil {
		t.Fatal(err)
	}
	ack := &teeproto.ResponseFrozen{SessionBinding: request.SessionBinding, BatchCount: request.BatchCount, RecordCount: request.RecordCount, PrefixCommitment: request.PrefixCommitment}
	if err := state.RequireFrozen(); err == nil {
		t.Fatal("unacknowledged freeze permitted finalization")
	}
	if err := state.FinishFreeze(ack); err != nil {
		t.Fatal(err)
	}
	if err := state.BeginRedaction(); err != nil {
		t.Fatal(err)
	}
	if err := state.BeginRedaction(); err == nil {
		t.Fatal("duplicate final redaction accepted")
	}
	if err := state.Accept(transcriptTestBatch(t, &state, []EncryptedResponseData{{SeqNum: 2}}), 22); err == nil {
		t.Fatal("append after freeze accepted")
	}
}

func TestResponseTranscriptConcurrentAppendOrFreezeHasSingleWinner(t *testing.T) {
	for range 100 {
		var state ResponseTranscript
		if err := state.Configure("session", make([]byte, 32), 0); err != nil {
			t.Fatal(err)
		}
		first := transcriptTestBatch(t, &state, []EncryptedResponseData{{SeqNum: 0}})
		if err := state.Accept(first, 22); err != nil {
			t.Fatal(err)
		}
		if err := state.ClaimPending(first); err != nil {
			t.Fatal(err)
		}
		if err := state.Complete(first); err != nil {
			t.Fatal(err)
		}
		freeze := state.Snapshot()
		next := transcriptTestBatch(t, &state, []EncryptedResponseData{{SeqNum: 1}})
		var winners atomic.Int32
		var wg sync.WaitGroup
		wg.Go(func() {
			if state.BeginFreeze(freeze) == nil {
				winners.Add(1)
			}
		})
		wg.Go(func() {
			if state.Accept(next, 22) == nil {
				winners.Add(1)
			}
		})
		wg.Wait()
		if winners.Load() != 1 {
			t.Fatalf("append/freeze winners=%d", winners.Load())
		}
	}
}

func TestResponseTranscriptRejectsMetadataAndLimitsBeforeAcceptance(t *testing.T) {
	for _, kind := range []string{"empty", "batch gap", "position gap", "wrong binding", "bad hash", "record limit", "byte limit"} {
		t.Run(kind, func(t *testing.T) {
			var state ResponseTranscript
			if err := state.Configure("session", make([]byte, 32), 0); err != nil {
				t.Fatal(err)
			}
			meta := transcriptTestBatch(t, &state, []EncryptedResponseData{{SeqNum: 0}})
			size := uint64(22)
			switch kind {
			case "empty":
				meta.RecordCount = 0
			case "batch gap":
				meta.BatchId = 1
			case "position gap":
				meta.FirstRecord = 1
			case "wrong binding":
				meta.SessionBinding[0] = 1
			case "bad hash":
				meta.PrefixCommitment = nil
			case "record limit":
				meta.RecordCount = MaxIncrementalBatchRecords + 1
			case "byte limit":
				size = MaxIncrementalResponseBytes + 1
			}
			if err := state.Accept(meta, size); err == nil {
				t.Fatal("invalid batch accepted")
			}
			if state.Snapshot().RecordCount != 0 {
				t.Fatal("invalid batch changed transcript")
			}
		})
	}
}

func TestIncrementalRecordShapeRejectsAmbiguousHeadersAndIVs(t *testing.T) {
	for _, tc := range []struct {
		name          string
		length        int
		header, iv    []byte
		seq, expected uint64
		tls13, gcm    bool
		valid         bool
	}{
		{"tls13", 2, []byte{23, 3, 3, 0, 18}, nil, 0, 0, true, false, true},
		{"tls12gcm", 2, []byte{23, 3, 3, 0, 26}, make([]byte, 8), 1, 1, false, true, true},
		{"tls12chacha", 2, []byte{21, 3, 3, 0, 18}, nil, 1, 1, false, false, true},
		{"wrong version", 2, []byte{23, 3, 1, 0, 18}, nil, 0, 0, true, false, false},
		{"wrong length", 2, []byte{23, 3, 3, 0, 19}, nil, 0, 0, true, false, false},
		{"wrong type", 2, []byte{22, 3, 3, 0, 18}, nil, 0, 0, true, false, false},
		{"missing inner type", 0, []byte{23, 3, 3, 0, 16}, nil, 0, 0, true, false, false},
		{"missing IV", 2, []byte{23, 3, 3, 0, 18}, nil, 1, 1, false, true, false},
		{"unexpected IV", 2, []byte{23, 3, 3, 0, 26}, make([]byte, 8), 0, 0, true, false, false},
		{"seq gap", 2, []byte{23, 3, 3, 0, 18}, nil, 2, 0, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateIncrementalRecordShape(tc.length, tc.header, tc.iv, tc.seq, tc.expected, tc.tls13, tc.gcm)
			if (err == nil) != tc.valid {
				t.Fatalf("validation error=%v, valid=%v", err, tc.valid)
			}
		})
	}
}

func TestResponseNegotiationRejectsPriorLegacyFinalization(t *testing.T) {
	for _, kind := range []string{"batch", "redaction", "OPRF"} {
		t.Run(kind, func(t *testing.T) {
			var state ResponseTranscript
			var err error
			switch kind {
			case "batch":
				err = state.StartLegacy()
			case "redaction":
				err = state.BeginRedaction()
			case "OPRF":
				err = state.RequireFrozenForInput()
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := state.Configure("session", make([]byte, 32), 0); err == nil {
				t.Fatal("negotiation accepted earlier legacy input")
			}
		})
	}
}

func TestResponseTranscriptRejectsCommitmentFromStaleAuthenticatedPrefix(t *testing.T) {
	var state ResponseTranscript
	if err := state.Configure("session", make([]byte, 32), 0); err != nil {
		t.Fatal(err)
	}
	firstRecords := []EncryptedResponseData{{SeqNum: 0, EncryptedData: []byte{1}}}
	first := transcriptTestBatch(t, &state, firstRecords)
	if err := state.AcceptRecords(first, firstRecords, 22); err != nil {
		t.Fatal(err)
	}
	snapshot := state.Snapshot()
	nextRecords := []EncryptedResponseData{{SeqNum: 1, EncryptedData: []byte{2}}}
	stale, err := BuildResponseBatchMetadata("session", snapshot.SessionBinding, snapshot.PrefixCommitment, 1, 1, nextRecords)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.ClaimPending(first); err != nil {
		t.Fatal(err)
	}
	if err := state.Complete(first); err != nil {
		t.Fatal(err)
	}
	if err := state.AcceptRecords(stale, nextRecords, 22); err == nil {
		t.Fatal("commitment based on pre-authentication snapshot was accepted")
	}
	proper := transcriptTestBatch(t, &state, nextRecords)
	if err := state.AcceptRecords(proper, nextRecords, 22); err != nil {
		t.Fatal(err)
	}
}
