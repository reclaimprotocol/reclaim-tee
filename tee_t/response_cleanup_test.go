package main

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/mpc"
	teeproto "github.com/reclaimprotocol/reclaim-tee/proto"
	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestIncrementalAuthenticationConcurrentDestroy(t *testing.T) {
	teet, identity, state := newIncrementalTEET(t)
	var records []shared.EncryptedResponseData
	secrets := shared.BatchedTagSecretsData{SessionID: identity.session.ID, TotalCount: 64}
	for seq := range 64 {
		content := make([]byte, 16384)
		content[len(content)-1] = 23
		record, secret := incrementalTEETRecord(t, uint64(seq), content)
		records = append(records, record)
		secrets.TagSecrets = append(secrets.TagSecrets, struct {
			TagSecrets []byte `json:"tag_secrets"`
			SeqNum     uint64 `json:"seq_num"`
		}{TagSecrets: secret, SeqNum: uint64(seq)})
	}
	batch := incrementalTEETBatch(t, identity, records)
	secrets.Metadata = batch.Metadata
	if err := teet.handleIncrementalEncryptedResponses(identity, batch); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		<-start
		// Cancellation can win before authentication, during its append, or
		// after the batch completes. Each outcome must allow safe cleanup.
		_ = teet.handleIncrementalTagSecrets(identity, secrets)
	})
	wg.Go(func() {
		<-start
		for range 5000 {
			state.DestroySessionState()
		}
	})
	wg.Go(func() {
		<-start
		for range 5000 {
			input, err := state.snapshotResponseCiphertextRange(0, 64)
			if err == nil && !bytes.Equal(input, records[0].EncryptedData[:64]) {
				t.Error("cleanup changed an owned OPRF input")
				return
			}
		}
	})
	close(start)
	wg.Wait()
	if len(state.snapshotResponseCiphertext()) != 0 {
		t.Fatal("authentication published response bytes after cleanup")
	}
	if err := state.AppendResponseCiphertext([]byte("late response")); err == nil {
		t.Fatal("append accepted after cleanup")
	}
}

func TestResponseCiphertextSnapshotsSurviveCleanup(t *testing.T) {
	plaintext := []byte("authenticated CBC response")
	state := &TEETSessionState{
		CBCAuthenticatedResponse:         bytes.Clone(plaintext),
		CBCAuthenticatedRedactedResponse: []byte("redacted CBC response"),
		CBCResponseDigest:                []byte("response digest"),
	}
	if err := state.replaceResponseCiphertext(plaintext); err != nil {
		t.Fatal(err)
	}
	full := state.snapshotResponseCiphertext()
	rangeInput, err := state.snapshotResponseCiphertextRange(1, 3)
	if err != nil {
		t.Fatal(err)
	}
	backing := [][]byte{state.ConsolidatedResponseCiphertext, state.CBCAuthenticatedResponse, state.CBCAuthenticatedRedactedResponse, state.CBCResponseDigest}
	state.DestroySessionState()
	for _, value := range backing {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("cleanup retained response bytes in the original backing buffer")
		}
	}
	if !bytes.Equal(full, plaintext) || !bytes.Equal(rangeInput, plaintext[1:4]) {
		t.Fatal("cleanup changed an owned response snapshot")
	}
	if err := state.replaceResponseCiphertext(plaintext); err == nil {
		t.Fatal("CBC publication accepted after cleanup")
	}
	if _, err := state.snapshotResponseCiphertextRange(0, 1); err == nil {
		t.Fatal("OPRF input accepted after cleanup")
	}
}

func TestResponseCleanupDoesNotWaitForResponseHandler(t *testing.T) {
	_, identity, state := newIncrementalTEET(t)
	// Transcript insertion can terminate the session while this lock is held.
	// Cleanup must not acquire it recursively.
	identity.session.ResponseState.ResponsesMutex.Lock()
	defer identity.session.ResponseState.ResponsesMutex.Unlock()
	done := make(chan struct{})
	go func() {
		state.DestroySessionState()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanup waited for the response handler lock")
	}
}

func TestOPRFInitializationConcurrentTeardown(t *testing.T) {
	manager := NewTEETSessionManager()
	manager.SetLogger(shared.NewNopLogger())
	if err := manager.RegisterSession("oprf-cleanup"); err != nil {
		t.Fatal(err)
	}
	session, err := manager.GetSession("oprf-cleanup")
	if err != nil {
		t.Fatal(err)
	}
	teet := &TEET{sessionManager: manager, logger: shared.NewNopLogger(), oprfKeyShare: make([]byte, 16)}
	identity := &teetSessionIdentity{session: session}
	for range 100 {
		state := &TEETSessionState{session: session, ConsolidatedResponseCiphertext: []byte{1}}
		manager.SetTEETSessionState(session.ID, state)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			<-start
			// The real handler must serialize its first initialization with cleanup,
			// even if it obtained the session state before removal started.
			_ = teet.handleOPRFOnlineFull(identity, &teeproto.OPRFOnlineFull{
				SessionId: session.ID, TlsSessionHash: make([]byte, 32), TotalRanges: 1, TlsLength: 1,
			})
		})
		wg.Go(func() {
			<-start
			for range 100 {
				state.DestroySessionState()
			}
		})
		close(start)
		wg.Wait()
		if state.PendingOPRF != nil {
			t.Fatal("initialization recreated pending OPRF state after cleanup")
		}
		if err := state.initializeOPRFState(1, teet.oprfKeyShare); err == nil {
			t.Fatal("OPRF initialization accepted after cleanup")
		}
		pending := &pendingOPRFEvaluation{Session: new(mpc.EvaluatorSession)}
		if err := state.SetPendingOPRF(0, pending); err == nil {
			t.Fatal("late evaluator publication accepted after cleanup")
		}
	}
}

func TestOPRFInitializationPreservesFirstSubmission(t *testing.T) {
	state := new(TEETSessionState)
	keyShare := bytes.Repeat([]byte{1}, 16)
	if err := state.initializeOPRFState(2, keyShare); err != nil {
		t.Fatal(err)
	}
	result := &shared.OPRFResult{RangeIndex: 0}
	state.SetOPRFResult(0, result)
	pending := &pendingOPRFEvaluation{Session: new(mpc.EvaluatorSession)}
	if err := state.SetPendingOPRF(1, pending); err != nil {
		t.Fatal(err)
	}
	if err := state.initializeOPRFState(2, bytes.Repeat([]byte{2}, 16)); err != nil {
		t.Fatal(err)
	}
	if state.OPRFResults[0] != result || state.PendingOPRF[1] != pending || !bytes.Equal(state.OPRFKeyShare, keyShare) {
		t.Fatal("later OPRF range replaced initialized state")
	}
	if err := state.initializeOPRFState(3, keyShare); err == nil {
		t.Fatal("changed total_ranges accepted")
	}
}
