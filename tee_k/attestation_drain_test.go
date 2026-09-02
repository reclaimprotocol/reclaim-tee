package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestTEEKRejectsSessionCreationAfterDrainRequest(t *testing.T) {
	requested := make(chan struct{})
	teek := &TEEK{sessionManager: NewTEEKSessionManager(), logger: shared.NewNopLogger()}
	teek.attestDrain = newTEEKDrainControllerForTest(teek, requested, closedDrainLoopsForTest(), func() {})

	close(requested)
	if _, err := teek.createAdmittedSession(nil); !errors.Is(err, errAttestationDraining) {
		t.Fatalf("createAdmittedSession error = %v, want %v", err, errAttestationDraining)
	}
	if got := teek.ActiveSessions(); got != 0 {
		t.Fatalf("active sessions after rejected admission = %d, want 0", got)
	}
}

func TestTEEKAdmissionReservationLinearizesCreateAgainstDrain(t *testing.T) {
	requested := make(chan struct{})
	stopCalled := make(chan struct{})
	reset := make(chan struct{}, 1)
	teek := &TEEK{sessionManager: NewTEEKSessionManager(), logger: shared.NewNopLogger()}
	teek.attestationMutex.Lock()
	teek.attestationExpiry = time.Now().Add(time.Hour)
	teek.attestationMutex.Unlock()
	teek.attestDrain = shared.NewAttestationDrainController(shared.AttestationDrainConfig{
		Requested: requested,
		StopLoops: func() <-chan struct{} {
			close(stopCalled)
			return closedDrainLoopsForTest()
		},
		CachedAttestationExpiry: teek.cachedAttestationExpiry,
		ActiveSessions:          teek.ActiveSessions,
		Reset:                   func() { reset <- struct{}{} },
		Logger:                  teek.logger,
	})

	beforeIncrement := make(chan struct{})
	allowIncrement := make(chan struct{})
	teek.beforeActiveSessionIncrement = func() {
		close(beforeIncrement)
		<-allowIncrement
	}
	created := make(chan string, 1)
	createErr := make(chan error, 1)
	go func() {
		sessionID, err := teek.createAdmittedSession(nil)
		created <- sessionID
		createErr <- err
	}()
	<-beforeIncrement

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go teek.attestDrain.Run(ctx)
	close(requested)
	<-stopCalled
	select {
	case <-reset:
		t.Fatal("reset occurred while session admission was reserved")
	default:
	}

	close(allowIncrement)
	sessionID := <-created
	if err := <-createErr; err != nil {
		t.Fatalf("createAdmittedSession: %v", err)
	}
	if got := teek.ActiveSessions(); got != 1 {
		t.Fatalf("active sessions after admitted create = %d, want 1", got)
	}
	select {
	case <-reset:
		t.Fatal("reset occurred while admitted session was active")
	default:
	}

	teek.cleanupSession(sessionID)
	<-reset
	if ctx.Err() != nil {
		t.Fatal("drain canceled the router-mode root context")
	}
}

func TestTEEKDrainLifecycleCancelsChildrenButNotRoot(t *testing.T) {
	requested := make(chan struct{})
	heartbeatStarted := make(chan struct{})
	refreshStarted := make(chan struct{})
	heartbeatExited := make(chan struct{})
	refreshExited := make(chan struct{})
	reset := make(chan struct{}, 1)
	teek := &TEEK{logger: shared.NewNopLogger()}
	teek.attestationMutex.Lock()
	teek.attestationExpiry = time.Now().Add(time.Hour)
	teek.attestationMutex.Unlock()
	rootCtx, cancelRoot := context.WithCancel(t.Context())
	defer cancelRoot()

	teek.startAttestationDrainLifecycle(
		rootCtx,
		requested,
		func(ctx context.Context) {
			close(heartbeatStarted)
			<-ctx.Done()
			close(heartbeatExited)
		},
		func(ctx context.Context) {
			close(refreshStarted)
			<-ctx.Done()
			close(refreshExited)
		},
		func() { reset <- struct{}{} },
	)
	<-heartbeatStarted
	<-refreshStarted

	close(requested)
	<-heartbeatExited
	<-refreshExited
	<-reset
	if rootCtx.Err() != nil {
		t.Fatal("drain canceled the router-mode root context")
	}
}

func TestTEEKCachedAttestationExpiryConcurrentReadWrite(t *testing.T) {
	teek := &TEEK{}
	start := make(chan struct{})
	const iterations = 1_000
	var workers sync.WaitGroup
	workers.Go(func() {
		<-start
		for i := range iterations {
			teek.attestationMutex.Lock()
			teek.attestationExpiry = time.Unix(int64(i+1), 0)
			teek.attestationMutex.Unlock()
		}
	})
	for range 4 {
		workers.Go(func() {
			<-start
			for range iterations {
				_ = teek.cachedAttestationExpiry()
			}
		})
	}
	close(start)
	workers.Wait()
	want := time.Unix(iterations, 0)
	if expiry := teek.cachedAttestationExpiry(); !expiry.Equal(want) {
		t.Fatalf("final cached attestation expiry = %s, want %s", expiry, want)
	}
}

func TestTEEKStandaloneAdmissionIsNilSafe(t *testing.T) {
	teek := &TEEK{}
	release, ok := teek.beginSessionAdmission()
	if !ok || release == nil {
		t.Fatal("standalone TEE_K admission was not allowed")
	}
	release()
	release()
}

func newTEEKDrainControllerForTest(teek *TEEK, requested <-chan struct{}, loopsDone <-chan struct{}, reset func()) *shared.AttestationDrainController {
	teek.attestationMutex.Lock()
	teek.attestationExpiry = time.Now().Add(time.Hour)
	teek.attestationMutex.Unlock()
	return shared.NewAttestationDrainController(shared.AttestationDrainConfig{
		Requested:               requested,
		StopLoops:               func() <-chan struct{} { return loopsDone },
		CachedAttestationExpiry: teek.cachedAttestationExpiry,
		ActiveSessions:          teek.ActiveSessions,
		Reset:                   reset,
		Logger:                  teek.logger,
	})
}

func closedDrainLoopsForTest() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}
