package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

var errAttestationDraining = errors.New("attestation drain in progress")

func (t *TEEK) beginSessionAdmission() (release func(), ok bool) {
	if t.attestDrain == nil {
		return func() {}, true
	}
	return t.attestDrain.BeginAdmission()
}

func (t *TEEK) createAdmittedSession(clientConn shared.Connection) (string, error) {
	releaseAdmission, ok := t.beginSessionAdmission()
	if !ok {
		return "", errAttestationDraining
	}
	defer releaseAdmission()

	sessionID, err := t.sessionManager.CreateSession(clientConn)
	if err != nil {
		return "", err
	}
	if t.beforeActiveSessionIncrement != nil {
		t.beforeActiveSessionIncrement()
	}
	t.activeSessions.Add(1)
	return sessionID, nil
}

func (t *TEEK) cachedAttestationExpiry() time.Time {
	t.attestationMutex.RLock()
	defer t.attestationMutex.RUnlock()
	return t.attestationExpiry
}

// startAttestationDrainLifecycle gives heartbeat and refresh independent child
// contexts. Its stop callback cancels only those children and acknowledges
// after both fixed goroutines return; the router-mode root remains live.
func (t *TEEK) startAttestationDrainLifecycle(
	ctx context.Context,
	requested <-chan struct{},
	runHeartbeat func(context.Context),
	runRefresh func(context.Context),
	reset func(),
) *shared.AttestationDrainController {
	heartbeatCtx, cancelHeartbeat := context.WithCancel(ctx)
	refreshCtx, cancelRefresh := context.WithCancel(ctx)
	loopsDone := make(chan struct{})

	controller := shared.NewAttestationDrainController(shared.AttestationDrainConfig{
		Requested: requested,
		StopLoops: func() <-chan struct{} {
			cancelHeartbeat()
			cancelRefresh()
			return loopsDone
		},
		CachedAttestationExpiry: t.cachedAttestationExpiry,
		ActiveSessions:          t.ActiveSessions,
		Reset:                   reset,
		Logger:                  t.logger,
	})
	t.attestDrain = controller

	var loops sync.WaitGroup
	loops.Go(func() { runHeartbeat(heartbeatCtx) })
	loops.Go(func() { runRefresh(refreshCtx) })
	go func() {
		loops.Wait()
		close(loopsDone)
	}()
	go controller.Run(ctx)
	return controller
}
