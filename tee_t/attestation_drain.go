package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

var (
	errAttestationDraining = errors.New("attestation drain in progress")
	errTEETPairIDNotKnown  = errors.New("register: pair_id not yet known")
)

func (t *TEET) beginSessionAdmission() (release func(), ok bool) {
	if t.attestDrain == nil {
		return func() {}, true
	}
	return t.attestDrain.BeginAdmission()
}

func (t *TEET) cachedAttestationExpiry() time.Time {
	t.attestationMutex.RLock()
	defer t.attestationMutex.RUnlock()
	return t.attestationExpiry
}

// startAttestationDrainLifecycle gives the heartbeat supervisor and refresh
// loop independent child contexts. Its stop callback cancels only those
// children and acknowledges after both fixed goroutines return.
func (t *TEET) startAttestationDrainLifecycle(
	ctx context.Context,
	requested <-chan struct{},
	runHeartbeat func(context.Context),
	runRefresh func(context.Context),
	reset func(),
) (context.Context, *shared.AttestationDrainController) {
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
	return heartbeatCtx, controller
}

// teetPairRegistrationQueue lets the control-channel read path publish the
// latest authenticated pair assignment without starting lifecycle goroutines.
// Notifications are coalesced; the supervisor always reads the latest pair ID.
type teetPairRegistrationQueue struct {
	mu                 sync.Mutex
	pairID             string
	changed            chan struct{}
	reregister         chan teetReregistrationRequest
	nextRegistration   uint64
	activeRegistration uint64
	activePairID       string
	cancelRegistration context.CancelFunc
}

func newTEETPairRegistrationQueue() *teetPairRegistrationQueue {
	return &teetPairRegistrationQueue{
		changed:    make(chan struct{}, 1),
		reregister: make(chan teetReregistrationRequest),
	}
}

func (q *teetPairRegistrationQueue) assign(pairID string) {
	q.mu.Lock()
	q.pairID = pairID
	if q.activeRegistration != 0 && q.activePairID != pairID {
		q.cancelRegistration()
	}
	q.mu.Unlock()
	select {
	case q.changed <- struct{}{}:
	default:
	}
}

func (q *teetPairRegistrationQueue) latest() string {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.pairID
}

// beginRegistration creates an attempt that the latest pair assignment owns.
// A newer pair cancels the context. complete atomically accepts the result only
// while that assignment still owns the attempt.
func (q *teetPairRegistrationQueue) beginRegistration(parent context.Context, pairID string) (context.Context, func() bool) {
	registrationCtx, cancel := context.WithCancel(parent)
	q.mu.Lock()
	q.nextRegistration++
	registrationID := q.nextRegistration
	if q.pairID == pairID {
		q.activeRegistration = registrationID
		q.activePairID = pairID
		q.cancelRegistration = cancel
	} else {
		cancel()
	}
	q.mu.Unlock()

	return registrationCtx, sync.OnceValue(func() bool {
		q.mu.Lock()
		current := q.activeRegistration == registrationID && q.pairID == pairID && registrationCtx.Err() == nil
		if q.activeRegistration == registrationID {
			q.activeRegistration = 0
			q.activePairID = ""
			q.cancelRegistration = nil
		}
		q.mu.Unlock()
		cancel()
		return current
	})
}

type teetReregistrationRequest struct {
	result chan error
}

// requestReregistration synchronously asks the fixed supervisor to force a
// registration of its latest pair ID. It is used by heartbeat 404 recovery so
// heartbeat code never calls the router registration function itself.
func (q *teetPairRegistrationQueue) requestReregistration(ctx context.Context) error {
	request := teetReregistrationRequest{result: make(chan error, 1)}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case q.reregister <- request:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-request.result:
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
}

type teetRouterSupervisorConfig struct {
	Requested      <-chan struct{}
	Assignments    *teetPairRegistrationQueue
	Register       func(context.Context, string) error
	RunHeartbeat   func(context.Context, func(context.Context) error)
	FatalRegister  func(context.Context, error)
	PairRegistered func(string, bool)
	RegisterFailed func(string, error)
}

// runTEETRouterSupervisor owns every pair-assignment registration and the
// lazily started heartbeat loop. The fixed outer lifecycle goroutine does not
// return until an in-flight registration and the heartbeat loop have exited,
// so the drain controller's loop acknowledgement covers both.
func runTEETRouterSupervisor(ctx context.Context, config teetRouterSupervisorConfig) {
	var heartbeatDone <-chan struct{}
	defer func() {
		if heartbeatDone != nil {
			<-heartbeatDone
		}
	}()

	registeredPair := ""
	for {
		var forced *teetReregistrationRequest
		select {
		case <-ctx.Done():
			return
		case <-config.Assignments.changed:
		case request := <-config.Assignments.reregister:
			forced = &request
		}
		if ctx.Err() != nil || attestationDrainRequested(config.Requested) {
			return
		}

		pairID := config.Assignments.latest()
		if pairID == "" {
			if forced != nil {
				forced.result <- errTEETPairIDNotKnown
			}
			continue
		}
		if forced == nil && pairID == registeredPair {
			continue
		}
		initialRegistration := registeredPair == ""
		registerCtx, completeRegistration := config.Assignments.beginRegistration(ctx, pairID)
		if registerCtx.Err() != nil {
			completeRegistration()
			if forced != nil {
				forced.result <- registerCtx.Err()
			}
			continue
		}
		err := config.Register(registerCtx, pairID)
		// Register can return concurrently with a terminal drain. Recheck both
		// signals before starting heartbeats, reporting success, or entering the
		// fatal-reset path.
		if ctx.Err() != nil || attestationDrainRequested(config.Requested) {
			completeRegistration()
			return
		}
		if forced != nil {
			if !completeRegistration() {
				forced.result <- registerCtx.Err()
				continue
			}
			forced.result <- err
			if err == nil {
				registeredPair = pairID
			}
			continue
		}
		if err != nil {
			if initialRegistration {
				if registerCtx.Err() != nil {
					completeRegistration()
					continue
				}
				config.FatalRegister(registerCtx, err)
				if ctx.Err() != nil || attestationDrainRequested(config.Requested) {
					completeRegistration()
					return
				}
				if !completeRegistration() {
					continue
				}
				return
			}
			if !completeRegistration() {
				continue
			}
			if config.RegisterFailed != nil {
				config.RegisterFailed(pairID, err)
			}
			continue
		}
		if !completeRegistration() {
			continue
		}

		registeredPair = pairID
		if config.PairRegistered != nil {
			config.PairRegistered(pairID, initialRegistration)
		}
		if heartbeatDone != nil {
			continue
		}
		// Recheck immediately before the one-shot heartbeat start. The child
		// repeats the check so cancellation between this point and scheduling
		// cannot enter RunHeartbeat after drain.
		if ctx.Err() != nil || attestationDrainRequested(config.Requested) {
			return
		}
		done := make(chan struct{})
		heartbeatDone = done
		go func() {
			defer close(done)
			if ctx.Err() != nil || attestationDrainRequested(config.Requested) {
				return
			}
			config.RunHeartbeat(ctx, config.Assignments.requestReregistration)
		}()
	}
}

func attestationDrainRequested(requested <-chan struct{}) bool {
	select {
	case <-requested:
		return true
	default:
		return false
	}
}
