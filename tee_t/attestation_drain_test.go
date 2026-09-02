package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func TestTEETRejectsNewSessionCreatedAfterDrainRequest(t *testing.T) {
	requested := make(chan struct{})
	teet := newTEETForDrainTest()
	teet.attestDrain = newTEETDrainControllerForTest(teet, requested, closedDrainLoopsForTest(), func() {})

	close(requested)
	if _, err := teet.registerSessionForControl("session-after-drain", 1); !errors.Is(err, errAttestationDraining) {
		t.Fatalf("registerSessionForControl error = %v, want %v", err, errAttestationDraining)
	}
	if got := teet.ActiveSessions(); got != 0 {
		t.Fatalf("active sessions after rejected SessionCreated = %d, want 0", got)
	}
}

func TestTEETExistingRegisteredSessionCanActivateDuringDrain(t *testing.T) {
	requested := make(chan struct{})
	teet := newTEETForDrainTest()
	teet.attestDrain = newTEETDrainControllerForTest(teet, requested, closedDrainLoopsForTest(), func() {})
	session, err := teet.registerSessionForControl("existing-session", 1)
	if err != nil {
		t.Fatalf("registerSessionForControl: %v", err)
	}

	close(requested)
	if err := teet.sessionManager.ActivateSessionIfCurrent(session, nil); err != nil {
		t.Fatalf("activate existing registered session during drain: %v", err)
	}
	if session.State != shared.SessionStateActive {
		t.Fatalf("existing session state = %v, want active", session.State)
	}
	teet.cleanupSessionWithSession(session)
}

func TestTEETRegistrationReturnAfterDrainDoesNotStartHeartbeatOrFatalReset(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "success"},
		{name: "failure", err: errors.New("registration failed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requested := make(chan struct{})
			assignments := newTEETPairRegistrationQueue()
			registerStarted := make(chan struct{})
			releaseRegister := make(chan struct{})
			reset := make(chan struct{}, 1)
			var heartbeatRuns atomic.Int32
			var fatalResets atomic.Int32
			teet := newTEETForDrainTest()
			teet.attestationMutex.Lock()
			teet.attestationExpiry = time.Now().Add(time.Hour)
			teet.attestationMutex.Unlock()
			rootCtx, cancelRoot := context.WithCancel(t.Context())
			defer cancelRoot()

			teet.startAttestationDrainLifecycle(
				rootCtx,
				requested,
				func(ctx context.Context) {
					runTEETRouterSupervisor(ctx, teetRouterSupervisorConfig{
						Requested:   requested,
						Assignments: assignments,
						Register: func(context.Context, string) error {
							close(registerStarted)
							<-releaseRegister
							return tc.err
						},
						RunHeartbeat: func(context.Context, func(context.Context) error) { heartbeatRuns.Add(1) },
						FatalRegister: func(context.Context, error) {
							fatalResets.Add(1)
						},
					})
				},
				func(ctx context.Context) { <-ctx.Done() },
				func() { reset <- struct{}{} },
			)
			assignments.assign("pair-a")
			waitForTEETTestSignal(t, registerStarted, "initial registration start")

			close(requested)
			select {
			case <-reset:
				t.Fatal("reset ran before blocked registration returned")
			default:
			}
			close(releaseRegister)
			waitForTEETTestSignal(t, reset, "reset after registration exit")

			if got := heartbeatRuns.Load(); got != 0 {
				t.Fatalf("heartbeat runs after drain = %d, want 0", got)
			}
			if got := fatalResets.Load(); got != 0 {
				t.Fatalf("fatal resets after drain = %d, want 0", got)
			}
			if rootCtx.Err() != nil {
				t.Fatal("drain canceled the router-mode root context")
			}
		})
	}
}

func TestTEETDrainCancelsFatalRegistrationDelay(t *testing.T) {
	requested := make(chan struct{})
	assignments := newTEETPairRegistrationQueue()
	fatalStarted := make(chan struct{})
	fatalCanceled := make(chan struct{})
	reset := make(chan struct{}, 1)
	teet := newTEETForDrainTest()
	teet.attestationMutex.Lock()
	teet.attestationExpiry = time.Now().Add(time.Hour)
	teet.attestationMutex.Unlock()
	rootCtx, cancelRoot := context.WithCancel(t.Context())
	defer cancelRoot()

	teet.startAttestationDrainLifecycle(
		rootCtx,
		requested,
		func(ctx context.Context) {
			runTEETRouterSupervisor(ctx, teetRouterSupervisorConfig{
				Requested:    requested,
				Assignments:  assignments,
				Register:     func(context.Context, string) error { return errors.New("registration failed") },
				RunHeartbeat: func(context.Context, func(context.Context) error) { t.Error("unexpected heartbeat") },
				FatalRegister: func(fatalCtx context.Context, _ error) {
					close(fatalStarted)
					<-fatalCtx.Done()
					close(fatalCanceled)
				},
			})
		},
		func(ctx context.Context) { <-ctx.Done() },
		func() { reset <- struct{}{} },
	)
	assignments.assign("pair-a")
	waitForTEETTestSignal(t, fatalStarted, "fatal registration delay start")

	close(requested)
	waitForTEETTestSignal(t, fatalCanceled, "fatal registration delay cancellation")
	waitForTEETTestSignal(t, reset, "drain reset")
	if rootCtx.Err() != nil {
		t.Fatal("drain canceled the router-mode root context")
	}
}

func TestTEETPairChangeCancelsInitialRegistrationRetry(t *testing.T) {
	requested := make(chan struct{})
	assignments := newTEETPairRegistrationQueue()
	pairAStarted := make(chan struct{})
	pairACanceled := make(chan struct{})
	pairRegistered := make(chan string, 1)
	heartbeatStarted := make(chan struct{})
	var fatalCalls atomic.Int32
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		runTEETRouterSupervisor(ctx, teetRouterSupervisorConfig{
			Requested:   requested,
			Assignments: assignments,
			Register: func(registerCtx context.Context, pairID string) error {
				if pairID == "pair-a" {
					close(pairAStarted)
					<-registerCtx.Done()
					close(pairACanceled)
					return registerCtx.Err()
				}
				return nil
			},
			RunHeartbeat: func(heartbeatCtx context.Context, _ func(context.Context) error) {
				close(heartbeatStarted)
				<-heartbeatCtx.Done()
			},
			FatalRegister: func(context.Context, error) { fatalCalls.Add(1) },
			PairRegistered: func(pairID string, _ bool) {
				pairRegistered <- pairID
			},
		})
		close(done)
	}()

	assignments.assign("pair-a")
	waitForTEETTestSignal(t, pairAStarted, "pair A registration retry")
	assignments.assign("pair-b")
	waitForTEETTestSignal(t, pairACanceled, "pair A registration cancellation")
	if got := waitForTEETTestValue(t, pairRegistered, "pair B registration"); got != "pair-b" {
		t.Fatalf("registered pair = %q, want pair-b", got)
	}
	waitForTEETTestSignal(t, heartbeatStarted, "heartbeat after pair B registration")
	if got := fatalCalls.Load(); got != 0 {
		t.Fatalf("fatal registration calls = %d, want 0", got)
	}

	cancel()
	waitForTEETTestSignal(t, done, "supervisor exit")
}

func TestTEETPairChangeCancelsInitialFatalDelay(t *testing.T) {
	requested := make(chan struct{})
	assignments := newTEETPairRegistrationQueue()
	fatalStarted := make(chan struct{})
	fatalCanceled := make(chan struct{})
	pairRegistered := make(chan string, 1)
	heartbeatStarted := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		runTEETRouterSupervisor(ctx, teetRouterSupervisorConfig{
			Requested:   requested,
			Assignments: assignments,
			Register: func(_ context.Context, pairID string) error {
				if pairID == "pair-a" {
					return errors.New("pair A registration failed")
				}
				return nil
			},
			RunHeartbeat: func(heartbeatCtx context.Context, _ func(context.Context) error) {
				close(heartbeatStarted)
				<-heartbeatCtx.Done()
			},
			FatalRegister: func(fatalCtx context.Context, _ error) {
				close(fatalStarted)
				<-fatalCtx.Done()
				close(fatalCanceled)
			},
			PairRegistered: func(pairID string, _ bool) {
				pairRegistered <- pairID
			},
		})
		close(done)
	}()

	assignments.assign("pair-a")
	waitForTEETTestSignal(t, fatalStarted, "pair A fatal delay")
	assignments.assign("pair-b")
	waitForTEETTestSignal(t, fatalCanceled, "pair A fatal delay cancellation")
	if got := waitForTEETTestValue(t, pairRegistered, "pair B registration"); got != "pair-b" {
		t.Fatalf("registered pair = %q, want pair-b", got)
	}
	waitForTEETTestSignal(t, heartbeatStarted, "heartbeat after pair B registration")

	cancel()
	waitForTEETTestSignal(t, done, "supervisor exit")
}

func TestTEETDrainWaitsForPairChangeRegistration(t *testing.T) {
	requested := make(chan struct{})
	assignments := newTEETPairRegistrationQueue()
	heartbeatStarted := make(chan struct{})
	secondRegisterStarted := make(chan struct{})
	secondRegisterCanceled := make(chan struct{})
	releaseSecondRegister := make(chan struct{})
	routerWrite := make(chan struct{})
	reset := make(chan struct{}, 1)
	var registerCalls atomic.Int32
	var postDrainRegistrations atomic.Int32
	teet := newTEETForDrainTest()
	teet.attestationMutex.Lock()
	teet.attestationExpiry = time.Now().Add(time.Hour)
	teet.attestationMutex.Unlock()
	rootCtx, cancelRoot := context.WithCancel(t.Context())
	defer cancelRoot()

	teet.startAttestationDrainLifecycle(
		rootCtx,
		requested,
		func(ctx context.Context) {
			runTEETRouterSupervisor(ctx, teetRouterSupervisorConfig{
				Requested:   requested,
				Assignments: assignments,
				Register: func(registerCtx context.Context, _ string) error {
					if registerCalls.Add(1) == 1 {
						return nil
					}
					close(secondRegisterStarted)
					<-registerCtx.Done()
					close(secondRegisterCanceled)
					<-releaseSecondRegister
					// Model a router liveness write at the end of a request that did
					// not return promptly when its context was canceled.
					close(routerWrite)
					return nil
				},
				RunHeartbeat: func(heartbeatCtx context.Context, _ func(context.Context) error) {
					close(heartbeatStarted)
					<-heartbeatCtx.Done()
				},
				FatalRegister: func(context.Context, error) {
					t.Error("unexpected fatal reset")
				},
				PairRegistered: func(_ string, initial bool) {
					if !initial {
						postDrainRegistrations.Add(1)
					}
				},
			})
		},
		func(ctx context.Context) { <-ctx.Done() },
		func() { reset <- struct{}{} },
	)
	assignments.assign("pair-a")
	waitForTEETTestSignal(t, heartbeatStarted, "heartbeat start")
	assignments.assign("pair-b")
	waitForTEETTestSignal(t, secondRegisterStarted, "pair-change registration start")

	close(requested)
	waitForTEETTestSignal(t, secondRegisterCanceled, "pair-change registration cancellation")
	select {
	case <-reset:
		t.Fatal("reset ran while pair-change registration was still in flight")
	default:
	}
	close(releaseSecondRegister)
	waitForTEETTestSignal(t, routerWrite, "in-flight router write")
	waitForTEETTestSignal(t, reset, "reset after pair-change registration exit")
	if got := postDrainRegistrations.Load(); got != 0 {
		t.Fatalf("pair registrations reported after drain = %d, want 0", got)
	}
	if rootCtx.Err() != nil {
		t.Fatal("drain canceled the router-mode root context")
	}
}

func TestTEETHeartbeatReregistrationSerializesPairChangeAndDrain(t *testing.T) {
	requested := make(chan struct{})
	assignments := newTEETPairRegistrationQueue()
	heartbeatStarted := make(chan struct{})
	forcedRegisterStarted := make(chan struct{})
	forcedRegisterCanceled := make(chan struct{})
	releaseForcedRegister := make(chan struct{})
	heartbeatRequestReturned := make(chan error, 1)
	reset := make(chan struct{}, 1)
	var registerCalls atomic.Int32
	var concurrentRegisters atomic.Int32
	var inFlight atomic.Int32
	teet := newTEETForDrainTest()
	teet.attestationMutex.Lock()
	teet.attestationExpiry = time.Now().Add(time.Hour)
	teet.attestationMutex.Unlock()
	rootCtx, cancelRoot := context.WithCancel(t.Context())
	defer cancelRoot()

	teet.startAttestationDrainLifecycle(
		rootCtx,
		requested,
		func(ctx context.Context) {
			runTEETRouterSupervisor(ctx, teetRouterSupervisorConfig{
				Requested:   requested,
				Assignments: assignments,
				Register: func(registerCtx context.Context, _ string) error {
					if inFlight.Add(1) != 1 {
						concurrentRegisters.Add(1)
					}
					defer inFlight.Add(-1)
					if registerCalls.Add(1) == 1 {
						return nil
					}
					close(forcedRegisterStarted)
					<-registerCtx.Done()
					close(forcedRegisterCanceled)
					<-releaseForcedRegister
					return nil
				},
				RunHeartbeat: func(heartbeatCtx context.Context, requestReregistration func(context.Context) error) {
					close(heartbeatStarted)
					heartbeatRequestReturned <- requestReregistration(heartbeatCtx)
				},
				FatalRegister: func(context.Context, error) { t.Error("unexpected fatal reset") },
			})
		},
		func(ctx context.Context) { <-ctx.Done() },
		func() { reset <- struct{}{} },
	)
	assignments.assign("pair-a")
	waitForTEETTestSignal(t, heartbeatStarted, "heartbeat start")
	waitForTEETTestSignal(t, forcedRegisterStarted, "heartbeat 404 re-registration start")
	// A new authenticated pair arrives while the supervisor owns the forced
	// same-pair registration. It must queue, not register concurrently.
	assignments.assign("pair-b")
	if got := concurrentRegisters.Load(); got != 0 {
		t.Fatalf("concurrent router registrations = %d, want 0", got)
	}

	close(requested)
	waitForTEETTestSignal(t, forcedRegisterCanceled, "heartbeat re-registration cancellation")
	if err := waitForTEETTestValue(t, heartbeatRequestReturned, "heartbeat re-registration return"); !errors.Is(err, context.Canceled) {
		t.Fatalf("heartbeat re-registration error = %v, want context canceled", err)
	}
	select {
	case <-reset:
		t.Fatal("reset ran while heartbeat re-registration was still in flight")
	default:
	}
	close(releaseForcedRegister)
	waitForTEETTestSignal(t, reset, "reset after heartbeat re-registration exit")
	if got := registerCalls.Load(); got != 2 {
		t.Fatalf("router registration calls = %d, want initial plus forced same-pair", got)
	}
	if got := concurrentRegisters.Load(); got != 0 {
		t.Fatalf("concurrent router registrations = %d, want 0", got)
	}
	if got := inFlight.Load(); got != 0 {
		t.Fatalf("in-flight router registrations after reset acknowledgment = %d, want 0", got)
	}
	if rootCtx.Err() != nil {
		t.Fatal("drain canceled the router-mode root context")
	}
}

func TestTEETRouterSupervisorRegistersLatestPairChanges(t *testing.T) {
	requested := make(chan struct{})
	assignments := newTEETPairRegistrationQueue()
	secondRegisterStarted := make(chan struct{})
	releaseSecondRegister := make(chan struct{})
	registered := make(chan string, 3)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		runTEETRouterSupervisor(ctx, teetRouterSupervisorConfig{
			Requested:   requested,
			Assignments: assignments,
			Register: func(_ context.Context, pairID string) error {
				if pairID == "pair-b" {
					close(secondRegisterStarted)
					<-releaseSecondRegister
				}
				registered <- pairID
				return nil
			},
			RunHeartbeat:  func(heartbeatCtx context.Context, _ func(context.Context) error) { <-heartbeatCtx.Done() },
			FatalRegister: func(context.Context, error) { t.Error("unexpected fatal reset") },
		})
		close(done)
	}()
	assignments.assign("pair-a")
	if got := waitForTEETTestValue(t, registered, "initial registration"); got != "pair-a" {
		t.Fatalf("initial registered pair = %q, want pair-a", got)
	}
	assignments.assign("pair-b")
	waitForTEETTestSignal(t, secondRegisterStarted, "second registration start")
	assignments.assign("pair-c")
	close(releaseSecondRegister)
	if got := waitForTEETTestValue(t, registered, "second registration"); got != "pair-b" {
		t.Fatalf("second registered pair = %q, want pair-b", got)
	}
	if got := waitForTEETTestValue(t, registered, "latest registration"); got != "pair-c" {
		t.Fatalf("latest registered pair = %q, want pair-c", got)
	}
	cancel()
	waitForTEETTestSignal(t, done, "supervisor exit")
}

func TestTEETRouterSupervisorDoesNotStartAfterRootCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	assignments := newTEETPairRegistrationQueue()
	var registerCalls atomic.Int32
	done := make(chan struct{})
	cancel()
	assignments.assign("pair-a")
	go func() {
		runTEETRouterSupervisor(ctx, teetRouterSupervisorConfig{
			Requested:   make(chan struct{}),
			Assignments: assignments,
			Register: func(context.Context, string) error {
				registerCalls.Add(1)
				return nil
			},
			RunHeartbeat:  func(context.Context, func(context.Context) error) { t.Error("unexpected heartbeat") },
			FatalRegister: func(context.Context, error) { t.Error("unexpected fatal reset") },
		})
		close(done)
	}()
	waitForTEETTestSignal(t, done, "supervisor exit")
	if got := registerCalls.Load(); got != 0 {
		t.Fatalf("registrations after root cancellation = %d, want 0", got)
	}
}

func TestTEETCachedAttestationExpiryConcurrentReadWrite(t *testing.T) {
	teet := &TEET{}
	start := make(chan struct{})
	const iterations = 1_000
	var workers sync.WaitGroup
	workers.Go(func() {
		<-start
		for i := range iterations {
			teet.attestationMutex.Lock()
			teet.attestationExpiry = time.Unix(int64(i+1), 0)
			teet.attestationMutex.Unlock()
		}
	})
	for range 4 {
		workers.Go(func() {
			<-start
			for range iterations {
				_ = teet.cachedAttestationExpiry()
			}
		})
	}
	close(start)
	workers.Wait()
	want := time.Unix(iterations, 0)
	if expiry := teet.cachedAttestationExpiry(); !expiry.Equal(want) {
		t.Fatalf("final cached attestation expiry = %s, want %s", expiry, want)
	}
}

func TestTEETStandaloneAdmissionIsNilSafe(t *testing.T) {
	teet := &TEET{}
	release, ok := teet.beginSessionAdmission()
	if !ok || release == nil {
		t.Fatal("standalone TEE_T admission was not allowed")
	}
	release()
	release()
}

func newTEETForDrainTest() *TEET {
	logger := shared.NewNopLogger()
	manager := NewTEETSessionManager()
	manager.SetLogger(logger)
	return &TEET{
		sessionManager:    manager,
		logger:            logger,
		sessionTerminator: shared.NewSessionTerminator(logger),
	}
}

func newTEETDrainControllerForTest(teet *TEET, requested <-chan struct{}, loopsDone <-chan struct{}, reset func()) *shared.AttestationDrainController {
	teet.attestationMutex.Lock()
	teet.attestationExpiry = time.Now().Add(time.Hour)
	teet.attestationMutex.Unlock()
	return shared.NewAttestationDrainController(shared.AttestationDrainConfig{
		Requested:               requested,
		StopLoops:               func() <-chan struct{} { return loopsDone },
		CachedAttestationExpiry: teet.cachedAttestationExpiry,
		ActiveSessions:          teet.ActiveSessions,
		Reset:                   reset,
		Logger:                  teet.logger,
	})
}

func closedDrainLoopsForTest() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}

func waitForTEETTestSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func waitForTEETTestValue[T any](t *testing.T, values <-chan T, description string) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
		var zero T
		return zero
	}
}
