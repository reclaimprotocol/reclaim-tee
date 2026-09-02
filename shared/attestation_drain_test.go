package shared

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

type drainSyncCore struct {
	zapcore.Core
	synced atomic.Bool
}

func (c *drainSyncCore) Sync() error {
	c.synced.Store(true)
	return nil
}

func TestAttestationDrainNoRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requested := make(chan struct{})
		var stopped, reset atomic.Int32
		controller := newTestAttestationDrain(requested, time.Now().Add(time.Hour),
			func() int { return 0 },
			func() <-chan struct{} {
				stopped.Add(1)
				return stoppedTestLoops()
			},
			func() { reset.Add(1) }, nil)
		ctx, cancel := context.WithCancel(t.Context())
		done := runTestAttestationDrain(controller, ctx)

		synctest.Wait()
		if controller.IsDraining() {
			t.Fatal("controller started draining without a request")
		}
		if got := stopped.Load(); got != 0 {
			t.Fatalf("stop calls without a request = %d, want 0", got)
		}
		if got := reset.Load(); got != 0 {
			t.Fatalf("reset calls without a request = %d, want 0", got)
		}

		cancel()
		synctest.Wait()
		<-done
	})
}

func TestAttestationDrainClosedRequestRejectsAdmissionBeforeRun(t *testing.T) {
	requested := make(chan struct{})
	var stopped, reset atomic.Int32
	controller := newTestAttestationDrain(requested, time.Now().Add(time.Hour),
		func() int { return 0 },
		func() <-chan struct{} {
			stopped.Add(1)
			return stoppedTestLoops()
		},
		func() { reset.Add(1) }, nil)

	close(requested)
	release, ok := controller.BeginAdmission()
	if ok || release != nil {
		t.Fatal("admission succeeded after the request channel closed")
	}
	if !controller.IsDraining() {
		t.Fatal("closed request did not make admission state sticky")
	}
	if got := stopped.Load(); got != 0 {
		t.Fatalf("stop calls before Run = %d, want 0", got)
	}
	if got := reset.Load(); got != 0 {
		t.Fatalf("reset calls before Run = %d, want 0", got)
	}
}

func TestAttestationDrainClosesAdmissionBeforeRequestingLoopStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requested := make(chan struct{})
		stopEntered := make(chan struct{})
		loopsDone := make(chan struct{})
		controller := newTestAttestationDrain(requested, time.Now().Add(time.Hour),
			func() int { return 1 },
			func() <-chan struct{} {
				close(stopEntered)
				return loopsDone
			}, func() {}, nil)
		ctx, cancel := context.WithCancel(t.Context())
		done := runTestAttestationDrain(controller, ctx)

		close(requested)
		synctest.Wait()
		<-stopEntered
		if !controller.IsDraining() {
			t.Fatal("controller was not draining when loop cancellation was requested")
		}
		if release, ok := controller.BeginAdmission(); ok || release != nil {
			t.Fatal("admission succeeded after drain began")
		}

		close(loopsDone)
		synctest.Wait()
		cancel()
		synctest.Wait()
		<-done
	})
}

func TestAttestationDrainReservationPreventsZeroRace(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requested := make(chan struct{})
		reset := make(chan struct{}, 1)
		controller := newTestAttestationDrain(requested, time.Now().Add(time.Hour),
			func() int { return 0 }, stoppedTestLoops,
			func() { reset <- struct{}{} }, nil)
		release, ok := controller.BeginAdmission()
		if !ok {
			t.Fatal("admission was rejected before drain")
		}
		done := runTestAttestationDrain(controller, t.Context())

		close(requested)
		synctest.Wait()
		select {
		case <-reset:
			t.Fatal("reset occurred while an admission was reserved")
		default:
		}

		release()
		release()
		synctest.Wait()
		<-reset
		<-done
	})
}

func TestAttestationDrainReleaseIsIdempotent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requested := make(chan struct{})
		var reset atomic.Int32
		controller := newTestAttestationDrain(requested, time.Now().Add(time.Hour),
			func() int { return 0 }, stoppedTestLoops, func() { reset.Add(1) }, nil)
		release, ok := controller.BeginAdmission()
		if !ok {
			t.Fatal("admission was rejected before drain")
		}
		release()
		release()
		done := runTestAttestationDrain(controller, t.Context())

		close(requested)
		synctest.Wait()
		<-done
		if got := reset.Load(); got != 1 {
			t.Fatalf("reset calls after duplicate release = %d, want 1", got)
		}
	})
}

func TestAttestationDrainActiveSessionCompletionTriggersReset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requested := make(chan struct{})
		expiry := time.Now().Add(time.Hour)
		var active atomic.Int32
		active.Store(1)
		reset := make(chan struct{}, 1)
		core, observed := observer.New(zap.DebugLevel)
		logger := &Logger{Logger: zap.New(core)}
		controller := newTestAttestationDrain(requested, expiry,
			func() int { return int(active.Load()) }, stoppedTestLoops,
			func() { reset <- struct{}{} }, logger)
		done := runTestAttestationDrain(controller, t.Context())

		close(requested)
		synctest.Wait()
		select {
		case <-reset:
			t.Fatal("reset occurred while a session was active")
		default:
		}
		active.Store(0)
		controller.SessionCountChanged()
		synctest.Wait()

		<-reset
		<-done
		for _, message := range []string{
			"attestation drain started",
			"attestation drain loop cancellation requested",
			"attestation drain loops stopped",
			"attestation drain waiting for sessions",
			"attestation drain attempting VM reset",
		} {
			if got := observed.FilterMessage(message).Len(); got == 0 {
				t.Errorf("log %q was not emitted", message)
			}
		}
		startedLogs := observed.FilterMessage("attestation drain started").All()
		if len(startedLogs) == 0 {
			t.Fatal("drain-start log was not emitted")
		}
		if got := startedLogs[0].ContextMap()["cached_attestation_expiry"]; got != expiry.UTC().Format(time.RFC3339Nano) {
			t.Errorf("cached_attestation_expiry log field = %v, want UTC RFC3339Nano", got)
		}
	})
}

func TestAttestationDrainExpiryForcesResetWithBlockedLoopsAndWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requested := make(chan struct{})
		loopsDone := make(chan struct{})
		var reset atomic.Int32
		controller := newTestAttestationDrain(requested, time.Now().Add(5*time.Minute),
			func() int { return 1 }, func() <-chan struct{} { return loopsDone },
			func() { reset.Add(1) }, nil)
		_, ok := controller.BeginAdmission()
		if !ok {
			t.Fatal("admission was rejected before drain")
		}
		done := runTestAttestationDrain(controller, t.Context())

		close(requested)
		synctest.Wait()
		if got := reset.Load(); got != 0 {
			t.Fatalf("reset calls before expiry = %d, want 0", got)
		}
		synctest.Sleep(5 * time.Minute)
		synctest.Wait()

		if got := reset.Load(); got != 1 {
			t.Fatalf("reset calls at expiry = %d, want 1", got)
		}
		<-done
	})
}

func TestAttestationDrainNilLoopAcknowledgmentWaitsForExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requested := make(chan struct{})
		var reset atomic.Int32
		core, observed := observer.New(zap.DebugLevel)
		logger := &Logger{Logger: zap.New(core)}
		controller := newTestAttestationDrain(requested, time.Now().Add(5*time.Minute),
			func() int { return 0 }, func() <-chan struct{} { return nil },
			func() { reset.Add(1) }, logger)
		done := runTestAttestationDrain(controller, t.Context())

		close(requested)
		synctest.Wait()
		if got := reset.Load(); got != 0 {
			t.Fatalf("reset calls without loop acknowledgment before expiry = %d, want 0", got)
		}
		if got := observed.FilterMessage("attestation drain loop stop acknowledgment unavailable").Len(); got != 1 {
			t.Fatalf("missing-acknowledgment log count = %d, want 1", got)
		}

		synctest.Sleep(5 * time.Minute)
		synctest.Wait()
		<-done
		if got := reset.Load(); got != 1 {
			t.Fatalf("reset calls without loop acknowledgment at expiry = %d, want 1", got)
		}
	})
}

func TestAttestationDrainMissingOrPastExpiryDoesNotWaitForLoopAcknowledgment(t *testing.T) {
	for _, test := range []struct {
		name   string
		expiry func() time.Time
	}{
		{name: "missing", expiry: func() time.Time { return time.Time{} }},
		{name: "past", expiry: func() time.Time { return time.Now().Add(-time.Second) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				requested := make(chan struct{})
				loopsDone := make(chan struct{})
				var stopCalled atomic.Bool
				var resetBeforeStop atomic.Bool
				var resetCalls atomic.Int32
				controller := newTestAttestationDrain(requested, test.expiry(),
					func() int { return 1 },
					func() <-chan struct{} {
						stopCalled.Store(true)
						return loopsDone
					},
					func() {
						resetCalls.Add(1)
						if !stopCalled.Load() {
							resetBeforeStop.Store(true)
						}
					}, nil)
				done := runTestAttestationDrain(controller, t.Context())

				close(requested)
				synctest.Wait()
				<-done
				if resetBeforeStop.Load() {
					t.Fatal("reset occurred before loop cancellation was requested")
				}
				if got := resetCalls.Load(); got != 1 {
					t.Fatalf("reset calls without loop acknowledgment = %d, want 1", got)
				}
			})
		})
	}
}

func TestAttestationDrainSnapshotsExpiryAtDrainStart(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requested := make(chan struct{})
		expiry := time.Now().Add(5 * time.Minute)
		var reset atomic.Int32
		controller := NewAttestationDrainController(AttestationDrainConfig{
			Requested:               requested,
			StopLoops:               stoppedTestLoops,
			CachedAttestationExpiry: func() time.Time { return expiry },
			ActiveSessions:          func() int { return 1 },
			Reset:                   func() { reset.Add(1) },
		})
		done := runTestAttestationDrain(controller, t.Context())

		close(requested)
		synctest.Wait()
		expiry = time.Now().Add(time.Hour)
		synctest.Sleep(5 * time.Minute)
		synctest.Wait()
		<-done

		if got := reset.Load(); got != 1 {
			t.Fatalf("reset calls at snapshotted expiry = %d, want 1", got)
		}
	})
}

func TestAttestationDrainExpiryCallbackMayReenterController(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requested := make(chan struct{})
		var controller *AttestationDrainController
		var observedDraining atomic.Bool
		var stopCalled, observedStopCalled atomic.Bool
		controller = NewAttestationDrainController(AttestationDrainConfig{
			Requested: requested,
			StopLoops: func() <-chan struct{} {
				stopCalled.Store(true)
				return stoppedTestLoops()
			},
			CachedAttestationExpiry: func() time.Time {
				observedDraining.Store(controller.IsDraining())
				observedStopCalled.Store(stopCalled.Load())
				return time.Time{}
			},
			ActiveSessions: func() int { return 0 },
			Reset:          func() {},
		})
		done := runTestAttestationDrain(controller, t.Context())

		close(requested)
		synctest.Wait()
		<-done
		if !observedDraining.Load() {
			t.Fatal("expiry callback did not observe the completed drain transition")
		}
		if !observedStopCalled.Load() {
			t.Fatal("loop cancellation was not requested before the expiry callback")
		}
	})
}

func TestAttestationDrainNotificationsDoNotDuplicateReset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requested := make(chan struct{})
		var active atomic.Int32
		active.Store(1)
		var reset atomic.Int32
		controller := newTestAttestationDrain(requested, time.Now().Add(time.Hour),
			func() int { return int(active.Load()) }, stoppedTestLoops,
			func() { reset.Add(1) }, nil)
		done := runTestAttestationDrain(controller, t.Context())

		close(requested)
		synctest.Wait()
		controller.SessionCountChanged()
		controller.SessionCountChanged()
		active.Store(0)
		controller.SessionCountChanged()
		controller.SessionCountChanged()
		synctest.Wait()
		<-done
		controller.SessionCountChanged()

		if got := reset.Load(); got != 1 {
			t.Fatalf("reset calls after repeated notifications = %d, want 1", got)
		}
	})
}

func TestAttestationDrainResetReturnLeavesAdmissionClosed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requested := make(chan struct{})
		var reset atomic.Int32
		controller := newTestAttestationDrain(requested, time.Now().Add(time.Hour),
			func() int { return 0 }, stoppedTestLoops, func() { reset.Add(1) }, nil)
		done := runTestAttestationDrain(controller, t.Context())

		close(requested)
		synctest.Wait()
		<-done
		if got := reset.Load(); got != 1 {
			t.Fatalf("reset calls = %d, want 1", got)
		}
		if !controller.IsDraining() {
			t.Fatal("controller reopened after reset returned")
		}
		if release, ok := controller.BeginAdmission(); ok || release != nil {
			t.Fatal("admission reopened after reset returned")
		}
	})
}

func TestAttestationDrainFlushesLoggerBeforeReset(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requested := make(chan struct{})
		observedCore, _ := observer.New(zap.DebugLevel)
		core := &drainSyncCore{Core: observedCore}
		logger := &Logger{Logger: zap.New(core)}
		var resetSawSync atomic.Bool
		controller := newTestAttestationDrain(requested, time.Now().Add(time.Hour),
			func() int { return 0 }, stoppedTestLoops,
			func() { resetSawSync.Store(core.synced.Load()) }, logger)
		done := runTestAttestationDrain(controller, t.Context())

		close(requested)
		synctest.Wait()
		<-done
		if !resetSawSync.Load() {
			t.Fatal("reset callback ran before logger Sync")
		}
	})
}

func TestAttestationDrainContextCancellationAfterDrain(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		requested := make(chan struct{})
		var reset atomic.Int32
		controller := newTestAttestationDrain(requested, time.Now().Add(time.Hour),
			func() int { return 1 }, stoppedTestLoops, func() { reset.Add(1) }, nil)
		ctx, cancel := context.WithCancel(t.Context())
		done := runTestAttestationDrain(controller, ctx)

		close(requested)
		synctest.Wait()
		cancel()
		synctest.Wait()
		<-done

		if got := reset.Load(); got != 0 {
			t.Fatalf("reset calls after process context cancellation = %d, want 0", got)
		}
		if !controller.IsDraining() {
			t.Fatal("controller reopened after process context cancellation")
		}
		if release, ok := controller.BeginAdmission(); ok || release != nil {
			t.Fatal("admission reopened after process context cancellation")
		}
	})
}

func TestAttestationDrainRejectsNilRequested(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("constructor accepted a nil Requested channel")
		}
	}()
	NewAttestationDrainController(AttestationDrainConfig{
		StopLoops:               stoppedTestLoops,
		CachedAttestationExpiry: func() time.Time { return time.Time{} },
		ActiveSessions:          func() int { return 0 },
		Reset:                   func() {},
	})
}

func TestAttestationDrainDefaultsResetCallback(t *testing.T) {
	requested := make(chan struct{})
	controller := NewAttestationDrainController(AttestationDrainConfig{
		Requested:               requested,
		StopLoops:               stoppedTestLoops,
		CachedAttestationExpiry: func() time.Time { return time.Time{} },
		ActiveSessions:          func() int { return 0 },
	})
	if controller.reset == nil {
		t.Fatal("constructor did not install the platform reset callback")
	}
}

func newTestAttestationDrain(
	requested <-chan struct{},
	expiry time.Time,
	activeSessions func() int,
	stopLoops func() <-chan struct{},
	reset func(),
	logger *Logger,
) *AttestationDrainController {
	return NewAttestationDrainController(AttestationDrainConfig{
		Requested:               requested,
		StopLoops:               stopLoops,
		CachedAttestationExpiry: func() time.Time { return expiry },
		ActiveSessions:          activeSessions,
		Reset:                   reset,
		Logger:                  logger,
	})
}

func stoppedTestLoops() <-chan struct{} {
	done := make(chan struct{})
	close(done)
	return done
}

func runTestAttestationDrain(controller *AttestationDrainController, ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		controller.Run(ctx)
		close(done)
	}()
	return done
}
