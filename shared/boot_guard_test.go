//go:build !mobile

package shared

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestBootGuardMarkReadyDisarms(t *testing.T) {
	b := NewBootGuard(nil, time.Hour)
	b.MarkReady()
	select {
	case <-b.done:
	default:
		t.Fatal("MarkReady did not disarm the guard")
	}
}

func TestBootGuardMarkReadyIdempotent(t *testing.T) {
	b := NewBootGuard(nil, time.Hour)
	b.MarkReady()
	b.MarkReady() // must not panic on double close
}

func TestBootGuardNilSafe(t *testing.T) {
	var b *BootGuard
	b.MarkReady()
}

// Off SEV-SNP the guard must never arm: a dev-only path that forgets
// MarkReady would otherwise take down a workstation process.
func TestBootGuardInertOutsideSEVSNP(t *testing.T) {
	if IsSEVSNPMode() {
		t.Skip("host is SEV-SNP")
	}
	b := NewBootGuard(nil, time.Nanosecond)
	time.Sleep(20 * time.Millisecond)
	select {
	case <-b.done:
		t.Fatal("guard armed outside SEV-SNP mode")
	default:
	}
}

func TestFatalBootResetContextCanceledBeforeDelay(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	var platformChecks atomic.Int32
	var delayCalls atomic.Int32
	var resetCalls atomic.Int32

	fatalBootResetContext(ctx, nil, errors.New("test failure"), fatalBootResetOperations{
		isSEVSNP: func() bool {
			platformChecks.Add(1)
			cancel()
			return true
		},
		waitDelay: func(context.Context) bool {
			delayCalls.Add(1)
			return true
		},
		reset: func(*Logger) { resetCalls.Add(1) },
		exit:  func(int) { t.Error("unexpected process exit") },
	})

	if got := platformChecks.Load(); got != 1 {
		t.Fatalf("platform checks before cancellation = %d, want 1", got)
	}
	if got := delayCalls.Load(); got != 0 {
		t.Fatalf("delay calls after prior cancellation = %d, want 0", got)
	}
	if got := resetCalls.Load(); got != 0 {
		t.Fatalf("reset calls after prior cancellation = %d, want 0", got)
	}
}

func TestFatalBootResetContextCanceledDuringDelay(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	delayStarted := make(chan struct{})
	done := make(chan struct{})
	var resetCalls atomic.Int32
	go func() {
		fatalBootResetContext(ctx, nil, errors.New("test failure"), fatalBootResetOperations{
			isSEVSNP: func() bool { return true },
			waitDelay: func(delayCtx context.Context) bool {
				close(delayStarted)
				<-delayCtx.Done()
				return false
			},
			reset: func(*Logger) { resetCalls.Add(1) },
			exit:  func(int) { t.Error("unexpected process exit") },
		})
		close(done)
	}()
	<-delayStarted
	cancel()
	<-done
	if got := resetCalls.Load(); got != 0 {
		t.Fatalf("reset calls after cancellation during delay = %d, want 0", got)
	}
}

func TestFatalBootResetContextCanceledImmediatelyBeforeReset(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	delayElapsed := make(chan struct{})
	releaseDelay := make(chan struct{})
	done := make(chan struct{})
	var resetCalls atomic.Int32
	go func() {
		fatalBootResetContext(ctx, nil, errors.New("test failure"), fatalBootResetOperations{
			isSEVSNP: func() bool { return true },
			waitDelay: func(context.Context) bool {
				close(delayElapsed)
				<-releaseDelay
				return true
			},
			reset: func(*Logger) { resetCalls.Add(1) },
			exit:  func(int) { t.Error("unexpected process exit") },
		})
		close(done)
	}()
	<-delayElapsed
	cancel()
	close(releaseDelay)
	<-done
	if got := resetCalls.Load(); got != 0 {
		t.Fatalf("reset calls after cancellation immediately before reset = %d, want 0", got)
	}
}
