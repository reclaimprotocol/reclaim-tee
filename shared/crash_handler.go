package shared

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// RecoverAndCrash is meant to be deferred at the root of every long-lived
// goroutine. On panic, it dumps the panic value + stack through the supplied
// logger AND directly to stderr (belt and suspenders — zap may not flush
// before the process exits, and stderr goes straight to the container
// launcher's log capture), syncs the logger, then re-panics so the process
// still terminates with the expected exit code.
//
// "where" is a short identifier for the goroutine (e.g., "tee_k.session_handler")
// — keep it human-scannable, it's the first thing on the panic line.
//
// Usage:
//
//	go func() {
//	    defer shared.RecoverAndCrash(logger, "tee_k.session_handler")
//	    handleSessionMessages(...)
//	}()
func RecoverAndCrash(logger *Logger, where string) {
	r := recover()
	if r == nil {
		return
	}
	stack := debug.Stack()

	// Synchronous stderr write FIRST — survives any zap-buffer issues.
	fmt.Fprintf(os.Stderr, "\n=== PANIC in %s ===\nvalue: %v\n%s\n", where, r, stack)

	// Structured log entry — searchable in Cloud Logging if it makes it out.
	if logger != nil {
		logger.Error("goroutine panic",
			zap.String("where", where),
			zap.Any("recovered", r),
			zap.ByteString("stack", stack),
		)
		_ = logger.Logger.Sync()
	}

	// Re-raise so the process exits the normal way. We're observability,
	// not error suppression — masking a panic would leave the process in
	// undefined state.
	panic(r)
}

// InstallSignalCrashHandler arms SIGTERM/SIGINT/SIGQUIT handlers that, on
// receipt, dump every goroutine's stack through the supplied logger and to
// stderr, sync the logger, then exit with the conventional 128+signal code.
//
// This is the diagnostic that catches "process was killed from the outside"
// — Confidential Space launcher's SIGTERM-then-SIGKILL sequence, kubelet
// liveness-probe kills, manual `gcloud compute instances stop`, etc.
// The 2-second grace period after Sync gives the launcher's log scraper a
// chance to drain the buffer before the VM goes down.
func InstallSignalCrashHandler(logger *Logger) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	go func() {
		sig := <-sigCh

		// Capture all goroutine stacks. 4MB buffer should cover even the
		// pathologically-large goroutine count cases we're chasing.
		buf := make([]byte, 4<<20)
		n := runtime.Stack(buf, true)

		fmt.Fprintf(os.Stderr, "\n=== SIGNAL %s — dumping %d bytes of goroutine state ===\n%s\n",
			sig, n, buf[:n])

		logger.Error("signal received — dumping goroutines before exit",
			zap.String("signal", sig.String()),
			zap.Int("num_goroutines", runtime.NumGoroutine()),
			zap.ByteString("goroutines", buf[:n]),
		)
		_ = logger.Logger.Sync()

		// Give the log scraper time to consume the dump.
		time.Sleep(2 * time.Second)

		// 128 + signal number, the conventional shell exit-code encoding.
		os.Exit(128 + int(sig.(syscall.Signal)))
	}()
}

// liveness tracks the last time RunRuntimeStatsLogger emitted a heartbeat.
// The deadlock watchdog reads it from a fully-independent goroutine that
// holds no locks the rest of the process uses.
var liveness atomic.Int64 // unix nanos of last RunRuntimeStatsLogger tick

// RunRuntimeStatsLogger logs goroutine count + memory stats every minute,
// AND updates the global liveness atomic so RunDeadlockWatchdog can detect
// the case where this very loop is no longer running. Stop by cancelling ctx.
func RunRuntimeStatsLogger(ctx context.Context, logger *Logger) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	var ms runtime.MemStats
	liveness.Store(time.Now().UnixNano())
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runtime.ReadMemStats(&ms)
			logger.Info("runtime stats",
				zap.Int("goroutines", runtime.NumGoroutine()),
				zap.Uint64("heap_alloc_mb", ms.HeapAlloc/1024/1024),
				zap.Uint64("heap_sys_mb", ms.HeapSys/1024/1024),
				zap.Uint64("sys_mb", ms.Sys/1024/1024),
				zap.Uint32("num_gc", ms.NumGC),
				zap.Uint64("next_gc_mb", ms.NextGC/1024/1024),
			)
			liveness.Store(time.Now().UnixNano())
		}
	}
}

// RunDeadlockWatchdog catches the failure mode where every goroutine is
// blocked (mutex deadlock, channel deadlock, scheduler stall) such that
// neither the panic-recover defers nor the SIGTERM signal handler can run.
//
// Mechanism: the runtime-stats logger ticks every 60s and updates the
// `liveness` atomic. If THIS goroutine wakes up and sees liveness more
// than `deadlockThreshold` ago, the rest of the process is dead. We dump
// every goroutine's stack — to stderr DIRECTLY (no zap, no buffered sink
// — fmt.Fprintln to fd 2 is one syscall and survives a wedged scheduler)
// — then os.Exit(137) so the launcher restarts us cleanly.
//
// Tunables:
//   - deadlockThreshold: 120s. RunRuntimeStatsLogger ticks every 60s, so
//     2x grace before declaring death. Bigger = fewer false positives;
//     smaller = faster recovery from a real deadlock.
//   - check interval: 30s. Cheap.
//
// Must be started AFTER RunRuntimeStatsLogger so the initial liveness
// value is set.
func RunDeadlockWatchdog(ctx context.Context, logger *Logger) {
	const deadlockThreshold = 120 * time.Second
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			lastNanos := liveness.Load()
			if lastNanos == 0 {
				continue // stats logger hasn't started yet
			}
			gap := now.Sub(time.Unix(0, lastNanos))
			if gap < deadlockThreshold {
				continue
			}

			// DEADLOCK DETECTED. Dump everything to stderr SYNCHRONOUSLY
			// before doing anything else — zap.Sync may itself be stuck
			// on a mutex the wedged goroutines hold.
			buf := make([]byte, 4<<20)
			n := runtime.Stack(buf, true)

			fmt.Fprintf(os.Stderr,
				"\n=== DEADLOCK WATCHDOG TRIPPED ===\n"+
					"last runtime-stats heartbeat: %v ago (threshold %v)\n"+
					"goroutines: %d\n"+
					"=== STACK DUMP (%d bytes) ===\n%s\n"+
					"=== END DUMP ===\n",
				gap, deadlockThreshold, runtime.NumGoroutine(), n, buf[:n])
			_ = os.Stderr.Sync()

			// Try to log structurally too, but don't trust it to finish.
			if logger != nil {
				go func() {
					logger.Error("deadlock watchdog tripped",
						zap.Duration("gap", gap),
						zap.Int("num_goroutines", runtime.NumGoroutine()),
						zap.ByteString("stacks", buf[:n]),
					)
					_ = logger.Logger.Sync()
				}()
			}

			// Give stderr 1s to flush to the launcher's log capture,
			// then take the process out. The launcher will see a non-
			// zero exit, schedule a restart per the container policy.
			time.Sleep(1 * time.Second)
			os.Exit(137) // 128 + SIGKILL, mnemonic for "killed by watchdog"
		}
	}
}
