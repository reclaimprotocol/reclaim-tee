package shared

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
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

// RunRuntimeStatsLogger logs goroutine count + memory stats every minute.
// If the process is leaking goroutines or memory before dying, this is the
// trail that tells us. Stop by cancelling ctx.
func RunRuntimeStatsLogger(ctx context.Context, logger *Logger) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	var ms runtime.MemStats
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
		}
	}
}
