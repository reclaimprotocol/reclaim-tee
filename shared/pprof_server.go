package shared

import (
	"net/http"
	_ "net/http/pprof" // registers /debug/pprof/* on http.DefaultServeMux
	"os"

	"go.uber.org/zap"
)

// MaybeStartPprofServer starts a debug HTTP server on the value of
// DEBUG_PPROF_PORT if that env var is set. The server uses
// http.DefaultServeMux which the pprof package self-registers on, so all
// /debug/pprof/* endpoints come for free. Bound to 127.0.0.1 only —
// never exposed off the host. Returns silently if the env var is unset
// (production behavior).
//
// Hit endpoints with:
//
//	curl http://127.0.0.1:${DEBUG_PPROF_PORT}/debug/pprof/heap > heap.pb.gz
//	curl http://127.0.0.1:${DEBUG_PPROF_PORT}/debug/pprof/goroutine?debug=2 > goroutines.txt
//	go tool pprof -http=:8000 heap.pb.gz
func MaybeStartPprofServer(logger *Logger) {
	port := os.Getenv("DEBUG_PPROF_PORT")
	if port == "" {
		return
	}
	addr := "127.0.0.1:" + port
	logger.Info("starting pprof debug server", zap.String("addr", addr))
	go func() {
		// Sole purpose of this goroutine is to serve pprof — its panic
		// would still take the workload down, but that's fine: pprof
		// isn't expected to fail at runtime, and if it does we want to
		// know.
		if err := http.ListenAndServe(addr, nil); err != nil {
			logger.Error("pprof server exited", zap.Error(err))
		}
	}()
}
