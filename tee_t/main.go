package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tee-mpc/shared"

	"go.uber.org/zap"
)

func main() {
	config := LoadTEETConfig()

	// Get the TEE_T logger for this service
	logger := shared.GetTEETLogger()
	defer logger.Sync()

	if config.EnclaveMode {
		logger.InfoIf("Starting TEE_T in enclave mode")
		startEnclaveMode(config, logger)
	} else {
		logger.InfoIf("Starting TEE_T in standalone mode")
		startStandaloneMode(config, logger)
	}
}

func startStandaloneMode(config *TEETConfig, logger *shared.Logger) {
	teet := NewTEETWithLogger(config.Port, logger)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.Port),
		Handler:      setupRoutes(teet),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Start server
	logger.InfoIf("Starting standalone server", zap.Int("port", config.Port))
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Critical("Server failed", zap.Error(err))
			// Signal shutdown instead of crashing
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGTERM)
			select {
			case sigChan <- syscall.SIGTERM:
				// Signal sent
			default:
				// Channel full, ignore
			}
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.InfoIf("Shutting down...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("Shutdown error", zap.Error(err))
	}

	logger.InfoIf("Shutdown complete")
}

func setupRoutes(teet *TEET) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", teet.handleClientWebSocket)
	mux.HandleFunc("/teek", teet.handleTEEKWebSocket)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "TEE_T Healthy")
	})
	return mux
}
