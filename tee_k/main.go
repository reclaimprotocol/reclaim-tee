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

	config := LoadTEEKConfig()
	// Get the TEE_K logger for this service
	logger := shared.GetTEEKLogger()
	defer logger.Sync()

	if config.EnclaveMode {
		logger.Info("=== TEE_K Enclave Mode ===")
		startEnclaveMode(config, logger)
	} else {
		logger.Info("=== TEE_K Standalone Mode ===")
		startStandaloneMode(config, logger)
	}
}

func startStandaloneMode(config *TEEKConfig, logger *shared.Logger) {
	teek := NewTEEKWithConfig(config)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.Port),
		Handler:      setupRoutes(teek),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Start server in goroutine
	go func() {
		logger.Info("Starting standalone server", zap.Int("port", config.Port))
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

	// Establish shared persistent connection to TEE_T after server is ready
	logger.Info("Server started, establishing shared connection to TEE_T")
	teek.establishSharedTEETConnection()

	// TEE_T URL and TLS configuration already set via NewTEEKWithConfig
	logger.Info("Standalone mode configuration",
		zap.String("teet_url", config.TEETURL),
		zap.String("tls_version", config.ForceTLSVersion))

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("Shutdown error", zap.Error(err))
	}

	logger.Info("Shutdown complete")
}

func setupRoutes(teek *TEEK) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", teek.handleWebSocket)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "TEE_K Healthy")
	})
	return mux
}
