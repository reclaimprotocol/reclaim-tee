package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	config := LoadTEEKConfig()

	if config.EnclaveMode {
		fmt.Println("=== TEE_K Enclave Mode ===")
		startEnclaveMode(config)
	} else {
		fmt.Println("=== TEE_K Standalone Mode ===")
		startStandaloneMode(config)
	}
}

func startStandaloneMode(config *TEEKConfig) {
	teek := NewTEEKWithConfig(config)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.Port),
		Handler:      setupRoutes(teek),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("[TEE_K] Starting standalone server on port %d", config.Port)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[TEE_K] CRITICAL ERROR: Server failed: %v", err)
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

	// TEE_T URL and TLS configuration already set via NewTEEKWithConfig
	log.Printf("[TEE_K] Standalone mode: TEE_T URL set to %s, will create per-session connections", config.TEETURL)
	if config.ForceTLSVersion != "" {
		log.Printf("[TEE_K] TLS version forced to: %s", config.ForceTLSVersion)
	}

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[TEE_K] Shutting down...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("[TEE_K] Shutdown error: %v", err)
	}

	log.Println("[TEE_K] Shutdown complete")
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
