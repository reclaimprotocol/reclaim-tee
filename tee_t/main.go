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
	config := LoadTEETConfig()

	if config.EnclaveMode {
		fmt.Println("=== TEE_T Enclave Mode ===")
		startEnclaveMode(config)
	} else {
		fmt.Println("=== TEE_T Standalone Mode ===")
		startStandaloneMode(config)
	}
}

func startStandaloneMode(config *TEETConfig) {
	teet := NewTEET(config.Port)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.Port),
		Handler:      setupRoutes(teet),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Start server
	log.Printf("[TEE_T] Starting standalone server on port %d", config.Port)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[TEE_T] CRITICAL ERROR: Server failed: %v", err)
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

	log.Println("[TEE_T] Shutting down...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("[TEE_T] Shutdown error: %v", err)
	}

	log.Println("[TEE_T] Shutdown complete")
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
