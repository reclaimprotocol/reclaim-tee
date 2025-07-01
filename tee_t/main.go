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
	"tee-mpc/shared"
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

func startEnclaveMode(config *TEETConfig) {
	// Initialize enclave services
	enclaveConfig := &shared.EnclaveConfig{
		Domain:    config.Domain,
		KMSKey:    config.KMSKey,
		ParentCID: config.ParentCID,
		ACMEURL:   "https://acme-v02.api.letsencrypt.org/directory",
	}

	services, err := shared.NewEnclaveServices(enclaveConfig)
	if err != nil {
		log.Fatalf("Failed to initialize enclave services: %v", err)
	}

	// Create and start TEE_T enclave
	enclave := NewTEETEnclave(config, services)

	if err := enclave.Start(); err != nil {
		log.Fatalf("TEE_T enclave failed: %v", err)
	}
}

func startStandaloneMode(config *TEETConfig) {
	fmt.Printf("Starting TEE_T service on port %d\n", config.Port)

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	teet := NewTEET(config.Port)

	// Create separate ServeMux for TEE_T
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", teet.handleClientWebSocket)
	mux.HandleFunc("/teek", teet.handleTEEKWebSocket)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", config.Port),
		Handler: mux,
	}

	// Start server in goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[TEE_T] server failed: %v", err)
		}
	}()

	fmt.Printf("TEE_T starting on :%d\n", config.Port)

	// Wait for shutdown signal
	<-sigChan
	fmt.Println("\nShutting down TEE_T gracefully...")

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("[TEE_T] server shutdown error: %v", err)
	}

	fmt.Println("TEE_T shutdown complete")
}
