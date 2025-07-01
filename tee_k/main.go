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
	config := LoadTEEKConfig()

	if config.EnclaveMode {
		fmt.Println("=== TEE_K Enclave Mode ===")
		startEnclaveMode(config)
	} else {
		fmt.Println("=== TEE_K Standalone Mode ===")
		startStandaloneMode(config)
	}
}

func startEnclaveMode(config *TEEKConfig) {
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

	// Create and start TEE_K enclave
	enclave := NewTEEKEnclave(config, services)

	if err := enclave.Start(); err != nil {
		log.Fatalf("TEE_K enclave failed: %v", err)
	}
}

func startStandaloneMode(config *TEEKConfig) {
	fmt.Printf("Starting TEE_K service on port %d\n", config.Port)

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	teek := NewTEEK(config.Port)
	teek.SetTEETURL(config.TEETURL)

	// Connect to TEE_T
	go func() {
		time.Sleep(1 * time.Second) // Wait a moment for TEE_T to start
		for i := 0; i < 10; i++ {
			if err := teek.ConnectToTEET(); err == nil {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()

	// Create separate ServeMux for TEE_K
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", teek.handleWebSocket)
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", config.Port),
		Handler: mux,
	}

	// Start server in goroutine
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[TEE_K] server failed: %v", err)
		}
	}()

	fmt.Printf("TEE_K starting on :%d\n", config.Port)

	// Wait for shutdown signal
	<-sigChan
	fmt.Println("\nShutting down TEE_K gracefully...")

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("[TEE_K] server shutdown error: %v", err)
	}

	fmt.Println("TEE_K shutdown complete")
}
