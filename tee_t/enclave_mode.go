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

	"tee-mpc/shared"
)

func startEnclaveMode(config *TEETConfig) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize enclave manager with production configuration
	enclaveConfig := &shared.EnclaveConfig{
		Domain:       config.Domain,
		ParentCID:    3, // Standard parent CID for AWS Nitro Enclaves
		ServiceName:  "tee_t",
		HTTPPort:     8080, // For ACME challenges
		HTTPSPort:    8443, // For production HTTPS
		InternetPort: 8444, // Internet proxy port
		KMSPort:      5000, // KMS proxy port
	}

	enclaveManager, err := shared.NewEnclaveManager(ctx, enclaveConfig, config.KMSKey)
	if err != nil {
		log.Printf("[TEE_T] CRITICAL ERROR: Failed to initialize enclave manager: %v", err)
		// Return gracefully instead of crashing enclave
		return
	}
	defer enclaveManager.Shutdown(ctx)

	// Phase 1: Bootstrap certificates via ACME
	if err := enclaveManager.BootstrapCertificates(ctx); err != nil {
		log.Printf("[TEE_T] CRITICAL ERROR: Certificate bootstrap failed: %v", err)
		// Return gracefully instead of crashing enclave
		return
	}

	// Phase 2: Start production HTTPS server with WebSocket support
	teet := NewTEET(int(enclaveConfig.HTTPSPort))

	// Create HTTPS server with integrated WebSocket handler
	httpsHandler := setupEnclaveRoutes(teet, enclaveManager)
	httpsServer := enclaveManager.CreateHTTPSServer(httpsHandler)

	// Start HTTPS server in background
	go func() {
		log.Printf("[TEE_T] Starting production HTTPS server on port %d", enclaveConfig.HTTPSPort)
		if err := httpsServer.ListenAndServeTLS(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("[TEE_T] CRITICAL ERROR: HTTPS server failed: %v", err)
			// Signal main goroutine to shut down gracefully
			cancel()
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("[TEE_T] Enclave mode started successfully - Domain: %s, HTTPS Port: %d",
		config.Domain, enclaveConfig.HTTPSPort)

	<-sigChan
	log.Printf("[TEE_T] Shutting down enclave mode...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := httpsServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("[TEE_T] HTTPS server shutdown error: %v", err)
	}

	cancel() // Cancel main context
	log.Printf("[TEE_T] Enclave mode shutdown complete")
}

func setupEnclaveRoutes(teet *TEET, enclaveManager *shared.EnclaveManager) http.Handler {
	mux := http.NewServeMux()

	// WebSocket upgrade endpoint for clients
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		// Upgrade HTTPS connection to WebSocket
		teet.handleClientWebSocket(w, r)
	})

	// WebSocket endpoint for TEE_K connections
	mux.HandleFunc("/teek", func(w http.ResponseWriter, r *http.Request) {
		// Upgrade HTTPS connection to WebSocket for TEE_K
		teet.handleTEEKWebSocket(w, r)
	})

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"healthy","mode":"enclave"}`)
	})

	// Attestation endpoint with certificate fingerprint
	mux.HandleFunc("/attest", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[TEE_T] Attestation request from %s", r.RemoteAddr)

		attestationDoc, err := enclaveManager.GenerateAttestation(r.Context())
		if err != nil {
			log.Printf("[TEE_T] Attestation generation failed: %v", err)
			http.Error(w, "Failed to generate attestation", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Enclave-Service", "tee_t")
		w.Write(attestationDoc)
	})

	// Default handler for the root
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[TEE_T] Received %s request for %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Enclave-Service", "tee_t")
		w.Header().Set("X-Enclave-Mode", "production")

		fmt.Fprintf(w, "TEE_T Enclave Service\nMode: Production\nDomain: %s\nStatus: Ready\n",
			enclaveManager.GetConfig().Domain)
	})

	return mux
}
