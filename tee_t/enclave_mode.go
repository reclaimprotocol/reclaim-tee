package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"tee-mpc/shared"
	"time"

	"go.uber.org/zap"
)

func startEnclaveMode(config *TEETConfig, logger *shared.Logger) {
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
		logger.Critical("Failed to initialize enclave manager", zap.Error(err))
		// Return gracefully instead of crashing enclave
		return
	}
	defer enclaveManager.Shutdown(ctx)

	// Phase 1: Bootstrap certificates via ACME
	if err = enclaveManager.BootstrapCertificates(ctx); err != nil {
		logger.Critical("Certificate bootstrap failed", zap.Error(err))
		// Return gracefully instead of crashing enclave
		return
	}

	// Phase 2: Start production HTTPS server with WebSocket support
	teet := NewTEETWithEnclaveManagerAndLogger(int(enclaveConfig.HTTPSPort), enclaveManager, logger)

	// Start background attestation refresh for performance optimization
	go teet.startAttestationRefresh(ctx)

	// Create HTTPS server with integrated WebSocket handler
	httpsHandler := setupEnclaveRoutes(teet, enclaveManager, logger)
	httpsServer := enclaveManager.CreateHTTPSServer(httpsHandler)

	// Start HTTPS server in background
	go func() {
		logger.InfoIf("Starting production HTTPS server", zap.Int("port", int(enclaveConfig.HTTPSPort)))
		if err := httpsServer.ListenAndServeTLS(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Critical("HTTPS server failed", zap.Error(err))
			// Signal main goroutine to shut down gracefully
			cancel()
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	logger.InfoIf("Enclave mode started successfully",
		zap.String("domain", config.Domain),
		zap.Int("https_port", int(enclaveConfig.HTTPSPort)))

	<-sigChan
	logger.InfoIf("Shutting down enclave mode...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := httpsServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("HTTPS server shutdown error", zap.Error(err))
	}

	cancel() // Cancel main context
	logger.InfoIf("Enclave mode shutdown complete")
}

func setupEnclaveRoutes(teet *TEET, enclaveManager *shared.EnclaveManager, logger *shared.Logger) http.Handler {
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

	// Attestation endpoint with ECDSA public key in user data
	mux.HandleFunc("/attest", func(w http.ResponseWriter, r *http.Request) {
		logger.InfoIf("Attestation request from", zap.String("remote_addr", r.RemoteAddr))

		// Get the ECDSA public key from the TEET signing key pair
		if teet.signingKeyPair == nil {
			logger.InfoIf("No signing key pair available for attestation")
			http.Error(w, "No signing key pair available", http.StatusInternalServerError)
			return
		}

		publicKeyDER, err := teet.signingKeyPair.GetPublicKeyDER()
		if err != nil {
			logger.Error("Failed to get public key DER", zap.Error(err))
			http.Error(w, "Failed to get public key", http.StatusInternalServerError)
			return
		}

		// Create user data containing the hex-encoded ECDSA public key
		userData := fmt.Sprintf("tee_t_public_key:%x", publicKeyDER)
		logger.InfoIf("Including ECDSA public key in attestation", zap.Int("der_length", len(publicKeyDER)))

		attestationDoc, err := enclaveManager.GenerateAttestation(r.Context(), []byte(userData))
		if err != nil {
			logger.Error("Attestation generation failed", zap.Error(err))
			http.Error(w, "Failed to generate attestation", http.StatusInternalServerError)
			return
		}

		// Encode attestation document as base64
		attestationBase64 := base64.StdEncoding.EncodeToString(attestationDoc)
		logger.InfoIf("Generated attestation document", zap.Int("doc_length", len(attestationDoc)), zap.Int("base64_length", len(attestationBase64)))

		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Enclave-Service", "tee_t")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(attestationBase64))
	})

	// Default handler for the root
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		logger.InfoIf("Received request", zap.String("method", r.Method), zap.String("path", r.URL.Path), zap.String("remote_addr", r.RemoteAddr))

		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Enclave-Service", "tee_t")
		w.Header().Set("X-Enclave-Mode", "production")

		// Create response content for enclave service info
		response := fmt.Sprintf("TEE_T Enclave Service\nMode: Production\nDomain: %s\nStatus: Ready\n",
			enclaveManager.GetConfig().Domain)
		w.Write([]byte(response))
	})

	return mux
}
