package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"tee/enclave"
)

func main() {
	// Load environment variables first
	enclave.LoadEnvVariables()

	// Initialize NSM for crypto operations
	if err := enclave.InitializeNSM(); err != nil {
		log.Fatalf("Failed to initialize NSM: %v", err)
	}

	// Create server configuration with the business mux
	config := enclave.CreateServerConfig(createBusinessMux())

	// Start the server
	startServer(config)
}

func createBusinessMux() *http.ServeMux {
	mux := http.NewServeMux()

	// Root endpoint - business logic
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received %s request for %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		response := fmt.Sprintf("Hello from TEE_1 service! Received %s request for %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Enclave", "Nitro")
		w.Header().Set("X-Service", "tee_1")
		fmt.Fprintln(w, response)
	})

	// Attestation endpoint - business logic
	mux.HandleFunc("/attest", createAttestHandler())

	return mux
}

func createAttestHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received attestation request from %s", r.RemoteAddr)

		// We need to get the server config to access the cache
		// For now, we'll create a temporary cache instance
		// This is a limitation of the current architecture
		cache := enclave.NewMemoryCache()

		fingerprint, err := enclave.GetCertificateFingerprint(r.Context(), cache)
		if err != nil {
			log.Printf("Failed to get certificate fingerprint: %v", err)
			http.Error(w, "Failed to generate attestation", http.StatusInternalServerError)
			return
		}

		// Convert fingerprint to hex
		fingerprintHex := hex.EncodeToString(fingerprint)

		handle := enclave.MustGlobalHandle()
		attestationDoc, err := enclave.GenerateAttestation(handle, []byte(fingerprintHex))
		if err != nil {
			log.Printf("Failed to generate attestation: %v", err)
			http.Error(w, "Failed to generate attestation", http.StatusInternalServerError)
			return
		}

		encoded := base64.StdEncoding.EncodeToString(attestationDoc)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Service", "tee_1")
		fmt.Fprint(w, encoded)
	}
}

func startServer(serverConfig *enclave.ServerConfig) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	httpErrChan, httpsErrChan := enclave.StartListeners(ctx, serverConfig.HTTPServer, serverConfig.HTTPSServer)

	log.Printf("Attempting to load or issue certificate for %s", enclave.EnclaveDomain)
	_, err := serverConfig.Manager.GetCertificate(&tls.ClientHelloInfo{ServerName: enclave.EnclaveDomain})
	if err != nil {
		log.Printf("Failed to load or issue certificate on startup: %v", err)
	} else {
		log.Printf("Successfully loaded or issued certificate for %s", enclave.EnclaveDomain)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err = <-httpErrChan:
		if err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	case err = <-httpsErrChan:
		if err != nil {
			log.Fatalf("HTTPS server failed: %v", err)
		}
	case <-sigChan:
		log.Println("Received shutdown signal, stopping TEE_1 service...")
		cancel()

		// Gracefully close connection manager
		if manager := enclave.GetConnectionManager(); manager != nil {
			log.Println("Closing connection pool...")
			manager.Close()
		}

		_ = serverConfig.HTTPServer.Close()
		_ = serverConfig.HTTPSServer.Close()
	}
}
