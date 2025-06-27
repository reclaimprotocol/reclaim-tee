package main

import (
	"log"
	"net/http"
	"os"
	"tee/enclave"
)

// startDemoServer starts a simple HTTP server for demo purposes
func startDemoServer(port string) {
	// Initialize TEE communication client for TEE_T coordination
	teeT_URL := os.Getenv("TEE_T_URL")
	if teeT_URL == "" {
		// Use HTTP for local development
		teeT_URL = "http://localhost:8081" // Default for local development
	}

	teeCommClient = enclave.NewTEECommClient(teeT_URL)
	log.Printf("TEE_K Demo: TEE communication client initialized for TEE_T at %s", teeT_URL)

	// Start WebSocket hub for any WebSocket functionality
	go wsHub.run()
	go wsHub.cleanupStaleConnections()

	mux := createBusinessMux()

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	log.Printf("TEE_K demo server starting on port %s", port)
	log.Printf("Available endpoints:")
	log.Printf("  GET / - Basic status check")
	log.Printf("  WS /ws - WebSocket endpoint for MPC protocol")

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Demo server failed: %v", err)
	}
}

// isDemoMode checks if the service should run in demo mode
func isDemoMode() bool {
	return os.Getenv("PORT") != ""
}

// getDemoPort returns the demo port from environment variable
func getDemoPort() string {
	return os.Getenv("PORT")
}

// createDemoTranscriptSigner creates a demo transcript signer
func createDemoTranscriptSigner() (*enclave.TranscriptSigner, error) {
	return enclave.GenerateDemoKey()
}

// setupDemoTEEClient initializes the TEE communication client for demo mode
func setupDemoTEEClient() error {
	// Initialize TEE communication client to connect to TEE_T
	// Default to localhost:8081 for demo mode, but allow override via TEE_T_URL
	teeT_URL := os.Getenv("TEE_T_URL")
	if teeT_URL == "" {
		teeT_URL = "http://localhost:8081"
	}

	log.Printf("Initializing TEE communication client to connect to TEE_T at %s", teeT_URL)
	teeCommClient = enclave.NewTEECommClient(teeT_URL)

	// Connect to TEE_T
	if err := teeCommClient.Connect(); err != nil {
		log.Printf("Warning: Failed to connect to TEE_T: %v", err)
		log.Printf("TEE_K will continue but Split AEAD operations may fail")
		return err
	} else {
		log.Printf("TEE_K successfully connected to TEE_T")
	}

	return nil
}
