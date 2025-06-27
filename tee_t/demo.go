package main

import (
	"log"
	"net/http"
	"os"
	"tee/enclave"
)

// startDemoServer starts a simple HTTP server for demo purposes
func startDemoServer(port string) {
	// Use the same business mux as production to ensure callbacks are set
	mux := createBusinessMux()

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	log.Printf("TEE_T demo server starting on port %s", port)
	log.Printf("Available endpoints:")
	log.Printf("  POST /process-redaction-streams - Process redaction streams from users")
	log.Printf("  WS /tee-comm - WebSocket endpoint for TEE-to-TEE communication")
	log.Printf("  GET /attest - Get attestation document")

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
