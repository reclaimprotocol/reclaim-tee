package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

func main() {
	fmt.Println("=== Client ===")

	// Default to enclave mode, fallback to standalone if specified
	teekURL := "wss://tee-k.reclaimprotocol.org/ws" // Default to enclave
	if len(os.Args) > 1 {
		teekURL = os.Args[1]
	}

	fmt.Printf(" Starting Client, connecting to TEE_K at %s\n", teekURL)

	client := NewClient(teekURL)
	defer client.Close()

	// Auto-detect TEE_T URL based on TEE_K URL
	teetURL := autoDetectTEETURL(teekURL)
	fmt.Printf(" Auto-detected TEE_T URL: %s\n", teetURL)
	client.SetTEETURL(teetURL)

	// Connect to TEE_K
	if err := client.ConnectToTEEK(); err != nil {
		log.Fatalf("[Client] Failed to connect to TEE_K: %v", err)
	}

	// Connect to TEE_T
	if err := client.ConnectToTEET(); err != nil {
		log.Fatalf("[Client] Failed to connect to TEE_T: %v", err)
	}

	// Fetch and verify attestations from both enclaves (only in enclave mode)
	if err := client.fetchAndVerifyAttestations(); err != nil {
		log.Fatalf("[Client] Failed to fetch and verify attestations: %v", err)
	}

	// Request HTTP to example.com
	if err := client.RequestHTTP("example.com", 443); err != nil {
		log.Fatalf("[Client] Failed to request HTTP: %v", err)
	}

	// Wait for processing to complete using proper completion tracking
	fmt.Println("⏳ Waiting for all processing to complete...")
	fmt.Println(" (decryption streams + redaction verification)")

	select {
	case <-client.WaitForCompletion():
		fmt.Println(" Split AEAD protocol completed successfully!")
	case <-time.After(30 * time.Second): // Reasonable timeout instead of hardcoded wait
		fmt.Println("⏰ Processing timeout - may indicate an issue")
	}

	fmt.Println(" Client processing completed!")
}

// autoDetectTEETURL automatically detects the appropriate TEE_T URL based on TEE_K URL
func autoDetectTEETURL(teekURL string) string {
	if strings.HasPrefix(teekURL, "wss://") && strings.Contains(teekURL, "reclaimprotocol.org") {
		// Enclave mode: TEE_K is using enclave domain, so TEE_T should too
		return "wss://tee-t.reclaimprotocol.org/ws"
	} else if strings.HasPrefix(teekURL, "ws://") && strings.Contains(teekURL, "localhost") {
		// Standalone mode: TEE_K is using localhost, so TEE_T should too
		return "ws://localhost:8081/ws"
	} else {
		// Custom URL - try to infer the pattern
		if strings.HasPrefix(teekURL, "wss://") {
			// Assume enclave mode for any wss:// URL
			return "wss://tee-t.reclaimprotocol.org/ws"
		} else {
			// Assume standalone mode for any ws:// URL
			return "ws://localhost:8081/ws"
		}
	}
}
