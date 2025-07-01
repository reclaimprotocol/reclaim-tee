package main

import (
	"fmt"
	"log"
	"os"
	"time"
)

func main() {
	fmt.Println("=== Client ===")

	teekURL := "ws://localhost:8080/ws"
	if len(os.Args) > 1 {
		teekURL = os.Args[1]
	}

	fmt.Printf(" Starting Client, connecting to TEE_K at %s\n", teekURL)

	client := NewClient(teekURL)
	defer client.Close()

	// Set TEE_T URL and connect to both services
	client.SetTEETURL("ws://localhost:8081/ws")

	// Connect to TEE_K
	if err := client.ConnectToTEEK(); err != nil {
		log.Fatalf("[Client] Failed to connect to TEE_K: %v", err)
	}

	// Connect to TEE_T
	if err := client.ConnectToTEET(); err != nil {
		log.Fatalf("[Client] Failed to connect to TEE_T: %v", err)
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
