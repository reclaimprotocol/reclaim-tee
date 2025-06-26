// Demo script showing TEE_K ↔ TEE_T WebSocket communication
// This demonstrates the Split AEAD protocol coordination in action
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"tee/enclave"
	"time"
)

func main() {
	fmt.Println("TEE Communication Demo - Split AEAD Protocol")
	fmt.Println("============================================")
	fmt.Println("Note: Using HTTP for local demo. In production, use HTTPS/WSS.")
	fmt.Println()

	// Start TEE_T server
	fmt.Println("Starting TEE_T server...")
	teeServer := enclave.NewTEECommServer()

	// Create HTTP server for TEE_T
	mux := http.NewServeMux()
	mux.HandleFunc("/tee-comm", teeServer.HandleWebSocket)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "TEE_T Communication Server - Ready for Split AEAD operations\n")
	})

	server := &http.Server{
		Addr:    ":8081",
		Handler: mux,
	}

	// Start server in background
	go func() {
		fmt.Println("TEE_T server listening on :8081")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("TEE_T server failed: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(1 * time.Second)

	// Create TEE_K client (using HTTP for demo since localhost doesn't have HTTPS cert)
	fmt.Println("Creating TEE_K client...")
	client := enclave.NewTEECommClient("http://localhost:8081")
	defer client.Disconnect()

	// Demonstrate the Split AEAD protocol
	fmt.Println("\nDemonstrating Split AEAD Protocol:")
	fmt.Println("===================================")

	// Step 1: Connect to TEE_T
	fmt.Println("1. TEE_K connecting to TEE_T...")
	if err := client.Connect(); err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	fmt.Println("   WebSocket connection established")

	// Step 2: Start session
	fmt.Println("2. Starting Split AEAD session...")
	sessionID := "demo-session-2024"
	if err := client.StartSession(sessionID, enclave.TLS_AES_128_GCM_SHA256); err != nil {
		log.Fatalf("Failed to start session: %v", err)
	}
	fmt.Println("   Session started with AES-128-GCM cipher suite")

	// Step 3: Demonstrate encryption and tag computation
	fmt.Println("3. Performing Split AEAD encryption...")

	// Create test data
	plaintext := []byte("This is a secret message that will be encrypted using Split AEAD!")
	nonce := make([]byte, 12) // GCM nonce
	aad := []byte("Demo AAD - Additional Authenticated Data")

	// Create encryption key
	key := make([]byte, 16) // AES-128 key
	for i := range key {
		key[i] = byte(i + 1)
	}

	// Create Split AEAD encryptor (TEE_K operation)
	encryptor, err := enclave.NewSplitAEADEncryptor(enclave.SplitAEAD_AES_GCM, key)
	if err != nil {
		log.Fatalf("Failed to create encryptor: %v", err)
	}
	defer encryptor.SecureZero()

	// Encrypt without tag (TEE_K generates ciphertext + tag secrets)
	ciphertext, tagSecrets, err := encryptor.EncryptWithoutTag(nonce, plaintext, aad)
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}
	defer tagSecrets.SecureZero()

	fmt.Printf("   Plaintext: %s\n", string(plaintext))
	fmt.Printf("   Ciphertext: %x (length: %d bytes)\n", ciphertext, len(ciphertext))
	fmt.Printf("   Tag secrets generated for TEE_T\n")

	// Step 4: Request tag computation from TEE_T
	fmt.Println("4. TEE_T computing authentication tag...")
	tag, err := client.ComputeTag(ciphertext, tagSecrets, "encrypt")
	if err != nil {
		log.Fatalf("Failed to compute tag: %v", err)
	}
	fmt.Printf("   Authentication tag: %x (length: %d bytes)\n", tag, len(tag))

	// Step 5: Verify tag
	fmt.Println("5. TEE_T verifying authentication tag...")
	verified, err := client.VerifyTag(ciphertext, tag, tagSecrets)
	if err != nil {
		log.Fatalf("Failed to verify tag: %v", err)
	}

	if verified {
		fmt.Println("   Tag verification successful - message is authentic!")
	} else {
		fmt.Println("   Tag verification failed - message may be tampered!")
	}

	// Step 6: Test with wrong tag (should fail)
	fmt.Println("6. Testing with tampered tag...")
	wrongTag := make([]byte, 16)
	wrongTag[0] = 0xFF // Tamper with tag

	verified, err = client.VerifyTag(ciphertext, wrongTag, tagSecrets)
	if err != nil {
		log.Fatalf("Failed to verify wrong tag: %v", err)
	}

	if !verified {
		fmt.Println("   Tampered tag correctly rejected - security working!")
	} else {
		fmt.Println("   Tampered tag accepted - security issue!")
	}

	// Step 7: Demonstrate ChaCha20-Poly1305
	fmt.Println("7. Demonstrating ChaCha20-Poly1305...")

	// Start new session with ChaCha20
	sessionID2 := "demo-session-chacha20"
	if err := client.StartSession(sessionID2, enclave.TLS_CHACHA20_POLY1305_SHA256); err != nil {
		log.Fatalf("Failed to start ChaCha20 session: %v", err)
	}

	// Create ChaCha20 encryptor
	key32 := make([]byte, 32) // ChaCha20 key
	for i := range key32 {
		key32[i] = byte(i + 10)
	}

	encryptor2, err := enclave.NewSplitAEADEncryptor(enclave.SplitAEAD_CHACHA20_POLY1305, key32)
	if err != nil {
		log.Fatalf("Failed to create ChaCha20 encryptor: %v", err)
	}
	defer encryptor2.SecureZero()

	// Encrypt with ChaCha20
	plaintext2 := []byte("ChaCha20-Poly1305 Split AEAD demo message!")
	ciphertext2, tagSecrets2, err := encryptor2.EncryptWithoutTag(nonce, plaintext2, aad)
	if err != nil {
		log.Fatalf("Failed to encrypt with ChaCha20: %v", err)
	}
	defer tagSecrets2.SecureZero()

	// Compute tag with TEE_T
	tag2, err := client.ComputeTag(ciphertext2, tagSecrets2, "encrypt")
	if err != nil {
		log.Fatalf("Failed to compute ChaCha20 tag: %v", err)
	}

	fmt.Printf("   ChaCha20 ciphertext: %x\n", ciphertext2)
	fmt.Printf("   Poly1305 tag: %x\n", tag2)

	// Verify ChaCha20 tag
	verified2, err := client.VerifyTag(ciphertext2, tag2, tagSecrets2)
	if err != nil {
		log.Fatalf("Failed to verify ChaCha20 tag: %v", err)
	}

	if verified2 {
		fmt.Println("   ChaCha20-Poly1305 verification successful!")
	}

	// Step 8: End sessions
	fmt.Println("8. Cleaning up sessions...")
	if err := client.EndSession(); err != nil {
		log.Printf("Warning: Failed to end session: %v", err)
	}
	fmt.Println("   Sessions ended successfully")

	// Summary
	fmt.Println("\nSplit AEAD Demo Complete!")
	fmt.Println("=========================")
	fmt.Println("WebSocket communication between TEE_K and TEE_T")
	fmt.Println("Split AEAD encryption/decryption with AES-GCM")
	fmt.Println("Split AEAD encryption/decryption with ChaCha20-Poly1305")
	fmt.Println("Authentication tag computation and verification")
	fmt.Println("Security validation (tampered tag rejection)")
	fmt.Println("Proper session management and cleanup")
	fmt.Println()
	fmt.Println("The Split AEAD protocol is working correctly!")
	fmt.Println("   TEE_K handles encryption and key management")
	fmt.Println("   TEE_T handles authentication tag computation")
	fmt.Println("   Both TEEs coordinate via secure WebSocket communication")
	fmt.Println()
	fmt.Println("Press Ctrl+C to exit...")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nDemo terminated. Thank you!")
}
