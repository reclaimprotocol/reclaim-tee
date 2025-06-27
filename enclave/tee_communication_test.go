package enclave

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestTEECommunication tests the full TEE_K ↔ TEE_T WebSocket communication flow
func TestTEECommunication(t *testing.T) {
	// Set up the CreateSessionDataForWebSocket callback for tests
	CreateSessionDataForWebSocket = func(sessionID string) error {
		// Test implementation - just create empty session data
		return nil
	}

	// Create TEE_T server
	teeServer := NewTEECommServer()

	// Create test HTTP server for TEE_T
	mux := http.NewServeMux()
	mux.HandleFunc("/tee-comm", teeServer.HandleWebSocket)

	server := httptest.NewServer(mux)
	defer server.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := strings.Replace(server.URL, "http://", "ws://", 1)

	// Create TEE_K client
	client := NewTEECommClient(wsURL)
	defer client.Disconnect()

	// Test connection
	err := client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect to TEE_T: %v", err)
	}

	// Test session start
	sessionID := "test-session-123"
	err = client.StartSession(sessionID, TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to start session: %v", err)
	}

	// Create test data for Split AEAD
	testData := []byte("Hello, World! This is a test message for Split AEAD.")
	nonce := make([]byte, 12) // GCM nonce
	aad := []byte("additional authenticated data")

	// Create test key and Split AEAD encryptor
	key := make([]byte, 16) // AES-128 key
	for i := range key {
		key[i] = byte(i)
	}

	encryptor, err := NewSplitAEADEncryptor(SplitAEAD_AES_GCM, key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}
	defer encryptor.SecureZero()

	// Perform encryption without tag
	ciphertext, tagSecrets, err := encryptor.EncryptWithoutTag(nonce, testData, aad)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	defer tagSecrets.SecureZero()

	// Test tag computation via TEE_T
	tag, err := client.ComputeTag(ciphertext, tagSecrets, "encrypt")
	if err != nil {
		t.Fatalf("Failed to compute tag via TEE_T: %v", err)
	}

	if len(tag) != 16 { // GCM tag is 16 bytes
		t.Fatalf("Expected tag length 16, got %d", len(tag))
	}

	// Test tag verification via TEE_T
	verified, err := client.VerifyTag(ciphertext, tag, tagSecrets)
	if err != nil {
		t.Fatalf("Failed to verify tag via TEE_T: %v", err)
	}

	if !verified {
		t.Fatalf("Tag verification failed")
	}

	// Test tag verification with wrong tag (should fail)
	wrongTag := make([]byte, 16)
	verified, err = client.VerifyTag(ciphertext, wrongTag, tagSecrets)
	if err != nil {
		t.Fatalf("Failed to verify wrong tag via TEE_T: %v", err)
	}

	if verified {
		t.Fatalf("Tag verification should have failed with wrong tag")
	}

	// Test session end
	err = client.EndSession()
	if err != nil {
		t.Fatalf("Failed to end session: %v", err)
	}

	t.Logf("TEE communication test passed successfully")
}

// TestTEECommunicationChaCha20 tests with ChaCha20-Poly1305
func TestTEECommunicationChaCha20(t *testing.T) {
	// Set up the CreateSessionDataForWebSocket callback for tests
	CreateSessionDataForWebSocket = func(sessionID string) error {
		// Test implementation - just create empty session data
		return nil
	}

	// Create TEE_T server
	teeServer := NewTEECommServer()

	// Create test HTTP server for TEE_T
	mux := http.NewServeMux()
	mux.HandleFunc("/tee-comm", teeServer.HandleWebSocket)

	server := httptest.NewServer(mux)
	defer server.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := strings.Replace(server.URL, "http://", "ws://", 1)

	// Create TEE_K client
	client := NewTEECommClient(wsURL)
	defer client.Disconnect()

	// Test connection
	err := client.Connect()
	if err != nil {
		t.Fatalf("Failed to connect to TEE_T: %v", err)
	}

	// Test session start with ChaCha20-Poly1305
	sessionID := "test-session-chacha20"
	err = client.StartSession(sessionID, TLS_CHACHA20_POLY1305_SHA256)
	if err != nil {
		t.Fatalf("Failed to start ChaCha20 session: %v", err)
	}

	// Create test data
	testData := []byte("ChaCha20-Poly1305 test message for Split AEAD protocol!")
	nonce := make([]byte, 12) // ChaCha20-Poly1305 nonce
	aad := []byte("chacha20 aad")

	// Create test key
	key := make([]byte, 32) // ChaCha20 key
	for i := range key {
		key[i] = byte(i + 1)
	}

	encryptor, err := NewSplitAEADEncryptor(SplitAEAD_CHACHA20_POLY1305, key)
	if err != nil {
		t.Fatalf("Failed to create ChaCha20 encryptor: %v", err)
	}
	defer encryptor.SecureZero()

	// Perform encryption without tag
	ciphertext, tagSecrets, err := encryptor.EncryptWithoutTag(nonce, testData, aad)
	if err != nil {
		t.Fatalf("Failed to encrypt with ChaCha20: %v", err)
	}
	defer tagSecrets.SecureZero()

	// Test tag computation via TEE_T
	tag, err := client.ComputeTag(ciphertext, tagSecrets, "encrypt")
	if err != nil {
		t.Fatalf("Failed to compute ChaCha20 tag via TEE_T: %v", err)
	}

	if len(tag) != 16 { // Poly1305 tag is 16 bytes
		t.Fatalf("Expected ChaCha20 tag length 16, got %d", len(tag))
	}

	// Test tag verification
	verified, err := client.VerifyTag(ciphertext, tag, tagSecrets)
	if err != nil {
		t.Fatalf("Failed to verify ChaCha20 tag via TEE_T: %v", err)
	}

	if !verified {
		t.Fatalf("ChaCha20 tag verification failed")
	}

	// End session
	err = client.EndSession()
	if err != nil {
		t.Fatalf("Failed to end ChaCha20 session: %v", err)
	}

	t.Logf("TEE communication ChaCha20 test passed successfully")
}

// TestTEECommunicationConcurrency tests concurrent operations
func TestTEECommunicationConcurrency(t *testing.T) {
	// Set up the CreateSessionDataForWebSocket callback for tests
	CreateSessionDataForWebSocket = func(sessionID string) error {
		// Test implementation - just create empty session data
		return nil
	}

	// Create TEE_T server
	teeServer := NewTEECommServer()

	// Create test HTTP server for TEE_T
	mux := http.NewServeMux()
	mux.HandleFunc("/tee-comm", teeServer.HandleWebSocket)

	server := httptest.NewServer(mux)
	defer server.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := strings.Replace(server.URL, "http://", "ws://", 1)

	// Test multiple concurrent clients
	numClients := 3
	clients := make([]*TEECommClient, numClients)

	// Create and connect clients
	for i := 0; i < numClients; i++ {
		clients[i] = NewTEECommClient(wsURL)
		err := clients[i].Connect()
		if err != nil {
			t.Fatalf("Failed to connect client %d: %v", i, err)
		}
		defer clients[i].Disconnect()
	}

	// Test concurrent operations
	done := make(chan bool, numClients)

	for i := 0; i < numClients; i++ {
		go func(clientIdx int) {
			defer func() { done <- true }()

			client := clients[clientIdx]
			sessionID := fmt.Sprintf("concurrent-session-%d", clientIdx)

			// Start session
			err := client.StartSession(sessionID, TLS_AES_128_GCM_SHA256)
			if err != nil {
				t.Errorf("Client %d failed to start session: %v", clientIdx, err)
				return
			}

			// Create test data
			testData := []byte(fmt.Sprintf("Concurrent test message %d", clientIdx))
			nonce := make([]byte, 12)
			aad := []byte(fmt.Sprintf("aad-%d", clientIdx))

			// Create encryptor
			key := make([]byte, 16)
			for j := range key {
				key[j] = byte(j + clientIdx)
			}

			encryptor, err := NewSplitAEADEncryptor(SplitAEAD_AES_GCM, key)
			if err != nil {
				t.Errorf("Client %d failed to create encryptor: %v", clientIdx, err)
				return
			}
			defer encryptor.SecureZero()

			// Encrypt and compute tag
			ciphertext, tagSecrets, err := encryptor.EncryptWithoutTag(nonce, testData, aad)
			if err != nil {
				t.Errorf("Client %d failed to encrypt: %v", clientIdx, err)
				return
			}
			defer tagSecrets.SecureZero()

			// Compute tag via TEE_T
			tag, err := client.ComputeTag(ciphertext, tagSecrets, "encrypt")
			if err != nil {
				t.Errorf("Client %d failed to compute tag: %v", clientIdx, err)
				return
			}

			// Verify tag
			verified, err := client.VerifyTag(ciphertext, tag, tagSecrets)
			if err != nil {
				t.Errorf("Client %d failed to verify tag: %v", clientIdx, err)
				return
			}

			if !verified {
				t.Errorf("Client %d tag verification failed", clientIdx)
				return
			}

			// End session
			err = client.EndSession()
			if err != nil {
				t.Errorf("Client %d failed to end session: %v", clientIdx, err)
				return
			}

			t.Logf("Client %d completed successfully", clientIdx)
		}(i)
	}

	// Wait for all clients to complete
	timeout := time.After(30 * time.Second)
	for i := 0; i < numClients; i++ {
		select {
		case <-done:
			// Client completed
		case <-timeout:
			t.Fatalf("Test timed out waiting for client completion")
		}
	}

	t.Logf("Concurrent TEE communication test passed successfully")
}

// TestTEECommunicationErrorHandling tests error conditions
func TestTEECommunicationErrorHandling(t *testing.T) {
	// Test connection to non-existent server
	client := NewTEECommClient("ws://localhost:99999")
	defer client.Disconnect()

	err := client.Connect()
	if err == nil {
		t.Fatalf("Expected connection error to non-existent server")
	}

	// Test operations without connection
	_, err = client.ComputeTag([]byte("test"), &TagSecrets{}, "encrypt")
	if err == nil {
		t.Fatalf("Expected error for tag computation without connection")
	}

	_, err = client.VerifyTag([]byte("test"), []byte("tag"), &TagSecrets{})
	if err == nil {
		t.Fatalf("Expected error for tag verification without connection")
	}

	t.Logf("Error handling test passed successfully")
}

// TestTEEServerStandalone tests TEE_T server independently
func TestTEEServerStandalone(t *testing.T) {
	// Create TEE_T server
	teeServer := NewTEECommServer()

	if teeServer == nil {
		t.Fatalf("Failed to create TEE server")
	}

	// Test server creation
	if len(teeServer.clients) != 0 {
		t.Fatalf("Expected empty clients map, got %d clients", len(teeServer.clients))
	}

	// Test upgrader configuration
	if teeServer.upgrader.CheckOrigin == nil {
		t.Fatalf("Expected CheckOrigin function to be set")
	}

	t.Logf("TEE server standalone test passed successfully")
}
