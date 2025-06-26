package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"tee/enclave"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// Test helper to create a WebSocket test server
func createTestServer() *httptest.Server {
	// Set required environment variables for testing
	os.Setenv("ENCLAVE_DOMAIN", "test.example.com")
	os.Setenv("KMS_KEY_ID", "test-kms-key-id")
	os.Setenv("ACME_URL", "https://acme-staging-v02.api.letsencrypt.org/directory")

	// Initialize test environment
	enclave.LoadEnvVariables()
	if err := enclave.InitializeNSM(); err != nil {
		log.Printf("Warning: Failed to initialize NSM in test: %v", err)
	}

	mux := createBusinessMux()
	return httptest.NewServer(mux)
}

// Test helper to create WebSocket connection for benchmarks
func createTestWSConnectionBench(b *testing.B, server *httptest.Server) *websocket.Conn {
	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		b.Fatalf("Failed to connect to WebSocket: %v", err)
	}
	return conn
}

// Test helper to send and receive WebSocket messages for benchmarks
func sendWSMessageBench(b *testing.B, conn *websocket.Conn, msgType, sessionID string, data interface{}) WSMessage {
	// Send message
	dataBytes, err := json.Marshal(data)
	if err != nil {
		b.Fatalf("Failed to marshal test data: %v", err)
	}

	msg := WSMessage{
		Type:      msgType,
		SessionID: sessionID,
		Data:      dataBytes,
		Timestamp: time.Now().Unix(),
	}

	if err := conn.WriteJSON(msg); err != nil {
		b.Fatalf("Failed to send WebSocket message: %v", err)
	}

	// Receive response
	var response WSMessage
	if err := conn.ReadJSON(&response); err != nil {
		b.Fatalf("Failed to read WebSocket response: %v", err)
	}

	return response
}

// Test helper to create WebSocket connection
func createTestWSConnection(t *testing.T, server *httptest.Server) *websocket.Conn {
	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect to WebSocket: %v", err)
	}
	return conn
}

// Test helper to send and receive WebSocket messages
func sendWSMessage(t *testing.T, conn *websocket.Conn, msgType, sessionID string, data interface{}) WSMessage {
	// Send message
	dataBytes, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Failed to marshal test data: %v", err)
	}

	msg := WSMessage{
		Type:      msgType,
		SessionID: sessionID,
		Data:      dataBytes,
		Timestamp: time.Now().Unix(),
	}

	if err := conn.WriteJSON(msg); err != nil {
		t.Fatalf("Failed to send WebSocket message: %v", err)
	}

	// Receive response
	var response WSMessage
	if err := conn.ReadJSON(&response); err != nil {
		t.Fatalf("Failed to read WebSocket response: %v", err)
	}

	return response
}

func TestWebSocketConnection(t *testing.T) {
	server := createTestServer()
	defer server.Close()

	conn := createTestWSConnection(t, server)
	defer conn.Close()

	// Test basic connection
	if conn == nil {
		t.Fatal("WebSocket connection should not be nil")
	}
}

func TestSessionInitialization(t *testing.T) {
	server := createTestServer()
	defer server.Close()

	conn := createTestWSConnection(t, server)
	defer conn.Close()

	// Test session initialization
	initData := SessionInitData{
		Hostname:      "example.com",
		Port:          443,
		SNI:           "example.com",
		ALPNProtocols: []string{"h2", "http/1.1"},
	}

	response := sendWSMessage(t, conn, MsgTypeSessionInit, "", initData)

	// Verify response
	if response.Type != MsgTypeSessionInitResp {
		t.Errorf("Expected response type %s, got %s", MsgTypeSessionInitResp, response.Type)
	}

	if response.Error != "" {
		t.Errorf("Unexpected error in response: %s", response.Error)
	}

	if response.SessionID == "" {
		t.Error("Session ID should not be empty")
	}

	// Parse response data
	var initResp WSSessionInitResponse
	if err := json.Unmarshal(response.Data, &initResp); err != nil {
		t.Fatalf("Failed to unmarshal session init response: %v", err)
	}

	if initResp.Status != "client_hello_ready" {
		t.Errorf("Expected status 'client_hello_ready', got '%s'", initResp.Status)
	}

	if len(initResp.ClientHello) == 0 {
		t.Error("Client Hello should not be empty")
	}

	// Verify session was created
	storeMutex.RLock()
	session, exists := sessionStore[response.SessionID]
	storeMutex.RUnlock()

	if !exists {
		t.Error("Session should exist in session store")
	}

	if session.WebsiteURL != "example.com:443" {
		t.Errorf("Expected website URL 'example.com:443', got '%s'", session.WebsiteURL)
	}
}

func TestEncryptRequest(t *testing.T) {
	server := createTestServer()
	defer server.Close()

	conn := createTestWSConnection(t, server)
	defer conn.Close()

	// First initialize a session
	initData := SessionInitData{
		Hostname: "example.com",
		Port:     443,
	}

	initResponse := sendWSMessage(t, conn, MsgTypeSessionInit, "", initData)
	sessionID := initResponse.SessionID

	// Test encrypt request
	encryptData := EncryptRequestData{
		RedactedRequest: []byte("GET /api/data HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		CommitmentS:     []byte("commitment_s_data"),
		CommitmentSP:    []byte("commitment_sp_data"),
		Nonce:           []byte("test_nonce"),
	}

	response := sendWSMessage(t, conn, MsgTypeEncryptReq, sessionID, encryptData)

	// Verify response
	if response.Type != MsgTypeEncryptResp {
		t.Errorf("Expected response type %s, got %s", MsgTypeEncryptResp, response.Type)
	}

	if response.Error != "" {
		t.Errorf("Unexpected error in response: %s", response.Error)
	}

	// Parse response data
	var encryptResp EncryptResponseData
	if err := json.Unmarshal(response.Data, &encryptResp); err != nil {
		t.Fatalf("Failed to unmarshal encrypt response: %v", err)
	}

	if encryptResp.Status != "encrypted" {
		t.Errorf("Expected status 'encrypted', got '%s'", encryptResp.Status)
	}

	if len(encryptResp.EncryptedRequest) == 0 {
		t.Error("Encrypted request should not be empty")
	}

	if len(encryptResp.TagSecrets) == 0 {
		t.Error("Tag secrets should not be empty")
	}

	// Verify session state was updated
	storeMutex.RLock()
	session, exists := sessionStore[sessionID]
	storeMutex.RUnlock()

	if !exists {
		t.Error("Session should still exist")
	}

	if session.RequestCount != 1 {
		t.Errorf("Expected request count 1, got %d", session.RequestCount)
	}
}

func TestDecryptRequest(t *testing.T) {
	server := createTestServer()
	defer server.Close()

	conn := createTestWSConnection(t, server)
	defer conn.Close()

	// Initialize session
	initData := SessionInitData{Hostname: "example.com"}
	initResponse := sendWSMessage(t, conn, MsgTypeSessionInit, "", initData)
	sessionID := initResponse.SessionID

	// Test decrypt request
	decryptData := DecryptRequestData{
		ResponseLength: 1024,
		TEETSuccess:    true,
		TEETMessage:    "Tag verification successful",
	}

	response := sendWSMessage(t, conn, MsgTypeDecryptReq, sessionID, decryptData)

	// Verify response
	if response.Type != MsgTypeDecryptResp {
		t.Errorf("Expected response type %s, got %s", MsgTypeDecryptResp, response.Type)
	}

	if response.Error != "" {
		t.Errorf("Unexpected error in response: %s", response.Error)
	}

	// Parse response data
	var decryptResp DecryptResponseData
	if err := json.Unmarshal(response.Data, &decryptResp); err != nil {
		t.Fatalf("Failed to unmarshal decrypt response: %v", err)
	}

	if decryptResp.Status != "decryption_stream_ready" {
		t.Errorf("Expected status 'decryption_stream_ready', got '%s'", decryptResp.Status)
	}

	if len(decryptResp.DecryptionStream) != 1024 {
		t.Errorf("Expected decryption stream length 1024, got %d", len(decryptResp.DecryptionStream))
	}
}

func TestFinalizeRequest(t *testing.T) {
	server := createTestServer()
	defer server.Close()

	conn := createTestWSConnection(t, server)
	defer conn.Close()

	// Initialize session
	initData := SessionInitData{Hostname: "example.com"}
	initResponse := sendWSMessage(t, conn, MsgTypeSessionInit, "", initData)
	sessionID := initResponse.SessionID

	// Test finalize request
	finalizeData := FinalizeRequestData{
		FinalMessage: "Protocol completed successfully",
	}

	response := sendWSMessage(t, conn, MsgTypeFinalizeReq, sessionID, finalizeData)

	// Verify response
	if response.Type != MsgTypeFinalizeResp {
		t.Errorf("Expected response type %s, got %s", MsgTypeFinalizeResp, response.Type)
	}

	if response.Error != "" {
		t.Errorf("Unexpected error in response: %s", response.Error)
	}

	// Parse response data
	var finalizeResp FinalizeResponseData
	if err := json.Unmarshal(response.Data, &finalizeResp); err != nil {
		t.Fatalf("Failed to unmarshal finalize response: %v", err)
	}

	if finalizeResp.Status != "finalized" {
		t.Errorf("Expected status 'finalized', got '%s'", finalizeResp.Status)
	}

	if len(finalizeResp.SignedTranscript) == 0 {
		t.Error("Signed transcript should not be empty")
	}

	if len(finalizeResp.TLSKeys) == 0 {
		t.Error("TLS keys should not be empty")
	}

	// Verify session was marked as completed
	storeMutex.RLock()
	session, exists := sessionStore[sessionID]
	storeMutex.RUnlock()

	if !exists {
		t.Error("Session should still exist")
	}

	if !session.Completed {
		t.Error("Session should be marked as completed")
	}
}

func TestFullProtocolFlow(t *testing.T) {
	server := createTestServer()
	defer server.Close()

	conn := createTestWSConnection(t, server)
	defer conn.Close()

	// Step 1: Initialize session
	initData := SessionInitData{
		Hostname:      "api.example.com",
		Port:          443,
		SNI:           "api.example.com",
		ALPNProtocols: []string{"h2"},
	}

	initResp := sendWSMessage(t, conn, MsgTypeSessionInit, "", initData)
	sessionID := initResp.SessionID

	if sessionID == "" {
		t.Fatal("Session ID should not be empty")
	}

	// Step 2: Encrypt request
	encryptData := EncryptRequestData{
		RedactedRequest: []byte("POST /api/secure HTTP/1.1\r\nContent-Length: 100\r\n\r\n"),
		CommitmentS:     []byte("commitment_s_test"),
		CommitmentSP:    []byte("commitment_sp_test"),
		Nonce:           []byte("protocol_nonce"),
	}

	encryptResp := sendWSMessage(t, conn, MsgTypeEncryptReq, sessionID, encryptData)
	if encryptResp.Error != "" {
		t.Fatalf("Encrypt request failed: %s", encryptResp.Error)
	}

	// Step 3: Decrypt response
	decryptData := DecryptRequestData{
		ResponseLength: 2048,
		TEETSuccess:    true,
		TEETMessage:    "Authentication tag verified",
	}

	decryptResp := sendWSMessage(t, conn, MsgTypeDecryptReq, sessionID, decryptData)
	if decryptResp.Error != "" {
		t.Fatalf("Decrypt request failed: %s", decryptResp.Error)
	}

	// Step 4: Finalize protocol
	finalizeData := FinalizeRequestData{
		FinalMessage: "Full protocol test completed",
	}

	finalizeResp := sendWSMessage(t, conn, MsgTypeFinalizeReq, sessionID, finalizeData)
	if finalizeResp.Error != "" {
		t.Fatalf("Finalize request failed: %s", finalizeResp.Error)
	}

	// Verify final session state
	storeMutex.RLock()
	session, exists := sessionStore[sessionID]
	storeMutex.RUnlock()

	if !exists {
		t.Fatal("Session should exist after full protocol")
	}

	if !session.Completed {
		t.Error("Session should be completed after full protocol")
	}

	if session.RequestCount != 1 {
		t.Errorf("Expected 1 request processed, got %d", session.RequestCount)
	}
}

func TestErrorHandling(t *testing.T) {
	server := createTestServer()
	defer server.Close()

	conn := createTestWSConnection(t, server)
	defer conn.Close()

	// Test invalid message type
	invalidMsg := WSMessage{
		Type:      "invalid_type",
		Timestamp: time.Now().Unix(),
	}

	if err := conn.WriteJSON(invalidMsg); err != nil {
		t.Fatalf("Failed to send invalid message: %v", err)
	}

	var response WSMessage
	if err := conn.ReadJSON(&response); err != nil {
		t.Fatalf("Failed to read error response: %v", err)
	}

	if response.Type != MsgTypeError {
		t.Errorf("Expected error response, got %s", response.Type)
	}

	if response.Error == "" {
		t.Error("Error message should not be empty")
	}
}

func TestConcurrentSessions(t *testing.T) {
	server := createTestServer()
	defer server.Close()

	numSessions := 5
	var wg sync.WaitGroup
	sessionIDs := make([]string, numSessions)

	// Create multiple concurrent sessions
	for i := 0; i < numSessions; i++ {
		wg.Add(1)
		go func(sessionIndex int) {
			defer wg.Done()

			conn := createTestWSConnection(t, server)
			defer conn.Close()

			initData := SessionInitData{
				Hostname: fmt.Sprintf("test%d.example.com", sessionIndex),
				Port:     443,
			}

			response := sendWSMessage(t, conn, MsgTypeSessionInit, "", initData)
			if response.Error != "" {
				t.Errorf("Session %d initialization failed: %s", sessionIndex, response.Error)
				return
			}

			sessionIDs[sessionIndex] = response.SessionID
		}(i)
	}

	wg.Wait()

	// Verify all sessions were created
	storeMutex.RLock()
	defer storeMutex.RUnlock()

	for i, sessionID := range sessionIDs {
		if sessionID == "" {
			t.Errorf("Session %d ID should not be empty", i)
			continue
		}

		session, exists := sessionStore[sessionID]
		if !exists {
			t.Errorf("Session %d should exist in store", i)
			continue
		}

		expectedURL := fmt.Sprintf("test%d.example.com:443", i)
		if session.WebsiteURL != expectedURL {
			t.Errorf("Session %d expected URL %s, got %s", i, expectedURL, session.WebsiteURL)
		}
	}
}

func TestSessionNotFound(t *testing.T) {
	server := createTestServer()
	defer server.Close()

	conn := createTestWSConnection(t, server)
	defer conn.Close()

	// Try to encrypt with non-existent session
	encryptData := EncryptRequestData{
		RedactedRequest: []byte("test"),
	}

	response := sendWSMessage(t, conn, MsgTypeEncryptReq, "non-existent-session", encryptData)

	if response.Type != MsgTypeError {
		t.Errorf("Expected error response, got %s", response.Type)
	}

	if !strings.Contains(response.Error, "session not found") {
		t.Errorf("Expected 'session not found' error, got: %s", response.Error)
	}
}

func TestInvalidJSON(t *testing.T) {
	server := createTestServer()
	defer server.Close()

	conn := createTestWSConnection(t, server)
	defer conn.Close()

	// Send message with invalid JSON data (valid JSON but invalid structure)
	invalidMsg := WSMessage{
		Type:      MsgTypeSessionInit,
		Data:      json.RawMessage(`{"hostname": 123}`), // Invalid type for hostname
		Timestamp: time.Now().Unix(),
	}

	if err := conn.WriteJSON(invalidMsg); err != nil {
		t.Fatalf("Failed to send invalid JSON message: %v", err)
	}

	var response WSMessage
	if err := conn.ReadJSON(&response); err != nil {
		t.Fatalf("Failed to read error response: %v", err)
	}

	if response.Type != MsgTypeError {
		t.Errorf("Expected error response, got %s", response.Type)
	}
}

func TestConnectionCleanup(t *testing.T) {
	server := createTestServer()
	defer server.Close()

	// Create connection and session
	conn := createTestWSConnection(t, server)

	initData := SessionInitData{Hostname: "cleanup-test.com"}
	response := sendWSMessage(t, conn, MsgTypeSessionInit, "", initData)
	sessionID := response.SessionID

	// Verify connection is registered
	wsConnMutex.RLock()
	_, exists := wsConnections[sessionID]
	wsConnMutex.RUnlock()

	if !exists {
		t.Error("WebSocket connection should be registered")
	}

	// Close connection
	conn.Close()

	// Give some time for cleanup
	time.Sleep(100 * time.Millisecond)

	// Note: In a real scenario, the cleanup happens when the connection handler exits
	// For this test, we'll verify the session still exists (cleanup happens on connection close)
	storeMutex.RLock()
	_, sessionExists := sessionStore[sessionID]
	storeMutex.RUnlock()

	if !sessionExists {
		t.Error("Session should still exist after connection close")
	}
}

// Benchmark tests
func BenchmarkSessionInitialization(b *testing.B) {
	server := createTestServer()
	defer server.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn := createTestWSConnectionBench(b, server)

		initData := SessionInitData{
			Hostname: fmt.Sprintf("bench%d.example.com", i),
			Port:     443,
		}

		_ = sendWSMessageBench(b, conn, MsgTypeSessionInit, "", initData)
		conn.Close()
	}
}

func BenchmarkEncryptRequest(b *testing.B) {
	server := createTestServer()
	defer server.Close()

	// Setup session
	conn := createTestWSConnectionBench(b, server)
	defer conn.Close()

	initData := SessionInitData{Hostname: "benchmark.com"}
	initResp := sendWSMessageBench(b, conn, MsgTypeSessionInit, "", initData)
	sessionID := initResp.SessionID

	encryptData := EncryptRequestData{
		RedactedRequest: bytes.Repeat([]byte("test"), 256), // 1KB request
		CommitmentS:     []byte("benchmark_commitment_s"),
		CommitmentSP:    []byte("benchmark_commitment_sp"),
		Nonce:           []byte("benchmark_nonce"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sendWSMessageBench(b, conn, MsgTypeEncryptReq, sessionID, encryptData)
	}
}
