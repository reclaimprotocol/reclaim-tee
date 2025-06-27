package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"tee/enclave"
	"testing"
)

// TestRedactionStreamDataStructures tests JSON marshaling/unmarshaling of redaction data structures
func TestRedactionStreamDataStructures(t *testing.T) {
	// Test RedactionStreamRequest
	req := RedactionStreamRequest{
		SessionID: "test-session-123",
		RedactionStreams: &enclave.RedactionStreams{
			StreamS:  []byte{0x01, 0x02, 0x03},
			StreamSP: []byte{0x04, 0x05, 0x06},
		},
		RedactionKeys: &enclave.RedactionKeys{
			KeyS:  make([]byte, 32),
			KeySP: make([]byte, 32),
		},
		ExpectedCommitments: &enclave.RedactionCommitments{
			CommitmentS:  []byte{0x07, 0x08, 0x09},
			CommitmentSP: []byte{0x0a, 0x0b, 0x0c},
		},
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal RedactionStreamRequest: %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaledReq RedactionStreamRequest
	if err := json.Unmarshal(jsonData, &unmarshaledReq); err != nil {
		t.Fatalf("Failed to unmarshal RedactionStreamRequest: %v", err)
	}

	// Validate fields
	if unmarshaledReq.SessionID != req.SessionID {
		t.Errorf("Expected SessionID %s, got %s", req.SessionID, unmarshaledReq.SessionID)
	}

	// Test RedactionStreamResponse
	resp := RedactionStreamResponse{
		SessionID: "test-session-123",
		Status:    "success",
		Ready:     true,
	}

	jsonData, err = json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal RedactionStreamResponse: %v", err)
	}

	var unmarshaledResp RedactionStreamResponse
	if err := json.Unmarshal(jsonData, &unmarshaledResp); err != nil {
		t.Fatalf("Failed to unmarshal RedactionStreamResponse: %v", err)
	}

	if unmarshaledResp.Status != resp.Status {
		t.Errorf("Expected Status %s, got %s", resp.Status, unmarshaledResp.Status)
	}
}

// TestRedactionStreamEndpoint tests the /process-redaction-streams endpoint
func TestRedactionStreamEndpoint(t *testing.T) {
	// Create test data
	processor := enclave.NewRedactionProcessor()
	streams, err := processor.GenerateRedactionStreams(10, 15)
	if err != nil {
		t.Fatalf("Failed to generate redaction streams: %v", err)
	}

	keys, err := processor.GenerateCommitmentKeys()
	if err != nil {
		t.Fatalf("Failed to generate commitment keys: %v", err)
	}

	commitments, err := processor.ComputeCommitments(streams, keys)
	if err != nil {
		t.Fatalf("Failed to compute commitments: %v", err)
	}

	request := RedactionStreamRequest{
		SessionID:           "test-session-456",
		RedactionStreams:    streams,
		RedactionKeys:       keys,
		ExpectedCommitments: commitments,
	}

	// Test successful request
	t.Run("Successful Request", func(t *testing.T) {
		jsonData, err := json.Marshal(request)
		if err != nil {
			t.Fatalf("Failed to marshal request: %v", err)
		}

		req, err := http.NewRequest("POST", "/process-redaction-streams", bytes.NewBuffer(jsonData))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(handleRedactionStreams)
		handler.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Expected status code %d, got %d", http.StatusOK, status)
		}

		var response RedactionStreamResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if response.Status != "success" {
			t.Errorf("Expected status 'success', got '%s'", response.Status)
		}

		if !response.Ready {
			t.Errorf("Expected Ready to be true")
		}

		if response.SessionID != request.SessionID {
			t.Errorf("Expected SessionID %s, got %s", request.SessionID, response.SessionID)
		}

		// Verify session data was stored
		redactionSessionsMu.RLock()
		sessionData, exists := redactionSessions[request.SessionID]
		redactionSessionsMu.RUnlock()

		if !exists {
			t.Errorf("Session data not found for session %s", request.SessionID)
		}

		if !sessionData.Verified {
			t.Errorf("Expected session to be verified")
		}
	})

	// Test invalid commitment
	t.Run("Invalid Commitment", func(t *testing.T) {
		invalidRequest := request
		// Tamper with commitment
		invalidRequest.ExpectedCommitments = &enclave.RedactionCommitments{
			CommitmentS:  []byte{0x99, 0x99, 0x99},
			CommitmentSP: []byte{0x99, 0x99, 0x99},
		}

		jsonData, err := json.Marshal(invalidRequest)
		if err != nil {
			t.Fatalf("Failed to marshal request: %v", err)
		}

		req, err := http.NewRequest("POST", "/process-redaction-streams", bytes.NewBuffer(jsonData))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(handleRedactionStreams)
		handler.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Expected status code %d, got %d", http.StatusOK, status)
		}

		var response RedactionStreamResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if response.Status != "error" {
			t.Errorf("Expected status 'error', got '%s'", response.Status)
		}

		if response.Ready {
			t.Errorf("Expected Ready to be false")
		}
	})

	// Test missing fields
	t.Run("Missing Session ID", func(t *testing.T) {
		invalidRequest := request
		invalidRequest.SessionID = ""

		jsonData, err := json.Marshal(invalidRequest)
		if err != nil {
			t.Fatalf("Failed to marshal request: %v", err)
		}

		req, err := http.NewRequest("POST", "/process-redaction-streams", bytes.NewBuffer(jsonData))
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(handleRedactionStreams)
		handler.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusBadRequest {
			t.Errorf("Expected status code %d, got %d", http.StatusBadRequest, status)
		}
	})

	// Test wrong HTTP method
	t.Run("Wrong HTTP Method", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/process-redaction-streams", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(handleRedactionStreams)
		handler.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusMethodNotAllowed {
			t.Errorf("Expected status code %d, got %d", http.StatusMethodNotAllowed, status)
		}
	})
}

// TestHandleRedactedTagComputation tests redacted tag computation with real redaction processing
func TestHandleRedactedTagComputation(t *testing.T) {
	// Create test redaction request
	originalRequest := &enclave.RedactionRequest{
		NonSensitive:   []byte("GET /api HTTP/1.1\nHost: example.com\n"),
		Sensitive:      []byte("Authorization: Bearer secret123\n"),
		SensitiveProof: []byte("X-Account: 1234567890\n"),
	}

	// Create processor and generate commitments
	processor := enclave.NewRedactionProcessor()
	keys := &enclave.RedactionKeys{
		KeyS:  make([]byte, 32),
		KeySP: make([]byte, 32),
	}

	// Generate streams
	streams, err := processor.GenerateRedactionStreams(len(originalRequest.Sensitive), len(originalRequest.SensitiveProof))
	if err != nil {
		t.Fatalf("Failed to generate streams: %v", err)
	}

	// Create session data
	sessionData := &RedactionSessionData{
		RedactionStreams:   streams,
		RedactionProcessor: processor,
		Verified:           true,
	}

	// Store session data
	sessionID := "test-redaction-session"
	redactionSessionsMu.Lock()
	redactionSessions[sessionID] = sessionData
	redactionSessionsMu.Unlock()

	// Test successful redacted tag computation through public interface
	t.Run("Successful Redaction Tag Computation", func(t *testing.T) {
		// Create original ciphertext (simulate encryption)
		originalCiphertext := make([]byte, 0)
		originalCiphertext = append(originalCiphertext, originalRequest.NonSensitive...)
		originalCiphertext = append(originalCiphertext, originalRequest.Sensitive...)
		originalCiphertext = append(originalCiphertext, originalRequest.SensitiveProof...)

		// Create tag secrets with proper values for GCM mode
		tagSecrets := &enclave.TagSecrets{
			Mode:   enclave.SplitAEAD_AES_GCM,
			Nonce:  make([]byte, 12),
			AAD:    []byte("test aad"),
			GCM_H:  make([]byte, 16),
			GCM_Y0: make([]byte, 16),
		}

		// Initialize tag secrets with some test values to avoid empty slices
		for i := range tagSecrets.GCM_H {
			tagSecrets.GCM_H[i] = byte(i + 1)
		}
		for i := range tagSecrets.GCM_Y0 {
			tagSecrets.GCM_Y0[i] = byte(i + 0x10)
		}

		// Test tag computation through the enclave package
		tagComputer := enclave.NewSplitAEADTagComputer()
		tag, err := tagComputer.ComputeTag(originalCiphertext, tagSecrets)
		if err != nil {
			t.Fatalf("Tag computation failed: %v", err)
		}

		if len(tag) == 0 {
			t.Errorf("Expected non-empty tag")
		}

		// Verify the tag is the expected length (16 bytes for GCM)
		if len(tag) != 16 {
			t.Errorf("Expected tag length 16, got %d", len(tag))
		}
	})

	// Test session not found scenario by testing redaction processing
	t.Run("Redaction Processing", func(t *testing.T) {
		// Test redaction application
		redactedData, err := processor.ApplyRedaction(originalRequest, streams)
		if err != nil {
			t.Fatalf("Failed to apply redaction: %v", err)
		}

		if len(redactedData) == 0 {
			t.Errorf("Expected non-empty redacted data")
		}

		// Test commitment computation
		commitments, err := processor.ComputeCommitments(streams, keys)
		if err != nil {
			t.Fatalf("Failed to compute commitments: %v", err)
		}

		if len(commitments.CommitmentS) == 0 || len(commitments.CommitmentSP) == 0 {
			t.Errorf("Expected non-empty commitments")
		}
	})

	// Cleanup
	redactionSessionsMu.Lock()
	delete(redactionSessions, sessionID)
	redactionSessionsMu.Unlock()
}

// TestExtendedTagComputeRequest tests the extended TagComputeRequest structure
func TestExtendedTagComputeRequest(t *testing.T) {
	originalRequest := &enclave.RedactionRequest{
		NonSensitive:   []byte("public"),
		Sensitive:      []byte("secret"),
		SensitiveProof: []byte("proof"),
	}

	tagSecrets := &enclave.TagSecrets{
		Mode:   enclave.SplitAEAD_AES_GCM,
		Nonce:  make([]byte, 12),
		AAD:    []byte("test aad"),
		GCM_H:  make([]byte, 16),
		GCM_Y0: make([]byte, 16),
	}

	// Test standard request (backward compatibility)
	t.Run("Standard Request", func(t *testing.T) {
		req := enclave.TagComputeRequest{
			Ciphertext:  []byte("test ciphertext"),
			TagSecrets:  tagSecrets,
			RequestType: "encrypt",
		}

		jsonData, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("Failed to marshal standard request: %v", err)
		}

		var unmarshaledReq enclave.TagComputeRequest
		if err := json.Unmarshal(jsonData, &unmarshaledReq); err != nil {
			t.Fatalf("Failed to unmarshal standard request: %v", err)
		}

		if unmarshaledReq.UseRedaction {
			t.Errorf("Expected UseRedaction to be false for standard request")
		}

		if unmarshaledReq.RequestType != "encrypt" {
			t.Errorf("Expected RequestType 'encrypt', got '%s'", unmarshaledReq.RequestType)
		}
	})

	// Test redacted request
	t.Run("Redacted Request", func(t *testing.T) {
		req := enclave.TagComputeRequest{
			Ciphertext:          []byte("original ciphertext"),
			TagSecrets:          tagSecrets,
			RequestType:         "encrypt",
			UseRedaction:        true,
			RedactedCiphertext:  []byte("redacted ciphertext"),
			OriginalRequestInfo: originalRequest,
		}

		jsonData, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("Failed to marshal redacted request: %v", err)
		}

		var unmarshaledReq enclave.TagComputeRequest
		if err := json.Unmarshal(jsonData, &unmarshaledReq); err != nil {
			t.Fatalf("Failed to unmarshal redacted request: %v", err)
		}

		if !unmarshaledReq.UseRedaction {
			t.Errorf("Expected UseRedaction to be true")
		}

		if unmarshaledReq.RequestType != "encrypt" {
			t.Errorf("Expected RequestType 'encrypt', got '%s'", unmarshaledReq.RequestType)
		}

		if unmarshaledReq.OriginalRequestInfo == nil {
			t.Errorf("Expected OriginalRequestInfo to be present")
		}
	})
}
