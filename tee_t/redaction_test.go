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

// TestHandleRedactedTagComputation tests the redacted tag computation logic
func TestHandleRedactedTagComputation(t *testing.T) {
	// Setup test data
	processor := enclave.NewRedactionProcessor()

	// Create original request
	originalRequest := &enclave.RedactionRequest{
		NonSensitive:   []byte("public data"),
		Sensitive:      []byte("secret123"),
		SensitiveProof: []byte("proof456"),
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

	// Test successful redacted tag computation
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

		// In the redaction protocol, TEE_K sends the original ciphertext
		// (after applying redaction streams) to TEE_T for tag computation
		req := TagComputeRequest{
			Ciphertext:          originalCiphertext,
			TagSecrets:          tagSecrets,
			SessionID:           sessionID,
			UseRedaction:        true,
			OriginalRequestInfo: originalRequest,
		}

		tag, err := handleRedactedTagComputation(req)
		if err != nil {
			t.Fatalf("Redacted tag computation failed: %v", err)
		}

		if len(tag) == 0 {
			t.Errorf("Expected non-empty tag")
		}

		// Verify tag is correct by computing expected tag
		tagComputer := enclave.NewSplitAEADTagComputer()
		expectedTag, err := tagComputer.ComputeTag(originalCiphertext, tagSecrets)
		if err != nil {
			t.Fatalf("Failed to compute expected tag: %v", err)
		}

		if !bytes.Equal(tag, expectedTag) {
			t.Errorf("Computed tag does not match expected tag")
		}
	})

	// Test session not found
	t.Run("Session Not Found", func(t *testing.T) {
		req := TagComputeRequest{
			Ciphertext:          []byte("test"),
			TagSecrets:          &enclave.TagSecrets{},
			SessionID:           "nonexistent-session",
			UseRedaction:        true,
			OriginalRequestInfo: originalRequest,
		}

		_, err := handleRedactedTagComputation(req)
		if err == nil {
			t.Errorf("Expected error for non-existent session")
		}
	})

	// Test unverified session
	t.Run("Unverified Session", func(t *testing.T) {
		unverifiedSessionID := "unverified-session"
		unverifiedSessionData := &RedactionSessionData{
			RedactionStreams:   streams,
			RedactionProcessor: processor,
			Verified:           false, // Not verified
		}

		redactionSessionsMu.Lock()
		redactionSessions[unverifiedSessionID] = unverifiedSessionData
		redactionSessionsMu.Unlock()

		req := TagComputeRequest{
			Ciphertext:          []byte("test"),
			TagSecrets:          &enclave.TagSecrets{},
			SessionID:           unverifiedSessionID,
			UseRedaction:        true,
			OriginalRequestInfo: originalRequest,
		}

		_, err := handleRedactedTagComputation(req)
		if err == nil {
			t.Errorf("Expected error for unverified session")
		}
	})

	// Cleanup
	redactionSessionsMu.Lock()
	delete(redactionSessions, sessionID)
	delete(redactionSessions, "unverified-session")
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
		req := TagComputeRequest{
			Ciphertext: []byte("test ciphertext"),
			TagSecrets: tagSecrets,
		}

		jsonData, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("Failed to marshal standard request: %v", err)
		}

		var unmarshaledReq TagComputeRequest
		if err := json.Unmarshal(jsonData, &unmarshaledReq); err != nil {
			t.Fatalf("Failed to unmarshal standard request: %v", err)
		}

		if unmarshaledReq.UseRedaction {
			t.Errorf("Expected UseRedaction to be false for standard request")
		}
	})

	// Test redacted request
	t.Run("Redacted Request", func(t *testing.T) {
		req := TagComputeRequest{
			Ciphertext:          []byte("original ciphertext"),
			TagSecrets:          tagSecrets,
			SessionID:           "test-session",
			UseRedaction:        true,
			RedactedCiphertext:  []byte("redacted ciphertext"),
			OriginalRequestInfo: originalRequest,
		}

		jsonData, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("Failed to marshal redacted request: %v", err)
		}

		var unmarshaledReq TagComputeRequest
		if err := json.Unmarshal(jsonData, &unmarshaledReq); err != nil {
			t.Fatalf("Failed to unmarshal redacted request: %v", err)
		}

		if !unmarshaledReq.UseRedaction {
			t.Errorf("Expected UseRedaction to be true")
		}

		if unmarshaledReq.SessionID != req.SessionID {
			t.Errorf("Expected SessionID %s, got %s", req.SessionID, unmarshaledReq.SessionID)
		}

		if unmarshaledReq.OriginalRequestInfo == nil {
			t.Errorf("Expected OriginalRequestInfo to be present")
		}
	})
}
