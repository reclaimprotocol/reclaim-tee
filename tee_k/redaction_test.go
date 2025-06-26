package main

import (
	"encoding/json"
	"tee/enclave"
	"testing"
)

// Test the extended EncryptRequestData structure for redaction support
func TestEncryptRequestData_Redaction_Marshaling(t *testing.T) {
	// Create test redaction data
	redactionProcessor := enclave.NewRedactionProcessor()

	request := &enclave.RedactionRequest{
		NonSensitive:   []byte("GET /api HTTP/1.1\r\n"),
		Sensitive:      []byte("secret-header"),
		SensitiveProof: []byte("auth-token"),
	}

	streams, err := redactionProcessor.GenerateRedactionStreams(
		len(request.Sensitive), len(request.SensitiveProof))
	if err != nil {
		t.Fatalf("Failed to generate streams: %v", err)
	}

	keys, err := redactionProcessor.GenerateCommitmentKeys()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	commitments, err := redactionProcessor.ComputeCommitments(streams, keys)
	if err != nil {
		t.Fatalf("Failed to compute commitments: %v", err)
	}

	// Test data structure using the same type as in handleEncryptRequest
	type EncryptRequestData struct {
		// Standard fields
		RequestData []byte            `json:"request_data"`
		Commitments map[string][]byte `json:"commitments"`
		Nonce       []byte            `json:"nonce"`
		AAD         []byte            `json:"aad"`

		// Redaction fields
		RedactionRequest *enclave.RedactionRequest `json:"redaction_request,omitempty"`
		RedactionStreams *enclave.RedactionStreams `json:"redaction_streams,omitempty"`
		RedactionKeys    *enclave.RedactionKeys    `json:"redaction_keys,omitempty"`
		UseRedaction     bool                      `json:"use_redaction"`
	}

	requestData := EncryptRequestData{
		UseRedaction:     true,
		RedactionRequest: request,
		RedactionStreams: streams,
		RedactionKeys:    keys,
		Commitments: map[string][]byte{
			"commitment_s":  commitments.CommitmentS,
			"commitment_sp": commitments.CommitmentSP,
		},
		Nonce: make([]byte, 12),
		AAD:   []byte("test-aad"),
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		t.Fatalf("Failed to marshal redaction request data: %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaledData EncryptRequestData
	err = json.Unmarshal(jsonData, &unmarshaledData)
	if err != nil {
		t.Fatalf("Failed to unmarshal redaction request data: %v", err)
	}

	// Verify unmarshaled data
	if !unmarshaledData.UseRedaction {
		t.Error("UseRedaction flag not preserved")
	}

	if unmarshaledData.RedactionRequest == nil {
		t.Fatal("RedactionRequest is nil after unmarshaling")
	}

	if string(unmarshaledData.RedactionRequest.NonSensitive) != string(request.NonSensitive) {
		t.Error("NonSensitive data not preserved")
	}

	if len(unmarshaledData.Commitments) != 2 {
		t.Errorf("Expected 2 commitments, got %d", len(unmarshaledData.Commitments))
	}
}

func TestEncryptRequestData_Standard_Marshaling(t *testing.T) {
	// Test standard (non-redaction) request data structure
	type EncryptRequestData struct {
		// Standard fields
		RequestData []byte            `json:"request_data"`
		Commitments map[string][]byte `json:"commitments"`
		Nonce       []byte            `json:"nonce"`
		AAD         []byte            `json:"aad"`

		// Redaction fields
		RedactionRequest *enclave.RedactionRequest `json:"redaction_request,omitempty"`
		RedactionStreams *enclave.RedactionStreams `json:"redaction_streams,omitempty"`
		RedactionKeys    *enclave.RedactionKeys    `json:"redaction_keys,omitempty"`
		UseRedaction     bool                      `json:"use_redaction"`
	}

	requestData := EncryptRequestData{
		RequestData:  []byte("Hello, World!"),
		UseRedaction: false,
		Nonce:        make([]byte, 12),
		AAD:          []byte("test-aad"),
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		t.Fatalf("Failed to marshal standard request data: %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaledData EncryptRequestData
	err = json.Unmarshal(jsonData, &unmarshaledData)
	if err != nil {
		t.Fatalf("Failed to unmarshal standard request data: %v", err)
	}

	// Verify unmarshaled data
	if unmarshaledData.UseRedaction {
		t.Error("UseRedaction should be false for standard request")
	}

	if unmarshaledData.RedactionRequest != nil {
		t.Error("RedactionRequest should be nil for standard request")
	}

	if string(unmarshaledData.RequestData) != "Hello, World!" {
		t.Error("RequestData not preserved")
	}
}

func TestEncryptResponseData_Redaction_Marshaling(t *testing.T) {
	// Test response data structure with redaction commitments
	type EncryptResponseData struct {
		EncryptedData        []byte                        `json:"encrypted_data"`
		Tag                  []byte                        `json:"tag"`
		Status               string                        `json:"status"`
		RedactionCommitments *enclave.RedactionCommitments `json:"redaction_commitments,omitempty"`
		UseRedaction         bool                          `json:"use_redaction"`
	}

	// Create test commitments
	commitments := &enclave.RedactionCommitments{
		CommitmentS:  make([]byte, 32),
		CommitmentSP: make([]byte, 32),
	}

	responseData := EncryptResponseData{
		EncryptedData:        []byte("encrypted-data"),
		Tag:                  []byte("auth-tag"),
		Status:               "encrypted_with_tag",
		RedactionCommitments: commitments,
		UseRedaction:         true,
	}

	// Test JSON marshaling
	jsonData, err := json.Marshal(responseData)
	if err != nil {
		t.Fatalf("Failed to marshal redaction response data: %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaledData EncryptResponseData
	err = json.Unmarshal(jsonData, &unmarshaledData)
	if err != nil {
		t.Fatalf("Failed to unmarshal redaction response data: %v", err)
	}

	// Verify unmarshaled data
	if !unmarshaledData.UseRedaction {
		t.Error("UseRedaction flag not preserved")
	}

	if unmarshaledData.RedactionCommitments == nil {
		t.Fatal("RedactionCommitments is nil after unmarshaling")
	}

	if len(unmarshaledData.RedactionCommitments.CommitmentS) != 32 {
		t.Error("CommitmentS length not preserved")
	}

	if len(unmarshaledData.RedactionCommitments.CommitmentSP) != 32 {
		t.Error("CommitmentSP length not preserved")
	}
}

func TestRedactionLogic_Integration(t *testing.T) {
	// Test the core redaction processing logic that would be used in handleEncryptRequest
	redactionProcessor := enclave.NewRedactionProcessor()

	// Create test data
	request := &enclave.RedactionRequest{
		NonSensitive:   []byte("GET /api/secure HTTP/1.1\r\nHost: example.com\r\n"),
		Sensitive:      []byte("User-Agent: MyApp/1.0"),
		SensitiveProof: []byte("Authorization: Bearer token-123"),
	}

	// Generate streams and keys
	streams, err := redactionProcessor.GenerateRedactionStreams(
		len(request.Sensitive), len(request.SensitiveProof))
	if err != nil {
		t.Fatalf("Failed to generate streams: %v", err)
	}
	defer streams.SecureZero()

	keys, err := redactionProcessor.GenerateCommitmentKeys()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}
	defer keys.SecureZero()

	// Compute commitments
	computedCommitments, err := redactionProcessor.ComputeCommitments(streams, keys)
	if err != nil {
		t.Fatalf("Failed to compute commitments: %v", err)
	}

	// Apply redaction (similar to what TEE_K does)
	redactedData, err := redactionProcessor.ApplyRedaction(request, streams)
	if err != nil {
		t.Fatalf("Failed to apply redaction: %v", err)
	}

	// Verify redacted data length
	expectedLen := len(request.NonSensitive) + len(request.Sensitive) + len(request.SensitiveProof)
	if len(redactedData) != expectedLen {
		t.Errorf("Expected redacted data length %d, got %d", expectedLen, len(redactedData))
	}

	// Verify commitments are computed correctly
	if len(computedCommitments.CommitmentS) != 32 {
		t.Errorf("Expected CommitmentS length 32, got %d", len(computedCommitments.CommitmentS))
	}

	if len(computedCommitments.CommitmentSP) != 32 {
		t.Errorf("Expected CommitmentSP length 32, got %d", len(computedCommitments.CommitmentSP))
	}

	// Test commitment verification (similar to what TEE_K does)
	err = redactionProcessor.VerifyCommitments(streams, keys, computedCommitments)
	if err != nil {
		t.Errorf("Commitment verification failed: %v", err)
	}

	// Test with wrong commitments (should fail)
	wrongCommitments := &enclave.RedactionCommitments{
		CommitmentS:  make([]byte, 32),
		CommitmentSP: computedCommitments.CommitmentSP, // Keep one correct
	}
	wrongCommitments.CommitmentS[0] = 0xFF // Make it wrong

	err = redactionProcessor.VerifyCommitments(streams, keys, wrongCommitments)
	if err == nil {
		t.Error("Expected verification to fail with wrong commitment")
	}

	t.Logf("Redaction integration test passed:")
	t.Logf("  Original data: %d bytes", expectedLen)
	t.Logf("  Redacted data: %d bytes", len(redactedData))
	t.Logf("  Commitments: S=%d, SP=%d bytes", len(computedCommitments.CommitmentS), len(computedCommitments.CommitmentSP))
}
