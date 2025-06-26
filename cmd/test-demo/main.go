package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"tee/enclave"
)

// HTTPRequestData represents the HTTP request structure for demo
type HTTPRequestData struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

func createRedactionRequest(httpReq HTTPRequestData) (*enclave.RedactionRequest, error) {
	// For demo purposes, we'll redact the "Auth" header
	// In a real implementation, this would be more sophisticated

	// Create a proper copy without the auth header for non-sensitive part
	authValue := httpReq.Headers["Auth"]

	// Make a deep copy of headers without the Auth header
	nonSensitiveHeaders := make(map[string]string)
	for k, v := range httpReq.Headers {
		if k != "Auth" {
			nonSensitiveHeaders[k] = v
		}
	}

	nonSensitiveReq := HTTPRequestData{
		Method:  httpReq.Method,
		URL:     httpReq.URL,
		Headers: nonSensitiveHeaders,
		Body:    httpReq.Body,
	}

	nonSensitiveBytes, err := json.Marshal(nonSensitiveReq)
	if err != nil {
		return nil, err
	}

	// The sensitive part is just the auth header
	authHeaderData := map[string]string{"Auth": authValue}
	sensitiveBytes, err := json.Marshal(authHeaderData)
	if err != nil {
		return nil, err
	}

	// For this demo, we'll use empty sensitive proof
	// In practice, this might contain proof-related data
	sensitiveProofBytes := []byte("")

	return &enclave.RedactionRequest{
		NonSensitive:   nonSensitiveBytes,
		Sensitive:      sensitiveBytes,
		SensitiveProof: sensitiveProofBytes,
	}, nil
}

func reconstructHTTPRequest(redactionRequest *enclave.RedactionRequest) (*HTTPRequestData, error) {
	// Combine non-sensitive and sensitive parts
	var combinedRequest HTTPRequestData

	// Parse non-sensitive part
	if err := json.Unmarshal(redactionRequest.NonSensitive, &combinedRequest); err != nil {
		return nil, fmt.Errorf("failed to parse non-sensitive data: %v", err)
	}

	// Parse and merge sensitive part (Auth header)
	if len(redactionRequest.Sensitive) > 0 {
		var sensitiveHeaders map[string]string
		if err := json.Unmarshal(redactionRequest.Sensitive, &sensitiveHeaders); err != nil {
			return nil, fmt.Errorf("failed to parse sensitive data: %v", err)
		}

		// Merge sensitive headers back into the request
		if combinedRequest.Headers == nil {
			combinedRequest.Headers = make(map[string]string)
		}
		for k, v := range sensitiveHeaders {
			combinedRequest.Headers[k] = v
		}
	}

	return &combinedRequest, nil
}

func printHTTPRequest(title string, req HTTPRequestData) {
	fmt.Printf("   %s:\n", title)
	fmt.Printf("     Method: %s\n", req.Method)
	fmt.Printf("     URL: %s\n", req.URL)
	fmt.Printf("     Headers:\n")
	for k, v := range req.Headers {
		if k == "Auth" {
			fmt.Printf("       %s: %s (🔒 SENSITIVE)\n", k, v)
		} else {
			fmt.Printf("       %s: %s\n", k, v)
		}
	}
	if req.Body != "" {
		fmt.Printf("     Body: %s\n", req.Body)
	}
	fmt.Println()
}

func printRedactionRequest(req *enclave.RedactionRequest) {
	fmt.Printf("   Redaction Breakdown:\n")
	fmt.Printf("     Non-sensitive data: %d bytes\n", len(req.NonSensitive))
	fmt.Printf("     Sensitive data: %d bytes (Auth header)\n", len(req.Sensitive))
	fmt.Printf("     Sensitive proof data: %d bytes\n", len(req.SensitiveProof))
	fmt.Printf("     Total: %d bytes\n", len(req.NonSensitive)+len(req.Sensitive)+len(req.SensitiveProof))
	fmt.Println()
}

// testDemo runs a local test of the redaction logic without network calls
func testDemo() error {
	fmt.Println("🧪 Testing Redaction Protocol Logic")
	fmt.Println(strings.Repeat("=", 40))

	// Step 1: Create test HTTP request
	originalRequest := HTTPRequestData{
		Method: "GET",
		URL:    "http://example.com",
		Headers: map[string]string{
			"Host":       "example.com",
			"User-Agent": "TEE-Demo-Client/1.0",
			"Auth":       "Bearer secret-token-12345",
		},
		Body: "",
	}

	fmt.Println("📝 Original Request Created:")
	printHTTPRequest("Test Request", originalRequest)

	// Step 2: Create redaction request
	redactionRequest, err := createRedactionRequest(originalRequest)
	if err != nil {
		return fmt.Errorf("failed to create redaction request: %v", err)
	}

	fmt.Println("🔒 Redaction Request:")
	printRedactionRequest(redactionRequest)

	// Step 3: Generate streams and commitments
	processor := enclave.NewRedactionProcessor()

	streams, err := processor.GenerateRedactionStreams(
		len(redactionRequest.Sensitive),
		len(redactionRequest.SensitiveProof),
	)
	if err != nil {
		return fmt.Errorf("failed to generate streams: %v", err)
	}

	keys, err := processor.GenerateCommitmentKeys()
	if err != nil {
		return fmt.Errorf("failed to generate keys: %v", err)
	}

	commitments, err := processor.ComputeCommitments(streams, keys)
	if err != nil {
		return fmt.Errorf("failed to compute commitments: %v", err)
	}

	fmt.Printf("🎲 Cryptographic Setup:\n")
	fmt.Printf("   Streams: S=%d bytes, SP=%d bytes\n",
		len(streams.StreamS), len(streams.StreamSP))
	fmt.Printf("   Commitments: S=%d bytes, SP=%d bytes\n",
		len(commitments.CommitmentS), len(commitments.CommitmentSP))

	// Step 4: Test commitment verification
	if err := processor.VerifyCommitments(streams, keys, commitments); err != nil {
		return fmt.Errorf("commitment verification failed: %v", err)
	}
	fmt.Println("   ✅ Commitment verification passed")

	// Step 5: Apply redaction
	redactedData, err := processor.ApplyRedaction(redactionRequest, streams)
	if err != nil {
		return fmt.Errorf("failed to apply redaction: %v", err)
	}
	fmt.Printf("   ✅ Redaction applied: %d bytes → %d bytes\n",
		len(redactionRequest.NonSensitive)+len(redactionRequest.Sensitive)+len(redactionRequest.SensitiveProof),
		len(redactedData))

	// Step 6: Test recovery
	recoveredRequest, err := processor.UnapplyRedaction(redactedData, streams, redactionRequest)
	if err != nil {
		return fmt.Errorf("failed to recover request: %v", err)
	}

	// Step 7: Reconstruct and verify
	reconstructedHTTP, err := reconstructHTTPRequest(recoveredRequest)
	if err != nil {
		return fmt.Errorf("failed to reconstruct HTTP request: %v", err)
	}

	fmt.Println("🔄 Reconstructed Request:")
	printHTTPRequest("Recovered Request", *reconstructedHTTP)

	// Step 8: Verify reconstruction is correct
	fmt.Printf("   🔍 Verification:\n")
	fmt.Printf("     Original Auth: '[%s]'\n", originalRequest.Headers["Auth"])
	fmt.Printf("     Reconstructed Auth: '[%s]'\n", reconstructedHTTP.Headers["Auth"])

	if reconstructedHTTP.Headers["Auth"] != originalRequest.Headers["Auth"] {
		return fmt.Errorf("auth header mismatch: got '%s', want '%s'",
			reconstructedHTTP.Headers["Auth"], originalRequest.Headers["Auth"])
	}
	fmt.Println("   ✅ Request reconstruction verified successfully")

	// Step 9: Test JSON serialization
	fmt.Println("📋 Testing JSON Serialization:")

	testData := map[string]interface{}{
		"redaction_request": redactionRequest,
		"streams":           streams,
		"keys":              keys,
		"commitments":       commitments,
	}

	jsonData, err := json.MarshalIndent(testData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal test data: %v", err)
	}
	fmt.Printf("   ✅ JSON serialization successful (%d bytes)\n", len(jsonData))

	// Step 10: Cleanup
	recoveredRequest.SecureZero()
	streams.SecureZero()
	keys.SecureZero()
	fmt.Println("   ✅ Secure cleanup completed")

	fmt.Println("\n🎉 All redaction protocol tests passed!")
	return nil
}

func main() {
	if err := testDemo(); err != nil {
		log.Fatalf("Test demo failed: %v", err)
	}
}
