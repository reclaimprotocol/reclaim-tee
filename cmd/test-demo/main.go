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
	// Implement the new redaction structure:
	// R_NS: domain, URL, and all public headers (goes as plaintext)
	// R_S: secret auth header (sensitive but not used in proof)
	// R_SP: bank account header (sensitive and used in proof)

	// Extract sensitive values
	authValue := httpReq.Headers["Auth"]
	bankAccountValue := httpReq.Headers["X-Bank-Account"]

	// R_NS: Create non-sensitive request with all public headers (domain, URL, public headers)
	nonSensitiveHeaders := make(map[string]string)
	for k, v := range httpReq.Headers {
		if k != "Auth" && k != "X-Bank-Account" {
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

	// R_S: The sensitive part is the auth header (not used in proof)
	authHeaderData := map[string]string{"Auth": authValue}
	sensitiveBytes, err := json.Marshal(authHeaderData)
	if err != nil {
		return nil, err
	}

	// R_SP: The sensitive proof part is the bank account header (used in proof)
	bankAccountData := map[string]string{"X-Bank-Account": bankAccountValue}
	sensitiveProofBytes, err := json.Marshal(bankAccountData)
	if err != nil {
		return nil, err
	}

	return &enclave.RedactionRequest{
		NonSensitive:   nonSensitiveBytes,
		Sensitive:      sensitiveBytes,
		SensitiveProof: sensitiveProofBytes,
	}, nil
}

func reconstructHTTPRequest(redactionRequest *enclave.RedactionRequest) (*HTTPRequestData, error) {
	// Combine non-sensitive, sensitive, and sensitive proof parts
	var combinedRequest HTTPRequestData

	// Parse non-sensitive part
	if err := json.Unmarshal(redactionRequest.NonSensitive, &combinedRequest); err != nil {
		return nil, fmt.Errorf("failed to parse non-sensitive data: %v", err)
	}

	// Initialize headers if nil
	if combinedRequest.Headers == nil {
		combinedRequest.Headers = make(map[string]string)
	}

	// Parse and merge sensitive part (Auth header)
	if len(redactionRequest.Sensitive) > 0 {
		var sensitiveHeaders map[string]string
		if err := json.Unmarshal(redactionRequest.Sensitive, &sensitiveHeaders); err != nil {
			return nil, fmt.Errorf("failed to parse sensitive data: %v", err)
		}

		// Merge sensitive headers back into the request
		for k, v := range sensitiveHeaders {
			combinedRequest.Headers[k] = v
		}
	}

	// Parse and merge sensitive proof part (Bank account header)
	if len(redactionRequest.SensitiveProof) > 0 {
		var sensitiveProofHeaders map[string]string
		if err := json.Unmarshal(redactionRequest.SensitiveProof, &sensitiveProofHeaders); err != nil {
			return nil, fmt.Errorf("failed to parse sensitive proof data: %v", err)
		}

		// Merge sensitive proof headers back into the request
		for k, v := range sensitiveProofHeaders {
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
			fmt.Printf("       %s: %s (R_S - SENSITIVE)\n", k, v)
		} else if k == "X-Bank-Account" {
			fmt.Printf("       %s: %s (R_SP - SENSITIVE PROOF)\n", k, v)
		} else {
			fmt.Printf("       %s: %s (R_NS - PUBLIC)\n", k, v)
		}
	}
	if req.Body != "" {
		fmt.Printf("     Body: %s\n", req.Body)
	}
	fmt.Println()
}

func printRedactionRequest(req *enclave.RedactionRequest) {
	fmt.Printf("   Redaction Breakdown:\n")
	fmt.Printf("     R_NS (Non-sensitive): %d bytes (domain, URL, public headers)\n", len(req.NonSensitive))
	fmt.Printf("     R_S (Sensitive): %d bytes (Auth header - not used in proof)\n", len(req.Sensitive))
	fmt.Printf("     R_SP (Sensitive Proof): %d bytes (Bank account header - used in proof)\n", len(req.SensitiveProof))
	fmt.Printf("     Total: %d bytes\n", len(req.NonSensitive)+len(req.Sensitive)+len(req.SensitiveProof))
	fmt.Println()
}

// testDemo runs a local test of the redaction logic without network calls
func testDemo() error {
	fmt.Println("Testing Redaction Protocol Logic")
	fmt.Println(strings.Repeat("=", 40))

	// Step 1: Create test HTTP request
	originalRequest := HTTPRequestData{
		Method: "GET",
		URL:    "http://example.com",
		Headers: map[string]string{
			"Host":            "example.com",
			"User-Agent":      "TEE-Demo-Client/1.0",
			"Accept":          "text/html,application/xhtml+xml",
			"Accept-Language": "en-US,en;q=0.9",
			"Auth":            "Bearer secret-token-12345", // R_S - sensitive
			"X-Bank-Account":  "ACC-987654321-TEST-BANK",   // R_SP - sensitive proof
			"Connection":      "close",
		},
		Body: "",
	}

	fmt.Println("Original Request Created:")
	printHTTPRequest("Test Request", originalRequest)

	// Step 2: Create redaction request
	redactionRequest, err := createRedactionRequest(originalRequest)
	if err != nil {
		return fmt.Errorf("failed to create redaction request: %v", err)
	}

	fmt.Println("Redaction Request:")
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

	fmt.Printf("Cryptographic Setup:\n")
	fmt.Printf("   Streams: S=%d bytes, SP=%d bytes\n",
		len(streams.StreamS), len(streams.StreamSP))
	fmt.Printf("   Commitments: S=%d bytes, SP=%d bytes\n",
		len(commitments.CommitmentS), len(commitments.CommitmentSP))

	// Step 4: Test commitment verification
	if err := processor.VerifyCommitments(streams, keys, commitments); err != nil {
		return fmt.Errorf("commitment verification failed: %v", err)
	}
	fmt.Println("   Commitment verification passed")

	// Step 5: Apply redaction
	redactedData, err := processor.ApplyRedaction(redactionRequest, streams)
	if err != nil {
		return fmt.Errorf("failed to apply redaction: %v", err)
	}
	fmt.Printf("   Redaction applied: %d bytes → %d bytes\n",
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

	fmt.Println("Reconstructed Request:")
	printHTTPRequest("Recovered Request", *reconstructedHTTP)

	// Step 8: Verify reconstruction is correct
	fmt.Printf("   Verification:\n")
	fmt.Printf("     Original Auth: '[%s]'\n", originalRequest.Headers["Auth"])
	fmt.Printf("     Reconstructed Auth: '[%s]'\n", reconstructedHTTP.Headers["Auth"])

	if reconstructedHTTP.Headers["Auth"] != originalRequest.Headers["Auth"] {
		return fmt.Errorf("auth header mismatch: got '%s', want '%s'",
			reconstructedHTTP.Headers["Auth"], originalRequest.Headers["Auth"])
	}
	fmt.Println("   Request reconstruction verified successfully")

	// Step 9: Test JSON serialization
	fmt.Println("Testing JSON Serialization:")

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
	fmt.Printf("   JSON serialization successful (%d bytes)\n", len(jsonData))

	// Step 10: Cleanup
	recoveredRequest.SecureZero()
	streams.SecureZero()
	keys.SecureZero()
	fmt.Println("   Secure cleanup completed")

	fmt.Println("\nAll redaction protocol tests passed!")
	return nil
}

func main() {
	if err := testDemo(); err != nil {
		log.Fatalf("Test demo failed: %v", err)
	}
}
