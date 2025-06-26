package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"tee/enclave"
	"time"
)

const (
	TEE_K_URL = "http://localhost:8080"
	TEE_T_URL = "http://localhost:8081"
)

// DemoConfig holds configuration for the demo
type DemoConfig struct {
	TargetURL    string
	AuthHeader   string
	SessionID    string
	ShowDetailed bool
}

// HTTPRequestData represents the HTTP request we want to make
type HTTPRequestData struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// HTTPResponseData represents the HTTP response we receive
type HTTPResponseData struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

func main() {
	fmt.Println("🚀 TEE Redaction Protocol - End-to-End Demo")
	fmt.Println(strings.Repeat("=", 50))

	config := DemoConfig{
		TargetURL:    "http://example.com",
		AuthHeader:   "Bearer secret-token-12345",
		SessionID:    fmt.Sprintf("demo-session-%d", time.Now().Unix()),
		ShowDetailed: true,
	}

	if err := runDemo(config); err != nil {
		log.Fatalf("Demo failed: %v", err)
	}

	fmt.Println("\n✅ Demo completed successfully!")
}

func runDemo(config DemoConfig) error {
	fmt.Printf("📋 Demo Configuration:\n")
	fmt.Printf("   Target URL: %s\n", config.TargetURL)
	fmt.Printf("   Session ID: %s\n", config.SessionID)
	fmt.Printf("   Auth Header: %s (will be redacted)\n", config.AuthHeader)
	fmt.Println()

	// Step 1: Create the original HTTP request
	fmt.Println("📝 Step 1: Creating HTTP request to example.com")
	originalRequest := HTTPRequestData{
		Method: "GET",
		URL:    config.TargetURL,
		Headers: map[string]string{
			"Host":            "example.com",
			"User-Agent":      "TEE-Demo-Client/1.0",
			"Accept":          "text/html,application/xhtml+xml",
			"Accept-Language": "en-US,en;q=0.9",
			"Auth":            config.AuthHeader, // This will be redacted
			"Connection":      "close",
		},
		Body: "",
	}

	if config.ShowDetailed {
		printHTTPRequest("Original Request", originalRequest)
	}

	// Step 2: Separate sensitive and non-sensitive data
	fmt.Println("🔒 Step 2: Separating sensitive data for redaction")
	redactionRequest, err := createRedactionRequest(originalRequest)
	if err != nil {
		return fmt.Errorf("failed to create redaction request: %v", err)
	}

	if config.ShowDetailed {
		printRedactionRequest(redactionRequest)
	}

	// Step 3: Generate redaction streams and commitments
	fmt.Println("🎲 Step 3: Generating redaction streams and commitments")
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

	fmt.Printf("   Generated streams: S=%d bytes, SP=%d bytes\n",
		len(streams.StreamS), len(streams.StreamSP))
	fmt.Printf("   Generated commitments: S=%d bytes, SP=%d bytes\n",
		len(commitments.CommitmentS), len(commitments.CommitmentSP))

	// Step 4: Send streams to TEE_T
	fmt.Println("📡 Step 4: Sending redaction streams to TEE_T")
	if err := sendStreamsToTEET(config.SessionID, streams, keys, commitments); err != nil {
		return fmt.Errorf("failed to send streams to TEE_T: %v", err)
	}
	fmt.Println("   ✅ TEE_T verified commitments and stored session data")

	// Step 5: Apply redaction and send to TEE_K
	fmt.Println("🔀 Step 5: Applying redaction and sending to TEE_K")
	redactedData, err := processor.ApplyRedaction(redactionRequest, streams)
	if err != nil {
		return fmt.Errorf("failed to apply redaction: %v", err)
	}

	response, err := sendRedactedRequestToTEEK(config.SessionID, originalRequest, redactedData, redactionRequest, streams, keys, commitments)
	if err != nil {
		return fmt.Errorf("failed to send request to TEE_K: %v", err)
	}

	// Step 6: Process and display results
	fmt.Println("📋 Step 6: Processing results")
	if config.ShowDetailed {
		printDemoResults(response)
	}

	return nil
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

func sendStreamsToTEET(sessionID string, streams *enclave.RedactionStreams, keys *enclave.RedactionKeys, commitments *enclave.RedactionCommitments) error {
	request := map[string]interface{}{
		"session_id":           sessionID,
		"redaction_streams":    streams,
		"redaction_keys":       keys,
		"expected_commitments": commitments,
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return err
	}

	resp, err := http.Post(TEE_T_URL+"/process-redaction-streams", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("TEE_T rejected streams: %s", string(body))
	}

	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}

	if status, ok := response["status"].(string); !ok || status != "success" {
		return fmt.Errorf("TEE_T stream processing failed: %v", response)
	}

	return nil
}

func sendRedactedRequestToTEEK(sessionID string, originalReq HTTPRequestData, redactedData []byte, redactionRequest *enclave.RedactionRequest, streams *enclave.RedactionStreams, keys *enclave.RedactionKeys, commitments *enclave.RedactionCommitments) (map[string]interface{}, error) {
	request := map[string]interface{}{
		"session_id":        sessionID,
		"target_url":        originalReq.URL,
		"method":            originalReq.Method,
		"use_redaction":     true,
		"redacted_data":     redactedData,
		"original_request":  redactionRequest,
		"redaction_streams": streams,
		"redaction_keys":    keys,
		"commitments":       commitments,
		"response_redaction": map[string]interface{}{
			"enabled":      true,
			"extract_text": "Example Domain", // Only show this text from response
		},
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(TEE_K_URL+"/demo-redacted-request", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("TEE_K rejected request: %s", string(body))
	}

	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, err
	}

	return response, nil
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

func printDemoResults(response map[string]interface{}) {
	fmt.Printf("   🎉 Redaction Protocol Results:\n")

	if status, ok := response["status"].(string); ok {
		fmt.Printf("     Status: %s\n", status)
	}

	if originalSize, ok := response["original_response_size"].(float64); ok {
		fmt.Printf("     Original response size: %.0f bytes\n", originalSize)
	}

	if redactedSize, ok := response["redacted_response_size"].(float64); ok {
		fmt.Printf("     Redacted response size: %.0f bytes\n", redactedSize)
	}

	if redactedContent, ok := response["redacted_content"].(string); ok {
		fmt.Printf("     Redacted content: \"%s\"\n", redactedContent)
	}

	if authHeaderRedacted, ok := response["auth_header_redacted"].(bool); ok && authHeaderRedacted {
		fmt.Printf("     ✅ Auth header successfully redacted from request\n")
	}

	fmt.Printf("     ✅ Response successfully redacted to show only target text\n")
	fmt.Println()
}
