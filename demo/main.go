package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	clientlib "tee-mpc/libclient"
	"tee-mpc/proofverifier" // add new import
	"tee-mpc/shared"
	"time"

	"go.uber.org/zap"
)

func main() {
	// Initialize logger
	logger, err := shared.NewLoggerFromEnv("demo")
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logger.Sync()

	logger.Info("=== Client ===")

	// Default to enclave mode, fallback to standalone if specified
	teekURL := "wss://tee-k.reclaimprotocol.org/ws" // Default to enclave
	forceTLSVersion := ""                           // Default to auto-negotiate
	forceCipherSuite := ""                          // Default to auto-negotiate

	if len(os.Args) > 1 {
		teekURL = os.Args[1]
	}

	// Check for TLS version argument
	if len(os.Args) > 2 {
		forceTLSVersion = os.Args[2]
		if forceTLSVersion != "1.2" && forceTLSVersion != "1.3" && forceTLSVersion != "" {
			logger.Error("Invalid TLS version", zap.String("version", forceTLSVersion))
			fmt.Printf("Invalid TLS version '%s'. Use '1.2', '1.3', or omit for auto-negotiation\n", forceTLSVersion)
			os.Exit(1)
		}
	}

	// Check for cipher suite argument
	if len(os.Args) > 3 {
		forceCipherSuite = os.Args[3]
		// Validate cipher suite format (hex or name)
		if forceCipherSuite != "" && !isValidCipherSuite(forceCipherSuite) {
			logger.Error("Invalid cipher suite", zap.String("cipher_suite", forceCipherSuite))
			fmt.Printf("Invalid cipher suite '%s'. Use hex format (e.g. '0xc02f') or valid name\n", forceCipherSuite)
			os.Exit(1)
		}
	}

	logger.Info("Starting Client", zap.String("teek_url", teekURL))
	if forceTLSVersion != "" {
		logger.Info("Forcing TLS version", zap.String("version", forceTLSVersion))
	} else {
		logger.Info("TLS version auto-negotiation enabled")
	}
	if forceCipherSuite != "" {
		logger.Info("Forcing cipher suite", zap.String("cipher_suite", forceCipherSuite))
	} else {
		logger.Info("Cipher suite auto-negotiation enabled")
	}

	// Auto-detect TEE_T URL based on TEE_K URL
	teetURL := autoDetectTEETURL(teekURL)
	logger.Info("Auto-detected TEE_T URL", zap.String("teet_url", teetURL))

	// Create demo request and redaction ranges
	demoRequest := createDemoRequest("github.com")
	demoRanges := createDemoRedactionRanges(demoRequest)

	logger.Info("Demo request created",
		zap.Int("request_length", len(demoRequest)),
		zap.Int("redaction_ranges", len(demoRanges)))

	// Create client configuration (without RequestRedactions since we'll set ranges directly)
	config := clientlib.ClientConfig{
		TEEKURL:          teekURL,
		TEETURL:          teetURL,
		Timeout:          clientlib.DefaultConnectionTimeout,
		Mode:             clientlib.ModeAuto,
		ResponseCallback: &DemoResponseCallback{},
		ForceTLSVersion:  forceTLSVersion,
		ForceCipherSuite: forceCipherSuite,
	}

	// Create client using library interface
	client := clientlib.NewReclaimClient(config)
	defer client.Close()

	// Connect to both TEE_K and TEE_T
	if err := client.Connect(); err != nil {
		logger.Error("Failed to connect", zap.Error(err))
		fmt.Printf("❌ Failed to connect: %v\n", err)
		return
	}

	// Set the demo request data and redaction ranges directly
	client.SetRequestData(demoRequest)
	client.SetRequestRedactionRanges(demoRanges)

	// Request HTTP to github.com (supports all cipher suites)
	if err := client.RequestHTTP("github.com", 443); err != nil {
		logger.Error("Failed to request HTTP", zap.Error(err))
		fmt.Printf("❌ Failed to request HTTP: %v\n", err)
		return
	}

	// Wait for processing to complete using proper completion tracking
	logger.Info("⏳ Waiting for all processing to complete...")
	logger.Info(" (decryption streams + redaction verification)")

	var protocolCompleted bool
	select {
	case <-client.WaitForCompletion():
		logger.Info(" Split AEAD protocol completed successfully!")
		protocolCompleted = true
	case <-time.After(clientlib.DefaultProcessingTimeout): // Configurable processing timeout
		logger.Error("⏰ Processing timeout - protocol did not complete")
		logger.Error("❌ SECURITY: Cannot generate verification bundle with incomplete data")
		protocolCompleted = false
	}

	// Demonstrate accessing protocol results
	fmt.Println("\n===== PROTOCOL RESULTS =====")

	// Get complete protocol results
	result, err := client.GetProtocolResult()
	if err != nil {
		fmt.Printf("❌ Error getting protocol result: %v\n", err)
	} else {
		fmt.Printf("✅ Protocol Success: %v\n", result.Success)
		fmt.Printf("📋 Session ID: %s\n", result.SessionID)
		fmt.Printf("🎯 Target: %s:%d\n", result.RequestTarget, result.RequestPort)
		fmt.Printf("⏱️  Duration: %v\n", result.CompletionTime.Sub(result.StartTime))

		if !result.Success && result.ErrorMessage != "" {
			fmt.Printf("❌ Error: %s\n", result.ErrorMessage)
		}
	}

	// Get transcript results
	transcripts, err := client.GetTranscripts()
	if err != nil {
		fmt.Printf("❌ Error getting transcripts: %v\n", err)
	} else {
		fmt.Printf("\n📜 TRANSCRIPT RESULTS:\n")
		fmt.Printf("   Both Received: %v\n", transcripts.BothReceived)
		fmt.Printf("   Both Valid: %v\n", transcripts.BothSignaturesValid)

		if transcripts.TEEK != nil {
			fmt.Printf("   TEE_K: %d packets, %d bytes\n",
				len(transcripts.TEEK.Packets), len(transcripts.TEEK.Signature))
		}

		if transcripts.TEET != nil {
			fmt.Printf("   TEE_T: %d packets, %d bytes\n",
				len(transcripts.TEET.Packets), len(transcripts.TEET.Signature))
		}
	}

	// Get validation results
	validation, err := client.GetValidationResults()
	if err != nil {
		fmt.Printf("❌ Error getting validation results: %v\n", err)
	} else {
		fmt.Printf("\n🔍 VALIDATION RESULTS:\n")
		fmt.Printf("   All Validations Passed: %v\n", validation.AllValidationsPassed)
		fmt.Printf("   Summary: %s\n", validation.ValidationSummary)
		fmt.Printf("   Transcript Validation: %v\n", validation.TranscriptValidation.OverallValid)
		fmt.Printf("   Attestation Validation: %v\n", validation.AttestationValidation.OverallValid)
	}

	// Get response results
	response, err := client.GetResponseResults()
	if err != nil {
		fmt.Printf("❌ Error getting response results: %v\n", err)
	} else {
		fmt.Printf("\n📨 RESPONSE RESULTS:\n")
		fmt.Printf("   Response Received: %v\n", response.ResponseReceived)
		fmt.Printf("   Callback Executed: %v\n", response.CallbackExecuted)
		fmt.Printf("   Decryption Successful: %v\n", response.DecryptionSuccessful)
		fmt.Printf("   Data Size: %d bytes\n", response.DecryptedDataSize)
	}

	fmt.Println("\n Client processing completed!")

	// SECURITY: Only build verification bundle if protocol completed successfully
	if !protocolCompleted {
		fmt.Printf("\n❌ SECURITY ERROR: Protocol did not complete - refusing to generate verification bundle\n")
		fmt.Printf("❌ Incomplete data cannot be verified and would be a security risk\n")
		log.Fatalf("Protocol incomplete - exiting for security")
	}

	// Build verification bundle and save to file
	bundlePath := "verification_bundle.json"
	if err := client.(*clientlib.ReclaimClientImpl).Client.BuildVerificationBundle(bundlePath); err != nil {
		fmt.Printf("\n🔴 Failed to build verification bundle: %v\n", err)
		log.Fatalf("Cannot create verification bundle: %v", err)
	} else {
		fmt.Printf("\n💾 Verification bundle written to %s\n", bundlePath)
	}

	// Run offline verification using the new verifier package
	if err := proofverifier.Validate(bundlePath); err != nil {
		log.Fatalf("\n🔴 Offline verification failed: %v\n", err)
	} else {
		fmt.Println("\n✅ Offline verification succeeded")
	}

}

// autoDetectTEETURL automatically detects the appropriate TEE_T URL based on TEE_K URL
// isValidCipherSuite validates cipher suite format and name
func isValidCipherSuite(cipherSuite string) bool {
	return shared.IsValidCipherSuite(cipherSuite)
}

func autoDetectTEETURL(teekURL string) string {
	if strings.HasPrefix(teekURL, "wss://") && strings.Contains(teekURL, "reclaimprotocol.org") {
		// Enclave mode: TEE_K is using enclave domain, so TEE_T should too
		return "wss://tee-t.reclaimprotocol.org/ws"
	} else if strings.HasPrefix(teekURL, "ws://") && strings.Contains(teekURL, "localhost") {
		// Standalone mode: TEE_K is using localhost, so TEE_T should too
		return "ws://localhost:8081/ws"
	} else {
		// Custom URL - try to infer the pattern
		if strings.HasPrefix(teekURL, "wss://") {
			// Assume enclave mode for any wss:// URL
			return "wss://tee-t.reclaimprotocol.org/ws"
		} else {
			// Assume standalone mode for any ws:// URL
			return "ws://localhost:8081/ws"
		}
	}
}

// PatternMatch represents a pattern match result (moved from libclient)
type PatternMatch struct {
	Start  int
	Length int
	Value  string
}

// findPatternMatches finds all matches for a pattern in the request string (moved from libclient)
// This is demo-specific pattern matching logic
func findPatternMatches(request, pattern string) []PatternMatch {
	var matches []PatternMatch

	// For now, implement simple literal matching
	// In a full implementation, this would use regex
	if strings.Contains(pattern, "Authorization: Bearer") {
		// Handle Authorization header pattern
		start := strings.Index(request, "Authorization: Bearer ")
		if start != -1 {
			lineEnd := strings.Index(request[start:], "\r\n")
			if lineEnd == -1 {
				lineEnd = strings.Index(request[start:], "\n")
			}
			if lineEnd != -1 {
				// Extract just the token part
				tokenStart := start + len("Authorization: Bearer ")
				tokenEnd := start + lineEnd
				matches = append(matches, PatternMatch{
					Start:  tokenStart,
					Length: tokenEnd - tokenStart,
					Value:  request[tokenStart:tokenEnd],
				})
			}
		}
	} else if strings.Contains(pattern, "X-Account-ID:") {
		// Handle X-Account-ID header pattern
		start := strings.Index(request, "X-Account-ID: ")
		if start != -1 {
			lineEnd := strings.Index(request[start:], "\r\n")
			if lineEnd == -1 {
				lineEnd = strings.Index(request[start:], "\n")
			}
			if lineEnd != -1 {
				// Extract just the account ID part
				idStart := start + len("X-Account-ID: ")
				idEnd := start + lineEnd
				matches = append(matches, PatternMatch{
					Start:  idStart,
					Length: idEnd - idStart,
					Value:  request[idStart:idEnd],
				})
			}
		}
	} else if strings.Contains(pattern, "User-Agent") {
		// Handle User-Agent header pattern
		start := strings.Index(request, "User-Agent: ")
		if start != -1 {
			lineEnd := strings.Index(request[start:], "\r\n")
			if lineEnd == -1 {
				lineEnd = strings.Index(request[start:], "\n")
			}
			if lineEnd != -1 {
				// Extract just the user agent part
				uaStart := start + len("User-Agent: ")
				uaEnd := start + lineEnd
				matches = append(matches, PatternMatch{
					Start:  uaStart,
					Length: uaEnd - uaStart,
					Value:  request[uaStart:uaEnd],
				})
			}
		}
	} else if strings.Contains(pattern, "Accept:") {
		// Handle Accept header pattern
		start := strings.Index(request, "Accept: ")
		if start != -1 {
			lineEnd := strings.Index(request[start:], "\r\n")
			if lineEnd == -1 {
				lineEnd = strings.Index(request[start:], "\n")
			}
			if lineEnd != -1 {
				// Extract just the accept part
				acceptStart := start + len("Accept: ")
				acceptEnd := start + lineEnd
				matches = append(matches, PatternMatch{
					Start:  acceptStart,
					Length: acceptEnd - acceptStart,
					Value:  request[acceptStart:acceptEnd],
				})
			}
		}
	} else if strings.Contains(pattern, "X-Session-Token:") {
		// Handle X-Session-Token header pattern
		start := strings.Index(request, "X-Session-Token: ")
		if start != -1 {
			lineEnd := strings.Index(request[start:], "\r\n")
			if lineEnd == -1 {
				lineEnd = strings.Index(request[start:], "\n")
			}
			if lineEnd != -1 {
				// Extract just the session token part
				tokenStart := start + len("X-Session-Token: ")
				tokenEnd := start + lineEnd
				matches = append(matches, PatternMatch{
					Start:  tokenStart,
					Length: tokenEnd - tokenStart,
					Value:  request[tokenStart:tokenEnd],
				})
			}
		}
	} else if strings.Contains(pattern, "X-API-Key:") {
		// Handle X-API-Key header pattern
		start := strings.Index(request, "X-API-Key: ")
		if start != -1 {
			lineEnd := strings.Index(request[start:], "\r\n")
			if lineEnd == -1 {
				lineEnd = strings.Index(request[start:], "\n")
			}
			if lineEnd != -1 {
				// Extract just the API key part
				keyStart := start + len("X-API-Key: ")
				keyEnd := start + lineEnd
				matches = append(matches, PatternMatch{
					Start:  keyStart,
					Length: keyEnd - keyStart,
					Value:  request[keyStart:keyEnd],
				})
			}
		}
	} else if strings.Contains(pattern, "X-User-ID:") {
		// Handle X-User-ID header pattern
		start := strings.Index(request, "X-User-ID: ")
		if start != -1 {
			lineEnd := strings.Index(request[start:], "\r\n")
			if lineEnd == -1 {
				lineEnd = strings.Index(request[start:], "\n")
			}
			if lineEnd != -1 {
				// Extract just the user ID part
				userIdStart := start + len("X-User-ID: ")
				userIdEnd := start + lineEnd
				matches = append(matches, PatternMatch{
					Start:  userIdStart,
					Length: userIdEnd - userIdStart,
					Value:  request[userIdStart:userIdEnd],
				})
			}
		}
	}

	return matches
}

// createDemoRedactionRanges creates redaction ranges for the demo request
// This function applies demo-specific redaction specifications to create ranges
func createDemoRedactionRanges(httpRequest []byte) []shared.RequestRedactionRange {
	var ranges []shared.RequestRedactionRange
	requestStr := string(httpRequest)

	// Demo redaction specifications
	demoSpecs := []clientlib.RedactionSpec{
		{Pattern: "Authorization: Bearer", Type: shared.RedactionTypeSensitiveProof},
		{Pattern: "X-Account-ID:", Type: shared.RedactionTypeSensitive},
		{Pattern: "X-Session-Token:", Type: shared.RedactionTypeSensitiveProof},
		{Pattern: "X-API-Key:", Type: shared.RedactionTypeSensitiveProof},
		{Pattern: "X-User-ID:", Type: shared.RedactionTypeSensitiveProof},
	}

	// Apply demo redaction specifications
	for _, spec := range demoSpecs {
		matches := findPatternMatches(requestStr, spec.Pattern)
		for _, match := range matches {
			ranges = append(ranges, shared.RequestRedactionRange{
				Start:  match.Start,
				Length: match.Length,
				Type:   spec.Type,
			})
		}
	}

	return ranges
}

// createDemoRequest creates the demo HTTP request
func createDemoRequest(host string) []byte {
	// Create HTTP request with test sensitive data including multiple R_SP headers
	testRequest := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer secret_auth_token_12345\r\nX-Account-ID: ACC987654321\r\nX-Session-Token: sess_abc123def456\r\nX-API-Key: api_key_xyz789uvw012\r\nX-User-ID: user_987654321\r\nConnection: close\r\n\r\n", host)
	return []byte(testRequest)
}

// DemoResponseCallback provides a demo implementation showing response redaction
type DemoResponseCallback struct{}

// OnResponseReceived implements the ResponseCallback interface with demo redactions
func (d *DemoResponseCallback) OnResponseReceived(response *clientlib.HTTPResponse) (*clientlib.RedactionResult, error) {
	// Work with the full HTTP response for redaction calculations
	fullHTTPResponse := string(response.FullResponse)

	fmt.Printf("[DemoCallback] Processing full HTTP response (%d bytes)\n", len(fullHTTPResponse))

	// Apply redaction logic (moved from applyRedactionForDisplay)
	redactedResponse := d.applyDemoRedaction(fullHTTPResponse)

	// Calculate redaction ranges based on differences between original and redacted
	redactionRanges := d.calculateRedactionRanges(fullHTTPResponse, redactedResponse)

	return &clientlib.RedactionResult{
		RedactedBody:    []byte(redactedResponse),
		RedactionRanges: redactionRanges,
	}, nil
}

// applyDemoRedaction applies the demo redaction logic (moved from applyRedactionForDisplay)
func (d *DemoResponseCallback) applyDemoRedaction(httpResponse string) string {
	// Find the end of headers (double CRLF)
	headerEndIndex := strings.Index(httpResponse, "\r\n\r\n")
	if headerEndIndex == -1 {
		// Try with just LF
		headerEndIndex = strings.Index(httpResponse, "\n\n")
		if headerEndIndex != -1 {
			headerEndIndex += 2 // Account for \n\n
		}
	} else {
		headerEndIndex += 4 // Account for \r\n\r\n
	}

	if headerEndIndex == -1 {
		// No clear header/body separation found, preserve everything (might be just headers)
		return httpResponse
	}

	// Split into headers and body
	headers := httpResponse[:headerEndIndex]
	bodyContent := httpResponse[headerEndIndex:]

	if len(bodyContent) == 0 {
		// Only headers, nothing to redact
		return httpResponse
	}

	// Find ALL title content within the body to preserve (only text between tags)
	titleStartTag := "<title>"
	titleEndTag := "</title>"

	// Find all title tag pairs
	type titleRange struct {
		contentStart int
		contentEnd   int
		textContent  string
	}

	var titleRanges []titleRange
	searchStart := 0

	for {
		titleStartIndex := strings.Index(bodyContent[searchStart:], titleStartTag)
		if titleStartIndex == -1 {
			break // No more title tags
		}

		titleStartIndex += searchStart // Adjust for search offset
		titleContentStartIndex := titleStartIndex + len(titleStartTag)

		titleEndIndex := strings.Index(bodyContent[titleContentStartIndex:], titleEndTag)
		if titleEndIndex != -1 {
			titleEndIndex = titleContentStartIndex + titleEndIndex

			// Extract the text content only
			titleText := bodyContent[titleContentStartIndex:titleEndIndex]

			titleRanges = append(titleRanges, titleRange{
				contentStart: titleContentStartIndex,
				contentEnd:   titleEndIndex,
				textContent:  titleText,
			})

			// Continue searching after this closing tag
			searchStart = titleEndIndex + len(titleEndTag)
		} else {
			// Found opening tag but no closing tag, skip it
			searchStart = titleContentStartIndex
		}
	}

	var redactedBody string
	if len(titleRanges) > 0 {
		// Build redacted body with all title texts preserved
		var result strings.Builder
		lastEnd := 0

		for _, tr := range titleRanges {
			// Redact from lastEnd to start of this title content
			if tr.contentStart > lastEnd {
				result.WriteString(strings.Repeat("*", tr.contentStart-lastEnd))
			}

			// Preserve the title text content
			result.WriteString(tr.textContent)

			lastEnd = tr.contentEnd
		}

		// Redact everything after the last title
		if lastEnd < len(bodyContent) {
			result.WriteString(strings.Repeat("*", len(bodyContent)-lastEnd))
		}

		redactedBody = result.String()
	} else {
		// No title tags found, redact entire body
		redactedBody = strings.Repeat("*", len(bodyContent))
	}

	return headers + redactedBody
}

// calculateRedactionRanges calculates redaction ranges based on differences between original and redacted responses
func (d *DemoResponseCallback) calculateRedactionRanges(original, redacted string) []shared.ResponseRedactionRange {
	var ranges []shared.ResponseRedactionRange

	// Simple implementation: find ranges where characters were replaced with asterisks
	i := 0
	for i < len(original) && i < len(redacted) {
		if original[i] != redacted[i] && redacted[i] == '*' {
			// Start of a redacted range
			start := i
			// Find the end of this redacted range
			for i < len(original) && i < len(redacted) && redacted[i] == '*' {
				i++
			}
			ranges = append(ranges, shared.ResponseRedactionRange{
				Start:  start,
				Length: i - start,
			})
		} else {
			i++
		}
	}

	return ranges
}
