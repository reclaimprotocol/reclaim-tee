package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	proofverifier "tee-mpc/proofverifier" // add new import
	"tee-mpc/shared"
	"time"
)

func main() {
	fmt.Println("=== Client ===")

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
			fmt.Printf("Invalid TLS version '%s'. Use '1.2', '1.3', or omit for auto-negotiation\n", forceTLSVersion)
			os.Exit(1)
		}
	}

	// Check for cipher suite argument
	if len(os.Args) > 3 {
		forceCipherSuite = os.Args[3]
		// Validate cipher suite format (hex or name)
		if forceCipherSuite != "" && !isValidCipherSuite(forceCipherSuite) {
			fmt.Printf("Invalid cipher suite '%s'. Use hex format (e.g. '0xc02f') or valid name\n", forceCipherSuite)
			os.Exit(1)
		}
	}

	fmt.Printf(" Starting Client, connecting to TEE_K at %s\n", teekURL)
	if forceTLSVersion != "" {
		fmt.Printf(" Forcing TLS version %s\n", forceTLSVersion)
	} else {
		fmt.Printf(" TLS version auto-negotiation enabled\n")
	}
	if forceCipherSuite != "" {
		fmt.Printf(" Forcing cipher suite %s\n", forceCipherSuite)
	} else {
		fmt.Printf(" Cipher suite auto-negotiation enabled\n")
	}

	// Auto-detect TEE_T URL based on TEE_K URL
	teetURL := autoDetectTEETURL(teekURL)
	fmt.Printf(" Auto-detected TEE_T URL: %s\n", teetURL)

	// Create client configuration
	config := ClientConfig{
		TEEKURL:           teekURL,
		TEETURL:           teetURL,
		Timeout:           30 * time.Second,
		Mode:              ModeAuto,
		RequestRedactions: getDemoRequestRedactions(),
		ResponseCallback:  &DemoResponseCallback{},
		ForceTLSVersion:   forceTLSVersion,
		ForceCipherSuite:  forceCipherSuite,
	}

	// Create client using library interface
	client := NewReclaimClient(config)
	defer client.Close()

	// Connect to both TEE_K and TEE_T
	if err := client.Connect(); err != nil {
		log.Fatalf("[Client] Failed to connect: %v", err)
	}

	// Request HTTP to github.com (supports all cipher suites)
	if err := client.RequestHTTP("github.com", 443); err != nil {
		log.Fatalf("[Client] Failed to request HTTP: %v", err)
	}

	// Wait for processing to complete using proper completion tracking
	fmt.Println("⏳ Waiting for all processing to complete...")
	fmt.Println(" (decryption streams + redaction verification)")

	select {
	case <-client.WaitForCompletion():
		fmt.Println(" Split AEAD protocol completed successfully!")
	case <-time.After(30 * time.Second): // Reasonable timeout instead of hardcoded wait
		panic("⏰ Processing timeout - may indicate an issue")
	}

	// *** NEW: Demonstrate accessing protocol results ***
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
		fmt.Printf("   Proof Claims: %d\n", len(response.ProofClaims))

		for i, claim := range response.ProofClaims {
			fmt.Printf("     %d. %s: %s\n", i+1, claim.Type, claim.Description)
		}
	}

	fmt.Println("\n Client processing completed!")

	// Build verification bundle and save to file
	bundlePath := "verification_bundle.json"
	if err := client.(*reclaimClientImpl).client.BuildVerificationBundle(bundlePath); err != nil {
		fmt.Printf("\n🔴 Failed to build verification bundle: %v\n", err)
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

// getDemoRequestRedactions returns demo request redaction specifications
func getDemoRequestRedactions() []RedactionSpec {
	return []RedactionSpec{
		{
			Pattern: "Authorization: Bearer [^\\r\\n]+",
			Type:    "sensitive",
		},
		{
			Pattern: "X-Account-ID: [^\\r\\n]+",
			Type:    "sensitive_proof",
		},
	}
}

// DemoResponseCallback provides a demo implementation showing response redaction
type DemoResponseCallback struct{}

// OnResponseReceived implements the ResponseCallback interface with demo redactions
func (d *DemoResponseCallback) OnResponseReceived(response *HTTPResponse) (*RedactionResult, error) {
	// Work with the full HTTP response for redaction calculations
	fullHTTPResponse := string(response.FullResponse)

	fmt.Printf("[DemoCallback] Processing full HTTP response (%d bytes)\n", len(fullHTTPResponse))

	// Apply redaction logic (moved from applyRedactionForDisplay)
	redactedResponse := d.applyDemoRedaction(fullHTTPResponse)

	// Calculate redaction ranges based on differences between original and redacted
	redactionRanges := d.calculateRedactionRanges(fullHTTPResponse, redactedResponse)

	var proofClaims []ProofClaim

	// Example: If this is an HTTP response, create some demo proof claims
	if response.StatusCode == 200 {
		proofClaims = append(proofClaims, ProofClaim{
			Type:        "status_code",
			Field:       "status_code",
			Value:       "200",
			Description: "Response status code is 200 OK",
		})
	}

	// Example: Create a claim about the server name
	if response.Metadata.ServerName != "" {
		proofClaims = append(proofClaims, ProofClaim{
			Type:        "server_name",
			Field:       "server_name",
			Value:       response.Metadata.ServerName,
			Description: "Connected to the specified server",
		})
	}

	// Example: Create proof claim about title content preservation
	if !strings.Contains(redactedResponse, "<title>") && !strings.Contains(redactedResponse, "</title>") {
		// Count how many title texts we preserved
		titleStartTag := "<title>"
		titleCount := strings.Count(string(response.FullResponse), titleStartTag)
		if titleCount > 0 {
			proofClaims = append(proofClaims, ProofClaim{
				Type:        "content_preservation",
				Field:       "html_title_texts",
				Value:       fmt.Sprintf("%d", titleCount),
				Description: fmt.Sprintf("HTML title text content from %d title tags is preserved and verifiable (tags redacted)", titleCount),
			})
		}
	}

	return &RedactionResult{
		RedactedBody:    []byte(redactedResponse),
		RedactionRanges: redactionRanges,
		ProofClaims:     proofClaims,
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

			fmt.Printf("[Debug] Found title %d: %q (positions %d-%d)\n",
				len(titleRanges), titleText, titleContentStartIndex, titleEndIndex)

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

		fmt.Printf("[Debug] Preserved %d title texts, body length: %d → %d\n",
			len(titleRanges), len(bodyContent), len(redactedBody))
	} else {
		// No title tags found, redact entire body
		redactedBody = strings.Repeat("*", len(bodyContent))
		fmt.Printf("[Debug] No title tags found, redacting entire body (%d bytes)\n", len(bodyContent))
	}

	return headers + redactedBody
}

// calculateRedactionRanges calculates redaction ranges based on differences between original and redacted responses
func (d *DemoResponseCallback) calculateRedactionRanges(original, redacted string) []RedactionRange {
	var ranges []RedactionRange

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
			ranges = append(ranges, RedactionRange{
				Start:  start,
				Length: i - start,
				Type:   "sensitive",
			})
		} else {
			i++
		}
	}

	return ranges
}
