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
		fmt.Println("⏰ Processing timeout - may indicate an issue")
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
	// For demo purposes, we'll create some basic redactions and claims
	redactedBody := make([]byte, len(response.Body))
	copy(redactedBody, response.Body)

	var redactionRanges []RedactionRange
	var proofClaims []ProofClaim

	// For demo purposes, no automatic redaction ranges - they're handled by redaction specification

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

	return &RedactionResult{
		RedactedBody:    redactedBody,
		RedactionRanges: redactionRanges,
		ProofClaims:     proofClaims,
	}, nil
}
