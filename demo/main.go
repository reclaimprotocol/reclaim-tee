package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	clientlib "tee-mpc/libclient"
	"tee-mpc/proofverifier" // add new import
	"tee-mpc/providers"
	"tee-mpc/shared"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
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

	publicParams := &providers.HTTPProviderParams{
		URL:    "https://vpic.nhtsa.dot.gov/api/vehicles/getallmanufacturers?format=json",
		Method: "GET",
		ResponseMatches: []providers.ResponseMatch{
			{
				Value: "TESLA, INC.",
				Type:  "contains",
			},
		},
		ResponseRedactions: []providers.ResponseRedaction{
			{
				JSONPath: "$.Results[*].Mfr_Name",
			},
		},
	}

	secretParams := &providers.HTTPProviderSecretParams{
		Headers: map[string]string{
			"accept": "application/json, text/plain, */*",
		},
	}

	// Create provider data structure for JSON encoding (production format)
	providerData := clientlib.ProviderRequestData{
		Name:         "http",
		Params:       publicParams,
		SecretParams: secretParams,
	}

	// Encode provider params as JSON
	providerParamsJSON, err := json.Marshal(providerData)
	if err != nil {
		log.Fatalf("Failed to encode provider params as JSON: %v", err)
	}

	logger.Info("Demo provider params configured")

	// Create client configuration with basic settings
	config := clientlib.ClientConfig{
		TEEKURL:          teekURL,
		TEETURL:          teetURL,
		Timeout:          clientlib.DefaultConnectionTimeout,
		Mode:             clientlib.ModeAuto,
		ForceTLSVersion:  forceTLSVersion,
		ForceCipherSuite: forceCipherSuite,
	}

	// Create client using library interface
	client := clientlib.NewReclaimClient(config)
	defer client.Close()

	// Execute complete protocol with one call!
	if err := client.StartProtocol(string(providerParamsJSON)); err != nil {
		logger.Error("Failed to start protocol", zap.Error(err))
		fmt.Printf("❌ Failed to start protocol: %v\n", err)
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
			totalTEEKBytes := 0
			for _, data := range transcripts.TEEK.Data {
				totalTEEKBytes += len(data)
			}
			fmt.Printf("   TEE_K: %d data streams, %d bytes total\n",
				len(transcripts.TEEK.Data), totalTEEKBytes)
		}

		if transcripts.TEET != nil {
			totalTEETBytes := 0
			for _, data := range transcripts.TEET.Data {
				totalTEETBytes += len(data)
			}
			fmt.Printf("   TEE_T: %d data streams, %d bytes total\n",
				len(transcripts.TEET.Data), totalTEETBytes)
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

	// Test attestor-core submission
	fmt.Println("\n📡 Testing attestor-core submission...")

	// Generate a test private key for signing
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	claimParams := clientlib.ClaimTeeBundleParams{
		Provider:   "http",
		Parameters: publicParams,
		Context:    map[string]interface{}{"test": "demo"},
	}

	// Submit to local attestor-core
	claim, err := client.(*clientlib.ReclaimClientImpl).Client.SubmitToAttestorCore(
		"ws://localhost:8001/ws",
		privateKey,
		claimParams,
	)
	if err != nil {
		fmt.Printf("\n🔴 Attestor submission failed: %v\n", err)
	} else {
		fmt.Printf("\n✅ Attestor submission succeeded! Claim ID: %s\n", claim.Identifier)
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
