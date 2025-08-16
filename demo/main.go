package main

import (
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

	publicParams := providers.HTTPProviderParams{
		URL:    "https://vpic.nhtsa.dot.gov/api/vehicles/getallmanufacturers?format=json",
		Method: "GET",
		ResponseMatches: []providers.ResponseMatch{
			{
				Value: "TESLA, INC.",
			},
		},
		ResponseRedactions: []providers.ResponseRedaction{
			{
				JSONPath: "$.Results[*].Mfr_Name",
			},
		},
	}

	secretParams := providers.HTTPProviderSecretParams{
		Headers: map[string]string{
			"accept": "application/json, text/plain, */*",
		},
	}

	req, ranges, err := initParams(publicParams, secretParams)
	if err != nil {
		log.Fatalf("initParams: %s", err.Error())
	}

	logger.Info("Demo request created")

	// Create client configuration (without RequestRedactions since we'll set ranges directly)
	config := clientlib.ClientConfig{
		TEEKURL:          teekURL,
		TEETURL:          teetURL,
		Timeout:          clientlib.DefaultConnectionTimeout,
		Mode:             clientlib.ModeAuto,
		ResponseCallback: &DemoResponseCallback{Params: publicParams},
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
	client.SetRequestData(req)
	client.SetRequestRedactionRanges(ranges)

	// Request HTTP to github.com (supports all cipher suites)
	if err := client.RequestHTTP("vpic.nhtsa.dot.gov", 443); err != nil {
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
			totalTEEKBytes := 0
			for _, packet := range transcripts.TEEK.Packets {
				totalTEEKBytes += len(packet)
			}
			fmt.Printf("   TEE_K: %d packets, %d bytes data\n",
				len(transcripts.TEEK.Packets), totalTEEKBytes)
		}

		if transcripts.TEET != nil {
			totalTEETBytes := 0
			for _, packet := range transcripts.TEET.Packets {
				totalTEETBytes += len(packet)
			}
			fmt.Printf("   TEE_T: %d packets, %d bytes data\n",
				len(transcripts.TEET.Packets), totalTEETBytes)
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

// DemoResponseCallback provides a demo implementation showing response redaction
type DemoResponseCallback struct {
	Params providers.HTTPProviderParams
}

// OnResponseReceived implements the ResponseCallback interface with demo redactions
func (d *DemoResponseCallback) OnResponseReceived(response *clientlib.HTTPResponse) (*clientlib.RedactionResult, error) {
	// Work with the full HTTP response for redaction calculations
	fullHTTPResponse := string(response.FullResponse)

	fmt.Printf("[DemoCallback] Processing full HTTP response (%d bytes)\n", len(fullHTTPResponse))

	ctx := providers.ProviderCtx{Version: providers.ATTESTOR_VERSION_2_0_1}

	ranges, err := providers.GetResponseRedactions(response.FullResponse, d.Params, ctx)
	if err != nil {
		return nil, err
	}
	var respRanges []shared.ResponseRedactionRange
	for _, r := range ranges {
		respRanges = append(respRanges, shared.ResponseRedactionRange{
			Start:  r.From,
			Length: r.To - r.From,
		})
	}

	return &clientlib.RedactionResult{
		RedactionRanges: respRanges,
	}, nil
}

func initParams(params providers.HTTPProviderParams, secretParams providers.HTTPProviderSecretParams) ([]byte, []shared.RequestRedactionRange, error) {

	req, err := providers.CreateRequest(secretParams, params)
	if err != nil {
		return nil, []shared.RequestRedactionRange{}, err
	}

	var ranges []shared.RequestRedactionRange
	for _, r := range req.Redactions {
		ranges = append(ranges, shared.RequestRedactionRange{
			Start:  r.From,
			Length: r.To - r.From,
			Type:   "sensitive",
		})
	}
	return req.Data, ranges, nil
}
