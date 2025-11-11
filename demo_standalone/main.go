package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"tee-mpc/client"
	"tee-mpc/minitls"
	"tee-mpc/providers"
	"tee-mpc/shared"

	"github.com/reclaimprotocol/zk-symmetric-crypto/gnark/libraries/prover/impl"
	"go.uber.org/zap"
)

// initializeZKCircuits loads the proving keys and R1CS files for OPRF algorithms
func initializeZKCircuits(logger *shared.Logger) error {
	// Define the circuits directory
	circuitsDir := "circuits"

	// Check if circuits directory exists
	if _, err := os.Stat(circuitsDir); os.IsNotExist(err) {
		// Try alternative paths
		alternativePaths := []string{
			"../circuits",
			"./circuits",
		}

		found := false
		for _, path := range alternativePaths {
			if _, err := os.Stat(path); err == nil {
				circuitsDir = path
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("circuits directory not found in any expected location")
		}
	}

	logger.Info("Initializing ZK circuits from directory", zap.String("path", circuitsDir))

	// Define algorithm mappings
	type circuitConfig struct {
		algorithmID   uint8
		pkFile        string
		r1csFile      string
		algorithmName string
	}

	circuits := []circuitConfig{
		{
			algorithmID:   impl.CHACHA20_OPRF,
			pkFile:        "pk.chacha20_oprf",
			r1csFile:      "r1cs.chacha20_oprf",
			algorithmName: "CHACHA20_OPRF",
		},
		{
			algorithmID:   impl.AES_128_OPRF,
			pkFile:        "pk.aes128_oprf",
			r1csFile:      "r1cs.aes128_oprf",
			algorithmName: "AES_128_OPRF",
		},
		{
			algorithmID:   impl.AES_256_OPRF,
			pkFile:        "pk.aes256_oprf",
			r1csFile:      "r1cs.aes256_oprf",
			algorithmName: "AES_256_OPRF",
		},
	}

	// Initialize each circuit
	for _, circuit := range circuits {
		// Read proving key
		pkPath := filepath.Join(circuitsDir, circuit.pkFile)
		pkData, err := os.ReadFile(pkPath)
		if err != nil {
			return fmt.Errorf("failed to read proving key for %s: %v", circuit.algorithmName, err)
		}

		// Read R1CS
		r1csPath := filepath.Join(circuitsDir, circuit.r1csFile)
		r1csData, err := os.ReadFile(r1csPath)
		if err != nil {
			return fmt.Errorf("failed to read R1CS for %s: %v", circuit.algorithmName, err)
		}

		// Initialize the algorithm
		success := impl.InitAlgorithm(circuit.algorithmID, pkData, r1csData)
		if !success {
			return fmt.Errorf("failed to initialize %s algorithm", circuit.algorithmName)
		}

		logger.Info("Successfully initialized ZK circuit",
			zap.String("algorithm", circuit.algorithmName),
			zap.Uint8("id", circuit.algorithmID),
			zap.Int("pk_size", len(pkData)),
			zap.Int("r1cs_size", len(r1csData)))
	}

	logger.Info("All ZK circuits initialized successfully")
	return nil
}

func main() {

	// Initialize logger
	logger := client.GetLogger("client", false)

	defer logger.Sync()

	// Initialize ZK circuits for OPRF
	if err := initializeZKCircuits(logger); err != nil {
		logger.Error("Failed to initialize ZK circuits", zap.Error(err))
		log.Fatalf("ZK circuit initialization failed: %v", err)
	}
	logger.Sync()

	// Show usage if requested
	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		fmt.Println("Usage: demo_standalone [teek_url] [tls_version] [cipher_suite] [attestor_url]")
		fmt.Println("  teek_url:     TEE_K WebSocket URL (default: wss://tee-k.reclaimprotocol.org/ws)")
		fmt.Println("  tls_version:  Force TLS version: 1.2, 1.3, or empty for auto")
		fmt.Println("  cipher_suite: Force cipher suite: hex (e.g. 0xc02f) or name")
		fmt.Println("  attestor_url: Attestor WebSocket URL (default: ws://localhost:8001/ws)")
		fmt.Println("\nExamples:")
		fmt.Println("  demo_standalone")
		fmt.Println("  demo_standalone ws://localhost:8080/ws")
		fmt.Println("  demo_standalone ws://localhost:8080/ws 1.2")
		fmt.Println("  demo_standalone ws://localhost:8080/ws 1.2 0xc02f ws://localhost:8001/ws")
		os.Exit(0)
	}

	logger.Info("=== Client ===")

	// Default to enclave mode, fallback to standalone if specified
	teekURL := "ws://localhost:8080/ws"                        // Default to enclave
	attestorURL := "wss://attestor.reclaimprotocol.org:444/ws" // Default attestor URL
	forceTLSVersion := ""                                      // Default to auto-negotiate
	forceCipherSuite := ""                                     // Default to auto-negotiate

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

	// Check for attestor URL argument
	if len(os.Args) > 4 {
		attestorURL = os.Args[4]
		logger.Info("Using custom attestor URL", zap.String("attestor_url", attestorURL))
	}

	logger.Info("Starting Client", zap.String("teek_url", teekURL), zap.String("attestor_url", attestorURL))
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

	providerParams := &providers.HTTPProviderParams{
		URL:    "https://sps.unipune.ac.in/app/",
		Method: "GET",
		ResponseMatches: []providers.ResponseMatch{
			{
				Value: "{{ttt}}",
				Type:  "contains",
			},
		},
		ResponseRedactions: []providers.ResponseRedaction{
			{
				XPath: "/html/body/div/div/div/section[3]/div/div/div/div/div/div/div/div[2]/strong[1]",
				Regex: "(?<ttt>Student Profile System \\(SPS\\))",
				Hash:  providers.HASH_TYPE_OPRF,
			},
		},
		ParamValues: map[string]string{
			"ttt": "Student Profile System (SPS)",
		},
	}

	secretParams := &providers.HTTPProviderSecretParams{
		Headers: map[string]string{
			"accept": "application/json, text/plain, */*",
		},
	}

	// Create provider data structure for JSON encoding (production format)
	providerData := client.ProviderRequestData{
		Name:         "http",
		Params:       providerParams,
		SecretParams: secretParams,
		Context:      `{"test":"demo","source":"standalone"}`,
	}

	logger.Info("Demo provider params configured")

	// Create reclaimClient configuration with basic settings
	config := client.ClientConfig{
		TEEKURL:             teekURL,
		TEETURL:             teetURL,
		AttestorURL:         attestorURL,
		Timeout:             client.DefaultConnectionTimeout,
		Mode:                client.ModeAuto,
		ForceTLSVersion:     forceTLSVersion,
		ForceCipherSuite:    forceCipherSuite,
		EnableProofVerifier: true, // Enable proof verification in standalone mode
	}

	// Create reclaimClient using library interface
	reclaimClient := client.NewReclaimClient(config)
	defer reclaimClient.Close()

	// Execute the complete protocol with progress reporting
	fmt.Println("\n🚀 Starting complete protocol execution...")
	result, err := reclaimClient.ExecuteCompleteProtocol(&providerData)
	if err != nil {
		fmt.Printf("\n🔴 Complete protocol execution failed: %v\n", err)
		log.Fatalf("Cannot execute complete protocol: %v", err)
	}

	// Display final results
	fmt.Printf("\n✅ Protocol completed successfully! Claim ID: %s\n", result.Claim.Identifier)
	fmt.Printf("🎯 Provider: %s\n", result.Claim.Provider)
	fmt.Printf("🔏 Attestor: %s\n", result.Signature.AttestorAddress)

	// Demonstrate accessing protocol results
	fmt.Println("\n===== PROTOCOL RESULTS =====")

	// Get complete protocol results
	protocolResult, err := reclaimClient.GetProtocolResult()
	if err != nil {
		fmt.Printf("❌ Error getting protocol result: %v\n", err)
	} else {
		fmt.Printf("✅ Protocol Success: %v\n", protocolResult.Success)
		fmt.Printf("📋 Session ID: %s\n", protocolResult.SessionID)
		fmt.Printf("🎯 Target: %s:%d\n", protocolResult.RequestTarget, protocolResult.RequestPort)
		fmt.Printf("⏱️  Duration: %v\n", protocolResult.CompletionTime.Sub(protocolResult.StartTime))

		if !protocolResult.Success && protocolResult.ErrorMessage != "" {
			fmt.Printf("❌ Error: %s\n", protocolResult.ErrorMessage)
		}
	}

	// Get transcript results
	transcripts, err := reclaimClient.GetTranscripts()
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
	validation, err := reclaimClient.GetValidationResults()
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
	response, err := reclaimClient.GetResponseResults()
	if err != nil {
		fmt.Printf("❌ Error getting response results: %v\n", err)
	} else {
		fmt.Printf("\n📨 RESPONSE RESULTS:\n")
		fmt.Printf("   Response Received: %v\n", response.ResponseReceived)
		fmt.Printf("   Callback Executed: %v\n", response.CallbackExecuted)
		fmt.Printf("   Decryption Successful: %v\n", response.DecryptionSuccessful)
		fmt.Printf("   Data Size: %d bytes\n", response.DecryptedDataSize)
	}

	// Display OPRF results if any were processed
	oprfRanges := reclaimClient.Client.GetOPRFRanges()
	if len(oprfRanges) > 0 {
		fmt.Printf("\n📊 OPRF Results Summary:\n")
		for start, oprfData := range oprfRanges {
			fmt.Printf("   Range [%d:%d]:\n", start, start+oprfData.Length)
			fmt.Printf("     - Data: %s\n", string(oprfData.Data[:min(32, len(oprfData.Data))]))
			fmt.Printf("     - OPRF Output: %x\n", oprfData.FinalOutput[:min(16, len(oprfData.FinalOutput))])
			fmt.Printf("     - ZK Proof: %d bytes\n", len(oprfData.ZKProof))
		}
	}

}

// autoDetectTEETURL automatically detects the appropriate TEE_T URL based on TEE_K URL
// isValidCipherSuite validates cipher suite format and name
func isValidCipherSuite(cipherSuite string) bool {
	return minitls.IsValidCipherSuite(cipherSuite)
}

func autoDetectTEETURL(teekURL string) string {
	if strings.HasPrefix(teekURL, "wss://") && strings.Contains(teekURL, "reclaimprotocol.org") {
		// Enclave mode: TEE_K is using enclave domain, so TEE_T should too
		return "wss://tee-t-gcp.reclaimprotocol.org/ws"
	} else if strings.HasPrefix(teekURL, "ws://") && strings.Contains(teekURL, "localhost") {
		// Standalone mode: TEE_K is using localhost, so TEE_T should too
		return "ws://localhost:8081/ws"
	} else {
		// Custom URL - try to infer the pattern
		if strings.HasPrefix(teekURL, "wss://") {
			// Assume enclave mode for any wss:// URL
			return "wss://tee-t-gcp.reclaimprotocol.org/ws"
		} else {
			// Assume standalone mode for any ws:// URL
			return "ws://localhost:8081/ws"
		}
	}
}
