package main

import (
	"crypto/ecdsa"
	"log"
	clientlib "tee-mpc/libclient"

	"github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"
)

// Example demonstrating how to submit a TEE verification bundle to attestor-core
func main() {

}

// Alternative example for GitHub provider
func submitGitHubClaim(client *clientlib.Client, privateKey *ecdsa.PrivateKey, logger *zap.Logger) {

	// Example private key (use your own in production)
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal("Failed to generate private key:", err)
	}

	// Execute TEE protocol (this would typically involve the full protocol)
	logger.Info("Starting TEE protocol...")

	// For this example, we'll assume the protocol has completed successfully
	// In real usage, you would call client.ExecuteProtocol() first

	// Example: Submit for HTTP provider claim
	httpParams := map[string]interface{}{
		"name":   "http",
		"method": "GET",
		"url":    "https://github.com",
		"responseMatches": []map[string]interface{}{
			{
				"type":  "regex",
				"value": "github",
			},
		},
		"responseRedactions": []map[string]interface{}{
			{
				"jsonPath": "$.cardano.usd",
				"regex":    "",
				"xPath":    "",
			},
			{
				"jsonPath": "$.solana.usd",
				"regex":    "",
				"xPath":    "",
			},
		},
	}

	claimParams := clientlib.ClaimTeeBundleParams{
		Provider:   "github",
		Parameters: httpParams,
		Context: map[string]interface{}{
			"purpose": "github_identity_proof",
		},
	}

	// Submit to attestor-core
	logger.Info("Submitting verification bundle to attestor-core...")

	// attestorURL := "wss://attestor.reclaimprotocol.org/ws" // Production
	attestorURL := "ws://localhost:8001/ws" // Local development

	claim, err := client.SubmitToAttestorCore(attestorURL, privateKey, claimParams)
	if err != nil {
		log.Fatal("Failed to submit to attestor-core:", err)
	}

	// Success!
	logger.Info("Claim validated successfully!",
		zap.String("claim_id", claim.Identifier),
		zap.String("provider", claim.Provider),
		zap.String("owner", claim.Owner),
		zap.String("parameters", claim.Parameters),
	)

	// You can now use the validated claim for your application
	log.Printf("Validated Claim: %+v", claim)
}
