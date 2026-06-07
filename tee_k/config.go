package main

import (
	"log"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/joho/godotenv"
)

type TEEKConfig struct {
	// Standalone mode settings
	Port    int    `json:"port"`
	TEETURL string `json:"teet_url"`

	// Enclave mode settings
	EnclaveMode bool   `json:"enclave_mode"`
	Domain      string `json:"domain"`
	KMSKey      string `json:"kms_key"`

	// KMS provider (Google KMS)
	KMSProvider     string `json:"kms_provider"`
	GoogleProjectID string `json:"google_project_id,omitempty"`
	GoogleLocation  string `json:"google_location,omitempty"`
	GoogleKeyRing   string `json:"google_key_ring,omitempty"`
	GoogleKeyName   string `json:"google_key_name,omitempty"`

	// TLS configuration
	ForceTLSVersion  string `json:"force_tls_version"`  // Force specific TLS version: "1.2", "1.3", or "" for auto
	ForceCipherSuite string `json:"force_cipher_suite"` // Force specific cipher suite: hex ID (e.g. "0xc02f") or name, or "" for auto

	// Router-mode settings (multi-pair architecture, Phase 3+).
	// Presence of RouterURL is what flips boot into router mode. When empty,
	// the binary falls back to the existing Lego/ACME enclave path.
	//
	// The TEE mints SA identity tokens with RouterURL as the `aud` claim;
	// the router validates against its own SA_TOKEN_AUDIENCE env var, so the
	// operator must keep router-side SA_TOKEN_AUDIENCE == TEE-side RouterURL.
	RouterURL               string `json:"router_url,omitempty"`
	SelfAddr                string `json:"self_addr,omitempty"`
	PeerAddr                string `json:"peer_addr,omitempty"`
	ExpectedPeerImageDigest string `json:"expected_peer_image_digest,omitempty"`
	// JWTPublicKey is the PEM-encoded ES256 verification key the router signs
	// allocation JWTs with. Read here so it's part of the bootstrapped config;
	// consumption is added in a later PR (client-WS JWT validation).
	JWTPublicKey string `json:"jwt_public_key,omitempty"`
}

// RouterMode returns true when the new multi-pair router boot path should be
// used. Detection is by presence of ROUTER_URL — all other router-mode env
// vars are required only when this is true.
func (c *TEEKConfig) RouterMode() bool {
	return c.RouterURL != ""
}

func LoadTEEKConfig() *TEEKConfig {
	err := godotenv.Load()
	if err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
	} else {
		log.Printf("Successfully loaded .env file")
	}

	// GCP uses Google KMS
	kmsProvider := "google"

	log.Printf("Configuration loaded - KMSProvider: %s", kmsProvider)

	enclaveMode := shared.GetEnvOrDefault("ENCLAVE_MODE", "false") == "true"

	// Determine TEE_T URL
	var teetURL string
	if enclaveMode {
		// GCP enclave mode - use production URL from env
		teetURL = shared.GetEnvOrDefault("TEET_URL", "wss://eu.tt.reclaimprotocol.org/teek")
	} else {
		// Standalone mode
		teetURL = shared.GetEnvOrDefault("TEET_URL", "ws://localhost:8081/teek")
	}

	// Determine TEE_K domain from env
	domain := shared.GetEnvOrDefault("ENCLAVE_DOMAIN", "eu.tk.reclaimprotocol.org")

	return &TEEKConfig{
		Port:             shared.GetEnvIntOrDefault("PORT", 8080),
		TEETURL:          teetURL,
		EnclaveMode:      enclaveMode,
		Domain:           domain,
		KMSKey:           shared.GetEnvOrDefault("KMS_KEY", ""),
		KMSProvider:      kmsProvider,
		GoogleProjectID:  shared.GetEnvOrDefault("GOOGLE_PROJECT_ID", ""),
		GoogleLocation:   shared.GetEnvOrDefault("GOOGLE_KMS_LOCATION", ""),
		GoogleKeyRing:    shared.GetEnvOrDefault("GOOGLE_KMS_KEYRING", ""),
		GoogleKeyName:    shared.GetEnvOrDefault("GOOGLE_KMS_KEY", ""),
		ForceTLSVersion:  shared.GetEnvOrDefault("FORCE_TLS_VERSION", ""),
		ForceCipherSuite: shared.GetEnvOrDefault("FORCE_CIPHER_SUITE", ""),

		RouterURL:               shared.GetEnvOrDefault("ROUTER_URL", ""),
		SelfAddr:                shared.GetEnvOrDefault("SELF_ADDR", ""),
		PeerAddr:                shared.GetEnvOrDefault("PEER_ADDR", ""),
		ExpectedPeerImageDigest: shared.GetEnvOrDefault("EXPECTED_PEER_IMAGE_DIGEST", ""),
		JWTPublicKey:            shared.GetEnvOrDefault("JWT_PUBLIC_KEY", ""),
	}
}
