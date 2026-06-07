package main

import (
	"log"

	"github.com/reclaimprotocol/reclaim-tee/shared"

	"github.com/joho/godotenv"
)

type TEETConfig struct {
	// Standalone mode
	Port int `json:"port"`

	// Enclave mode settings
	EnclaveMode bool   `json:"enclave_mode"`
	Domain      string `json:"domain"`
	KMSKey      string `json:"kms_key"`
	HTTPPort    int    `json:"http_port"`
	HTTPSPort   int    `json:"https_port"`

	// KMS provider (Google KMS)
	KMSProvider     string `json:"kms_provider"`
	GoogleProjectID string `json:"google_project_id,omitempty"`
	GoogleLocation  string `json:"google_location,omitempty"`
	GoogleKeyRing   string `json:"google_key_ring,omitempty"`
	GoogleKeyName   string `json:"google_key_name,omitempty"`

	// Router-mode settings (multi-pair architecture, Phase 3+).
	// Presence of RouterURL is what flips boot into router mode. The TEE
	// mints SA identity tokens with RouterURL as the `aud` claim; the
	// router validates against its own SA_TOKEN_AUDIENCE env var.
	RouterURL               string `json:"router_url,omitempty"`
	SelfAddr                string `json:"self_addr,omitempty"`
	PeerAddr                string `json:"peer_addr,omitempty"`
	ExpectedPeerImageDigest string `json:"expected_peer_image_digest,omitempty"`
	JWTPublicKey            string `json:"jwt_public_key,omitempty"`
}

// RouterMode returns true when the new multi-pair router boot path should
// be used. Detection is by presence of ROUTER_URL.
func (c *TEETConfig) RouterMode() bool {
	return c.RouterURL != ""
}

func LoadTEETConfig() *TEETConfig {
	err := godotenv.Load()
	if err != nil {
		log.Printf("Warning: Error loading .env file: %v", err)
	} else {
		log.Printf("Successfully loaded .env file")
	}

	// GCP uses Google KMS
	kmsProvider := "google"

	log.Printf("Configuration loaded - KMSProvider: %s", kmsProvider)

	return &TEETConfig{
		Port:            shared.GetEnvIntOrDefault("PORT", 8081),
		EnclaveMode:     shared.GetEnvOrDefault("ENCLAVE_MODE", "false") == "true",
		Domain:          shared.GetEnvOrDefault("ENCLAVE_DOMAIN", "eu.tt.reclaimprotocol.org"),
		KMSKey:          shared.GetEnvOrDefault("KMS_KEY", ""),
		HTTPPort:        shared.GetEnvIntOrDefault("HTTP_PORT", 80),
		HTTPSPort:       shared.GetEnvIntOrDefault("HTTPS_PORT", 443),
		KMSProvider:     kmsProvider,
		GoogleProjectID: shared.GetEnvOrDefault("GOOGLE_PROJECT_ID", ""),
		GoogleLocation:  shared.GetEnvOrDefault("GOOGLE_KMS_LOCATION", ""),
		GoogleKeyRing:   shared.GetEnvOrDefault("GOOGLE_KMS_KEYRING", ""),
		GoogleKeyName:   shared.GetEnvOrDefault("GOOGLE_KMS_KEY", ""),

		RouterURL:               shared.GetEnvOrDefault("ROUTER_URL", ""),
		SelfAddr:                shared.GetEnvOrDefault("SELF_ADDR", ""),
		PeerAddr:                shared.GetEnvOrDefault("PEER_ADDR", ""),
		ExpectedPeerImageDigest: shared.GetEnvOrDefault("EXPECTED_PEER_IMAGE_DIGEST", ""),
		JWTPublicKey:            shared.GetEnvOrDefault("JWT_PUBLIC_KEY", ""),
	}
}
