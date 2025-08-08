package main

import (
	"log"
	"tee-mpc/shared"

	"github.com/joho/godotenv"
)

type TEETConfig struct {
	// Standalone mode
	Port int `json:"port"`

	// Enclave mode settings
	EnclaveMode bool   `json:"enclave_mode"`
	Domain      string `json:"domain"`
	KMSKey      string `json:"kms_key"`

	// KMS provider selection
	KMSProvider     string `json:"kms_provider"` // "aws" or "google"
	GoogleProjectID string `json:"google_project_id,omitempty"`
	GoogleLocation  string `json:"google_location,omitempty"`
	GoogleKeyRing   string `json:"google_key_ring,omitempty"`
	GoogleKeyName   string `json:"google_key_name,omitempty"`

	// Platform selection for attestation ("nitro" or "google_cvm")
	Platform string `json:"platform,omitempty"`
}

func LoadTEETConfig() *TEETConfig {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	return &TEETConfig{
		Port:            shared.GetEnvIntOrDefault("PORT", 8081),
		EnclaveMode:     shared.GetEnvOrDefault("ENCLAVE_MODE", "false") == "true",
		Domain:          shared.GetEnvOrDefault("ENCLAVE_DOMAIN", "tee-t.reclaimprotocol.org"),
		KMSKey:          shared.GetEnvOrDefault("KMS_KEY", "arn:aws:kms:ap-south-1:342772716647:key/ff4db6ac-b9fe-474c-9f59-5224c0c0f912"),
		KMSProvider:     shared.GetEnvOrDefault("KMS_PROVIDER", "aws"),
		GoogleProjectID: shared.GetEnvOrDefault("GOOGLE_PROJECT_ID", ""),
		GoogleLocation:  shared.GetEnvOrDefault("GOOGLE_KMS_LOCATION", ""),
		GoogleKeyRing:   shared.GetEnvOrDefault("GOOGLE_KMS_KEYRING", ""),
		GoogleKeyName:   shared.GetEnvOrDefault("GOOGLE_KMS_KEY", ""),
		Platform:        shared.GetEnvOrDefault("PLATFORM", "nitro"),
	}
}
