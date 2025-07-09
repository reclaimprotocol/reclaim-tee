package main

import (
	"log"
	"tee-mpc/shared"

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
}

func LoadTEEKConfig() *TEEKConfig {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	enclaveMode := shared.GetEnvOrDefault("ENCLAVE_MODE", "false") == "true"

	// Set TEETURL based on mode
	var teetURL string
	if enclaveMode {
		// Enclave mode: connect to TEE_T over internet via vsock proxy
		teetURL = shared.GetEnvOrDefault("TEET_URL", "wss://tee-t.reclaimprotocol.org/teek")
	} else {
		// Standalone mode: connect to TEE_T on localhost
		teetURL = shared.GetEnvOrDefault("TEET_URL", "ws://localhost:8081/teek")
	}

	return &TEEKConfig{
		Port:        shared.GetEnvIntOrDefault("PORT", 8080),
		TEETURL:     teetURL,
		EnclaveMode: enclaveMode,
		Domain:      shared.GetEnvOrDefault("ENCLAVE_DOMAIN", "tee-k.reclaimprotocol.org"),
		KMSKey:      shared.GetEnvOrDefault("KMS_KEY", "arn:aws:kms:ap-south-1:342772716647:key/ff4db6ac-b9fe-474c-9f59-5224c0c0f912"),
	}
}
