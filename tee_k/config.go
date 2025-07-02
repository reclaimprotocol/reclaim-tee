package main

import (
	"tee-mpc/shared"
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
	return &TEEKConfig{
		Port:        shared.GetEnvIntOrDefault("PORT", 8080),
		TEETURL:     shared.GetEnvOrDefault("TEET_URL", "ws://localhost:8081/teek"),
		EnclaveMode: shared.GetEnvOrDefault("ENCLAVE_MODE", "false") == "true",
		Domain:      shared.GetEnvOrDefault("ENCLAVE_DOMAIN", "tee-k.reclaimprotocol.org"),
		KMSKey:      shared.GetEnvOrDefault("KMS_KEY", "arn:aws:kms:ap-south-1:342772716647:key/ff4db6ac-b9fe-474c-9f59-5224c0c0f912"),
	}
}
