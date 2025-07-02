package main

import (
	"tee-mpc/shared"
)

type TEETConfig struct {
	// Standalone mode
	Port int `json:"port"`

	// Enclave mode settings
	EnclaveMode bool   `json:"enclave_mode"`
	Domain      string `json:"domain"`
	KMSKey      string `json:"kms_key"`
}

func LoadTEETConfig() *TEETConfig {
	return &TEETConfig{
		Port:        shared.GetEnvIntOrDefault("PORT", 8081),
		EnclaveMode: shared.GetEnvOrDefault("ENCLAVE_MODE", "false") == "true",
		Domain:      shared.GetEnvOrDefault("ENCLAVE_DOMAIN", "tee-t.reclaimprotocol.org"),
		KMSKey:      shared.GetEnvOrDefault("KMS_KEY", "arn:aws:kms:ap-south-1:342772716647:key/ff4db6ac-b9fe-474c-9f59-5224c0c0f912"),
	}
}
