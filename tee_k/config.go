package main

import (
	"tee-mpc/shared"
)

type TEEKConfig struct {
	// Deployment mode
	EnclaveMode bool   `json:"enclave_mode"`
	Domain      string `json:"domain"`

	// Standalone mode settings
	Port    int    `json:"port"`
	TEETURL string `json:"teet_url"`

	// Enclave mode settings
	HTTPPort  int    `json:"http_port"`  // 8080 for ACME
	HTTPSPort int    `json:"https_port"` // 8443 for service
	KMSKey    string `json:"kms_key"`
	ParentCID uint32 `json:"parent_cid"` // 3
}

func LoadTEEKConfig() *TEEKConfig {
	return &TEEKConfig{
		EnclaveMode: shared.GetEnvOrDefault("ENCLAVE_MODE", "false") == "true",
		Domain:      shared.GetEnvOrDefault("TEE_DOMAIN", "tee-k.reclaimprotocol.org"),
		Port:        shared.GetEnvIntOrDefault("PORT", 8080),
		TEETURL:     shared.GetEnvOrDefault("TEET_URL", "ws://localhost:8081/teek"),
		HTTPPort:    shared.GetEnvIntOrDefault("HTTP_PORT", 8080),
		HTTPSPort:   shared.GetEnvIntOrDefault("HTTPS_PORT", 8443),
		KMSKey:      shared.GetEnvOrDefault("KMS_KEY", ""),
		ParentCID:   shared.GetEnvUint32OrDefault("PARENT_CID", 3),
	}
}
