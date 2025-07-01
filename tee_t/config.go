package main

import (
	"tee-mpc/shared"
)

type TEETConfig struct {
	// Deployment mode
	EnclaveMode bool   `json:"enclave_mode"`
	Domain      string `json:"domain"`

	// Standalone mode
	Port int `json:"port"`

	// Enclave mode
	HTTPPort  int    `json:"http_port"`
	HTTPSPort int    `json:"https_port"`
	KMSKey    string `json:"kms_key"`
	ParentCID uint32 `json:"parent_cid"`
}

func LoadTEETConfig() *TEETConfig {
	return &TEETConfig{
		EnclaveMode: shared.GetEnvOrDefault("ENCLAVE_MODE", "false") == "true",
		Domain:      shared.GetEnvOrDefault("TEE_DOMAIN", "tee-t.reclaimprotocol.org"),
		Port:        shared.GetEnvIntOrDefault("PORT", 8081),
		HTTPPort:    shared.GetEnvIntOrDefault("HTTP_PORT", 8080),
		HTTPSPort:   shared.GetEnvIntOrDefault("HTTPS_PORT", 8443),
		KMSKey:      shared.GetEnvOrDefault("KMS_KEY", "arn:aws:kms:ap-south-1:342772716647:key/ff4db6ac-b9fe-474c-9f59-5224c0c0f912"),
		ParentCID:   shared.GetEnvUint32OrDefault("PARENT_CID", 3),
	}
}
