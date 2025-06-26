package enclave

import (
	"fmt"
	"log"
	"os"
	"strconv"
)

// ServiceConfig holds configuration for a specific TEE service
type ServiceConfig struct {
	// Service identification
	ServiceName string

	// Certificate and domain configuration
	Domain   string
	AcmeURL  string
	KmsKeyID string

	// Vsock configuration
	VsockPort        uint32
	VsockForwardPort uint32
	VsockParentCID   uint32

	// HTTP server ports
	HTTPPort  string
	HTTPSPort string
}

// LoadTEEKConfig loads configuration for TEE_K service
func LoadTEEKConfig() (*ServiceConfig, error) {
	config := &ServiceConfig{
		ServiceName: "tee_k",
	}

	var missing []string

	// Load domain configuration
	config.Domain = os.Getenv("ENCLAVE_DOMAIN")
	if config.Domain == "" {
		missing = append(missing, "ENCLAVE_DOMAIN")
	}

	// Load KMS configuration
	config.KmsKeyID = os.Getenv("KMS_KEY_ID")
	if config.KmsKeyID == "" {
		missing = append(missing, "KMS_KEY_ID")
	}

	// Load ACME configuration
	config.AcmeURL = os.Getenv("ACME_URL")
	if config.AcmeURL == "" {
		missing = append(missing, "ACME_URL")
	}

	// Load vsock configuration
	config.VsockParentCID = parseUint32Env("ENCLAVE_VSOCK_PARENT_CID", 3)
	config.VsockPort = parseUint32Env("ENCLAVE_VSOCK_PORT", 8000)
	config.VsockForwardPort = parseUint32Env("ENCLAVE_VSOCK_FORWARD_PORT", 8001)

	// Load HTTP server ports
	config.HTTPPort = getEnvWithDefault("HTTP_PORT", "8080")
	config.HTTPSPort = getEnvWithDefault("HTTPS_PORT", "8443")

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %v", missing)
	}

	log.Printf("Loaded TEE_K configuration: domain=%s, acmeURL=%s, vsockPort=%d",
		config.Domain, config.AcmeURL, config.VsockPort)

	return config, nil
}

// LoadTEETConfig loads configuration for TEE_T service
func LoadTEETConfig() (*ServiceConfig, error) {
	config := &ServiceConfig{
		ServiceName: "tee_t",
	}

	var missing []string

	// Load domain configuration (separate from TEE_K)
	config.Domain = os.Getenv("TEE_T_DOMAIN")
	if config.Domain == "" {
		missing = append(missing, "TEE_T_DOMAIN")
	}

	// Load KMS configuration (separate from TEE_K)
	config.KmsKeyID = os.Getenv("TEE_T_KMS_KEY_ID")
	if config.KmsKeyID == "" {
		missing = append(missing, "TEE_T_KMS_KEY_ID")
	}

	// Load ACME configuration (can be same as TEE_K)
	config.AcmeURL = os.Getenv("ACME_URL")
	if config.AcmeURL == "" {
		missing = append(missing, "ACME_URL")
	}

	// Load vsock configuration (separate ports for TEE_T)
	config.VsockParentCID = parseUint32Env("TEE_T_VSOCK_PARENT_CID", 3)
	config.VsockPort = parseUint32Env("TEE_T_VSOCK_PORT", 8002)
	config.VsockForwardPort = parseUint32Env("TEE_T_VSOCK_FORWARD_PORT", 8003)

	// Load HTTP server ports (different from TEE_K)
	config.HTTPPort = getEnvWithDefault("TEE_T_HTTP_PORT", "8081")
	config.HTTPSPort = getEnvWithDefault("TEE_T_HTTPS_PORT", "8444")

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %v", missing)
	}

	log.Printf("Loaded TEE_T configuration: domain=%s, acmeURL=%s, vsockPort=%d",
		config.Domain, config.AcmeURL, config.VsockPort)

	return config, nil
}

// ToCertConfig converts ServiceConfig to CertConfig
func (sc *ServiceConfig) ToCertConfig() *CertConfig {
	return &CertConfig{
		Domain:    sc.Domain,
		AcmeURL:   sc.AcmeURL,
		KmsKeyID:  sc.KmsKeyID,
		VsockPort: sc.VsockForwardPort,
	}
}

// Helper functions
func parseUint32Env(key string, defaultValue uint32) uint32 {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseUint(value, 10, 32); err == nil {
			return uint32(parsed)
		}
		log.Printf("Invalid value for %s: %s, using default: %d", key, value, defaultValue)
	}
	return defaultValue
}

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
