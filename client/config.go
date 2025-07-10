package main

import (
	"time"
)

// ClientConfig contains all configuration options for the ReclaimClient
type ClientConfig struct {
	TEEKURL           string           // TEE_K WebSocket URL
	TEETURL           string           // TEE_T WebSocket URL
	Timeout           time.Duration    // Connection timeout
	Mode              ClientMode       // Client operational mode
	RequestRedactions []RedactionSpec  // Request redactions defined upfront
	ResponseCallback  ResponseCallback // Callback for response redactions
}

// RedactionSpec defines a redaction specification for request data
type RedactionSpec struct {
	Pattern     string `json:"pattern"`     // Regex or literal pattern to match
	Type        string `json:"type"`        // "sensitive" or "sensitive_proof"
	Replacement string `json:"replacement"` // Optional replacement value
}

// DefaultClientConfig returns a default configuration for the client
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		TEEKURL:           "wss://tee-k.reclaimprotocol.org/ws",
		TEETURL:           "wss://tee-t.reclaimprotocol.org/ws",
		Timeout:           30 * time.Second,
		Mode:              ModeAuto,
		RequestRedactions: []RedactionSpec{},
		ResponseCallback:  nil,
	}
}

// StandaloneConfig returns a configuration for standalone mode
func StandaloneConfig(teekURL, teetURL string) ClientConfig {
	return ClientConfig{
		TEEKURL:           teekURL,
		TEETURL:           teetURL,
		Timeout:           30 * time.Second,
		Mode:              ModeStandalone,
		RequestRedactions: []RedactionSpec{},
		ResponseCallback:  nil,
	}
}

// EnclaveConfig returns a configuration for enclave mode
func EnclaveConfig() ClientConfig {
	return ClientConfig{
		TEEKURL:           "wss://tee-k.reclaimprotocol.org/ws",
		TEETURL:           "wss://tee-t.reclaimprotocol.org/ws",
		Timeout:           30 * time.Second,
		Mode:              ModeEnclave,
		RequestRedactions: []RedactionSpec{},
		ResponseCallback:  nil,
	}
}
