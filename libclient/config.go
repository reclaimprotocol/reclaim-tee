package clientlib

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
	ForceTLSVersion   string           // Force specific TLS version: "1.2", "1.3", or "" for auto
	ForceCipherSuite  string           // Force specific cipher suite: hex ID (e.g. "0xc02f") or name, or "" for auto
}

// RedactionSpec defines a redaction specification for request data
type RedactionSpec struct {
	Pattern     string `json:"pattern"`     // Regex or literal pattern to match
	Type        string `json:"type"`        // "sensitive" or "sensitive_proof"
	Replacement string `json:"replacement"` // Optional replacement value
}
