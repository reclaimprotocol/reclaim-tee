package clientlib

import (
	"tee-mpc/providers"
	"time"
)

// ClientConfig contains all configuration options for the ReclaimClient
type ClientConfig struct {
	TEEKURL              string                              // TEE_K WebSocket URL
	TEETURL              string                              // TEE_T WebSocket URL
	Timeout              time.Duration                       // Connection timeout
	Mode                 ClientMode                          // Client operational mode
	RequestRedactions    []RedactionSpec                     // Request redactions defined upfront
	ProviderParams       *providers.HTTPProviderParams       // Provider params for automatic response redactions
	ProviderSecretParams *providers.HTTPProviderSecretParams // Provider secret params for automatic response redactions
	ForceTLSVersion      string                              // Force specific TLS version: "1.2", "1.3", or "" for auto
	ForceCipherSuite     string                              // Force specific cipher suite: hex ID (e.g. "0xc02f") or name, or "" for auto
}

// RedactionSpec defines a redaction specification for request data
type RedactionSpec struct {
	Pattern     string `json:"pattern"`     // Regex or literal pattern to match
	Type        string `json:"type"`        // Use shared.RedactionTypeSensitive or shared.RedactionTypeSensitiveProof
	Replacement string `json:"replacement"` // Optional replacement value
}

// HTTPResponse contains the complete HTTP response data
type HTTPResponse struct {
	StatusCode   int               `json:"status_code"`
	Headers      map[string]string `json:"headers"`
	Body         []byte            `json:"body"`          // Just the HTTP body part
	FullResponse []byte            `json:"full_response"` // Complete HTTP response (status + headers + body)
	Metadata     ResponseMetadata  `json:"metadata"`
}

// ResponseMetadata contains additional metadata about the response
type ResponseMetadata struct {
	Timestamp     int64  `json:"timestamp"`
	ContentLength int    `json:"content_length"`
	ContentType   string `json:"content_type"`
	TLSVersion    string `json:"tls_version"`
	CipherSuite   string `json:"cipher_suite"`
	ServerName    string `json:"server_name"`
	RequestID     string `json:"request_id"`
}
