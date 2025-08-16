package clientlib

import "tee-mpc/shared"

// ResponseCallback defines the interface for handling response redactions
type ResponseCallback interface {
	OnResponseReceived(response *HTTPResponse) (*RedactionResult, error)
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

// RedactionResult contains the result of response redaction
type RedactionResult struct {
	RedactionRanges []shared.ResponseRedactionRange `json:"redaction_ranges"`
}
