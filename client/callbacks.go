package main

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
	RedactedBody    []byte           `json:"redacted_body"`
	RedactionRanges []RedactionRange `json:"redaction_ranges"`
	ProofClaims     []ProofClaim     `json:"proof_claims"`
}

// ProofClaim defines a claim to be proven about the response
type ProofClaim struct {
	Type        string `json:"type"`        // Type of claim (e.g., "contains", "equals", "range")
	Field       string `json:"field"`       // Field being claimed (e.g., "body", "header.authorization")
	Value       string `json:"value"`       // Expected value or pattern
	Description string `json:"description"` // Human-readable description
}

// DefaultResponseCallback provides a simple default implementation
type DefaultResponseCallback struct{}

// OnResponseReceived implements the ResponseCallback interface with no redactions
func (d *DefaultResponseCallback) OnResponseReceived(response *HTTPResponse) (*RedactionResult, error) {
	return &RedactionResult{
		RedactedBody:    response.Body,
		RedactionRanges: []RedactionRange{},
		ProofClaims:     []ProofClaim{},
	}, nil
}
