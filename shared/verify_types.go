package shared

// RequestMetadata contains the redacted request data
// that was previously included in the SignedTranscript packets
type RequestMetadata struct {
	RedactedRequest []byte                  `json:"redacted_request"` // The redacted HTTP request (R_red)
	RedactionRanges []RequestRedactionRange `json:"redaction_ranges"` // Ranges used for request redaction (signed by TEE_K)
}

// Opening contains the commitment opening data (Str_SP, K_SP) provided by the User
type Opening struct {
	ProofStream []byte `json:"proof_stream"` // Str_SP - proof stream for revealing sensitive_proof data
	ProofKey    []byte `json:"proof_key"`    // K_SP - commitment key for proof stream
}

// Legacy VerificationBundle, TEEKTranscript, TEETTranscript removed - now using protobuf VerificationBundlePB directly!

// Report captures the result of offline verification. The verifier returns it
// to the caller so they can inspect what failed.
// For the first iteration we only expose booleans; we can extend later.

type VerificationReport struct {
	TranscriptSignaturesValid bool `json:"transcript_signatures_valid"`
	StreamsMatch              bool `json:"streams_match"`
	HandshakeDecrypted        bool `json:"handshake_decrypted"`
	AttestationsValid         bool `json:"attestations_valid"`
	OverallSuccess            bool `json:"overall_success"`

	// Optional human-readable message if something fails
	Error string `json:"error,omitempty"`
}
