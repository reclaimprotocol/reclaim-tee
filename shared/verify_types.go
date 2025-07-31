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

// TEEKTranscript represents TEE_K's signed transcript including all its data
type TEEKTranscript struct {
	Packets [][]byte `json:"packets"` // TLS packets only (binary data)

	// Request metadata (redacted request, commitment, redaction ranges)
	RequestMetadata *RequestMetadata `json:"request_metadata,omitempty"`

	// Signed decryption keystreams produced by TEE_K, one per ApplicationData record
	RedactedStreams []SignedRedactedDecryptionStream `json:"redacted_streams,omitempty"`

	Signature []byte `json:"signature"`  // Master signature over all TEE_K data
	PublicKey []byte `json:"public_key"` // Public key in DER format (binary data)
}

// TEETTranscript represents TEE_T's signed transcript (response data)
type TEETTranscript struct {
	Packets [][]byte `json:"packets"` // TLS packets only (binary data)

	Signature []byte `json:"signature"`  // Signature over TLS packets
	PublicKey []byte `json:"public_key"` // Public key in DER format (binary data)
}

// VerificationBundle is the single JSON artefact that the client produces
// and that the offline verifier consumes to reproduce all checks.
// The fields mirror the outputs of the protocol phases.
//
// Binary blobs (packets, signatures, ciphertext, etc.) are stored directly
// as byte-slices and will be base64-encoded automatically by the JSON
// encoder/decoder.
//
// This structure follows the protocol design where:
// - TEE_K provides: signed request_transcript (including redacted streams) + TLS keys
// - TEE_T provides: signed response_transcript
// - User provides: opening (proof_stream + proof_key)

type HandshakeSecrets struct {
	HandshakeKey []byte `json:"handshake_key"`
	HandshakeIV  []byte `json:"handshake_iv"`
	CipherSuite  uint16 `json:"cipher_suite"`
	Algorithm    string `json:"algorithm"`
}

type VerificationBundle struct {
	// ---- Phase 2: handshake authenticity ----
	HandshakeKeys HandshakeSecrets `json:"handshake_keys,omitempty"`

	// ---- Phase 3 & 4: traffic authenticity & integrity ----
	Transcripts struct {
		TEEK *TEEKTranscript `json:"tee_k,omitempty"`
		TEET *TEETTranscript `json:"tee_t,omitempty"`
	} `json:"transcripts"`

	// ---- Phase 5: commitment opening ----
	// Opening for the proof-relevant redaction commitment (Str_SP, K_SP)
	Opening *Opening `json:"opening,omitempty"`

	// ---- Attestation verification ----
	// Attestation documents (optional in standalone mode)
	AttestationTEEK []byte `json:"attestation_tee_k,omitempty"`
	AttestationTEET []byte `json:"attestation_tee_t,omitempty"`
}

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
