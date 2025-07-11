package shared

// VerificationBundle is the single JSON artefact that the client produces
// and that the offline verifier consumes to reproduce all checks.
// The fields mirror the outputs of the protocol phases.
//
// Binary blobs (packets, signatures, ciphertext, etc.) are stored directly
// as byte-slices and will be base64-encoded automatically by the JSON
// encoder/decoder.
//
// NOTE: additional fields can be added later without breaking existing
// bundles – the verifier will ignore unknown JSON keys.

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
		TEEK *SignedTranscript `json:"tee_k,omitempty"`
		TEET *SignedTranscript `json:"tee_t,omitempty"`
	} `json:"transcripts"`

	// Signed decryption keystreams produced by TEE_K, one per ApplicationData record
	RedactedStreams []SignedRedactedDecryptionStream `json:"redacted_streams,omitempty"`

	// Opening for the proof-relevant redaction commitment (Str_SP, K_SP)
	ProofStream []byte `json:"proof_stream,omitempty"`
	ProofKey    []byte `json:"proof_key,omitempty"`

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
