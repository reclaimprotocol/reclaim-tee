package enclave

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// RedactionRequest represents a request divided into sensitive and non-sensitive parts
type RedactionRequest struct {
	NonSensitive   []byte `json:"non_sensitive"`   // R_NS - will go as plaintext
	Sensitive      []byte `json:"sensitive"`       // R_S - sensitive data not used in proof
	SensitiveProof []byte `json:"sensitive_proof"` // R_SP - sensitive data used in proof
}

// RedactionStreams holds the random streams used for redaction
type RedactionStreams struct {
	StreamS  []byte `json:"stream_s"`  // Str_S - stream for sensitive data
	StreamSP []byte `json:"stream_sp"` // Str_SP - stream for sensitive proof data
}

// RedactionCommitments holds the commitments to redaction streams
type RedactionCommitments struct {
	CommitmentS  []byte `json:"commitment_s"`  // comm_s = HMAC(Str_S, K_S)
	CommitmentSP []byte `json:"commitment_sp"` // comm_sp = HMAC(Str_SP, K_SP)
}

// RedactionKeys holds the commitment keys
type RedactionKeys struct {
	KeyS  []byte `json:"key_s"`  // K_S - commitment key for sensitive data
	KeySP []byte `json:"key_sp"` // K_SP - commitment key for sensitive proof data
}

// RedactedData represents the result of applying redaction streams
type RedactedData struct {
	Data        []byte               `json:"data"`        // R_red - redacted data
	Commitments RedactionCommitments `json:"commitments"` // commitments to streams
}

// RedactionProcessor handles redaction operations
type RedactionProcessor struct{}

// NewRedactionProcessor creates a new redaction processor
func NewRedactionProcessor() *RedactionProcessor {
	return &RedactionProcessor{}
}

// GenerateRedactionStreams generates random streams for redaction
func (rp *RedactionProcessor) GenerateRedactionStreams(sensitiveLen, sensitiveProofLen int) (*RedactionStreams, error) {
	if sensitiveLen < 0 || sensitiveProofLen < 0 {
		return nil, errors.New("stream lengths cannot be negative")
	}

	streams := &RedactionStreams{
		StreamS:  make([]byte, sensitiveLen),
		StreamSP: make([]byte, sensitiveProofLen),
	}

	if sensitiveLen > 0 {
		if _, err := rand.Read(streams.StreamS); err != nil {
			return nil, fmt.Errorf("failed to generate stream S: %v", err)
		}
	}

	if sensitiveProofLen > 0 {
		if _, err := rand.Read(streams.StreamSP); err != nil {
			return nil, fmt.Errorf("failed to generate stream SP: %v", err)
		}
	}

	return streams, nil
}

// GenerateCommitmentKeys generates random keys for commitments
func (rp *RedactionProcessor) GenerateCommitmentKeys() (*RedactionKeys, error) {
	keys := &RedactionKeys{
		KeyS:  make([]byte, 32), // 256-bit keys
		KeySP: make([]byte, 32),
	}

	if _, err := rand.Read(keys.KeyS); err != nil {
		return nil, fmt.Errorf("failed to generate commitment key S: %v", err)
	}

	if _, err := rand.Read(keys.KeySP); err != nil {
		return nil, fmt.Errorf("failed to generate commitment key SP: %v", err)
	}

	return keys, nil
}

// ComputeCommitments computes HMAC commitments to the streams
func (rp *RedactionProcessor) ComputeCommitments(streams *RedactionStreams, keys *RedactionKeys) (*RedactionCommitments, error) {
	if streams == nil || keys == nil {
		return nil, errors.New("streams and keys cannot be nil")
	}

	commitments := &RedactionCommitments{}

	// comm_s = HMAC(Str_S, K_S)
	if len(streams.StreamS) > 0 {
		h := hmac.New(sha256.New, keys.KeyS)
		h.Write(streams.StreamS)
		commitments.CommitmentS = h.Sum(nil)
	}

	// comm_sp = HMAC(Str_SP, K_SP)
	if len(streams.StreamSP) > 0 {
		h := hmac.New(sha256.New, keys.KeySP)
		h.Write(streams.StreamSP)
		commitments.CommitmentSP = h.Sum(nil)
	}

	return commitments, nil
}

// VerifyCommitments verifies that commitments match the streams
func (rp *RedactionProcessor) VerifyCommitments(streams *RedactionStreams, keys *RedactionKeys, commitments *RedactionCommitments) error {
	if streams == nil || keys == nil || commitments == nil {
		return errors.New("streams, keys, and commitments cannot be nil")
	}

	// Recompute expected commitments
	expectedCommitments, err := rp.ComputeCommitments(streams, keys)
	if err != nil {
		return fmt.Errorf("failed to compute expected commitments: %v", err)
	}

	// Verify commitment S
	if len(streams.StreamS) > 0 {
		if !hmac.Equal(commitments.CommitmentS, expectedCommitments.CommitmentS) {
			return errors.New("commitment S verification failed")
		}
	}

	// Verify commitment SP
	if len(streams.StreamSP) > 0 {
		if !hmac.Equal(commitments.CommitmentSP, expectedCommitments.CommitmentSP) {
			return errors.New("commitment SP verification failed")
		}
	}

	return nil
}

// ApplyRedaction applies redaction streams to request data using XOR
func (rp *RedactionProcessor) ApplyRedaction(request *RedactionRequest, streams *RedactionStreams) ([]byte, error) {
	if request == nil || streams == nil {
		return nil, errors.New("request and streams cannot be nil")
	}

	// Validate stream lengths match data lengths
	if len(request.Sensitive) != len(streams.StreamS) {
		return nil, fmt.Errorf("sensitive data length (%d) does not match stream S length (%d)",
			len(request.Sensitive), len(streams.StreamS))
	}

	if len(request.SensitiveProof) != len(streams.StreamSP) {
		return nil, fmt.Errorf("sensitive proof data length (%d) does not match stream SP length (%d)",
			len(request.SensitiveProof), len(streams.StreamSP))
	}

	// Calculate total redacted data length
	totalLen := len(request.NonSensitive) + len(request.Sensitive) + len(request.SensitiveProof)
	redactedData := make([]byte, totalLen)

	offset := 0

	// Copy non-sensitive data as-is
	copy(redactedData[offset:], request.NonSensitive)
	offset += len(request.NonSensitive)

	// XOR sensitive data with stream S
	for i := 0; i < len(request.Sensitive); i++ {
		redactedData[offset+i] = request.Sensitive[i] ^ streams.StreamS[i]
	}
	offset += len(request.Sensitive)

	// XOR sensitive proof data with stream SP
	for i := 0; i < len(request.SensitiveProof); i++ {
		redactedData[offset+i] = request.SensitiveProof[i] ^ streams.StreamSP[i]
	}

	return redactedData, nil
}

// UnapplyRedaction reverses redaction by applying streams again (XOR is its own inverse)
func (rp *RedactionProcessor) UnapplyRedaction(redactedData []byte, streams *RedactionStreams, originalRequest *RedactionRequest) (*RedactionRequest, error) {
	if redactedData == nil || streams == nil || originalRequest == nil {
		return nil, errors.New("redacted data, streams, and original request cannot be nil")
	}

	// Validate total length
	expectedLen := len(originalRequest.NonSensitive) + len(originalRequest.Sensitive) + len(originalRequest.SensitiveProof)
	if len(redactedData) != expectedLen {
		return nil, fmt.Errorf("redacted data length (%d) does not match expected length (%d)",
			len(redactedData), expectedLen)
	}

	request := &RedactionRequest{
		NonSensitive:   make([]byte, len(originalRequest.NonSensitive)),
		Sensitive:      make([]byte, len(originalRequest.Sensitive)),
		SensitiveProof: make([]byte, len(originalRequest.SensitiveProof)),
	}

	offset := 0

	// Copy non-sensitive data as-is
	copy(request.NonSensitive, redactedData[offset:offset+len(originalRequest.NonSensitive)])
	offset += len(originalRequest.NonSensitive)

	// XOR to recover sensitive data
	for i := 0; i < len(originalRequest.Sensitive); i++ {
		request.Sensitive[i] = redactedData[offset+i] ^ streams.StreamS[i]
	}
	offset += len(originalRequest.Sensitive)

	// XOR to recover sensitive proof data
	for i := 0; i < len(originalRequest.SensitiveProof); i++ {
		request.SensitiveProof[i] = redactedData[offset+i] ^ streams.StreamSP[i]
	}

	return request, nil
}

// SecureZero securely zeros sensitive data structures
func (streams *RedactionStreams) SecureZero() {
	if streams.StreamS != nil {
		for i := range streams.StreamS {
			streams.StreamS[i] = 0
		}
		streams.StreamS = nil
	}
	if streams.StreamSP != nil {
		for i := range streams.StreamSP {
			streams.StreamSP[i] = 0
		}
		streams.StreamSP = nil
	}
}

func (keys *RedactionKeys) SecureZero() {
	if keys.KeyS != nil {
		for i := range keys.KeyS {
			keys.KeyS[i] = 0
		}
		keys.KeyS = nil
	}
	if keys.KeySP != nil {
		for i := range keys.KeySP {
			keys.KeySP[i] = 0
		}
		keys.KeySP = nil
	}
}

func (request *RedactionRequest) SecureZero() {
	if request.Sensitive != nil {
		for i := range request.Sensitive {
			request.Sensitive[i] = 0
		}
		request.Sensitive = nil
	}
	if request.SensitiveProof != nil {
		for i := range request.SensitiveProof {
			request.SensitiveProof[i] = 0
		}
		request.SensitiveProof = nil
	}
	// NonSensitive data doesn't need secure zeroing
}
