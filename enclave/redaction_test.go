package enclave

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

func TestRedactionProcessor_GenerateRedactionStreams(t *testing.T) {
	rp := NewRedactionProcessor()

	t.Run("ValidLengths", func(t *testing.T) {
		streams, err := rp.GenerateRedactionStreams(10, 20)
		if err != nil {
			t.Fatalf("Failed to generate streams: %v", err)
		}

		if len(streams.StreamS) != 10 {
			t.Errorf("Expected StreamS length 10, got %d", len(streams.StreamS))
		}

		if len(streams.StreamSP) != 20 {
			t.Errorf("Expected StreamSP length 20, got %d", len(streams.StreamSP))
		}

		// Streams should contain random data (not all zeros)
		allZerosS := true
		for _, b := range streams.StreamS {
			if b != 0 {
				allZerosS = false
				break
			}
		}
		if allZerosS {
			t.Error("StreamS should not be all zeros")
		}

		allZerosSP := true
		for _, b := range streams.StreamSP {
			if b != 0 {
				allZerosSP = false
				break
			}
		}
		if allZerosSP {
			t.Error("StreamSP should not be all zeros")
		}
	})

	t.Run("ZeroLengths", func(t *testing.T) {
		streams, err := rp.GenerateRedactionStreams(0, 0)
		if err != nil {
			t.Fatalf("Failed to generate streams with zero lengths: %v", err)
		}

		if len(streams.StreamS) != 0 {
			t.Errorf("Expected StreamS length 0, got %d", len(streams.StreamS))
		}

		if len(streams.StreamSP) != 0 {
			t.Errorf("Expected StreamSP length 0, got %d", len(streams.StreamSP))
		}
	})

	t.Run("NegativeLengths", func(t *testing.T) {
		_, err := rp.GenerateRedactionStreams(-1, 10)
		if err == nil {
			t.Error("Expected error for negative sensitive length")
		}

		_, err = rp.GenerateRedactionStreams(10, -1)
		if err == nil {
			t.Error("Expected error for negative sensitive proof length")
		}
	})

	t.Run("StreamsDifferent", func(t *testing.T) {
		streams1, err := rp.GenerateRedactionStreams(32, 32)
		if err != nil {
			t.Fatalf("Failed to generate first streams: %v", err)
		}

		streams2, err := rp.GenerateRedactionStreams(32, 32)
		if err != nil {
			t.Fatalf("Failed to generate second streams: %v", err)
		}

		if bytes.Equal(streams1.StreamS, streams2.StreamS) {
			t.Error("Generated streams should be different")
		}

		if bytes.Equal(streams1.StreamSP, streams2.StreamSP) {
			t.Error("Generated streams should be different")
		}
	})
}

func TestRedactionProcessor_GenerateCommitmentKeys(t *testing.T) {
	rp := NewRedactionProcessor()

	t.Run("ValidKeys", func(t *testing.T) {
		keys, err := rp.GenerateCommitmentKeys()
		if err != nil {
			t.Fatalf("Failed to generate commitment keys: %v", err)
		}

		if len(keys.KeyS) != 32 {
			t.Errorf("Expected KeyS length 32, got %d", len(keys.KeyS))
		}

		if len(keys.KeySP) != 32 {
			t.Errorf("Expected KeySP length 32, got %d", len(keys.KeySP))
		}

		// Keys should contain random data (not all zeros)
		allZerosS := true
		for _, b := range keys.KeyS {
			if b != 0 {
				allZerosS = false
				break
			}
		}
		if allZerosS {
			t.Error("KeyS should not be all zeros")
		}

		allZerosSP := true
		for _, b := range keys.KeySP {
			if b != 0 {
				allZerosSP = false
				break
			}
		}
		if allZerosSP {
			t.Error("KeySP should not be all zeros")
		}
	})

	t.Run("KeysDifferent", func(t *testing.T) {
		keys1, err := rp.GenerateCommitmentKeys()
		if err != nil {
			t.Fatalf("Failed to generate first keys: %v", err)
		}

		keys2, err := rp.GenerateCommitmentKeys()
		if err != nil {
			t.Fatalf("Failed to generate second keys: %v", err)
		}

		if bytes.Equal(keys1.KeyS, keys2.KeyS) {
			t.Error("Generated keys should be different")
		}

		if bytes.Equal(keys1.KeySP, keys2.KeySP) {
			t.Error("Generated keys should be different")
		}
	})
}

func TestRedactionProcessor_ComputeCommitments(t *testing.T) {
	rp := NewRedactionProcessor()

	t.Run("ValidCommitments", func(t *testing.T) {
		streams, err := rp.GenerateRedactionStreams(16, 32)
		if err != nil {
			t.Fatalf("Failed to generate streams: %v", err)
		}

		keys, err := rp.GenerateCommitmentKeys()
		if err != nil {
			t.Fatalf("Failed to generate keys: %v", err)
		}

		commitments, err := rp.ComputeCommitments(streams, keys)
		if err != nil {
			t.Fatalf("Failed to compute commitments: %v", err)
		}

		// Commitments should be SHA256 hashes (32 bytes)
		if len(commitments.CommitmentS) != 32 {
			t.Errorf("Expected CommitmentS length 32, got %d", len(commitments.CommitmentS))
		}

		if len(commitments.CommitmentSP) != 32 {
			t.Errorf("Expected CommitmentSP length 32, got %d", len(commitments.CommitmentSP))
		}

		// Verify commitments manually
		h := hmac.New(sha256.New, keys.KeyS)
		h.Write(streams.StreamS)
		expectedS := h.Sum(nil)

		if !bytes.Equal(commitments.CommitmentS, expectedS) {
			t.Error("CommitmentS does not match expected value")
		}

		h = hmac.New(sha256.New, keys.KeySP)
		h.Write(streams.StreamSP)
		expectedSP := h.Sum(nil)

		if !bytes.Equal(commitments.CommitmentSP, expectedSP) {
			t.Error("CommitmentSP does not match expected value")
		}
	})

	t.Run("EmptyStreams", func(t *testing.T) {
		streams := &RedactionStreams{
			StreamS:  []byte{},
			StreamSP: []byte{},
		}

		keys, err := rp.GenerateCommitmentKeys()
		if err != nil {
			t.Fatalf("Failed to generate keys: %v", err)
		}

		commitments, err := rp.ComputeCommitments(streams, keys)
		if err != nil {
			t.Fatalf("Failed to compute commitments for empty streams: %v", err)
		}

		if len(commitments.CommitmentS) != 0 {
			t.Errorf("Expected empty CommitmentS, got %d bytes", len(commitments.CommitmentS))
		}

		if len(commitments.CommitmentSP) != 0 {
			t.Errorf("Expected empty CommitmentSP, got %d bytes", len(commitments.CommitmentSP))
		}
	})

	t.Run("NilInputs", func(t *testing.T) {
		_, err := rp.ComputeCommitments(nil, nil)
		if err == nil {
			t.Error("Expected error for nil inputs")
		}

		streams := &RedactionStreams{}
		_, err = rp.ComputeCommitments(streams, nil)
		if err == nil {
			t.Error("Expected error for nil keys")
		}

		keys := &RedactionKeys{}
		_, err = rp.ComputeCommitments(nil, keys)
		if err == nil {
			t.Error("Expected error for nil streams")
		}
	})
}

func TestRedactionProcessor_VerifyCommitments(t *testing.T) {
	rp := NewRedactionProcessor()

	t.Run("ValidVerification", func(t *testing.T) {
		streams, err := rp.GenerateRedactionStreams(16, 32)
		if err != nil {
			t.Fatalf("Failed to generate streams: %v", err)
		}

		keys, err := rp.GenerateCommitmentKeys()
		if err != nil {
			t.Fatalf("Failed to generate keys: %v", err)
		}

		commitments, err := rp.ComputeCommitments(streams, keys)
		if err != nil {
			t.Fatalf("Failed to compute commitments: %v", err)
		}

		err = rp.VerifyCommitments(streams, keys, commitments)
		if err != nil {
			t.Errorf("Valid commitments should verify: %v", err)
		}
	})

	t.Run("InvalidCommitmentS", func(t *testing.T) {
		streams, err := rp.GenerateRedactionStreams(16, 32)
		if err != nil {
			t.Fatalf("Failed to generate streams: %v", err)
		}

		keys, err := rp.GenerateCommitmentKeys()
		if err != nil {
			t.Fatalf("Failed to generate keys: %v", err)
		}

		commitments, err := rp.ComputeCommitments(streams, keys)
		if err != nil {
			t.Fatalf("Failed to compute commitments: %v", err)
		}

		// Tamper with commitment S
		commitments.CommitmentS[0] ^= 1

		err = rp.VerifyCommitments(streams, keys, commitments)
		if err == nil {
			t.Error("Tampered commitments should not verify")
		}
	})

	t.Run("InvalidCommitmentSP", func(t *testing.T) {
		streams, err := rp.GenerateRedactionStreams(16, 32)
		if err != nil {
			t.Fatalf("Failed to generate streams: %v", err)
		}

		keys, err := rp.GenerateCommitmentKeys()
		if err != nil {
			t.Fatalf("Failed to generate keys: %v", err)
		}

		commitments, err := rp.ComputeCommitments(streams, keys)
		if err != nil {
			t.Fatalf("Failed to compute commitments: %v", err)
		}

		// Tamper with commitment SP
		commitments.CommitmentSP[0] ^= 1

		err = rp.VerifyCommitments(streams, keys, commitments)
		if err == nil {
			t.Error("Tampered commitments should not verify")
		}
	})
}

func TestRedactionProcessor_ApplyRedaction(t *testing.T) {
	rp := NewRedactionProcessor()

	t.Run("ValidRedaction", func(t *testing.T) {
		request := &RedactionRequest{
			NonSensitive:   []byte("Hello "),
			Sensitive:      []byte("secret"),
			SensitiveProof: []byte("password123"),
		}

		streams, err := rp.GenerateRedactionStreams(len(request.Sensitive), len(request.SensitiveProof))
		if err != nil {
			t.Fatalf("Failed to generate streams: %v", err)
		}

		redactedData, err := rp.ApplyRedaction(request, streams)
		if err != nil {
			t.Fatalf("Failed to apply redaction: %v", err)
		}

		expectedLen := len(request.NonSensitive) + len(request.Sensitive) + len(request.SensitiveProof)
		if len(redactedData) != expectedLen {
			t.Errorf("Expected redacted data length %d, got %d", expectedLen, len(redactedData))
		}

		// Non-sensitive part should be unchanged
		if !bytes.Equal(redactedData[:len(request.NonSensitive)], request.NonSensitive) {
			t.Error("Non-sensitive data should be unchanged")
		}

		// Sensitive parts should be different (XORed with streams)
		sensitiveStart := len(request.NonSensitive)
		sensitiveEnd := sensitiveStart + len(request.Sensitive)
		if bytes.Equal(redactedData[sensitiveStart:sensitiveEnd], request.Sensitive) {
			t.Error("Sensitive data should be redacted")
		}

		proofStart := sensitiveEnd
		proofEnd := proofStart + len(request.SensitiveProof)
		if bytes.Equal(redactedData[proofStart:proofEnd], request.SensitiveProof) {
			t.Error("Sensitive proof data should be redacted")
		}
	})

	t.Run("StreamLengthMismatch", func(t *testing.T) {
		request := &RedactionRequest{
			NonSensitive:   []byte("Hello "),
			Sensitive:      []byte("secret"),
			SensitiveProof: []byte("password123"),
		}

		streams := &RedactionStreams{
			StreamS:  make([]byte, 5), // Wrong length
			StreamSP: make([]byte, len(request.SensitiveProof)),
		}

		_, err := rp.ApplyRedaction(request, streams)
		if err == nil {
			t.Error("Expected error for stream length mismatch")
		}
	})

	t.Run("NilInputs", func(t *testing.T) {
		_, err := rp.ApplyRedaction(nil, nil)
		if err == nil {
			t.Error("Expected error for nil inputs")
		}
	})
}

func TestRedactionProcessor_UnapplyRedaction(t *testing.T) {
	rp := NewRedactionProcessor()

	t.Run("ValidUnapply", func(t *testing.T) {
		originalRequest := &RedactionRequest{
			NonSensitive:   []byte("Hello "),
			Sensitive:      []byte("secret"),
			SensitiveProof: []byte("password123"),
		}

		streams, err := rp.GenerateRedactionStreams(len(originalRequest.Sensitive), len(originalRequest.SensitiveProof))
		if err != nil {
			t.Fatalf("Failed to generate streams: %v", err)
		}

		redactedData, err := rp.ApplyRedaction(originalRequest, streams)
		if err != nil {
			t.Fatalf("Failed to apply redaction: %v", err)
		}

		recoveredRequest, err := rp.UnapplyRedaction(redactedData, streams, originalRequest)
		if err != nil {
			t.Fatalf("Failed to unapply redaction: %v", err)
		}

		// All parts should be recovered correctly
		if !bytes.Equal(recoveredRequest.NonSensitive, originalRequest.NonSensitive) {
			t.Error("Non-sensitive data not recovered correctly")
		}

		if !bytes.Equal(recoveredRequest.Sensitive, originalRequest.Sensitive) {
			t.Error("Sensitive data not recovered correctly")
		}

		if !bytes.Equal(recoveredRequest.SensitiveProof, originalRequest.SensitiveProof) {
			t.Error("Sensitive proof data not recovered correctly")
		}
	})

	t.Run("LengthMismatch", func(t *testing.T) {
		originalRequest := &RedactionRequest{
			NonSensitive:   []byte("Hello "),
			Sensitive:      []byte("secret"),
			SensitiveProof: []byte("password123"),
		}

		streams := &RedactionStreams{
			StreamS:  make([]byte, len(originalRequest.Sensitive)),
			StreamSP: make([]byte, len(originalRequest.SensitiveProof)),
		}

		wrongLengthData := make([]byte, 10) // Wrong length

		_, err := rp.UnapplyRedaction(wrongLengthData, streams, originalRequest)
		if err == nil {
			t.Error("Expected error for length mismatch")
		}
	})
}

func TestRedactionProcessor_EndToEnd(t *testing.T) {
	rp := NewRedactionProcessor()

	// Create a realistic HTTP request
	request := &RedactionRequest{
		NonSensitive:   []byte("GET /api/data HTTP/1.1\r\nHost: example.com\r\nUser-Agent: "),
		Sensitive:      []byte("MyApp/1.0"),
		SensitiveProof: []byte("Authorization: Bearer secret-token-123"),
	}

	// Generate streams and keys
	streams, err := rp.GenerateRedactionStreams(len(request.Sensitive), len(request.SensitiveProof))
	if err != nil {
		t.Fatalf("Failed to generate streams: %v", err)
	}
	defer streams.SecureZero()

	keys, err := rp.GenerateCommitmentKeys()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}
	defer keys.SecureZero()

	// Compute commitments
	commitments, err := rp.ComputeCommitments(streams, keys)
	if err != nil {
		t.Fatalf("Failed to compute commitments: %v", err)
	}

	// Apply redaction
	redactedData, err := rp.ApplyRedaction(request, streams)
	if err != nil {
		t.Fatalf("Failed to apply redaction: %v", err)
	}

	// Verify commitments
	err = rp.VerifyCommitments(streams, keys, commitments)
	if err != nil {
		t.Fatalf("Failed to verify commitments: %v", err)
	}

	// Unapply redaction
	recoveredRequest, err := rp.UnapplyRedaction(redactedData, streams, request)
	if err != nil {
		t.Fatalf("Failed to unapply redaction: %v", err)
	}

	// Verify complete recovery
	if !bytes.Equal(recoveredRequest.NonSensitive, request.NonSensitive) {
		t.Error("End-to-end: Non-sensitive data not preserved")
	}

	if !bytes.Equal(recoveredRequest.Sensitive, request.Sensitive) {
		t.Error("End-to-end: Sensitive data not recovered")
	}

	if !bytes.Equal(recoveredRequest.SensitiveProof, request.SensitiveProof) {
		t.Error("End-to-end: Sensitive proof data not recovered")
	}

	t.Logf("End-to-end test successful:")
	t.Logf("  Original length: %d bytes", len(request.NonSensitive)+len(request.Sensitive)+len(request.SensitiveProof))
	t.Logf("  Redacted length: %d bytes", len(redactedData))
	t.Logf("  Commitments: S=%d bytes, SP=%d bytes", len(commitments.CommitmentS), len(commitments.CommitmentSP))
}

func TestRedactionSecureZero(t *testing.T) {
	t.Run("RedactionStreams", func(t *testing.T) {
		streams := &RedactionStreams{
			StreamS:  []byte{1, 2, 3, 4},
			StreamSP: []byte{5, 6, 7, 8},
		}

		streams.SecureZero()

		if streams.StreamS != nil {
			t.Error("StreamS should be nil after SecureZero")
		}

		if streams.StreamSP != nil {
			t.Error("StreamSP should be nil after SecureZero")
		}
	})

	t.Run("RedactionKeys", func(t *testing.T) {
		keys := &RedactionKeys{
			KeyS:  []byte{1, 2, 3, 4},
			KeySP: []byte{5, 6, 7, 8},
		}

		keys.SecureZero()

		if keys.KeyS != nil {
			t.Error("KeyS should be nil after SecureZero")
		}

		if keys.KeySP != nil {
			t.Error("KeySP should be nil after SecureZero")
		}
	})

	t.Run("RedactionRequest", func(t *testing.T) {
		request := &RedactionRequest{
			NonSensitive:   []byte("public"),
			Sensitive:      []byte("secret"),
			SensitiveProof: []byte("private"),
		}

		request.SecureZero()

		if request.Sensitive != nil {
			t.Error("Sensitive should be nil after SecureZero")
		}

		if request.SensitiveProof != nil {
			t.Error("SensitiveProof should be nil after SecureZero")
		}

		// NonSensitive should remain (it's not sensitive)
		if request.NonSensitive == nil {
			t.Error("NonSensitive should not be nil after SecureZero")
		}
	})
}
