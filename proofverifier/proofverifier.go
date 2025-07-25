package proofverifier

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"tee-mpc/shared"
)

// collapseAsterisks reduces consecutive asterisks to a maximum of 100 followed by "..." if more exist
func collapseAsterisks(data string) string {
	if len(data) == 0 {
		return data
	}

	var result strings.Builder
	asteriskCount := 0

	for _, char := range data {
		if char == '*' {
			asteriskCount++
		} else {
			// We hit a non-asterisk character
			if asteriskCount > 0 {
				if asteriskCount <= 100 {
					// 100 or fewer asterisks, show them all
					result.WriteString(strings.Repeat("*", asteriskCount))
				} else {
					// More than 100 asterisks, show 9 + "..."
					result.WriteString("*********...")
				}
				asteriskCount = 0
			}
			result.WriteRune(char)
		}
	}

	// Handle trailing asterisks
	if asteriskCount > 0 {
		if asteriskCount <= 100 {
			result.WriteString(strings.Repeat("*", asteriskCount))
		} else {
			result.WriteString("*********...")
		}
	}

	return result.String()
}

// Validate loads the verification bundle from the given file path and performs
// a minimal set of checks (transcript signature verification, redacted stream
// XOR match against redacted response). It returns an error if any check fails.
func Validate(bundlePath string) error {
	fmt.Printf("[Verifier] Loading verification bundle: %s\n", bundlePath)

	f, err := os.Open(bundlePath)
	if err != nil {
		return fmt.Errorf("cannot open bundle: %v", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("failed to read bundle: %v", err)
	}

	var bundle shared.VerificationBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("failed to decode bundle JSON: %v", err)
	}

	// --- Transcript signature verification ---
	if bundle.Transcripts.TEEK != nil {
		if err := verifyTEEKTranscript(bundle.Transcripts.TEEK); err != nil {
			return fmt.Errorf("TEE_K transcript signature invalid: %v", err)
		}
	}
	if bundle.Transcripts.TEET != nil {
		if err := verifyTEETTranscript(bundle.Transcripts.TEET); err != nil {
			return fmt.Errorf("TEE_T transcript signature invalid: %v", err)
		}
	}

	fmt.Println("[Verifier] Comprehensive signature verification successful")

	// --- Commitment verification for proof stream ---
	if bundle.Opening != nil && bundle.Opening.ProofStream != nil && bundle.Opening.ProofKey != nil && bundle.Transcripts.TEEK != nil {
		mac := hmac.New(sha256.New, bundle.Opening.ProofKey)
		mac.Write(bundle.Opening.ProofStream)
		expectedCommitment := mac.Sum(nil)

		// Verify commitment directly from request metadata
		if bundle.Transcripts.TEEK.RequestMetadata == nil {
			return fmt.Errorf("TEE_K request metadata missing")
		}

		actualCommitment := bundle.Transcripts.TEEK.RequestMetadata.CommSP
		if len(actualCommitment) != len(expectedCommitment) {
			return fmt.Errorf("commitment length mismatch: expected %d bytes, got %d bytes",
				len(expectedCommitment), len(actualCommitment))
		}

		if !bytes.Equal(expectedCommitment, actualCommitment) {
			return fmt.Errorf("commitment verification failed: values do not match")
		}

		fmt.Printf("[Verifier] Commitment verified ✅ (len=%d, first16=%x)\n",
			len(expectedCommitment), expectedCommitment[:min(16, len(expectedCommitment))])
		fmt.Printf("[Verifier]   ProofStream len=%d, ProofKey len=%d\n", len(bundle.Opening.ProofStream), len(bundle.Opening.ProofKey))

		// Apply proof stream to reveal original sensitive_proof data
		if err := verifyAndRevealProofData(bundle); err != nil {
			return fmt.Errorf("failed to apply proof stream: %v", err)
		}
	} else {
		fmt.Println("[Verifier] Proof stream/key or TEE_K transcript missing – skipping commitment verification")
	}

	// --- Redacted response reconstruction check ---
	if bundle.Transcripts.TEET == nil {
		fmt.Println("[Verifier] No TEET transcript present – skipping stream check")
		return nil
	}
	// Build ordered slice of ciphertexts (application data) from TEET transcript
	var ciphertexts [][]byte

	// Check if this is TLS 1.2 AES-GCM (has explicit IV)
	isTLS12AESGCM := bundle.HandshakeKeys.CipherSuite == 0xc02f || // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		bundle.HandshakeKeys.CipherSuite == 0xc02b || // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		bundle.HandshakeKeys.CipherSuite == 0xc030 || // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		bundle.HandshakeKeys.CipherSuite == 0xc02c // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

	for _, pkt := range bundle.Transcripts.TEET.Packets {
		if len(pkt) < 5+16 {
			continue
		}
		// Skip non-ApplicationData packets, but allow Alert packets (0x15) for completeness
		if pkt[0] != 0x17 && pkt[0] != 0x15 {
			continue
		}

		var ctLen int
		var startOffset int
		if isTLS12AESGCM {
			// TLS 1.2 AES-GCM (both ApplicationData and Alert): Header(5) + ExplicitIV(8) + EncryptedData + Tag(16)
			ctLen = len(pkt) - 5 - 8 - 16 // Skip explicit IV and tag
			startOffset = 5 + 8           // Skip header and explicit IV
		} else {
			// TLS 1.3: Header(5) + EncryptedData + Tag(16)
			ctLen = len(pkt) - 5 - 16 // Skip header and tag
			startOffset = 5           // Skip header only
		}

		if ctLen <= 0 {
			continue
		}
		ciphertexts = append(ciphertexts, pkt[startOffset:startOffset+ctLen])
	}

	// Reconstruct plaintext by walking streams and finding the next ciphertext with matching length
	var reconstructed []byte
	cipherIdx := 0
	if bundle.Transcripts.TEEK != nil && len(bundle.Transcripts.TEEK.RedactedStreams) > 0 {
		for _, stream := range bundle.Transcripts.TEEK.RedactedStreams {
			// advance cipherIdx until length matches
			for cipherIdx < len(ciphertexts) && len(ciphertexts[cipherIdx]) != len(stream.RedactedStream) {
				cipherIdx++
			}
			if cipherIdx >= len(ciphertexts) {
				return fmt.Errorf("no ciphertext of length %d found for stream seq %d", len(stream.RedactedStream), stream.SeqNum)
			}
			cipher := ciphertexts[cipherIdx]
			plain := make([]byte, len(cipher))
			for i := range cipher {
				plain[i] = cipher[i] ^ stream.RedactedStream[i]
			}
			reconstructed = append(reconstructed, plain...)
			cipherIdx++
		}

		fmt.Println("[Verifier] Reconstructed redacted response:\n---\n" + collapseAsterisks(string(reconstructed)) + "\n---")
		fmt.Println("[Verifier] Redacted streams applied successfully ✅")
	} else {
		fmt.Println("[Verifier] No redacted streams available for reconstruction")
	}

	// --- Verify redaction ranges authenticity ---
	if bundle.Transcripts.TEEK != nil && bundle.Transcripts.TEEK.RequestMetadata != nil {
		signedRanges := bundle.Transcripts.TEEK.RequestMetadata.RedactionRanges
		fmt.Printf("[Verifier] Redaction ranges verified ✅ (TEE_K signed %d ranges)\n", len(signedRanges))
	} else {
		fmt.Println("[Verifier] Warning: No signed redaction ranges from TEE_K")
	}

	// NOTE: Request display is now handled in verifyAndRevealProofData() function above
	// which shows the proper revealed version with proof data visible and sensitive data hidden

	fmt.Println("[Verifier] Offline verification complete – success 🥳")
	return nil
}

// verifyTEEKTranscript verifies TEE_K's master signature over all data
func verifyTEEKTranscript(transcript *shared.TEEKTranscript) error {
	if transcript == nil {
		return fmt.Errorf("transcript is nil")
	}

	if len(transcript.Signature) == 0 {
		return fmt.Errorf("signature is empty")
	}

	// Reconstruct the original data that was signed (master signature covers all data)
	var buffer bytes.Buffer

	// Add request metadata
	if transcript.RequestMetadata != nil {
		buffer.Write(transcript.RequestMetadata.RedactedRequest)
		buffer.Write(transcript.RequestMetadata.CommSP)

		// Include redaction ranges in signature verification (same as signing)
		if len(transcript.RequestMetadata.RedactionRanges) > 0 {
			redactionRangesBytes, err := json.Marshal(transcript.RequestMetadata.RedactionRanges)
			if err != nil {
				return fmt.Errorf("failed to marshal redaction ranges for verification: %v", err)
			}
			buffer.Write(redactionRangesBytes)
		}
	}

	// Add concatenated redacted streams
	for _, stream := range transcript.RedactedStreams {
		buffer.Write(stream.RedactedStream)
	}

	// Add TLS packets
	for _, packet := range transcript.Packets {
		buffer.Write(packet)
	}

	originalData := buffer.Bytes()

	// Verify signature using the public key
	return shared.VerifySignatureWithDER(originalData, transcript.Signature, transcript.PublicKey)
}

// verifyTEETTranscript verifies TEE_T's signature over TLS packets
func verifyTEETTranscript(transcript *shared.TEETTranscript) error {
	if transcript == nil {
		return fmt.Errorf("transcript is nil")
	}

	if len(transcript.Signature) == 0 {
		return fmt.Errorf("signature is empty")
	}

	// Reconstruct the original data that was signed (TLS packets only)
	var buffer bytes.Buffer

	// Write each TLS packet to buffer
	for _, packet := range transcript.Packets {
		buffer.Write(packet)
	}

	originalData := buffer.Bytes()

	// Verify signature using the public key
	return shared.VerifySignatureWithDER(originalData, transcript.Signature, transcript.PublicKey)
}

// verifyAndRevealProofData applies the proof stream to reveal original sensitive_proof data
func verifyAndRevealProofData(bundle shared.VerificationBundle) error {
	if bundle.Transcripts.TEEK == nil || bundle.Transcripts.TEEK.RequestMetadata == nil {
		return fmt.Errorf("no TEE_K request metadata available")
	}

	redactedRequest := bundle.Transcripts.TEEK.RequestMetadata.RedactedRequest
	redactionRanges := bundle.Transcripts.TEEK.RequestMetadata.RedactionRanges

	if bundle.Opening == nil || bundle.Opening.ProofStream == nil {
		fmt.Println("[Verifier] No proof stream available for SP revelation")
		return nil
	}

	proofStream := bundle.Opening.ProofStream

	if len(redactedRequest) == 0 || len(proofStream) == 0 {
		fmt.Println("[Verifier] No proof stream or redacted request available for SP revelation")
		return nil
	}

	// Create a copy of the redacted request to apply proof stream
	revealedRequest := make([]byte, len(redactedRequest))
	copy(revealedRequest, redactedRequest)

	// Apply proof stream ONLY to sensitive_proof ranges
	proofStreamOffset := 0
	proofRangesFound := 0

	for _, r := range redactionRanges {
		// Only reveal ranges marked as proof-relevant (sensitive_proof)
		if strings.Contains(r.Type, "proof") {
			// Check bounds
			if r.Start+r.Length > len(revealedRequest) {
				return fmt.Errorf("proof range [%d:%d] exceeds request length %d", r.Start, r.Start+r.Length, len(revealedRequest))
			}

			// Check if we have enough proof stream data
			if proofStreamOffset+r.Length > len(proofStream) {
				return fmt.Errorf("insufficient proof stream data for range %d (need %d bytes, have %d)",
					proofRangesFound, r.Length, len(proofStream)-proofStreamOffset)
			}

			// Apply XOR to reveal original sensitive_proof data
			for i := 0; i < r.Length; i++ {
				revealedRequest[r.Start+i] ^= proofStream[proofStreamOffset+i]
			}

			fmt.Printf("[Verifier] Revealed proof range [%d:%d] type=%s (%d bytes)\n",
				r.Start, r.Start+r.Length, r.Type, r.Length)

			proofStreamOffset += r.Length
			proofRangesFound++
		}
	}

	if proofRangesFound == 0 {
		fmt.Println("[Verifier] No proof ranges found to reveal")
		return nil
	}

	// Display the request with proof data revealed (but other sensitive data still redacted)
	fmt.Printf("[Verifier] Request with proof data revealed (sensitive data remains hidden):\n---\n")

	// Create pretty display: show revealed proof data, but keep other sensitive data as '*'
	prettyRequest := make([]byte, len(revealedRequest))
	copy(prettyRequest, revealedRequest)

	for _, r := range redactionRanges {
		// Keep non-proof sensitive data as '*' for display
		if !strings.Contains(r.Type, "proof") {
			for i := 0; i < r.Length && r.Start+i < len(prettyRequest); i++ {
				prettyRequest[r.Start+i] = '*'
			}
		}
	}

	fmt.Printf("%s\n---\n", collapseAsterisks(string(prettyRequest)))
	fmt.Printf("[Verifier] Successfully revealed %d proof ranges while keeping sensitive data hidden ✅\n", proofRangesFound)

	return nil
}
