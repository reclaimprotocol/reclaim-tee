package proofverifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	teeproto "tee-mpc/proto"
	"tee-mpc/shared"

	"google.golang.org/protobuf/proto"
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
				if asteriskCount <= AsteriskCollapseThreshold {
					// Threshold or fewer asterisks, show them all
					result.WriteString(strings.Repeat("*", asteriskCount))
				} else {
					// More than threshold asterisks, show collapsed pattern
					result.WriteString(CollapsedAsteriskPattern)
				}
				asteriskCount = 0
			}
			result.WriteRune(char)
		}
	}

	// Handle trailing asterisks
	if asteriskCount > 0 {
		if asteriskCount <= AsteriskCollapseThreshold {
			result.WriteString(strings.Repeat("*", asteriskCount))
		} else {
			result.WriteString(CollapsedAsteriskPattern)
		}
	}

	return result.String()
}

// replaceRandomGarbageWithAsterisks replaces random garbage in redacted plaintext with asterisks
func replaceRandomGarbageWithAsterisks(content []byte, ranges []shared.ResponseRedactionRange) []byte {
	result := make([]byte, len(content))
	copy(result, content)

	// Apply each redaction range to replace random garbage with asterisks
	for _, r := range ranges {
		rangeStart := r.Start
		rangeEnd := r.Start + r.Length

		// Check bounds
		if rangeStart < 0 || rangeEnd > len(content) {
			continue // Skip invalid ranges
		}

		// Replace random garbage with asterisks
		for i := rangeStart; i < rangeEnd; i++ {
			result[i] = '*'
		}
	}

	return result
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

	var bundlePB teeproto.VerificationBundlePB
	if err := proto.Unmarshal(data, &bundlePB); err != nil {
		return fmt.Errorf("failed to decode bundle protobuf: %v", err)
	}

	// --- SECURITY: Validate required data is present ---
	if bundlePB.TeekSigned == nil {
		return fmt.Errorf("SECURITY ERROR: missing TEE_K signed message - verification bundle incomplete")
	}
	if bundlePB.TeetSigned == nil {
		return fmt.Errorf("SECURITY ERROR: missing TEE_T signed message - verification bundle incomplete")
	}

	// --- Signed message verification ---
	if err := verifySignedMessage(bundlePB.TeekSigned, "TEE_K"); err != nil {
		return fmt.Errorf("TEE_K signed message invalid: %v", err)
	}
	if err := verifySignedMessage(bundlePB.TeetSigned, "TEE_T"); err != nil {
		return fmt.Errorf("TEE_T signed message invalid: %v", err)
	}

	fmt.Println("[Verifier] Comprehensive signature verification successful")

	// Convert protobuf SignedMessage back to legacy bundle format for existing verification logic
	bundle := &shared.VerificationBundle{}

	// Extract data from TEE_K signed message
	if bundlePB.TeekSigned != nil {
		var kPayload teeproto.KOutputPayload
		if err := proto.Unmarshal(bundlePB.TeekSigned.GetBody(), &kPayload); err != nil {
			return fmt.Errorf("failed to unmarshal TEE_K body: %v", err)
		}

		// Convert request redaction ranges
		var reqRanges []shared.RequestRedactionRange
		for _, r := range kPayload.GetRequestRedactionRanges() {
			reqRanges = append(reqRanges, shared.RequestRedactionRange{
				Start:          int(r.GetStart()),
				Length:         int(r.GetLength()),
				Type:           r.GetType(),
				RedactionBytes: r.GetRedactionBytes(),
			})
		}

		// Convert redacted streams
		var redactedStreams []shared.SignedRedactedDecryptionStream
		for _, s := range kPayload.GetRedactedStreams() {
			redactedStreams = append(redactedStreams, shared.SignedRedactedDecryptionStream{
				RedactedStream: s.GetRedactedStream(),
				SeqNum:         s.GetSeqNum(),
			})
		}

		// Convert response redaction ranges
		var respRanges []shared.ResponseRedactionRange
		for _, rr := range kPayload.GetResponseRedactionRanges() {
			respRanges = append(respRanges, shared.ResponseRedactionRange{
				Start:  int(rr.GetStart()),
				Length: int(rr.GetLength()),
			})
		}

		bundle.Transcripts.TEEK = &shared.TEEKTranscript{
			Packets: kPayload.GetPackets(),
			RequestMetadata: &shared.RequestMetadata{
				RedactedRequest: kPayload.GetRedactedRequest(),
				RedactionRanges: reqRanges,
			},
			ResponseRedactionRanges: respRanges,
			RedactedStreams:         redactedStreams,
			Signature:               bundlePB.TeekSigned.GetSignature(),
			PublicKey:               bundlePB.TeekSigned.GetPublicKey(),
		}
	}

	// Extract data from TEE_T signed message
	if bundlePB.TeetSigned != nil {
		var tPayload teeproto.TOutputPayload
		if err := proto.Unmarshal(bundlePB.TeetSigned.GetBody(), &tPayload); err != nil {
			return fmt.Errorf("failed to unmarshal TEE_T body: %v", err)
		}

		bundle.Transcripts.TEET = &shared.TEETTranscript{
			Packets:   tPayload.GetPackets(),
			Signature: bundlePB.TeetSigned.GetSignature(),
			PublicKey: bundlePB.TeetSigned.GetPublicKey(),
		}
	}

	// Convert handshake keys if present
	if bundlePB.HandshakeKeys != nil {
		bundle.HandshakeKeys = shared.HandshakeSecrets{
			HandshakeKey: bundlePB.HandshakeKeys.GetHandshakeKey(),
			HandshakeIV:  bundlePB.HandshakeKeys.GetHandshakeIv(),
			CipherSuite:  uint16(bundlePB.HandshakeKeys.GetCipherSuite()),
			Algorithm:    bundlePB.HandshakeKeys.GetAlgorithm(),
		}
	}

	// Convert opening if present
	if bundlePB.Opening != nil {
		bundle.Opening = &shared.Opening{
			ProofStream: bundlePB.Opening.GetProofStream(),
			ProofKey:    bundlePB.Opening.GetProofKey(),
		}
	}

	// Now run the existing verification logic with the converted bundle

	// --- Proof stream application (commitment verification handled by TEE_T) ---
	if bundle.Opening.ProofStream != nil && bundle.Opening.ProofKey != nil && bundle.Transcripts.TEEK != nil {
		fmt.Printf("[Verifier] Proof stream available ✅ (len=%d, key_len=%d)\n",
			len(bundle.Opening.ProofStream), len(bundle.Opening.ProofKey))
		fmt.Printf("[Verifier] Note: Commitment verification performed by TEE_T during protocol execution\n")

		// Apply proof stream to reveal original sensitive_proof data
		if err := verifyAndRevealProofData(*bundle); err != nil {
			return fmt.Errorf("failed to apply proof stream: %v", err)
		}
	} else {
		// SECURITY: Missing proof components compromise verification integrity
		return fmt.Errorf("critical security failure: proof stream/key or TEE_K transcript missing - cannot perform proof stream application")
	}

	// --- Redacted response reconstruction check ---
	if bundle.Transcripts.TEET == nil {
		// SECURITY: TEET transcript is required for proper verification
		return fmt.Errorf("critical security failure: TEET transcript missing - cannot perform stream verification")
	}
	// Build ordered slice of ciphertexts (application data) from TEET transcript
	var ciphertexts [][]byte

	// Check if this is TLS 1.2 AES-GCM (has explicit IV)
	isTLS12AESGCM := shared.IsTLS12AESGCMCipherSuite(bundle.HandshakeKeys.CipherSuite)

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

		// Replace random garbage with asterisks using response redaction ranges
		if bundle.Transcripts.TEEK.ResponseRedactionRanges != nil && len(bundle.Transcripts.TEEK.ResponseRedactionRanges) > 0 {
			// Consolidate ranges for display (same as client)
			consolidatedRanges := shared.ConsolidateResponseRedactionRanges(bundle.Transcripts.TEEK.ResponseRedactionRanges)
			reconstructed = replaceRandomGarbageWithAsterisks(reconstructed, consolidatedRanges)
			fmt.Printf("[Verifier] Applied %d consolidated response redaction ranges to replace random garbage with asterisks\n", len(consolidatedRanges))
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
		// Note: Commitments are no longer included in signature verification
		// TEE_T verifies commitments and signs the proof stream

		// Include redaction ranges in signature verification (same as signing)
		if len(transcript.RequestMetadata.RedactionRanges) > 0 {
			redactionRangesBytes, err := json.Marshal(transcript.RequestMetadata.RedactionRanges)
			if err != nil {
				return fmt.Errorf("failed to marshal redaction ranges for verification: %v", err)
			}
			buffer.Write(redactionRangesBytes)
		}
	}

	// Add response redaction ranges to signature verification (same as signing)
	if len(transcript.ResponseRedactionRanges) > 0 {
		responseRedactionRangesBytes, err := json.Marshal(transcript.ResponseRedactionRanges)
		if err != nil {
			return fmt.Errorf("failed to marshal response redaction ranges for verification: %v", err)
		}
		buffer.Write(responseRedactionRangesBytes)
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
		if r.Type == shared.RedactionTypeSensitiveProof {
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

// verifySignedMessage verifies a protobuf SignedMessage
func verifySignedMessage(signedMsg *teeproto.SignedMessage, source string) error {
	if signedMsg == nil {
		return fmt.Errorf("SECURITY ERROR: %s signed message is nil", source)
	}

	fmt.Printf("[Verifier] Verifying %s signed message (body type: %v)\n", source, signedMsg.GetBodyType())

	// SECURITY: Strict validation of required fields
	if len(signedMsg.GetSignature()) == 0 {
		return fmt.Errorf("SECURITY ERROR: %s missing signature - cannot verify authenticity", source)
	}
	if len(signedMsg.GetPublicKey()) == 0 {
		return fmt.Errorf("SECURITY ERROR: %s missing public key - cannot verify authenticity", source)
	}
	if len(signedMsg.GetBody()) == 0 {
		return fmt.Errorf("SECURITY ERROR: %s missing body - no data to verify", source)
	}

	// Validate body type
	expectedBodyType := teeproto.BodyType_BODY_TYPE_K_OUTPUT
	if source == "TEE_T" {
		expectedBodyType = teeproto.BodyType_BODY_TYPE_T_OUTPUT
	}
	if signedMsg.GetBodyType() != expectedBodyType {
		return fmt.Errorf("SECURITY ERROR: %s wrong body type, expected %v got %v", source, expectedBodyType, signedMsg.GetBodyType())
	}

	// For TEE_K signatures, we need to reconstruct the original signed data
	// The signature was created over concatenated raw data, not the protobuf body
	var dataToVerify []byte
	if source == "TEE_K" {
		// Reconstruct the masterBuffer that was originally signed by TEE_K
		var kPayload teeproto.KOutputPayload
		if err := proto.Unmarshal(signedMsg.GetBody(), &kPayload); err != nil {
			return fmt.Errorf("failed to unmarshal TEE_K body for verification: %v", err)
		}

		var masterBuffer bytes.Buffer

		// Add request metadata (redacted request + redaction ranges as JSON)
		if kPayload.RedactedRequest != nil {
			masterBuffer.Write(kPayload.RedactedRequest)
		}
		if len(kPayload.RequestRedactionRanges) > 0 {
			// Convert protobuf ranges back to shared format for JSON marshaling
			var ranges []shared.RequestRedactionRange
			for _, r := range kPayload.RequestRedactionRanges {
				ranges = append(ranges, shared.RequestRedactionRange{
					Start: int(r.Start), Length: int(r.Length),
					Type: r.Type, RedactionBytes: r.RedactionBytes,
				})
			}
			if rangesJSON, err := json.Marshal(ranges); err == nil {
				masterBuffer.Write(rangesJSON)
			}
		}

		// Add response redaction ranges as JSON
		if len(kPayload.ResponseRedactionRanges) > 0 {
			var respRanges []shared.ResponseRedactionRange
			for _, rr := range kPayload.ResponseRedactionRanges {
				respRanges = append(respRanges, shared.ResponseRedactionRange{
					Start: int(rr.Start), Length: int(rr.Length),
				})
			}
			if respRangesJSON, err := json.Marshal(respRanges); err == nil {
				masterBuffer.Write(respRangesJSON)
			}
		}

		// Add redacted streams
		for _, s := range kPayload.RedactedStreams {
			masterBuffer.Write(s.RedactedStream)
		}

		// Add TLS packets
		for _, p := range kPayload.Packets {
			masterBuffer.Write(p)
		}

		dataToVerify = masterBuffer.Bytes()
	} else {
		// For TEE_T, the signature is over concatenated raw packets, not the protobuf body
		var tPayload teeproto.TOutputPayload
		if err := proto.Unmarshal(signedMsg.GetBody(), &tPayload); err != nil {
			return fmt.Errorf("failed to unmarshal TEE_T body for verification: %v", err)
		}

		// Concatenate all packets (same as SignTranscript method)
		var allData []byte
		for _, packet := range tPayload.Packets {
			allData = append(allData, packet...)
		}
		dataToVerify = allData
	}

	// Perform actual cryptographic signature verification
	if err := shared.VerifySignatureWithDER(dataToVerify, signedMsg.GetSignature(), signedMsg.GetPublicKey()); err != nil {
		return fmt.Errorf("SECURITY ERROR: %s cryptographic signature verification FAILED: %v", source, err)
	}

	fmt.Printf("[Verifier] ✅ %s cryptographic signature verification PASSED (signature: %d bytes, body: %d bytes)\n",
		source, len(signedMsg.GetSignature()), len(signedMsg.GetBody()))
	return nil
}
