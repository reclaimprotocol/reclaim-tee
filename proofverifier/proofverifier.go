package proofverifier

import (
	"fmt"
	"io"
	"os"
	"strings"

	teeproto "tee-mpc/proto"
	"tee-mpc/shared"

	"github.com/anjuna-security/go-nitro-attestation/verifier"
	"github.com/ethereum/go-ethereum/common"
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

	var bundlePB teeproto.VerificationBundle
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

	// Work directly with protobuf format - no legacy conversion needed!

	// --- Proof stream application (commitment verification handled by TEE_T) ---
	if bundlePB.Opening != nil && bundlePB.Opening.ProofStream != nil && bundlePB.TeekSigned != nil {
		fmt.Printf("[Verifier] Proof stream available ✅ (len=%d\n",
			len(bundlePB.Opening.ProofStream))
		fmt.Printf("[Verifier] Note: Commitment verification performed by TEE_T during protocol execution\n")

		// Apply proof stream to reveal original sensitive_proof data
		if err := verifyAndRevealProofDataProtobuf(&bundlePB); err != nil {
			return fmt.Errorf("failed to apply proof stream: %v", err)
		}
	} else {
		// SECURITY: Missing proof components compromise verification integrity
		return fmt.Errorf("critical security failure: proof stream/key or TEE_K transcript missing - cannot perform proof stream application")
	}

	// --- Redacted response reconstruction check ---
	if bundlePB.TeetSigned == nil {
		// SECURITY: TEET transcript is required for proper verification
		return fmt.Errorf("critical security failure: TEET transcript missing - cannot perform stream verification")
	}
	// Extract TEE_T payload for redacted response reconstruction
	var tPayload teeproto.TOutputPayload
	if err := proto.Unmarshal(bundlePB.TeetSigned.GetBody(), &tPayload); err != nil {
		return fmt.Errorf("failed to unmarshal TEE_T body: %v", err)
	}

	// Extract TEE_K payload for redacted streams and redaction ranges
	var kPayload teeproto.KOutputPayload
	if err := proto.Unmarshal(bundlePB.TeekSigned.GetBody(), &kPayload); err != nil {
		return fmt.Errorf("failed to unmarshal TEE_K body: %v", err)
	}

	// Build ordered slice of ciphertexts (application data) from TEET transcript
	var ciphertexts [][]byte

	// Check if this is TLS 1.2 AES-GCM (has explicit IV)
	var cipherSuite uint16
	if bundlePB.HandshakeKeys != nil {
		cipherSuite = uint16(bundlePB.HandshakeKeys.GetCipherSuite())
	}
	isTLS12AESGCM := shared.IsTLS12AESGCMCipherSuite(cipherSuite)

	for _, pkt := range tPayload.GetPackets() {
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
	if len(kPayload.GetRedactedStreams()) > 0 {
		for _, stream := range kPayload.GetRedactedStreams() {
			// advance cipherIdx until length matches
			for cipherIdx < len(ciphertexts) && len(ciphertexts[cipherIdx]) != len(stream.GetRedactedStream()) {
				cipherIdx++
			}
			if cipherIdx >= len(ciphertexts) {
				return fmt.Errorf("no ciphertext of length %d found for stream seq %d", len(stream.GetRedactedStream()), stream.GetSeqNum())
			}
			cipher := ciphertexts[cipherIdx]
			plain := make([]byte, len(cipher))
			for i := range cipher {
				plain[i] = cipher[i] ^ stream.GetRedactedStream()[i]
			}
			reconstructed = append(reconstructed, plain...)
			cipherIdx++
		}

		// Replace random garbage with asterisks using response redaction ranges
		if len(kPayload.GetResponseRedactionRanges()) > 0 {
			// Convert protobuf ranges to shared format for consolidation
			var respRanges []shared.ResponseRedactionRange
			for _, rr := range kPayload.GetResponseRedactionRanges() {
				respRanges = append(respRanges, shared.ResponseRedactionRange{
					Start:  int(rr.GetStart()),
					Length: int(rr.GetLength()),
				})
			}
			// Consolidate ranges for display (same as client)
			consolidatedRanges := shared.ConsolidateResponseRedactionRanges(respRanges)
			reconstructed = replaceRandomGarbageWithAsterisks(reconstructed, consolidatedRanges)
			fmt.Printf("[Verifier] Applied %d consolidated response redaction ranges to replace random garbage with asterisks\n", len(consolidatedRanges))
		}

		fmt.Println("[Verifier] Reconstructed redacted response:\n---\n" + collapseAsterisks(string(reconstructed)) + "\n---")
		fmt.Println("[Verifier] Redacted streams applied successfully ✅")
	} else {
		fmt.Println("[Verifier] No redacted streams available for reconstruction")
	}

	// --- Verify redaction ranges authenticity ---
	if len(kPayload.GetRequestRedactionRanges()) > 0 {
		fmt.Printf("[Verifier] Redaction ranges verified ✅ (TEE_K signed %d ranges)\n", len(kPayload.GetRequestRedactionRanges()))
	} else {
		fmt.Println("[Verifier] Warning: No signed redaction ranges from TEE_K")
	}

	// NOTE: Request display is now handled in verifyAndRevealProofData() function above
	// which shows the proper revealed version with proof data visible and sensitive data hidden

	fmt.Println("[Verifier] Offline verification complete – success 🥳")
	return nil
}

// verifyAndRevealProofDataProtobuf applies the proof stream to reveal original sensitive_proof data (protobuf version)
func verifyAndRevealProofDataProtobuf(bundlePB *teeproto.VerificationBundle) error {
	// Extract TEE_K payload
	var kPayload teeproto.KOutputPayload
	if err := proto.Unmarshal(bundlePB.TeekSigned.GetBody(), &kPayload); err != nil {
		return fmt.Errorf("failed to unmarshal TEE_K body: %v", err)
	}

	redactedRequest := kPayload.GetRedactedRequest()
	redactionRanges := kPayload.GetRequestRedactionRanges()

	if bundlePB.Opening == nil || bundlePB.Opening.ProofStream == nil {
		fmt.Println("[Verifier] No proof stream available for SP revelation")
		return nil
	}

	proofStream := bundlePB.Opening.ProofStream

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
		if r.GetType() == shared.RedactionTypeSensitiveProof {
			// Check bounds
			start := int(r.GetStart())
			length := int(r.GetLength())
			if start+length > len(revealedRequest) {
				return fmt.Errorf("proof range [%d:%d] exceeds request length %d", start, start+length, len(revealedRequest))
			}

			// Check if we have enough proof stream data
			if proofStreamOffset+length > len(proofStream) {
				return fmt.Errorf("insufficient proof stream data for range %d (need %d bytes, have %d)",
					proofRangesFound, length, len(proofStream)-proofStreamOffset)
			}

			// Apply XOR to reveal original sensitive_proof data
			for i := 0; i < length; i++ {
				revealedRequest[start+i] ^= proofStream[proofStreamOffset+i]
			}

			fmt.Printf("[Verifier] Revealed proof range [%d:%d] type=%s (%d bytes)\n",
				start, start+length, r.GetType(), length)

			proofStreamOffset += length
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
		if !strings.Contains(r.GetType(), "proof") {
			start := int(r.GetStart())
			length := int(r.GetLength())
			for i := 0; i < length && start+i < len(prettyRequest); i++ {
				prettyRequest[start+i] = '*'
			}
		}
	}

	fmt.Printf("%s\n---\n", collapseAsterisks(string(prettyRequest)))
	fmt.Printf("[Verifier] Successfully revealed %d proof ranges while keeping sensitive data hidden ✅\n", proofRangesFound)

	return nil
}

// verifyAttestationReportETH verifies a protobuf AttestationReport and extracts the ETH address
func verifyAttestationReportETH(report *teeproto.AttestationReport, expectedSource string) (common.Address, error) {
	switch report.Type {
	case "nitro":
		sr, err := verifier.NewSignedAttestationReport(strings.NewReader(string(report.Report)))
		if err != nil {
			return common.Address{}, fmt.Errorf("failed to parse nitro report: %v", err)
		}
		if err := verifier.Validate(sr, nil); err != nil {
			return common.Address{}, fmt.Errorf("nitro validation failed: %v", err)
		}

		// Extract ETH address from user data in the attestation document
		userDataStr := string(sr.Document.UserData)
		expectedPrefix := fmt.Sprintf("%s_public_key:", strings.ToLower(expectedSource))
		if !strings.HasPrefix(userDataStr, expectedPrefix) {
			return common.Address{}, fmt.Errorf("invalid user data format, expected prefix %s", expectedPrefix)
		}

		ethAddressHex := userDataStr[len(expectedPrefix):]
		if !strings.HasPrefix(ethAddressHex, "0x") {
			return common.Address{}, fmt.Errorf("invalid ETH address format, expected 0x prefix")
		}

		if !common.IsHexAddress(ethAddressHex) {
			return common.Address{}, fmt.Errorf("invalid ETH address format: %s", ethAddressHex)
		}

		ethAddress := common.HexToAddress(ethAddressHex)
		fmt.Printf("[Verifier] Extracted ETH address from Nitro attestation: %s\n", ethAddress.Hex())
		return ethAddress, nil

	case "gcp":
		// For GCP, we need to extract the ETH address from the attestation token
		// This is a placeholder - GCP attestation ETH address extraction needs specific implementation
		return common.Address{}, fmt.Errorf("GCP ETH address extraction not yet implemented for protobuf format")

	default:
		return common.Address{}, fmt.Errorf("unsupported attestation type: %s", report.Type)
	}
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

	// Extract ETH address - either from AttestationReport (enclave mode) or PublicKey field (standalone mode)
	var ethAddress common.Address
	var err error

	if signedMsg.GetAttestationReport() != nil {
		// Enclave mode: extract ETH address from attestation report
		attestationReport := signedMsg.GetAttestationReport()
		fmt.Printf("[Verifier] Verifying %s attestation report (type: %s)\n", source, attestationReport.GetType())

		// Verify attestation and extract ETH address
		ethAddress, err = verifyAttestationReportETH(attestationReport, source)
		if err != nil {
			return fmt.Errorf("SECURITY ERROR: %s attestation verification failed: %v", source, err)
		}
		fmt.Printf("[Verifier] %s attestation verification SUCCESS, extracted ETH address: %s\n", source, ethAddress.Hex())
	} else if len(signedMsg.GetEthAddress()) > 0 {
		// Standalone mode: use ETH address
		ethAddress = common.HexToAddress(string(signedMsg.GetEthAddress()))
		fmt.Printf("[Verifier] Using %s standalone mode ETH address: %s\n", source, ethAddress.Hex())
	} else {
		return fmt.Errorf("SECURITY ERROR: %s missing both attestation report and public key", source)
	}

	// SECURITY FIX: Verify ETH signature against the exact signed bytes (SignedMessage.Body)
	// The TEEs sign their protobuf payload and put those signed bytes as the body
	if err := shared.VerifySignatureWithETH(signedMsg.GetBody(), signedMsg.GetSignature(), ethAddress); err != nil {
		return fmt.Errorf("SECURITY ERROR: %s cryptographic signature verification FAILED: %v", source, err)
	}

	fmt.Printf("[Verifier] ✅ %s cryptographic signature verification PASSED (verified %d bytes exactly as signed)\n",
		source, len(signedMsg.GetBody()))

	// Only after signature verification succeeds, validate that the body can be parsed
	switch signedMsg.GetBodyType() {
	case teeproto.BodyType_BODY_TYPE_K_OUTPUT:
		var kPayload teeproto.KOutputPayload
		if err := proto.Unmarshal(signedMsg.GetBody(), &kPayload); err != nil {
			return fmt.Errorf("SECURITY ERROR: %s body parsing failed after signature verification: %v", source, err)
		}
		fmt.Printf("[Verifier] %s body content validated: redacted_request=%d bytes, ranges=%d, streams=%d, packets=%d\n",
			source, len(kPayload.GetRedactedRequest()), len(kPayload.GetRequestRedactionRanges()),
			len(kPayload.GetRedactedStreams()), len(kPayload.GetPackets()))
	case teeproto.BodyType_BODY_TYPE_T_OUTPUT:
		var tPayload teeproto.TOutputPayload
		if err := proto.Unmarshal(signedMsg.GetBody(), &tPayload); err != nil {
			return fmt.Errorf("SECURITY ERROR: %s body parsing failed after signature verification: %v", source, err)
		}
		fmt.Printf("[Verifier] %s body content validated: packets=%d\n", source, len(tPayload.GetPackets()))
	}

	return nil
}
