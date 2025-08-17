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

	if bundlePB.TeekSigned == nil {
		// SECURITY: Missing proof components compromise verification integrity
		return fmt.Errorf("critical security failure: TEE_K transcript missing - cannot perform proof stream application")
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
		// Only process ApplicationData packets (0x17) - skip handshake messages like session tickets
		// TEE_K only generates redacted streams for application data, not TLS handshake messages
		if pkt[0] != 0x17 {
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

	// Reconstruct plaintext by matching streams to ciphertexts by sequence order
	var reconstructed []byte
	if len(kPayload.GetRedactedStreams()) > 0 {
		// Both streams (from TEE_K) and ciphertexts (from TEE_T) are already in sequence order
		// TEE_K now sorts seqNumbers before processing, TEE_T sorts responses before transcript
		streams := kPayload.GetRedactedStreams()

		// Match streams to ciphertexts by position (both are in sequence number order)
		for i, stream := range streams {
			if i >= len(ciphertexts) {
				return fmt.Errorf("not enough ciphertexts for stream seq %d (have %d ciphertexts, need %d)", stream.GetSeqNum(), len(ciphertexts), i+1)
			}

			cipher := ciphertexts[i]
			if len(cipher) != len(stream.GetRedactedStream()) {
				return fmt.Errorf("ciphertext length mismatch for stream seq %d: expected %d, got %d", stream.GetSeqNum(), len(stream.GetRedactedStream()), len(cipher))
			}

			plain := make([]byte, len(cipher))
			for j := range cipher {
				plain[j] = cipher[j] ^ stream.GetRedactedStream()[j]
			}
			reconstructed = append(reconstructed, plain...)
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

	// --- Request reconstruction using TEE_T-signed proof streams ---
	if len(tPayload.GetRequestProofStreams()) > 0 {
		fmt.Printf("[Verifier] Found %d R_SP proof streams signed by TEE_T ✅\n", len(tPayload.GetRequestProofStreams()))

		redactedRequest := kPayload.GetRedactedRequest()
		redactionRanges := kPayload.GetRequestRedactionRanges()

		if len(redactedRequest) > 0 {
			// Create a copy of the redacted request to apply proof streams
			revealedRequest := make([]byte, len(redactedRequest))
			copy(revealedRequest, redactedRequest)

			// Apply proof streams ONLY to sensitive_proof ranges
			proofStreamIndex := 0

			for _, r := range redactionRanges {
				if r.GetType() == "sensitive_proof" {
					if proofStreamIndex >= len(tPayload.GetRequestProofStreams()) {
						return fmt.Errorf("insufficient TEE_T-signed proof streams for sensitive_proof range")
					}

					proofStream := tPayload.GetRequestProofStreams()[proofStreamIndex]
					start := int(r.GetStart())
					length := int(r.GetLength())

					if start+length > len(revealedRequest) {
						return fmt.Errorf("proof range [%d:%d] exceeds request length %d", start, start+length, len(revealedRequest))
					}

					if length != len(proofStream) {
						return fmt.Errorf("proof stream length mismatch: range needs %d bytes, stream has %d", length, len(proofStream))
					}

					// Apply XOR to reveal original sensitive_proof data
					for i := 0; i < length; i++ {
						revealedRequest[start+i] ^= proofStream[i]
					}

					fmt.Printf("[Verifier] ✅ Revealed sensitive_proof range [%d:%d] using TEE_T-signed stream\n", start, start+length)
					proofStreamIndex++
				}
			}

			fmt.Printf("[Verifier] Reconstructed request with TEE_T-signed proof streams:\n---\n%s\n---\n", string(revealedRequest))
		}
	} else {
		fmt.Println("[Verifier] No R_SP proof streams - only R_S verification available (sensitive data remains redacted)")
	}

	// --- Verify redaction ranges authenticity ---
	if len(kPayload.GetRequestRedactionRanges()) > 0 {
		fmt.Printf("[Verifier] Redaction ranges verified ✅ (TEE_K signed %d ranges)\n", len(kPayload.GetRequestRedactionRanges()))
	} else {
		fmt.Println("[Verifier] Warning: No signed redaction ranges from TEE_K")
	}

	fmt.Println("[Verifier] Offline verification complete – success 🥳")
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
