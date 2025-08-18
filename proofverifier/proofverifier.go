package proofverifier

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

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

	// --- Timestamp validation ---
	if err := validateTimestamps(bundlePB.TeekSigned, bundlePB.TeetSigned); err != nil {
		return fmt.Errorf("timestamp validation failed: %v", err)
	}

	fmt.Println("[Verifier] Timestamp validation successful")

	// Work directly with protobuf format - no legacy conversion needed!

	if bundlePB.TeekSigned == nil {
		// SECURITY: Missing proof components compromise verification integrity
		return fmt.Errorf("critical security failure: TEE_K transcript missing - cannot perform proof stream application")
	}

	// --- Extract payloads ---
	var kPayload teeproto.KOutputPayload
	if err := proto.Unmarshal(bundlePB.TeekSigned.GetBody(), &kPayload); err != nil {
		return fmt.Errorf("failed to unmarshal TEE_K payload: %v", err)
	}

	var tPayload teeproto.TOutputPayload
	if err := proto.Unmarshal(bundlePB.TeetSigned.GetBody(), &tPayload); err != nil {
		return fmt.Errorf("failed to unmarshal TEE_T payload: %v", err)
	}

	// --- SIMPLIFIED RESPONSE RECONSTRUCTION ---
	consolidatedKeystream := kPayload.GetConsolidatedResponseKeystream()
	consolidatedCiphertext := tPayload.GetConsolidatedResponseCiphertext()

	if len(consolidatedKeystream) != len(consolidatedCiphertext) {
		return fmt.Errorf("response keystream/ciphertext length mismatch: %d vs %d",
			len(consolidatedKeystream), len(consolidatedCiphertext))
	}

	// Direct XOR - NO PACKET PARSING FOR RESPONSE!
	reconstructedResponse := make([]byte, len(consolidatedCiphertext))
	for i := range consolidatedCiphertext {
		reconstructedResponse[i] = consolidatedCiphertext[i] ^ consolidatedKeystream[i]
	}

	fmt.Printf("[Verifier] Reconstructed %d response bytes via direct XOR\n", len(reconstructedResponse))

	// --- Apply response redactions (UNCHANGED) ---
	if len(kPayload.GetResponseRedactionRanges()) > 0 {
		var respRanges []shared.ResponseRedactionRange
		for _, rr := range kPayload.GetResponseRedactionRanges() {
			respRanges = append(respRanges, shared.ResponseRedactionRange{
				Start:  int(rr.GetStart()),
				Length: int(rr.GetLength()),
			})
		}
		consolidatedRanges := shared.ConsolidateResponseRedactionRanges(respRanges)
		reconstructedResponse = replaceRandomGarbageWithAsterisks(reconstructedResponse, consolidatedRanges)
		fmt.Printf("[Verifier] Applied %d response redaction ranges\n", len(consolidatedRanges))
	}

	// --- Display response ---
	fmt.Println("[Verifier] Reconstructed response:\n---\n" + collapseAsterisks(string(reconstructedResponse)) + "\n---")

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

	// --- Display certificate info ---
	// SECURITY: Extract certificate info from signed TEE_K payload, not unsigned bundle field
	certInfo := kPayload.GetCertificateInfo()
	if certInfo != nil {
		fmt.Printf("[Verifier] Certificate: %s (issued by %s)\n",
			certInfo.GetCommonName(), certInfo.GetIssuerCommonName())
		fmt.Printf("[Verifier] Valid: %s to %s\n",
			time.Unix(int64(certInfo.GetNotBeforeUnix()), 0).Format(time.RFC3339),
			time.Unix(int64(certInfo.GetNotAfterUnix()), 0).Format(time.RFC3339))
	}

	// --- Verify redaction ranges authenticity ---
	if len(kPayload.GetRequestRedactionRanges()) > 0 {
		fmt.Printf("[Verifier] Redaction ranges verified ✅ (TEE_K signed %d ranges)\n", len(kPayload.GetRequestRedactionRanges()))
	}

	fmt.Println("[Verifier] Verification complete – success 🥳")
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
		fmt.Printf("[Verifier] %s body content validated: redacted_request=%d bytes, ranges=%d, consolidated_keystream=%d bytes\n",
			source, len(kPayload.GetRedactedRequest()), len(kPayload.GetRequestRedactionRanges()),
			len(kPayload.GetConsolidatedResponseKeystream()))
	case teeproto.BodyType_BODY_TYPE_T_OUTPUT:
		var tPayload teeproto.TOutputPayload
		if err := proto.Unmarshal(signedMsg.GetBody(), &tPayload); err != nil {
			return fmt.Errorf("SECURITY ERROR: %s body parsing failed after signature verification: %v", source, err)
		}
		fmt.Printf("[Verifier] %s body content validated: consolidated_ciphertext=%d bytes\n", source, len(tPayload.GetConsolidatedResponseCiphertext()))
	}

	return nil
}

// validateTimestamps checks that both TEE timestamps are within acceptable ranges
// Requirements:
// 1. TEE_K and TEE_T timestamps must be within 5 seconds of each other
// 2. Neither timestamp can be older than 10 minutes in the past
// NOTE: Timestamps are now extracted from the SIGNED payloads, not the wrapper
func validateTimestamps(teekSigned, teetSigned *teeproto.SignedMessage) error {
	// Extract TEE_K timestamp from signed KOutputPayload
	var kPayload teeproto.KOutputPayload
	if err := proto.Unmarshal(teekSigned.GetBody(), &kPayload); err != nil {
		return fmt.Errorf("failed to unmarshal TEE_K payload for timestamp: %v", err)
	}
	teekTimestamp := kPayload.GetTimestampMs()

	// Extract TEE_T timestamp from signed TOutputPayload
	var tPayload teeproto.TOutputPayload
	if err := proto.Unmarshal(teetSigned.GetBody(), &tPayload); err != nil {
		return fmt.Errorf("failed to unmarshal TEE_T payload for timestamp: %v", err)
	}
	teetTimestamp := tPayload.GetTimestampMs()

	now := time.Now().UnixMilli()

	// Check if timestamps are present
	if teekTimestamp == 0 {
		return fmt.Errorf("TEE_K timestamp missing or invalid in signed payload")
	}
	if teetTimestamp == 0 {
		return fmt.Errorf("TEE_T timestamp missing or invalid in signed payload")
	}

	// Check that neither timestamp is older than 10 minutes
	maxAgeMs := int64(10 * 60 * 1000) // 10 minutes in milliseconds
	if now-int64(teekTimestamp) > maxAgeMs {
		return fmt.Errorf("TEE_K timestamp too old: %d minutes ago", (now-int64(teekTimestamp))/60000)
	}
	if now-int64(teetTimestamp) > maxAgeMs {
		return fmt.Errorf("TEE_T timestamp too old: %d minutes ago", (now-int64(teetTimestamp))/60000)
	}

	// Check that TEE_K and TEE_T timestamps are within 5 seconds of each other
	timeDiffMs := int64(teekTimestamp) - int64(teetTimestamp)
	if timeDiffMs < 0 {
		timeDiffMs = -timeDiffMs
	}
	maxDiffMs := int64(5 * 1000) // 5 seconds in milliseconds
	if timeDiffMs > maxDiffMs {
		return fmt.Errorf("TEE_K and TEE_T timestamps differ by %d seconds (max allowed: 5 seconds)", timeDiffMs/1000)
	}

	fmt.Printf("[Verifier] Timestamp validation passed (SIGNED timestamps):\n")
	fmt.Printf("  TEE_K: %s\n", time.UnixMilli(int64(teekTimestamp)).UTC().Format("2006-01-02 15:04:05.000 UTC"))
	fmt.Printf("  TEE_T: %s\n", time.UnixMilli(int64(teetTimestamp)).UTC().Format("2006-01-02 15:04:05.000 UTC"))
	fmt.Printf("  Time difference: %d ms\n", timeDiffMs)

	return nil
}
