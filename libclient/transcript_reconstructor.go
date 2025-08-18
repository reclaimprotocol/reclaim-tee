package clientlib

import (
	"fmt"

	teeproto "tee-mpc/proto"

	"google.golang.org/protobuf/proto"
)

// ReconstructTranscriptForClaimTunnel reconstructs TLS transcript exactly like attestor does
// This ensures the ClaimTunnelRequest we sign matches what the attestor will validate
func ReconstructTranscriptForClaimTunnel(bundlePB *teeproto.VerificationBundle) ([]*teeproto.ClaimTunnelRequest_TranscriptMessage, error) {
	// Extract payloads (copy from proofverifier.go lines 150-160)
	var kPayload teeproto.KOutputPayload
	if err := proto.Unmarshal(bundlePB.TeekSigned.GetBody(), &kPayload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal TEE_K body: %v", err)
	}

	var tPayload teeproto.TOutputPayload
	if err := proto.Unmarshal(bundlePB.TeetSigned.GetBody(), &tPayload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal TEE_T body: %v", err)
	}

	// Reconstruct request (copy from proofverifier.go lines 250-336)
	revealedRequest, err := reconstructRequest(&kPayload, &tPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct request: %v", err)
	}

	// Reconstruct response (copy from proofverifier.go lines 170-230)
	reconstructedResponse, err := reconstructResponse(&kPayload, &tPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct response: %v", err)
	}

	// Create transcript messages exactly like attestor does
	return createTranscriptMessages(&kPayload, revealedRequest, reconstructedResponse, bundlePB)
}

// reconstructRequest applies TEE_T-signed proof streams to reveal sensitive_proof data
// Updated to use secure TEE_T-signed streams instead of client-provided opening
func reconstructRequest(kPayload *teeproto.KOutputPayload, tPayload *teeproto.TOutputPayload) ([]byte, error) {
	if len(tPayload.GetRequestProofStreams()) == 0 {
		return kPayload.RedactedRequest, nil
	}

	if len(kPayload.RequestRedactionRanges) == 0 {
		return kPayload.RedactedRequest, nil
	}

	// Create a copy of the redacted request to apply proof streams
	revealedRequest := make([]byte, len(kPayload.RedactedRequest))
	copy(revealedRequest, kPayload.RedactedRequest)

	// Apply proof streams ONLY to sensitive_proof ranges
	proofStreamIndex := 0

	for _, r := range kPayload.RequestRedactionRanges {
		if r.GetType() == "sensitive_proof" {
			if proofStreamIndex >= len(tPayload.GetRequestProofStreams()) {
				return nil, fmt.Errorf("insufficient TEE_T-signed proof streams for sensitive_proof range")
			}

			proofStream := tPayload.GetRequestProofStreams()[proofStreamIndex]
			start := int(r.GetStart())
			length := int(r.GetLength())

			if start+length > len(revealedRequest) {
				return nil, fmt.Errorf("proof range [%d:%d] exceeds request length %d", start, start+length, len(revealedRequest))
			}

			if length != len(proofStream) {
				return nil, fmt.Errorf("proof stream length mismatch: range needs %d bytes, stream has %d", length, len(proofStream))
			}

			// Apply XOR to reveal original sensitive_proof data
			for i := 0; i < length; i++ {
				revealedRequest[start+i] ^= proofStream[i]
			}

			proofStreamIndex++
		}
	}

	return revealedRequest, nil
}

// reconstructResponse XORs redacted streams with ciphertexts
// Copied from proofverifier.go lines 170-230
func reconstructResponse(kPayload *teeproto.KOutputPayload, tPayload *teeproto.TOutputPayload) ([]byte, error) {
	// Direct XOR with consolidated streams for verification
	consolidatedKeystream := kPayload.GetConsolidatedResponseKeystream()
	consolidatedCiphertext := tPayload.GetConsolidatedResponseCiphertext()

	if len(consolidatedKeystream) == 0 || len(consolidatedCiphertext) == 0 {
		return []byte{}, nil
	}

	if len(consolidatedKeystream) != len(consolidatedCiphertext) {
		return nil, fmt.Errorf("consolidated keystream/ciphertext length mismatch: %d vs %d",
			len(consolidatedKeystream), len(consolidatedCiphertext))
	}

	// Direct XOR - dramatically simpler!
	result := make([]byte, len(consolidatedCiphertext))
	for i := range consolidatedCiphertext {
		result[i] = consolidatedCiphertext[i] ^ consolidatedKeystream[i]
	}

	// Apply response redaction ranges to replace random garbage with asterisks
	return applyResponseRedactionRanges(result, kPayload.ResponseRedactionRanges), nil
}

// applyResponseRedactionRanges replaces random garbage with asterisks
func applyResponseRedactionRanges(response []byte, redactionRanges []*teeproto.ResponseRedactionRange) []byte {
	if len(redactionRanges) == 0 {
		return response
	}

	result := make([]byte, len(response))
	copy(result, response)

	// Apply each redaction range
	for _, r := range redactionRanges {
		start := int(r.Start)
		length := int(r.Length)
		end := start + length

		// Check bounds
		if start < 0 || end > len(result) {
			continue
		}

		// Replace with asterisks
		for i := start; i < end; i++ {
			result[i] = 0x2A // ASCII asterisk '*'
		}
	}

	return result
}

// createTranscriptMessages creates transcript messages matching attestor's logic
func createTranscriptMessages(kPayload *teeproto.KOutputPayload, revealedRequest, reconstructedResponse []byte, bundlePB *teeproto.VerificationBundle) ([]*teeproto.ClaimTunnelRequest_TranscriptMessage, error) {
	var messages []*teeproto.ClaimTunnelRequest_TranscriptMessage

	// Add client request (revealed)
	messages = append(messages, &teeproto.ClaimTunnelRequest_TranscriptMessage{
		Sender:  teeproto.TranscriptMessageSenderType_TRANSCRIPT_MESSAGE_SENDER_TYPE_CLIENT,
		Message: wrapInTlsRecord(revealedRequest, 0x17),
	})

	// Add server response (reconstructed)
	if len(reconstructedResponse) > 0 {
		messages = append(messages, &teeproto.ClaimTunnelRequest_TranscriptMessage{
			Sender:  teeproto.TranscriptMessageSenderType_TRANSCRIPT_MESSAGE_SENDER_TYPE_SERVER,
			Message: wrapInTlsRecord(reconstructedResponse, 0x17),
		})
	}

	return messages, nil
}

// Helper functions for transcript reconstruction

func wrapInTlsRecord(data []byte, recordType byte) []byte {
	// Create TLS record: Type(1) + Version(2) + Length(2) + Data
	record := make([]byte, 5+len(data))
	record[0] = recordType             // Record type
	record[1] = 0x03                   // TLS version major
	record[2] = 0x03                   // TLS version minor (TLS 1.2)
	record[3] = byte(len(data) >> 8)   // Length high byte
	record[4] = byte(len(data) & 0xFF) // Length low byte
	copy(record[5:], data)
	return record
}

// ExtractHostFromBundle extracts hostname from certificate info in signed TEE_K payload
func ExtractHostFromBundle(bundle *teeproto.VerificationBundle) string {
	// SECURITY: Extract certificate info from signed TEE_K payload, not unsigned bundle field
	if bundle.GetTeekSigned() != nil {
		var kPayload teeproto.KOutputPayload
		if err := proto.Unmarshal(bundle.GetTeekSigned().GetBody(), &kPayload); err != nil {
			return "example.com" // Fallback on unmarshal error
		}

		if certInfo := kPayload.GetCertificateInfo(); certInfo != nil {
			// Prefer DNS names if available
			if len(certInfo.GetDnsNames()) > 0 {
				return certInfo.GetDnsNames()[0]
			}

			// Fall back to common name
			if certInfo.GetCommonName() != "" {
				return certInfo.GetCommonName()
			}
		}
	}

	return "example.com" // Fallback
}
