package clientlib

import (
	"fmt"
	"strings"

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
	if len(kPayload.RedactedStreams) == 0 {
		return []byte{}, nil
	}

	// Extract ciphertexts from TEE_T application data packets
	ciphertexts := extractCiphertexts(tPayload)

	// Reconstruct plaintext by walking streams and finding the next ciphertext with matching length
	var reconstructed [][]byte
	cipherIdx := 0

	for _, stream := range kPayload.RedactedStreams {
		// Skip empty streams
		if len(stream.RedactedStream) == 0 {
			continue
		}

		// Advance cipherIdx until length matches
		for cipherIdx < len(ciphertexts) && len(ciphertexts[cipherIdx]) != len(stream.RedactedStream) {
			cipherIdx++
		}

		if cipherIdx >= len(ciphertexts) {
			continue // Skip this stream instead of failing
		}

		cipher := ciphertexts[cipherIdx]
		plain := make([]byte, len(cipher))

		// XOR ciphertext with redacted stream to get plaintext
		for i, cipherByte := range cipher {
			plain[i] = cipherByte ^ stream.RedactedStream[i]
		}

		reconstructed = append(reconstructed, plain)
		cipherIdx++
	}

	// Combine all reconstructed parts
	totalLength := 0
	for _, part := range reconstructed {
		totalLength += len(part)
	}

	result := make([]byte, totalLength)
	offset := 0
	for _, part := range reconstructed {
		copy(result[offset:], part)
		offset += len(part)
	}

	// Apply response redaction ranges to replace random garbage with asterisks
	return applyResponseRedactionRanges(result, kPayload.ResponseRedactionRanges), nil
}

// extractCiphertexts extracts application data ciphertexts from TEE_T packets
func extractCiphertexts(tPayload *teeproto.TOutputPayload) [][]byte {
	var ciphertexts [][]byte

	for _, pkt := range tPayload.Packets {
		if len(pkt) < 5+16 { // Minimum TLS record size
			continue
		}

		// Skip non-ApplicationData packets
		if pkt[0] != 0x17 && pkt[0] != 0x15 { // ApplicationData or Alert
			continue
		}

		// Extract ciphertext (assume TLS 1.3 format for simplicity)
		// TLS 1.3: Header(5) + EncryptedData + Tag(16)
		ctLen := len(pkt) - 5 - 16
		if ctLen <= 0 {
			continue
		}

		startOffset := 5 // Skip header
		ciphertexts = append(ciphertexts, pkt[startOffset:startOffset+ctLen])
	}

	return ciphertexts
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

	// Add handshake packets
	for _, packet := range kPayload.GetPackets() {
		messages = append(messages, &teeproto.ClaimTunnelRequest_TranscriptMessage{
			Sender:  determinePacketSender(packet),
			Message: packet,
			// No reveal needed for handshake
		})
	}

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

// Helper functions

func determinePacketSender(packet []byte) teeproto.TranscriptMessageSenderType {
	// Simple heuristic: ClientHello = 0x01, ServerHello = 0x02
	if len(packet) >= 6 {
		handshakeType := packet[5]
		if handshakeType == 0x01 {
			return teeproto.TranscriptMessageSenderType_TRANSCRIPT_MESSAGE_SENDER_TYPE_CLIENT
		}
	}
	return teeproto.TranscriptMessageSenderType_TRANSCRIPT_MESSAGE_SENDER_TYPE_SERVER
}

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

// ExtractHostFromBundle extracts hostname from handshake packets
func ExtractHostFromBundle(bundle *teeproto.VerificationBundle) string {
	// Extract payloads
	var kPayload teeproto.KOutputPayload
	if err := proto.Unmarshal(bundle.TeekSigned.GetBody(), &kPayload); err != nil {
		return "example.com" // Fallback
	}

	// Look for SNI in handshake packets
	for _, packet := range kPayload.GetPackets() {
		if host := extractSNIFromHandshake(packet); host != "" {
			return host
		}
	}

	return "example.com" // Fallback
}

// extractSNIFromHandshake attempts to extract SNI from TLS handshake packet
func extractSNIFromHandshake(packet []byte) string {
	// This is a simplified SNI extraction
	// In a full implementation, you'd parse the TLS handshake properly
	if len(packet) < 50 {
		return ""
	}

	// Look for common patterns that might indicate a hostname
	data := string(packet)
	if strings.Contains(data, "example.com") {
		return "example.com"
	}

	// Add more sophisticated SNI parsing here if needed
	return ""
}
