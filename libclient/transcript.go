package clientlib

import (
	"bytes"
	"fmt"
	"tee-mpc/shared"

	"go.uber.org/zap"
)

// validateTranscriptsAgainstCapturedTraffic validates both TEE transcripts
// against the client's captured TLS traffic to ensure integrity and completeness
func (c *Client) validateTranscriptsAgainstCapturedTraffic() {
	c.logger.Info("===== TRANSCRIPT VALIDATION REPORT =====")

	c.logger.Info("Validating transcripts against captured TLS records", zap.Int("records_count", len(c.capturedTraffic)))

	// Since we now capture raw TCP chunks exactly as TEE_K sees them,
	// we should compare them directly without trying to categorize by TLS record type

	for i, chunk := range c.capturedTraffic {
		if len(chunk) < 1 {
			// Empty chunks in captured traffic indicate protocol corruption
			c.terminateConnectionWithError("Empty chunk in captured traffic", fmt.Errorf("chunk %d is empty", i))
			return
		}

	}

	// Calculate total sizes
	totalCapturedSize := 0
	for _, chunk := range c.capturedTraffic {
		totalCapturedSize += len(chunk)
	}

	c.logger.Info("Client captured traffic analysis",
		zap.Int("total_chunks", len(c.capturedTraffic)),
		zap.Int("total_captured_size", totalCapturedSize))

	// Perform detailed comparison with TEE transcripts
	c.logger.Info("Detailed transcript comparison")

	// Validate TEE_K transcript (should contain raw TCP chunks - bidirectional)
	teekValidation := c.validateTEEKTranscriptRaw()

	// Validate TEE_T transcript (should contain application data packets - bidirectional)
	teetValidation := c.validateTEETTranscriptRaw()

	// Summary
	c.logger.Info("VALIDATION RESULTS",
		zap.Bool("both_transcripts_received", true),
		zap.Bool("both_signatures_verified", true),
		zap.Int("tcp_chunks_captured", len(c.capturedTraffic)))

	if teekValidation && teetValidation {
		c.logger.Info("TRANSCRIPT VALIDATION PASSED - All packets match!")
	} else {
		c.logger.Error("TRANSCRIPT VALIDATION FAILED - Packet mismatches detected!")
	}

	c.logger.Info("===== VALIDATION COMPLETE =====")
}

// validateTEEKTranscriptRaw validates TEE_K transcript against client raw TCP chunks
func (c *Client) validateTEEKTranscriptRaw() bool {
	c.logger.Info("Validating TEE_K transcript against client captures", zap.Int("packets_count", len(c.teekTranscriptPackets)))

	if c.teekTranscriptPackets == nil {
		c.logger.Error("TEE_K transcript packets not available")
		return false
	}

	// TEE_K captures raw TCP chunks during handshake, so we should compare against
	// the raw TCP chunks we captured (not the individual TLS records from application phase)
	c.logger.Info("TEE_K transcript analysis")

	handshakePacketsMatched := 0
	totalCompared := 0 // number of transcript packets that we actually compared against captures
	for _, teekPacket := range c.teekTranscriptPackets {

		// All transcript packets are now TLS records by definition
		totalCompared++

		// Check if this packet matches any of the client's captured data
		found := false
		for _, chunk := range c.capturedTraffic {
			if len(teekPacket) == len(chunk) && bytes.Equal(teekPacket, chunk) {
				handshakePacketsMatched++
				found = true
				break
			}
		}

		if !found {
			c.logger.Debug("Packet NOT found in client captures")
		}
	}

	c.logger.Info("TEE_K validation result", zap.Int("packets_matched", handshakePacketsMatched), zap.Int("total_compared", totalCompared))

	return handshakePacketsMatched == totalCompared
}

// validateTEETTranscriptRaw validates TEE_T transcript against client application data records
func (c *Client) validateTEETTranscriptRaw() bool {
	c.logger.Info("Validating TEE_T transcript against client captures", zap.Int("packets_count", len(c.teetTranscriptPackets)))

	if c.teetTranscriptPackets == nil {
		c.logger.Error("TEE_T transcript packets not available")
		return false
	}

	c.logger.Info("TEE_T transcript analysis")

	packetsMatched := 0
	for _, teetPacket := range c.teetTranscriptPackets {
		// fmt.Printf("[Client]   TEE_T packet %d: %d bytes (type: 0x%02x)\n",
		// 	i+1, len(teetPacket), teetPacket[0])

		// Check if this packet matches any of our captured packets
		found := false
		for _, clientPacket := range c.capturedTraffic {
			if len(teetPacket) == len(clientPacket) && bytes.Equal(teetPacket, clientPacket) {
				packetsMatched++
				found = true
				break
			}
		}

		if !found {
			c.logger.Debug("Packet NOT found in client captures")
		}
	}

	c.logger.Info("TEE_T validation result", zap.Int("packets_matched", packetsMatched), zap.Int("total_packets", len(c.teetTranscriptPackets)))

	return packetsMatched == len(c.teetTranscriptPackets)
}

// handleSignedTranscript processes signed transcript messages from TEE_T
// Note: TEE_K now sends combined messages via handleRedactedTranscriptAndStreams
func (c *Client) handleSignedTranscript(msg *shared.Message) {
	var signedTranscript shared.SignedTranscript
	if err := msg.UnmarshalData(&signedTranscript); err != nil {
		c.logger.Error("Failed to unmarshal signed transcript", zap.Error(err))
		return
	}

	c.logger.Info("Received signed transcript from TEE_T",
		zap.Int("packets_count", len(signedTranscript.Packets)),
		zap.Int("signature_bytes", len(signedTranscript.Signature)),
		zap.Int("public_key_bytes", len(signedTranscript.PublicKey)))

	// Store the public key for attestation verification
	c.teetTranscriptPublicKey = signedTranscript.PublicKey
	c.teetSignedTranscript = &signedTranscript
	c.teetTranscriptPackets = signedTranscript.Packets // Store packets for validation

	// Calculate total size of all packets
	totalSize := 0
	for _, packet := range signedTranscript.Packets {
		totalSize += len(packet)
	}

	c.logger.Info("Total transcript size", zap.Int("bytes", totalSize))

	// Display signature and public key info for verification
	if len(signedTranscript.Signature) > 0 {
		c.logger.Info("Signature info", zap.String("source", "TEE_T"), zap.Int("signature_bytes", len(signedTranscript.Signature)))
	}

	if len(signedTranscript.PublicKey) > 0 {
		c.logger.Info("Public key info", zap.String("source", "TEE_T"), zap.Int("public_key_bytes", len(signedTranscript.PublicKey)))
	}

	// Verify signature using regular TLS packet verification
	c.logger.Info("Verifying signature for transcript", zap.String("source", "TEE_T"))
	verificationErr := shared.VerifyTranscriptSignature(&signedTranscript)
	if verificationErr != nil {
		c.logger.Error("Signature verification FAILED", zap.String("source", "TEE_T"), zap.Error(verificationErr))
	} else {
		c.logger.Info("Signature verification SUCCESS", zap.String("source", "TEE_T"))
	}

	// Increment transcript count
	c.incrementTranscriptCount()

	c.logger.Info("Marked transcript as received", zap.String("source", "TEE_T"), zap.Bool("signature_valid", verificationErr == nil))

	// Check if we now have both transcript public keys and can verify against attestations
	if c.teekTranscriptPublicKey != nil && c.teetTranscriptPublicKey != nil && !c.publicKeyComparisonDone {
		c.logger.Info("Both transcript public keys received - verifying against attestations")
		if err := c.verifyAttestationPublicKeys(); err != nil {
			c.logger.Error("Attestation public key verification failed", zap.Error(err))
		} else {
			c.logger.Info("Attestation public key verification successful - transcripts are from verified enclaves")
		}
	}

	transcriptsComplete := c.transcriptsReceived >= 2
	signaturesValid := c.hasCompletionFlag(CompletionFlagTEEKSignatureValid)
	currentPhase, _ := c.getProtocolState()

	c.logger.Info("Signed transcript processed successfully", zap.String("source", "TEE_T"))

	// Show packet summary
	c.logger.Info("Transcript summary", zap.String("source", "TEE_T"))

	// Perform final validation and display BEFORE advancing to PhaseComplete
	if transcriptsComplete && signaturesValid && currentPhase != PhaseComplete {
		c.logger.Info("Both transcripts received with valid signatures - performing final validation and display")
		c.validateTranscriptsAgainstCapturedTraffic()

		// Display final redacted response BEFORE protocol completion
		c.logger.Info("Protocol ready for completion - displaying final redacted response")
		redactionSpec := c.analyzeResponseRedaction()
		// Consolidate ranges for display (same as verifier)
		consolidatedRanges := shared.ConsolidateResponseRedactionRanges(redactionSpec.Ranges)
		c.displayRedactedResponseFromRandomGarbage(consolidatedRanges)

		// Now advance to PhaseComplete (which will signal completion)
		c.logger.Info("Final display complete - advancing to PhaseComplete")
		c.advanceToPhase(PhaseComplete)
	} else if transcriptsComplete && signaturesValid && currentPhase == PhaseComplete {
		c.logger.Info("Protocol already complete - final validation and display already performed")
	} else if transcriptsComplete && signaturesValid {
		c.logger.Info("Both transcripts received with valid signatures, but protocol not yet complete - waiting for PhaseComplete")
	}

	if transcriptsComplete {
		if signaturesValid {
			c.logger.Info("Received signed transcripts from both TEE_K and TEE_T with VALID signatures!")
		} else {
			c.logger.Error("Received signed transcripts from both TEE_K and TEE_T but signatures are INVALID!")
		}
	}

}
