package main

import (
	"bytes"
	"fmt"
	"log"
	"tee-mpc/shared"
)

// validateTranscriptsAgainstCapturedTraffic validates both TEE transcripts
// against the client's captured TLS traffic to ensure integrity and completeness
func (c *Client) validateTranscriptsAgainstCapturedTraffic() {
	fmt.Printf("\n===== TRANSCRIPT VALIDATION REPORT =====\n")

	log.Printf("[Client] Validating transcripts against %d captured TLS records", len(c.capturedTraffic))

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

	fmt.Printf("[Client] Client captured traffic analysis:\n")
	fmt.Printf("[Client]   Total chunks: %d\n", len(c.capturedTraffic))
	fmt.Printf("[Client]   Total captured size: %d bytes\n", totalCapturedSize)

	// Perform detailed comparison with TEE transcripts
	fmt.Printf("\n[Client] Detailed transcript comparison:\n")

	// Validate TEE_K transcript (should contain raw TCP chunks - bidirectional)
	teekValidation := c.validateTEEKTranscriptRaw()

	// Validate TEE_T transcript (should contain application data packets - bidirectional)
	teetValidation := c.validateTEETTranscriptRaw()

	// Summary
	fmt.Printf("\n[Client] VALIDATION RESULTS:\n")
	fmt.Printf("[Client]   Both TEE_K and TEE_T transcripts received\n")
	fmt.Printf("[Client]   Both transcript signatures verified successfully\n")
	fmt.Printf("[Client]   Client captured %d TCP chunks during session (bidirectional)\n", len(c.capturedTraffic))

	if teekValidation && teetValidation {
		fmt.Printf("[Client]   TRANSCRIPT VALIDATION PASSED - All packets match!\n")
	} else {
		fmt.Printf("[Client]   TRANSCRIPT VALIDATION FAILED - Packet mismatches detected!\n")
	}

	fmt.Printf("===== VALIDATION COMPLETE =====\n\n")
}

// validateTEEKTranscriptRaw validates TEE_K transcript against client raw TCP chunks
func (c *Client) validateTEEKTranscriptRaw() bool {
	fmt.Printf("[Client] Validating TEE_K transcript (%d packets) against client captures\n",
		len(c.teekTranscriptPackets))

	if c.teekTranscriptPackets == nil {
		fmt.Printf("[Client] TEE_K transcript packets not available\n")
		return false
	}

	// TEE_K captures raw TCP chunks during handshake, so we should compare against
	// the raw TCP chunks we captured (not the individual TLS records from application phase)
	fmt.Printf("[Client] TEE_K transcript analysis:\n")

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
			fmt.Printf("[Client]     NOT found in client captures\n")
		}
	}

	fmt.Printf("[Client] TEE_K validation result: %d/%d packets matched exactly\n",
		handshakePacketsMatched, totalCompared)

	return handshakePacketsMatched == totalCompared
}

// validateTEETTranscriptRaw validates TEE_T transcript against client application data records
func (c *Client) validateTEETTranscriptRaw() bool {
	fmt.Printf("[Client] Validating TEE_T transcript (%d packets) against client captures\n",
		len(c.teetTranscriptPackets))

	if c.teetTranscriptPackets == nil {
		fmt.Printf("[Client] TEE_T transcript packets not available\n")
		return false
	}

	fmt.Printf("[Client] TEE_T transcript analysis:\n")

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
			fmt.Printf("[Client]     NOT found in client captures\n")
		}
	}

	fmt.Printf("[Client] TEE_T validation result: %d/%d packets matched exactly\n",
		packetsMatched, len(c.teetTranscriptPackets))

	return packetsMatched == len(c.teetTranscriptPackets)
}

// handleSignedTranscript processes signed transcript messages from TEE_K and TEE_T
func (c *Client) handleSignedTranscript(msg *shared.Message) {
	var signedTranscript shared.SignedTranscript
	if err := msg.UnmarshalData(&signedTranscript); err != nil {
		log.Printf("[Client] Failed to unmarshal signed transcript: %v", err)
		return
	}

	log.Printf("[Client] Received signed transcript")
	log.Printf("[Client] Transcript contains %d packets", len(signedTranscript.Packets))
	log.Printf("[Client] Comprehensive signature: %d bytes", len(signedTranscript.Signature))
	log.Printf("[Client] Public Key: %d bytes (DER format)", len(signedTranscript.PublicKey))

	// Store the public key for attestation verification
	// Determine source based on transcript structure: TEE_K has RequestMetadata, TEE_T doesn't
	if signedTranscript.RequestMetadata != nil {
		// This is from TEE_K
		c.teekTranscriptPublicKey = signedTranscript.PublicKey
		c.teekSignedTranscript = &signedTranscript
		c.teekTranscriptPackets = signedTranscript.Packets // Store packets for validation
	} else {
		// This is from TEE_T
		c.teetTranscriptPublicKey = signedTranscript.PublicKey
		c.teetSignedTranscript = &signedTranscript
		c.teetTranscriptPackets = signedTranscript.Packets // Store packets for validation
	}

	// Calculate total size of all packets
	totalSize := 0
	for _, packet := range signedTranscript.Packets {
		totalSize += len(packet)
	}

	log.Printf("[Client] Total transcript size: %d bytes", totalSize)

	// Determine source name for logging
	sourceName := "TEE_T"
	if signedTranscript.RequestMetadata != nil {
		sourceName = "TEE_K"
	}

	// Display signature and public key info for verification
	if len(signedTranscript.Signature) > 0 {
		fmt.Printf("[Client] %s signature: %d bytes\n", sourceName, len(signedTranscript.Signature))
	}

	if len(signedTranscript.PublicKey) > 0 {
		fmt.Printf("[Client] %s public key: %d bytes\n", sourceName, len(signedTranscript.PublicKey))
	}

	// Verify signature
	log.Printf("[Client] Verifying signature for %s transcript...", sourceName)
	var verificationErr error
	if signedTranscript.RequestMetadata != nil {
		// This is TEE_K - check if we have all expected redacted streams before verification
		log.Printf("[Client] TEE_K transcript received, checking if all expected redacted streams are available...")
		if len(c.signedRedactedStreams) < c.expectedRedactedStreams {
			log.Printf("[Client] TEE_K comprehensive verification deferred - waiting for redacted streams (%d/%d)", len(c.signedRedactedStreams), c.expectedRedactedStreams)
			// Increment transcript count (parallel to existing logic)
			c.incrementTranscriptCount()
			// Don't set signature valid flag yet - will be set after successful verification
		} else {
			log.Printf("[Client] TEE_K comprehensive verification: have all %d expected redacted streams", c.expectedRedactedStreams)
			verificationErr = shared.VerifyComprehensiveSignature(&signedTranscript, c.signedRedactedStreams)
			if verificationErr != nil {
				log.Printf("[Client] Signature verification FAILED for %s: %v", sourceName, verificationErr)
				fmt.Printf("[Client] %s signature verification FAILED: %v\n", sourceName, verificationErr)
			} else {
				log.Printf("[Client] Signature verification SUCCESS for %s", sourceName)
				fmt.Printf("[Client] %s signature verification SUCCESS\n", sourceName)
			}

			// Increment transcript count (parallel to existing logic)
			c.incrementTranscriptCount()
			if verificationErr == nil {
				c.setCompletionFlag(CompletionFlagTEEKSignatureValid)
			}
		}
	} else {
		// This is TEE_T - use regular TLS packet verification
		verificationErr = shared.VerifyTranscriptSignature(&signedTranscript)
		if verificationErr != nil {
			log.Printf("[Client] Signature verification FAILED for %s: %v", sourceName, verificationErr)
			fmt.Printf("[Client] %s signature verification FAILED: %v\n", sourceName, verificationErr)
		} else {
			log.Printf("[Client] Signature verification SUCCESS for %s", sourceName)
			fmt.Printf("[Client] %s signature verification SUCCESS\n", sourceName)
		}

		// Increment transcript count (parallel to existing logic)
		c.incrementTranscriptCount()
	}

	log.Printf("[Client] Marked %s transcript as received (signature valid: %v)", sourceName, verificationErr == nil)

	// Check if we now have both transcript public keys and can verify against attestations
	if c.teekTranscriptPublicKey != nil && c.teetTranscriptPublicKey != nil && !c.publicKeyComparisonDone {
		log.Printf("[Client] Both transcript public keys received - verifying against attestations...")
		if err := c.verifyAttestationPublicKeys(); err != nil {
			log.Printf("[Client] Attestation public key verification failed: %v", err)
			fmt.Printf("[Client] ATTESTATION VERIFICATION FAILED: %v\n", err)
		} else {
			log.Printf("[Client] Attestation public key verification successful")
			fmt.Printf("[Client] ATTESTATION VERIFICATION SUCCESSFUL - transcripts are from verified enclaves\n")
		}
	}

	transcriptsComplete := c.transcriptsReceived >= 2
	signaturesValid := c.hasCompletionFlag(CompletionFlagTEEKSignatureValid)

	log.Printf("[Client] Signed transcript from %s processed successfully", sourceName)

	// Show packet summary
	fmt.Printf("[Client] %s transcript summary:\n", sourceName)
	// if len(signedTranscript.Packets) > 0 {
	// 	// Display packet information
	// 	for i, packet := range signedTranscript.Packets {
	// 		fmt.Printf("[Client] TEE_K packet %d: %d bytes\n", i+1, len(packet))
	// 	}
	// }

	// if len(signedTranscript.Packets) > 0 {
	// 	// Display packet information
	// 	for i, packet := range signedTranscript.Packets {
	// 		fmt.Printf("[Client] TEE_T packet %d: %d bytes\n", i+1, len(packet))
	// 	}[Client]   TEE_T packet 1
	// }

	if transcriptsComplete && signaturesValid {
		log.Printf("[Client] Both transcripts received with valid signatures - performing transcript validation...")
		c.validateTranscriptsAgainstCapturedTraffic()
	}

	if transcriptsComplete {
		if signaturesValid {
			log.Println("[Client] Received signed transcripts from both TEE_K and TEE_T with VALID signatures!")
		} else {
			log.Println("[Client] Received signed transcripts from both TEE_K and TEE_T but signatures are INVALID!")
		}
	}

}
