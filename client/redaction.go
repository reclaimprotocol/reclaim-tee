package main

import (
	"fmt"
	"log"
	"tee-mpc/shared"
)

// handleRedactionVerification handles redaction verification responses from TEE_T
func (c *Client) handleRedactionVerification(msg *shared.Message) {
	log.Printf("[Client] Received redaction verification message")

	var verificationData shared.RedactionVerificationData
	if err := msg.UnmarshalData(&verificationData); err != nil {
		log.Printf("[Client] Failed to unmarshal redaction verification data: %v", err)
		return
	}

	if verificationData.Success {
		fmt.Println(" Redaction verification successful")
	} else {
		fmt.Println(" Redaction verification failed")
	}
}

// handleSignedRedactedDecryptionStream handles signed redacted decryption streams from TEE_K
func (c *Client) handleSignedRedactedDecryptionStream(msg *shared.Message) {
	var redactedStream shared.SignedRedactedDecryptionStream
	if err := msg.UnmarshalData(&redactedStream); err != nil {
		log.Printf("[Client] Failed to unmarshal redacted decryption stream: %v", err)
		return
	}

	log.Printf("[Client] Received redacted decryption stream for seq %d (%d bytes)",
		redactedStream.SeqNum, len(redactedStream.RedactedStream))

	// Add to collection for verification bundle
	c.signedRedactedStreams = append(c.signedRedactedStreams, redactedStream)

	// Only verify TEE_K signature when ALL expected redacted streams received
	if c.teekSignedTranscript != nil && !c.hasCompletionFlag(CompletionFlagTEEKSignatureValid) {
		if len(c.signedRedactedStreams) >= c.expectedRedactedStreams {
			log.Printf("[Client] Received all %d expected redacted streams, attempting TEE_K comprehensive signature verification", c.expectedRedactedStreams)
			verificationErr := shared.VerifyComprehensiveSignature(c.teekSignedTranscript, c.signedRedactedStreams)
			if verificationErr != nil {
				log.Printf("[Client] TEE_K signature verification FAILED: %v", verificationErr)
				fmt.Printf("[Client] TEE_K signature verification FAILED: %v\n", verificationErr)
			} else {
				log.Printf("[Client] TEE_K signature verification SUCCESS")
				fmt.Printf("[Client] TEE_K signature verification SUCCESS\n")
				c.setCompletionFlag(CompletionFlagTEEKSignatureValid)

				// *** NEW: Check if we can complete protocol (both transcripts + redacted streams ready) ***
				_, transcriptCount := c.getProtocolState()
				if transcriptCount >= 2 {
					log.Printf("[Client] Redacted streams processed AND both transcripts received - completing protocol")
					c.advanceToPhase(PhaseComplete)
				} else {
					log.Printf("[Client] Redacted streams processed but waiting for remaining transcripts...")
				}

				// *** NEW: Display redacted response now that all streams are processed ***
				log.Printf("[Client] All redacted streams received - displaying final redacted response")
				redactionSpec := c.analyzeResponseRedaction()
				c.displayRedactedResponseFromRanges(redactionSpec.Ranges)

				// Check if we can now proceed with full protocol completion
				// *** CLEANUP: Completion is now triggered automatically by phase transitions - removed redundant check ***
				// When both transcripts received + redacted streams processed, incrementTranscriptCount() → PhaseComplete

				// Check if we can now proceed with full protocol completion
				// *** CLEANUP: Replaced completion flags with phase-based logic ***
				transcriptsComplete := c.transcriptsReceived >= 2
				signaturesValid := c.hasCompletionFlag(CompletionFlagTEEKSignatureValid)

				if transcriptsComplete && signaturesValid {
					log.Printf("[Client] Both transcripts received with valid signatures - performing transcript validation...")
					c.validateTranscriptsAgainstCapturedTraffic()
					fmt.Printf("[Client] Received signed transcripts from both TEE_K and TEE_T with VALID signatures!")
				}
			}
		} else {
			log.Printf("[Client] Received redacted stream %d/%d - waiting for remaining streams before verification", len(c.signedRedactedStreams), c.expectedRedactedStreams)
		}
	}

	// Note: Individual stream signatures removed - using master signature verification

	// Apply redacted stream to ciphertext to get redacted plaintext
	c.responseContentMutex.Lock()
	ciphertext, exists := c.ciphertextBySeq[redactedStream.SeqNum]
	c.responseContentMutex.Unlock()

	if !exists {
		log.Printf("[Client] No ciphertext found for seq %d", redactedStream.SeqNum)
		return
	}

	if len(redactedStream.RedactedStream) != len(ciphertext) {
		log.Printf("[Client] Stream length mismatch for seq %d: stream=%d, ciphertext=%d",
			redactedStream.SeqNum, len(redactedStream.RedactedStream), len(ciphertext))
		return
	}

	// XOR ciphertext with redacted stream to get redacted plaintext
	redactedPlaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		redactedPlaintext[i] = ciphertext[i] ^ redactedStream.RedactedStream[i]
	}

	log.Printf("[Client] Generated redacted plaintext for seq %d (%d bytes)",
		redactedStream.SeqNum, len(redactedPlaintext))

	// Store the redacted plaintext and check if we are ready to print
	c.responseContentMutex.Lock()
	c.redactedPlaintextBySeq[redactedStream.SeqNum] = redactedPlaintext
	c.responseContentMutex.Unlock()

	// *** CLEANUP: Removed redundant checkProtocolCompletion - phase transitions handle completion automatically ***
	// Completion triggered automatically when: transcriptsReceived >= 2 + redacted streams processed
}
