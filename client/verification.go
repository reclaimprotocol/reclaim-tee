package main

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"tee-mpc/shared"
)

// handleBatchedTagVerifications handles batched tag verification results
func (c *Client) handleBatchedTagVerifications(msg *shared.Message) {
	var batchedVerification shared.BatchedTagVerificationData
	if err := msg.UnmarshalData(&batchedVerification); err != nil {
		log.Printf("[Client] Failed to unmarshal batched tag verification: %v", err)
		return
	}

	log.Printf("[Client] Received batch tag verification for %d responses", len(batchedVerification.Verifications))

	// Process each verification result
	successCount := 0
	for _, verification := range batchedVerification.Verifications {
		if verification.Success {
			successCount++
		} else {
			log.Printf("[Client] Response tag verification failed (seq=%d): %s", verification.SeqNum, verification.Message)
		}
	}

	log.Printf("[Client] Processed %d tag verifications (%d successful)", len(batchedVerification.Verifications), successCount)
}

// handleBatchedDecryptionStreams handles batched decryption streams
func (c *Client) handleBatchedDecryptionStreams(msg *shared.Message) {
	var batchedStreams shared.BatchedDecryptionStreamData
	if err := msg.UnmarshalData(&batchedStreams); err != nil {
		log.Printf("[Client] Failed to unmarshal batched decryption streams: %v", err)
		return
	}

	log.Printf("[Client] Processing batch of %d decryption streams", len(batchedStreams.DecryptionStreams))

	if len(batchedStreams.DecryptionStreams) == 0 {
		c.checkProtocolCompletion("batched decryption streams processed (empty)")
		return
	}

	// Process each decryption stream
	for _, streamData := range batchedStreams.DecryptionStreams {

		// Store decryption stream by sequence number (preserve existing logic)
		c.responseContentMutex.Lock()
		c.decryptionStreamBySeq[streamData.SeqNum] = streamData.DecryptionStream
		c.responseContentMutex.Unlock()

		// Decrypt and store redacted plaintext (preserve existing logic)
		if ciphertext, exists := c.ciphertextBySeq[streamData.SeqNum]; exists {
			redactedPlaintext := make([]byte, len(ciphertext))
			for j := 0; j < len(ciphertext); j++ {
				redactedPlaintext[j] = ciphertext[j] ^ streamData.DecryptionStream[j]
			}

			// *** SIMPLIFIED: Minimize mutex usage ***
			c.responseContentMutex.Lock()

			// *** CRITICAL: Initialize maps if they're nil to prevent panic ***
			if c.redactedPlaintextBySeq == nil {
				c.redactedPlaintextBySeq = make(map[uint64][]byte)
			}
			if c.responseContentBySeq == nil {
				c.responseContentBySeq = make(map[uint64][]byte)
			}
			if c.recordTypeBySeq == nil {
				c.recordTypeBySeq = make(map[uint64]byte)
			}

			c.redactedPlaintextBySeq[streamData.SeqNum] = redactedPlaintext
			c.responseContentBySeq[streamData.SeqNum] = redactedPlaintext
			c.responseContentMutex.Unlock()

			// Processing complete for this stream
		} else {
			log.Printf("[Client] No ciphertext found for seq=%d", streamData.SeqNum)
		}
	}

	// Reconstruct HTTP response if we haven't already
	if !c.responseReconstructed {
		c.reconstructHTTPResponseFromDecryptedData()
		log.Printf("[Client] HTTP response reconstruction completed, callback executed")
	}

	// *** NEW: Track batch decryption received alongside existing logic ***
	c.setBatchDecryptionReceived()

	// *** NEW: Advance to redaction sending phase (parallel to existing logic) ***
	c.advanceToPhase(PhaseSendingRedaction)

	// *** NEW: Automatically send redaction spec when entering redaction phase ***
	log.Printf("[Client] Entering redaction phase - automatically sending redaction specification")
	if err := c.sendRedactionSpec(); err != nil {
		log.Printf("[Client] Failed to send redaction spec: %v", err)
	}

	// Trigger completion check after callback execution
	c.checkProtocolCompletion("batched decryption streams processed")
}

// reconstructHTTPResponseFromDecryptedData reconstructs HTTP response from all decrypted response data
func (c *Client) reconstructHTTPResponseFromDecryptedData() {
	c.responseContentMutex.Lock()
	defer c.responseContentMutex.Unlock()

	if len(c.redactedPlaintextBySeq) == 0 {
		fmt.Printf("[Client] No decrypted response data to reconstruct\n")
		return
	}

	// Sort sequence numbers and concatenate response data
	var seqNums []uint64
	for seqNum := range c.redactedPlaintextBySeq {
		seqNums = append(seqNums, seqNum)
	}
	sort.Slice(seqNums, func(i, j int) bool { return seqNums[i] < seqNums[j] })

	var fullResponse []byte
	for _, seqNum := range seqNums {
		if seqNum > 0 { // Skip handshake sequences (seq 0)
			plaintext := c.redactedPlaintextBySeq[seqNum]

			// Use stored TLS record type instead of extracting from plaintext
			if len(plaintext) > 0 {
				// Get the TLS record type that was stored during processing
				recordType, hasRecordType := c.recordTypeBySeq[seqNum]
				if !hasRecordType {
					// Missing record type is a critical error in protocol state
					c.terminateConnectionWithError("Missing record type for sequence", fmt.Errorf("no record type found for seq %d", seqNum))
					return
				}

				// For TLS 1.3, we need to remove padding and extract content type
				var actualContent []byte
				var contentType byte

				if c.handshakeDisclosure != nil && c.isTLS12CipherSuite(c.handshakeDisclosure.CipherSuite) {
					// TLS 1.2: No inner content type, use record type
					actualContent = plaintext
					contentType = recordType
				} else {
					// TLS 1.3: Remove padding and get inner content type
					actualContent, contentType = c.removeTLSPadding(plaintext)
				}

				// Only include application data (0x17), skip handshake (0x16) and alerts (0x15)
				if contentType == 0x17 && len(actualContent) > 0 {
					fullResponse = append(fullResponse, actualContent...)
				}
			}
		}
	}

	log.Printf("[Client] Reconstructed HTTP response (%d bytes total)", len(fullResponse))

	// Parse HTTP response and set success flags
	if len(fullResponse) > 0 {
		responseStr := string(fullResponse)

		// Search for HTTP status line anywhere in the response, not just at the beginning
		// This handles cases where redacted session tickets prefix the response with asterisks
		httpIndex := strings.Index(responseStr, "HTTP/1.1 ")
		if httpIndex == -1 {
			httpIndex = strings.Index(responseStr, "HTTP/1.0 ")
		}
		if httpIndex == -1 {
			httpIndex = strings.Index(responseStr, "HTTP/2 ")
		}

		if httpIndex != -1 {
			log.Printf("[Client] HTTP response reconstruction successful at offset %d", httpIndex)

			// Extract the actual HTTP response
			actualHTTPResponse := responseStr[httpIndex:]

			// If there was data before the HTTP response, log it
			if httpIndex > 0 {
				prefixData := responseStr[:httpIndex]
				previewData := prefixData[:min(100, len(prefixData))] // Show more data but collapse asterisks
				log.Printf("[Client] Found %d bytes before HTTP response (likely redacted session tickets): %q",
					httpIndex, collapseAsterisks(previewData))
			}

			// Set success flags for results reporting
			c.responseProcessingMutex.Lock()
			c.responseProcessingSuccessful = true
			c.reconstructedResponseSize = len(actualHTTPResponse)
			c.responseProcessingMutex.Unlock()

			// Call response callback now that we have complete HTTP response
			if c.responseCallback != nil && len(c.lastRedactionRanges) == 0 {
				log.Printf("[Client] Calling response callback with complete HTTP response (%d bytes)", len(actualHTTPResponse))

				// Parse the HTTP response and call the callback
				httpResponse := c.parseHTTPResponse([]byte(actualHTTPResponse))
				result, err := c.responseCallback.OnResponseReceived(httpResponse)

				if err != nil {
					fmt.Printf("[Client] Response callback error: %v\n", err)
				} else if result != nil {
					fmt.Printf("[Client] Response callback completed with %d redaction ranges and %d proof claims\n",
						len(result.RedactionRanges), len(result.ProofClaims))

					// Store results for use in redaction spec generation
					c.lastProofClaims = result.ProofClaims
					c.lastRedactionRanges = result.RedactionRanges
					c.lastRedactedResponse = result.RedactedBody
					c.lastResponseData = httpResponse

					fmt.Printf("[Client] Stored callback results: %d ranges, %d claims, %d bytes redacted response\n",
						len(result.RedactionRanges), len(result.ProofClaims), len(result.RedactedBody))

					// Log redaction ranges
					for i, r := range result.RedactionRanges {
						fmt.Printf("[Client] Redaction range %d: start=%d, length=%d, type=%s\n",
							i+1, r.Start, r.Length, r.Type)
					}

				}
			} else if c.responseCallback != nil {
				fmt.Printf("[Client] Response callback already executed (cached ranges: %d)\n", len(c.lastRedactionRanges))
			}

			// Display the raw HTTP response (redaction will be handled at TLS record level)
			previewLen := HTTPResponsePreviewLength
			if len(actualHTTPResponse) < previewLen {
				previewLen = len(actualHTTPResponse)
			}
			fmt.Printf("[Client] Raw HTTP response (%d bytes) preview: %s\n", len(actualHTTPResponse), actualHTTPResponse[:previewLen])

			// Set success flags
			log.Printf("[Client] Response processing successful (%d bytes)", len(actualHTTPResponse))
		} else {
			previewLen := 100
			if len(responseStr) < previewLen {
				previewLen = len(responseStr)
			}
			log.Printf("[Client] Warning - reconstructed response doesn't look like HTTP: %q", responseStr[:previewLen])
		}
	}
}
