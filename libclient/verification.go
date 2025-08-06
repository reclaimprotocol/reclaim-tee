package clientlib

import (
	"fmt"
	"sort"
	"strings"
	"tee-mpc/shared"

	"go.uber.org/zap"
)

// handleBatchedTagVerifications handles batched tag verification results
// Note: This is now only called by TEE_K handler (if at all) - TEE_T no longer sends these to client
func (c *Client) handleBatchedTagVerifications(msg *shared.Message) {
	var batchedVerification shared.BatchedTagVerificationData
	if err := msg.UnmarshalData(&batchedVerification); err != nil {
		c.logger.Error("Failed to unmarshal batched tag verification", zap.Error(err))
		return
	}

	if batchedVerification.AllSuccessful {
		// All verifications passed - simple success message
		c.logger.Info("All tag verifications successful", zap.Int("total_count", batchedVerification.TotalCount))
	} else {
		// Some failures - process detailed results
		c.logger.Warn("Tag verification batch has failures",
			zap.Int("total_count", batchedVerification.TotalCount),
			zap.Int("failed_count", len(batchedVerification.Verifications)))

		for _, verification := range batchedVerification.Verifications {
			c.logger.Error("Response tag verification failed",
				zap.Uint64("seq_num", verification.SeqNum),
				zap.String("message", verification.Message))
		}
	}
}

// handleBatchedDecryptionStreams handles batched decryption streams
func (c *Client) handleBatchedDecryptionStreams(msg *shared.Message) {
	var batchedStreams shared.BatchedDecryptionStreamData
	if err := msg.UnmarshalData(&batchedStreams); err != nil {
		c.logger.Error("Failed to unmarshal batched decryption streams", zap.Error(err))
		return
	}

	c.logger.Info("Processing batch of decryption streams", zap.Int("streams_count", len(batchedStreams.DecryptionStreams)))

	if len(batchedStreams.DecryptionStreams) == 0 {
		c.logger.Info("No batched decryption streams to process")
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

			c.responseContentMutex.Lock()

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

			// Check if this is an Alert record and parse the decrypted alert
			if recordType, exists := c.recordTypeBySeq[streamData.SeqNum]; exists && recordType == 0x15 {
				c.responseContentMutex.Unlock()
				c.parseDecryptedAlert(streamData.SeqNum, redactedPlaintext)
				c.responseContentMutex.Lock()
			}

			c.responseContentMutex.Unlock()

			// Processing complete for this stream
		} else {
			c.logger.Error("No ciphertext found for sequence", zap.Uint64("seq_num", streamData.SeqNum))
		}
	}

	// Reconstruct HTTP response if we haven't already
	if !c.responseReconstructed {
		c.reconstructHTTPResponseFromDecryptedData()
		c.logger.Info("HTTP response reconstruction completed, callback executed")
	}

	c.setBatchDecryptionReceived()

	// Check if we're in 2-phase mode
	if c.twoPhaseMode {
		c.logger.Info("2-phase mode: Pausing after response decryption, waiting for redaction ranges")
		c.advanceToPhase(PhaseWaitingForRedactionRanges)
		c.phase1Completed = true
		close(c.phase1Completion)
		return
	}

	// Normal single-phase mode: continue to redaction
	c.advanceToPhase(PhaseSendingRedaction)

	c.logger.Info("Entering redaction phase - automatically sending redaction specification")
	if err := c.sendRedactionSpec(); err != nil {
		c.logger.Error("Failed to send redaction spec", zap.Error(err))
	}

}

// reconstructHTTPResponseFromDecryptedData reconstructs HTTP response from all decrypted response data
func (c *Client) reconstructHTTPResponseFromDecryptedData() {
	c.responseContentMutex.Lock()
	defer c.responseContentMutex.Unlock()

	if len(c.redactedPlaintextBySeq) == 0 {
		c.logger.Warn("No decrypted response data to reconstruct")
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

				if c.handshakeDisclosure != nil && shared.IsTLS12CipherSuite(c.handshakeDisclosure.CipherSuite) {
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

	c.logger.Info("Reconstructed HTTP response", zap.Int("total_bytes", len(fullResponse)))

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
			c.logger.Info("HTTP response reconstruction successful", zap.Int("offset", httpIndex))

			// Extract the actual HTTP response
			actualHTTPResponse := responseStr[httpIndex:]

			// If there was data before the HTTP response, log it
			if httpIndex > 0 {
				prefixData := responseStr[:httpIndex]
				previewData := prefixData[:min(100, len(prefixData))] // Show more data but collapse asterisks
				c.logger.Info("Found bytes before HTTP response (likely redacted session tickets)",
					zap.Int("bytes_count", httpIndex),
					zap.String("preview", collapseAsterisks(previewData)))
			}

			// Set success flags for results reporting
			c.responseProcessingSuccessful = true
			c.reconstructedResponseSize = len(actualHTTPResponse)
			c.httpResponseReceived = true

			// Parse the HTTP response and store it for later use
			httpResponse := c.parseHTTPResponse([]byte(actualHTTPResponse))
			c.lastResponseData = httpResponse

			// Call response callback now that we have complete HTTP response
			if c.responseCallback != nil && len(c.lastRedactionRanges) == 0 {
				c.logger.Info("Calling response callback with complete HTTP response", zap.Int("response_bytes", len(actualHTTPResponse)))

				result, err := c.responseCallback.OnResponseReceived(httpResponse)

				if err != nil {
					c.logger.Error("Response callback error", zap.Error(err))
				} else if result != nil {
					c.logger.Info("Response callback completed",
						zap.Int("redaction_ranges", len(result.RedactionRanges)))

					// Store results for use in redaction spec generation
					c.lastRedactionRanges = result.RedactionRanges
					c.lastRedactedResponse = result.RedactedBody

					c.logger.Info("Stored callback results",
						zap.Int("ranges_count", len(result.RedactionRanges)),
						zap.Int("redacted_response_bytes", len(result.RedactedBody)))

					// Log redaction ranges
					// for i, r := range result.RedactionRanges {
					// 	fmt.Printf("[Client] Redaction range %d: start=%d, length=%d, type=%s\n",
					// 		i+1, r.Start, r.Length, r.Type)
					// }

				}
			} else if c.responseCallback != nil {
				c.logger.Info("Response callback already executed", zap.Int("cached_ranges", len(c.lastRedactionRanges)))
			} else {
				// In 2-phase mode, store the response data for later retrieval
				c.logger.Info("2-phase mode: Response data stored for later retrieval", zap.Int("response_bytes", len(actualHTTPResponse)))
			}

			// Display the raw HTTP response (redaction will be handled at TLS record level)
			previewLen := HTTPResponsePreviewLength
			if len(actualHTTPResponse) < previewLen {
				previewLen = len(actualHTTPResponse)
			}
			c.logger.Info("Raw HTTP response preview",
				zap.Int("total_bytes", len(actualHTTPResponse)),
				zap.String("preview", actualHTTPResponse[:previewLen]))

			// Set success flags
			c.logger.Info("Response processing successful", zap.Int("response_bytes", len(actualHTTPResponse)))
		} else {
			previewLen := 100
			if len(responseStr) < previewLen {
				previewLen = len(responseStr)
			}
			c.logger.Warn("Reconstructed response doesn't look like HTTP", zap.String("preview", responseStr[:previewLen]))
		}
	}
}
