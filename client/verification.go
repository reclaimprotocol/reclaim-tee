package client

import (
	"sort"
	"strings"
	"tee-mpc/minitls"
	"tee-mpc/shared"

	"go.uber.org/zap"
)

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

		// Store decryption stream by sequence number
		c.responseContentMutex.Lock()
		c.decryptionStreamBySeq[streamData.SeqNum] = streamData.DecryptionStream
		c.responseContentMutex.Unlock()

		// Decrypt and parse plaintext
		if ciphertext, exists := c.ciphertextBySeq[streamData.SeqNum]; exists {
			plaintext := make([]byte, len(ciphertext))
			for j := 0; j < len(ciphertext); j++ {
				plaintext[j] = ciphertext[j] ^ streamData.DecryptionStream[j]
			}

			c.responseContentMutex.Lock()

			// Parse TLS padding once and store all data
			actualContent, contentType := c.removeTLSPadding(plaintext)

			c.ciphertextBySeq[streamData.SeqNum] = c.ciphertextBySeq[streamData.SeqNum][:len(actualContent)] // !!! Strip content type byte (and padding if exists)

			c.parsedResponseBySeq[streamData.SeqNum] = &TLSResponseData{
				ActualContent: actualContent,
				ContentType:   contentType,
			}

			c.responseContentMutex.Unlock()

		} else {
			c.logger.Error("No ciphertext found for sequence", zap.Uint64("seq_num", streamData.SeqNum))
		}
	}

	// Reconstruct HTTP response if we haven't already
	if !c.responseReconstructed {
		c.reconstructHTTPResponseFromDecryptedData()

		// Check if connection was terminated during reconstruction (e.g., non-2XX response)
		if c.wsConn == nil {
			c.logger.Info("Connection terminated during response reconstruction - stopping processing")
			return
		}

		c.logger.Info("HTTP response reconstruction completed, callback executed")
	}

	// continue to redaction
	c.advanceToPhase(PhaseSendingRedaction)

	c.logger.Info("Entering redaction phase - automatically sending redaction specification")
	if err := c.sendRedactionSpec(); err != nil {
		c.logger.Error("Failed to send redaction spec", zap.Error(err))
		c.terminateConnectionWithError("Failed to send redaction spec", err)
		return
	}
}

// reconstructHTTPResponseFromDecryptedData reconstructs HTTP response from all parsed response data
func (c *Client) reconstructHTTPResponseFromDecryptedData() {
	c.responseContentMutex.Lock()
	defer c.responseContentMutex.Unlock()

	if len(c.parsedResponseBySeq) == 0 {
		c.logger.Warn("No parsed response data to reconstruct")
		return
	}

	// Sort sequence numbers and concatenate response data
	var seqNums []uint64
	for seqNum := range c.parsedResponseBySeq {
		seqNums = append(seqNums, seqNum)
	}
	sort.Slice(seqNums, func(i, j int) bool { return seqNums[i] < seqNums[j] })

	var fullResponse []byte
	for _, seqNum := range seqNums {
		if seqNum > 0 { // Skip handshake sequences (seq 0)
			parsed := c.parsedResponseBySeq[seqNum]

			// Only include application data, skip handshake and alerts
			if parsed.ContentType == minitls.RecordTypeApplicationData && len(parsed.ActualContent) > 0 {
				fullResponse = append(fullResponse, parsed.ActualContent...)
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

			// Set success flags for results reporting
			c.responseProcessingSuccessful = true
			c.reconstructedResponseSize = len(actualHTTPResponse)

			// Parse the HTTP response and store it for later use
			httpResponse := c.parseHTTPResponse([]byte(actualHTTPResponse))
			c.lastResponseData = httpResponse

			// Get automatic response redactions now that we have complete HTTP response
			// if len(c.lastRedactionRanges) == 0 {
			// 	c.logger.Info("Getting automatic response redactions", zap.Int("response_bytes", len(actualHTTPResponse)))
			//
			// 	ranges, err := c.getResponseRedactions(httpResponse)
			//
			// 	if err != nil {
			// 		c.terminateConnectionWithError("Failed to get response redactions", err)
			// 		return
			// 	} else {
			// 		c.logger.Info("Automatic response redactions generated",
			// 			zap.Int("redaction_ranges", len(ranges)))
			//
			// 		// Store results for use in redaction spec generation
			// 		c.lastRedactionRanges = ranges
			//
			// 		c.logger.Info("Stored automatic redaction results",
			// 			zap.Int("ranges_count", len(ranges)))
			// 	}
			// } else {
			// 	c.logger.Info("Response redactions already generated", zap.Int("cached_ranges", len(c.lastRedactionRanges)))
			// }

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
