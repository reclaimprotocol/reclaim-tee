package clientlib

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"tee-mpc/shared"

	"go.uber.org/zap"
)

// handleRedactionVerification handles redaction verification responses from TEE_T
func (c *Client) handleRedactionVerification(msg *shared.Message) {
	c.logger.Info("Received redaction verification message")

	var verificationData shared.RedactionVerificationData
	if err := msg.UnmarshalData(&verificationData); err != nil {
		c.logger.Error("Failed to unmarshal redaction verification data", zap.Error(err))
		return
	}

	if verificationData.Success {
		c.logger.Info("Redaction verification successful")
	} else {
		c.logger.Error("Redaction verification failed")
	}
}

// analyzeHTTPResponseRedactionWithBytes identifies sensitive parts within HTTP response content and calculates redaction bytes (no Type field)
func (c *Client) analyzeHTTPResponseRedactionWithBytes(httpData []byte, baseOffset int, ciphertext []byte) []shared.ResponseRedactionRange {
	// Simple implementation - return empty ranges for now
	// This can be enhanced later with proper response redaction logic
	return []shared.ResponseRedactionRange{}
}

// analyzeResponseRedaction analyzes all response content to identify redaction ranges and calculate redaction bytes
func (c *Client) analyzeResponseRedaction() shared.ResponseRedactionSpec {
	c.logger.Info("Analyzing response content for redaction ranges")

	c.responseContentMutex.Lock()
	defer c.responseContentMutex.Unlock()

	var redactionRanges []shared.ResponseRedactionRange
	totalOffset := 0

	// Iterate over map keys in sorted order to guarantee correctness
	// 1. Get all sequence numbers (keys) from the map.
	keys := make([]int, 0, len(c.responseContentBySeq))
	for k := range c.responseContentBySeq {
		keys = append(keys, int(k))
	}
	// 2. Sort the keys numerically.
	sort.Ints(keys)

	// Collect all HTTP application data first, then analyze as a whole
	var allHTTPContent []byte
	var httpContentMappings []struct {
		seqNum     uint64
		httpPos    int // Position within allHTTPContent
		tlsOffset  int // Position within TLS stream
		length     int
		ciphertext []byte
	}

	// 3. First pass: collect all HTTP application data and build mappings
	for _, k := range keys {
		seqNum := uint64(k)
		content := c.responseContentBySeq[seqNum]

		// Get corresponding ciphertext for redaction byte calculation
		ciphertext, ciphertextExists := c.ciphertextBySeq[seqNum]
		if !ciphertextExists {
			c.logger.Warn("No ciphertext found for sequence", zap.Uint64("sequence", seqNum))
			totalOffset += len(content)
			continue
		}

		// Correctly handle content/type separation and offset calculation
		// 1. Separate actual content from its single-byte type identifier
		actualContent, contentType := c.removeTLSPadding(content)

		switch contentType {
		case 0x16: // Handshake message - likely NewSessionTicket
			if len(actualContent) >= 4 && actualContent[0] == 0x04 { // NewSessionTicket
				c.logger.Info("Redacting NewSessionTicket",
					zap.Int("start_offset", totalOffset),
					zap.Int("end_offset", totalOffset+len(actualContent)-1))

				redactionRanges = append(redactionRanges, shared.ResponseRedactionRange{
					Start:  totalOffset,
					Length: len(content), // Cover full record including padding
				})

				c.logger.Info("Session ticket redaction", zap.Int("length", len(actualContent)))
			}

		case 0x17: // ApplicationData - HTTP response
			// Collect this HTTP content for combined analysis
			httpContentMappings = append(httpContentMappings, struct {
				seqNum     uint64
				httpPos    int
				tlsOffset  int
				length     int
				ciphertext []byte
			}{
				seqNum:     seqNum,
				httpPos:    len(allHTTPContent),
				tlsOffset:  totalOffset,
				length:     len(actualContent),
				ciphertext: ciphertext,
			})

			// Append this HTTP content to the growing buffer
			allHTTPContent = append(allHTTPContent, actualContent...)

		case 0x15: // TLS Alert - keep visible
			c.logger.Info("Found TLS alert - keeping visible", zap.Int("offset", totalOffset), zap.Uint64("sequence", seqNum))

		default:
			// Unknown content type - no specific handling needed
		}

		totalOffset += len(content)
	}

	// Analyze all HTTP content as a single unit if we collected any
	if len(allHTTPContent) > 0 && len(httpContentMappings) > 0 {
		c.logger.Info("Analyzing combined HTTP content", zap.Int("content_bytes", len(allHTTPContent)), zap.Int("tls_records", len(httpContentMappings)))

		var combinedHTTPRanges []shared.ResponseRedactionRange

		if len(c.lastRedactionRanges) > 0 {
			c.logger.Info("Using cached redaction ranges from response callback", zap.Int("ranges_count", len(c.lastRedactionRanges)))

			// Use cached ResponseRedactionRange directly
			combinedHTTPRanges = c.lastRedactionRanges
			// log.Printf("[Client] Using cached range: [%d:%d]", r.Start, r.Start+r.Length-1)
		} else {
			c.logger.Info("No cached redaction ranges available, using automatic analysis")

			// Use response-specific redaction analysis (no Type field needed)
			combinedHTTPRanges = c.analyzeHTTPResponseRedactionWithBytes(allHTTPContent, 0, nil)
		}

		// Now map these ranges back to the original TLS record positions and calculate proper redaction bytes
		for _, httpRange := range combinedHTTPRanges {
			// Find which TLS record(s) this range spans
			rangeStart := httpRange.Start
			rangeEnd := httpRange.Start + httpRange.Length

			var thisRangeMappings []struct {
				mapping *struct {
					seqNum     uint64
					httpPos    int
					tlsOffset  int
					length     int
					ciphertext []byte
				}
				overlapStart    int
				overlapEnd      int
				localStart      int
				overlapLength   int
				actualTLSOffset int
			}

			// First pass: collect all mappings for this HTTP range
			for i := range httpContentMappings {
				mapping := &httpContentMappings[i]
				mappingStart := mapping.httpPos
				mappingEnd := mapping.httpPos + mapping.length

				// Check if this mapping overlaps with the HTTP range
				overlapStart := max(rangeStart, mappingStart)
				overlapEnd := min(rangeEnd, mappingEnd)

				if overlapStart < overlapEnd {
					localStart := overlapStart - mappingStart // Position within this HTTP record's content
					overlapLength := overlapEnd - overlapStart
					actualTLSOffset := mapping.tlsOffset + localStart

					thisRangeMappings = append(thisRangeMappings, struct {
						mapping *struct {
							seqNum     uint64
							httpPos    int
							tlsOffset  int
							length     int
							ciphertext []byte
						}
						overlapStart    int
						overlapEnd      int
						localStart      int
						overlapLength   int
						actualTLSOffset int
					}{
						mapping:         mapping,
						overlapStart:    overlapStart,
						overlapEnd:      overlapEnd,
						localStart:      localStart,
						overlapLength:   overlapLength,
						actualTLSOffset: actualTLSOffset,
					})
				}
			}

			// Second pass: create redaction ranges, extending to fill gaps between consecutive records
			for i, m := range thisRangeMappings {
				overlapLength := m.overlapLength

				// If this is not the last mapping and the next mapping is consecutive, extend to fill gap
				if i < len(thisRangeMappings)-1 {
					nextM := thisRangeMappings[i+1]
					currentEnd := m.actualTLSOffset + m.overlapLength
					gap := nextM.actualTLSOffset - currentEnd

					if gap == 1 {
						// Fill the 1-byte gap
						overlapLength += 1
					}
				}

				redactionRanges = append(redactionRanges, shared.ResponseRedactionRange{
					Start:  m.actualTLSOffset,
					Length: overlapLength,
				})
			}
		}
	}

	spec := shared.ResponseRedactionSpec{
		Ranges:                     redactionRanges,
		AlwaysRedactSessionTickets: true,
	}

	c.logger.Info("Generated redaction spec", zap.Int("ranges_count", len(redactionRanges)))
	// for i, r := range redactionRanges {
	// 	log.Printf("[Client] Range %d: [%d:%d] (%d redaction bytes)", i+1, r.Start, r.Start+r.Length-1, len(r.RedactionBytes))
	// }

	return spec
}

// applyRedactionRangesToContent applies redaction ranges to a content segment
func (c *Client) applyRedactionRangesToContent(content []byte, baseOffset int, ranges []shared.ResponseRedactionRange) []byte {
	result := make([]byte, len(content))
	copy(result, content)

	// Apply each redaction range that overlaps with this content
	for _, r := range ranges {
		rangeStart := r.Start
		rangeEnd := r.Start + r.Length
		contentStart := baseOffset
		contentEnd := baseOffset + len(content)

		// Check for overlap
		overlapStart := max(rangeStart, contentStart)
		overlapEnd := min(rangeEnd, contentEnd)

		if overlapStart < overlapEnd {
			// Apply redaction (replace with asterisks)
			localStart := overlapStart - contentStart
			localEnd := overlapEnd - contentStart
			for i := localStart; i < localEnd; i++ {
				result[i] = '*'
			}
		}
	}

	return result
}

// sendRedactionSpec sends redaction specification to TEE_K
func (c *Client) sendRedactionSpec() error {
	c.logger.Info("Generating and sending redaction specification to TEE_K")

	// Analyze response content to identify redaction ranges
	redactionSpec := c.analyzeResponseRedaction()

	// Consolidate ranges to reduce transmission overhead
	originalCount := len(redactionSpec.Ranges)
	redactionSpec.Ranges = shared.ConsolidateResponseRedactionRanges(redactionSpec.Ranges)
	consolidatedCount := len(redactionSpec.Ranges)

	c.logger.Info("Consolidated redaction ranges",
		zap.Int("original_count", originalCount),
		zap.Int("consolidated_count", consolidatedCount),
		zap.Float64("reduction_percent", float64(originalCount-consolidatedCount)/float64(originalCount)*100))

	// Send redaction spec to TEE_K
	msg := shared.CreateSessionMessage(shared.MsgRedactionSpec, c.sessionID, redactionSpec)
	if err := c.wsConn.WriteJSON(msg); err != nil {
		return fmt.Errorf("failed to send redaction spec to TEE_K: %v", err)
	}

	c.logger.Info("Sent redaction specification to TEE_K", zap.Int("consolidated_ranges", len(redactionSpec.Ranges)))

	c.logger.Info("Redaction specification sent successfully")

	c.advanceToPhase(PhaseReceivingRedacted)

	// Protocol specification: TEE_K will send 'finished' to TEE_T after processing redaction specification
	// No client finished messages are required in single session mode
	c.logger.Info("Entering redacted receiving phase - waiting for TEE_K to send 'finished' to TEE_T")

	return nil
}

// displayRedactedResponseFromRanges immediately displays the redacted response using calculated ranges
func (c *Client) displayRedactedResponseFromRanges(ranges []shared.ResponseRedactionRange) {
	c.responseContentMutex.Lock()
	defer c.responseContentMutex.Unlock()

	// Guard against multiple displays
	if c.fullRedactedResponse != nil {
		c.logger.Info("Redacted response already displayed, skipping")
		return
	}

	// Build the complete response in sequence order
	keys := make([]int, 0, len(c.responseContentBySeq))
	for k := range c.responseContentBySeq {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)

	var fullResponse strings.Builder
	totalOffset := 0

	for _, k := range keys {
		seqNum := uint64(k)
		content := c.responseContentBySeq[seqNum]

		// Apply ranges to FULL content (like verifier does)
		redactedContent := c.applyRedactionRangesToContent(content, totalOffset, ranges)

		// But only display the actual HTTP content part (remove TLS padding)
		actualRedactedContent, _ := c.removeTLSPadding(redactedContent)
		fullResponse.Write(actualRedactedContent)

		// Use same offset calculation as range generation
		totalOffset += len(content) // Full content including TLS padding
	}

	redactedResponse := fullResponse.String()
	c.fullRedactedResponse = []byte(redactedResponse)

	// Display the redacted response immediately with collapsed asterisks
	c.logger.Info("Displaying final redacted response from ranges")
	fmt.Printf("\n\n--- FINAL REDACTED RESPONSE (FROM RANGES) ---\n%s\n--- END REDACTED RESPONSE ---\n\n",
		collapseAsterisks(string(c.fullRedactedResponse)))

	c.logger.Info("Displayed redacted response from ranges", zap.Int("bytes", len(redactedResponse)))
}

// displayRedactedResponseFromRandomGarbage displays the redacted response by replacing random garbage with asterisks
func (c *Client) displayRedactedResponseFromRandomGarbage(ranges []shared.ResponseRedactionRange) {
	c.responseContentMutex.Lock()
	defer c.responseContentMutex.Unlock()

	// Guard against multiple displays
	if c.fullRedactedResponse != nil {
		c.logger.Info("Redacted response already displayed, skipping")
		return
	}

	// Build the complete response in sequence order
	keys := make([]int, 0, len(c.redactedPlaintextBySeq))
	for k := range c.redactedPlaintextBySeq {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)

	var fullResponse strings.Builder
	totalOffset := 0

	for _, k := range keys {
		seqNum := uint64(k)
		redactedPlaintext := c.redactedPlaintextBySeq[seqNum]

		// Replace random garbage with asterisks in the redacted plaintext
		redactedContent := c.replaceRandomGarbageWithAsterisks(redactedPlaintext, totalOffset, ranges)

		// Remove TLS padding and get actual HTTP content
		actualRedactedContent, _ := c.removeTLSPadding(redactedContent)
		fullResponse.Write(actualRedactedContent)

		// Use same offset calculation as range generation
		totalOffset += len(redactedPlaintext) // Full content including TLS padding
	}

	redactedResponse := fullResponse.String()
	c.fullRedactedResponse = []byte(redactedResponse)

	// Display the redacted response immediately with collapsed asterisks
	c.logger.Info("Displaying final redacted response from random garbage")
	fmt.Printf("\n\n--- FINAL REDACTED RESPONSE (FROM RANDOM GARBAGE) ---\n%s\n--- END REDACTED RESPONSE ---\n\n",
		collapseAsterisks(string(c.fullRedactedResponse)))

	c.logger.Info("Displayed redacted response from random garbage", zap.Int("bytes", len(redactedResponse)))
}

// replaceRandomGarbageWithAsterisks replaces random garbage in redacted plaintext with asterisks
func (c *Client) replaceRandomGarbageWithAsterisks(content []byte, baseOffset int, ranges []shared.ResponseRedactionRange) []byte {
	result := make([]byte, len(content))
	copy(result, content)

	// Apply each redaction range that overlaps with this content
	for _, r := range ranges {
		rangeStart := r.Start
		rangeEnd := r.Start + r.Length
		contentStart := baseOffset
		contentEnd := baseOffset + len(content)

		// Check for overlap
		overlapStart := max(rangeStart, contentStart)
		overlapEnd := min(rangeEnd, contentEnd)

		if overlapStart < overlapEnd {
			// Replace random garbage with asterisks
			localStart := overlapStart - contentStart
			localEnd := overlapEnd - contentStart
			for i := localStart; i < localEnd; i++ {
				result[i] = '*'
			}
		}
	}

	return result
}

// handleRedactedTranscriptAndStreams handles the combined message containing both signed transcript and redacted streams
func (c *Client) handleRedactedTranscriptAndStreams(msg *shared.Message) {
	var combinedData shared.RedactedTranscriptData
	if err := msg.UnmarshalData(&combinedData); err != nil {
		c.logger.Error("Failed to unmarshal combined transcript and streams data", zap.Error(err))
		return
	}

	c.logger.Info("Received combined transcript and streams message",
		zap.Int("streams_count", len(combinedData.RedactedStreams)),
		zap.Int("total_streams", combinedData.TotalStreams))

	// Process the signed transcript first (same logic as handleSignedTranscript)
	c.logger.Info("Processing signed transcript from combined message",
		zap.Int("packets_count", len(combinedData.SignedTranscript.Packets)),
		zap.Int("signature_bytes", len(combinedData.SignedTranscript.Signature)))

	// Store the public key for attestation verification
	// This is from TEE_K (has RequestMetadata)
	c.teekTranscriptPublicKey = combinedData.SignedTranscript.PublicKey
	c.teekSignedTranscript = &combinedData.SignedTranscript
	c.teekTranscriptPackets = combinedData.SignedTranscript.Packets

	// Calculate total size of all packets
	totalSize := 0
	for _, packet := range combinedData.SignedTranscript.Packets {
		totalSize += len(packet)
	}

	c.logger.Info("Total transcript size", zap.Int("bytes", totalSize))

	// Display signature and public key info for verification
	if len(combinedData.SignedTranscript.Signature) > 0 {
		c.logger.Info("Signature info", zap.String("source", "TEE_K"), zap.Int("signature_bytes", len(combinedData.SignedTranscript.Signature)))
	}

	if len(combinedData.SignedTranscript.PublicKey) > 0 {
		c.logger.Info("Public key info", zap.String("source", "TEE_K"), zap.Int("public_key_bytes", len(combinedData.SignedTranscript.PublicKey)))
	}

	// Process the redacted streams (same logic as the deprecated handleBatchedSignedRedactedDecryptionStreams)
	c.logger.Info("Processing redacted streams from combined message", zap.Int("streams_count", len(combinedData.RedactedStreams)))

	// Process ALL streams from combined message
	for _, redactedStream := range combinedData.RedactedStreams {
		// Add to collection for verification bundle
		c.signedRedactedStreams = append(c.signedRedactedStreams, redactedStream)

		// Apply redacted stream to ciphertext to get redacted plaintext
		c.responseContentMutex.Lock()
		ciphertext, exists := c.ciphertextBySeq[redactedStream.SeqNum]
		c.responseContentMutex.Unlock()

		if !exists {
			log.Fatalf("[Client] No ciphertext found for seq %d", redactedStream.SeqNum)
		}

		if len(redactedStream.RedactedStream) != len(ciphertext) {
			log.Fatalf("[Client] Stream length mismatch for seq %d: stream=%d, ciphertext=%d",
				redactedStream.SeqNum, len(redactedStream.RedactedStream), len(ciphertext))
		}

		// XOR to get redacted plaintext
		redactedPlaintext := make([]byte, len(ciphertext))
		for i := 0; i < len(ciphertext); i++ {
			redactedPlaintext[i] = ciphertext[i] ^ redactedStream.RedactedStream[i]
		}

		// Store redacted plaintext
		c.responseContentMutex.Lock()
		if c.redactedPlaintextBySeq == nil {
			c.redactedPlaintextBySeq = make(map[uint64][]byte)
		}
		c.redactedPlaintextBySeq[redactedStream.SeqNum] = redactedPlaintext
		c.responseContentMutex.Unlock()
	}

	// Now verify the signature since we have both transcript and streams
	c.logger.Info("TEE_K comprehensive verification: have all expected redacted streams", zap.Int("streams_count", len(combinedData.RedactedStreams)))
	verificationErr := shared.VerifyComprehensiveSignature(&combinedData.SignedTranscript, combinedData.RedactedStreams)
	if verificationErr != nil {
		c.logger.Error("Signature verification FAILED", zap.String("source", "TEE_K"), zap.Error(verificationErr))
	} else {
		c.logger.Info("Signature verification SUCCESS", zap.String("source", "TEE_K"))
	}

	// Set completion flag for TEE_K signature validation
	if verificationErr == nil {
		c.setCompletionFlag(CompletionFlagTEEKSignatureValid)
	}

	// Note: We do NOT increment transcript count here because this is TEE_K's transcript
	// The transcript count should only be incremented when actual signed transcripts are received
	// Redacted streams are part of TEE_K's transcript, not a separate transcript

	// Increment transcript count for TEE_K's signed transcript
	c.incrementTranscriptCount()

	c.logger.Info("Marked transcript as received", zap.String("source", "TEE_K"), zap.Bool("signature_valid", verificationErr == nil))

	// Check completion condition
	_, transcriptCount := c.getProtocolState()
	if transcriptCount >= 2 {
		c.logger.Info("Combined message processed AND both transcripts received - protocol ready for completion")
		// Note: Phase advancement to PhaseComplete will be handled in handleSignedTranscript
		// to ensure proper sequencing of final validation and display
	} else {
		c.logger.Info("Combined message processed but waiting for remaining transcripts")
	}

	// Note: Final redacted response display will be handled in handleSignedTranscript when both transcripts are received
	// to ensure it only happens after protocol completion

	// Check if we can now proceed with full protocol completion
	// Note: Final validation will be handled in handleSignedTranscript when both transcripts are received
	// to avoid duplicate validation calls

	c.logger.Info("Completed processing combined transcript and streams message", zap.Int("streams_count", len(combinedData.RedactedStreams)))
}
