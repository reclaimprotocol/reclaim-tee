package clientlib

import (
	"fmt"
	"log"
	"sort"
	"strings"
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

// analyzeHTTPResponseRedactionWithBytes identifies sensitive parts within HTTP response content and calculates redaction bytes (no Type field)
func (c *Client) analyzeHTTPResponseRedactionWithBytes(httpData []byte, baseOffset int, ciphertext []byte) []shared.ResponseRedactionRange {
	// Simple implementation - return empty ranges for now
	// This can be enhanced later with proper response redaction logic
	return []shared.ResponseRedactionRange{}
}

// analyzeResponseRedaction analyzes all response content to identify redaction ranges and calculate redaction bytes
func (c *Client) analyzeResponseRedaction() shared.ResponseRedactionSpec {
	log.Printf("[Client] Analyzing response content for redaction ranges...")

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
			log.Printf("[Client] Warning: No ciphertext found for seq %d", seqNum)
			totalOffset += len(content)
			continue
		}

		// Correctly handle content/type separation and offset calculation
		// 1. Separate actual content from its single-byte type identifier
		actualContent, contentType := c.removeTLSPadding(content)

		switch contentType {
		case 0x16: // Handshake message - likely NewSessionTicket
			if len(actualContent) >= 4 && actualContent[0] == 0x04 { // NewSessionTicket
				log.Printf("[Client] Redacting NewSessionTicket at offset %d-%d", totalOffset, totalOffset+len(actualContent)-1)

				redactionRanges = append(redactionRanges, shared.ResponseRedactionRange{
					Start:  totalOffset,
					Length: len(content), // Cover full record including padding
				})

				log.Printf("[Client] Session ticket redaction: length=%d", len(actualContent))
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
			log.Printf("[Client] Found TLS alert at offset %d (seq %d) - keeping visible", totalOffset, seqNum)

		default:
			// Unknown content type - no specific handling needed
		}

		totalOffset += len(content)
	}

	// Analyze all HTTP content as a single unit if we collected any
	if len(allHTTPContent) > 0 && len(httpContentMappings) > 0 {
		log.Printf("[Client] Analyzing combined HTTP content (%d bytes) from %d TLS records", len(allHTTPContent), len(httpContentMappings))

		var combinedHTTPRanges []shared.ResponseRedactionRange

		if len(c.lastRedactionRanges) > 0 {
			log.Printf("[Client] Using cached redaction ranges from response callback (%d ranges)", len(c.lastRedactionRanges))

			// Use cached ResponseRedactionRange directly
			combinedHTTPRanges = c.lastRedactionRanges
			// log.Printf("[Client] Using cached range: [%d:%d]", r.Start, r.Start+r.Length-1)
		} else {
			log.Printf("[Client] No cached redaction ranges available, using automatic analysis")

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

	log.Printf("[Client] Generated redaction spec with %d ranges (after gap filling)", len(redactionRanges))
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
	log.Printf("[Client] Generating and sending redaction specification to TEE_K...")

	// Analyze response content to identify redaction ranges
	redactionSpec := c.analyzeResponseRedaction()

	// Send redaction spec to TEE_K
	msg := shared.CreateSessionMessage(shared.MsgRedactionSpec, c.sessionID, redactionSpec)
	if err := c.wsConn.WriteJSON(msg); err != nil {
		return fmt.Errorf("failed to send redaction spec to TEE_K: %v", err)
	}

	log.Printf("[Client] Sent redaction specification to TEE_K with %d ranges", len(redactionSpec.Ranges))

	// Display ranges sent to TEE_K
	// for i, r := range redactionSpec.Ranges {
	// 	if r.Type == "session_ticket" {
	// 		log.Printf("[Client] Range %d: [%d:%d] type=%s (session ticket)", i+1, r.Start, r.Start+r.Length-1, r.Type)
	// 	} else {
	// 		log.Printf("[Client] Range %d: [%d:%d] type=%s (%d bytes)", i+1, r.Start, r.Start+r.Length-1, r.Type, len(r.RedactionBytes))
	// 	}
	// }

	log.Printf("[Client] Redaction specification sent successfully")

	c.advanceToPhase(PhaseReceivingRedacted)

	//  send finished command when entering redacted receiving phase ***
	log.Printf("[Client] Entering redacted receiving phase - automatically sending finished command")
	if err := c.sendFinishedCommand(); err != nil {
		log.Printf("[Client] Failed to send finished command: %v", err)
	}

	return nil
}

// displayRedactedResponseFromRanges immediately displays the redacted response using calculated ranges
func (c *Client) displayRedactedResponseFromRanges(ranges []shared.ResponseRedactionRange) {
	c.responseContentMutex.Lock()
	defer c.responseContentMutex.Unlock()

	// Guard against multiple displays
	if c.fullRedactedResponse != nil {
		log.Printf("[Client] Redacted response already displayed, skipping...")
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
	fmt.Printf("\n\n--- FINAL REDACTED RESPONSE (FROM RANGES) ---\n%s\n--- END REDACTED RESPONSE ---\n\n",
		collapseAsterisks(string(c.fullRedactedResponse)))

	log.Printf("[Client] Displayed redacted response from ranges (%d bytes)", len(redactedResponse))
}

// displayRedactedResponseFromRandomGarbage displays the redacted response by replacing random garbage with asterisks
func (c *Client) displayRedactedResponseFromRandomGarbage(ranges []shared.ResponseRedactionRange) {
	c.responseContentMutex.Lock()
	defer c.responseContentMutex.Unlock()

	// Guard against multiple displays
	if c.fullRedactedResponse != nil {
		log.Printf("[Client] Redacted response already displayed, skipping...")
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
	fmt.Printf("\n\n--- FINAL REDACTED RESPONSE (FROM RANDOM GARBAGE) ---\n%s\n--- END REDACTED RESPONSE ---\n\n",
		collapseAsterisks(string(c.fullRedactedResponse)))

	log.Printf("[Client] Displayed redacted response from random garbage (%d bytes)", len(redactedResponse))
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

// handleBatchedSignedRedactedDecryptionStreams handles batched signed redacted decryption streams
// while preserving exact same state machine behavior as individual messages
func (c *Client) handleBatchedSignedRedactedDecryptionStreams(msg *shared.Message) {
	var batchedStreams shared.BatchedSignedRedactedDecryptionStreamData
	if err := msg.UnmarshalData(&batchedStreams); err != nil {
		log.Printf("[Client] Failed to unmarshal batched signed redacted decryption streams: %v", err)
		return
	}

	log.Printf("[Client] Received batch of %d signed redacted decryption streams", len(batchedStreams.SignedRedactedStreams))

	// Process ALL streams from batch at once
	for _, redactedStream := range batchedStreams.SignedRedactedStreams {
		// log.Printf("[Client] Processing redacted decryption stream for seq %d (%d bytes)",
		// 	redactedStream.SeqNum, len(redactedStream.RedactedStream))

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

		// log.Printf("[Client] Applied redacted stream to seq %d successfully", redactedStream.SeqNum)
	}

	// Check completion condition - triggers immediately since all streams received at once
	if c.teekSignedTranscript != nil && !c.hasCompletionFlag(CompletionFlagTEEKSignatureValid) {
		if len(c.signedRedactedStreams) >= c.expectedRedactedStreams {
			log.Printf("[Client] Received all %d expected redacted streams from batch, attempting TEE_K comprehensive signature verification", c.expectedRedactedStreams)
			verificationErr := shared.VerifyComprehensiveSignature(c.teekSignedTranscript, c.signedRedactedStreams)
			if verificationErr != nil {
				log.Printf("[Client] TEE_K signature verification FAILED: %v", verificationErr)
				fmt.Printf("[Client] TEE_K signature verification FAILED: %v\n", verificationErr)
			} else {
				log.Printf("[Client] TEE_K signature verification SUCCESS")
				fmt.Printf("[Client] TEE_K signature verification SUCCESS\n")
				c.setCompletionFlag(CompletionFlagTEEKSignatureValid)

				_, transcriptCount := c.getProtocolState()
				if transcriptCount >= 2 {
					log.Printf("[Client] Redacted streams processed AND both transcripts received - completing protocol")
					c.advanceToPhase(PhaseComplete)
				} else {
					log.Printf("[Client] Redacted streams processed but waiting for remaining transcripts...")
				}

				log.Printf("[Client] All redacted streams received - displaying final redacted response")
				redactionSpec := c.analyzeResponseRedaction()
				c.displayRedactedResponseFromRandomGarbage(redactionSpec.Ranges)

				// Check if we can now proceed with full protocol completion
				transcriptsComplete := c.transcriptsReceived >= 2
				signaturesValid := c.hasCompletionFlag(CompletionFlagTEEKSignatureValid)

				if transcriptsComplete && signaturesValid {
					log.Printf("[Client] Both transcripts received with valid signatures - performing transcript validation...")
					c.validateTranscriptsAgainstCapturedTraffic()
					fmt.Printf("[Client] Received signed transcripts from both TEE_K and TEE_T with VALID signatures!")
				}
			}
		}
	}

	log.Printf("[Client] Completed processing batch of %d signed redacted decryption streams", len(batchedStreams.SignedRedactedStreams))
}
