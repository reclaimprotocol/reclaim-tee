package main

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"sync/atomic"
	"tee-mpc/shared"
)

// WaitForCompletion returns a channel that closes when the protocol is complete
func (c *Client) WaitForCompletion() <-chan struct{} {
	return c.completionChan
}

// checkProtocolCompletion checks if all conditions are met and signals completion if so
func (c *Client) checkProtocolCompletion(reason string) {
	// Use atomic operations to read state values
	eofCondition := atomic.LoadInt64(&c.eofReached) == 1
	recordsSent := atomic.LoadInt64(&c.recordsSent)
	recordsProcessed := atomic.LoadInt64(&c.recordsProcessed)
	streamsReceived := atomic.LoadInt64(&c.decryptionStreamsReceived)

	// Completion conditions:
	// 1. EOF reached (TCP connection closed)
	// 2. All split AEAD records processed (or no records sent)
	// 3. Redaction result received (if expected)
	// 4. Signed transcripts received from both TEE_K and TEE_T (if expected)

	recordsCondition := recordsSent == 0 || recordsProcessed >= recordsSent
	redactionCondition := !c.hasCompletionFlag(CompletionFlagRedactionExpected) || c.hasCompletionFlag(CompletionFlagRedactionReceived)

	// *** FIX: Add condition to ensure all decryption streams are received ***
	streamsCondition := recordsSent == 0 || streamsReceived >= recordsSent

	// Check if split AEAD processing is complete (conditions 1-3 + new streams condition)
	splitAEADComplete := eofCondition && recordsCondition && redactionCondition && streamsCondition

	// IMPORTANT: Only proceed with redaction and completion if EOF has been reached
	// This ensures all TLS records (including alerts) have been received and processed
	// before we send redaction specs to TEE_K
	if !eofCondition {
		log.Printf("[Client] Waiting for EOF before proceeding with redaction (records: %d/%d, streams: %d/%d, EOF: %v)",
			recordsProcessed, recordsSent, streamsReceived, recordsSent, eofCondition)
		return
	}

	// If split AEAD is complete but we haven't sent redaction spec yet, send it now
	if splitAEADComplete && !c.hasCompletionFlag(CompletionFlagRedactedStreamsExpected) && !c.hasCompletionFlag(CompletionFlagSignedTranscriptsExpected) {
		log.Printf("[Client] Split AEAD processing complete and EOF reached - sending redaction specification")
		if err := c.sendRedactionSpec(); err != nil {
			log.Printf("[Client] Failed to send redaction spec: %v", err)
			return
		}
		// Note: CompletionFlagRedactedStreamsExpected is set to true in sendRedactionSpec
	}

	// If redaction spec sent but we haven't sent finished command yet, send it now
	// (For now, we'll skip waiting for redacted streams and proceed to finished command)
	if splitAEADComplete && c.hasCompletionFlag(CompletionFlagRedactedStreamsExpected) && !c.hasCompletionFlag(CompletionFlagSignedTranscriptsExpected) {
		log.Printf("[Client] Redaction spec sent - sending finished command")
		if err := c.sendFinishedCommand(); err != nil {
			log.Printf("[Client] Failed to send finished command: %v", err)
			return
		}
		// Note: CompletionFlagSignedTranscriptsExpected is set to true in sendFinishedCommand
	}

	// Final completion condition: signed transcripts received AND signatures valid
	transcriptCondition := !c.hasCompletionFlag(CompletionFlagSignedTranscriptsExpected) ||
		(c.hasAllCompletionFlags(CompletionFlagTEEKTranscriptReceived | CompletionFlagTEETTranscriptReceived | CompletionFlagTEEKSignatureValid | CompletionFlagTEETSignatureValid))

	allConditionsMet := splitAEADComplete && transcriptCondition

	if allConditionsMet {
		c.completionOnce.Do(func() {
			log.Printf("[Client] All protocol conditions met (including signature validation) - completing client processing")
			close(c.completionChan)
		})
	} else if splitAEADComplete && c.hasCompletionFlag(CompletionFlagSignedTranscriptsExpected) &&
		c.hasAllCompletionFlags(CompletionFlagTEEKTranscriptReceived|CompletionFlagTEETTranscriptReceived) &&
		(!c.hasCompletionFlag(CompletionFlagTEEKSignatureValid) || !c.hasCompletionFlag(CompletionFlagTEETSignatureValid)) {
		// Special case: All transcripts received but signatures invalid
		log.Printf("[Client] Protocol completion BLOCKED due to invalid signatures (TEE_K: %v, TEE_T: %v)",
			c.hasCompletionFlag(CompletionFlagTEEKSignatureValid), c.hasCompletionFlag(CompletionFlagTEETSignatureValid))
	}
}

// sendFinishedCommand sends "finished" message to both TEE_K and TEE_T
func (c *Client) sendFinishedCommand() error {
	log.Printf("[Client] Sending finished command to both TEE_K and TEE_T")

	// Set flag to expect signed transcripts
	c.setCompletionFlag(CompletionFlagSignedTranscriptsExpected)

	finishedMsg := shared.FinishedMessage{}

	// Send to TEE_K
	msg := shared.CreateSessionMessage(shared.MsgFinished, c.sessionID, finishedMsg)
	if err := c.wsConn.WriteJSON(msg); err != nil {
		return fmt.Errorf("failed to send finished to TEE_K: %v", err)
	}
	log.Printf("[Client] Sent finished command to TEE_K")

	// Send to TEE_T
	if err := c.teetConn.WriteJSON(msg); err != nil {
		return fmt.Errorf("failed to send finished to TEE_T: %v", err)
	}
	log.Printf("[Client] Sent finished command to TEE_T")

	log.Printf("[Client] Now waiting for signed transcripts from both TEE_K and TEE_T...")

	return nil
}

// sendRedactionSpec sends redaction specification to TEE_K
func (c *Client) sendRedactionSpec() error {
	log.Printf("[Client] Generating and sending redaction specification to TEE_K...")
	log.Printf("[Client] 🔍 DEBUG: About to call analyzeResponseRedaction() - cached ranges: %d", len(c.lastRedactionRanges))

	// Analyze response content to identify redaction ranges
	redactionSpec := c.analyzeResponseRedaction()

	// *** NEW: IMMEDIATELY display redacted response using calculated ranges ***
	c.displayRedactedResponseFromRanges(redactionSpec.Ranges)

	// Count expected redacted streams based on records sent to TEE_T for processing
	// Use recordsSent instead of responseContentBySeq length to avoid race conditions
	c.expectedRedactedStreams = int(atomic.LoadInt64(&c.recordsSent))

	log.Printf("[Client] Expecting %d redacted streams based on records sent to TEE_T", c.expectedRedactedStreams)

	// Send redaction spec to TEE_K
	msg := shared.CreateSessionMessage(shared.MsgRedactionSpec, c.sessionID, redactionSpec)
	if err := c.wsConn.WriteJSON(msg); err != nil {
		return fmt.Errorf("failed to send redaction spec to TEE_K: %v", err)
	}

	log.Printf("[Client] Sent redaction specification to TEE_K with %d ranges", len(redactionSpec.Ranges))

	// *** DEBUG: Show detailed ranges sent to TEE_K ***
	for i, r := range redactionSpec.Ranges {
		log.Printf("[Client] 🔧 SENT Range %d: [%d:%d] type=%s, redactionBytes=%d bytes",
			i+1, r.Start, r.Start+r.Length-1, r.Type, len(r.RedactionBytes))
		if r.Type == "session_ticket" {
			log.Printf("[Client] 🔧   Session ticket range: seq offset %d, length %d", r.Start, r.Length)
			if len(r.RedactionBytes) > 0 {
				log.Printf("[Client] 🔧   First 16 redaction bytes: %x", r.RedactionBytes[:min(16, len(r.RedactionBytes))])
			}
		}
	}

	// Set flag to expect redacted streams
	c.setCompletionFlag(CompletionFlagRedactedStreamsExpected)

	return nil
}

// displayRedactedResponseFromRanges immediately displays the redacted response using calculated ranges
func (c *Client) displayRedactedResponseFromRanges(ranges []shared.RedactionRange) {
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

		// *** CRITICAL FIX: Apply ranges to FULL content (like verifier does) ***
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

	log.Printf("[Client] ✅ Displayed redacted response immediately using calculated ranges (%d bytes)", len(redactedResponse))
}

// applyRedactionRangesToContent applies redaction ranges to a content segment
func (c *Client) applyRedactionRangesToContent(content []byte, baseOffset int, ranges []shared.RedactionRange) []byte {
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

// calculateRedactionBytes calculates what should replace parts of decryption stream to produce '*' when XORed with ciphertext
func (c *Client) calculateRedactionBytes(ciphertext []byte, startOffset, length int, seqNum uint64) []byte {
	redactionBytes := make([]byte, length)
	asterisk := byte('*') // 0x2A

	for i := 0; i < length; i++ {
		pos := startOffset + i
		if pos < len(ciphertext) {
			// redaction_byte = ciphertext_byte XOR '*'
			// This ensures: ciphertext_byte XOR redaction_byte = '*'
			redactionBytes[i] = ciphertext[pos] ^ asterisk
		}
	}

	return redactionBytes
}

// isTLS12AESGCMCipher checks if the current connection is using TLS 1.2 AES-GCM
func (c *Client) isTLS12AESGCMCipher() bool {
	if c.handshakeDisclosure == nil {
		return false
	}

	cipherSuite := c.handshakeDisclosure.CipherSuite
	return cipherSuite == 0xc02f || // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		cipherSuite == 0xc02b || // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		cipherSuite == 0xc030 || // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		cipherSuite == 0xc02c // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
}

// analyzeResponseRedaction analyzes all response content to identify redaction ranges and calculate redaction bytes
func (c *Client) analyzeResponseRedaction() shared.RedactionSpec {
	log.Printf("[Client] Analyzing response content for redaction ranges...")

	c.responseContentMutex.Lock()
	defer c.responseContentMutex.Unlock()

	var redactionRanges []shared.RedactionRange
	totalOffset := 0

	// *** FIX: Iterate over map keys in sorted order to guarantee correctness ***
	// 1. Get all sequence numbers (keys) from the map.
	keys := make([]int, 0, len(c.responseContentBySeq))
	for k := range c.responseContentBySeq {
		keys = append(keys, int(k))
	}
	// 2. Sort the keys numerically.
	sort.Ints(keys)

	// *** NEW APPROACH: Collect all HTTP application data first, then analyze as a whole ***
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

		// *** FIX: Correctly handle content/type separation and offset calculation ***
		// 1. Separate actual content from its single-byte type identifier
		actualContent, contentType := c.removeTLSPadding(content)

		log.Printf("[Client] 🔍 Analyzing sequence %d: %d bytes, content type 0x%02x", seqNum, len(actualContent), contentType)
		if seqNum <= 5 { // Debug first few sequences
			log.Printf("[Client] 🔍 Seq %d first 16 bytes: %x", seqNum, actualContent[:min(16, len(actualContent))])
		}

		switch contentType {
		case 0x16: // Handshake message - likely NewSessionTicket
			log.Printf("[Client] 🔍 Found handshake message at offset %d (seq %d), content length=%d", totalOffset, seqNum, len(actualContent))
			if len(actualContent) >= 4 {
				log.Printf("[Client] 🔍 Handshake message type: 0x%02x (0x04=NewSessionTicket)", actualContent[0])
			}
			if len(actualContent) >= 4 && actualContent[0] == 0x04 { // NewSessionTicket
				log.Printf("[Client] Redacting NewSessionTicket at offset %d-%d", totalOffset, totalOffset+len(actualContent)-1)

				// *** FIX: Find where actualContent starts within the original ciphertext ***
				// For TLS 1.3, actualContent is at the beginning of the decrypted payload
				// For TLS 1.2, we need to account for explicit IV and other headers
				ciphertextOffset := 0
				if c.isTLS12AESGCMCipher() {
					ciphertextOffset = 8 // Skip explicit IV for TLS 1.2 AES-GCM
				}

				// Calculate redaction bytes using correct offset within ciphertext
				redactionBytes := c.calculateRedactionBytes(ciphertext, ciphertextOffset, len(actualContent), seqNum)

				// *** DEBUG: Show what we're calculating against ***
				log.Printf("[Client] 🔧 Session ticket redaction bytes calc:")
				log.Printf("[Client] 🔧   Ciphertext length: %d", len(ciphertext))
				log.Printf("[Client] 🔧   Using offset: %d, length: %d", ciphertextOffset, len(actualContent))
				if len(ciphertext) > ciphertextOffset+16 {
					log.Printf("[Client] 🔧   Ciphertext[%d:%d]: %x",
						ciphertextOffset, ciphertextOffset+16, ciphertext[ciphertextOffset:ciphertextOffset+16])
				}
				log.Printf("[Client] 🔧   Expected result: %d asterisks (full record: %d bytes)", len(actualContent), len(content))
				// *** CRITICAL FIX: Cover full TLS record including padding ***
				// Extend redaction bytes to cover the full record
				fullRedactionBytes := make([]byte, len(content))
				copy(fullRedactionBytes, redactionBytes)
				// Fill padding byte with asterisk redaction
				for i := len(redactionBytes); i < len(content); i++ {
					if i < len(ciphertext) {
						fullRedactionBytes[i] = ciphertext[i] ^ byte('*')
					}
				}

				redactionRanges = append(redactionRanges, shared.RedactionRange{
					Start:          totalOffset,
					Length:         len(content), // Cover full record including padding
					Type:           "session_ticket",
					RedactionBytes: fullRedactionBytes,
				})

				log.Printf("[Client] Session ticket redaction: ciphertext offset=%d, length=%d", ciphertextOffset, len(actualContent))
				log.Printf("[Client] 🔧 Session ticket fix: ciphertext[%d:%d] → asterisks",
					ciphertextOffset, ciphertextOffset+len(actualContent))
			}

		case 0x17: // ApplicationData - HTTP response
			log.Printf("[Client] 🔍 Found HTTP response part at offset %d (seq %d) - collecting for combined analysis", totalOffset, seqNum)

			// Collect this HTTP content for combined analysis
			httpContentMappings = append(httpContentMappings, struct {
				seqNum     uint64
				httpPos    int
				tlsOffset  int
				length     int
				ciphertext []byte
			}{
				seqNum:     seqNum,
				httpPos:    len(allHTTPContent), // Position in HTTP stream
				tlsOffset:  totalOffset,         // Position in TLS stream
				length:     len(actualContent),
				ciphertext: ciphertext,
			})

			// *** CRITICAL: Store the TLS offset for this HTTP record ***
			log.Printf("[Client] 🔧 HTTP record seq=%d: TLS offset=%d, HTTP pos=%d, length=%d",
				seqNum, totalOffset, len(allHTTPContent), len(actualContent))

			allHTTPContent = append(allHTTPContent, actualContent...)

		case 0x15: // Alert - usually safe to keep
			log.Printf("[Client] 🔍 Found TLS alert at offset %d (seq %d) - keeping visible", totalOffset, seqNum)

		default:
			log.Printf("[Client] ❓ Unknown content type 0x%02x at offset %d (seq %d), length=%d",
				contentType, totalOffset, seqNum, len(actualContent))
		}

		// ***  Increment offset by the length of the ORIGINAL PADDED content ***
		totalOffset += len(content)
	}

	// *** NEW: Analyze all HTTP content as a single unit if we collected any ***
	if len(allHTTPContent) > 0 && len(httpContentMappings) > 0 {
		log.Printf("[Client] Analyzing combined HTTP content (%d bytes) from %d TLS records", len(allHTTPContent), len(httpContentMappings))

		// *** Use cached redaction ranges from response callback if available ***
		var combinedHTTPRanges []shared.RedactionRange

		if c.responseCallback != nil && len(c.lastRedactionRanges) > 0 {
			log.Printf("[Client] ✅ Using cached redaction ranges from response callback (%d ranges)", len(c.lastRedactionRanges))

			// Convert cached RedactionRange to shared.RedactionRange format
			for _, r := range c.lastRedactionRanges {
				combinedHTTPRanges = append(combinedHTTPRanges, shared.RedactionRange{
					Start:  r.Start,
					Length: r.Length,
					Type:   r.Type,
					// RedactionBytes will be calculated below during mapping
				})
				log.Printf("[Client] Using cached range: [%d:%d] type=%s", r.Start, r.Start+r.Length-1, r.Type)
			}
		} else {
			log.Printf("[Client] ❌ No cached redaction ranges available, using automatic analysis")
			log.Printf("[Client] ❌ Debug: responseCallback != nil: %v, len(lastRedactionRanges): %d",
				c.responseCallback != nil, len(c.lastRedactionRanges))
			combinedHTTPRanges = c.analyzeHTTPRedactionWithBytes(allHTTPContent, 0, nil)
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
						log.Printf("[Client] 🔧 Filling 1-byte gap to next record (seq %d → seq %d)",
							m.mapping.seqNum, nextM.mapping.seqNum)
					}
				}

				log.Printf("[Client] 🔧 Mapping: HTTP range [%d:%d] → TLS offset %d (seq %d, length %d)",
					m.overlapStart, m.overlapEnd-1, m.actualTLSOffset, m.mapping.seqNum, overlapLength)

				// Calculate redaction bytes for this specific TLS record portion
				baseRedactionBytes := c.calculateRedactionBytes(m.mapping.ciphertext, m.localStart, m.overlapLength, m.mapping.seqNum)

				// If we extended for gap filling, add gap redaction byte
				redactionBytes := baseRedactionBytes
				if overlapLength > m.overlapLength {
					// The gap byte is the padding at the end of the current record
					ciphertext := m.mapping.ciphertext
					if len(ciphertext) > m.localStart+m.overlapLength {
						gapCipherByte := ciphertext[m.localStart+m.overlapLength] // Gap byte at end of content
						gapByte := gapCipherByte ^ byte('*')                      // Should produce asterisk
						redactionBytes = append(redactionBytes, gapByte)
						log.Printf("[Client] 🔧 Added gap redaction byte from current record padding")
					}
				}

				redactionRanges = append(redactionRanges, shared.RedactionRange{
					Start:          m.actualTLSOffset,
					Length:         overlapLength,
					Type:           httpRange.Type,
					RedactionBytes: redactionBytes,
				})

				log.Printf("[Client] ✅ Mapped HTTP range [%d:%d] to TLS offset [%d:%d] (seq=%d)",
					m.overlapStart, m.overlapEnd-1, m.actualTLSOffset, m.actualTLSOffset+overlapLength-1, m.mapping.seqNum)
			}
		}
	}

	// *** NO MORE HACKS - ranges should be calculated correctly from the start ***

	spec := shared.RedactionSpec{
		Ranges:                     redactionRanges,
		AlwaysRedactSessionTickets: true,
	}

	log.Printf("[Client] Generated redaction spec with %d ranges (after gap filling)", len(redactionRanges))
	for i, r := range redactionRanges {
		log.Printf("[Client] Range %d: [%d:%d] type=%s (%d redaction bytes)", i+1, r.Start, r.Start+r.Length-1, r.Type, len(r.RedactionBytes))
	}

	return spec
}

// fillRedactionGaps fills gaps between redaction ranges to ensure continuous coverage
func (c *Client) fillRedactionGaps(ranges []shared.RedactionRange, totalLength int) []shared.RedactionRange {
	if len(ranges) == 0 {
		return ranges
	}

	// Sort ranges by start position
	sortedRanges := make([]shared.RedactionRange, len(ranges))
	copy(sortedRanges, ranges)

	// Simple bubble sort for RedactionRange
	for i := 0; i < len(sortedRanges)-1; i++ {
		for j := 0; j < len(sortedRanges)-i-1; j++ {
			if sortedRanges[j].Start > sortedRanges[j+1].Start {
				sortedRanges[j], sortedRanges[j+1] = sortedRanges[j+1], sortedRanges[j]
			}
		}
	}

	var filledRanges []shared.RedactionRange
	currentPos := 0

	for _, r := range sortedRanges {
		// Fill gap before this range
		if r.Start > currentPos {
			gapLength := r.Start - currentPos

			// *** SMART GAP FILLING: Only fill small TLS padding gaps, not content gaps ***
			if gapLength <= 8 { // Only fill small gaps (TLS padding, record boundaries)
				log.Printf("[Client] 🔧 Filling small gap [%d:%d] (%d bytes) - TLS padding", currentPos, r.Start-1, gapLength)

				// Create dummy redaction bytes for the gap
				gapRedactionBytes := make([]byte, gapLength)
				for i := range gapRedactionBytes {
					gapRedactionBytes[i] = 0x2A ^ 0x20 // Will produce '*' when XORed with space or other chars
				}

				filledRanges = append(filledRanges, shared.RedactionRange{
					Start:          currentPos,
					Length:         gapLength,
					Type:           "gap_fill",
					RedactionBytes: gapRedactionBytes,
				})
			} else {
				// Large gap - probably intended to be preserved (HTTP headers, etc.)
				log.Printf("[Client] 🔧 Skipping large gap [%d:%d] (%d bytes) - preserving content", currentPos, r.Start-1, gapLength)
			}
		}

		// Add the original range
		filledRanges = append(filledRanges, r)
		currentPos = r.Start + r.Length
	}

	// Fill any remaining gap at the end
	if currentPos < totalLength {
		gapLength := totalLength - currentPos
		log.Printf("[Client] 🔧 Filling final gap [%d:%d] (%d bytes)", currentPos, totalLength-1, gapLength)

		gapRedactionBytes := make([]byte, gapLength)
		for i := range gapRedactionBytes {
			gapRedactionBytes[i] = 0x2A ^ 0x20
		}

		filledRanges = append(filledRanges, shared.RedactionRange{
			Start:          currentPos,
			Length:         gapLength,
			Type:           "gap_fill",
			RedactionBytes: gapRedactionBytes,
		})
	}

	log.Printf("[Client] 🔧 Gap filling: %d ranges → %d ranges", len(ranges), len(filledRanges))
	return filledRanges
}

// mergeAdjacentRanges merges ranges that are adjacent or overlapping to eliminate gaps
func (c *Client) mergeAdjacentRanges(ranges []shared.RedactionRange) []shared.RedactionRange {
	if len(ranges) <= 1 {
		return ranges
	}

	// Sort ranges by start position
	sortedRanges := make([]shared.RedactionRange, len(ranges))
	copy(sortedRanges, ranges)

	// Simple bubble sort
	for i := 0; i < len(sortedRanges)-1; i++ {
		for j := 0; j < len(sortedRanges)-i-1; j++ {
			if sortedRanges[j].Start > sortedRanges[j+1].Start {
				sortedRanges[j], sortedRanges[j+1] = sortedRanges[j+1], sortedRanges[j]
			}
		}
	}

	var mergedRanges []shared.RedactionRange
	current := sortedRanges[0]

	for i := 1; i < len(sortedRanges); i++ {
		next := sortedRanges[i]

		// Check if ranges are adjacent or overlapping (gap <= 1 byte)
		currentEnd := current.Start + current.Length
		gap := next.Start - currentEnd

		if gap <= 1 { // Adjacent or 1-byte gap
			// Merge ranges
			log.Printf("[Client] 🔧 Merging ranges [%d:%d] + [%d:%d] (gap: %d)",
				current.Start, currentEnd-1, next.Start, next.Start+next.Length-1, gap)

			// Extend current range to cover the gap and next range
			newLength := (next.Start + next.Length) - current.Start
			current.Length = newLength

			// For redaction bytes, we need to extend with gap-filling bytes
			if gap == 1 {
				// Add one gap byte (assume it should be asterisk)
				current.RedactionBytes = append(current.RedactionBytes, byte('*')^byte(' '))
			}
			// Append next range's redaction bytes
			current.RedactionBytes = append(current.RedactionBytes, next.RedactionBytes...)

		} else {
			// Gap too large, keep current and move to next
			mergedRanges = append(mergedRanges, current)
			current = next
		}
	}

	// Add the last range
	mergedRanges = append(mergedRanges, current)

	log.Printf("[Client] 🔧 Range merging: %d ranges → %d ranges", len(ranges), len(mergedRanges))
	return mergedRanges
}

// analyzeHTTPRedactionWithBytes identifies sensitive parts within HTTP response content and calculates redaction bytes
func (c *Client) analyzeHTTPRedactionWithBytes(httpData []byte, baseOffset int, ciphertext []byte) []shared.RedactionRange {
	var ranges []shared.RedactionRange

	httpStr := string(httpData)

	// NEW STRATEGY: Preserve HTTP headers AND title content, redact everything else
	// Find the end of headers (double CRLF)
	headerEndIndex := strings.Index(httpStr, "\r\n\r\n")
	if headerEndIndex == -1 {
		// Try with just LF
		headerEndIndex = strings.Index(httpStr, "\n\n")
		if headerEndIndex != -1 {
			headerEndIndex += 2 // Account for \n\n
		}
	} else {
		headerEndIndex += 4 // Account for \r\n\r\n
	}

	if headerEndIndex == -1 {
		// No clear header/body separation found, treat everything as headers and preserve it
		log.Printf("[Client] No header/body separation found, preserving entire response")
		return ranges // Return empty ranges - preserve everything
	}

	// Headers section (preserve entirely)
	log.Printf("[Client] Found HTTP headers (0-%d) - preserving", headerEndIndex-1)

	// Body section - look for title content to preserve
	bodyContent := httpStr[headerEndIndex:]

	if len(bodyContent) == 0 {
		log.Printf("[Client] No body content found, only headers")
		return ranges // Only headers, nothing to redact
	}

	// Find title tags within the body
	titleStartTag := "<title>"
	titleEndTag := "</title>"
	titleStartIndex := strings.Index(bodyContent, titleStartTag)

	if titleStartIndex != -1 {
		titleContentStartIndex := titleStartIndex + len(titleStartTag)
		titleEndIndex := strings.Index(bodyContent[titleContentStartIndex:], titleEndTag)

		if titleEndIndex != -1 {
			// Adjust titleEndIndex to be absolute within bodyContent
			titleEndIndex = titleContentStartIndex + titleEndIndex

			log.Printf("[Client] Found title content at body offset %d-%d (preserving this content)",
				titleContentStartIndex, titleEndIndex-1)

			// Calculate absolute positions in the full HTTP response
			bodyStartInFull := headerEndIndex
			titleEndInFull := bodyStartInFull + titleEndIndex

			// Redact everything in body BEFORE the title content
			if titleContentStartIndex > 0 {
				beforeTitleLength := titleContentStartIndex
				beforeTitleStart := bodyStartInFull

				if ciphertext != nil {
					redactionBytes := c.calculateRedactionBytes(ciphertext, beforeTitleStart, beforeTitleLength, 0)
					ranges = append(ranges, shared.RedactionRange{
						Start:          baseOffset + beforeTitleStart,
						Length:         beforeTitleLength,
						Type:           "body_before_title",
						RedactionBytes: redactionBytes,
					})
				} else {
					// For combined analysis, we'll calculate redaction bytes later
					ranges = append(ranges, shared.RedactionRange{
						Start:          beforeTitleStart,
						Length:         beforeTitleLength,
						Type:           "body_before_title",
						RedactionBytes: nil,
					})
				}

				log.Printf("[Client] Redacting body content before title: offset %d-%d (%d bytes)",
					beforeTitleStart, beforeTitleStart+beforeTitleLength-1, beforeTitleLength)
			}

			// Redact everything in body AFTER the title content
			if titleEndIndex < len(bodyContent) {
				afterTitleStart := titleEndInFull
				afterTitleLength := len(bodyContent) - titleEndIndex

				if ciphertext != nil {
					redactionBytes := c.calculateRedactionBytes(ciphertext, afterTitleStart, afterTitleLength, 0)
					ranges = append(ranges, shared.RedactionRange{
						Start:          baseOffset + afterTitleStart,
						Length:         afterTitleLength,
						Type:           "body_after_title",
						RedactionBytes: redactionBytes,
					})
				} else {
					// For combined analysis, we'll calculate redaction bytes later
					ranges = append(ranges, shared.RedactionRange{
						Start:          afterTitleStart,
						Length:         afterTitleLength,
						Type:           "body_after_title",
						RedactionBytes: nil,
					})
				}

				log.Printf("[Client] Redacting body content after title: offset %d-%d (%d bytes)",
					afterTitleStart, afterTitleStart+afterTitleLength-1, afterTitleLength)
			}
		} else {
			// No closing title tag found, redact everything in body except headers
			log.Printf("[Client] No closing title tag found, redacting entire body content")

			if ciphertext != nil {
				redactionBytes := c.calculateRedactionBytes(ciphertext, headerEndIndex, len(bodyContent), 0)
				ranges = append(ranges, shared.RedactionRange{
					Start:          baseOffset + headerEndIndex,
					Length:         len(bodyContent),
					Type:           "entire_body",
					RedactionBytes: redactionBytes,
				})
			} else {
				ranges = append(ranges, shared.RedactionRange{
					Start:          headerEndIndex,
					Length:         len(bodyContent),
					Type:           "entire_body",
					RedactionBytes: nil,
				})
			}
		}
	} else {
		// No title tag found, redact entire body but preserve headers
		log.Printf("[Client] No title tag found, redacting entire body content but preserving headers")

		if ciphertext != nil {
			redactionBytes := c.calculateRedactionBytes(ciphertext, headerEndIndex, len(bodyContent), 0)
			ranges = append(ranges, shared.RedactionRange{
				Start:          baseOffset + headerEndIndex,
				Length:         len(bodyContent),
				Type:           "entire_body",
				RedactionBytes: redactionBytes,
			})
		} else {
			ranges = append(ranges, shared.RedactionRange{
				Start:          headerEndIndex,
				Length:         len(bodyContent),
				Type:           "entire_body",
				RedactionBytes: nil,
			})
		}
	}

	return ranges
}
