package main

import (
	"fmt"
	"log"
	"sort"
	"strings"
	"tee-mpc/shared"
)

// WaitForCompletion returns a channel that closes when the protocol is complete
func (c *Client) WaitForCompletion() <-chan struct{} {
	return c.completionChan
}

// checkProtocolCompletion checks if all conditions are met and signals completion if so
func (c *Client) checkProtocolCompletion(reason string) {
	// *** SIMPLE PHASE-BASED COMPLETION (replacing complex batch logic) ***
	currentPhase := c.getCurrentPhase()

	log.Printf("[Client] Checking completion: %s (current phase: %s)", reason, currentPhase)

	// In the new simple approach, completion is handled automatically by phase transitions:
	// - advanceToPhase(PhaseComplete) automatically closes the completion channel
	// - This happens when incrementTranscriptCount() reaches 2 transcripts
	// - No complex state checking needed - just let the state machine work

	if currentPhase == PhaseComplete {
		log.Printf("[Client] Protocol already complete")
		return
	}

	// For debugging: show where we are in the process
	switch currentPhase {
	case PhaseHandshaking:
		log.Printf("[Client] Still in handshaking phase")
	case PhaseCollectingResponses:
		collectionComplete, _, _ := c.getBatchState()
		if collectionComplete {
			log.Printf("[Client] Responses collected, batch will be sent automatically")
		} else {
			log.Printf("[Client] Still collecting responses")
		}
	case PhaseReceivingDecryption:
		log.Printf("[Client] Waiting for batched decryption streams")
	case PhaseSendingRedaction:
		log.Printf("[Client] Redaction phase - specs will be sent automatically")
	case PhaseReceivingRedacted:
		log.Printf("[Client] Waiting for redacted streams")
	case PhaseReceivingTranscripts:
		phase, count := c.getProtocolState()
		log.Printf("[Client] Waiting for transcripts: %d/2 received (phase: %s)", count, phase)
	default:
		panic("unhandled default case")
	}
}

// sendFinishedCommand sends "finished" message to both TEE_K and TEE_T
func (c *Client) sendFinishedCommand() error {
	log.Printf("[Client] Sending finished command to both TEE_K and TEE_T")

	// *** CLEANUP: Removed redundant CompletionFlagSignedTranscriptsExpected - phase system handles this ***

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

	// Analyze response content to identify redaction ranges
	redactionSpec := c.analyzeResponseRedaction()

	// Send redaction spec to TEE_K
	msg := shared.CreateSessionMessage(shared.MsgRedactionSpec, c.sessionID, redactionSpec)
	if err := c.wsConn.WriteJSON(msg); err != nil {
		return fmt.Errorf("failed to send redaction spec to TEE_K: %v", err)
	}

	log.Printf("[Client] Sent redaction specification to TEE_K with %d ranges", len(redactionSpec.Ranges))

	// Display ranges sent to TEE_K
	for i, r := range redactionSpec.Ranges {
		if r.Type == "session_ticket" {
			log.Printf("[Client] Range %d: [%d:%d] type=%s (session ticket)", i+1, r.Start, r.Start+r.Length-1, r.Type)
		} else {
			log.Printf("[Client] Range %d: [%d:%d] type=%s (%d bytes)", i+1, r.Start, r.Start+r.Length-1, r.Type, len(r.RedactionBytes))
		}
	}

	log.Printf("[Client] Redaction specification sent successfully")

	// *** CLEANUP: Removed redundant CompletionFlagRedactedStreamsExpected - phase transition handles this ***

	// *** NEW: Advance to receiving redacted streams phase (parallel to existing logic) ***
	c.advanceToPhase(PhaseReceivingRedacted)

	// *** NEW: Automatically send finished command when entering redacted receiving phase ***
	log.Printf("[Client] Entering redacted receiving phase - automatically sending finished command")
	if err := c.sendFinishedCommand(); err != nil {
		log.Printf("[Client] Failed to send finished command: %v", err)
	}

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

				// Find where actualContent starts within the original ciphertext
				// For TLS 1.3, actualContent is at the beginning of the decrypted payload
				// For TLS 1.2, we need to account for explicit IV and other headers
				ciphertextOffset := 0
				if c.isTLS12AESGCMCipher() {
					ciphertextOffset = 8 // Skip explicit IV for TLS 1.2 AES-GCM
				}

				// Calculate redaction bytes using correct offset within ciphertext
				redactionBytes := c.calculateRedactionBytes(ciphertext, ciphertextOffset, len(actualContent), seqNum)

				// Cover full TLS record including padding
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

		// ***  Increment offset by the length of the ORIGINAL PADDED content ***
		totalOffset += len(content)
	}

	// Analyze all HTTP content as a single unit if we collected any
	if len(allHTTPContent) > 0 && len(httpContentMappings) > 0 {
		log.Printf("[Client] Analyzing combined HTTP content (%d bytes) from %d TLS records", len(allHTTPContent), len(httpContentMappings))

		// *** Use cached redaction ranges from response callback if available ***
		var combinedHTTPRanges []shared.RedactionRange

		if len(c.lastRedactionRanges) > 0 {
			log.Printf("[Client] Using cached redaction ranges from response callback (%d ranges)", len(c.lastRedactionRanges))

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
			log.Printf("[Client] No cached redaction ranges available, using automatic analysis")

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
					}
				}

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
					}
				}

				redactionRanges = append(redactionRanges, shared.RedactionRange{
					Start:          m.actualTLSOffset,
					Length:         overlapLength,
					Type:           httpRange.Type,
					RedactionBytes: redactionBytes,
				})
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
