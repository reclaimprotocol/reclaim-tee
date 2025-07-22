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

	// Analyze response content to identify redaction ranges
	redactionSpec := c.analyzeResponseRedaction()

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

	// Set flag to expect redacted streams
	c.setCompletionFlag(CompletionFlagRedactedStreamsExpected)

	return nil
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
		startPos   int
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

		log.Printf("[Client] Analyzing sequence %d: %d bytes, content type 0x%02x", seqNum, len(actualContent), contentType)

		switch contentType {
		case 0x16: // Handshake message - likely NewSessionTicket
			log.Printf("[Client] Found handshake message at offset %d (seq %d)", totalOffset, seqNum)
			if len(actualContent) >= 4 && actualContent[0] == 0x04 { // NewSessionTicket
				log.Printf("[Client] Redacting NewSessionTicket at offset %d-%d", totalOffset, totalOffset+len(actualContent)-1)

				// Redact the entire actual content of the handshake message
				redactionBytes := c.calculateRedactionBytes(ciphertext, 0, len(actualContent), seqNum)
				redactionRanges = append(redactionRanges, shared.RedactionRange{
					Start:          totalOffset,
					Length:         len(actualContent),
					Type:           "session_ticket",
					RedactionBytes: redactionBytes,
				})
			}

		case 0x17: // ApplicationData - HTTP response
			log.Printf("[Client] Found HTTP response part at offset %d (seq %d) - collecting for combined analysis", totalOffset, seqNum)

			// Collect this HTTP content for combined analysis
			httpContentMappings = append(httpContentMappings, struct {
				seqNum     uint64
				startPos   int
				length     int
				ciphertext []byte
			}{
				seqNum:     seqNum,
				startPos:   len(allHTTPContent),
				length:     len(actualContent),
				ciphertext: ciphertext,
			})

			allHTTPContent = append(allHTTPContent, actualContent...)

		case 0x15: // Alert - usually safe to keep
			log.Printf("[Client] Found TLS alert at offset %d (seq %d) - keeping visible", totalOffset, seqNum)
		}

		// ***  Increment offset by the length of the ORIGINAL PADDED content ***
		totalOffset += len(content)
	}

	// *** NEW: Analyze all HTTP content as a single unit if we collected any ***
	if len(allHTTPContent) > 0 && len(httpContentMappings) > 0 {
		log.Printf("[Client] Analyzing combined HTTP content (%d bytes) from %d TLS records", len(allHTTPContent), len(httpContentMappings))

		// Analyze the combined HTTP content for redaction ranges
		combinedHTTPRanges := c.analyzeHTTPRedactionWithBytes(allHTTPContent, 0, nil)

		// Now map these ranges back to the original TLS record positions and calculate proper redaction bytes
		for _, httpRange := range combinedHTTPRanges {
			// Find which TLS record(s) this range spans
			rangeStart := httpRange.Start
			rangeEnd := httpRange.Start + httpRange.Length

			for _, mapping := range httpContentMappings {
				mappingStart := mapping.startPos
				mappingEnd := mapping.startPos + mapping.length

				// Check if this mapping overlaps with the HTTP range
				overlapStart := max(rangeStart, mappingStart)
				overlapEnd := min(rangeEnd, mappingEnd)

				if overlapStart < overlapEnd {
					// There's an overlap - create a redaction range for this TLS record
					localStart := overlapStart - mappingStart // Position within this TLS record's content
					overlapLength := overlapEnd - overlapStart

					// Calculate the actual offset in the final transcript
					actualOffset := totalOffset
					// Need to recalculate the actual offset by finding this sequence in the original order
					tempOffset := 0
					for _, k2 := range keys {
						seqNum2 := uint64(k2)
						content2 := c.responseContentBySeq[seqNum2]
						_, contentType2 := c.removeTLSPadding(content2)

						if seqNum2 == mapping.seqNum && contentType2 == 0x17 {
							actualOffset = tempOffset + localStart
							break
						}
						tempOffset += len(content2)
					}

					// Calculate redaction bytes for this specific TLS record portion
					redactionBytes := c.calculateRedactionBytes(mapping.ciphertext, localStart, overlapLength, mapping.seqNum)

					redactionRanges = append(redactionRanges, shared.RedactionRange{
						Start:          actualOffset,
						Length:         overlapLength,
						Type:           httpRange.Type,
						RedactionBytes: redactionBytes,
					})

					log.Printf("[Client] Mapped HTTP range [%d:%d] to TLS record seq=%d at offset %d-%d",
						rangeStart, rangeEnd-1, mapping.seqNum, actualOffset, actualOffset+overlapLength-1)
				}
			}
		}
	}

	spec := shared.RedactionSpec{
		Ranges:                     redactionRanges,
		AlwaysRedactSessionTickets: true,
	}

	log.Printf("[Client] Generated redaction spec with %d ranges", len(redactionRanges))
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
