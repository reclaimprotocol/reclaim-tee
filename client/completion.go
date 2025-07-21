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

	// 3. Process each sequence number in the correct order.
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
			log.Printf("[Client] Found HTTP response at offset %d (seq %d)", totalOffset, seqNum)
			httpRanges := c.analyzeHTTPRedactionWithBytes(actualContent, totalOffset, ciphertext)
			redactionRanges = append(redactionRanges, httpRanges...)

		case 0x15: // Alert - usually safe to keep
			log.Printf("[Client] Found TLS alert at offset %d (seq %d) - keeping visible", totalOffset, seqNum)
		}

		// *** FIX: Increment offset by the length of the ORIGINAL PADDED content ***
		totalOffset += len(content)
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

	// NEW STRATEGY: Redact EVERYTHING except the title content for github.com
	// Find the title tags and preserve only the content inside them
	titleStartTag := "<title>"
	titleEndTag := "</title>"
	titleStartIndex := strings.Index(httpStr, titleStartTag)

	if titleStartIndex != -1 {
		titleContentStartIndex := titleStartIndex + len(titleStartTag)
		titleEndIndex := strings.Index(httpStr[titleContentStartIndex:], titleEndTag)

		if titleEndIndex != -1 {
			// Adjust titleEndIndex to be absolute
			titleEndIndex = titleContentStartIndex + titleEndIndex

			log.Printf("[Client] Found title content at offset %d-%d (preserving this content)",
				titleContentStartIndex, titleEndIndex-1)

			// Redact everything BEFORE the title content
			if titleContentStartIndex > 0 {
				beforeTitleLength := titleContentStartIndex
				redactionBytes := c.calculateRedactionBytes(ciphertext, 0, beforeTitleLength, 0)

				ranges = append(ranges, shared.RedactionRange{
					Start:          baseOffset,
					Length:         beforeTitleLength,
					Type:           "everything_before_title",
					RedactionBytes: redactionBytes,
				})

				log.Printf("[Client] Redacting everything before title: offset %d-%d (%d bytes)",
					baseOffset, baseOffset+beforeTitleLength-1, beforeTitleLength)
			}

			// Redact everything AFTER the title content
			if titleEndIndex < len(httpStr) {
				afterTitleStart := titleEndIndex
				afterTitleLength := len(httpStr) - afterTitleStart
				redactionBytes := c.calculateRedactionBytes(ciphertext, afterTitleStart, afterTitleLength, 0)

				ranges = append(ranges, shared.RedactionRange{
					Start:          baseOffset + afterTitleStart,
					Length:         afterTitleLength,
					Type:           "everything_after_title",
					RedactionBytes: redactionBytes,
				})

				log.Printf("[Client] Redacting everything after title: offset %d-%d (%d bytes)",
					baseOffset+afterTitleStart, baseOffset+afterTitleStart+afterTitleLength-1, afterTitleLength)
			}
		} else {
			// No closing title tag found, redact everything
			log.Printf("[Client] No closing title tag found, redacting entire content")
			redactionBytes := c.calculateRedactionBytes(ciphertext, 0, len(httpStr), 0)

			ranges = append(ranges, shared.RedactionRange{
				Start:          baseOffset,
				Length:         len(httpStr),
				Type:           "entire_content",
				RedactionBytes: redactionBytes,
			})
		}
	} else {
		// No title tag found, redact everything
		log.Printf("[Client] No title tag found, redacting entire content")
		redactionBytes := c.calculateRedactionBytes(ciphertext, 0, len(httpStr), 0)

		ranges = append(ranges, shared.RedactionRange{
			Start:          baseOffset,
			Length:         len(httpStr),
			Type:           "entire_content",
			RedactionBytes: redactionBytes,
		})
	}

	return ranges
}
