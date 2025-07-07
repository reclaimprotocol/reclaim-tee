package main

import (
	"fmt"
	"log"
	"strings"
	"tee-mpc/shared"
)

// WaitForCompletion returns a channel that closes when the protocol is complete
func (c *Client) WaitForCompletion() <-chan struct{} {
	return c.completionChan
}

// checkProtocolCompletion checks if all conditions are met and signals completion if so
func (c *Client) checkProtocolCompletion(reason string) {
	c.completionMutex.Lock()
	defer c.completionMutex.Unlock()

	// Completion conditions:
	// 1. EOF reached (TCP connection closed)
	// 2. All split AEAD records processed (or no records sent)
	// 3. Redaction result received (if expected)
	// 4. Signed transcripts received from both TEE_K and TEE_T (if expected)

	eofCondition := c.eofReached
	recordsCondition := c.recordsSent == 0 || c.recordsProcessed >= c.recordsSent
	redactionCondition := !c.expectingRedactionResult || c.receivedRedactionResult

	// Check if split AEAD processing is complete (conditions 1-3)
	splitAEADComplete := eofCondition && recordsCondition && redactionCondition

	// IMPORTANT: Only proceed with redaction and completion if EOF has been reached
	// This ensures all TLS records (including alerts) have been received and processed
	// before we send redaction specs to TEE_K
	if !eofCondition {
		log.Printf("[Client] 🎯 Waiting for EOF before proceeding with redaction (records: %d/%d, EOF: %v)",
			c.recordsProcessed, c.recordsSent, c.eofReached)
		return
	}

	// If split AEAD is complete but we haven't sent redaction spec yet, send it now
	if splitAEADComplete && !c.expectingRedactedStreams && !c.expectingSignedTranscripts {
		log.Printf("[Client] 🎯 Split AEAD processing complete and EOF reached - sending redaction specification")
		if err := c.sendRedactionSpec(); err != nil {
			log.Printf("[Client] Failed to send redaction spec: %v", err)
			return
		}
		// Note: expectingRedactedStreams is set to true in sendRedactionSpec
	}

	// If redaction spec sent but we haven't sent finished command yet, send it now
	// (For now, we'll skip waiting for redacted streams and proceed to finished command)
	if splitAEADComplete && c.expectingRedactedStreams && !c.expectingSignedTranscripts {
		log.Printf("[Client] 🎯 Redaction spec sent - sending finished command")
		if err := c.sendFinishedCommand(); err != nil {
			log.Printf("[Client] Failed to send finished command: %v", err)
			return
		}
		// Note: expectingSignedTranscripts is set to true in sendFinishedCommand
	}

	// Final completion condition: signed transcripts received AND signatures valid
	transcriptCondition := !c.expectingSignedTranscripts || (c.receivedTEEKTranscript && c.receivedTEETTranscript && c.teeKSignatureValid && c.teeTSignatureValid)

	allConditionsMet := splitAEADComplete && transcriptCondition

	if allConditionsMet {
		c.completionOnce.Do(func() {
			log.Printf("[Client] 🎯 All protocol conditions met (including signature validation) - completing client processing")
			close(c.completionChan)
		})
	} else if splitAEADComplete && c.expectingSignedTranscripts &&
		c.receivedTEEKTranscript && c.receivedTEETTranscript &&
		(!c.teeKSignatureValid || !c.teeTSignatureValid) {
		// Special case: All transcripts received but signatures invalid
		log.Printf("[Client] ❌ Protocol completion BLOCKED due to invalid signatures (TEE_K: %v, TEE_T: %v)",
			c.teeKSignatureValid, c.teeTSignatureValid)
	}
}

// sendFinishedCommand sends "finished" message to both TEE_K and TEE_T
func (c *Client) sendFinishedCommand() error {
	log.Printf("[Client] Sending finished command to both TEE_K and TEE_T")

	// Set flag to expect signed transcripts
	c.expectingSignedTranscripts = true

	finishedMsg := shared.FinishedMessage{
		Source: "client",
	}

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

	log.Printf("[Client] 📝 Now waiting for signed transcripts from both TEE_K and TEE_T...")

	return nil
}

// sendRedactionSpec sends redaction specification to TEE_K
func (c *Client) sendRedactionSpec() error {
	log.Printf("[Client] 📝 Generating and sending redaction specification to TEE_K...")

	// Analyze response content to identify redaction ranges
	redactionSpec := c.analyzeResponseRedaction()

	// Send redaction spec to TEE_K
	msg := shared.CreateSessionMessage(shared.MsgRedactionSpec, c.sessionID, redactionSpec)
	if err := c.wsConn.WriteJSON(msg); err != nil {
		return fmt.Errorf("failed to send redaction spec to TEE_K: %v", err)
	}

	log.Printf("[Client] 📝 Sent redaction specification to TEE_K with %d ranges", len(redactionSpec.Ranges))

	// Set flag to expect redacted streams
	c.expectingRedactedStreams = true

	return nil
}

// calculateRedactionBytes calculates what should replace parts of decryption stream to produce '*' when XORed with ciphertext
func (c *Client) calculateRedactionBytes(ciphertext []byte, startOffset, length int) []byte {
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

// analyzeResponseRedaction analyzes all response content to identify redaction ranges and calculate redaction bytes
func (c *Client) analyzeResponseRedaction() shared.RedactionSpec {
	log.Printf("[Client] 📝 Analyzing response content for redaction ranges...")

	c.responseContentMutex.Lock()
	defer c.responseContentMutex.Unlock()

	var redactionRanges []shared.RedactionRange
	totalOffset := 0

	// Process each sequence number in order
	for seqNum := uint64(0); seqNum < uint64(len(c.responseContentBySeq)); seqNum++ {
		content, exists := c.responseContentBySeq[seqNum]
		if !exists {
			continue
		}

		// Get corresponding ciphertext for redaction byte calculation
		ciphertext, ciphertextExists := c.ciphertextBySeq[seqNum]
		if !ciphertextExists {
			log.Printf("[Client] 📝 Warning: No ciphertext found for seq %d", seqNum)
			totalOffset += len(content)
			continue
		}

		log.Printf("[Client] 📝 Analyzing sequence %d: %d bytes", seqNum, len(content))

		// Remove TLS padding and extract actual content
		actualContent := c.removeTLSPadding(content)
		if len(actualContent) == 0 {
			totalOffset += len(content)
			continue
		}

		// Check content type
		contentType := actualContent[len(actualContent)-1]
		actualData := actualContent[:len(actualContent)-1]

		switch contentType {
		case 0x16: // Handshake message - likely NewSessionTicket
			log.Printf("[Client] 📝 Found handshake message at offset %d (seq %d)", totalOffset, seqNum)
			if len(actualData) >= 4 && actualData[0] == 0x04 { // NewSessionTicket
				log.Printf("[Client] 📝 Redacting NewSessionTicket at offset %d-%d", totalOffset, totalOffset+len(content)-1)

				redactionBytes := c.calculateRedactionBytes(ciphertext, 0, len(content))
				redactionRanges = append(redactionRanges, shared.RedactionRange{
					Start:          totalOffset,
					Length:         len(content),
					Type:           "session_ticket",
					RedactionBytes: redactionBytes,
				})
			}

		case 0x17: // ApplicationData - HTTP response
			log.Printf("[Client] 📝 Found HTTP response at offset %d (seq %d)", totalOffset, seqNum)
			httpRanges := c.analyzeHTTPRedactionWithBytes(actualData, totalOffset, ciphertext)
			redactionRanges = append(redactionRanges, httpRanges...)

		case 0x15: // Alert - usually safe to keep
			log.Printf("[Client] 📝 Found TLS alert at offset %d (seq %d) - keeping visible", totalOffset, seqNum)
		}

		totalOffset += len(content)
	}

	spec := shared.RedactionSpec{
		Ranges:                     redactionRanges,
		AlwaysRedactSessionTickets: true,
	}

	log.Printf("[Client] 📝 Generated redaction spec with %d ranges", len(redactionRanges))
	for i, r := range redactionRanges {
		log.Printf("[Client] 📝 Range %d: [%d:%d] type=%s (%d redaction bytes)", i+1, r.Start, r.Start+r.Length-1, r.Type, len(r.RedactionBytes))
	}

	return spec
}

// analyzeHTTPRedactionWithBytes identifies sensitive parts within HTTP response content and calculates redaction bytes
func (c *Client) analyzeHTTPRedactionWithBytes(httpData []byte, baseOffset int, ciphertext []byte) []shared.RedactionRange {
	var ranges []shared.RedactionRange

	httpStr := string(httpData)

	// Look for common sensitive patterns in HTTP responses
	sensitivePatterns := []struct {
		pattern string
		name    string
	}{
		{"Set-Cookie:", "cookie"},
		{"Authorization:", "auth_header"},
		{"X-Auth-Token:", "auth_token"},
		{"X-Session-ID:", "session_id"},
		{"X-CSRF-Token:", "csrf_token"},
		{"ETag:", "etag"},
		{"Date:", "date"},
		{"Alt-Svc:", "alt_svc"},
	}

	for _, p := range sensitivePatterns {
		start := 0
		for {
			index := strings.Index(httpStr[start:], p.pattern)
			if index == -1 {
				break
			}

			absoluteIndex := start + index
			// Find the end of the line
			endIndex := strings.Index(httpStr[absoluteIndex:], "\r\n")
			if endIndex == -1 {
				endIndex = strings.Index(httpStr[absoluteIndex:], "\n")
				if endIndex == -1 {
					endIndex = len(httpStr) - absoluteIndex
				}
			}

			rangeStart := baseOffset + absoluteIndex
			rangeLength := endIndex

			log.Printf("[Client] 📝 Found sensitive pattern '%s' at offset %d-%d",
				p.pattern, rangeStart, rangeStart+rangeLength-1)

			// Calculate redaction bytes using ciphertext coordinates
			// The HTTP data corresponds to the beginning of the ciphertext
			ciphertextOffset := absoluteIndex // Position within the HTTP data portion
			redactionBytes := c.calculateRedactionBytes(ciphertext, ciphertextOffset, rangeLength)

			ranges = append(ranges, shared.RedactionRange{
				Start:          rangeStart,
				Length:         rangeLength,
				Type:           p.name,
				RedactionBytes: redactionBytes,
			})

			start = absoluteIndex + endIndex + 1
		}
	}

	return ranges
}
