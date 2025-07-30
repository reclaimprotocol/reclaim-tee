package clientlib

import (
	"fmt"
	"log"
	"strings"
	"tee-mpc/shared"
)

// collapseAsterisks reduces consecutive asterisks to a maximum of 100 followed by "..." if more exist
func collapseAsterisks(data string) string {
	if len(data) == 0 {
		return data
	}

	var result strings.Builder
	asteriskCount := 0

	for _, char := range data {
		if char == '*' {
			asteriskCount++
		} else {
			// We hit a non-asterisk character
			if asteriskCount > 0 {
				if asteriskCount <= AsteriskCollapseThreshold {
					// Threshold or fewer asterisks, show them all
					result.WriteString(strings.Repeat("*", asteriskCount))
				} else {
					// More than threshold asterisks, show collapsed pattern
					result.WriteString(CollapsedAsteriskPattern)
				}
				asteriskCount = 0
			}
			result.WriteRune(char)
		}
	}

	// Handle trailing asterisks
	if asteriskCount > 0 {
		if asteriskCount <= AsteriskCollapseThreshold {
			result.WriteString(strings.Repeat("*", asteriskCount))
		} else {
			result.WriteString(CollapsedAsteriskPattern)
		}
	}

	return result.String()
}

// handleHandshakeComplete processes handshake completion messages from TEE_K
func (c *Client) handleHandshakeComplete(msg *shared.Message) {
	var completeData shared.HandshakeCompleteData
	if err := msg.UnmarshalData(&completeData); err != nil {
		log.Printf("[Client] Failed to unmarshal handshake complete data: %v", err)
		return
	}

	if completeData.Success {
		log.Printf("[Client] Handshake completed successfully")
	} else {
		log.Printf("[Client] Handshake completed with errors")
	}
}

// handleHandshakeKeyDisclosure handles key disclosure for certificate verification
func (c *Client) handleHandshakeKeyDisclosure(msg *shared.Message) {
	var disclosureData shared.HandshakeKeyDisclosureData
	if err := msg.UnmarshalData(&disclosureData); err != nil {
		log.Printf("[Client] Failed to unmarshal handshake key disclosure data: %v", err)
		return
	}

	fmt.Printf("[Client] Handshake complete: %s, cipher 0x%04x\n", disclosureData.Algorithm, disclosureData.CipherSuite)

	// Mark handshake as complete for response handling
	c.handshakeComplete = true

	c.advanceToPhase(PhaseCollectingResponses)

	// Initialize response sequence number to 1 (first application data after handshake)
	c.responseSeqNum = 1

	// Store disclosure for verification bundle
	c.handshakeDisclosure = &disclosureData

	// Phase 3: Redaction System - Send redacted HTTP request to TEE_K for encryption

	// Create redacted HTTP request using the redaction system
	redactedData, streamsData, err := c.createRedactedRequest(nil)
	if err != nil {
		log.Printf("[Client] Failed to create redacted request: %v", err)
		return
	}

	fmt.Printf("[Client] Sending redacted HTTP request to TEE_K\n")

	// Send redacted request to TEE_K for validation and encryption
	redactedMsg := shared.CreateMessage(shared.MsgRedactedRequest, redactedData)

	if err := c.sendMessage(redactedMsg); err != nil {
		log.Printf("[Client] Failed to send redacted request to TEE_K: %v", err)
		return
	}

	// Send redaction streams to TEE_T for stream application
	fmt.Printf("[Client] Sending redaction streams to TEE_T\n")

	fmt.Printf("[Client] EXPECTING redaction verification result from TEE_T\n")

	streamsMsg := shared.CreateMessage(shared.MsgRedactionStreams, streamsData)

	if err := c.sendMessageToTEET(streamsMsg); err != nil {
		log.Printf("[Client] Failed to send redaction streams to TEE_T: %v", err)
		return
	}
}

// NOTE: processCompleteRecords and processAllRemainingRecords functions removed
// during atomic state machine refactoring. TLS record processing now happens
// directly via processTLSRecordFromData() without buffering.

// processSingleTLSRecord handles a single, complete TLS record
func (c *Client) processSingleTLSRecord(record []byte, recordType byte, recordLength int) {
	switch recordType {
	case 0x17: // ApplicationData
		// fmt.Printf("[Client] → ApplicationData record, processing with split AEAD\n")
		c.processTLSRecord(record)

	case 0x14: // ChangeCipherSpec
		fmt.Printf("[Client] → ChangeCipherSpec record (maintenance)\n")

	case 0x15: // Alert
		fmt.Printf("[Client] → Processing alert record with split AEAD\n")
		c.processTLSRecord(record)

	case 0x16: // Handshake
		fmt.Printf("[Client] → Handshake record (post-handshake message)\n")
		if recordLength >= 1 {
			handshakeType := record[5]
			fmt.Printf("[Client] Handshake type: %d\n", handshakeType)
		}

	default:
		fmt.Printf("[Client] → Unknown record type: 0x%02x\n", recordType)
	}
}

// processTLSRecord processes a single TLS ApplicationData record using split AEAD protocol
func (c *Client) processTLSRecord(record []byte) {
	// Extract encrypted payload and tag (skip 5-byte header)
	encryptedPayload := record[5:]

	// For AES-GCM, tag is last 16 bytes of encrypted payload
	if len(encryptedPayload) < 16 {
		log.Printf("[Client] Invalid TLS record: payload too short (%d bytes)", len(encryptedPayload))
		return
	}

	tagSize := 16 // AES-GCM tag size
	tag := encryptedPayload[len(encryptedPayload)-tagSize:]

	// Extract explicit IV and encrypted data for TLS 1.2 AES-GCM
	var encryptedData []byte
	var explicitIV []byte

	// Check if this is TLS 1.2 AES-GCM response (needs explicit IV extraction)
	isTLS12AESGCMResponse := c.handshakeDisclosure != nil &&
		(c.handshakeDisclosure.CipherSuite == 0xc02f || // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			c.handshakeDisclosure.CipherSuite == 0xc02b || // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
			c.handshakeDisclosure.CipherSuite == 0xc030 || // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
			c.handshakeDisclosure.CipherSuite == 0xc02c) // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

	if isTLS12AESGCMResponse {
		// TLS 1.2 AES-GCM: explicit_iv(8) + encrypted_data + auth_tag(16)
		if len(encryptedPayload) < 8+tagSize {
			log.Printf("[Client] Invalid TLS 1.2 AES-GCM record: payload too short for explicit IV (%d bytes)", len(encryptedPayload))
			return
		}

		explicitIV = encryptedPayload[:8]
		encryptedData = encryptedPayload[8 : len(encryptedPayload)-tagSize]

		// fmt.Printf("[Client] TLS 1.2 AES-GCM: extracted explicit IV (%d bytes) and encrypted data (%d bytes), tag (%d bytes)\n",
		// 	len(explicitIV), len(encryptedData), len(tag))
		// fmt.Printf("[Client] Explicit IV: %x\n", explicitIV)
	} else {
		// TLS 1.3 or other: no explicit IV
		encryptedData = encryptedPayload[:len(encryptedPayload)-tagSize]

		// fmt.Printf("[Client] Processing TLS record: %d bytes encrypted data, %d bytes tag\n",
		// 	len(encryptedData), len(tag))
	}

	if c.isClosing {
		fmt.Printf("[Client] System is shutting down, storing record but skipping split AEAD processing\n")
		return
	}

	teetConnState := c.teetConn != nil
	if !teetConnState {
		fmt.Printf("[Client] TEE_T connection closed, storing record but skipping split AEAD processing\n")
		return
	}

	// Store ciphertext by sequence number for later decryption
	// Use the correct shared mutex to prevent race conditions
	c.responseContentMutex.Lock()
	c.ciphertextBySeq[c.responseSeqNum] = encryptedData
	// Store TLS record type for reconstruction
	c.recordTypeBySeq[c.responseSeqNum] = record[0] // TLS record type from header
	c.responseContentMutex.Unlock()

	// Prepare data to send to TEE_T for tag verification
	// Get the actual negotiated cipher suite from handshake disclosure
	cipherSuite := uint16(0x1302) // Default fallback
	if c.handshakeDisclosure != nil {
		cipherSuite = c.handshakeDisclosure.CipherSuite
	}

	encryptedResponseData := shared.EncryptedResponseData{
		EncryptedData: encryptedData,
		Tag:           tag,
		RecordHeader:  record[:5], // Include actual TLS record header from server
		SeqNum:        c.responseSeqNum,
		CipherSuite:   cipherSuite, // Use actual negotiated cipher suite
		ExplicitIV:    explicitIV,  // TLS 1.2 AES-GCM explicit IV (nil for TLS 1.3)
	}

	// Batch responses until EOF instead of sending immediately
	collectionComplete, _, _ := c.getBatchState()

	if !collectionComplete {
		// Collection not complete yet - collect packet for batch processing
		c.batchedResponses = append(c.batchedResponses, encryptedResponseData)

		// Still increment sequence number
		c.responseSeqNum++
		return // Don't send yet - wait for collection complete
	}

	// If EOF already reached, send packet immediately (shouldn't happen)
	log.Printf("[Client] EOF already reached, sending packet immediately")

	responseMsg := shared.CreateMessage(shared.MsgEncryptedResponse, encryptedResponseData)

	if err := c.sendMessageToTEET(responseMsg); err != nil {

		if c.isClosing {
			fmt.Printf("[Client] Send failed during shutdown - this is expected, continuing\n")
		} else {
			log.Printf("[Client] Failed to send encrypted response to TEE_T: %v", err)
		}
		return
	}

	// Increment sequence number for next response
	c.responseSeqNum++
}

// Send batched responses when EOF is detected
func (c *Client) sendBatchedResponses() error {

	if len(c.batchedResponses) == 0 {
		log.Printf("[Client] No response packets to send")
		return nil
	}

	log.Printf("[Client] Sending batch of %d response packets to TEE_T", len(c.batchedResponses))

	// Create batched message using new data structure
	batchedData := shared.BatchedEncryptedResponseData{
		Responses:  c.batchedResponses,
		SessionID:  c.sessionID,
		TotalCount: len(c.batchedResponses),
	}

	// Send batch to TEE_T using new message type
	batchMsg := shared.CreateMessage(shared.MsgBatchedEncryptedResponses, batchedData)

	if err := c.sendMessageToTEET(batchMsg); err != nil {
		return fmt.Errorf("failed to send batched responses to TEE_T: %v", err)
	}

	log.Printf("[Client] Successfully sent batch of %d packets to TEE_T", len(c.batchedResponses))

	c.setBatchSentToTEET()

	c.expectedRedactedStreams = len(c.batchedResponses)
	log.Printf("[Client] Expecting %d redacted streams based on batch size", c.expectedRedactedStreams)

	c.advanceToPhase(PhaseReceivingDecryption)

	// Clear the batch after successful send
	c.batchedResponses = make([]shared.EncryptedResponseData, 0)
	return nil
}

// handleResponseTagVerification handles tag verification result from TEE_T
func (c *Client) handleResponseTagVerification(msg *shared.Message) {
	var verificationData shared.ResponseTagVerificationData
	if err := msg.UnmarshalData(&verificationData); err != nil {
		log.Printf("[Client] Failed to unmarshal response tag verification: %v", err)
		return
	}

	if verificationData.Success {
		// Phase advances to PhaseSendingRedaction automatically after batch processing
	} else {
		log.Printf("[Client] Tag verification failed for seq %d: %s", verificationData.SeqNum, verificationData.Message)
	}
}

// analyzeNewSessionTicket provides details about session ticket content
func (c *Client) analyzeNewSessionTicket(data []byte) {
	if len(data) < 8 {
		fmt.Printf("[Client] NewSessionTicket too short\n")
		return
	}

	ticketLifetime := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	ticketAgeAdd := uint32(data[4])<<24 | uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])

	fmt.Printf("[Client] Ticket lifetime: %d seconds\n", ticketLifetime)
	fmt.Printf("[Client] Age add: 0x%08x\n", ticketAgeAdd)

	if len(data) > 8 {
		nonceLen := int(data[8])
		fmt.Printf("[Client] Nonce length: %d bytes\n", nonceLen)

		if len(data) > 9+nonceLen+2 {
			ticketLen := int(data[9+nonceLen])<<8 | int(data[10+nonceLen])
			fmt.Printf("[Client] Ticket length: %d bytes\n", ticketLen)
		}
	}

	fmt.Printf("[Client] This is likely a session resumption ticket, not HTTP content\n")
}

// analyzeAlertMessage analyzes TLS alert messages
func (c *Client) analyzeAlertMessage(data []byte) {
	if len(data) < 2 {
		fmt.Printf("[Client] Alert message too short\n")
		return
	}

	alertLevel := data[0]
	alertDescription := data[1]

	levelStr := "warning"
	if alertLevel == 2 {
		levelStr = "FATAL"
	}

	descStr := getClientAlertDescription(alertDescription)
	fmt.Printf("[Client] Alert: %s (%d) - %s (%d)\n", levelStr, alertLevel, descStr, alertDescription)

	// Note: We don't signal completion on CLOSE_NOTIFY since TEEs may still be processing
}

// parseDecryptedAlert parses alert level and description from decrypted alert data
func (c *Client) parseDecryptedAlert(seqNum uint64, decryptedData []byte) {
	if len(decryptedData) >= 2 {
		alertLevel := decryptedData[0]
		alertDescription := decryptedData[1]
		fmt.Printf("[Client] Alert (seq %d): level=%d, description=%d (%s)\n",
			seqNum, alertLevel, alertDescription, getClientAlertDescription(alertDescription))

		if alertDescription == 0 {
			fmt.Printf("[Client] *** CLOSE_NOTIFY ALERT DETECTED (seq %d) ***\n", seqNum)
		}

		c.analyzeAlertMessage(decryptedData)
	} else {
		log.Printf("[Client] Alert record (seq %d) too short for parsing: %d bytes", seqNum, len(decryptedData))
	}
}

// getClientAlertDescription returns alert description strings
func getClientAlertDescription(code byte) string {
	switch code {
	case 0:
		return "CLOSE_NOTIFY"
	case 20:
		return "BAD_RECORD_MAC"
	case 21:
		return "DECRYPTION_FAILED"
	case 22:
		return "RECORD_OVERFLOW"
	case 40:
		return "HANDSHAKE_FAILURE"
	case 50:
		return "DECODE_ERROR"
	case 51:
		return "DECRYPT_ERROR"
	default:
		return "UNKNOWN"
	}
}

// removeTLSPadding removes TLS 1.3 padding from decrypted content (TLS 1.2 has no padding)
func (c *Client) removeTLSPadding(data []byte) ([]byte, byte) {
	if len(data) == 0 {
		return nil, 0
	}

	// Check TLS version from cipher suite in handshake disclosure
	isTLS12 := c.handshakeDisclosure != nil && c.isTLS12CipherSuite(c.handshakeDisclosure.CipherSuite)

	if isTLS12 {
		// TLS 1.2: No inner content type or padding, content type comes from record header
		// All decrypted data is actual content, content type is always ApplicationData (0x17)
		return data, 0x17
	} else {
		// TLS 1.3: Has inner content type byte + zero padding
		// Find the last non-zero byte which indicates the content type
		lastNonZero := len(data) - 1
		for lastNonZero >= 0 && data[lastNonZero] == 0 {
			lastNonZero--
		}

		if lastNonZero < 0 {
			// All zeros, likely a padding-only record
			return nil, 0
		}

		// The byte at lastNonZero is the content type
		contentType := data[lastNonZero]
		// The data before that byte is the actual content
		actualContent := data[:lastNonZero]

		return actualContent, contentType
	}
}

// State for processing TLS records directly from TCP data
type tlsRecordState struct {
	buffer       []byte
	expectedSize int
	recordType   byte
}

var recordProcessingState = &tlsRecordState{
	buffer:       make([]byte, 0),
	expectedSize: 0,
}

// processTLSRecordFromData processes TLS records directly from raw TCP data
func (c *Client) processTLSRecordFromData(data []byte) {
	// Add new data to our processing buffer
	recordProcessingState.buffer = append(recordProcessingState.buffer, data...)

	// Process all complete records in the buffer
	for len(recordProcessingState.buffer) >= 5 {
		// Check if we have a complete TLS record header
		if recordProcessingState.expectedSize == 0 {
			// Parse TLS record header: type (1) + version (2) + length (2)
			recordProcessingState.recordType = recordProcessingState.buffer[0]
			recordLength := int(recordProcessingState.buffer[3])<<8 | int(recordProcessingState.buffer[4])
			recordProcessingState.expectedSize = 5 + recordLength
		}

		// Check if we have a complete record
		if len(recordProcessingState.buffer) >= recordProcessingState.expectedSize {
			// Extract the complete record
			record := make([]byte, recordProcessingState.expectedSize)
			copy(record, recordProcessingState.buffer[:recordProcessingState.expectedSize])

			// Remove the processed record from buffer
			recordProcessingState.buffer = recordProcessingState.buffer[recordProcessingState.expectedSize:]
			recordProcessingState.expectedSize = 0

			// Process the complete record
			recordType := record[0]
			recordLength := int(record[3])<<8 | int(record[4])
			c.processSingleTLSRecord(record, recordType, recordLength)
		} else {
			// Not enough data for complete record, wait for more
			break
		}
	}
}

// isTLS12CipherSuite checks if a cipher suite belongs to TLS 1.2
func (c *Client) isTLS12CipherSuite(cipherSuite uint16) bool {
	switch cipherSuite {
	case 0xc02f, 0xc02b, 0xc030, 0xc02c: // TLS 1.2 AES-GCM cipher suites
		return true
	case 0xcca8, 0xcca9: // TLS 1.2 ChaCha20-Poly1305 cipher suites
		return true
	default:
		return false // TLS 1.3 or other
	}
}
