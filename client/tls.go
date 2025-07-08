package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
)

// handleHandshakeComplete processes handshake completion messages from TEE_K
func (c *Client) handleHandshakeComplete(msg *Message) {
	var completeData HandshakeCompleteData
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
func (c *Client) handleHandshakeKeyDisclosure(msg *Message) {
	var disclosureData HandshakeKeyDisclosureData
	if err := msg.UnmarshalData(&disclosureData); err != nil {
		log.Printf("[Client] Failed to unmarshal handshake key disclosure data: %v", err)
		return
	}

	fmt.Printf("[Client] Handshake complete: %s, cipher 0x%04x\n", disclosureData.Algorithm, disclosureData.CipherSuite)

	// Mark handshake as complete for response handling
	c.handshakeComplete = true

	// Phase 3: Redaction System - Send redacted HTTP request to TEE_K for encryption

	// Create redacted HTTP request using the redaction system
	redactedData, streamsData, err := c.createRedactedRequest(nil)
	if err != nil {
		log.Printf("[Client] Failed to create redacted request: %v", err)
		return
	}

	fmt.Printf("[Client] Sending redacted HTTP request to TEE_K\n")

	// Send redacted request to TEE_K for validation and encryption
	redactedMsg, err := CreateMessage(MsgRedactedRequest, redactedData)
	if err != nil {
		log.Printf("[Client] Failed to create redacted request message: %v", err)
		return
	}

	if err := c.sendMessage(redactedMsg); err != nil {
		log.Printf("[Client] Failed to send redacted request to TEE_K: %v", err)
		return
	}

	// Send redaction streams to TEE_T for stream application
	fmt.Printf("[Client] Sending redaction streams to TEE_T\n")

	// Track that we're expecting redaction verification result
	c.setCompletionFlag(CompletionFlagRedactionExpected)
	fmt.Printf("[Client] EXPECTING redaction verification result from TEE_T\n")

	streamsMsg, err := CreateMessage(MsgRedactionStreams, streamsData)
	if err != nil {
		log.Printf("[Client] Failed to create redaction streams message: %v", err)
		return
	}

	if err := c.sendMessageToTEET(streamsMsg); err != nil {
		log.Printf("[Client] Failed to send redaction streams to TEE_T: %v", err)
		return
	}
}

// verifyCertificateInTraffic verifies certificate packet in captured traffic
func (c *Client) verifyCertificateInTraffic(certPacket []byte) bool {
	// Search for the certificate packet in captured traffic
	for _, traffic := range c.capturedTraffic {
		if bytes.Contains(traffic, certPacket) {
			return true
		}
	}
	return false
}

// decryptAndVerifyCertificate decrypts and verifies certificate using disclosed keys
func (c *Client) decryptAndVerifyCertificate(disclosure *HandshakeKeyDisclosureData) bool {
	// Extract the encrypted payload from the certificate packet
	// TLS record format: [type(1)] [version(2)] [length(2)] [payload(length)]
	if len(disclosure.CertificatePacket) < 5 {
		fmt.Println(" Certificate packet too short")
		return false
	}

	encryptedPayload := disclosure.CertificatePacket[5:] // Skip TLS record header
	fmt.Printf(" Decrypting certificate payload (%d bytes)\n", len(encryptedPayload))

	// Create AEAD cipher based on algorithm
	var aead cipher.AEAD
	var err error

	switch disclosure.Algorithm {
	case "AES-128-GCM":
		block, err := aes.NewCipher(disclosure.HandshakeKey[:16])
		if err != nil {
			fmt.Printf(" Failed to create AES-128 cipher: %v\n", err)
			return false
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			fmt.Printf(" Failed to create GCM: %v\n", err)
			return false
		}
	case "AES-256-GCM":
		block, err := aes.NewCipher(disclosure.HandshakeKey)
		if err != nil {
			fmt.Printf(" Failed to create AES-256 cipher: %v\n", err)
			return false
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			fmt.Printf(" Failed to create GCM: %v\n", err)
			return false
		}
	default:
		fmt.Printf(" Unsupported algorithm: %s\n", disclosure.Algorithm)
		return false
	}

	// Create nonce (IV for this record)
	nonce := make([]byte, len(disclosure.HandshakeIV))
	copy(nonce, disclosure.HandshakeIV)
	// For handshake messages, sequence number is typically 1 for certificate
	// XOR sequence number with IV
	nonce[len(nonce)-1] ^= 1

	// Additional authenticated data is the TLS record header
	aad := disclosure.CertificatePacket[:5]

	// Decrypt the payload
	plaintext, err := aead.Open(nil, nonce, encryptedPayload, aad)
	if err != nil {
		fmt.Printf(" Failed to decrypt certificate: %v\n", err)
		return false
	}

	fmt.Printf(" Successfully decrypted %d bytes\n", len(plaintext))

	// Remove padding and find content type
	i := len(plaintext) - 1
	for i >= 0 && plaintext[i] == 0 {
		i--
	}
	if i < 0 {
		fmt.Println(" Certificate record is all padding")
		return false
	}

	contentType := plaintext[i]
	actualData := plaintext[:i]

	if contentType != 22 { // handshake content type
		fmt.Printf(" Expected handshake content type (22), got %d\n", contentType)
		return false
	}

	// Parse the certificate handshake message
	return c.parseCertificateMessage(actualData)
}

// parseCertificateMessage parses TLS certificate message content
func (c *Client) parseCertificateMessage(data []byte) bool {
	if len(data) < 4 {
		fmt.Println(" Certificate message too short")
		return false
	}

	msgType := data[0]
	if msgType != 11 { // Certificate handshake type
		fmt.Printf(" Expected certificate message type (11), got %d\n", msgType)
		return false
	}

	// Skip handshake message header and certificate request context
	offset := 4 // handshake header
	if offset >= len(data) {
		fmt.Println(" No data after handshake header")
		return false
	}

	contextLen := int(data[offset])
	offset++

	if offset+contextLen > len(data) {
		fmt.Println(" Invalid certificate request context length")
		return false
	}
	offset += contextLen // skip context

	// Parse certificate list length
	if offset+3 > len(data) {
		fmt.Println(" No certificate list length")
		return false
	}

	certListLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
	offset += 3

	if offset+certListLen > len(data) {
		fmt.Println(" Invalid certificate list length")
		return false
	}

	// Parse certificates
	certCount := 0
	for offset < len(data) && offset < 4+int(data[1])<<16|int(data[2])<<8|int(data[3]) {
		if offset+3 > len(data) {
			break
		}

		certLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
		offset += 3

		if offset+certLen > len(data) {
			fmt.Println(" Invalid certificate length")
			return false
		}

		certData := data[offset : offset+certLen]
		offset += certLen

		// Parse the certificate
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			fmt.Printf(" Failed to parse certificate %d: %v\n", certCount, err)
			return false
		}

		fmt.Printf(" Certificate %d: %s\n", certCount, cert.Subject.CommonName)
		certCount++

		// Skip extensions length and data
		if offset+2 <= len(data) {
			extLen := int(data[offset])<<8 | int(data[offset+1])
			offset += 2 + extLen
		}
	}

	if certCount > 0 {
		fmt.Printf(" Successfully verified %d certificates from decrypted packet\n", certCount)
		return true
	}

	fmt.Println(" No certificates found in decrypted packet")
	return false
}

// NOTE: processCompleteRecords and processAllRemainingRecords functions removed
// during atomic state machine refactoring. TLS record processing now happens
// directly via processTLSRecordFromData() without buffering.

// processSingleTLSRecord handles a single, complete TLS record
func (c *Client) processSingleTLSRecord(record []byte, recordType byte, recordLength int) {
	switch recordType {
	case 0x17: // ApplicationData
		fmt.Printf("[Client] → ApplicationData record, processing with split AEAD\n")
		c.processTLSRecord(record)

	case 0x14: // ChangeCipherSpec
		fmt.Printf("[Client] → ChangeCipherSpec record (maintenance)\n")

	case 0x15: // Alert
		fmt.Printf("[Client] → Alert record\n")
		if recordLength >= 2 {
			alertLevel := record[5]
			alertDescription := record[6]
			fmt.Printf("[Client] Alert: level=%d, description=%d (%s)\n",
				alertLevel, alertDescription, getClientAlertDescription(alertDescription))

			if alertDescription == 0 {
				fmt.Printf("[Client] *** CLOSE_NOTIFY ALERT DETECTED ***\n")
			}

			c.analyzeAlertMessage(record[5 : 5+recordLength])
		}

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
	fmt.Printf("[Client] ENTERING processTLSRecord with responseSeqNum=%d\n", c.responseSeqNum)

	// *** ALWAYS store record for transcript creation ***
	c.capturedTraffic = append(c.capturedTraffic, record)
	fmt.Printf("[Client] Stored TLS record for transcript (%d bytes, total records: %d)\n",
		len(record), len(c.capturedTraffic))

	// Extract encrypted payload and tag (skip 5-byte header)
	encryptedPayload := record[5:]

	// For AES-GCM, tag is last 16 bytes of encrypted payload
	if len(encryptedPayload) < 16 {
		log.Printf("[Client] Invalid TLS record: payload too short (%d bytes)", len(encryptedPayload))
		return
	}

	tagSize := 16 // AES-GCM tag size
	encryptedData := encryptedPayload[:len(encryptedPayload)-tagSize]
	tag := encryptedPayload[len(encryptedPayload)-tagSize:]

	fmt.Printf("[Client] Processing TLS record: %d bytes encrypted data, %d bytes tag\n",
		len(encryptedData), len(tag))

	// *** Check if system is shutting down or TEE_T connection is closed ***
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
	// *** FIX: Use the correct shared mutex to prevent race conditions ***
	c.responseContentMutex.Lock()
	c.ciphertextBySeq[c.responseSeqNum] = encryptedData
	c.responseContentMutex.Unlock()

	// Prepare data to send to TEE_T for tag verification
	encryptedResponseData := EncryptedResponseData{
		EncryptedData: encryptedData,
		Tag:           tag,
		RecordHeader:  record[:5], // Include actual TLS record header from server
		SeqNum:        c.responseSeqNum,
		CipherSuite:   0x1302, // TLS_AES_256_GCM_SHA384 - TODO: get from handshake
	}

	responseMsg, err := CreateMessage(MsgEncryptedResponse, encryptedResponseData)
	if err != nil {
		log.Printf("[Client] Failed to create encrypted response message: %v", err)
		return
	}

	if err := c.sendMessageToTEET(responseMsg); err != nil {
		fmt.Printf("[Client] DEBUG: sendMessageToTEET FAILED: %v\n", err)

		// *** Don't treat this as fatal during shutdown ***
		if c.isClosing {
			fmt.Printf("[Client] Send failed during shutdown - this is expected, continuing\n")
		} else {
			log.Printf("[Client] Failed to send encrypted response to TEE_T: %v", err)
		}
		return
	}

	// Track expected decryption stream ONLY if we successfully sent to TEE_T
	atomic.AddInt64(&c.recordsSent, 1)
	fmt.Printf("[Client] EXPECTING decryption stream #%d\n", atomic.LoadInt64(&c.recordsSent))
	c.responseSeqNum++
}

// handleResponseTagVerification handles tag verification result from TEE_T
func (c *Client) handleResponseTagVerification(msg *Message) {
	var verificationData ResponseTagVerificationData
	if err := msg.UnmarshalData(&verificationData); err != nil {
		log.Printf("[Client] Failed to unmarshal response tag verification: %v", err)
		return
	}

	if verificationData.Success {
		fmt.Printf("[Client] Response tag verification successful (seq=%d)\n", verificationData.SeqNum)

		// *** FIX: Increment the processed records counter ***
		atomic.AddInt64(&c.recordsProcessed, 1)

		// Check for protocol completion now that a record has been fully processed by TEE_T
		c.checkProtocolCompletion("response tag verified")
	} else {
		log.Printf("[Client] Response tag verification FAILED (seq=%d): %s",
			verificationData.SeqNum, verificationData.Message)
	}
}

// handleResponseDecryptionStream handles decryption stream from TEE_K
func (c *Client) handleResponseDecryptionStream(msg *Message) {
	var streamData ResponseDecryptionStreamData
	if err := msg.UnmarshalData(&streamData); err != nil {
		log.Printf("[Client] Failed to unmarshal response decryption stream: %v", err)
		return
	}

	log.Printf("[Client] Received decryption stream (%d bytes) for seq=%d", len(streamData.DecryptionStream), streamData.SeqNum)

	// Store the decryption stream
	c.responseContentMutex.Lock()
	c.decryptionStreamBySeq[streamData.SeqNum] = streamData.DecryptionStream

	// Decrypt the corresponding pending response data
	ciphertext, exists := c.ciphertextBySeq[streamData.SeqNum]
	if !exists {
		c.responseContentMutex.Unlock()
		log.Printf("[Client] No pending response data found for sequence %d", streamData.SeqNum)
		return
	}

	// XOR ciphertext with decryption stream to get plaintext
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		plaintext[i] = ciphertext[i] ^ streamData.DecryptionStream[i]
	}
	c.responseContentMutex.Unlock()

	log.Printf("[Client] Successfully decrypted response (%d bytes, seq=%d)", len(plaintext), streamData.SeqNum)

	// *** FIX: Increment the received streams counter ***
	atomic.AddInt64(&c.decryptionStreamsReceived, 1)
	log.Printf("[Client] RECEIVED decryption stream #%d of %d expected",
		atomic.LoadInt64(&c.decryptionStreamsReceived), atomic.LoadInt64(&c.recordsSent))

	// Handle the decrypted content
	c.handleDecryptedResponse(&Message{
		Type:      MsgDecryptedResponse,
		SessionID: c.sessionID,
		Data: DecryptedResponseData{
			SeqNum:        streamData.SeqNum,
			PlaintextData: plaintext,
			Success:       true,
		},
	})
}

// handleDecryptedResponse handles final decrypted response
func (c *Client) handleDecryptedResponse(msg *Message) {
	var responseData DecryptedResponseData
	if err := msg.UnmarshalData(&responseData); err != nil {
		log.Printf("[Client] Failed to unmarshal decrypted response data: %v", err)
		return
	}

	if !responseData.Success {
		log.Printf("[Client] Response decryption failed (seq=%d)", responseData.SeqNum)
		return
	}

	// 1. Store decrypted response content
	c.responseContentMutex.Lock()
	c.responseContentBySeq[responseData.SeqNum] = responseData.PlaintextData
	c.responseContentMutex.Unlock()

	// 2. Analyze the content of the decrypted response
	c.analyzeServerContent(responseData.PlaintextData, responseData.SeqNum)

	// 3. Check for completion after storing and analyzing content
	c.checkProtocolCompletion("decrypted response received")
}

// analyzeServerContent analyzes the decrypted server response to identify its type
// (e.g., handshake, application data, alert) and handle it accordingly.
func (c *Client) analyzeServerContent(content []byte, seqNum uint64) {
	fmt.Printf("[Client] ANALYZING SERVER CONTENT (seq=%d, %d bytes):\n", seqNum, len(content))

	if len(content) == 0 {
		fmt.Printf("[Client] Empty content received\n")
		return
	}

	// Remove TLS padding and extract actual content
	actualContent, contentType := c.removeTLSPadding(content)
	if len(actualContent) == 0 {
		fmt.Printf("[Client] No content after removing TLS padding\n")
		return
	}

	fmt.Printf("[Client] Content type: 0x%02x, actual data: %d bytes\n", contentType, len(actualContent))

	switch contentType {
	case 0x16: // Handshake message in application data phase
		fmt.Printf("[Client] POST-HANDSHAKE MESSAGE:\n")
		c.analyzeHandshakeMessage(actualContent)
		// This is NewSessionTicket - not the HTTP response we're waiting for

	case 0x17: // ApplicationData - this should be the HTTP response
		fmt.Printf("[Client] HTTP APPLICATION DATA:\n")
		c.analyzeHTTPContent(actualContent)

		// Track that HTTP response content has been received (but don't complete yet - wait for TCP EOF)
		if c.httpRequestSent && c.httpResponseExpected && !c.httpResponseReceived {
			c.httpResponseReceived = true
			fmt.Printf("[Client] HTTP response content received - waiting for TCP EOF to complete protocol\n")
		}

	case 0x15: // Alert
		fmt.Printf("[Client] TLS ALERT:\n")
		c.analyzeAlertMessage(actualContent)

	default:
		fmt.Printf("[Client] UNKNOWN CONTENT TYPE: 0x%02x\n", contentType)
		fmt.Printf("[Client] Raw data preview: %x\n", actualContent[:min(64, len(actualContent))])
	}
}

// analyzeHandshakeMessage analyzes post-handshake messages
func (c *Client) analyzeHandshakeMessage(data []byte) {
	if len(data) < 4 {
		fmt.Printf("[Client] Handshake message too short: %d bytes\n", len(data))
		return
	}

	handshakeType := data[0]
	msgLength := int(data[1])<<16 | int(data[2])<<8 | int(data[3])

	switch handshakeType {
	case 0x00:
		fmt.Printf("[Client] → HelloRequest (unexpected in TLS 1.3)\n")
	case 0x01:
		fmt.Printf("[Client] → ClientHello (unexpected post-handshake)\n")
	case 0x02:
		fmt.Printf("[Client] → ServerHello (unexpected post-handshake)\n")
	case 0x04:
		fmt.Printf("[Client] → NewSessionTicket (%d bytes)\n", msgLength)
		c.analyzeNewSessionTicket(data[4:])
	case 0x08:
		fmt.Printf("[Client] → EncryptedExtensions (%d bytes)\n", msgLength)
	case 0x0b:
		fmt.Printf("[Client] → Certificate (%d bytes)\n", msgLength)
	case 0x0d:
		fmt.Printf("[Client] → CertificateRequest (%d bytes)\n", msgLength)
	case 0x0f:
		fmt.Printf("[Client] → CertificateVerify (%d bytes)\n", msgLength)
	case 0x14:
		fmt.Printf("[Client] → Finished (%d bytes)\n", msgLength)
	case 0x18:
		fmt.Printf("[Client] → KeyUpdate (%d bytes)\n", msgLength)
	default:
		fmt.Printf("[Client] → Unknown handshake type: 0x%02x (%d bytes)\n", handshakeType, msgLength)
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

// analyzeHTTPContent analyzes what should be HTTP response data
func (c *Client) analyzeHTTPContent(data []byte) {
	if len(data) == 0 {
		fmt.Printf("[Client] No HTTP data\n")
		return
	}

	// Check if this looks like HTTP
	dataStr := string(data)

	// Check for HTTP response status line
	if strings.HasPrefix(dataStr, "HTTP/1.1 ") || strings.HasPrefix(dataStr, "HTTP/1.0 ") {
		fmt.Printf("[Client] VALID HTTP RESPONSE DETECTED!\n")
		lines := strings.Split(dataStr, "\r\n")
		if len(lines) > 0 {
			fmt.Printf("[Client] Status line: %s\n", lines[0])
		}

		// Show response content (truncated if long)
		if len(dataStr) > 500 {
			fmt.Printf("[Client] Response content:\n%s\n... (truncated, total %d bytes)\n", dataStr[:500], len(data))
		} else {
			fmt.Printf("[Client] Response content:\n%s\n", dataStr)
		}
	} else {
		fmt.Printf("[Client] NON-HTTP APPLICATION DATA (binary content):\n")

		// Check if it's mostly printable
		printableCount := 0
		for _, b := range data[:min(64, len(data))] {
			if (b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D {
				printableCount++
			}
		}

		threshold := min(64, len(data))
		if float64(printableCount)/float64(threshold) > 0.7 {
			fmt.Printf("[Client] Appears to be text data: %s\n", dataStr[:min(200, len(dataStr))])
		} else {
			fmt.Printf("[Client] Appears to be binary data: %x\n", data[:min(64, len(data))])
		}
	}
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

// removeTLSPadding removes TLS 1.3 padding from decrypted content
func (c *Client) removeTLSPadding(data []byte) ([]byte, byte) {
	if len(data) == 0 {
		return nil, 0
	}

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

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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
