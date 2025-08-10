package clientlib

import (
	"fmt"
	"strings"
	teeproto "tee-mpc/proto"
	"tee-mpc/shared"
	"time"

	"go.uber.org/zap"
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
		c.logger.Error("Failed to unmarshal handshake complete data", zap.Error(err))
		return
	}

	if completeData.Success {
		c.logger.Info("Handshake completed successfully")
	} else {
		c.logger.Error("Handshake completed with errors")
	}
}

// handleHandshakeKeyDisclosure handles key disclosure for certificate verification
func (c *Client) handleHandshakeKeyDisclosure(msg *shared.Message) {
	var disclosureData shared.HandshakeKeyDisclosureData
	if err := msg.UnmarshalData(&disclosureData); err != nil {
		c.logger.Error("Failed to unmarshal handshake key disclosure data", zap.Error(err))
		return
	}

	c.logger.Info("Handshake complete",
		zap.String("algorithm", disclosureData.Algorithm),
		zap.Uint16("cipher_suite", disclosureData.CipherSuite))

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
		c.logger.Error("Failed to create redacted request", zap.Error(err))
		return
	}

	c.logger.Info("Sending redacted HTTP request to TEE_K")

	// Log what TEE_K will see (the redacted request)
	c.logger.Info("TEE_K will receive redacted request",
		zap.Int("redacted_request_length", len(redactedData.RedactedRequest)),
		zap.Int("redaction_ranges_count", len(redactedData.RedactionRanges)),
		zap.Int("commitments_count", len(redactedData.Commitments)))

	// Show the redacted request content that TEE_K will see
	prettyRedactedRequest := make([]byte, len(redactedData.RedactedRequest))
	copy(prettyRedactedRequest, redactedData.RedactedRequest)

	// Overlay '*' over redacted ranges for display
	for _, r := range redactedData.RedactionRanges {
		end := r.Start + r.Length
		if r.Start >= 0 && end <= len(prettyRedactedRequest) {
			for i := r.Start; i < end; i++ {
				prettyRedactedRequest[i] = '*'
			}
		}
	}

	c.logger.Info("TEE_K redacted request content",
		zap.String("redacted_request", string(prettyRedactedRequest)))

	// Log redaction ranges details
	for i, r := range redactedData.RedactionRanges {
		c.logger.Info("Redaction range for TEE_K",
			zap.Int("index", i),
			zap.Int("start", r.Start),
			zap.Int("length", r.Length),
			zap.String("type", r.Type))
	}

	// Send redacted request to TEE_K for validation and encryption
	// Convert redaction ranges to protobuf format
	var pbRanges []*teeproto.RequestRedactionRange
	for _, r := range redactedData.RedactionRanges {
		pbRanges = append(pbRanges, &teeproto.RequestRedactionRange{
			Start:          int32(r.Start),
			Length:         int32(r.Length),
			Type:           r.Type,
			RedactionBytes: r.RedactionBytes,
		})
	}

	env := &teeproto.Envelope{
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_RedactedRequest{
			RedactedRequest: &teeproto.RedactedRequest{
				RedactedRequest: redactedData.RedactedRequest,
				Commitments:     redactedData.Commitments,
				RedactionRanges: pbRanges,
			},
		},
	}

	if err := c.sendEnvelope(env); err != nil {
		c.logger.Error("Failed to send redacted request to TEE_K", zap.Error(err))
		return
	}

	// Send redaction streams to TEE_T for stream application
	c.logger.Info("Sending redaction streams to TEE_T")

	c.logger.Info("EXPECTING redaction verification result from TEE_T")

	env = &teeproto.Envelope{
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_RedactionStreams{
			RedactionStreams: &teeproto.RedactionStreams{
				Streams:        streamsData.Streams,
				CommitmentKeys: streamsData.CommitmentKeys,
			},
		},
	}

	if err := c.sendEnvelopeToTEET(env); err != nil {
		c.logger.Error("Failed to send redaction streams to TEE_T", zap.Error(err))
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
		c.logger.Info("→ ChangeCipherSpec record (maintenance)")

	case 0x15: // Alert
		c.logger.Info("→ Processing alert record with split AEAD")
		c.processTLSRecord(record)

	case 0x16: // Handshake
		c.logger.Info("→ Handshake record (post-handshake message)")
		if recordLength >= 1 {
			handshakeType := record[5]
			c.logger.Info("Handshake type", zap.Int("type", int(handshakeType)))
		}

	default:
		c.logger.Info("→ Unknown record type", zap.Int("type", int(recordType)))
	}
}

// processTLSRecord processes a single TLS ApplicationData record using split AEAD protocol
func (c *Client) processTLSRecord(record []byte) {
	// Extract encrypted payload and tag (skip 5-byte header)
	encryptedPayload := record[5:]

	// For AES-GCM, tag is last 16 bytes of encrypted payload
	if len(encryptedPayload) < 16 {
		c.logger.Error("CRITICAL: Invalid TLS record - payload too short", zap.Int("payload_length", len(encryptedPayload)))
		// This is a protocol violation - should terminate the session
		c.isClosing = true
		return
	}

	tagSize := 16 // AES-GCM tag size
	tag := encryptedPayload[len(encryptedPayload)-tagSize:]

	// Extract explicit IV and encrypted data for TLS 1.2 AES-GCM
	var encryptedData []byte
	var explicitIV []byte

	// Check if this is TLS 1.2 AES-GCM response (needs explicit IV extraction)
	isTLS12AESGCMResponse := c.handshakeDisclosure != nil &&
		shared.IsTLS12AESGCMCipherSuite(c.handshakeDisclosure.CipherSuite)

	if isTLS12AESGCMResponse {
		// TLS 1.2 AES-GCM: explicit_iv(8) + encrypted_data + auth_tag(16)
		if len(encryptedPayload) < 8+tagSize {
			c.logger.Error("CRITICAL: Invalid TLS 1.2 AES-GCM record - payload too short for explicit IV", zap.Int("payload_length", len(encryptedPayload)))
			// This is a protocol violation - should terminate the session
			c.isClosing = true
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
		c.logger.Info("System is shutting down, storing record but skipping split AEAD processing")
		return
	}

	teetConnState := c.teetConn != nil
	if !teetConnState {
		c.logger.Info("TEE_T connection closed, storing record but skipping split AEAD processing")
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
	encryptedResponseData := shared.EncryptedResponseData{
		EncryptedData: encryptedData,
		Tag:           tag,
		RecordHeader:  record[:5], // Include actual TLS record header from server
		SeqNum:        c.responseSeqNum,
		ExplicitIV:    explicitIV, // TLS 1.2 AES-GCM explicit IV (nil for TLS 1.3)
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
	c.logger.Info("EOF already reached, sending packet immediately")

	env := &teeproto.Envelope{
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_EncryptedResponse{
			EncryptedResponse: &teeproto.EncryptedResponseData{
				EncryptedData: encryptedResponseData.EncryptedData,
				Tag:           encryptedResponseData.Tag,
				RecordHeader:  encryptedResponseData.RecordHeader,
				SeqNum:        encryptedResponseData.SeqNum,
				ExplicitIv:    encryptedResponseData.ExplicitIV,
			},
		},
	}

	if err := c.sendEnvelopeToTEET(env); err != nil {

		if c.isClosing {
			c.logger.Info("Send failed during shutdown - this is expected, continuing")
		} else {
			c.logger.Error("CRITICAL: Failed to send encrypted response to TEE_T - terminating session", zap.Error(err))
			// This is a protocol violation - should terminate the session
			c.isClosing = true
		}
		return
	}

	// Increment sequence number for next response
	c.responseSeqNum++
}

// Send batched responses when EOF is detected
func (c *Client) sendBatchedResponses() error {

	if len(c.batchedResponses) == 0 {
		c.logger.Info("No response packets to send")
		return nil
	}

	c.logger.Info("Sending batch of response packets to TEE_T",
		zap.Int("count", len(c.batchedResponses)))

	// Create batched message using new data structure
	batchedData := shared.BatchedEncryptedResponseData{
		Responses:  c.batchedResponses,
		SessionID:  c.sessionID,
		TotalCount: len(c.batchedResponses),
	}

	// Send batch to TEE_T using new message type
	// Convert responses to protobuf format
	var pbResponses []*teeproto.EncryptedResponseData
	for _, r := range batchedData.Responses {
		pbResponses = append(pbResponses, &teeproto.EncryptedResponseData{
			EncryptedData: r.EncryptedData,
			Tag:           r.Tag,
			RecordHeader:  r.RecordHeader,
			SeqNum:        r.SeqNum,
			ExplicitIv:    r.ExplicitIV,
		})
	}

	env := &teeproto.Envelope{
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_BatchedEncryptedResponses{
			BatchedEncryptedResponses: &teeproto.BatchedEncryptedResponses{
				Responses:  pbResponses,
				SessionId:  batchedData.SessionID,
				TotalCount: int32(batchedData.TotalCount),
			},
		},
	}

	if err := c.sendEnvelopeToTEET(env); err != nil {
		return fmt.Errorf("failed to send batched responses to TEE_T: %v", err)
	}

	c.logger.Info("Successfully sent batch to TEE_T", zap.Int("packets", len(c.batchedResponses)))

	c.setBatchSentToTEET()

	c.expectedRedactedStreams = len(c.batchedResponses)
	c.logger.Info("Expecting redacted streams based on batch size", zap.Int("expected_streams", c.expectedRedactedStreams))

	c.advanceToPhase(PhaseReceivingDecryption)

	// Clear the batch after successful send
	c.batchedResponses = make([]shared.EncryptedResponseData, 0)
	return nil
}

// handleResponseTagVerification handles tag verification result from TEE_T
func (c *Client) handleResponseTagVerification(msg *shared.Message) {
	var verificationData shared.ResponseTagVerificationData
	if err := msg.UnmarshalData(&verificationData); err != nil {
		c.logger.Error("Failed to unmarshal response tag verification", zap.Error(err))
		return
	}

	if verificationData.Success {
		// Phase advances to PhaseSendingRedaction automatically after batch processing
	} else {
		c.logger.Error("Tag verification failed", zap.Uint64("sequence", verificationData.SeqNum), zap.String("message", verificationData.Message))
	}
}

// analyzeNewSessionTicket provides details about session ticket content
func (c *Client) analyzeNewSessionTicket(data []byte) {
	if len(data) < 8 {
		c.logger.Info("NewSessionTicket too short")
		return
	}

	ticketLifetime := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	ticketAgeAdd := uint32(data[4])<<24 | uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])

	c.logger.Info("Ticket lifetime", zap.Uint32("seconds", ticketLifetime))
	c.logger.Info("Age add", zap.Uint32("value", ticketAgeAdd))

	if len(data) > 8 {
		nonceLen := int(data[8])
		c.logger.Info("Nonce length", zap.Int("bytes", nonceLen))

		if len(data) > 9+nonceLen+2 {
			ticketLen := int(data[9+nonceLen])<<8 | int(data[10+nonceLen])
			c.logger.Info("Ticket length", zap.Int("bytes", ticketLen))
		}
	}

	c.logger.Info("This is likely a session resumption ticket, not HTTP content")
}

// analyzeAlertMessage analyzes TLS alert messages
func (c *Client) analyzeAlertMessage(data []byte) {
	if len(data) < 2 {
		c.logger.Info("Alert message too short")
		return
	}

	alertLevel := data[0]
	alertDescription := data[1]

	levelStr := "warning"
	if alertLevel == 2 {
		levelStr = "FATAL"
	}

	descStr := getClientAlertDescription(alertDescription)
	c.logger.Info("Alert",
		zap.String("level", levelStr),
		zap.Int("level_code", int(alertLevel)),
		zap.String("description", descStr),
		zap.Int("description_code", int(alertDescription)))

	// Note: We don't signal completion on CLOSE_NOTIFY since TEEs may still be processing
}

// parseDecryptedAlert parses alert level and description from decrypted alert data
func (c *Client) parseDecryptedAlert(seqNum uint64, decryptedData []byte) {
	if len(decryptedData) >= 2 {
		alertLevel := decryptedData[0]
		alertDescription := decryptedData[1]
		c.logger.Info("Alert",
			zap.Uint64("sequence", seqNum),
			zap.Int("level", int(alertLevel)),
			zap.Int("description", int(alertDescription)),
			zap.String("description_name", getClientAlertDescription(alertDescription)))

		if alertDescription == 0 {
			c.logger.Info("*** CLOSE_NOTIFY ALERT DETECTED ***",
				zap.Uint64("sequence", seqNum))
		}

		c.analyzeAlertMessage(decryptedData)
	} else {
		c.logger.Error("Alert record too short for parsing",
			zap.Uint64("sequence", seqNum),
			zap.Int("bytes", len(decryptedData)))
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
	isTLS12 := c.handshakeDisclosure != nil && shared.IsTLS12CipherSuite(c.handshakeDisclosure.CipherSuite)

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
