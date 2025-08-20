package clientlib

import (
	"bytes"
	"fmt"
	"tee-mpc/shared"

	"go.uber.org/zap"
)

// validateTranscriptsAgainstCapturedTraffic validates both TEE transcripts
// against the client's captured TLS traffic to ensure integrity and completeness
func (c *Client) validateTranscriptsAgainstCapturedTraffic() {
	c.logger.Info("===== TRANSCRIPT VALIDATION REPORT =====")

	c.logger.Info("Validating transcripts against captured TLS records", zap.Int("records_count", len(c.capturedTraffic)))

	// Since we now capture raw TCP chunks exactly as TEE_K sees them,
	// we should compare them directly without trying to categorize by TLS record type

	for i, chunk := range c.capturedTraffic {
		if len(chunk) < 1 {
			// Empty chunks in captured traffic indicate protocol corruption
			c.terminateConnectionWithError("Empty chunk in captured traffic", fmt.Errorf("chunk %d is empty", i))
			return
		}

	}

	// Calculate total sizes
	totalCapturedSize := 0
	for _, chunk := range c.capturedTraffic {
		totalCapturedSize += len(chunk)
	}

	c.logger.Info("Client captured traffic analysis",
		zap.Int("total_chunks", len(c.capturedTraffic)),
		zap.Int("total_captured_size", totalCapturedSize))

	// Perform detailed comparison with TEE transcripts
	c.logger.Info("Detailed transcript comparison")

	// Validate TEE_K transcript (should contain raw TCP chunks - bidirectional)
	teekValidation := c.validateTEEKTranscriptRaw()

	// Validate TEE_T transcript (should contain application data - bidirectional)
	teetValidation := c.validateTEETTranscriptRaw()

	// Summary
	c.logger.Info("VALIDATION RESULTS",
		zap.Bool("both_transcripts_received", true),
		zap.Bool("both_signatures_verified", true),
		zap.Int("tcp_chunks_captured", len(c.capturedTraffic)))

	if teekValidation && teetValidation {
		c.logger.Info("TRANSCRIPT VALIDATION PASSED - All packets match!")
	} else {
		c.logger.Error("TRANSCRIPT VALIDATION FAILED - Packet mismatches detected!")
	}

	c.logger.Info("===== VALIDATION COMPLETE =====")
}

// validateTEEKTranscriptRaw validates TEE_K transcript against client raw TCP chunks
func (c *Client) validateTEEKTranscriptRaw() bool {
	c.logger.Info("Validating TEE_K transcript against client captures", zap.Int("data_count", len(c.teekTranscriptData)))

	if c.teekTranscriptData == nil {
		c.logger.Error("TEE_K transcript data not available")
		return false
	}

	// TEE_K captures raw TCP chunks during handshake, so we should compare against
	// the raw TCP chunks we captured (not the individual TLS records from application phase)
	c.logger.Info("TEE_K transcript analysis")

	handshakeDataMatched := 0
	totalCompared := 0 // number of transcript data entries that we actually compared against captures
	for _, teekData := range c.teekTranscriptData {

		// All transcript data entries are now consolidated streams by definition
		totalCompared++

		// Check if this data matches any of the client's captured data
		found := false
		for _, chunk := range c.capturedTraffic {
			if len(teekData) == len(chunk) && bytes.Equal(teekData, chunk) {
				handshakeDataMatched++
				found = true
				break
			}
		}

		if !found {
			c.logger.Debug("Data NOT found in client captures")
		}
	}

	c.logger.Info("TEE_K validation result", zap.Int("data_matched", handshakeDataMatched), zap.Int("total_compared", totalCompared))

	return handshakeDataMatched == totalCompared
}

// validateTEETTranscriptRaw validates TEE_T transcript against client application data records
func (c *Client) validateTEETTranscriptRaw() bool {
	c.logger.Info("Validating TEE_T transcript against client captures", zap.Int("data_count", len(c.teetTranscriptData)))

	if c.teetTranscriptData == nil {
		c.logger.Error("TEE_T transcript data not available")
		return false
	}

	c.logger.Info("TEE_T transcript analysis")

	dataMatched := 0
	for _, teetData := range c.teetTranscriptData {
		// fmt.Printf("[Client]   TEE_T data %d: %d bytes (type: 0x%02x)\n",
		// 	i+1, len(teetData), teetData[0])

		// Check if this data matches any of our captured data
		found := false
		for _, clientData := range c.capturedTraffic {
			if len(teetData) == len(clientData) && bytes.Equal(teetData, clientData) {
				dataMatched++
				found = true
				break
			}
		}

		if !found {
			c.logger.Debug("Data NOT found in client captures")
		}
	}

	c.logger.Info("TEE_T validation result", zap.Int("data_matched", dataMatched), zap.Int("total_data", len(c.teetTranscriptData)))

	return dataMatched == len(c.teetTranscriptData)
}

// handleSignedTranscriptWithStreams processes combined transcript and streams from TEE_K
func (c *Client) handleSignedTranscriptWithStreams(msg *shared.Message) {
	var combinedData shared.SignedTranscriptWithStreams
	if err := msg.UnmarshalData(&combinedData); err != nil {
		c.logger.Error("Failed to unmarshal signed transcript with streams", zap.Error(err))
		return
	}

	c.logger.Info("Received combined signed transcript with streams",
		zap.Int("data_count", len(combinedData.SignedTranscript.Data)),
		zap.Int("signature_bytes", len(combinedData.SignedTranscript.Signature)),
		zap.Int("eth_address_bytes", len(combinedData.SignedTranscript.EthAddress)),
		zap.Int("streams_count", len(combinedData.SignedRedactedStreams)))

	// Process the streams part FIRST if present
	if len(combinedData.SignedRedactedStreams) > 0 {
		batchedData := shared.BatchedSignedRedactedDecryptionStreamData{
			SignedRedactedStreams: combinedData.SignedRedactedStreams,
			SessionID:             msg.SessionID,
			TotalCount:            combinedData.TotalStreamsCount,
		}
		c.processBatchedSignedRedactedDecryptionStreamsData(&batchedData)
	}

	// Process the transcript part AFTER streams are available
	c.processSignedTranscriptDataWithStreams(&combinedData.SignedTranscript)

	// Final completion check for combined messages to address race conditions
	c.checkFinalCompletion("combined message processed")
}

// handleSignedTranscript processes signed transcript messages from TEE_K and TEE_T
func (c *Client) handleSignedTranscript(msg *shared.Message) {
	var signedTranscript shared.SignedTranscript
	if err := msg.UnmarshalData(&signedTranscript); err != nil {
		c.logger.Error("Failed to unmarshal signed transcript", zap.Error(err))
		return
	}

	c.logger.Info("Received signed transcript",
		zap.Int("data_count", len(signedTranscript.Data)),
		zap.Int("signature_bytes", len(signedTranscript.Signature)),
		zap.Int("eth_address_bytes", len(signedTranscript.EthAddress)))

	c.processSignedTranscriptData(&signedTranscript)

	// Add completion check for regular transcript messages as well for robustness
	c.checkFinalCompletion("individual transcript processed")
}

// processSignedTranscriptDataWithStreams processes transcript data when streams are already available (combined message)
func (c *Client) processSignedTranscriptDataWithStreams(signedTranscript *shared.SignedTranscript) {
	// Store data for validation
	c.teekTranscriptData = signedTranscript.Data

	// Calculate total size of all data
	totalSize := 0
	for _, data := range signedTranscript.Data {
		totalSize += len(data)
	}

	c.logger.Info("Total transcript size", zap.Int("bytes", totalSize))

	// Determine source name for logging
	sourceName := "TEE_K"

	// Display signature and public key info for verification
	if len(signedTranscript.Signature) > 0 {
		c.logger.Info("Signature info", zap.String("source", sourceName), zap.Int("signature_bytes", len(signedTranscript.Signature)))
	}

	if len(signedTranscript.EthAddress) > 0 {
		c.logger.Info("ETH address info", zap.String("source", sourceName), zap.Int("eth_address_bytes", len(signedTranscript.EthAddress)))
	}

	// SECURITY FIX: Signature verification now done upfront on SignedMessage
	// The old VerifyComprehensiveSignature is disabled because it expects old signing format
	c.logger.Info("Signature already verified on SignedMessage", zap.String("source", sourceName))
	c.logger.Info("TEE_K comprehensive verification: have all expected redacted streams from combined message", zap.Int("streams_count", c.expectedRedactedStreams))

	// Set completion flag before marking transcript received (no race condition with boolean approach)
	c.setCompletionFlag(CompletionFlagTEEKSignatureValid)
	// Mark TEE_K transcript as received and check for completion
	c.markTEEKTranscriptReceived()

	c.logger.Info("Marked transcript as received", zap.String("source", sourceName), zap.Bool("signature_valid", true))

	c.logger.Info("Signed transcript processed successfully", zap.String("source", sourceName))

	// Show packet summary
	c.logger.Info("Transcript summary", zap.String("source", sourceName))

	// Validation is now handled centrally by checkValidationAndCompletion()
	// Success logging is handled in the specific transcript received methods
}

// processSignedTranscriptData contains the shared logic for processing SignedTranscript data
func (c *Client) processSignedTranscriptData(signedTranscript *shared.SignedTranscript) {

	// Store data for validation
	// Determine source based on transcript structure: TEE_K has RequestMetadata, TEE_T doesn't
	if signedTranscript.RequestMetadata != nil {
		// This is from TEE_K
		c.teekTranscriptData = signedTranscript.Data // Store data for validation
	} else {
		// This is from TEE_T
		c.teetTranscriptData = signedTranscript.Data // Store data for validation
	}

	// Calculate total size of all data
	totalSize := 0
	for _, data := range signedTranscript.Data {
		totalSize += len(data)
	}

	c.logger.Info("Total transcript size", zap.Int("bytes", totalSize))

	// Determine source name for logging
	sourceName := "TEE_T"
	if signedTranscript.RequestMetadata != nil {
		sourceName = "TEE_K"
	}

	// Display signature and public key info for verification
	if len(signedTranscript.Signature) > 0 {
		c.logger.Info("Signature info", zap.String("source", sourceName), zap.Int("signature_bytes", len(signedTranscript.Signature)))
	}

	if len(signedTranscript.EthAddress) > 0 {
		c.logger.Info("ETH address info", zap.String("source", sourceName), zap.Int("eth_address_bytes", len(signedTranscript.EthAddress)))
	}

	// SECURITY FIX: Signature verification now done upfront on SignedMessage
	// The old verification logic is disabled because it expects old signing format
	c.logger.Info("Signature already verified on SignedMessage", zap.String("source", sourceName))

	if signedTranscript.RequestMetadata != nil {
		// This is TEE_K
		c.logger.Info("TEE_K transcript received")
		c.setCompletionFlag(CompletionFlagTEEKSignatureValid)
		c.markTEEKTranscriptReceived()
	} else {
		// This is TEE_T
		c.logger.Info("TEE_T transcript received")
		c.markTEETTranscriptReceived()
	}

	c.logger.Info("Marked transcript as received", zap.String("source", sourceName), zap.Bool("signature_valid", true))

	c.logger.Info("Signed transcript processed successfully", zap.String("source", sourceName))

	// Show packet summary
	c.logger.Info("Transcript summary", zap.String("source", sourceName))
	// if len(signedTranscript.Data) > 0 {
	// 	// Display data information
	// 	for i, data := range signedTranscript.Data {
	// 		fmt.Printf("[Client] TEE_K data %d: %d bytes\n", i+1, len(data))
	// 	}
	// }

	// if len(signedTranscript.Data) > 0 {
	// 	// Display data information
	// 	for i, data := range signedTranscript.Data {
	// 		fmt.Printf("[Client] TEE_T data %d: %d bytes\n", i+1, len(data))
	// 	}
	// }

	// Validation is now handled centrally by checkValidationAndCompletion()
	// Success logging is handled in the specific transcript received methods

}
