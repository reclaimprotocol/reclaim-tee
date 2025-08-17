package main

import (
	"fmt"
	"strings"
	"time"

	teeproto "tee-mpc/proto"
	"tee-mpc/shared"

	"go.uber.org/zap"
)

// handleRequestConnectionSession handles connection request from client
func (t *TEEK) handleRequestConnectionSession(sessionID string, msg *shared.Message) {
	t.logger.WithSession(sessionID).Info("Handling connection request")

	var reqData shared.RequestConnectionData
	if err := msg.UnmarshalData(&reqData); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to parse connection request")
		return
	}

	t.logger.WithSession(sessionID).Info("Connection request received",
		zap.String("hostname", reqData.Hostname),
		zap.Int("port", reqData.Port))

	// Store connection data in session
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonSessionNotFound, err, "Session not found")
		return
	}
	session.ConnectionData = &reqData

	// Send connection ready message to client
	envReady := &teeproto.Envelope{SessionId: sessionID, TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_ConnectionReady{ConnectionReady: &teeproto.ConnectionReady{Success: true}},
	}
	if err := t.sessionManager.RouteToClient(sessionID, envReady); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonNetworkFailure, err, "Failed to send connection ready message")
		return
	}

	t.logger.WithSession(sessionID).Info("Connection ready message sent, waiting for TCP ready")
	// Now wait for client to send MsgTCPReady - the TLS handshake will start in handleTCPReadySession
}

// handleTCPReadySession handles TCP ready message from client
func (t *TEEK) handleTCPReadySession(sessionID string, msg *shared.Message) {
	var tcpData shared.TCPReadyData
	if err := msg.UnmarshalData(&tcpData); err != nil {
		t.terminateSessionWithError(sessionID, shared.ReasonMessageParsingFailed, err, "Failed to unmarshal TCP ready data")
		return
	}

	if !tcpData.Success {
		tcpErr := fmt.Errorf("TCP connection failed")
		t.terminateSessionWithError(sessionID, shared.ReasonNetworkFailure, tcpErr, "TCP connection failed")
		return
	}

	t.logger.WithSession(sessionID).Info("TCP connection ready, starting TLS handshake")

	// Start TLS handshake for this session
	go t.performTLSHandshakeAndHTTPForSession(sessionID)
}

// handleTCPDataSession handles TCP data from client
func (t *TEEK) handleTCPDataSession(sessionID string, msg *shared.Message) {
	var tcpData shared.TCPData
	if err := msg.UnmarshalData(&tcpData); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to unmarshal TCP data", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to unmarshal TCP data: %v", err))
		return
	}

	// Handle incoming data from Client (TLS handshake data or encrypted application data)
	// Use session state for TCP data handling
	tlsState, err := t.getSessionTLSState(sessionID)
	if err != nil {
		t.logger.WithSession(sessionID).Error("Failed to get TLS state", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to get TLS state: %v", err))
		return
	}

	if tlsState.WSConn2TLS != nil {
		// Forward data to TLS client for processing
		tlsState.WSConn2TLS.pendingData <- tcpData.Data
	} else {
		t.logger.WithSession(sessionID).Error("No WebSocket-to-TLS adapter available")
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, fmt.Errorf("no WebSocket-to-TLS adapter available"), "No WebSocket-to-TLS adapter available")
	}
}

// handleRedactedRequestSession handles redacted request from client
func (t *TEEK) handleRedactedRequestSession(sessionID string, msg *shared.Message) {
	var redactedRequest shared.RedactedRequestData
	if err := msg.UnmarshalData(&redactedRequest); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to unmarshal redacted request", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to unmarshal redacted request: %v", err))
		return
	}

	t.logger.WithSession(sessionID).Info("Validating redacted request",
		zap.Int("request_bytes", len(redactedRequest.RedactedRequest)),
		zap.Int("redaction_ranges", len(redactedRequest.RedactionRanges)),
		zap.Int("commitments", len(redactedRequest.Commitments)))

	// Validate redacted request format and positions
	if err := t.validateHTTPRequestFormat(redactedRequest.RedactedRequest, redactedRequest.RedactionRanges); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to validate redacted request format", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to validate redacted request format: %v", err))
		return
	}

	if err := t.validateRedactionPositions(redactedRequest.RedactionRanges, len(redactedRequest.RedactedRequest)); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to validate redaction positions", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to validate redaction positions: %v", err))
		return
	}

	// --- Add redacted request, comm_sp, and redaction ranges to transcript before encryption ---
	t.addToTranscriptForSessionWithType(sessionID, redactedRequest.RedactedRequest, shared.TranscriptPacketTypeHTTPRequestRedacted)

	// Store redaction ranges in transcript for signing using protobuf
	redactionRangesBytes, err := shared.MarshalRequestRedactionRangesProtobuf(redactedRequest.RedactionRanges)
	if err != nil {
		t.logger.WithSession(sessionID).Error("Failed to marshal redaction ranges", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to marshal redaction ranges: %v", err))
		return
	}
	t.addToTranscriptForSessionWithType(sessionID, redactionRangesBytes, "redaction_ranges")
	t.logger.WithSession(sessionID).Info("Stored redaction ranges in transcript",
		zap.Int("ranges_count", len(redactedRequest.RedactionRanges)),
		zap.Int("bytes", len(redactionRangesBytes)))

	// TEE_T signs the proof stream, providing sufficient cryptographic proof

	t.logger.WithSession(sessionID).Info("Added redaction ranges to transcript for signing")

	t.logger.WithSession(sessionID).Info("Split AEAD: encrypting redacted request",
		zap.Int("bytes", len(redactedRequest.RedactedRequest)))

	// Encrypt the request and send to TEE_T
	if err := t.encryptAndSendRequest(sessionID, redactedRequest); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to encrypt and send request", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to encrypt and send request: %v", err))
		return
	}

	t.logger.WithSession(sessionID).Info("Encrypted request sent to TEE_T successfully")
}

// validateHTTPRequestFormat validates that the redacted request maintains proper HTTP format
func (t *TEEK) validateHTTPRequestFormat(redactedRequest []byte, ranges []shared.RequestRedactionRange) error {
	// Create a pretty version with asterisks for redacted ranges
	prettyRequest := make([]byte, len(redactedRequest))
	copy(prettyRequest, redactedRequest)

	// Replace redacted ranges with asterisks for display
	for _, r := range ranges {
		end := r.Start + r.Length
		if r.Start >= 0 && end <= len(prettyRequest) {
			for i := r.Start; i < end; i++ {
				prettyRequest[i] = '*'
			}
		}
	}

	// Log the pretty version that TEE_K sees
	t.logger.Info("TEE_K sees redacted request with asterisks",
		zap.String("redacted_request", string(prettyRequest)),
		zap.Int("redaction_ranges", len(ranges)))

	// Log details of each redaction range
	for i, r := range ranges {
		t.logger.Info("Redaction range for TEE_K",
			zap.Int("index", i),
			zap.Int("start", r.Start),
			zap.Int("length", r.Length),
			zap.String("type", r.Type))
	}

	// Convert to string for easier parsing
	reqStr := string(prettyRequest)

	// Check basic HTTP request format
	if !strings.HasPrefix(reqStr, "GET ") && !strings.HasPrefix(reqStr, "POST ") {
		return fmt.Errorf("request does not start with valid HTTP method")
	}

	// Check for HTTP version
	if !strings.Contains(reqStr, " HTTP/1.1") {
		return fmt.Errorf("request does not contain HTTP/1.1 version")
	}

	// Check for proper line endings
	if !strings.Contains(reqStr, "\r\n") {
		return fmt.Errorf("request does not contain proper CRLF line endings")
	}

	// Check that request ends with double CRLF
	if !strings.HasSuffix(reqStr, "\r\n\r\n") {
		return fmt.Errorf("request does not end with proper double CRLF")
	}

	// Validate that critical parts aren't fully redacted
	lines := strings.Split(reqStr, "\r\n")
	if len(lines) < 2 {
		return fmt.Errorf("request has insufficient lines")
	}

	// First line should contain method, path, and version
	firstLine := lines[0]
	parts := strings.Split(firstLine, " ")
	if len(parts) < 3 {
		return fmt.Errorf("invalid HTTP request line format")
	}

	t.logger.Info("Redacted request format validation passed")
	return nil
}

// validateRedactionPositions validates that redaction ranges are within bounds and non-overlapping
func (t *TEEK) validateRedactionPositions(ranges []shared.RequestRedactionRange, requestLen int) error {
	for i, r := range ranges {
		// Check bounds
		if r.Start < 0 || r.Length <= 0 || r.Start+r.Length > requestLen {
			return fmt.Errorf("range %d out of bounds: [%d:%d] for request length %d", i, r.Start, r.Start+r.Length, requestLen)
		}

		// Check for valid type
		if r.Type != shared.RedactionTypeSensitive && r.Type != shared.RedactionTypeSensitiveProof {
			return fmt.Errorf("range %d has invalid type: %s", i, r.Type)
		}

		// Check for overlaps with other ranges
		for j := i + 1; j < len(ranges); j++ {
			other := ranges[j]
			if !(r.Start+r.Length <= other.Start || other.Start+other.Length <= r.Start) {
				return fmt.Errorf("ranges %d and %d overlap: [%d:%d] and [%d:%d]", i, j, r.Start, r.Start+r.Length, other.Start, other.Start+other.Length)
			}
		}
	}

	t.logger.Info("Redaction position validation passed", zap.Int("ranges", len(ranges)))
	return nil
}

// handleRedactionSpecSession handles redaction specification from client
func (t *TEEK) handleRedactionSpecSession(sessionID string, msg *shared.Message) {
	t.logger.WithSession(sessionID).Info("Handling redaction specification")

	var redactionSpec shared.ResponseRedactionSpec
	if err := msg.UnmarshalData(&redactionSpec); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to unmarshal redaction spec", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, fmt.Errorf("failed to parse redaction specification"), "failed to parse redaction specification")
		return
	}

	t.logger.WithSession(sessionID).Info("Received redaction spec", zap.Int("ranges", len(redactionSpec.Ranges)))

	// Validate redaction ranges
	if err := t.validateResponseRedactionSpec(redactionSpec); err != nil {
		t.logger.WithSession(sessionID).Error("Invalid redaction spec", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Invalid redaction specification: %v", err))
		return
	}

	// Store response redaction ranges in session state for transcript signature
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.logger.WithSession(sessionID).Error("Failed to get session for storing redaction ranges", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to store redaction ranges: %v", err))
		return
	}

	if session.ResponseState == nil {
		session.ResponseState = &shared.ResponseSessionState{}
	}
	session.ResponseState.ResponseRedactionRanges = redactionSpec.Ranges
	t.logger.WithSession(sessionID).Info("Stored response redaction ranges for transcript signature", zap.Int("ranges", len(redactionSpec.Ranges)))

	// Generate and send redacted decryption streams
	if err := t.generateAndSendRedactedDecryptionStreamResponse(sessionID, redactionSpec); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to generate redacted streams", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to generate redacted streams: %v", err))
		return
	}

	t.logger.WithSession(sessionID).Info("Successfully processed redaction specification")

	// Send "finished" to TEE_T as per protocol specification
	env := &teeproto.Envelope{
		SessionId:   sessionID,
		TimestampMs: time.Now().UnixMilli(),
		Payload: &teeproto.Envelope_Finished{
			Finished: &teeproto.FinishedMessage{},
		},
	}
	if err := t.sendEnvelopeToTEETForSession(sessionID, env); err != nil {
		t.logger.WithSession(sessionID).Error("Failed to send finished message to TEE_T", zap.Error(err))
		t.terminateSessionWithError(sessionID, shared.ReasonInternalError, err, fmt.Sprintf("Failed to send finished message to TEE_T: %v", err))
		return
	}

	t.logger.WithSession(sessionID).Info("Sent finished message to TEE_T")
}

// validateResponseRedactionSpec validates the response redaction specification from client
func (t *TEEK) validateResponseRedactionSpec(spec shared.ResponseRedactionSpec) error {
	// Validate ranges don't overlap and are within bounds
	for i, range1 := range spec.Ranges {
		// Check for overlaps with other ranges
		for j := i + 1; j < len(spec.Ranges); j++ {
			range2 := spec.Ranges[j]
			if rangesOverlapResponse(range1, range2) {
				return fmt.Errorf("ranges %d and %d overlap", i, j)
			}
		}

		// Basic bounds check (we'll validate against actual packet boundaries later)
		if range1.Start < 0 || range1.Length <= 0 {
			return fmt.Errorf("range %d: invalid bounds (start=%d, length=%d)", i, range1.Start, range1.Length)
		}
	}

	return nil
}

// rangesOverlapResponse checks if two response redaction ranges overlap
func rangesOverlapResponse(r1, r2 shared.ResponseRedactionRange) bool {
	return r1.Start < r2.Start+r2.Length && r2.Start < r1.Start+r1.Length
}
