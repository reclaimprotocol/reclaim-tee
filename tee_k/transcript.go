package main

import (
	"fmt"
	"time"

	teeproto "tee-mpc/proto"
	"tee-mpc/shared"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

// addToTranscriptForSessionWithType safely adds a packet with explicit type to the session's transcript.
func (t *TEEK) addToTranscriptForSessionWithType(sessionID string, packet []byte, packetType string) {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.logger.WithSession(sessionID).Error("Failed to get session for transcript", zap.Error(err))
		return
	}

	session.TranscriptMutex.Lock()
	defer session.TranscriptMutex.Unlock()

	// Copy buffer to avoid unexpected mutation
	pktCopy := make([]byte, len(packet))
	copy(pktCopy, packet)

	session.TranscriptPackets = append(session.TranscriptPackets, pktCopy)
	session.TranscriptPacketTypes = append(session.TranscriptPacketTypes, packetType)

	t.logger.WithSession(sessionID).Info("Added packet to transcript",
		zap.Int("bytes", len(packet)),
		zap.String("type", packetType),
		zap.Int("total_packets", len(session.TranscriptPackets)))
}

// addToTranscriptForSession safely adds a packet to the session's transcript collection
func (t *TEEK) addToTranscriptForSession(sessionID string, packet []byte) {
	// Default to TLS record type
	t.addToTranscriptForSessionWithType(sessionID, packet, shared.TranscriptPacketTypeTLSRecord)
}

// getTranscriptForSession safely returns a copy of the session's transcript
func (t *TEEK) getTranscriptForSession(sessionID string) [][]byte {
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		t.logger.WithSession(sessionID).Error("Failed to get session for transcript", zap.Error(err))
		return nil
	}

	session.TranscriptMutex.Lock()
	defer session.TranscriptMutex.Unlock()

	// Return a copy to avoid external modification
	transcriptCopy := make([][]byte, len(session.TranscriptPackets))
	for i, packet := range session.TranscriptPackets {
		packetCopy := make([]byte, len(packet))
		copy(packetCopy, packet)
		transcriptCopy[i] = packetCopy
	}

	return transcriptCopy
}

// generateComprehensiveSignatureAndSendTranscript creates comprehensive signature and sends all verification data to client
func (t *TEEK) generateComprehensiveSignatureAndSendTranscript(sessionID string) error {
	t.logger.WithSession(sessionID).Info("Generating comprehensive signature")

	// Get session
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("session %s not found: %v", sessionID, err)
	}

	if t.signingKeyPair == nil {
		return fmt.Errorf("no signing key pair available")
	}

	// Get transcript data
	session.TranscriptMutex.Lock()
	defer session.TranscriptMutex.Unlock()

	// Get redacted streams
	session.StreamsMutex.Lock()
	defer session.StreamsMutex.Unlock()

	// SIMPLIFIED: Only extract request metadata, no TLS packet processing
	var requestMetadata *shared.RequestMetadata

	for i, packet := range session.TranscriptPackets {
		packetType := ""
		if i < len(session.TranscriptPacketTypes) {
			packetType = session.TranscriptPacketTypes[i]
		}

		switch packetType {
		case shared.TranscriptPacketTypeHTTPRequestRedacted:
			if requestMetadata == nil {
				requestMetadata = &shared.RequestMetadata{}
			}
			requestMetadata.RedactedRequest = packet
		case "redaction_ranges":
			if requestMetadata == nil {
				requestMetadata = &shared.RequestMetadata{}
			}
			// Unmarshal the redaction ranges from protobuf
			ranges, err := shared.UnmarshalRequestRedactionRangesProtobuf(packet)
			if err != nil {
				t.logger.WithSession(sessionID).Error("Failed to unmarshal redaction ranges from transcript", zap.Error(err))
			} else {
				requestMetadata.RedactionRanges = ranges
				t.logger.WithSession(sessionID).Info("Loaded redaction ranges from transcript", zap.Int("ranges", len(ranges)))
			}
			// REMOVED: TLS packet processing - no longer needed for consolidated approach
		}
	}

	// SECURITY FIX: Sign protobuf body directly instead of reconstructing data

	// Get ETH address for this key pair
	ethAddress := t.signingKeyPair.GetEthAddress()

	// SECURITY FIX: Build KOutputPayload and sign it directly
	timestampMs := time.Now().UnixMilli()
	kPayload := &teeproto.KOutputPayload{
		TimestampMs: uint64(timestampMs), // Include signed timestamp
	}
	if requestMetadata != nil {
		kPayload.RedactedRequest = requestMetadata.RedactedRequest
		for _, r := range requestMetadata.RedactionRanges {
			kPayload.RequestRedactionRanges = append(kPayload.RequestRedactionRanges, &teeproto.RequestRedactionRange{Start: int32(r.Start), Length: int32(r.Length), Type: r.Type})
		}
	}
	// NEW: Consolidate response keystreams - use consolidated keystream from session
	kPayload.ConsolidatedResponseKeystream = session.ConsolidatedResponseKeystream

	// NEW: Include certificate info in signed payload
	kPayload.CertificateInfo = session.CertificateInfo
	if session.ResponseState != nil && len(session.ResponseState.ResponseRedactionRanges) > 0 {
		for _, rr := range session.ResponseState.ResponseRedactionRanges {
			kPayload.ResponseRedactionRanges = append(kPayload.ResponseRedactionRanges, &teeproto.ResponseRedactionRange{Start: int32(rr.Start), Length: int32(rr.Length)})
		}
		t.logger.WithSession(sessionID).Info("Included response redaction ranges in signed payload", zap.Int("ranges", len(session.ResponseState.ResponseRedactionRanges)))
	}

	// Create protobuf body and sign it directly
	body, err := proto.Marshal(kPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal KOutputPayload: %v", err)
	}

	// Sign the exact protobuf body bytes
	comprehensiveSignature, err := t.signingKeyPair.SignData(body)
	if err != nil {
		return fmt.Errorf("failed to generate comprehensive signature: %v", err)
	}

	t.logger.WithSession(sessionID).Info("Generated comprehensive signature over protobuf body",
		zap.Int("consolidated_response_keystream_bytes", len(session.ConsolidatedResponseKeystream)),
		zap.Bool("metadata_present", requestMetadata != nil),
		zap.Int("body_bytes", len(body)),
		zap.Int("signature_bytes", len(comprehensiveSignature)))

	// Generate attestation report for enclave mode, or use public key for standalone
	var attestationReport *teeproto.AttestationReport
	var publicKeyForStandalone []byte

	if t.enclaveManager != nil {
		// Enclave mode: include attestation report
		var err error
		attestationReport, err = t.generateAttestationReport(sessionID)
		if err != nil {
			return fmt.Errorf("failed to generate attestation report: %v", err)
		}
		t.logger.WithSession(sessionID).Info("Including attestation report in SignedMessage")
	} else {
		// Standalone mode: include ETH address as public key
		publicKeyForStandalone = []byte(ethAddress.String())
		t.logger.WithSession(sessionID).Info("Including ETH address in SignedMessage (standalone mode)",
			zap.String("eth_address", ethAddress.Hex()))
	}

	// Send the signed message to client (timestamp is now inside signed body)
	signedMsg := &teeproto.SignedMessage{
		BodyType:          teeproto.BodyType_BODY_TYPE_K_OUTPUT,
		Body:              body,
		EthAddress:        publicKeyForStandalone,
		Signature:         comprehensiveSignature,
		AttestationReport: attestationReport,
	}

	env := &teeproto.Envelope{SessionId: sessionID, TimestampMs: timestampMs,
		Payload: &teeproto.Envelope_SignedMessage{SignedMessage: signedMsg},
	}
	if err := t.sessionManager.RouteToClient(sessionID, env); err != nil {
		return fmt.Errorf("failed to send signed message to client: %v", err)
	}

	t.logger.WithSession(sessionID).Info("Sent SignedMessage (KOutput) to client",
		zap.Int("consolidated_response_keystream_bytes", len(session.ConsolidatedResponseKeystream)))

	return nil
}
