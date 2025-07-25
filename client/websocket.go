package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"tee-mpc/shared"
	"time"

	"github.com/gorilla/websocket"
)

// createEnclaveWebSocketDialer creates a custom WebSocket dialer for enclave mode
func createEnclaveWebSocketDialer() *websocket.Dialer {
	return &websocket.Dialer{
		HandshakeTimeout: 30 * time.Second,
	}
}

// ConnectToTEEK establishes WebSocket connection to TEE_K
func (c *Client) ConnectToTEEK() error {
	u, err := url.Parse(c.teekURL)
	if err != nil {
		return fmt.Errorf("failed to parse TEE_K URL: %v", err)
	}

	log.Printf("[Client] Attempting WebSocket connection to TEE_K at: %s", c.teekURL)

	// Determine connection mode and use appropriate dialer
	var conn *websocket.Conn
	if strings.HasPrefix(c.teekURL, "wss://") && strings.Contains(c.teekURL, "reclaimprotocol.org") {
		// Enclave mode: use custom dialer with TLS config
		log.Printf("[Client] Enclave mode detected for TEE_K - using custom dialer")
		dialer := createEnclaveWebSocketDialer()
		conn, _, err = dialer.Dial(u.String(), nil)
	} else {
		// Standalone mode: use default dialer
		log.Printf("[Client] Standalone mode detected for TEE_K - using default dialer")
		conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	}

	if err != nil {
		log.Printf("[Client] WebSocket dial failed for TEE_K %s: %v", c.teekURL, err)
		return fmt.Errorf("failed to connect to TEE_K: %v", err)
	}

	c.wsConn = conn
	log.Printf("[Client] WebSocket connection to TEE_K established successfully")

	// Start message handling goroutine
	go c.handleMessages()

	return nil
}

// ConnectToTEET establishes WebSocket connection to TEE_T
func (c *Client) ConnectToTEET() error {
	u, err := url.Parse(c.teetURL)
	if err != nil {
		return fmt.Errorf("failed to parse TEE_T URL: %v", err)
	}

	log.Printf("[Client] Attempting WebSocket connection to TEE_T at: %s", c.teetURL)

	// Determine connection mode and use appropriate dialer
	var conn *websocket.Conn
	if strings.HasPrefix(c.teetURL, "wss://") && strings.Contains(c.teetURL, "reclaimprotocol.org") {
		// Enclave mode: use custom dialer with TLS config
		log.Printf("[Client] Enclave mode detected for TEE_T - using custom dialer")
		dialer := createEnclaveWebSocketDialer()
		conn, _, err = dialer.Dial(u.String(), nil)
	} else {
		// Standalone mode: use default dialer
		log.Printf("[Client] Standalone mode detected for TEE_T - using default dialer")
		conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	}

	if err != nil {
		log.Printf("[Client] WebSocket dial failed for TEE_T %s: %v", c.teetURL, err)
		return fmt.Errorf("failed to connect to TEE_T: %v", err)
	}

	c.teetConn = conn
	log.Printf("[Client] WebSocket connection to TEE_T established successfully")

	// Start message handling goroutine for TEE_T
	go c.handleTEETMessages()

	return nil
}

// handleMessages handles incoming messages from TEE_K
func (c *Client) handleMessages() {
	for {
		conn := c.wsConn
		closing := c.isClosing

		if conn == nil {
			break
		}

		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			// Only log errors if we're not intentionally closing and it's not a normal shutdown condition
			if !closing {
				// Check for normal close conditions or network errors during shutdown
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				} else if !isClientNetworkShutdownError(err) {
					log.Printf("[Client] Failed to read websocket message: %v", err)
				}
			}
			break
		}

		msg, err := ParseMessage(msgBytes)
		if err != nil {
			if !closing {
				log.Printf("[Client] Failed to parse message: %v", err)
			}
			continue
		}

		switch msg.Type {
		case MsgConnectionReady:
			c.handleConnectionReady(msg)
		case MsgSendTCPData:
			c.handleSendTCPData(msg)
		case MsgHandshakeComplete:
			c.handleHandshakeComplete(msg)
		case MsgHandshakeKeyDisclosure:
			c.handleHandshakeKeyDisclosure(msg)
		case MsgHTTPResponse:
			c.handleHTTPResponse(msg)
		case MsgSessionReady:
			c.handleSessionReady(msg)
		case MsgError:
			c.handleError(msg)
		case MsgSignedRedactedDecryptionStream:
			c.handleSignedRedactedDecryptionStream(msg)
		case MsgSignedTranscript:
			c.handleSignedTranscript(msg)
		case MsgAttestationResponse:
			c.handleAttestationResponse(msg)

		// *** NEW: Handle batched response messages ***
		case MsgBatchedTagVerifications:
			c.handleBatchedTagVerifications(msg)
		case MsgBatchedDecryptionStreams:
			c.handleBatchedDecryptionStreams(msg)

		default:
			if !closing {
				log.Printf("[Client] Unknown message type: %s", msg.Type)
			}
		}
	}
}

// handleTEETMessages handles incoming messages from TEE_T
func (c *Client) handleTEETMessages() {
	for {
		conn := c.teetConn
		closing := c.isClosing

		if conn == nil {
			break
		}

		_, msgBytes, err := conn.ReadMessage()
		if err != nil {
			if !closing {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				} else if !isClientNetworkShutdownError(err) {
					log.Printf("[Client] Failed to read TEE_T websocket message: %v", err)
				}
			}
			break
		}

		msg, err := ParseMessage(msgBytes)
		if err != nil {
			if !closing {
				log.Printf("[Client] Failed to parse TEE_T message: %v", err)
			}
			continue
		}

		switch msg.Type {
		case MsgEncryptedData:
			c.handleEncryptedData(msg)
		case MsgTEETReady:
			c.handleTEETReady(msg)
		case MsgRedactionVerification:
			c.handleRedactionVerification(msg)
		case MsgResponseTagVerification:
			c.handleResponseTagVerification(msg)
		case "signed_transcript":
			c.handleSignedTranscript(msg)
		case MsgAttestationResponse:
			c.handleAttestationResponse(msg)
		case MsgError:
			c.handleTEETError(msg)

		// *** NEW: Handle batched response messages from TEE_T ***
		case MsgBatchedTagVerifications:
			c.handleBatchedTagVerifications(msg)

		default:
			if !closing {
				log.Printf("[Client] Unknown TEE_T message type: %s", msg.Type)
			}
		}
	}
}

// sendMessage sends a message to TEE_K
func (c *Client) sendMessage(msg *Message) error {
	conn := c.wsConn

	if conn == nil {
		return fmt.Errorf("no websocket connection")
	}

	// Add session ID if available and not already set
	if c.sessionID != "" && msg.SessionID == "" {
		msg.SessionID = c.sessionID
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	return conn.WriteMessage(websocket.TextMessage, msgBytes)
}

// isEnclaveMode checks if the client is running in enclave mode
func (c *Client) isEnclaveMode() bool {
	return c.clientMode == ModeEnclave
}

// sendMessageToTEET sends a message to TEE_T
func (c *Client) sendMessageToTEET(msg *Message) error {
	conn := c.teetConn

	if conn == nil {
		fmt.Printf("[Client] DEBUG: No TEE_T connection available when trying to send %s\n", msg.Type)
		return fmt.Errorf("no TEE_T websocket connection")
	}

	// Add session ID if available and not already set
	if c.sessionID != "" && msg.SessionID == "" {
		msg.SessionID = c.sessionID
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	if err := conn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		fmt.Printf("[Client] DEBUG: WriteMessage failed for %s: %v\n", msg.Type, err)

		// *** Try to detect connection state ***
		if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
			fmt.Printf("[Client] DEBUG: WebSocket close error detected: %v\n", err)
		} else if strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "connection reset") {
			fmt.Printf("[Client] DEBUG: Network connection error detected: %v\n", err)
		}

		return err
	}
	return nil
}

// sendError sends an error message to TEE_K
func (c *Client) sendError(errMsg string) {
	errorMsg, err := CreateMessage(MsgError, ErrorData{Message: errMsg})
	if err != nil {
		log.Printf("[Client] Failed to create error message: %v", err)
		return
	}

	if err := c.sendMessage(errorMsg); err != nil {
		log.Printf("[Client] Failed to send error message: %v", err)
	}
}

// sendPendingConnectionRequest sends the stored connection request with the session ID
func (c *Client) sendPendingConnectionRequest() error {
	if !c.connectionRequestPending || c.pendingConnectionRequest == nil {
		return nil
	}

	msg, err := CreateMessage(MsgRequestConnection, *c.pendingConnectionRequest)
	if err != nil {
		return fmt.Errorf("failed to create connection request: %v", err)
	}

	if err := c.sendMessage(msg); err != nil {
		return fmt.Errorf("failed to send connection request: %v", err)
	}

	c.connectionRequestPending = false
	c.pendingConnectionRequest = nil
	return nil
}

// handleSessionReady processes session ready messages from TEE_K
func (c *Client) handleSessionReady(msg *Message) {
	var sessionData SessionReadyData
	if err := msg.UnmarshalData(&sessionData); err != nil {
		log.Printf("[Client] Failed to unmarshal session ready data: %v", err)
		return
	}

	c.sessionID = sessionData.SessionID
	fmt.Printf("[Client] Received session ID: %s\n", c.sessionID)

	// Send pending connection request if we have one
	if c.connectionRequestPending && c.pendingConnectionRequest != nil {
		if err := c.sendPendingConnectionRequest(); err != nil {
			log.Printf("[Client] Failed to send pending connection request: %v", err)
		}
	}
}

// handleError handles error messages from TEE_K
func (c *Client) handleError(msg *Message) {
	var errorData ErrorData
	if err := msg.UnmarshalData(&errorData); err != nil {
		log.Printf("[Client] Failed to unmarshal error data: %v", err)
		return
	}

	log.Printf("[Client] Error from TEE_K: %s", errorData.Message)
}

// handleHTTPResponse handles HTTP response messages from TEE_K
func (c *Client) handleHTTPResponse(msg *Message) {
	var responseData HTTPResponseData
	if err := msg.UnmarshalData(&responseData); err != nil {
		log.Printf("[Client] Failed to unmarshal HTTP response data: %v", err)
		return
	}

	if responseData.Success {
	} else {
		fmt.Println(" TEE_K reported HTTP request failed")
	}
}

// handleEncryptedData handles encrypted data from TEE_T
func (c *Client) handleEncryptedData(msg *Message) {
	var encData EncryptedDataResponse
	if err := msg.UnmarshalData(&encData); err != nil {
		log.Printf("[Client] Failed to unmarshal encrypted data: %v", err)
		return
	}

	if !encData.Success {
		log.Printf("[Client] TEE_T reported failure in encrypted data")
		return
	}

	fmt.Printf("[Client] Received encrypted data (%d bytes) + tag (%d bytes)\n", len(encData.EncryptedData), len(encData.AuthTag))

	// Track received redaction verification result but don't complete yet - wait for HTTP response
	if c.hasCompletionFlag(CompletionFlagRedactionExpected) && !c.hasCompletionFlag(CompletionFlagRedactionReceived) {
		c.setCompletionFlag(CompletionFlagRedactionReceived)
		fmt.Printf("[Client] RECEIVED redaction verification result from TEE_T\n")
	}

	// Create TLS record with encrypted data and authentication tag
	// Format depends on TLS version and cipher suite
	var payload []byte

	// Check if this is TLS 1.2 AES-GCM (needs explicit IV)
	isTLS12AESGCMCipher := c.handshakeDisclosure != nil &&
		(c.handshakeDisclosure.CipherSuite == 0xc02f || // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			c.handshakeDisclosure.CipherSuite == 0xc02b || // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
			c.handshakeDisclosure.CipherSuite == 0xc030 || // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
			c.handshakeDisclosure.CipherSuite == 0xc02c) // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

	if isTLS12AESGCMCipher {
		// TLS 1.2 AES-GCM: explicit_iv(8) + encrypted_data + auth_tag(16)
		// Explicit IV = sequence number (big-endian, 8 bytes)
		seqNum := uint64(1) // Application data sequence number after handshake
		explicitIV := make([]byte, 8)
		explicitIV[0] = byte(seqNum >> 56)
		explicitIV[1] = byte(seqNum >> 48)
		explicitIV[2] = byte(seqNum >> 40)
		explicitIV[3] = byte(seqNum >> 32)
		explicitIV[4] = byte(seqNum >> 24)
		explicitIV[5] = byte(seqNum >> 16)
		explicitIV[6] = byte(seqNum >> 8)
		explicitIV[7] = byte(seqNum)

		payload = make([]byte, 8+len(encData.EncryptedData)+len(encData.AuthTag))
		copy(payload[0:8], explicitIV)
		copy(payload[8:8+len(encData.EncryptedData)], encData.EncryptedData)
		copy(payload[8+len(encData.EncryptedData):], encData.AuthTag)
	} else {
		// TLS 1.3 or ChaCha20: encrypted_data + auth_tag
		payload = make([]byte, len(encData.EncryptedData)+len(encData.AuthTag))
		copy(payload, encData.EncryptedData)
		copy(payload[len(encData.EncryptedData):], encData.AuthTag)
	}

	recordLength := len(payload)
	tlsRecord := make([]byte, 5+recordLength)
	tlsRecord[0] = 0x17                      // ApplicationData record type
	tlsRecord[1] = 0x03                      // TLS version major
	tlsRecord[2] = 0x03                      // TLS version minor
	tlsRecord[3] = byte(recordLength >> 8)   // Length high byte
	tlsRecord[4] = byte(recordLength & 0xFF) // Length low byte
	copy(tlsRecord[5:], payload)             // Complete payload

	fmt.Printf("[Client] Sending TLS record (%d bytes)\n", len(tlsRecord))

	// *** CAPTURE OUTGOING APPLICATION DATA RECORD FOR TRANSCRIPT VALIDATION ***
	// TEE_T expects individual TLS records for application data, not raw TCP chunks
	c.capturedTraffic = append(c.capturedTraffic, tlsRecord)
	fmt.Printf("[Client] Captured outgoing application data record: type 0x%02x, %d bytes\n", tlsRecord[0], len(tlsRecord))
	fmt.Printf("[Client] Total captured records now: %d\n", len(c.capturedTraffic))

	// Send to website via TCP connection
	if c.tcpConn != nil {
		n, err := c.tcpConn.Write(tlsRecord)
		if err != nil {
			log.Printf("[Client] Failed to write to TCP connection: %v", err)
			return
		}
		fmt.Printf("[Client] Sent %d bytes to website\n", n)

		// Mark that HTTP request has been sent and we're expecting a response
		c.httpRequestSent = true
		c.httpResponseExpected = true
		fmt.Printf("[Client] HTTP request sent, now expecting HTTP response...\n")

	} else {
		log.Printf("[Client] No TCP connection available")
	}
}

// handleTEETReady handles TEE_T ready confirmation
func (c *Client) handleTEETReady(msg *Message) {
	var readyData TEETReadyData
	if err := msg.UnmarshalData(&readyData); err != nil {
		log.Printf("[Client] Failed to unmarshal TEE_T ready data: %v", err)
		return
	}

}

// handleRedactionVerification handles redaction verification from TEE_T
func (c *Client) handleRedactionVerification(msg *Message) {
	log.Printf("[Client] DEBUG: Received redaction verification message")

	var verificationData RedactionVerificationData
	if err := msg.UnmarshalData(&verificationData); err != nil {
		log.Printf("[Client] Failed to unmarshal redaction verification data: %v", err)
		return
	}

	if verificationData.Success {
		fmt.Println(" Redaction verification successful")
	} else {
		fmt.Println(" Redaction verification failed")
	}
}

// handleTEETError handles error messages from TEE_T
func (c *Client) handleTEETError(msg *Message) {
	var errorData ErrorData
	if err := msg.UnmarshalData(&errorData); err != nil {
		log.Printf("[Client] Failed to unmarshal TEE_T error: %v", err)
		return
	}

	log.Printf("[Client] TEE_T error: %s", errorData.Message)
}

// handleSignedTranscript processes signed transcript messages from TEE_K and TEE_T
func (c *Client) handleSignedTranscript(msg *Message) {
	var signedTranscript shared.SignedTranscript
	if err := msg.UnmarshalData(&signedTranscript); err != nil {
		log.Printf("[Client] Failed to unmarshal signed transcript: %v", err)
		return
	}

	log.Printf("[Client] Received signed transcript")
	log.Printf("[Client] Transcript contains %d packets", len(signedTranscript.Packets))
	log.Printf("[Client] Comprehensive signature: %d bytes", len(signedTranscript.Signature))
	log.Printf("[Client] Public Key: %d bytes (DER format)", len(signedTranscript.PublicKey))

	// Store the public key for attestation verification
	// Determine source based on transcript structure: TEE_K has RequestMetadata, TEE_T doesn't
	if signedTranscript.RequestMetadata != nil {
		// This is from TEE_K
		c.teekTranscriptPublicKey = signedTranscript.PublicKey
		c.teekSignedTranscript = &signedTranscript
		c.teekTranscriptPackets = signedTranscript.Packets // Store packets for validation
	} else {
		// This is from TEE_T
		c.teetTranscriptPublicKey = signedTranscript.PublicKey
		c.teetSignedTranscript = &signedTranscript
		c.teetTranscriptPackets = signedTranscript.Packets // Store packets for validation
	}

	// Calculate total size of all packets
	totalSize := 0
	for _, packet := range signedTranscript.Packets {
		totalSize += len(packet)
	}

	log.Printf("[Client] Total transcript size: %d bytes", totalSize)

	// Determine source name for logging
	sourceName := "TEE_T"
	if signedTranscript.RequestMetadata != nil {
		sourceName = "TEE_K"
	}

	// Display signature for verification
	if len(signedTranscript.Signature) > 0 {
		fmt.Printf("[Client] %s signature (first 16 bytes): %x\n",
			sourceName, signedTranscript.Signature[:min(16, len(signedTranscript.Signature))])
	}

	// Display public key for verification
	if len(signedTranscript.PublicKey) > 0 {
		fmt.Printf("[Client] %s public key (first 16 bytes): %x\n",
			sourceName, signedTranscript.PublicKey[:min(16, len(signedTranscript.PublicKey))])
	}

	// Verify signature
	log.Printf("[Client] Verifying signature for %s transcript...", sourceName)
	var verificationErr error
	if signedTranscript.RequestMetadata != nil {
		// This is TEE_K - check if we have all expected redacted streams before verification
		log.Printf("[Client] TEE_K transcript received, checking if all expected redacted streams are available...")
		if len(c.signedRedactedStreams) < c.expectedRedactedStreams {
			log.Printf("[Client] TEE_K comprehensive verification deferred - waiting for redacted streams (%d/%d)", len(c.signedRedactedStreams), c.expectedRedactedStreams)
			// Mark transcript as received but don't verify signature yet
			c.setCompletionFlag(CompletionFlagTEEKTranscriptReceived)
			// Don't set signature valid flag yet - will be set after successful verification
		} else {
			log.Printf("[Client] TEE_K comprehensive verification: have all %d expected redacted streams", c.expectedRedactedStreams)
			verificationErr = shared.VerifyComprehensiveSignature(&signedTranscript, c.signedRedactedStreams)
			if verificationErr != nil {
				log.Printf("[Client] Signature verification FAILED for %s: %v", sourceName, verificationErr)
				fmt.Printf("[Client] %s signature verification FAILED: %v\n", sourceName, verificationErr)
			} else {
				log.Printf("[Client] Signature verification SUCCESS for %s", sourceName)
				fmt.Printf("[Client] %s signature verification SUCCESS\n", sourceName)
			}

			// Mark transcript as received and set signature validity
			c.setCompletionFlag(CompletionFlagTEEKTranscriptReceived)
			if verificationErr == nil {
				c.setCompletionFlag(CompletionFlagTEEKSignatureValid)
			}
		}
	} else {
		// This is TEE_T - use regular TLS packet verification
		verificationErr = shared.VerifyTranscriptSignature(&signedTranscript)
		if verificationErr != nil {
			log.Printf("[Client] Signature verification FAILED for %s: %v", sourceName, verificationErr)
			fmt.Printf("[Client] %s signature verification FAILED: %v\n", sourceName, verificationErr)
		} else {
			log.Printf("[Client] Signature verification SUCCESS for %s", sourceName)
			fmt.Printf("[Client] %s signature verification SUCCESS\n", sourceName)
		}

		// Mark transcript as received and set signature validity
		c.setCompletionFlag(CompletionFlagTEETTranscriptReceived)
		if verificationErr == nil {
			c.setCompletionFlag(CompletionFlagTEETSignatureValid)
		}
	}

	log.Printf("[Client] Marked %s transcript as received (signature valid: %v)", sourceName, verificationErr == nil)

	// Check if we now have both transcript public keys and can verify against attestations
	if c.teekTranscriptPublicKey != nil && c.teetTranscriptPublicKey != nil && !c.publicKeyComparisonDone {
		log.Printf("[Client] Both transcript public keys received - verifying against attestations...")
		if err := c.verifyAttestationPublicKeys(); err != nil {
			log.Printf("[Client] Attestation public key verification failed: %v", err)
			fmt.Printf("[Client] ATTESTATION VERIFICATION FAILED: %v\n", err)
		} else {
			log.Printf("[Client] Attestation public key verification successful")
			fmt.Printf("[Client] ATTESTATION VERIFICATION SUCCESSFUL - transcripts are from verified enclaves\n")
		}
	}

	transcriptsComplete := c.hasAllCompletionFlags(CompletionFlagTEEKTranscriptReceived | CompletionFlagTEETTranscriptReceived)
	signaturesValid := c.hasAllCompletionFlags(CompletionFlagTEEKSignatureValid | CompletionFlagTEETSignatureValid)

	log.Printf("[Client] Signed transcript from %s processed successfully", sourceName)

	// Show packet summary
	fmt.Printf("[Client] %s transcript summary:\n", sourceName)
	// for i, packet := range signedTranscript.Packets {
	// 	if len(packet) > 0 {
	// 	}
	// }

	// *** CRITICAL VALIDATION: Compare TEE transcripts with client's captured traffic ***
	if transcriptsComplete && signaturesValid {
		log.Printf("[Client] Both transcripts received with valid signatures - performing transcript validation...")
		c.validateTranscriptsAgainstCapturedTraffic()
	}

	if transcriptsComplete {
		if signaturesValid {
			log.Println("[Client] Received signed transcripts from both TEE_K and TEE_T with VALID signatures!")
		} else {
			log.Println("[Client] Received signed transcripts from both TEE_K and TEE_T but signatures are INVALID!")
		}
	}

	// Check protocol completion (function will only proceed if all conditions are met)
	c.checkProtocolCompletion("signed transcript received from " + sourceName)
}

// validateTranscriptsAgainstCapturedTraffic performs comprehensive validation of signed transcripts
// against the client's captured TLS traffic to ensure integrity and completeness
func (c *Client) validateTranscriptsAgainstCapturedTraffic() {
	fmt.Printf("\n===== TRANSCRIPT VALIDATION REPORT =====\n")

	log.Printf("[Client] Validating transcripts against %d captured TLS records", len(c.capturedTraffic))

	// Since we now capture raw TCP chunks exactly as TEE_K sees them,
	// we should compare them directly without trying to categorize by TLS record type
	fmt.Printf("[Client] DEBUG: Analyzing each captured TCP chunk:\n")

	for i, chunk := range c.capturedTraffic {
		if len(chunk) < 1 {
			fmt.Printf("[Client] Chunk %d: EMPTY (length: 0)\n", i)
			continue
		}

	}

	// Calculate total sizes
	totalCapturedSize := 0
	for _, chunk := range c.capturedTraffic {
		totalCapturedSize += len(chunk)
	}

	fmt.Printf("[Client] Client captured traffic analysis:\n")
	fmt.Printf("[Client]   Total chunks: %d\n", len(c.capturedTraffic))
	fmt.Printf("[Client]   Total captured size: %d bytes\n", totalCapturedSize)

	// Perform detailed comparison with TEE transcripts
	fmt.Printf("\n[Client] Detailed transcript comparison:\n")

	// Validate TEE_K transcript (should contain raw TCP chunks - bidirectional)
	teekValidation := c.validateTEEKTranscriptRaw()

	// Validate TEE_T transcript (should contain application data packets - bidirectional)
	teetValidation := c.validateTEETTranscriptRaw()

	// Summary
	fmt.Printf("\n[Client] VALIDATION RESULTS:\n")
	fmt.Printf("[Client]   Both TEE_K and TEE_T transcripts received\n")
	fmt.Printf("[Client]   Both transcript signatures verified successfully\n")
	fmt.Printf("[Client]   Client captured %d TCP chunks during session (bidirectional)\n", len(c.capturedTraffic))

	if teekValidation && teetValidation {
		fmt.Printf("[Client]   TRANSCRIPT VALIDATION PASSED - All packets match!\n")
	} else {
		fmt.Printf("[Client]   TRANSCRIPT VALIDATION FAILED - Packet mismatches detected!\n")
	}

	fmt.Printf("===== VALIDATION COMPLETE =====\n\n")
}

// validateTEEKTranscriptRaw validates TEE_K transcript against client raw TCP chunks
func (c *Client) validateTEEKTranscriptRaw() bool {
	fmt.Printf("[Client] Validating TEE_K transcript (%d packets) against client captures\n",
		len(c.teekTranscriptPackets))

	if c.teekTranscriptPackets == nil {
		fmt.Printf("[Client] TEE_K transcript packets not available\n")
		return false
	}

	// TEE_K captures raw TCP chunks during handshake, so we should compare against
	// the raw TCP chunks we captured (not the individual TLS records from application phase)
	fmt.Printf("[Client] TEE_K transcript analysis:\n")

	handshakePacketsMatched := 0
	totalCompared := 0 // number of transcript packets that we actually compared against captures
	for _, teekPacket := range c.teekTranscriptPackets {

		// All transcript packets are now TLS records by definition
		totalCompared++

		// Check if this packet matches any of the client's captured data
		found := false
		for _, chunk := range c.capturedTraffic {
			if len(teekPacket) == len(chunk) && bytes.Equal(teekPacket, chunk) {
				handshakePacketsMatched++
				found = true
				break
			}
		}

		if !found {
			fmt.Printf("[Client]     NOT found in client captures\n")
			// Show first 32 bytes of TEE_K packet for debugging
			fmt.Printf("[Client]       TEE_K packet: %x...\n", teekPacket[:min(32, len(teekPacket))])
		}
	}

	fmt.Printf("[Client] TEE_K validation result: %d/%d packets matched exactly\n",
		handshakePacketsMatched, totalCompared)

	return handshakePacketsMatched == totalCompared
}

// validateTEETTranscriptRaw validates TEE_T transcript against client application data records
func (c *Client) validateTEETTranscriptRaw() bool {
	fmt.Printf("[Client] Validating TEE_T transcript (%d packets) against client captures\n",
		len(c.teetTranscriptPackets))

	if c.teetTranscriptPackets == nil {
		fmt.Printf("[Client] TEE_T transcript packets not available\n")
		return false
	}

	fmt.Printf("[Client] TEE_T transcript analysis:\n")

	packetsMatched := 0
	for i, teetPacket := range c.teetTranscriptPackets {
		fmt.Printf("[Client]   TEE_T packet %d: %d bytes (type: 0x%02x)\n",
			i+1, len(teetPacket), teetPacket[0])

		// Check if this packet matches any of our captured packets
		found := false
		for _, clientPacket := range c.capturedTraffic {
			if len(teetPacket) == len(clientPacket) && bytes.Equal(teetPacket, clientPacket) {
				packetsMatched++
				found = true
				break
			}
		}

		if !found {
			fmt.Printf("[Client]     NOT found in client captures\n")
			// Show first 32 bytes of TEE_T packet for debugging
			fmt.Printf("[Client]       TEE_T packet: %x...\n", teetPacket[:min(32, len(teetPacket))])
		}
	}

	fmt.Printf("[Client] TEE_T validation result: %d/%d packets matched exactly\n",
		packetsMatched, len(c.teetTranscriptPackets))

	return packetsMatched == len(c.teetTranscriptPackets)
}

// handleSignedRedactedDecryptionStream handles redacted decryption streams from TEE_K
func (c *Client) handleSignedRedactedDecryptionStream(msg *Message) {
	var redactedStream shared.SignedRedactedDecryptionStream
	if err := msg.UnmarshalData(&redactedStream); err != nil {
		log.Printf("[Client] Failed to unmarshal redacted decryption stream: %v", err)
		return
	}

	log.Printf("[Client] Received redacted decryption stream for seq %d (%d bytes)",
		redactedStream.SeqNum, len(redactedStream.RedactedStream))

	// Add to collection for verification bundle
	c.signedRedactedStreams = append(c.signedRedactedStreams, redactedStream)

	// *** FIXED: Only verify TEE_K signature when ALL expected redacted streams received ***
	if c.teekSignedTranscript != nil && !c.hasCompletionFlag(CompletionFlagTEEKSignatureValid) {
		if len(c.signedRedactedStreams) >= c.expectedRedactedStreams {
			log.Printf("[Client] Received all %d expected redacted streams, attempting TEE_K comprehensive signature verification", c.expectedRedactedStreams)
			verificationErr := shared.VerifyComprehensiveSignature(c.teekSignedTranscript, c.signedRedactedStreams)
			if verificationErr != nil {
				log.Printf("[Client] TEE_K signature verification FAILED: %v", verificationErr)
				fmt.Printf("[Client] TEE_K signature verification FAILED: %v\n", verificationErr)
			} else {
				log.Printf("[Client] TEE_K signature verification SUCCESS")
				fmt.Printf("[Client] TEE_K signature verification SUCCESS\n")
				c.setCompletionFlag(CompletionFlagTEEKSignatureValid)

				// Check if we can now proceed with full protocol completion
				transcriptsComplete := c.hasAllCompletionFlags(CompletionFlagTEEKTranscriptReceived | CompletionFlagTEETTranscriptReceived)
				signaturesValid := c.hasAllCompletionFlags(CompletionFlagTEEKSignatureValid | CompletionFlagTEETSignatureValid)

				if transcriptsComplete && signaturesValid {
					log.Printf("[Client] Both transcripts received with valid signatures - performing transcript validation...")
					c.validateTranscriptsAgainstCapturedTraffic()
					fmt.Printf("[Client] Received signed transcripts from both TEE_K and TEE_T with VALID signatures!")
				}
			}
		} else {
			log.Printf("[Client] Received redacted stream %d/%d - waiting for remaining streams before verification", len(c.signedRedactedStreams), c.expectedRedactedStreams)
			log.Printf("[Client] 🔧 REDACTED STREAM DEBUG: Received seq %d (%d bytes)", redactedStream.SeqNum, len(redactedStream.RedactedStream))

			// Show which sequences have redacted streams so far
			sequences := make([]uint64, 0, len(c.signedRedactedStreams))
			for _, stream := range c.signedRedactedStreams {
				sequences = append(sequences, stream.SeqNum)
			}
			log.Printf("[Client] 🔧   Sequences with redacted streams: %v", sequences)
		}
	}

	// Note: Individual stream signatures removed - using master signature verification

	// Apply redacted stream to ciphertext to get redacted plaintext
	c.responseContentMutex.Lock()
	ciphertext, exists := c.ciphertextBySeq[redactedStream.SeqNum]
	c.responseContentMutex.Unlock()

	if !exists {
		log.Printf("[Client] No ciphertext found for seq %d", redactedStream.SeqNum)
		return
	}

	if len(redactedStream.RedactedStream) != len(ciphertext) {
		log.Printf("[Client] Stream length mismatch for seq %d: stream=%d, ciphertext=%d",
			redactedStream.SeqNum, len(redactedStream.RedactedStream), len(ciphertext))
		return
	}

	// XOR ciphertext with redacted stream to get redacted plaintext
	redactedPlaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		redactedPlaintext[i] = ciphertext[i] ^ redactedStream.RedactedStream[i]
	}

	// *** DEBUG: For session tickets (seq 1-2), show XOR result ***
	if redactedStream.SeqNum <= 2 {
		log.Printf("[Client] 🔧 XOR DEBUG for seq %d:", redactedStream.SeqNum)
		log.Printf("[Client] 🔧   Ciphertext[0:16]: %x", ciphertext[:min(16, len(ciphertext))])
		log.Printf("[Client] 🔧   RedactedStream[0:16]: %x", redactedStream.RedactedStream[:min(16, len(redactedStream.RedactedStream))])
		log.Printf("[Client] 🔧   Result[0:16]: %x", redactedPlaintext[:min(16, len(redactedPlaintext))])
		log.Printf("[Client] 🔧   Result as string[0:16]: %q", string(redactedPlaintext[:min(16, len(redactedPlaintext))]))

		// Count asterisks in result
		asteriskCount := 0
		for _, b := range redactedPlaintext {
			if b == '*' {
				asteriskCount++
			}
		}
		log.Printf("[Client] 🔧   Asterisk count: %d/%d", asteriskCount, len(redactedPlaintext))
	}

	log.Printf("[Client] Generated redacted plaintext for seq %d (%d bytes)",
		redactedStream.SeqNum, len(redactedPlaintext))

	// Store the redacted plaintext and check if we are ready to print
	c.responseContentMutex.Lock()
	c.redactedPlaintextBySeq[redactedStream.SeqNum] = redactedPlaintext
	c.responseContentMutex.Unlock()

	// *** NOTE: No longer printing from XOR streams - client displays immediately from ranges ***
	log.Printf("[Client] 🔧 XOR STREAM CHECK: Have %d redacted streams, expecting %d",
		len(c.redactedPlaintextBySeq), c.expectedRedactedStreams)
	log.Printf("[Client] 🔧 XOR streams are for verifier use only - client displays from ranges")

	// Check protocol completion after processing redacted stream
	c.checkProtocolCompletion("redacted stream processed")
}

// printRedactedResponse - DEPRECATED: No longer used for client display
// Client now displays immediately from ranges, this is kept only for verifier compatibility
func (c *Client) printRedactedResponse() {
	log.Printf("[Client] 🔧 DEPRECATED: printRedactedResponse called (XOR-based display no longer used)")
	return // Early return - client displays from ranges now
	c.responseContentMutex.Lock()
	defer c.responseContentMutex.Unlock()

	// Only print if we have received all expected redacted streams
	if len(c.redactedPlaintextBySeq) < int(atomic.LoadInt64(&c.recordsSent)) {
		return
	}

	// Guard against multiple prints of the same response
	if c.fullRedactedResponse != nil {
		return
	}

	log.Printf("[Client] All redacted streams received, printing full response...")

	// *** USE XOR STREAMS (same as verifier) - must produce clean asterisks ***
	keys := make([]int, 0, len(c.redactedPlaintextBySeq))
	for k := range c.redactedPlaintextBySeq {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)

	log.Printf("[Client] 🔧 ASSEMBLY DEBUG: Found %d sequences to assemble", len(keys))

	var fullResponse strings.Builder
	for i, k := range keys {
		seqData := c.redactedPlaintextBySeq[uint64(k)]
		fullResponse.Write(seqData)

		// Debug first few sequences
		if i < 5 {
			log.Printf("[Client] 🔧   Seq %d: %d bytes", k, len(seqData))
			if len(seqData) > 0 {
				// Count asterisks in this sequence
				asteriskCount := 0
				for _, b := range seqData {
					if b == '*' {
						asteriskCount++
					}
				}
				log.Printf("[Client] 🔧   Seq %d asterisks: %d/%d", k, asteriskCount, len(seqData))

				// Show first 16 bytes
				preview := seqData[:min(16, len(seqData))]
				log.Printf("[Client] 🔧   Seq %d first 16 bytes: %x", k, preview)
				log.Printf("[Client] 🔧   Seq %d as string: %q", k, string(preview))
			}
		}
	}

	c.fullRedactedResponse = []byte(fullResponse.String())

	// *** DEBUG: Check assembled response ***
	assembled := fullResponse.String()
	log.Printf("[Client] 🔧 ASSEMBLED RESPONSE:")
	log.Printf("[Client] 🔧   Total length: %d bytes", len(assembled))
	if len(assembled) > 0 {
		preview := assembled[:min(64, len(assembled))]
		log.Printf("[Client] 🔧   First 64 bytes: %x", []byte(preview))
		log.Printf("[Client] 🔧   As string: %q", preview)
	}

	// Print the XOR-assembled response (should be identical to verifier)
	fmt.Printf("\n\n--- FINAL REDACTED RESPONSE ---\n%s\n--- END REDACTED RESPONSE ---\n\n",
		collapseAsterisks(fullResponse.String()))
}

// Close closes all WebSocket connections
func (c *Client) Close() {
	c.isClosing = true

	// *** Close TCP connection FIRST to allow tcpToWebsocket() to exit gracefully ***
	// This mimics standard HTTP client behavior - close the underlying connection first
	if c.tcpConn != nil {
		c.tcpConn.Close()
		c.tcpConn = nil
	}

	// Close TEE_K connection
	if c.wsConn != nil {
		c.wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		c.wsConn.Close()
		c.wsConn = nil
	}

	// Close TEE_T connection
	if c.teetConn != nil {
		c.teetConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		c.teetConn.Close()
		c.teetConn = nil
	}
}

// handleAttestationResponse handles attestation responses from both TEE_K and TEE_T
func (c *Client) handleAttestationResponse(msg *Message) {
	var attestResp AttestationResponseData
	if err := msg.UnmarshalData(&attestResp); err != nil {
		log.Printf("[Client] Failed to unmarshal attestation response: %v", err)
		return
	}

	if !attestResp.Success {
		// Only log attestation failures in enclave mode - they're expected in standalone mode
		if c.isEnclaveMode() {
			log.Printf("[Client] Attestation request failed: %s", attestResp.ErrorMessage)
		}
		return
	}

	// Try to verify as TEE_K first
	var sourceTEE string
	var publicKey []byte
	var err error

	publicKey, err = c.verifyAttestation(attestResp.AttestationDoc, "tee_k")
	if err == nil {
		sourceTEE = "TEE_K"
		c.teekAttestationPublicKey = publicKey
		log.Printf("[Client] TEE_K attestation verified successfully")
	} else {
		// Try as TEE_T
		publicKey, err = c.verifyAttestation(attestResp.AttestationDoc, "tee_t")
		if err == nil {
			sourceTEE = "TEE_T"
			c.teetAttestationPublicKey = publicKey
			log.Printf("[Client] TEE_T attestation verified successfully")
		} else {
			log.Printf("[Client] Failed to verify attestation as either TEE_K or TEE_T: %v", err)
			return
		}
	}

	fmt.Printf("[Client] Received successful attestation response from %s (%d bytes)\n", sourceTEE, len(attestResp.AttestationDoc))

	// Check if we have both attestations and can proceed
	if c.teekAttestationPublicKey != nil && c.teetAttestationPublicKey != nil {
		c.attestationVerified = true
		fmt.Printf("[Client] Successfully verified both TEE_K and TEE_T attestations via WebSocket\n")

		// Display public keys in a more distinguishable way
		// For P-256 keys, skip the common DER header (first ~26 bytes) and show the actual key material
		teekDisplayBytes := c.teekAttestationPublicKey
		if len(c.teekAttestationPublicKey) > 26 {
			teekDisplayBytes = c.teekAttestationPublicKey[26:] // Skip DER header, show actual key material
		}

		teetDisplayBytes := c.teetAttestationPublicKey
		if len(c.teetAttestationPublicKey) > 26 {
			teetDisplayBytes = c.teetAttestationPublicKey[26:] // Skip DER header, show actual key material
		}

		fmt.Printf("[Client] TEE_K public key (key material): %x\n", teekDisplayBytes[:min(32, len(teekDisplayBytes))])
		fmt.Printf("[Client] TEE_T public key (key material): %x\n", teetDisplayBytes[:min(32, len(teetDisplayBytes))])
		fmt.Printf("[Client] TEE_K full key length: %d bytes\n", len(c.teekAttestationPublicKey))
		fmt.Printf("[Client] TEE_T full key length: %d bytes\n", len(c.teetAttestationPublicKey))

		// Check if we now have transcript public keys and can compare
		if c.teekTranscriptPublicKey != nil && c.teetTranscriptPublicKey != nil && !c.publicKeyComparisonDone {
			log.Printf("[Client] Both attestation and transcript public keys available - verifying...")
			if err := c.verifyAttestationPublicKeys(); err != nil {
				log.Printf("[Client] Attestation public key verification failed: %v", err)
				fmt.Printf("[Client] ATTESTATION VERIFICATION FAILED: %v\n", err)
			} else {
				log.Printf("[Client] Attestation public key verification successful")
				fmt.Printf("[Client] ATTESTATION VERIFICATION SUCCESSFUL - transcripts are from verified enclaves\n")
			}
		}
	}
}

// *** NEW: Handle batched tag verification results ***
func (c *Client) handleBatchedTagVerifications(msg *Message) {
	var batchedVerification BatchedTagVerificationData
	if err := msg.UnmarshalData(&batchedVerification); err != nil {
		log.Printf("[Client] Failed to unmarshal batched tag verification: %v", err)
		return
	}

	fmt.Printf("[Client] BATCHING: Received batch tag verification for %d responses (all successful: %v)\n",
		batchedVerification.TotalCount, batchedVerification.AllSuccessful)

	// Process each verification result to update completion counters
	for _, verification := range batchedVerification.Verifications {
		if verification.Success {
			fmt.Printf("[Client] Response tag verification successful (seq=%d)\n", verification.SeqNum)
			// *** CRITICAL: Increment completion counters to match existing logic ***
			atomic.AddInt64(&c.recordsProcessed, 1)
			fmt.Printf("[Client] BATCHING: Incremented recordsProcessed to %d\n", atomic.LoadInt64(&c.recordsProcessed))
		} else {
			log.Printf("[Client] Response tag verification failed (seq=%d): %s", verification.SeqNum, verification.Message)
		}
	}

	fmt.Printf("[Client] BATCHING: Processed %d tag verifications\n", len(batchedVerification.Verifications))
}

// *** NEW: Handle batched decryption streams ***
func (c *Client) handleBatchedDecryptionStreams(msg *Message) {
	fmt.Printf("[Client] BATCHING: handleBatchedDecryptionStreams started\n")
	defer fmt.Printf("[Client] BATCHING: handleBatchedDecryptionStreams FINISHED\n")

	var batchedStreams BatchedDecryptionStreamData
	if err := msg.UnmarshalData(&batchedStreams); err != nil {
		log.Printf("[Client] Failed to unmarshal batched decryption streams: %v", err)
		return
	}

	fmt.Printf("[Client] BATCHING: Received batch of %d decryption streams\n", batchedStreams.TotalCount)
	fmt.Printf("[Client] BATCHING: About to process %d streams\n", len(batchedStreams.DecryptionStreams))

	if len(batchedStreams.DecryptionStreams) == 0 {
		fmt.Printf("[Client] BATCHING: No streams to process, calling completion check\n")
		c.checkProtocolCompletion("batched decryption streams processed (empty)")
		return
	}

	// Process each decryption stream
	for i, streamData := range batchedStreams.DecryptionStreams {
		if i%100 == 0 { // Log every 100 streams to avoid spam
			fmt.Printf("[Client] BATCHING: Processing stream %d/%d\n", i+1, len(batchedStreams.DecryptionStreams))
		}

		// Store decryption stream by sequence number (preserve existing logic)
		c.responseContentMutex.Lock()
		c.decryptionStreamBySeq[streamData.SeqNum] = streamData.DecryptionStream
		c.responseContentMutex.Unlock()

		// Decrypt and store redacted plaintext (preserve existing logic)
		if ciphertext, exists := c.ciphertextBySeq[streamData.SeqNum]; exists {
			redactedPlaintext := make([]byte, len(ciphertext))
			for j := 0; j < len(ciphertext); j++ {
				redactedPlaintext[j] = ciphertext[j] ^ streamData.DecryptionStream[j]
			}

			// *** SIMPLIFIED: Minimize mutex usage ***
			c.responseContentMutex.Lock()

			// *** CRITICAL: Initialize maps if they're nil to prevent panic ***
			if c.redactedPlaintextBySeq == nil {
				c.redactedPlaintextBySeq = make(map[uint64][]byte)
			}
			if c.responseContentBySeq == nil {
				c.responseContentBySeq = make(map[uint64][]byte)
			}
			if c.recordTypeBySeq == nil {
				c.recordTypeBySeq = make(map[uint64]byte)
			}

			c.redactedPlaintextBySeq[streamData.SeqNum] = redactedPlaintext
			c.responseContentBySeq[streamData.SeqNum] = redactedPlaintext
			c.responseContentMutex.Unlock()

			// *** CRITICAL: Increment completion counters to match existing logic ***
			atomic.AddInt64(&c.decryptionStreamsReceived, 1)
		} else {
			log.Printf("[Client] No ciphertext found for seq=%d", streamData.SeqNum)
		}
	}

	fmt.Printf("[Client] BATCHING: Processed %d decryption streams\n", len(batchedStreams.DecryptionStreams))

	// *** CRITICAL: Reconstruct HTTP response and call callback BEFORE protocol completion ***
	if !c.responseReconstructed {
		c.reconstructHTTPResponseFromDecryptedData()
		c.responseReconstructed = true

		// Give a moment for callback results to be stored
		fmt.Printf("[Client] BATCHING: HTTP response reconstruction completed, callback executed\n")
	}

	// *** CRITICAL: Trigger completion check after callback execution ***
	fmt.Printf("[Client] BATCHING: About to call checkProtocolCompletion...\n")
	c.checkProtocolCompletion("batched decryption streams processed")
	fmt.Printf("[Client] BATCHING: checkProtocolCompletion returned\n")
}

// *** NEW: Reconstruct HTTP response from all decrypted response data ***
func (c *Client) reconstructHTTPResponseFromDecryptedData() {
	c.responseContentMutex.Lock()
	defer c.responseContentMutex.Unlock()

	if len(c.redactedPlaintextBySeq) == 0 {
		fmt.Printf("[Client] No decrypted response data to reconstruct\n")
		return
	}

	// Sort sequence numbers and concatenate response data
	var seqNums []uint64
	for seqNum := range c.redactedPlaintextBySeq {
		seqNums = append(seqNums, seqNum)
	}
	sort.Slice(seqNums, func(i, j int) bool { return seqNums[i] < seqNums[j] })

	var fullResponse []byte
	for _, seqNum := range seqNums {
		if seqNum > 0 { // Skip handshake sequences (seq 0)
			plaintext := c.redactedPlaintextBySeq[seqNum]

			// *** FIX: Use stored TLS record type instead of extracting from plaintext ***
			if len(plaintext) > 0 {
				// Get the TLS record type that was stored during processing
				recordType, hasRecordType := c.recordTypeBySeq[seqNum]
				if !hasRecordType {
					log.Printf("[Client] No record type found for seq %d, skipping", seqNum)
					continue
				}

				// For TLS 1.3, we need to remove padding and extract content type
				var actualContent []byte
				var contentType byte

				if c.handshakeDisclosure != nil && c.isTLS12CipherSuite(c.handshakeDisclosure.CipherSuite) {
					// TLS 1.2: No inner content type, use record type
					actualContent = plaintext
					contentType = recordType
				} else {
					// TLS 1.3: Remove padding and get inner content type
					actualContent, contentType = c.removeTLSPadding(plaintext)
				}

				// Only include application data (0x17), skip handshake (0x16) and alerts (0x15)
				if contentType == 0x17 && len(actualContent) > 0 {
					fullResponse = append(fullResponse, actualContent...)
				}
			}
		}
	}

	fmt.Printf("[Client] BATCHING: Reconstructed HTTP response (%d bytes total)\n", len(fullResponse))

	// Parse HTTP response and set success flags
	if len(fullResponse) > 0 {
		responseStr := string(fullResponse)

		// *** FIX: Search for HTTP status line anywhere in the response, not just at the beginning ***
		// This handles cases where redacted session tickets prefix the response with asterisks
		httpIndex := strings.Index(responseStr, "HTTP/1.1 ")
		if httpIndex == -1 {
			httpIndex = strings.Index(responseStr, "HTTP/1.0 ")
		}
		if httpIndex == -1 {
			httpIndex = strings.Index(responseStr, "HTTP/2 ")
		}

		if httpIndex != -1 {
			fmt.Printf("[Client] BATCHING: HTTP response reconstruction successful at offset %d\n", httpIndex)

			// Extract the actual HTTP response
			actualHTTPResponse := responseStr[httpIndex:]

			// If there was data before the HTTP response, log it
			if httpIndex > 0 {
				prefixData := responseStr[:httpIndex]
				previewData := prefixData[:min(100, len(prefixData))] // Show more data but collapse asterisks
				fmt.Printf("[Client] BATCHING: Found %d bytes before HTTP response (likely redacted session tickets): %q\n",
					httpIndex, collapseAsterisks(previewData))
			}

			// *** CRITICAL: Set success flags for results reporting ***
			c.responseProcessingMutex.Lock()
			c.responseProcessingSuccessful = true
			c.reconstructedResponseSize = len(actualHTTPResponse)
			c.responseProcessingMutex.Unlock()

			// *** NATURAL PLACE: Call response callback now that we have complete HTTP response ***
			if c.responseCallback != nil && len(c.lastRedactionRanges) == 0 {
				fmt.Printf("[Client] Calling response callback with complete HTTP response (%d bytes)\n", len(actualHTTPResponse))

				// Parse the HTTP response and call the callback
				httpResponse := c.parseHTTPResponse([]byte(actualHTTPResponse))
				result, err := c.responseCallback.OnResponseReceived(httpResponse)

				if err != nil {
					fmt.Printf("[Client] Response callback error: %v\n", err)
				} else if result != nil {
					fmt.Printf("[Client] Response callback completed with %d redaction ranges and %d proof claims\n",
						len(result.RedactionRanges), len(result.ProofClaims))

					// Store results for use in redaction spec generation
					c.lastProofClaims = result.ProofClaims
					c.lastRedactionRanges = result.RedactionRanges
					c.lastRedactedResponse = result.RedactedBody
					c.lastResponseData = httpResponse

					fmt.Printf("[Client] ✅ STORED callback results: %d ranges, %d claims, %d bytes redacted response\n",
						len(result.RedactionRanges), len(result.ProofClaims), len(result.RedactedBody))

					// Log redaction ranges for debugging
					for i, r := range result.RedactionRanges {
						fmt.Printf("[Client] Redaction range %d: start=%d, length=%d, type=%s\n",
							i+1, r.Start, r.Length, r.Type)
					}

				}
			} else if c.responseCallback != nil {
				fmt.Printf("[Client] Response callback already executed (cached ranges: %d)\n", len(c.lastRedactionRanges))
			}

			// *** Display the raw HTTP response (redaction will be handled at TLS record level) ***
			fmt.Printf("[Client] DEBUG: Raw HTTP response (%d bytes)\n", len(actualHTTPResponse))
			previewLen := 200
			if len(actualHTTPResponse) < previewLen {
				previewLen = len(actualHTTPResponse)
			}
			fmt.Printf("[Client] DEBUG: Raw HTTP response preview: %s\n", actualHTTPResponse[:previewLen])

			// Set success flags
			fmt.Printf("[Client] BATCHING: Response processing marked as successful (%d bytes)\n", len(actualHTTPResponse))
		} else {
			previewLen := 100
			if len(responseStr) < previewLen {
				previewLen = len(responseStr)
			}
			fmt.Printf("[Client] BATCHING: Warning - reconstructed response doesn't look like HTTP: %q\n", responseStr[:previewLen])
		}
	}
}
