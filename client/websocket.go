package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"
	"tee-mpc/shared"

	"github.com/gorilla/websocket"
)

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
				c.terminateConnectionWithError("Failed to parse message from TEE_K", err)
				return
			}
			// Allow graceful shutdown during close
			break
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
				c.terminateConnectionWithError("Failed to parse message from TEE_T", err)
				return
			}
			// Allow graceful shutdown during close
			break
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

		// *** Try to detect connection state ***
		if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {

		} else if strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "connection reset") {

		}

		return err
	}
	return nil
}

// sendError sends an error message to TEE_K (fail-fast implementation)
func (c *Client) sendError(errMsg string) {
	errorMsg, err := CreateMessage(MsgError, ErrorData{Message: errMsg})
	if err != nil {
		c.terminateConnectionWithError("Failed to create error message", err)
		return
	}

	if err := c.sendMessage(errorMsg); err != nil {
		c.terminateConnectionWithError("Failed to send error message", err)
		return
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

// handleError handles error messages from TEE_K (fail-fast implementation)
func (c *Client) handleError(msg *Message) {
	var errorData ErrorData
	if err := msg.UnmarshalData(&errorData); err != nil {
		c.terminateConnectionWithError("Failed to unmarshal error data from TEE_K", err)
		return
	}

	// Any error from TEE_K should terminate the session immediately
	c.terminateConnectionWithError("Received error from TEE_K", fmt.Errorf("TEE_K error: %s", errorData.Message))
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

// handleTEETError handles error messages from TEE_T (fail-fast implementation)
func (c *Client) handleTEETError(msg *Message) {
	var errorData ErrorData
	if err := msg.UnmarshalData(&errorData); err != nil {
		c.terminateConnectionWithError("Failed to unmarshal TEE_T error", err)
		return
	}

	// Any error from TEE_T should terminate the session immediately
	c.terminateConnectionWithError("Received error from TEE_T", fmt.Errorf("TEE_T error: %s", errorData.Message))
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

	// Display signature and public key info for verification
	if len(signedTranscript.Signature) > 0 {
		fmt.Printf("[Client] %s signature: %d bytes\n", sourceName, len(signedTranscript.Signature))
	}

	if len(signedTranscript.PublicKey) > 0 {
		fmt.Printf("[Client] %s public key: %d bytes\n", sourceName, len(signedTranscript.PublicKey))
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
	if len(signedTranscript.Packets) > 0 {
		// Display packet information
		for i, packet := range signedTranscript.Packets {
			fmt.Printf("[Client] TEE_K packet %d: %d bytes\n", i+1, len(packet))
		}
	}

	if len(signedTranscript.Packets) > 0 {
		// Display packet information
		for i, packet := range signedTranscript.Packets {
			fmt.Printf("[Client] TEE_T packet %d: %d bytes\n", i+1, len(packet))
		}
	}

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

// terminateConnectionWithError performs immediate connection termination due to critical error
// This implements strict fail-fast behavior - no error continuation is allowed
func (c *Client) terminateConnectionWithError(reason string, err error) {
	// Log the critical error
	log.Printf("[Client] CRITICAL ERROR - terminating connection: %s: %v", reason, err)

	// Perform immediate cleanup and termination
	c.Close()

	// Signal completion to prevent hanging
	c.completionOnce.Do(func() {
		close(c.completionChan)
	})
}
