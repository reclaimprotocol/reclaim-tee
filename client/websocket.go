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
		case MsgResponseDecryptionStream:
			c.handleResponseDecryptionStream(msg)
		case MsgDecryptedResponse:
			c.handleDecryptedResponse(msg)
		case MsgSignedRedactedDecryptionStream:
			c.handleSignedRedactedDecryptionStream(msg)
		case MsgSignedTranscript:
			c.handleSignedTranscript(msg)
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
		case MsgError:
			c.handleTEETError(msg)
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
	// TLS ApplicationData record format: [type(1)] [version(2)] [length(2)] [encrypted_payload + tag]
	taggedData := make([]byte, len(encData.EncryptedData)+len(encData.AuthTag))
	copy(taggedData, encData.EncryptedData)
	copy(taggedData[len(encData.EncryptedData):], encData.AuthTag)

	recordLength := len(taggedData)
	tlsRecord := make([]byte, 5+recordLength)
	tlsRecord[0] = 0x17                      // ApplicationData record type
	tlsRecord[1] = 0x03                      // TLS version major
	tlsRecord[2] = 0x03                      // TLS version minor
	tlsRecord[3] = byte(recordLength >> 8)   // Length high byte
	tlsRecord[4] = byte(recordLength & 0xFF) // Length low byte
	copy(tlsRecord[5:], taggedData)          // Encrypted payload + tag

	fmt.Printf("[Client] Sending TLS record (%d bytes)\n", len(tlsRecord))

	// *** CAPTURE OUTGOING APPLICATION DATA RECORD FOR TRANSCRIPT VALIDATION ***
	// TEE_T expects individual TLS records for application data, not raw TCP chunks
	c.capturedTraffic = append(c.capturedTraffic, tlsRecord)
	fmt.Printf("[Client] 📦 Captured outgoing application data record: type 0x%02x, %d bytes\n", tlsRecord[0], len(tlsRecord))
	fmt.Printf("[Client] 📊 Total captured records now: %d\n", len(c.capturedTraffic))

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
	log.Printf("[Client] DEBUG: Received redaction verification message, raw data type: %T", msg.Data)

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

	log.Printf("[Client] 📝 Received signed transcript from %s", signedTranscript.Source)
	log.Printf("[Client] 📝 Transcript contains %d packets", len(signedTranscript.Packets))
	log.Printf("[Client] 📝 Signature: %d bytes", len(signedTranscript.Signature))
	log.Printf("[Client] 📝 Public Key: %d bytes (DER format)", len(signedTranscript.PublicKey))

	// Store the public key for attestation verification
	switch signedTranscript.Source {
	case "tee_k":
		c.teekTranscriptPublicKey = signedTranscript.PublicKey
		c.teekTranscriptPackets = signedTranscript.Packets // Store packets for validation
	case "tee_t":
		c.teetTranscriptPublicKey = signedTranscript.PublicKey
		c.teetTranscriptPackets = signedTranscript.Packets // Store packets for validation
	}

	// Calculate total size of all packets
	totalSize := 0
	for _, packet := range signedTranscript.Packets {
		totalSize += len(packet)
	}

	log.Printf("[Client] 📝 Total transcript size: %d bytes", totalSize)

	// Display signature for verification
	if len(signedTranscript.Signature) > 0 {
		fmt.Printf("[Client] 📝 %s signature (first 16 bytes): %x\n",
			strings.ToUpper(signedTranscript.Source), signedTranscript.Signature[:min(16, len(signedTranscript.Signature))])
	}

	// Display public key for verification
	if len(signedTranscript.PublicKey) > 0 {
		fmt.Printf("[Client] 📝 %s public key (first 16 bytes): %x\n",
			strings.ToUpper(signedTranscript.Source), signedTranscript.PublicKey[:min(16, len(signedTranscript.PublicKey))])
	}

	// Verify signature
	log.Printf("[Client] 🔐 Verifying signature for %s transcript...", signedTranscript.Source)
	verificationErr := shared.VerifyTranscriptSignature(&signedTranscript)
	if verificationErr != nil {
		log.Printf("[Client] ❌ Signature verification FAILED for %s: %v", signedTranscript.Source, verificationErr)
		fmt.Printf("[Client] ❌ %s signature verification FAILED: %v\n",
			strings.ToUpper(signedTranscript.Source), verificationErr)
		// Don't return here - continue processing but mark signature as invalid
	} else {
		log.Printf("[Client] ✅ Signature verification SUCCESS for %s", signedTranscript.Source)
		fmt.Printf("[Client] ✅ %s signature verification SUCCESS\n",
			strings.ToUpper(signedTranscript.Source))
	}

	// Track transcript completion and signature validity
	switch signedTranscript.Source {
	case "tee_k":
		c.setCompletionFlag(CompletionFlagTEEKTranscriptReceived)
		if verificationErr == nil {
			c.setCompletionFlag(CompletionFlagTEEKSignatureValid)
		}
		log.Printf("[Client] 📝 Marked TEE_K transcript as received (signature valid: %v)", verificationErr == nil)
	case "tee_t":
		c.setCompletionFlag(CompletionFlagTEETTranscriptReceived)
		if verificationErr == nil {
			c.setCompletionFlag(CompletionFlagTEETSignatureValid)
		}
		log.Printf("[Client] 📝 Marked TEE_T transcript as received (signature valid: %v)", verificationErr == nil)
	default:
		log.Printf("[Client] 📝 Unknown transcript source: %s", signedTranscript.Source)
	}

	// Check if we now have both transcript public keys and can verify against attestations
	if c.teekTranscriptPublicKey != nil && c.teetTranscriptPublicKey != nil && !c.publicKeyComparisonDone {
		log.Printf("[Client] 🔒 Both transcript public keys received - verifying against attestations...")
		if err := c.verifyAttestationPublicKeys(); err != nil {
			log.Printf("[Client] ❌ Attestation public key verification failed: %v", err)
			fmt.Printf("[Client] ❌ ATTESTATION VERIFICATION FAILED: %v\n", err)
		} else {
			log.Printf("[Client] ✅ Attestation public key verification successful")
			fmt.Printf("[Client] ✅ ATTESTATION VERIFICATION SUCCESSFUL - transcripts are from verified enclaves\n")
		}
	}

	transcriptsComplete := c.hasAllCompletionFlags(CompletionFlagTEEKTranscriptReceived | CompletionFlagTEETTranscriptReceived)
	signaturesValid := c.hasAllCompletionFlags(CompletionFlagTEEKSignatureValid | CompletionFlagTEETSignatureValid)

	log.Printf("[Client] 📝 Signed transcript from %s processed successfully", signedTranscript.Source)

	// Show packet summary
	fmt.Printf("[Client] 📝 %s transcript summary:\n", strings.ToUpper(signedTranscript.Source))
	for i, packet := range signedTranscript.Packets {
		if len(packet) > 0 {
			fmt.Printf("[Client]   Packet %d: %d bytes (starts with %02x)\n", i+1, len(packet), packet[0])
		}
	}

	// *** CRITICAL VALIDATION: Compare TEE transcripts with client's captured traffic ***
	if transcriptsComplete && signaturesValid {
		log.Printf("[Client] 🔍 Both transcripts received with valid signatures - performing transcript validation...")
		c.validateTranscriptsAgainstCapturedTraffic()
	}

	if transcriptsComplete {
		if signaturesValid {
			log.Printf("[Client] 📝 ✅ Received signed transcripts from both TEE_K and TEE_T with VALID signatures!")
		} else {
			log.Printf("[Client] 📝 ❌ Received signed transcripts from both TEE_K and TEE_T but signatures are INVALID!")
		}
	}

	// Check protocol completion (function will only proceed if all conditions are met)
	c.checkProtocolCompletion("signed transcript received from " + signedTranscript.Source)
}

// validateTranscriptsAgainstCapturedTraffic performs comprehensive validation of signed transcripts
// against the client's captured TLS traffic to ensure integrity and completeness
func (c *Client) validateTranscriptsAgainstCapturedTraffic() {
	fmt.Printf("\n🔍 ===== TRANSCRIPT VALIDATION REPORT =====\n")

	log.Printf("[Client] 🔍 Validating transcripts against %d captured TLS records", len(c.capturedTraffic))

	// Since we now capture raw TCP chunks exactly as TEE_K sees them,
	// we should compare them directly without trying to categorize by TLS record type
	fmt.Printf("[Client] 🔍 DEBUG: Analyzing each captured TCP chunk:\n")

	for i, chunk := range c.capturedTraffic {
		if len(chunk) < 1 {
			fmt.Printf("[Client] 🔍 Chunk %d: EMPTY (length: 0)\n", i)
			continue
		}

		fmt.Printf("[Client] 🔍 Chunk %d: %d bytes, First 16 bytes: %x\n",
			i, len(chunk), chunk[:min(16, len(chunk))])
	}

	// Calculate total sizes
	totalCapturedSize := 0
	for _, chunk := range c.capturedTraffic {
		totalCapturedSize += len(chunk)
	}

	fmt.Printf("[Client] 🔍 Client captured traffic analysis:\n")
	fmt.Printf("[Client]   📊 Total chunks: %d\n", len(c.capturedTraffic))
	fmt.Printf("[Client]   📊 Total captured size: %d bytes\n", totalCapturedSize)

	// Perform detailed comparison with TEE transcripts
	fmt.Printf("\n[Client] 🔍 Detailed transcript comparison:\n")

	// Validate TEE_K transcript (should contain raw TCP chunks - bidirectional)
	teekValidation := c.validateTEEKTranscriptRaw()

	// Validate TEE_T transcript (should contain application data packets - bidirectional)
	teetValidation := c.validateTEETTranscriptRaw()

	// Summary
	fmt.Printf("\n[Client] 🔍 📝 VALIDATION RESULTS:\n")
	fmt.Printf("[Client]   ✅ Both TEE_K and TEE_T transcripts received\n")
	fmt.Printf("[Client]   ✅ Both transcript signatures verified successfully\n")
	fmt.Printf("[Client]   ✅ Client captured %d TCP chunks during session (bidirectional)\n", len(c.capturedTraffic))

	if teekValidation && teetValidation {
		fmt.Printf("[Client]   ✅ TRANSCRIPT VALIDATION PASSED - All packets match!\n")
	} else {
		fmt.Printf("[Client]   ❌ TRANSCRIPT VALIDATION FAILED - Packet mismatches detected!\n")
	}

	fmt.Printf("🔍 ===== VALIDATION COMPLETE =====\n\n")
}

// validateTEEKTranscriptRaw validates TEE_K transcript against client raw TCP chunks
func (c *Client) validateTEEKTranscriptRaw() bool {
	fmt.Printf("[Client] 🔍 Validating TEE_K transcript (%d packets) against client captures\n",
		len(c.teekTranscriptPackets))

	if c.teekTranscriptPackets == nil {
		fmt.Printf("[Client] ❌ TEE_K transcript packets not available\n")
		return false
	}

	// TEE_K captures raw TCP chunks during handshake, so we should compare against
	// the raw TCP chunks we captured (not the individual TLS records from application phase)
	fmt.Printf("[Client] 🔍 TEE_K transcript analysis:\n")

	handshakePacketsMatched := 0
	for i, teekPacket := range c.teekTranscriptPackets {
		fmt.Printf("[Client]   📦 TEE_K packet %d: %d bytes (type: 0x%02x)\n",
			i+1, len(teekPacket), teekPacket[0])

		// Check if this packet matches any of the client's captured data
		found := false
		for j, chunk := range c.capturedTraffic {
			if len(teekPacket) == len(chunk) && bytes.Equal(teekPacket, chunk) {
				fmt.Printf("[Client]     ✅ Exactly matches client capture %d\n", j+1)
				handshakePacketsMatched++
				found = true
				break
			}
		}

		if !found {
			fmt.Printf("[Client]     ❌ NOT found in client captures\n")
			// Show first 32 bytes of TEE_K packet for debugging
			fmt.Printf("[Client]       TEE_K packet: %x...\n", teekPacket[:min(32, len(teekPacket))])
		}
	}

	fmt.Printf("[Client] 🔍 TEE_K validation result: %d/%d packets matched exactly\n",
		handshakePacketsMatched, len(c.teekTranscriptPackets))

	// For TEE_K, we expect exact matches since it should see the same raw TCP data
	return handshakePacketsMatched == len(c.teekTranscriptPackets)
}

// validateTEETTranscriptRaw validates TEE_T transcript against client application data records
func (c *Client) validateTEETTranscriptRaw() bool {
	fmt.Printf("[Client] 🔍 Validating TEE_T transcript (%d packets) against client captures\n",
		len(c.teetTranscriptPackets))

	if c.teetTranscriptPackets == nil {
		fmt.Printf("[Client] ❌ TEE_T transcript packets not available\n")
		return false
	}

	// TEE_T captures individual TLS records during application phase
	fmt.Printf("[Client] 🔍 TEE_T transcript analysis:\n")

	applicationPacketsMatched := 0
	for i, teetPacket := range c.teetTranscriptPackets {
		fmt.Printf("[Client]   📦 TEE_T packet %d: %d bytes (type: 0x%02x)\n",
			i+1, len(teetPacket), teetPacket[0])

		// Check if this packet matches any of the client's captured data
		found := false
		for j, chunk := range c.capturedTraffic {
			if len(teetPacket) == len(chunk) && bytes.Equal(teetPacket, chunk) {
				fmt.Printf("[Client]     ✅ Exactly matches client capture %d\n", j+1)
				applicationPacketsMatched++
				found = true
				break
			}
		}

		if !found {
			fmt.Printf("[Client]     ❌ NOT found in client captures\n")
			// Show first 32 bytes of TEE_T packet for debugging
			fmt.Printf("[Client]       TEE_T packet: %x...\n", teetPacket[:min(32, len(teetPacket))])
		}
	}

	fmt.Printf("[Client] 🔍 TEE_T validation result: %d/%d packets matched exactly\n",
		applicationPacketsMatched, len(c.teetTranscriptPackets))

	// For TEE_T, we expect exact matches since it should see the same TLS records
	return applicationPacketsMatched == len(c.teetTranscriptPackets)
}

// handleSignedRedactedDecryptionStream handles redacted decryption streams from TEE_K
func (c *Client) handleSignedRedactedDecryptionStream(msg *Message) {
	var redactedStream shared.SignedRedactedDecryptionStream
	if err := msg.UnmarshalData(&redactedStream); err != nil {
		log.Printf("[Client] Failed to unmarshal redacted decryption stream: %v", err)
		return
	}

	log.Printf("[Client] 📝 Received redacted decryption stream for seq %d (%d bytes)",
		redactedStream.SeqNum, len(redactedStream.RedactedStream))

	// Verify signature if present
	if len(redactedStream.Signature) > 0 {
		log.Printf("[Client] 🔐 Verifying signature for redacted stream seq %d...", redactedStream.SeqNum)
		// TODO: Implement signature verification for redacted streams
		// For now, just log that we received a signed stream
		log.Printf("[Client] 📝 Redacted stream signature received: %d bytes", len(redactedStream.Signature))
	}

	// Apply redacted stream to ciphertext to get redacted plaintext
	c.responseContentMutex.Lock()
	ciphertext, exists := c.ciphertextBySeq[redactedStream.SeqNum]
	c.responseContentMutex.Unlock()

	if !exists {
		log.Printf("[Client] 📝 No ciphertext found for seq %d", redactedStream.SeqNum)
		return
	}

	if len(redactedStream.RedactedStream) != len(ciphertext) {
		log.Printf("[Client] 📝 Stream length mismatch for seq %d: stream=%d, ciphertext=%d",
			redactedStream.SeqNum, len(redactedStream.RedactedStream), len(ciphertext))
		return
	}

	// XOR ciphertext with redacted stream to get redacted plaintext
	redactedPlaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i++ {
		redactedPlaintext[i] = ciphertext[i] ^ redactedStream.RedactedStream[i]
	}

	log.Printf("[Client] 📝 Generated redacted plaintext for seq %d (%d bytes)",
		redactedStream.SeqNum, len(redactedPlaintext))

	// Store the redacted plaintext and check if we are ready to print
	c.responseContentMutex.Lock()
	c.redactedPlaintextBySeq[redactedStream.SeqNum] = redactedPlaintext
	c.responseContentMutex.Unlock()

	c.printRedactedResponse()
}

// printRedactedResponse prints the full redacted response in order once all parts are received
func (c *Client) printRedactedResponse() {
	c.responseContentMutex.Lock()
	defer c.responseContentMutex.Unlock()

	// Only print if we have received all expected redacted streams
	if len(c.redactedPlaintextBySeq) < int(atomic.LoadInt64(&c.recordsSent)) {
		return
	}

	log.Printf("[Client] 📝 All redacted streams received, printing full response...")

	// Get keys and sort them to ensure correct order
	keys := make([]int, 0, len(c.redactedPlaintextBySeq))
	for k := range c.redactedPlaintextBySeq {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)

	var fullResponse strings.Builder
	for _, k := range keys {
		fullResponse.Write(c.redactedPlaintextBySeq[uint64(k)])
	}

	// Print the final, ordered, redacted response
	fmt.Printf("\n\n--- 📝 FINAL REDACTED RESPONSE 📝 ---\n%s\n--- END REDACTED RESPONSE ---\n\n", fullResponse.String())
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
