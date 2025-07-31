package clientlib

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

		msg, err := shared.ParseMessage(msgBytes)
		if err != nil {
			if !closing {
				c.terminateConnectionWithError("Failed to parse message from TEE_K", err)
				return
			}
			// Allow graceful shutdown during close
			break
		}

		switch msg.Type {
		case shared.MsgConnectionReady:
			c.handleConnectionReady(msg)
		case shared.MsgSendTCPData:
			c.handleSendTCPData(msg)
		case shared.MsgHandshakeComplete:
			c.handleHandshakeComplete(msg)
		case shared.MsgHandshakeKeyDisclosure:
			c.handleHandshakeKeyDisclosure(msg)
		case shared.MsgHTTPResponse:
			c.handleHTTPResponse(msg)
		case shared.MsgSessionReady:
			c.handleSessionReady(msg)
		case shared.MsgError:
			c.handleError(msg)
		case shared.MsgBatchedSignedRedactedDecryptionStreams:
			c.handleBatchedSignedRedactedDecryptionStreams(msg)
		case shared.MsgSignedTranscript:
			c.handleSignedTranscript(msg)
		case shared.MsgAttestationResponse:
			c.handleAttestationResponse(msg)

		// Handle batched response messages
		case shared.MsgBatchedTagVerifications:
			c.handleBatchedTagVerifications(msg)
		case shared.MsgBatchedDecryptionStreams:
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

		msg, err := shared.ParseMessage(msgBytes)
		if err != nil {
			if !closing {
				c.terminateConnectionWithError("Failed to parse message from TEE_T", err)
				return
			}
			// Allow graceful shutdown during close
			break
		}

		switch msg.Type {
		case shared.MsgEncryptedData:
			c.handleEncryptedData(msg)
		case shared.MsgTEETReady:
			c.handleTEETReady(msg)
		case shared.MsgRedactionVerification:
			c.handleRedactionVerification(msg)
		case shared.MsgResponseTagVerification:
			c.handleResponseTagVerification(msg)
		case "signed_transcript":
			c.handleSignedTranscript(msg)
		case shared.MsgAttestationResponse:
			c.handleAttestationResponse(msg)
		case shared.MsgError:
			c.handleTEETError(msg)

		// Handle batched response messages from TEE_T
		case shared.MsgBatchedTagVerifications:
			c.handleBatchedTagVerifications(msg)

		default:
			if !closing {
				log.Printf("[Client] Unknown TEE_T message type: %s", msg.Type)
			}
		}
	}
}

// sendMessage sends a message to TEE_K
func (c *Client) sendMessage(msg *shared.Message) error {
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
func (c *Client) sendMessageToTEET(msg *shared.Message) error {
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

		if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {

		} else if strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "connection reset") {

		}

		return err
	}
	return nil
}

// sendError sends an error message to TEE_K (fail-fast implementation)
func (c *Client) sendError(errMsg string) {
	errorMsg := shared.CreateMessage(shared.MsgError, shared.ErrorData{Message: errMsg})

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

	msg := shared.CreateMessage(shared.MsgRequestConnection, *c.pendingConnectionRequest)

	if err := c.sendMessage(msg); err != nil {
		return fmt.Errorf("failed to send connection request: %v", err)
	}

	c.connectionRequestPending = false
	c.pendingConnectionRequest = nil
	return nil
}

// handleEncryptedData handles encrypted data from TEE_T
func (c *Client) handleEncryptedData(msg *shared.Message) {
	var encData shared.EncryptedDataResponse
	if err := msg.UnmarshalData(&encData); err != nil {
		log.Printf("[Client] Failed to unmarshal encrypted data: %v", err)
		return
	}

	if !encData.Success {
		log.Printf("[Client] TEE_T reported failure in encrypted data")
		return
	}

	fmt.Printf("[Client] Received encrypted data (%d bytes) + tag (%d bytes)\n", len(encData.EncryptedData), len(encData.AuthTag))

	fmt.Printf("[Client] RECEIVED redaction verification result from TEE_T\n")

	// Create TLS record with encrypted data and authentication tag
	// Format depends on TLS version and cipher suite
	var payload []byte

	// Check if this is TLS 1.2 AES-GCM (needs explicit IV)
	isTLS12AESGCMCipher := c.handshakeDisclosure != nil &&
		shared.IsTLS12AESGCMCipherSuite(c.handshakeDisclosure.CipherSuite)

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

// validateTranscriptsAgainstCapturedTraffic performs comprehensive validation of signed transcripts

// Close closes all WebSocket connections
func (c *Client) Close() {
	c.isClosing = true

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
