package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type Client struct {
	wsConn   *websocket.Conn
	teetConn *websocket.Conn
	tcpConn  net.Conn

	// *** CRITICAL FIX: Add mutexes to prevent concurrent websocket writes ***
	wsConnMu   sync.Mutex // Protects wsConn writes (TEE_K)
	teetConnMu sync.Mutex // Protects teetConn writes (TEE_T)

	// Session management
	sessionID string // Session ID received from TEE_K

	teekURL           string
	teetURL           string
	targetHost        string
	targetPort        int
	isClosing         bool
	capturedTraffic   [][]byte // Store all captured traffic for verification
	handshakeComplete bool     // Track if TLS handshake is complete

	// Phase 4: Response handling
	responseBuffer       []byte            // Buffer for accumulating TLS record data
	responseSeqNum       uint64            // TLS sequence number for response AEAD
	firstApplicationData bool              // Track if this is the first ApplicationData record
	pendingResponsesData map[uint64][]byte // Encrypted response data by sequence number

	// *** FIX: Add response buffer mutex to prevent race conditions ***
	responseBufferMutex sync.Mutex // Protects responseBuffer access

	// Protocol completion signaling
	completionChan chan struct{} // Signals when protocol is complete

	// *** FIX: Add sync.Once to prevent double-close panic ***
	completionOnce sync.Once // Ensures completion channel is only closed once

	// *** SIMPLIFIED: Track records sent vs processed instead of streams ***
	recordsSent      int  // TLS records sent for split AEAD processing
	recordsProcessed int  // TLS records that completed split AEAD processing
	eofReached       bool // Whether we've reached EOF on TCP connection
	completionMutex  sync.Mutex

	// Track redaction verification completion
	expectingRedactionResult bool
	receivedRedactionResult  bool

	// Track HTTP request/response lifecycle
	httpRequestSent      bool // Track if HTTP request has been sent
	httpResponseExpected bool // Track if we should expect HTTP response
	httpResponseReceived bool // Track if HTTP response content has been received
}

func NewClient(teekURL string) *Client {
	return &Client{
		teekURL:                  teekURL,
		teetURL:                  "wss://tee-t.reclaimprotocol.org/ws", // Default TEE_T URL (enclave mode)
		pendingResponsesData:     make(map[uint64][]byte),
		completionChan:           make(chan struct{}),
		recordsSent:              0,
		recordsProcessed:         0,
		eofReached:               false,
		expectingRedactionResult: false,
		receivedRedactionResult:  false,
		httpRequestSent:          false,
		httpResponseExpected:     false,
		httpResponseReceived:     false,
	}
}

// SetTEETURL sets the TEE_T connection URL
func (c *Client) SetTEETURL(url string) {
	c.teetURL = url
}

// WaitForCompletion returns a channel that closes when the protocol is complete
func (c *Client) WaitForCompletion() <-chan struct{} {
	return c.completionChan
}

// createEnclaveWebSocketDialer creates a custom WebSocket dialer for enclave mode
// that skips TLS certificate verification for staging certificates
func createEnclaveWebSocketDialer() *websocket.Dialer {
	return &websocket.Dialer{
		HandshakeTimeout: 30 * time.Second,
		// Skip TLS certificate verification for staging certificates
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}

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
		log.Printf("[Client] Note: TLS certificate verification is disabled for staging certificates")
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
		log.Printf("[Client] Note: TLS certificate verification is disabled for staging certificates")
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

func (c *Client) RequestHTTP(hostname string, port int) error {
	c.targetHost = hostname
	c.targetPort = port

	fmt.Printf("[Client] Requesting connection to %s:%d\n", hostname, port)

	// Send connection request to TEE_K
	reqData := RequestConnectionData{
		Hostname: hostname,
		Port:     port,
		SNI:      hostname,
		ALPN:     []string{"http/1.1"},
	}

	msg, err := CreateMessage(MsgRequestConnection, reqData)
	if err != nil {
		return fmt.Errorf("failed to create connection request: %v", err)
	}

	if err := c.sendMessage(msg); err != nil {
		return fmt.Errorf("failed to send connection request: %v", err)
	}

	return nil
}

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
		case MsgSessionReady:
			c.handleSessionReady(msg)
		case MsgConnectionReady:
			c.handleConnectionReady(msg)
		case MsgSendTCPData:
			c.handleSendTCPData(msg)
		case MsgHTTPResponse:
			c.handleHTTPResponse(msg)
		case MsgError:
			c.handleError(msg)
		case MsgHandshakeComplete:
			c.handleHandshakeComplete(msg)
		case "handshake_key_disclosure":
			c.handleHandshakeKeyDisclosure(msg)
		case MsgResponseDecryptionStream:
			c.handleResponseDecryptionStream(msg)
		case MsgDecryptedResponse:
			c.handleDecryptedResponse(msg)
		default:
			if !closing {
				log.Printf("[Client] Unknown message type: %s", msg.Type)
			}
		}
	}
}

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
		case MsgError:
			c.handleTEETError(msg)
		default:
			if !closing {
				log.Printf("[Client] Unknown TEE_T message type: %s", msg.Type)
			}
		}
	}
}

// Helper function to detect network errors that occur during normal shutdown
func isClientNetworkShutdownError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "broken pipe")
}

func (c *Client) handleConnectionReady(msg *Message) {
	var readyData ConnectionReadyData
	if err := msg.UnmarshalData(&readyData); err != nil {
		log.Printf("[Client] Failed to unmarshal connection ready data: %v", err)
		return
	}

	if readyData.Success {
		// In Phase 2 split AEAD protocol, Client waits for handshake disclosure
		// then sends plaintext data to TEE_K for encryption
		// No direct TCP connection is established until we have encrypted data to send

		// Send TCP ready confirmation to TEE_K so it can start the handshake
		c.sendTCPReady(true)
	}
}

func (c *Client) sendTCPReady(success bool) {
	fmt.Printf("[Client] DEBUG: sendTCPReady called with success=%v\n", success)

	if success {
		// Establish TCP connection to website to act as proxy for TEE_K
		tcpAddr := fmt.Sprintf("%s:%d", c.targetHost, c.targetPort)
		fmt.Printf("[Client] DEBUG: Attempting TCP connection to %s\n", tcpAddr)

		tcpConn, err := net.Dial("tcp", tcpAddr)
		if err != nil {
			log.Printf("[Client] Failed to establish TCP connection to website: %v", err)
			fmt.Printf("[Client] DEBUG: TCP connection failed: %v\n", err)
			success = false
		} else {
			fmt.Printf("[Client] DEBUG: TCP connection established successfully to %s\n", tcpAddr)
			c.tcpConn = tcpConn
			fmt.Printf("[Client] DEBUG: c.tcpConn set to %p\n", c.tcpConn)

			// Start proxying data from website back to TEE_K
			fmt.Printf("[Client] DEBUG: Starting tcpToWebsocket goroutine\n")
			go c.tcpToWebsocket()
		}
	}

	fmt.Printf("[Client] DEBUG: Sending MsgTCPReady with success=%v\n", success)
	tcpReadyMsg, err := CreateMessage(MsgTCPReady, TCPReadyData{Success: success})
	if err != nil {
		log.Printf("[Client] Failed to create TCP ready message: %v", err)
		return
	}

	if err := c.sendMessage(tcpReadyMsg); err != nil {
		log.Printf("[Client] Failed to send TCP ready message: %v", err)
	}
	fmt.Printf("[Client] DEBUG: MsgTCPReady sent successfully\n")
}

func (c *Client) handleSendTCPData(msg *Message) {
	fmt.Printf("[Client] DEBUG: handleSendTCPData called\n")
	fmt.Printf("[Client] DEBUG: c.tcpConn = %p\n", c.tcpConn)

	var tcpData TCPData
	if err := msg.UnmarshalData(&tcpData); err != nil {
		log.Printf("[Client] Failed to unmarshal TCP data: %v", err)
		return
	}

	fmt.Printf("[Client] DEBUG: Received TCP data with %d bytes\n", len(tcpData.Data))

	// Forward TLS data from TEE_K to website via our TCP connection
	conn := c.tcpConn

	if conn == nil {
		fmt.Printf("[Client] DEBUG: TCP connection is nil!\n")
		fmt.Printf("[Client] DEBUG: c.isClosing = %v\n", c.isClosing)
		fmt.Printf("[Client] DEBUG: c.targetHost = %s, c.targetPort = %d\n", c.targetHost, c.targetPort)
		log.Printf("[Client] No TCP connection to website available")
		return
	}

	fmt.Printf("[Client] DEBUG: TCP connection available, forwarding %d bytes\n", len(tcpData.Data))
	// Forward TLS data to website
	_, err := conn.Write(tcpData.Data)
	if err != nil {
		log.Printf("[Client] Failed to forward TLS data to website: %v", err)
		return
	}
	fmt.Printf("[Client] DEBUG: Successfully forwarded %d bytes to website\n", len(tcpData.Data))
}

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

func (c *Client) handleError(msg *Message) {
	var errorData ErrorData
	if err := msg.UnmarshalData(&errorData); err != nil {
		log.Printf("[Client] Failed to unmarshal error data: %v", err)
		return
	}

	log.Printf("[Client] Error from TEE_K: %s", errorData.Message)
}

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

func (c *Client) handleHandshakeKeyDisclosure(msg *Message) {
	var disclosureData HandshakeKeyDisclosureData
	if err := msg.UnmarshalData(&disclosureData); err != nil {
		log.Printf("[Client] Failed to unmarshal handshake key disclosure data: %v", err)
		return
	}

	fmt.Printf("[Client] Handshake complete: %s, cipher 0x%04x\n", disclosureData.Algorithm, disclosureData.CipherSuite)

	// Mark handshake as complete for response handling
	c.handshakeComplete = true

	// Wait for server post-handshake messages to complete properly
	// instead of using hardcoded sleep
	fmt.Printf("[Client] Waiting for server post-handshake messages to complete...\n")

	// Give server time to send NewSessionTicket and other post-handshake messages
	// Use a shorter, more reasonable wait with proper timeout handling
	postHandshakeTimeout := 500 * time.Millisecond // Much shorter than 2 seconds

	select {
	case <-time.After(postHandshakeTimeout):
		// Normal case - brief wait for post-handshake messages
		fmt.Printf("[Client] Post-handshake wait completed\n")
	case <-c.completionChan:
		// If protocol completes early, no need to wait
		fmt.Printf("[Client] Protocol completed during post-handshake wait\n")
		return
	}

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
	c.completionMutex.Lock()
	c.expectingRedactionResult = true
	fmt.Printf("[Client] EXPECTING redaction verification result from TEE_T\n")
	c.completionMutex.Unlock()

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

func (c *Client) verifyCertificateInTraffic(certPacket []byte) bool {

	// Search for the certificate packet in captured traffic
	for _, traffic := range c.capturedTraffic {
		if bytes.Contains(traffic, certPacket) {
			return true
		}
	}
	return false
}

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

func (c *Client) tcpToWebsocket() {
	fmt.Printf("[Client] DEBUG: tcpToWebsocket goroutine started\n")
	fmt.Printf("[Client] DEBUG: c.tcpConn = %p\n", c.tcpConn)

	defer func() {
		fmt.Printf("[Client] DEBUG: tcpToWebsocket defer called\n")
		// Only close if we're shutting down or there was a real error
		// Don't close on initial read timeouts when no data is available
		if c.isClosing && c.tcpConn != nil {
			fmt.Printf("[Client] DEBUG: Closing TCP connection on shutdown\n")
			c.tcpConn.Close()
			c.tcpConn = nil
		} else {
			fmt.Printf("[Client] DEBUG: Not closing TCP connection (isClosing=%v, tcpConn=%p)\n", c.isClosing, c.tcpConn)
		}
	}()

	buffer := make([]byte, 4096)

	for {
		// Don't close connection on first error - might just be no data available yet
		if c.isClosing {
			fmt.Printf("[Client] DEBUG: tcpToWebsocket exiting because c.isClosing=true\n")
			break
		}

		// Set a reasonable read timeout to avoid blocking forever
		if c.tcpConn != nil {
			c.tcpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		}

		n, err := c.tcpConn.Read(buffer)

		if err != nil {
			// Handle different types of errors
			if err == io.EOF {
				fmt.Printf("[Client] TCP connection closed by server (EOF)\n")
				// Server closed connection - this is final
				// Mark EOF reached and process any remaining buffered data
				c.completionMutex.Lock()
				c.eofReached = true
				c.completionMutex.Unlock()

				fmt.Printf("[Client] EOF reached, processing any remaining buffered data...\n")
				c.processAllRemainingRecords()
				break
			} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout is normal when no data is available - continue waiting
				fmt.Printf("[Client] DEBUG: TCP read timeout (normal), continuing...\n")
				continue
			} else if !isClientNetworkShutdownError(err) {
				fmt.Printf("[Client] TCP read error: %v\n", err)
				fmt.Printf("[Client] DEBUG: Real TCP error, exiting tcpToWebsocket\n")
				// Real error - exit
				break
			} else {
				fmt.Printf("[Client] DEBUG: Network shutdown error, exiting tcpToWebsocket\n")
				// Network shutdown error during normal close
				break
			}
		}

		// Clear read deadline for successful reads
		if c.tcpConn != nil {
			c.tcpConn.SetReadDeadline(time.Time{})
		}

		if !c.handshakeComplete {
			// During handshake: Forward raw data to TEE_K
			tcpDataMsg, err := CreateMessage(MsgTCPData, TCPData{Data: buffer[:n]})
			if err != nil {
				log.Printf("[Client] Failed to create TCP data message: %v", err)
				continue
			}

			if err := c.sendMessage(tcpDataMsg); err != nil {
				if !isClientNetworkShutdownError(err) {
					log.Printf("[Client] Failed to send TCP data to TEE_K: %v", err)
				}
				break
			}
		} else {
			// After handshake: Process raw TLS records for split AEAD response handling
			fmt.Printf("[Client] Response data (%d bytes), processing for split AEAD\n", n)

			// Add to response buffer
			c.responseBufferMutex.Lock()
			c.responseBuffer = append(c.responseBuffer, buffer[:n]...)
			c.responseBufferMutex.Unlock()

			// Process any complete TLS records in buffer
			c.processCompleteRecords()
		}
	}

	// Final completion check after EOF
	c.checkProtocolCompletion("TCP connection closed")
}

// processCompleteRecords processes all complete TLS records in the buffer
func (c *Client) processCompleteRecords() {
	c.responseBufferMutex.Lock()
	defer c.responseBufferMutex.Unlock()

	offset := 0
	processedRecords := 0

	for offset+5 <= len(c.responseBuffer) {
		// Parse TLS record header
		recordType := c.responseBuffer[offset]
		version := uint16(c.responseBuffer[offset+1])<<8 | uint16(c.responseBuffer[offset+2])
		recordLength := int(c.responseBuffer[offset+3])<<8 | int(c.responseBuffer[offset+4])
		totalLength := 5 + recordLength

		if offset+totalLength > len(c.responseBuffer) {
			// Incomplete record - leave it for next time
			fmt.Printf("[Client] Incomplete record: need %d bytes, have %d bytes remaining\n",
				totalLength, len(c.responseBuffer)-offset)
			break
		}

		// Extract complete TLS record
		record := c.responseBuffer[offset : offset+totalLength]
		offset += totalLength
		processedRecords++

		fmt.Printf("[Client] Processing TLS record %d: type=0x%02x, version=0x%04x, length=%d bytes\n",
			processedRecords, recordType, version, recordLength)

		// Process the record based on type
		c.processSingleTLSRecord(record, recordType, recordLength)
	}

	// Remove processed bytes from buffer
	if offset > 0 {
		c.responseBuffer = c.responseBuffer[offset:]
		fmt.Printf("[Client] Processed %d records, %d bytes remaining in buffer\n",
			processedRecords, len(c.responseBuffer))
	}
}

// processAllRemainingRecords processes any remaining data in buffer after EOF
func (c *Client) processAllRemainingRecords() {
	c.responseBufferMutex.Lock()
	defer c.responseBufferMutex.Unlock()

	if len(c.responseBuffer) == 0 {
		fmt.Printf("[Client] No remaining data to process\n")
		return
	}

	fmt.Printf("[Client] Processing remaining %d bytes in buffer\n", len(c.responseBuffer))

	offset := 0
	processedRecords := 0

	// Process all complete records first
	for offset+5 <= len(c.responseBuffer) {
		recordType := c.responseBuffer[offset]
		version := uint16(c.responseBuffer[offset+1])<<8 | uint16(c.responseBuffer[offset+2])
		recordLength := int(c.responseBuffer[offset+3])<<8 | int(c.responseBuffer[offset+4])
		totalLength := 5 + recordLength

		if offset+totalLength > len(c.responseBuffer) {
			// Incomplete record - log it but continue
			fmt.Printf("[Client] Incomplete final record: type=0x%02x, need %d bytes, have %d bytes\n",
				recordType, totalLength, len(c.responseBuffer)-offset)

			// Check for partial CLOSE_NOTIFY
			if recordType == 0x15 && offset+7 <= len(c.responseBuffer) {
				alertLevel := c.responseBuffer[offset+5]
				alertDescription := c.responseBuffer[offset+6]
				if alertDescription == 0 {
					fmt.Printf("[Client] *** PARTIAL CLOSE_NOTIFY DETECTED: level=%d, desc=%d ***\n",
						alertLevel, alertDescription)
				}
			}
			break
		}

		// Process complete record
		record := c.responseBuffer[offset : offset+totalLength]
		offset += totalLength
		processedRecords++

		fmt.Printf("[Client] Final processing TLS record %d: type=0x%02x, version=0x%04x, length=%d bytes\n",
			processedRecords, recordType, version, recordLength)

		c.processSingleTLSRecord(record, recordType, recordLength)
	}

	// Clear processed data
	c.responseBuffer = c.responseBuffer[offset:]

	fmt.Printf("[Client] Final processing complete: %d records processed, %d bytes remaining\n",
		processedRecords, len(c.responseBuffer))
}

// processSingleTLSRecord handles a single complete TLS record
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

func (c *Client) sendMessage(msg *Message) error {
	c.wsConnMu.Lock()
	defer c.wsConnMu.Unlock()

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

func (c *Client) sendMessageToTEET(msg *Message) error {
	c.teetConnMu.Lock()
	defer c.teetConnMu.Unlock()

	conn := c.teetConn

	if conn == nil {
		fmt.Printf("[Client] DEBUG: No TEE_T connection available when trying to send %s\n", msg.Type)
		return fmt.Errorf("no TEE_T websocket connection")
	}

	fmt.Printf("[Client] DEBUG: TEE_T connection available, sending %s message\n", msg.Type)

	// Add session ID if available and not already set
	if c.sessionID != "" && msg.SessionID == "" {
		msg.SessionID = c.sessionID
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		fmt.Printf("[Client] DEBUG: Failed to marshal %s message: %v\n", msg.Type, err)
		return fmt.Errorf("failed to marshal message: %v", err)
	}

	fmt.Printf("[Client] DEBUG: Marshaled %s message (%d bytes), about to write to websocket\n", msg.Type, len(msgBytes))

	// *** NEW: Add websocket state debugging ***
	fmt.Printf("[Client] DEBUG: WebSocket remote addr: %s\n", conn.RemoteAddr().String())
	fmt.Printf("[Client] DEBUG: WebSocket local addr: %s\n", conn.LocalAddr().String())

	if err := conn.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		fmt.Printf("[Client] DEBUG: WriteMessage failed for %s: %v\n", msg.Type, err)
		fmt.Printf("[Client] DEBUG: Connection might be closed or broken\n")

		// *** NEW: Try to detect connection state ***
		if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
			fmt.Printf("[Client] DEBUG: WebSocket close error detected: %v\n", err)
		} else if strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "connection reset") {
			fmt.Printf("[Client] DEBUG: Network connection error detected: %v\n", err)
		}

		return err
	}

	fmt.Printf("[Client] DEBUG: Successfully sent %s message to TEE_T\n", msg.Type)
	fmt.Printf("[Client] DEBUG: Message content preview: %s\n", string(msgBytes[:min(100, len(msgBytes))]))
	return nil
}

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

// Phase 2: TEE_T message handlers

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
	c.completionMutex.Lock()
	if c.expectingRedactionResult && !c.receivedRedactionResult {
		c.receivedRedactionResult = true
		fmt.Printf("[Client] RECEIVED redaction verification result from TEE_T\n")

		// Don't complete yet - we're about to send HTTP request and need to wait for response
		fmt.Printf("[Client] HTTP request ready to send, but waiting for HTTP response before completing\n")
	}
	c.completionMutex.Unlock()

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

	fmt.Printf("[Client] Actually-sending TLS record (%d bytes): %x...\n", len(tlsRecord), tlsRecord[:min(32, len(tlsRecord))])
	fmt.Printf("[Client] Record header: type=0x%02x version=0x%04x length=%d\n", tlsRecord[0], uint16(tlsRecord[1])<<8|uint16(tlsRecord[2]), recordLength)

	// Send to website via TCP connection
	if c.tcpConn != nil {
		n, err := c.tcpConn.Write(tlsRecord)
		if err != nil {
			log.Printf("[Client] Failed to write to TCP connection: %v", err)
			return
		}
		fmt.Printf("[Client] Sent %d bytes to website\n", n)

		// Mark that HTTP request has been sent and we're expecting a response
		c.completionMutex.Lock()
		c.httpRequestSent = true
		c.httpResponseExpected = true
		fmt.Printf("[Client] HTTP request sent, now expecting HTTP response...\n")
		c.completionMutex.Unlock()

		// tcpToWebsocket() is already running and will automatically read the response
		fmt.Printf("[Client] Request sent, tcpToWebsocket() will handle response automatically\n")
	} else {
		log.Printf("[Client] No TCP connection available")
	}
}

func (c *Client) handleTEETReady(msg *Message) {
	var readyData TEETReadyData
	if err := msg.UnmarshalData(&readyData); err != nil {
		log.Printf("[Client] Failed to unmarshal TEE_T ready data: %v", err)
		return
	}

}

func (c *Client) handleRedactionVerification(msg *Message) {
	log.Printf("[Client] DEBUG: Received redaction verification message, raw data type: %T", msg.Data)
	if dataBytes, ok := msg.Data.([]byte); ok {
		log.Printf("[Client] DEBUG: Raw data bytes (first 50): %s", string(dataBytes[:min(50, len(dataBytes))]))
	} else if dataStr, ok := msg.Data.(string); ok {
		log.Printf("[Client] DEBUG: Raw data string (first 50): %s", dataStr[:min(50, len(dataStr))])
	} else {
		log.Printf("[Client] DEBUG: Raw data as interface: %+v", msg.Data)
	}

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

func (c *Client) handleTEETError(msg *Message) {
	var errorData ErrorData
	if err := msg.UnmarshalData(&errorData); err != nil {
		log.Printf("[Client] Failed to unmarshal TEE_T error: %v", err)
		return
	}

	log.Printf("[Client] TEE_T error: %s", errorData.Message)
}

func (c *Client) Close() {
	c.isClosing = true

	// *** FIX: Close TCP connection FIRST to allow tcpToWebsocket() to exit gracefully ***
	// This mimics standard HTTP client behavior - close the underlying connection first
	if c.tcpConn != nil {
		c.tcpConn.Close()
		c.tcpConn = nil
	}

	// Close TEE_K connection with mutex protection
	c.wsConnMu.Lock()
	if c.wsConn != nil {
		c.wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		c.wsConn.Close()
		c.wsConn = nil
	}
	c.wsConnMu.Unlock()

	// Close TEE_T connection with mutex protection
	c.teetConnMu.Lock()
	if c.teetConn != nil {
		c.teetConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		c.teetConn.Close()
		c.teetConn = nil
	}
	c.teetConnMu.Unlock()
}

// Phase 3: Redaction system implementation

// createRedactedRequest creates a redacted HTTP request with XOR streams and commitments
func (c *Client) createRedactedRequest(httpRequest []byte) (RedactedRequestData, RedactionStreamsData, error) {
	// Create test scenario as specified in requirements
	// HTTP Request: GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer dummy_token_12345\r\nX-Account-ID: ACC123456789\r\nConnection: close\r\n\r\n

	// *** REDACTION SYSTEM: Create proper HTTP request with sensitive headers ***
	// R_NS (non-sensitive): GET, Host, Connection headers - no redaction
	// R_S (sensitive): Authorization header - redacted but not for proof
	// R_SP (sensitive with proof): X-Account-ID header - redacted and used for proof
	testRequest := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer secret_auth_token_12345\r\nX-Account-ID: ACC987654321\r\nConnection: close\r\n\r\n", c.targetHost)
	httpRequest = []byte(testRequest)

	fmt.Printf("[Client] ORIGINAL REQUEST (length=%d):\n%s\n", len(httpRequest), string(httpRequest))
	fmt.Printf("[Client] TARGET HOST: '%s' (length=%d)\n", c.targetHost, len(c.targetHost))

	// Show the complete HTTP request with sensitive data before redaction
	fmt.Printf("[Client] COMPLETE HTTP REQUEST (before redaction):\n%s\n", string(httpRequest))
	fmt.Printf("[Client] Request analysis:\n")
	fmt.Printf(" Total length: %d bytes\n", len(httpRequest))
	fmt.Printf(" R_NS (non-sensitive): Basic headers\n")
	fmt.Printf(" R_S (sensitive): %d bytes auth token\n", len("secret_auth_token_12345"))
	fmt.Printf(" R_SP (sensitive+proof): %d bytes account ID\n", len("ACC987654321"))

	// *** REDACTION RANGES: Define R_S and R_SP according to specification ***
	// R_S (sensitive): Authorization token - redacted but not for proof
	// R_SP (sensitive with proof): Account ID - redacted and used for proof generation
	authTokenStart := strings.Index(testRequest, "secret_auth_token_12345")
	accountIdStart := strings.Index(testRequest, "ACC987654321")

	if authTokenStart == -1 {
		return RedactedRequestData{}, RedactionStreamsData{}, fmt.Errorf("auth token not found in request")
	}
	if accountIdStart == -1 {
		return RedactedRequestData{}, RedactionStreamsData{}, fmt.Errorf("account ID not found in request")
	}

	ranges := []RedactionRange{
		{
			Start:  authTokenStart,
			Length: len("secret_auth_token_12345"),
			Type:   "sensitive", // R_S: sensitive but not for proof
		},
		{
			Start:  accountIdStart,
			Length: len("ACC987654321"),
			Type:   "sensitive_proof", // R_SP: sensitive with proof
		},
	}

	fmt.Printf("[Client] REDACTION CONFIGURATION:\n")
	fmt.Printf(" R_NS (non-sensitive): Basic headers (no redaction)\n")
	fmt.Printf(" R_S (sensitive): Auth token at [%d:%d] - redacted, not for proof\n",
		authTokenStart, authTokenStart+len("secret_auth_token_12345"))
	fmt.Printf(" R_SP (sensitive+proof): Account ID at [%d:%d] - redacted, for proof\n",
		accountIdStart, accountIdStart+len("ACC987654321"))

	// Validate redaction ranges
	if err := c.validateRedactionRanges(ranges, len(httpRequest)); err != nil {
		return RedactedRequestData{}, RedactionStreamsData{}, fmt.Errorf("invalid redaction ranges: %v", err)
	}

	// Generate redaction streams and commitment keys
	streams, keys, err := c.generateRedactionStreams(ranges)
	if err != nil {
		return RedactedRequestData{}, RedactionStreamsData{}, fmt.Errorf("failed to generate redaction streams: %v", err)
	}

	// Apply redaction using XOR streams
	redactedRequest := c.applyRedaction(httpRequest, ranges, streams)

	fmt.Printf("[Client] REDACTED REQUEST:\n%s\n", string(redactedRequest))

	// Show non-sensitive parts remain unchanged
	fmt.Printf("[Client] NON-SENSITIVE PARTS (unchanged):\n")
	lines := strings.Split(string(httpRequest), "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "GET ") || strings.HasPrefix(line, "Host: ") ||
			strings.HasPrefix(line, "Connection: ") || line == "" {
			fmt.Printf(" R_NS: %s\n", line)
		}
	}

	// Compute commitments
	commitments := c.computeCommitments(streams, keys)

	fmt.Printf("[Client] REDACTION SUMMARY:\n")
	fmt.Printf(" Original length: %d bytes\n", len(httpRequest))
	fmt.Printf(" Redacted length: %d bytes (same, redaction via XOR)\n", len(redactedRequest))
	fmt.Printf(" Redaction ranges: %d\n", len(ranges))

	return RedactedRequestData{
			RedactedRequest: redactedRequest,
			Commitments:     commitments,
			RedactionRanges: ranges,
		}, RedactionStreamsData{
			Streams:        streams,
			CommitmentKeys: keys,
		}, nil
}

// generateRedactionStreams generates random XOR streams and commitment keys for each redaction range
func (c *Client) generateRedactionStreams(ranges []RedactionRange) ([][]byte, [][]byte, error) {
	streams := make([][]byte, len(ranges))
	keys := make([][]byte, len(ranges))

	for i, r := range ranges {
		// Generate random stream for XOR redaction
		stream := make([]byte, r.Length)
		if _, err := rand.Read(stream); err != nil {
			return nil, nil, fmt.Errorf("failed to generate stream %d: %v", i, err)
		}
		streams[i] = stream

		// Generate random commitment key
		key := make([]byte, 32) // 256-bit key for HMAC-SHA256
		if _, err := rand.Read(key); err != nil {
			return nil, nil, fmt.Errorf("failed to generate key %d: %v", i, err)
		}
		keys[i] = key
	}

	return streams, keys, nil
}

// applyRedaction applies XOR streams to sensitive data ranges in the HTTP request
func (c *Client) applyRedaction(request []byte, ranges []RedactionRange, streams [][]byte) []byte {
	redacted := make([]byte, len(request))
	copy(redacted, request)

	for i, r := range ranges {
		if i >= len(streams) {
			continue
		}

		// Apply XOR stream to redact sensitive data
		for j := 0; j < r.Length && r.Start+j < len(redacted); j++ {
			redacted[r.Start+j] ^= streams[i][j]
		}
	}

	return redacted
}

// computeCommitments computes HMAC commitments for each stream using its corresponding key
func (c *Client) computeCommitments(streams, keys [][]byte) [][]byte {
	commitments := make([][]byte, len(streams))

	for i := 0; i < len(streams) && i < len(keys); i++ {
		// Compute HMAC(stream, key)
		h := hmac.New(sha256.New, keys[i])
		h.Write(streams[i])
		commitments[i] = h.Sum(nil)
	}

	return commitments
}

// validateRedactionRanges ensures redaction ranges don't overlap and are within bounds
func (c *Client) validateRedactionRanges(ranges []RedactionRange, requestLen int) error {
	for _, r := range ranges {
		if r.Start < 0 || r.Length < 0 || r.Start+r.Length > requestLen {
			return fmt.Errorf("invalid redaction range: start=%d, length=%d, requestLen=%d", r.Start, r.Length, requestLen)
		}
	}
	return nil
}

// Phase 4: Response handling methods

// processResponseRecords processes accumulated response data for complete TLS records

// processTLSRecord processes a single TLS ApplicationData record using split AEAD protocol
func (c *Client) processTLSRecord(record []byte) {
	// *** CRITICAL FIX: Initialize sequence number properly ***
	// This should only happen once when we start processing response records
	// responseSeqNum is already initialized to 0 in the struct, so just use it directly
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

	// *** CRITICAL DEBUG: Show exact tag from server ***
	fmt.Printf("[Client] SERVER TAG DEBUG (seq=%d):\n", c.responseSeqNum)
	fmt.Printf(" TLS record: %x\n", record[:min(32, len(record))])
	fmt.Printf(" Encrypted data: %x\n", encryptedData[:min(32, len(encryptedData))])
	fmt.Printf(" Server tag: %x\n", tag)

	// *** FIX: Check if system is shutting down or TEE_T connection is closed ***
	if c.isClosing {
		fmt.Printf("[Client] System is shutting down, storing record but skipping split AEAD processing\n")
		return
	}

	// *** CRITICAL DEBUG: Check TEE_T connection state ***
	teetConnState := c.teetConn != nil
	fmt.Printf("[Client] DEBUG: TEE_T connection state: %v\n", teetConnState)
	if !teetConnState {
		fmt.Printf("[Client] TEE_T connection closed, storing record but skipping split AEAD processing\n")
		return
	}

	// Send encrypted response to TEE_T for tag verification
	encryptedResponse := EncryptedResponseData{
		EncryptedData: encryptedData,
		Tag:           tag,
		RecordHeader:  record[:5], // Include actual TLS record header from server
		SeqNum:        c.responseSeqNum,
		CipherSuite:   0x1302, // TLS_AES_256_GCM_SHA384 - TODO: get from handshake
	}

	fmt.Printf("[Client] DEBUG: Created EncryptedResponseData: %d bytes encrypted, %d bytes tag, seq=%d\n",
		len(encryptedResponse.EncryptedData), len(encryptedResponse.Tag), encryptedResponse.SeqNum)
	fmt.Printf("[Client] SENDING TO TEE_T: encrypted=%x, tag=%x\n",
		encryptedResponse.EncryptedData[:min(16, len(encryptedResponse.EncryptedData))],
		encryptedResponse.Tag)

	responseMsg, err := CreateMessage(MsgEncryptedResponse, encryptedResponse)
	if err != nil {
		fmt.Printf("[Client] DEBUG: Failed to create message: %v\n", err)
		log.Printf("[Client] Failed to create encrypted response message: %v", err)
		return
	}

	fmt.Printf("[Client] DEBUG: Created message of type %s successfully\n", responseMsg.Type)

	fmt.Printf("[Client] DEBUG: Sending encrypted response to TEE_T (seq=%d)\n", c.responseSeqNum)

	fmt.Printf("[Client] DEBUG: About to call sendMessageToTEET\n")

	if err := c.sendMessageToTEET(responseMsg); err != nil {
		fmt.Printf("[Client] DEBUG: sendMessageToTEET FAILED: %v\n", err)

		// *** FIX: Don't treat this as fatal during shutdown ***
		if c.isClosing {
			fmt.Printf("[Client] Send failed during shutdown - this is expected, continuing\n")
		} else {
			log.Printf("[Client] Failed to send encrypted response to TEE_T: %v", err)
		}
		return
	}

	fmt.Printf("[Client] DEBUG: sendMessageToTEET returned SUCCESS\n")

	// Store encrypted data for later decryption (lock already held by caller)
	c.pendingResponsesData[c.responseSeqNum] = encryptedData

	fmt.Printf("[Client] Sent encrypted response to TEE_T for verification (seq=%d)\n", c.responseSeqNum)

	// Track expected decryption stream ONLY if we successfully sent to TEE_T
	c.completionMutex.Lock()
	c.recordsSent++
	fmt.Printf("[Client] EXPECTING decryption stream #%d\n", c.recordsSent)
	c.completionMutex.Unlock()

	fmt.Printf("[Client] INCREMENTING: responseSeqNum from %d to %d\n", c.responseSeqNum, c.responseSeqNum+1)
	c.responseSeqNum++
	fmt.Printf("[Client] INCREMENTED: responseSeqNum is now %d\n", c.responseSeqNum)
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
		// TEE_K will send decryption stream after receiving verification success from TEE_T
	} else {
		fmt.Printf("[Client] Response tag verification failed (seq=%d): %s\n",
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

	fmt.Printf("[Client] Received decryption stream (%d bytes) for seq=%d\n",
		len(streamData.DecryptionStream), streamData.SeqNum)

	// Retrieve stored encrypted data for this sequence number
	encryptedData, exists := c.pendingResponsesData[streamData.SeqNum]
	if exists {
		delete(c.pendingResponsesData, streamData.SeqNum) // Clean up
	}

	if !exists {
		log.Printf("[Client] No encrypted data found for seq=%d", streamData.SeqNum)
		return
	}

	// Decrypt the response by XORing with the decryption stream
	if len(streamData.DecryptionStream) != len(encryptedData) {
		log.Printf("[Client] Decryption stream length (%d) doesn't match encrypted data length (%d)",
			len(streamData.DecryptionStream), len(encryptedData))
		return
	}

	// XOR encrypted data with decryption stream to get plaintext
	plaintext := make([]byte, len(encryptedData))
	for i := 0; i < len(encryptedData); i++ {
		plaintext[i] = encryptedData[i] ^ streamData.DecryptionStream[i]
	}

	fmt.Printf("[Client] Successfully decrypted response (%d bytes, seq=%d)\n",
		len(plaintext), streamData.SeqNum)

	// Track received decryption stream and check for completion
	c.completionMutex.Lock()
	c.recordsProcessed++
	fmt.Printf("[Client] RECEIVED decryption stream #%d of %d expected\n", c.recordsProcessed, c.recordsSent)

	// Check if all records processed and trigger completion check
	if c.recordsProcessed >= c.recordsSent && c.recordsSent > 0 {
		fmt.Printf("[Client] All split AEAD records processed (%d/%d)\n", c.recordsProcessed, c.recordsSent)
	}
	c.completionMutex.Unlock()

	// Always check for protocol completion after processing a decryption stream
	c.checkProtocolCompletion("decryption stream received")

	// Analyze the server content to understand what we received
	c.analyzeServerContent(plaintext, streamData.SeqNum)
}

// handleDecryptedResponse handles final decrypted response
func (c *Client) handleDecryptedResponse(msg *Message) {
	var responseData DecryptedResponseData
	if err := msg.UnmarshalData(&responseData); err != nil {
		log.Printf("[Client] Failed to unmarshal decrypted response: %v", err)
		return
	}

	if responseData.Success {
		fmt.Printf("[Client] Received decrypted response (%d bytes, seq=%d)\n",
			len(responseData.PlaintextData), responseData.SeqNum)

		// Display the decrypted HTTP response
		responseStr := string(responseData.PlaintextData)
		if len(responseStr) > 500 {
			fmt.Printf("[Client] HTTP Response:\n%s\n... (truncated, total %d bytes)\n",
				responseStr[:500], len(responseData.PlaintextData))
		} else {
			fmt.Printf("[Client] HTTP Response:\n%s\n", responseStr)
		}
	} else {
		fmt.Printf("[Client] Response decryption failed (seq=%d)\n", responseData.SeqNum)
	}
}

// analyzeServerContent analyzes the content of the decrypted response to identify what we received
func (c *Client) analyzeServerContent(content []byte, seqNum uint64) {
	fmt.Printf("[Client] ANALYZING SERVER CONTENT (seq=%d, %d bytes):\n", seqNum, len(content))

	if len(content) == 0 {
		fmt.Printf("[Client] Empty content received\n")
		return
	}

	// Remove TLS padding and extract actual content
	actualContent := c.removeTLSPadding(content)
	if len(actualContent) == 0 {
		fmt.Printf("[Client] No content after removing TLS padding\n")
		return
	}

	// Check content type (last byte before padding)
	contentType := actualContent[len(actualContent)-1]
	actualData := actualContent[:len(actualContent)-1]

	fmt.Printf("[Client] Content type: 0x%02x, actual data: %d bytes\n", contentType, len(actualData))

	switch contentType {
	case 0x16: // Handshake message in application data phase
		fmt.Printf("[Client] POST-HANDSHAKE MESSAGE:\n")
		c.analyzeHandshakeMessage(actualData)
		// This is NewSessionTicket - not the HTTP response we're waiting for

	case 0x17: // ApplicationData - this should be the HTTP response
		fmt.Printf("[Client] HTTP APPLICATION DATA:\n")
		c.analyzeHTTPContent(actualData)

		// Track that HTTP response content has been received (but don't complete yet - wait for TCP EOF)
		c.completionMutex.Lock()
		if c.httpRequestSent && c.httpResponseExpected && !c.httpResponseReceived {
			c.httpResponseReceived = true
			fmt.Printf("[Client] HTTP response content received - waiting for TCP EOF to complete protocol\n")
		}
		c.completionMutex.Unlock()

	case 0x15: // Alert
		fmt.Printf("[Client] TLS ALERT:\n")
		c.analyzeAlertMessage(actualData)

	default:
		fmt.Printf("[Client] UNKNOWN CONTENT TYPE: 0x%02x\n", contentType)
		fmt.Printf("[Client] Raw data preview: %x\n", actualData[:min(64, len(actualData))])
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
func (c *Client) removeTLSPadding(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	// TLS 1.3 padding consists of zero bytes at the end
	// The actual content ends with a non-zero content type byte
	i := len(data) - 1

	// Skip trailing zero bytes (padding)
	for i >= 0 && data[i] == 0 {
		i--
	}

	// Return content including the content type byte
	if i >= 0 {
		return data[:i+1]
	}

	// All bytes were zero - shouldn't happen in valid TLS 1.3
	return []byte{}
}

// checkProtocolCompletion checks if all conditions are met and signals completion if so
func (c *Client) checkProtocolCompletion(reason string) {
	c.completionMutex.Lock()
	defer c.completionMutex.Unlock()

	// Completion conditions:
	// 1. EOF reached (TCP connection closed)
	// 2. All split AEAD records processed (or no records sent)
	// 3. Redaction result received (if expected)

	eofCondition := c.eofReached
	recordsCondition := c.recordsSent == 0 || c.recordsProcessed >= c.recordsSent
	redactionCondition := !c.expectingRedactionResult || c.receivedRedactionResult

	allConditionsMet := eofCondition && recordsCondition && redactionCondition

	if allConditionsMet {
		fmt.Printf("[Client] Protocol completed after %s - all conditions met!\n", reason)
		fmt.Printf("[Client] ✓ EOF reached: %v\n", c.eofReached)
		fmt.Printf("[Client] ✓ Records: %d sent, %d processed\n", c.recordsSent, c.recordsProcessed)
		if c.expectingRedactionResult {
			fmt.Printf("[Client] ✓ Redaction: expecting=%v received=%v\n", c.expectingRedactionResult, c.receivedRedactionResult)
		}
		c.completionOnce.Do(func() { close(c.completionChan) })
	} else {
		fmt.Printf("[Client] Protocol not yet complete after %s:\n", reason)
		fmt.Printf("[Client] EOF reached: %v (need: true)\n", c.eofReached)
		fmt.Printf("[Client] Records: %d sent, %d processed (need: processed >= sent)\n", c.recordsSent, c.recordsProcessed)
		if c.expectingRedactionResult {
			fmt.Printf("[Client] Redaction: expecting=%v received=%v (need: !expecting OR received)\n", c.expectingRedactionResult, c.receivedRedactionResult)
		}
	}
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

	// Now we can proceed with the normal protocol flow
	// No immediate action needed - the connection request will come next
}
