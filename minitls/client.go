package minitls

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"net"
)

type Client struct {
	conn net.Conn

	// AEAD ciphers are managed across the client's lifetime
	clientAEAD *AEAD
	serverAEAD *AEAD

	// SupportedCipherSuites can be overridden for testing.
	// If nil, a default set is used.
	SupportedCipherSuites []uint16

	keySchedule        *KeySchedule
	transcript         []byte // Running transcript of all handshake messages
	finishedTranscript []byte // Transcript for Finished message verification
	readBuffer         []byte // Buffer for incoming TLS records
	handshakeBuffer    []byte // Buffer for reassembling handshake messages
}

// Data needed for handshake key disclosure
var certificatePacket []byte // Store the encrypted certificate packet for disclosure

func NewClient(conn net.Conn) *Client {
	return &Client{
		conn: conn,
	}
}

func (c *Client) Handshake(serverName string) error {
	fmt.Println("=== Starting TLS 1.3 Handshake ===")

	// Step 1: Send ClientHello
	clientHello, clientPrivateKey, err := c.buildClientHello(serverName)
	if err != nil {
		return fmt.Errorf("failed to build ClientHello: %v", err)
	}

	fmt.Printf("Sending ClientHello (%d bytes)\n", len(clientHello))
	if _, err := c.conn.Write(clientHello); err != nil {
		return fmt.Errorf("failed to send ClientHello: %v", err)
	}

	// Add ClientHello to both transcripts (handshake message only, not record header)
	clientHelloMsg := clientHello[5:]
	c.transcript = append(c.transcript, clientHelloMsg...)
	c.finishedTranscript = append(c.finishedTranscript, clientHelloMsg...)

	// Step 2: Read and process ServerHello
	serverHello, err := c.readServerHello()
	if err != nil {
		return fmt.Errorf("failed to read ServerHello: %v", err)
	}

	// Add ServerHello to both transcripts (handshake message only)
	c.transcript = append(c.transcript, serverHello...)
	c.finishedTranscript = append(c.finishedTranscript, serverHello...)

	// Parse ServerHello to extract cipher suite and server key share
	cipherSuite, serverPublicKey, err := c.parseServerHello(serverHello)
	if err != nil {
		return fmt.Errorf("failed to parse ServerHello: %v", err)
	}

	fmt.Printf("Negotiated cipher suite: 0x%04x\n", cipherSuite)

	// Step 3: Derive shared secret using ECDH
	sharedSecret, err := clientPrivateKey.ECDH(serverPublicKey)
	if err != nil {
		return fmt.Errorf("ECDH failed: %v", err)
	}

	fmt.Printf("Shared secret (%d bytes): %x\n", len(sharedSecret), sharedSecret)

	// Step 4: Initialize key schedule with shared secret and current transcript
	c.keySchedule = NewKeySchedule(cipherSuite, sharedSecret, c.transcript)

	// Step 5: Derive handshake keys (this is the correct point to derive them)
	if err := c.keySchedule.DeriveHandshakeKeys(); err != nil {
		return fmt.Errorf("failed to derive handshake keys: %v", err)
	}

	// Create AEADs for the handshake phase. These will be used for the handshake and then replaced.
	c.clientAEAD, err = c.keySchedule.CreateClientHandshakeAEAD()
	if err != nil {
		return fmt.Errorf("failed to create client handshake AEAD: %v", err)
	}
	c.serverAEAD, err = c.keySchedule.CreateServerHandshakeAEAD()
	if err != nil {
		return fmt.Errorf("failed to create server handshake AEAD: %v", err)
	}

	fmt.Println("Handshake keys derived successfully")

	// Step 6: Process encrypted handshake messages sequentially
	if err := c.processEncryptedHandshakeMessages(); err != nil {
		return fmt.Errorf("failed to process encrypted handshake messages: %v", err)
	}

	fmt.Println(" TLS 1.3 handshake completed successfully!")
	return nil
}

func (c *Client) processEncryptedHandshakeMessages() error {
	fmt.Println("=== Processing Encrypted Handshake Messages ===")

	// This loop will exit when the Finished message has been processed,
	// which is signaled by the processHandshakeBuffer function.
	for {
		// Attempt to process any complete handshake messages already in the buffer.
		done, err := c.processHandshakeBuffer()
		if err != nil {
			return err
		}
		if done {
			return nil // Handshake complete
		}

		// If we're here, it means the buffer doesn't contain a full message yet.
		// We need to read the next TLS record from the network.
		fmt.Println("[CLIENT] Handshake buffer incomplete, reading next record...")
		header := make([]byte, 5)
		if _, err := io.ReadFull(c.conn, header); err != nil {
			return fmt.Errorf("failed to read record header: %v", err)
		}

		recordType := header[0]
		recordLength := int(header[3])<<8 | int(header[4])
		fmt.Printf("[CLIENT] \nRecord: type=%d, version=0x%04x, length=%d\n", recordType, uint16(header[1])<<8|uint16(header[2]), recordLength)

		payload := make([]byte, recordLength)
		if _, err := io.ReadFull(c.conn, payload); err != nil {
			return fmt.Errorf("failed to read record payload: %v", err)
		}

		if recordType == recordTypeChangeCipherSpec {
			fmt.Println(" Received ChangeCipherSpec (TLS 1.3 compatibility - ignored)")
			continue
		}
		if recordType != recordTypeApplicationData {
			return fmt.Errorf("expected application_data record for encrypted handshake, got %d", recordType)
		}

		// Decrypt the payload and add it to our handshake buffer
		fmt.Printf(" Encrypted handshake record - attempting to decrypt %d bytes with sequence %d\n", len(payload), c.serverAEAD.seq)
		plaintext, err := c.serverAEAD.Decrypt(payload, header)
		if err != nil {
			return fmt.Errorf("decryption failed during handshake: %v", err)
		}

		// The decrypted plaintext contains one or more handshake messages (or fragments).
		// We must find the content type byte to extract the actual handshake data.
		i := len(plaintext) - 1
		for i >= 0 && plaintext[i] == 0 {
			i--
		}
		if i < 0 {
			return fmt.Errorf("handshake record is all padding")
		}
		contentType := plaintext[i]
		actualData := plaintext[:i]

		if contentType != recordTypeHandshake {
			return fmt.Errorf("expected handshake content type in encrypted record, got %d", contentType)
		}

		// Check if this is a certificate message by examining the handshake type
		if len(actualData) >= 1 && HandshakeType(actualData[0]) == typeCertificate {
			// Store the encrypted certificate packet for later disclosure
			encryptedPacket := make([]byte, 5+len(payload))
			copy(encryptedPacket[:5], header)
			copy(encryptedPacket[5:], payload)
			certificatePacket = encryptedPacket
			fmt.Printf(" Captured encrypted certificate packet (%d bytes) for key disclosure\n", len(certificatePacket))
		}

		c.handshakeBuffer = append(c.handshakeBuffer, actualData...)
	}
}

// processHandshakeBuffer loops over the handshake buffer and processes any
// complete handshake messages it finds. It returns true if the handshake
// is complete (i.e., the Finished message was processed).
func (c *Client) processHandshakeBuffer() (bool, error) {
	for {
		// Check if we have enough data for a handshake message header.
		if len(c.handshakeBuffer) < 4 {
			return false, nil // Need more data
		}

		msgLen := uint32(c.handshakeBuffer[1])<<16 | uint32(c.handshakeBuffer[2])<<8 | uint32(c.handshakeBuffer[3])
		totalMsgLen := 4 + msgLen

		// Check if the full message is in the buffer.
		if uint32(len(c.handshakeBuffer)) < totalMsgLen {
			fmt.Printf(" ... entire message not yet in buffer (need %d, have %d). Reading more.\n", totalMsgLen, len(c.handshakeBuffer))
			return false, nil // Need more data
		}

		// We have a full message, so let's process it.
		msg := c.handshakeBuffer[:totalMsgLen]
		msgType := HandshakeType(msg[0])
		fmt.Printf(" Processing buffered handshake message: type=%s, length=%d\n", handshakeTypeString(msgType), msgLen)

		// Process the message.
		// NOTE: The `processSingleHandshakeMessage` function now replaces the old `processHandshakeMessage`.
		// It's responsible for updating transcripts and deriving keys.
		done, err := c.processSingleHandshakeMessage(msg)
		if err != nil {
			return false, err
		}

		// Consume the message from the buffer.
		c.handshakeBuffer = c.handshakeBuffer[totalMsgLen:]

		if done {
			return true, nil // Finished message was processed.
		}
	}
}

// processSingleHandshakeMessage handles a single, complete handshake message.
func (c *Client) processSingleHandshakeMessage(data []byte) (bool, error) {
	msgType := HandshakeType(data[0])

	switch msgType {
	case typeEncryptedExtensions, typeCertificateVerify:
		fmt.Printf(" Received %s\n", handshakeTypeString(msgType))
		c.finishedTranscript = append(c.finishedTranscript, data...)

	case typeCertificate:
		if err := c.processServerCertificate(data); err != nil {
			return false, err
		}
		c.finishedTranscript = append(c.finishedTranscript, data...)

	case typeFinished:
		fmt.Printf(" Received Finished\n")
		hasherForVerify := c.keySchedule.getHashFunc()()
		hasherForVerify.Write(c.finishedTranscript)
		transcriptHashForVerify := hasherForVerify.Sum(nil)
		fmt.Printf(" Transcript hash for verification (48 bytes): %x\n", transcriptHashForVerify)

		if err := c.verifyServerFinished(data, transcriptHashForVerify); err != nil {
			return false, fmt.Errorf("server Finished verification failed: %v", err)
		}

		c.finishedTranscript = append(c.finishedTranscript, data...)

		if err := c.sendClientFinished(); err != nil {
			return false, fmt.Errorf("failed to send client Finished: %v", err)
		}

		// The transcript for the application keys is hash(ClientHello...ServerFinished).
		// At this point, c.finishedTranscript has exactly that, so we hash it directly.
		hasherForApp := c.keySchedule.getHashFunc()()
		hasherForApp.Write(c.finishedTranscript)
		fullTranscriptHash := hasherForApp.Sum(nil)

		if err := c.deriveApplicationKeys(fullTranscriptHash); err != nil {
			return false, err
		}
		return true, nil // Handshake is complete.

	default:
		fmt.Printf(" Received unknown message type: %d\n", msgType)
		c.finishedTranscript = append(c.finishedTranscript, data...)
	}

	return false, nil // Handshake is not yet complete.
}

func (c *Client) verifyServerFinished(msg []byte, transcriptHash []byte) error {
	if len(msg) < 4 {
		return fmt.Errorf("Finished message too short")
	}

	msgType := msg[0]
	if msgType != 20 {
		return fmt.Errorf("expected Finished message type 20, got %d", msgType)
	}
	msgLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	if len(msg) < 4+msgLen {
		return fmt.Errorf("Finished message incomplete: expected %d bytes, got %d", 4+msgLen, len(msg))
	}

	// Extract the verify_data from the server's Finished message
	serverVerifyData := msg[4 : 4+msgLen]
	fmt.Printf(" Server verify_data (%d bytes): %x\n", len(serverVerifyData), serverVerifyData)

	// Calculate what the verify_data should be.
	expectedVerifyData, err := c.keySchedule.CalculateServerFinishedVerifyData(transcriptHash)
	if err != nil {
		return fmt.Errorf("failed to calculate expected verify_data: %v", err)
	}
	fmt.Printf(" Expected verify_data (%d bytes): %x\n", len(expectedVerifyData), expectedVerifyData)

	if !hmac.Equal(serverVerifyData, expectedVerifyData) {
		return fmt.Errorf("verify_data mismatch")
	}

	return nil
}

func (c *Client) deriveApplicationKeys(transcriptHash []byte) error {
	fmt.Println("=== Deriving Application Keys ===")

	// The handshake hash should be the hash of ClientHello...ServerFinished
	fmt.Printf("Using full transcript hash (%d bytes) for application key derivation\n", len(transcriptHash))

	if err := c.keySchedule.DeriveApplicationKeys(transcriptHash); err != nil {
		return fmt.Errorf("failed to derive application keys: %v", err)
	}

	// Create application AEADs to replace the handshake AEADs
	clientAppAEAD, err := c.keySchedule.CreateClientApplicationAEAD()
	if err != nil {
		return fmt.Errorf("failed to create client application AEAD: %v", err)
	}

	serverAppAEAD, err := c.keySchedule.CreateServerApplicationAEAD()
	if err != nil {
		return fmt.Errorf("failed to create server application AEAD: %v", err)
	}

	// Replace handshake AEADs with application AEADs
	c.clientAEAD = clientAppAEAD
	c.serverAEAD = serverAppAEAD

	fmt.Println("Application keys derived successfully")
	return nil
}

func (c *Client) sendClientFinished() error {
	fmt.Println("=== Sending Client Finished ===")

	// The transcript hash for the client's Finished message includes the server's Finished.
	hasher := c.keySchedule.getHashFunc()()
	hasher.Write(c.finishedTranscript)
	transcriptHash := hasher.Sum(nil)
	fmt.Printf(" Transcript hash for client Finished (%d bytes): %x\n", len(transcriptHash), transcriptHash)

	// Calculate verify_data
	verifyData, err := c.keySchedule.CalculateClientFinishedVerifyData(transcriptHash)
	if err != nil {
		return fmt.Errorf("failed to calculate client verify_data: %v", err)
	}

	// Construct the Finished message
	msg := make([]byte, 4+len(verifyData))
	msg[0] = byte(typeFinished)
	putUint24(msg[1:4], uint32(len(verifyData)))
	copy(msg[4:], verifyData)

	// Encrypt the Finished message using the client's HANDSHAKE keys.
	// We need to create a record for it.
	plaintextWithContentType := make([]byte, 0, len(msg)+1)
	plaintextWithContentType = append(plaintextWithContentType, msg...)
	plaintextWithContentType = append(plaintextWithContentType, recordTypeHandshake) // Real content type

	ciphertextLen := len(plaintextWithContentType) + c.clientAEAD.aead.Overhead()
	header := make([]byte, 5)
	header[0] = recordTypeApplicationData // Encrypted handshake messages are sent in application_data records
	header[1] = 0x03                      // Legacy version
	header[2] = 0x03
	header[3] = byte(ciphertextLen >> 8)
	header[4] = byte(ciphertextLen)

	fmt.Printf("AEAD Encrypt (Client Finished): seq=%d\n", c.clientAEAD.seq)
	ciphertext := c.clientAEAD.Encrypt(plaintextWithContentType, header)

	// Send the encrypted record
	record := append(header, ciphertext...)
	if _, err := c.conn.Write(record); err != nil {
		return fmt.Errorf("failed to write client Finished record: %v", err)
	}

	fmt.Println(" Client Finished message sent successfully.")
	return nil
}

func (c *Client) buildClientHello(serverName string) ([]byte, *ecdh.PrivateKey, error) {
	// Generate X25519 key pair
	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate X25519 key: %v", err)
	}

	publicKeyBytes := privateKey.PublicKey().Bytes()
	fmt.Printf("Generated X25519 public key (%d bytes): %x\n", len(publicKeyBytes), publicKeyBytes)

	// Build ClientHello message
	cipherSuites := c.SupportedCipherSuites
	if cipherSuites == nil {
		cipherSuites = []uint16{TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256}
	}

	hello := &ClientHelloMsg{
		vers:               0x0303, // TLS 1.2 for compatibility
		random:             make([]byte, 32),
		sessionId:          make([]byte, 32),
		cipherSuites:       cipherSuites,
		compressionMethods: []uint8{0},
		serverName:         serverName,
		supportedCurves:    []uint16{X25519},
		supportedVersions:  []uint16{0x0304}, // TLS 1.3
		supportedSignatureAlgorithms: []uint16{
			rsa_pss_rsae_sha256,
			ecdsa_secp256r1_sha256,
			rsa_pss_rsae_sha384,
			ecdsa_secp384r1_sha384,
			rsa_pss_rsae_sha512,
		},
		keyShares: []keyShare{
			{group: X25519, data: publicKeyBytes},
		},
	}

	// Fill random bytes using cryptographically secure randomness
	if _, err := rand.Read(hello.random); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random bytes: %v", err)
	}
	if _, err := rand.Read(hello.sessionId); err != nil {
		return nil, nil, fmt.Errorf("failed to generate session ID: %v", err)
	}

	return hello.Marshal(), privateKey, nil
}

func (c *Client) readServerHello() ([]byte, error) {
	// Read TLS record header
	header := make([]byte, 5)
	if _, err := c.conn.Read(header); err != nil {
		return nil, fmt.Errorf("failed to read record header: %v", err)
	}

	recordType := header[0]
	recordLength := int(header[3])<<8 | int(header[4])

	if recordType != 22 { // handshake
		return nil, fmt.Errorf("expected handshake record, got type %d", recordType)
	}

	// Read the handshake message
	message := make([]byte, recordLength)
	if _, err := c.conn.Read(message); err != nil {
		return nil, fmt.Errorf("failed to read handshake message: %v", err)
	}

	// Verify it's a ServerHello
	if len(message) < 4 || message[0] != 2 {
		return nil, fmt.Errorf("expected ServerHello message type 2, got %d", message[0])
	}

	fmt.Printf("Received ServerHello (%d bytes)\n", len(message))
	return message, nil
}

func (c *Client) parseServerHello(data []byte) (uint16, *ecdh.PublicKey, error) {
	if len(data) < 40 {
		return 0, nil, fmt.Errorf("ServerHello too short")
	}

	// Parse basic fields
	msgType := data[0]
	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	version := uint16(data[4])<<8 | uint16(data[5])
	random := data[6:38]
	sessionIDLen := int(data[38])

	fmt.Printf("ServerHello: type=%d, len=%d, version=0x%04x, sessionIDLen=%d\n",
		msgType, msgLen, version, sessionIDLen)

	offset := 39 + sessionIDLen
	if offset+2 > len(data) {
		return 0, nil, fmt.Errorf("invalid ServerHello: missing cipher suite")
	}

	cipherSuite := uint16(data[offset])<<8 | uint16(data[offset+1])
	offset += 2

	// Skip compression method
	offset += 1

	// Parse extensions
	if offset+2 > len(data) {
		return 0, nil, fmt.Errorf("invalid ServerHello: missing extensions length")
	}

	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	extensionsData := data[offset : offset+extensionsLen]

	// Find key_share extension (51)
	serverPublicKey, err := c.parseKeyShareExtension(extensionsData)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to parse key_share: %v", err)
	}

	_ = random // Suppress unused variable warning
	return cipherSuite, serverPublicKey, nil
}

func (c *Client) parseKeyShareExtension(extensionsData []byte) (*ecdh.PublicKey, error) {
	offset := 0
	for offset < len(extensionsData) {
		if offset+4 > len(extensionsData) {
			break
		}

		extType := uint16(extensionsData[offset])<<8 | uint16(extensionsData[offset+1])
		extLen := int(extensionsData[offset+2])<<8 | int(extensionsData[offset+3])
		offset += 4

		if extType == 51 { // key_share
			if offset+extLen > len(extensionsData) {
				return nil, fmt.Errorf("invalid key_share extension length")
			}

			keyShareData := extensionsData[offset : offset+extLen]
			return c.parseKeyShare(keyShareData)
		}

		offset += extLen
	}

	return nil, fmt.Errorf("key_share extension not found")
}

func (c *Client) parseKeyShare(data []byte) (*ecdh.PublicKey, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("key_share data too short")
	}

	group := uint16(data[0])<<8 | uint16(data[1])
	keyLen := int(data[2])<<8 | int(data[3])

	if group != 0x001d { // X25519
		return nil, fmt.Errorf("unsupported key share group: 0x%04x", group)
	}

	if len(data) < 4+keyLen {
		return nil, fmt.Errorf("invalid key_share length")
	}

	keyBytes := data[4 : 4+keyLen]
	fmt.Printf("Server public key (%d bytes): %x\n", len(keyBytes), keyBytes)

	curve := ecdh.X25519()
	publicKey, err := curve.NewPublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server public key: %v", err)
	}

	return publicKey, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SendHTTPRequest sends an HTTP request over the established TLS connection
func (c *Client) SendHTTPRequest(method, path, host string) error {
	// Create HTTP request
	request := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", method, path, host)
	requestBytes := []byte(request)

	fmt.Printf("Sending HTTP request (%d bytes):\n%s", len(requestBytes), request)

	// Create a new AEAD for this application data, which resets the sequence number to 0.
	clientAEAD, err := c.keySchedule.CreateClientApplicationAEAD()
	if err != nil {
		return fmt.Errorf("failed to create client application AEAD: %v", err)
	}

	// In TLS 1.3, we encrypt the HTTP request along with the content type and padding.
	// 1. Construct the inner plaintext.
	innerPlaintext := make([]byte, 0, len(requestBytes)+2)
	innerPlaintext = append(innerPlaintext, requestBytes...)
	innerPlaintext = append(innerPlaintext, recordTypeApplicationData)
	innerPlaintext = append(innerPlaintext, 0x00) // One byte of padding

	// 2. Construct the record header, which serves as the Additional Data (AD) for the AEAD.
	ciphertextLen := len(innerPlaintext) + clientAEAD.aead.Overhead()
	header := make([]byte, 5)
	header[0] = recordTypeApplicationData // Record type: Application Data
	header[1] = 0x03                      // Legacy version: TLS 1.2
	header[2] = 0x03
	header[3] = byte(ciphertextLen >> 8)
	header[4] = byte(ciphertextLen)

	fmt.Printf("Before encryption:\n")
	fmt.Printf(" Record header (AAD): %x\n", header)
	fmt.Printf(" Inner Plaintext (%d bytes): %x\n", len(innerPlaintext), innerPlaintext[:min(32, len(innerPlaintext))])

	// 3. Encrypt the inner plaintext using the header as Additional Data.
	ciphertext := clientAEAD.Encrypt(innerPlaintext, header)

	// 4. Construct the final record to be sent over the wire.
	finalRecord := append(header, ciphertext...)

	// 5. Send the complete record.
	if _, err := c.conn.Write(finalRecord); err != nil {
		return fmt.Errorf("failed to send HTTP request: %v", err)
	}

	fmt.Printf("Sent encrypted HTTP request (%d bytes total, %d bytes ciphertext)\n", len(finalRecord), len(ciphertext))
	fmt.Printf(" Final record header: %x\n", finalRecord[:5])

	return nil
}

// ReadHTTPResponse reads and decrypts the HTTP response from the server.
// It continuously reads from the socket and buffers the data, processing
// any complete TLS records it finds. It will skip over post-handshake
// messages until it finds and returns the first block of application data.
func (c *Client) ReadHTTPResponse() ([]byte, error) {
	// Create a new AEAD for decrypting server application data
	serverAEAD, err := c.keySchedule.CreateServerApplicationAEAD()
	if err != nil {
		return nil, fmt.Errorf("failed to create server application AEAD: %v", err)
	}

	readTmpBuf := make([]byte, 4096) // A temporary buffer for socket reads

	for {
		// Attempt to parse any records currently in our persistent buffer.
		appData, consumed, err := c.parseResponseRecords(serverAEAD)
		if err != nil {
			return nil, err // A fatal error occurred during parsing.
		}

		// After parsing, trim the consumed bytes from the buffer.
		if consumed > 0 {
			c.readBuffer = c.readBuffer[consumed:]
		}

		// If we found application data, we're done. Return it.
		if appData != nil {
			fmt.Printf("Total decrypted HTTP response data: %d bytes\n", len(appData))
			return appData, nil
		}

		// If we got here, it means we need to read more data from the network.
		fmt.Println("No application data yet, reading more from connection...")
		n, readErr := c.conn.Read(readTmpBuf)
		if readErr != nil {
			if readErr == io.EOF {
				return nil, fmt.Errorf("connection closed by peer before HTTP response was received")
			}
			return nil, fmt.Errorf("failed to read from connection: %v", readErr)
		}

		c.readBuffer = append(c.readBuffer, readTmpBuf[:n]...)
	}
}

// parseResponseRecords tries to parse TLS records from the client's readBuffer.
// It returns the first chunk of application data it finds, the total bytes consumed
// from the buffer, and any fatal error.
func (c *Client) parseResponseRecords(serverAEAD *AEAD) (appData []byte, consumed int, err error) {
	offset := 0
	for offset < len(c.readBuffer) {
		// Check if we have enough data for a record header.
		if len(c.readBuffer[offset:]) < 5 {
			return nil, offset, nil // Need more data
		}

		header := c.readBuffer[offset : offset+5]
		recordType := header[0]
		recordLength := int(header[3])<<8 | int(header[4])

		// Check if we have the full record payload in the buffer.
		if len(c.readBuffer[offset+5:]) < recordLength {
			// *** RACE CONDITION FIX: Log partial records for debugging ***
			fmt.Printf("Partial TLS record in buffer: type=%d, expected=%d bytes, have=%d bytes\n",
				recordType, recordLength, len(c.readBuffer[offset+5:]))

			// *** : Check for partial CLOSE_NOTIFY alerts ***
			if recordType == 21 && len(c.readBuffer[offset+5:]) >= 2 { // Alert record with at least 2 bytes
				alertLevel := c.readBuffer[offset+5]
				alertDescription := c.readBuffer[offset+6]
				if alertDescription == 0 { // CLOSE_NOTIFY
					fmt.Printf("*** PARTIAL CLOSE_NOTIFY ALERT DETECTED in minitls buffer ***\n")
					fmt.Printf("Alert level: %d, description: %d (CLOSE_NOTIFY)\n", alertLevel, alertDescription)
				}
			}

			return nil, offset, nil // Need more data
		}

		fmt.Printf("Response record: type=%d, version=0x%04x, length=%d\n",
			recordType, uint16(header[1])<<8|uint16(header[2]), recordLength)

		if recordType != 23 { // We only expect application_data records at this point
			// ***  ALERT PROCESSING ***
			if recordType == 21 { // Alert record
				ciphertext := c.readBuffer[offset+5 : offset+5+recordLength]

				// Try to decrypt the alert
				plaintext, decryptErr := serverAEAD.Decrypt(ciphertext, header)
				if decryptErr != nil {
					fmt.Printf("Failed to decrypt alert record: %v\n", decryptErr)
				} else {
					// Find the content type byte by stripping trailing padding zeros.
					i := len(plaintext) - 1
					for i >= 0 && plaintext[i] == 0 {
						i--
					}
					if i >= 1 { // Need at least 2 bytes for alert level and description
						actualData := plaintext[:i]
						if len(actualData) >= 2 {
							alertLevel := actualData[0]
							alertDescription := actualData[1]
							levelStr := "Warning"
							if alertLevel == 2 {
								levelStr = "Fatal"
							}
							fmt.Printf("*** TLS Alert Decrypted in minitls: %s - %s ***\n", levelStr, alertDescriptionString(alertDescription))

							// ***  CLOSE_NOTIFY DETECTION ***
							if alertDescription == 0 {
								fmt.Printf("*** CLOSE_NOTIFY ALERT SUCCESSFULLY PROCESSED IN MINITLS ***\n")
							}

							if alertLevel == 2 { // Fatal alert
								return nil, 0, fmt.Errorf("received fatal alert: %s", alertDescriptionString(alertDescription))
							}
						}
					}
				}

				// Update the offset to point to the start of the next record and continue
				offset += 5 + recordLength
				continue
			}

			return nil, 0, fmt.Errorf("unexpected record type in application data phase: %d", recordType)
		}

		ciphertext := c.readBuffer[offset+5 : offset+5+recordLength]

		// Decrypt the response
		plaintext, decryptErr := serverAEAD.Decrypt(ciphertext, header)
		if decryptErr != nil {
			return nil, 0, fmt.Errorf("failed to decrypt response: %v", decryptErr)
		}

		// Find the content type byte by stripping trailing padding zeros.
		i := len(plaintext) - 1
		for i >= 0 && plaintext[i] == 0 {
			i--
		}
		if i < 0 {
			return nil, 0, fmt.Errorf("decrypted record is all padding")
		}
		contentType := plaintext[i]
		actualData := plaintext[:i]

		// Update the offset to point to the start of the next record
		offset += 5 + recordLength

		if contentType == recordTypeApplicationData {
			// Success! We found application data. Return it and the bytes consumed.
			return actualData, offset, nil
		}

		// It's not application data, so handle it as a post-handshake message.
		fmt.Printf(" Unexpected content type: %d\n", contentType)
		if contentType == recordTypeHandshake {
			fmt.Println(" Received post-handshake message.")
			if len(actualData) > 0 {
				handshakeMsgType := HandshakeType(actualData[0])
				fmt.Printf(" Post-handshake message type: %s\n", handshakeTypeString(handshakeMsgType))
			}
		} else if contentType == recordTypeAlert && len(actualData) >= 2 {
			alertLevel := actualData[0]
			alertDesc := actualData[1]
			levelStr := "Warning"
			if alertLevel == alertLevelFatal {
				levelStr = "Fatal"
			}
			fmt.Printf(" TLS Alert Received: %s - %s\n", levelStr, alertDescriptionString(alertDesc))

			// ***  CLOSE_NOTIFY DETECTION ***
			if alertDesc == 0 {
				fmt.Printf(" *** CLOSE_NOTIFY ALERT SUCCESSFULLY DETECTED AND PROCESSED ***\n")
			}

			if alertLevel == alertLevelFatal {
				return nil, 0, fmt.Errorf("received fatal alert: %s", alertDescriptionString(alertDesc))
			}
		}
		// Loop again to process the next record in the buffer.
	}

	return nil, offset, nil // Processed the whole buffer, but no app data found yet.
}

func handshakeTypeString(t HandshakeType) string {
	switch t {
	case typeClientHello:
		return "ClientHello"
	case typeServerHello:
		return "ServerHello"
	case typeNewSessionTicket:
		return "NewSessionTicket"
	case typeEncryptedExtensions:
		return "EncryptedExtensions"
	case typeCertificate:
		return "Certificate"
	case typeCertificateVerify:
		return "CertificateVerify"
	case typeFinished:
		return "Finished"
	default:
		return "Unknown"
	}
}

func (c *Client) processServerCertificate(data []byte) error {
	fmt.Println("=== Processing Server Certificate ===")
	// data is the entire handshake message, including its 4-byte header.
	payload := data[4:]

	// 1. Parse Certificate Request Context (1-byte length prefix)
	if len(payload) < 1 {
		return fmt.Errorf("payload too short for context length")
	}
	contextLen := int(payload[0])
	if len(payload) < 1+contextLen {
		return fmt.Errorf("payload too short for context body")
	}
	// For server-sent certificates, this should be zero.
	if contextLen != 0 {
		fmt.Printf(" Warning: server sent non-empty certificate request context (%d bytes)\n", contextLen)
	}
	// Advance payload past the context
	payload = payload[1+contextLen:]

	// 2. Parse Certificate List (3-byte length prefix)
	if len(payload) < 3 {
		return fmt.Errorf("payload too short for certificate list length")
	}
	certListLen := uint32(payload[0])<<16 | uint32(payload[1])<<8 | uint32(payload[2])
	if uint32(len(payload)-3) < certListLen {
		return fmt.Errorf("certificate list length (%d) is larger than remaining payload (%d)",
			certListLen, len(payload)-3)
	}
	// Advance payload to the start of the actual list entries
	listBytes := payload[3 : 3+certListLen]

	// 3. Parse each CertificateEntry from the list
	var certs []*x509.Certificate
	offset := 0
	for offset < len(listBytes) {
		// Each entry has cert_data and extensions.
		// 3a. Parse cert_data (3-byte length prefix)
		if len(listBytes[offset:]) < 3 {
			return fmt.Errorf("not enough data for certificate entry data length")
		}
		certLen := int(listBytes[offset])<<16 | int(listBytes[offset+1])<<8 | int(listBytes[offset+2])
		offset += 3
		if len(listBytes[offset:]) < certLen {
			return fmt.Errorf("not enough data for certificate body")
		}
		certData := listBytes[offset : offset+certLen]
		offset += certLen

		// 3b. Parse extensions (2-byte length prefix)
		if len(listBytes[offset:]) < 2 {
			return fmt.Errorf("not enough data for extensions length")
		}
		extLen := int(listBytes[offset])<<8 | int(listBytes[offset+1])
		offset += 2
		if len(listBytes[offset:]) < extLen {
			return fmt.Errorf("not enough data for extensions body")
		}
		// We can ignore the extensions themselves for now.
		offset += extLen

		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %v", err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return fmt.Errorf("server sent no certificates")
	}

	// --- Print Server's Common Name and Validate Chain ---
	leafCert := certs[0]
	fmt.Printf(" Received %d certificates. Server's Common Name: %s\n", len(certs), leafCert.Subject.CommonName)

	// Basic chain validation
	if len(certs) > 1 {
		for i := 0; i < len(certs)-1; i++ {
			issuer := certs[i+1]
			subject := certs[i]
			fmt.Printf(" - Validating cert #%d (%s) against issuer #%d (%s)\n", i, subject.Subject.CommonName, i+1, issuer.Subject.CommonName)
			if err := subject.CheckSignatureFrom(issuer); err != nil {
				return fmt.Errorf("certificate chain validation failed: cert #%d not signed by #%d: %v", i, i+1, err)
			}
		}
		fmt.Println(" Certificate chain signatures are valid.")
	}

	return nil
}

// GetHandshakeKey returns the server handshake key for certificate verification
func (c *Client) GetHandshakeKey() []byte {
	if c.keySchedule == nil {
		return nil
	}
	return c.keySchedule.serverHandshakeKey
}

// GetHandshakeIV returns the server handshake IV for certificate verification
func (c *Client) GetHandshakeIV() []byte {
	if c.keySchedule == nil {
		return nil
	}
	return c.keySchedule.serverHandshakeIV
}

// GetCertificatePacket returns the encrypted certificate packet
func (c *Client) GetCertificatePacket() []byte {
	return certificatePacket
}

// GetCipherSuite returns the negotiated cipher suite
func (c *Client) GetCipherSuite() uint16 {
	if c.keySchedule == nil {
		return 0
	}
	return c.keySchedule.cipherSuite
}

// GetClientApplicationAEAD returns the client application AEAD for split AEAD operations
func (c *Client) GetClientApplicationAEAD() *AEAD {
	return c.clientAEAD
}

// GetServerApplicationAEAD returns the server application AEAD for response decryption
func (c *Client) GetServerApplicationAEAD() *AEAD {
	return c.serverAEAD
}

// GetKeySchedule returns the key schedule for accessing application keys
func (c *Client) GetKeySchedule() *KeySchedule {
	return c.keySchedule
}
