package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"tee-mpc/minitls"
	"tee-mpc/shared"

	"go.uber.org/zap"
)

// encryptAndSendRequest encrypts the redacted request and sends it to TEE_T
func (t *TEEK) encryptAndSendRequest(sessionID string, redactedRequest shared.RedactedRequestData) error {
	// Get TLS state from session
	tlsState, err := t.getSessionTLSState(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get TLS state: %v", err)
	}

	tlsClient := tlsState.TLSClient
	if tlsClient == nil {
		return fmt.Errorf("no TLS client available for encryption")
	}

	// Get cipher suite and encryption parameters
	cipherSuite := tlsClient.GetCipherSuite()

	// Prepare data for encryption based on TLS version
	var dataToEncrypt []byte
	var clientAppKey, clientAppIV []byte
	var actualSeqNum uint64

	tlsVersion := tlsClient.GetNegotiatedVersion()
	t.logger.WithSession(sessionID).Debug("TLS version and cipher suite",
		zap.Uint16("tls_version", tlsVersion),
		zap.Uint16("cipher_suite", cipherSuite))

	if tlsVersion == 0x0303 { // TLS 1.2
		// TLS 1.2: encrypt raw application data directly, no inner content type
		dataToEncrypt = redactedRequest.RedactedRequest
		t.logger.WithSession(sessionID).Info("TLS 1.2 - Encrypting raw HTTP data",
			zap.Int("bytes", len(dataToEncrypt)))

		tls12AEAD := tlsClient.GetTLS12AEAD()
		if tls12AEAD == nil {
			return fmt.Errorf("no TLS 1.2 AEAD available")
		}

		clientAppKey = tls12AEAD.GetWriteKey()
		clientAppIV = tls12AEAD.GetWriteIV()
		actualSeqNum = tls12AEAD.GetWriteSequence()

		t.logger.WithSession(sessionID).Debug("TLS 1.2 Key Material",
			zap.Int("write_key_bytes", len(clientAppKey)),
			zap.Int("write_iv_bytes", len(clientAppIV)),
			zap.Uint64("write_sequence", actualSeqNum))

	} else { // TLS 1.3
		// TLS 1.3: Add inner content type byte + padding (RFC 8446)
		dataToEncrypt = make([]byte, len(redactedRequest.RedactedRequest)+2) // +2 for content type + padding
		copy(dataToEncrypt, redactedRequest.RedactedRequest)
		dataToEncrypt[len(redactedRequest.RedactedRequest)] = 0x17   // ApplicationData content type
		dataToEncrypt[len(redactedRequest.RedactedRequest)+1] = 0x00 // Required TLS 1.3 padding byte
		t.logger.WithSession(sessionID).Info("TLS 1.3 - Added inner content type + padding",
			zap.Int("bytes", len(dataToEncrypt)))

		clientAEAD := tlsClient.GetClientApplicationAEAD()
		if clientAEAD == nil {
			return fmt.Errorf("no client application AEAD available")
		}

		actualSeqNum = clientAEAD.GetSequence()

		// Get encryption keys
		keySchedule := tlsClient.GetKeySchedule()
		if keySchedule == nil {
			return fmt.Errorf("no key schedule available")
		}

		clientAppKey = keySchedule.GetClientApplicationKey()
		clientAppIV = keySchedule.GetClientApplicationIV()

		if len(clientAppKey) == 0 || len(clientAppIV) == 0 {
			return fmt.Errorf("no application keys available")
		}
	}

	// Use consolidated crypto functions from minitls
	splitAEAD := minitls.NewSplitAEAD(clientAppKey, clientAppIV, cipherSuite)
	splitAEAD.SetSequence(actualSeqNum)

	// Create AAD based on TLS version
	var additionalData []byte
	if tlsVersion == 0x0303 { // TLS 1.2
		// TLS 1.2: AAD = seq_num(8) + record header(5)
		additionalData = make([]byte, 13)
		// Sequence number (8 bytes, big-endian)
		for i := 0; i < 8; i++ {
			additionalData[i] = byte(actualSeqNum >> (8 * (7 - i)))
		}
		// Record header (5 bytes) - use plaintext length
		additionalData[8] = 0x17                             // ApplicationData
		additionalData[9] = 0x03                             // TLS version major
		additionalData[10] = 0x03                            // TLS version minor
		additionalData[11] = byte(len(dataToEncrypt) >> 8)   // plaintext length high byte
		additionalData[12] = byte(len(dataToEncrypt) & 0xFF) // plaintext length low byte
	} else { // TLS 1.3
		// TLS 1.3: AAD = record header with ciphertext+tag length (5 bytes)
		tagSize := 16                                // GCM tag size
		recordLength := len(dataToEncrypt) + tagSize // encrypted data + authentication tag
		additionalData = []byte{
			0x17,                      // ApplicationData
			0x03,                      // TLS version major (compatibility)
			0x03,                      // TLS version minor (compatibility)
			byte(recordLength >> 8),   // Length high byte (includes tag)
			byte(recordLength & 0xFF), // Length low byte (includes tag)
		}
	}

	encryptedData, tagSecrets, err := splitAEAD.EncryptWithoutTag(dataToEncrypt, additionalData)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}

	t.logger.WithSession(sessionID).Info("Generated client application tag secrets",
		zap.Uint64("sequence", actualSeqNum))
	t.logger.WithSession(sessionID).Info("Encrypted data using split AEAD",
		zap.Int("bytes", len(encryptedData)))

	// Send encrypted request and tag secrets to TEE_T with session ID
	if err := t.sendEncryptedRequestToTEETWithSession(sessionID, encryptedData, tagSecrets, cipherSuite, actualSeqNum, redactedRequest.RedactionRanges, redactedRequest.Commitments); err != nil {
		return fmt.Errorf("failed to send encrypted request to TEE_T: %v", err)
	}

	return nil
}

// generateResponseTagSecretsWithSession generates tag secrets for response verification
func (t *TEEK) generateResponseTagSecretsWithSession(sessionID string, responseLength int, seqNum uint64, recordHeader []byte, explicitIV []byte) ([]byte, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("sessionID is empty")
	}

	// Get TLS client from session state
	tlsState, err := t.getSessionTLSState(sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get TLS state: %v", err)
	}
	tlsClient := tlsState.TLSClient
	cipherSuite := tlsState.CipherSuite

	if tlsClient == nil {
		return nil, fmt.Errorf("no TLS client available")
	}

	// Get server application keys based on TLS version
	var serverAppKey, serverAppIV []byte

	tlsVersion := tlsClient.GetNegotiatedVersion()
	if tlsVersion == 0x0303 { // TLS 1.2
		// Get server keys from TLS 1.2 AEAD context
		tls12AEAD := tlsClient.GetTLS12AEAD()
		if tls12AEAD == nil {
			return nil, fmt.Errorf("no TLS 1.2 AEAD available for response tag secrets")
		}

		serverAppKey = tls12AEAD.GetReadKey()
		serverAppIV = tls12AEAD.GetReadIV()
	} else { // TLS 1.3
		// Get server application AEAD for tag secret generation
		serverAEAD := tlsClient.GetServerApplicationAEAD()
		if serverAEAD == nil {
			return nil, fmt.Errorf("no server application AEAD available")
		}

		// Get key schedule to access server application keys
		keySchedule := tlsClient.GetKeySchedule()
		if keySchedule == nil {
			return nil, fmt.Errorf("no key schedule available")
		}

		serverAppKey = keySchedule.GetServerApplicationKey()
		serverAppIV = keySchedule.GetServerApplicationIV()
	}

	if serverAppKey == nil || serverAppIV == nil {
		return nil, fmt.Errorf("missing server application key or IV")
	}

	// Construct version-specific AAD for tag secret generation (must match TEE_T's verification)
	var additionalData []byte

	if tlsVersion == 0x0303 { // TLS 1.2
		// TLS 1.2: AAD = seq_num(8) + record header(5) = 13 bytes total
		if len(recordHeader) != 5 {
			return nil, fmt.Errorf("invalid TLS 1.2 record header length: expected 5, got %d", len(recordHeader))
		}

		// Construct TLS 1.2 AAD: sequence_number(8) + record_header(5)
		additionalData = make([]byte, 13)

		// Sequence number (8 bytes, big-endian)
		additionalData[0] = byte(seqNum >> 56)
		additionalData[1] = byte(seqNum >> 48)
		additionalData[2] = byte(seqNum >> 40)
		additionalData[3] = byte(seqNum >> 32)
		additionalData[4] = byte(seqNum >> 24)
		additionalData[5] = byte(seqNum >> 16)
		additionalData[6] = byte(seqNum >> 8)
		additionalData[7] = byte(seqNum)

		// Record header (5 bytes) - use PLAINTEXT length for TLS 1.2 AAD
		additionalData[8] = recordHeader[0]              // content type (0x17)
		additionalData[9] = recordHeader[1]              // version major (0x03)
		additionalData[10] = recordHeader[2]             // version minor (0x03)
		additionalData[11] = byte(responseLength >> 8)   // plaintext length high byte
		additionalData[12] = byte(responseLength & 0xFF) // plaintext length low byte
	} else {
		// TLS 1.3: AAD = record header with ciphertext+tag length (5 bytes)
		tagSize := 16                                // GCM tag size
		ciphertextLength := responseLength + tagSize // encrypted data + authentication tag
		additionalData = []byte{
			0x17,                          // ApplicationData
			0x03,                          // TLS version major (compatibility)
			0x03,                          // TLS version minor (compatibility)
			byte(ciphertextLength >> 8),   // Length high byte (includes tag)
			byte(ciphertextLength & 0xFF), // Length low byte (includes tag)
		}
	}

	// For TLS 1.2, server sequence matches client sequence (both start at 1 after handshake)
	// For TLS 1.3, server sequence = client sequence - 1 (server starts at 0)
	var actualSeqToUse uint64
	if tlsVersion == 0x0303 { // TLS 1.2
		actualSeqToUse = seqNum // Server sequence matches client sequence
	} else { // TLS 1.3
		actualSeqToUse = seqNum - 1
	}

	if tlsVersion == 0x0303 { // TLS 1.2
		if len(explicitIV) > 0 && shared.IsTLS12AESGCMCipherSuite(cipherSuite) {
			// TLS 1.2 AES-GCM with explicit IV
			if len(explicitIV) != 8 {
				return nil, fmt.Errorf("TLS 1.2 explicit IV must be 8 bytes, got %d", len(explicitIV))
			}

			// Parse explicit IV as uint64 (like minitls does)
			explicitIVUint64 := binary.BigEndian.Uint64(explicitIV)

			// Construct nonce: implicit_iv(4) || explicit_nonce(8)
			nonce := make([]byte, 12)                                 // GCM nonce is 12 bytes
			copy(nonce[0:4], serverAppIV[0:4])                        // 4-byte implicit IV
			binary.BigEndian.PutUint64(nonce[4:12], explicitIVUint64) // 8-byte explicit IV as uint64

			// Generate AES-GCM tag secrets using the constructed nonce
			block, err := aes.NewCipher(serverAppKey)
			if err != nil {
				return nil, fmt.Errorf("failed to create AES cipher: %v", err)
			}

			// Generate tag secrets: E_K(0^128) || E_K(nonce||1)
			tagSecrets := make([]byte, 32)

			// E_K(0^128) - first 16 bytes
			zeros := make([]byte, 16)
			block.Encrypt(tagSecrets[0:16], zeros)

			// E_K(nonce||1) - last 16 bytes
			nonceWith1 := make([]byte, 16)
			copy(nonceWith1, nonce)
			nonceWith1[15] = 1
			block.Encrypt(tagSecrets[16:32], nonceWith1)

			return tagSecrets, nil
		} else if shared.IsTLS12ChaCha20Poly1305CipherSuite(cipherSuite) {
			// TLS 1.2 ChaCha20-Poly1305 (no explicit IV)
			// Use TLS 1.2 ChaCha20 nonce construction: IV XOR sequence number
			nonce := make([]byte, len(serverAppIV))
			copy(nonce, serverAppIV)
			for i := 0; i < 8; i++ {
				nonce[len(nonce)-1-i] ^= byte(actualSeqToUse >> (8 * i))
			}

			// Use consolidated minitls function for ChaCha20-Poly1305 tag secrets
			splitAEAD := minitls.NewSplitAEAD(serverAppKey, serverAppIV, cipherSuite)
			splitAEAD.SetSequence(actualSeqToUse)

			// Create dummy encrypted data to generate tag secrets
			dummyEncrypted := make([]byte, responseLength)

			// Generate tag secrets using the same method as requests
			_, tagSecrets, err := splitAEAD.EncryptWithoutTag(dummyEncrypted, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to generate tag secrets: %v", err)
			}

			return tagSecrets, nil
		} else {
			return nil, fmt.Errorf("unsupported TLS 1.2 cipher suite: 0x%04x", cipherSuite)
		}
	} else {
		// TLS 1.3 or TLS 1.2 without explicit IV (use standard SplitAEAD)
		splitAEAD := minitls.NewSplitAEAD(serverAppKey, serverAppIV, cipherSuite)

		// Set sequence number to match server's current state
		splitAEAD.SetSequence(actualSeqToUse)

		// Create dummy encrypted data to generate tag secrets
		dummyEncrypted := make([]byte, responseLength)

		// Generate tag secrets using the same method as requests
		_, tagSecrets, err := splitAEAD.EncryptWithoutTag(dummyEncrypted, additionalData)
		if err != nil {
			return nil, fmt.Errorf("failed to generate tag secrets: %v", err)
		}

		return tagSecrets, nil
	}
}

// generateSingleDecryptionStreamWithSession generates a decryption stream for a single response
func (t *TEEK) generateSingleDecryptionStreamWithSession(sessionID string, responseLength int, seqNum uint64) ([]byte, error) {
	// Get session to access cache
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return nil, fmt.Errorf("session %s not found: %v", sessionID, err)
	}

	// Get TLS client from session state
	var tlsClient *minitls.Client
	if sessionID != "" {
		tlsState, err := t.getSessionTLSState(sessionID)
		if err != nil {
			return nil, fmt.Errorf("failed to get TLS state: %v", err)
		}
		tlsClient = tlsState.TLSClient
	}

	if tlsClient == nil {
		return nil, fmt.Errorf("no TLS client available")
	}

	// Use the provided responseLength parameter
	streamLength := responseLength

	// Get server application keys based on TLS version (same as existing working code)
	var serverAppKey, serverAppIV []byte

	tlsVersion := tlsClient.GetNegotiatedVersion()
	if tlsVersion == 0x0303 { // TLS 1.2
		// Get server keys from TLS 1.2 AEAD context
		tls12AEAD := tlsClient.GetTLS12AEAD()
		if tls12AEAD == nil {
			return nil, fmt.Errorf("no TLS 1.2 AEAD available for decryption")
		}

		serverAppKey = tls12AEAD.GetReadKey()
		serverAppIV = tls12AEAD.GetReadIV()
	} else { // TLS 1.3
		// Get key schedule to access server application keys
		keySchedule := tlsClient.GetKeySchedule()
		if keySchedule == nil {
			return nil, fmt.Errorf("no key schedule available")
		}

		serverAppKey = keySchedule.GetServerApplicationKey()
		serverAppIV = keySchedule.GetServerApplicationIV()
	}

	if serverAppKey == nil || serverAppIV == nil {
		return nil, fmt.Errorf("missing server application key or IV")
	}

	// Get cipher suite from TLS client
	cipherSuite := tlsClient.GetCipherSuite()

	// Get stored explicit IV for TLS 1.2 AES-GCM
	var explicitIV []byte
	responseState, err := t.getSessionResponseState(sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session response state: %v", err)
	}
	explicitIV = responseState.ExplicitIVBySeq[seqNum]

	// Generate cipher-agnostic decryption stream
	// Use same sequence logic as tag generation for consistency
	var serverSeqNum uint64
	if tlsVersion == 0x0303 { // TLS 1.2
		serverSeqNum = seqNum // Server sequence matches client sequence
	} else { // TLS 1.3
		serverSeqNum = seqNum - 1
	}

	decryptionStream, err := minitls.GenerateDecryptionStream(serverAppKey, serverAppIV, serverSeqNum, streamLength, cipherSuite, explicitIV)
	if err != nil {
		return nil, fmt.Errorf("failed to generate decryption stream: %v", err)
	}

	// Cache the generated stream
	session.StreamsMutex.Lock()
	if session.CachedDecryptionStreams == nil {
		session.CachedDecryptionStreams = make(map[uint64][]byte)
	}
	session.CachedDecryptionStreams[seqNum] = decryptionStream
	session.StreamsMutex.Unlock()

	return decryptionStream, nil
}

// generateAndSendRedactedDecryptionStream creates redacted decryption streams but defers signature sending until all processing is complete
func (t *TEEK) generateAndSendRedactedDecryptionStream(sessionID string, spec shared.ResponseRedactionSpec) error {
	t.logger.WithSession(sessionID).Info("Generating redacted decryption stream", zap.Int("ranges", len(spec.Ranges)))

	// Get session to access response state
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("session %s not found: %v", sessionID, err)
	}

	// Get response state for this session
	if session.ResponseState == nil {
		return fmt.Errorf("no response state available for session %s", sessionID)
	}

	// Get all response lengths for this session
	totalLength := 0
	seqNumbers := make([]uint64, 0)

	for seqNum, length := range session.ResponseState.ResponseLengthBySeq {
		totalLength += int(length) // Convert from uint32 to int
		seqNumbers = append(seqNumbers, seqNum)
	}

	if totalLength == 0 {
		return fmt.Errorf("no response data available for redaction in session %s", sessionID)
	}

	t.logger.WithSession(sessionID).Info("Total response length",
		zap.Int("total_bytes", totalLength),
		zap.Int("sequences", len(seqNumbers)))

	// Clear any existing redacted streams for this session
	session.StreamsMutex.Lock()
	session.RedactedStreams = make([]shared.SignedRedactedDecryptionStream, 0)
	session.StreamsMutex.Unlock()

	t.logger.WithSession(sessionID).Info("Pre-processing redaction ranges", zap.Int("ranges", len(spec.Ranges)))

	// Map each sequence to its redaction operations
	seqToOperations := make(map[uint64][]RedactionOperation)

	// Process each range exactly once
	for _, redactionRange := range spec.Ranges {
		rangeStart := redactionRange.Start
		rangeEnd := redactionRange.Start + redactionRange.Length

		// Find which sequences this range affects
		seqOffset := 0
		for _, seqNum := range seqNumbers {
			length := int(session.ResponseState.ResponseLengthBySeq[seqNum])
			seqStart := seqOffset
			seqEnd := seqOffset + length

			// Check if this range overlaps with current sequence
			if rangeStart < seqEnd && rangeEnd > seqStart {
				// Calculate overlap
				overlapStart := max(rangeStart, seqStart) - seqStart
				overlapEnd := min(rangeEnd, seqEnd) - seqStart
				overlapLength := overlapEnd - overlapStart

				if overlapLength > 0 {
					// Create redaction operation for this sequence
					operation := RedactionOperation{
						SeqNum: seqNum,
						Start:  overlapStart,
						End:    overlapStart + overlapLength,
						Bytes:  make([]byte, overlapLength),
					}

					// Generate cryptographically secure random bytes for redaction
					_, err := rand.Read(operation.Bytes)
					if err != nil {
						return fmt.Errorf("failed to generate random redaction bytes: %v", err)
					}

					seqToOperations[seqNum] = append(seqToOperations[seqNum], operation)
				}
			}
			seqOffset += length
		}
	}

	totalOperations := func() int {
		total := 0
		for _, ops := range seqToOperations {
			total += len(ops)
		}
		return total
	}()
	t.logger.WithSession(sessionID).Info("Pre-processing complete", zap.Int("total_operations", totalOperations))

	// Create redacted decryption stream for each sequence using pre-computed operations
	for _, seqNum := range seqNumbers {
		length := int(session.ResponseState.ResponseLengthBySeq[seqNum])

		// Get original decryption stream from cache (reuse from Phase 4)
		originalStream, err := t.getCachedDecryptionStream(sessionID, length, seqNum)
		if err != nil {
			return fmt.Errorf("failed to get cached decryption stream for seq %d: %v", seqNum, err)
		}

		// Apply redaction to this stream using pre-computed operations
		redactedStream := make([]byte, len(originalStream))
		copy(redactedStream, originalStream)

		// Apply pre-computed redaction operations for this sequence (O(1) per sequence)
		operations := seqToOperations[seqNum]
		for _, operation := range operations {
			// Apply redaction bytes for this operation
			for i := 0; i < len(operation.Bytes) && operation.Start+i < len(redactedStream); i++ {
				redactedStream[operation.Start+i] = operation.Bytes[i]
			}
		}

		// Store redacted stream in session for master signature generation
		streamData := shared.SignedRedactedDecryptionStream{
			RedactedStream: redactedStream,
			SeqNum:         seqNum,
		}

		session.StreamsMutex.Lock()
		session.RedactedStreams = append(session.RedactedStreams, streamData)
		session.StreamsMutex.Unlock()
	}

	// Instead of immediately sending signature, mark redaction processing as complete
	session.StreamsMutex.Lock()
	session.RedactionProcessingComplete = true
	session.StreamsMutex.Unlock()

	t.logger.WithSession(sessionID).Info("Redaction processing complete, checking if ready to send signature")

	// Check if all processing is complete and we can send signature
	if err := t.checkAndSendSignatureIfReady(sessionID); err != nil {
		return fmt.Errorf("failed to check signature readiness: %v", err)
	}

	return nil
}

// Helper function for max
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// getCachedDecryptionStream retrieves a cached decryption stream, generating it if not cached
func (t *TEEK) getCachedDecryptionStream(sessionID string, responseLength int, seqNum uint64) ([]byte, error) {
	// Get session to access cache
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return nil, fmt.Errorf("session %s not found: %v", sessionID, err)
	}

	// Check cache first
	session.StreamsMutex.Lock()
	if session.CachedDecryptionStreams == nil {
		session.CachedDecryptionStreams = make(map[uint64][]byte)
	}
	if cachedStream, exists := session.CachedDecryptionStreams[seqNum]; exists {
		session.StreamsMutex.Unlock()
		// Return a copy to avoid external modification
		streamCopy := make([]byte, len(cachedStream))
		copy(streamCopy, cachedStream)
		return streamCopy, nil
	}
	session.StreamsMutex.Unlock()

	// If not cached, generate and cache it
	return t.generateSingleDecryptionStreamWithSession(sessionID, responseLength, seqNum)
}

// generateAndSendRedactedDecryptionStreamResponse creates redacted decryption streams for response redaction
func (t *TEEK) generateAndSendRedactedDecryptionStreamResponse(sessionID string, spec shared.ResponseRedactionSpec) error {
	// Direct call to the main implementation
	return t.generateAndSendRedactedDecryptionStream(sessionID, spec)
}
