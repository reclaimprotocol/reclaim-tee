package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sort"

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

	// Prepare data for encryption based on cipher suite (handles TLS version differences)
	dataToEncrypt = minitls.PrepareDataForEncryption(redactedRequest.RedactedRequest, cipherSuite)
	t.logger.WithSession(sessionID).Info("Prepared data for encryption",
		zap.Int("bytes", len(dataToEncrypt)))

	// Get keys based on cipher suite (TLS 1.2 vs 1.3 handled internally)
	if minitls.IsTLS13CipherSuite(cipherSuite) {
		// TLS 1.3: Use client application AEAD
		clientAEAD := tlsClient.GetClientApplicationAEAD()
		if clientAEAD == nil {
			return fmt.Errorf("no client application AEAD available")
		}
		actualSeqNum = clientAEAD.GetSequence()

		keySchedule := tlsClient.GetKeySchedule()
		if keySchedule == nil {
			return fmt.Errorf("no key schedule available")
		}
		clientAppKey = keySchedule.GetClientApplicationKey()
		clientAppIV = keySchedule.GetClientApplicationIV()
	} else {
		// TLS 1.2: Use TLS 1.2 AEAD
		tls12AEAD := tlsClient.GetTLS12AEAD()
		if tls12AEAD == nil {
			return fmt.Errorf("no TLS 1.2 AEAD available")
		}
		clientAppKey = tls12AEAD.GetWriteKey()
		clientAppIV = tls12AEAD.GetWriteIV()
		actualSeqNum = tls12AEAD.GetWriteSequence()
	}

	if len(clientAppKey) == 0 || len(clientAppIV) == 0 {
		return fmt.Errorf("no application keys available")
	}

	t.logger.WithSession(sessionID).Debug("Key Material",
		zap.Int("key_bytes", len(clientAppKey)),
		zap.Int("iv_bytes", len(clientAppIV)),
		zap.Uint64("sequence", actualSeqNum))

	// Use consolidated crypto functions from minitls
	splitAEAD := minitls.NewSplitAEAD(clientAppKey, clientAppIV, cipherSuite)
	splitAEAD.SetSequence(actualSeqNum)

	// Create AAD based on cipher suite (handles TLS version differences internally)
	additionalData := minitls.CreateAdditionalData(cipherSuite, actualSeqNum, len(dataToEncrypt))

	encryptedData, tagSecrets, err := splitAEAD.EncryptWithoutTag(dataToEncrypt, additionalData)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %v", err)
	}

	t.logger.WithSession(sessionID).Info("Generated client application tag secrets",
		zap.Uint64("sequence", actualSeqNum))
	t.logger.WithSession(sessionID).Info("Encrypted data using split AEAD",
		zap.Int("bytes", len(encryptedData)))

	// Send encrypted request and tag secrets to TEE_T with session ID
	if err := t.sendEncryptedRequestToTEET(sessionID, encryptedData, tagSecrets, cipherSuite, actualSeqNum, redactedRequest.RedactionRanges, redactedRequest.Commitments); err != nil {
		return fmt.Errorf("failed to send encrypted request to TEE_T: %v", err)
	}

	return nil
}

// generateResponseTagSecrets generates tag secrets for response verification and returns the nonce used
func (t *TEEK) generateResponseTagSecrets(sessionID string, responseLength int, seqNum uint64, recordHeader []byte, explicitIV []byte) ([]byte, []byte, error) {
	if sessionID == "" {
		return nil, nil, fmt.Errorf("sessionID is empty")
	}

	// Get TLS client from session state
	tlsState, err := t.getSessionTLSState(sessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get TLS state: %v", err)
	}
	tlsClient := tlsState.TLSClient
	cipherSuite := tlsState.CipherSuite

	if tlsClient == nil {
		return nil, nil, fmt.Errorf("no TLS client available")
	}

	// Get server application keys based on cipher suite (handles TLS version internally)
	var serverAppKey, serverAppIV []byte

	if minitls.IsTLS13CipherSuite(cipherSuite) {
		// TLS 1.3: Get server keys from key schedule
		serverAEAD := tlsClient.GetServerApplicationAEAD()
		if serverAEAD == nil {
			return nil, nil, fmt.Errorf("no server application AEAD available")
		}

		keySchedule := tlsClient.GetKeySchedule()
		if keySchedule == nil {
			return nil, nil, fmt.Errorf("no key schedule available")
		}

		serverAppKey = keySchedule.GetServerApplicationKey()
		serverAppIV = keySchedule.GetServerApplicationIV()
	} else {
		// TLS 1.2: Get server keys from TLS 1.2 AEAD
		tls12AEAD := tlsClient.GetTLS12AEAD()
		if tls12AEAD == nil {
			return nil, nil, fmt.Errorf("no TLS 1.2 AEAD available for response tag secrets")
		}

		serverAppKey = tls12AEAD.GetReadKey()
		serverAppIV = tls12AEAD.GetReadIV()
	}

	if serverAppKey == nil || serverAppIV == nil {
		return nil, nil, fmt.Errorf("missing server application key or IV")
	}

	// Create AAD based on cipher suite (handles TLS version differences internally)
	additionalData := minitls.CreateAdditionalData(cipherSuite, seqNum, responseLength)

	// Override record type from header if TLS 1.2
	if !minitls.IsTLS13CipherSuite(cipherSuite) && len(recordHeader) >= 1 {
		additionalData[8] = recordHeader[0] // Use actual record type from header
	}

	if !minitls.IsTLS13CipherSuite(cipherSuite) { // TLS 1.2
		if len(explicitIV) > 0 && minitls.IsTLS12AESGCMCipherSuite(cipherSuite) {
			// TLS 1.2 AES-GCM with explicit IV
			if len(explicitIV) != 8 {
				return nil, nil, fmt.Errorf("TLS 1.2 explicit IV must be 8 bytes, got %d", len(explicitIV))
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
				return nil, nil, fmt.Errorf("failed to create AES cipher: %v", err)
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

			return tagSecrets, nonce, nil
		} else if minitls.IsTLS12ChaCha20Poly1305CipherSuite(cipherSuite) {
			// TLS 1.2 ChaCha20-Poly1305 (no explicit IV)
			// Use TLS 1.2 ChaCha20 nonce construction: IV XOR sequence number
			nonce := make([]byte, len(serverAppIV))
			copy(nonce, serverAppIV)
			for i := 0; i < 8; i++ {
				nonce[len(nonce)-1-i] ^= byte(seqNum >> (8 * i))
			}

			// Use consolidated minitls function for ChaCha20-Poly1305 tag secrets
			splitAEAD := minitls.NewSplitAEAD(serverAppKey, serverAppIV, cipherSuite)
			splitAEAD.SetSequence(seqNum)

			// Create dummy encrypted data to generate tag secrets
			dummyEncrypted := make([]byte, responseLength)

			// Generate tag secrets using the same method as requests
			_, tagSecrets, err := splitAEAD.EncryptWithoutTag(dummyEncrypted, nil)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to generate tag secrets: %v", err)
			}

			return tagSecrets, nonce, nil
		} else {
			return nil, nil, fmt.Errorf("unsupported TLS 1.2 cipher suite: 0x%04x", cipherSuite)
		}
	} else {
		// TLS 1.3 or TLS 1.2 without explicit IV (use standard SplitAEAD)
		splitAEAD := minitls.NewSplitAEAD(serverAppKey, serverAppIV, cipherSuite)

		// Set sequence number to match server's current state
		splitAEAD.SetSequence(seqNum)

		// Create dummy encrypted data to generate tag secrets
		dummyEncrypted := make([]byte, responseLength)

		// Generate tag secrets using the same method as requests
		_, tagSecrets, err := splitAEAD.EncryptWithoutTag(dummyEncrypted, additionalData)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate tag secrets: %v", err)
		}

		// Construct the nonce for TLS 1.3 (same as splitAEAD would use)
		nonce := make([]byte, len(serverAppIV))
		copy(nonce, serverAppIV)
		for i := 0; i < 8; i++ {
			nonce[len(nonce)-1-i] ^= byte(seqNum >> (8 * i))
		}
		return tagSecrets, nonce, nil
	}
}

// generateSingleDecryptionStream generates a decryption stream for a single response
func (t *TEEK) generateSingleDecryptionStream(sessionID string, responseLength int, seqNum uint64) ([]byte, error) {
	// Get session to access cache and stored nonces
	session, err := t.sessionManager.GetSession(sessionID)
	if err != nil {
		return nil, fmt.Errorf("session %s not found: %v", sessionID, err)
	}

	// Check if we already have this stream cached
	session.StreamsMutex.Lock()
	if session.CachedDecryptionStreams != nil {
		if cachedStream, exists := session.CachedDecryptionStreams[seqNum]; exists {
			session.StreamsMutex.Unlock()
			return cachedStream, nil
		}
	}
	session.StreamsMutex.Unlock()

	// Get the stored nonce from when we generated tag secrets
	session.ResponseState.ResponsesMutex.Lock()
	nonce := session.ResponseState.NonceBySeq[seqNum]
	session.ResponseState.ResponsesMutex.Unlock()

	if nonce == nil {
		return nil, fmt.Errorf("no nonce found for sequence %d - tag secrets must be generated first", seqNum)
	}

	// Get TLS client and keys
	tlsState, err := t.getSessionTLSState(sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get TLS state: %v", err)
	}

	if tlsState.TLSClient == nil {
		return nil, fmt.Errorf("no TLS client available")
	}

	// Get server application key based on cipher suite
	var serverAppKey []byte
	if minitls.IsTLS13CipherSuite(tlsState.CipherSuite) {
		// TLS 1.3: Get from key schedule
		keySchedule := tlsState.TLSClient.GetKeySchedule()
		if keySchedule == nil {
			return nil, fmt.Errorf("no key schedule available")
		}
		serverAppKey = keySchedule.GetServerApplicationKey()
	} else {
		// TLS 1.2: Get from TLS 1.2 AEAD
		tls12AEAD := tlsState.TLSClient.GetTLS12AEAD()
		if tls12AEAD == nil {
			return nil, fmt.Errorf("no TLS 1.2 AEAD available")
		}
		serverAppKey = tls12AEAD.GetReadKey()
	}

	if serverAppKey == nil {
		return nil, fmt.Errorf("missing server application key")
	}

	// Generate decryption stream using the stored nonce and cipher suite
	var decryptionStream []byte
	switch tlsState.CipherSuite {
	case minitls.TLS_AES_128_GCM_SHA256, minitls.TLS_AES_256_GCM_SHA384,
		minitls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, minitls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		minitls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, minitls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		decryptionStream, err = minitls.GenerateAESKeystream(serverAppKey, nonce, responseLength)
	case minitls.TLS_CHACHA20_POLY1305_SHA256,
		minitls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, minitls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		decryptionStream, err = minitls.GenerateChaCha20Keystream(serverAppKey, nonce, responseLength)
	default:
		return nil, fmt.Errorf("unsupported cipher suite: 0x%04x", tlsState.CipherSuite)
	}

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
	seqNumbers := make([]uint64, 0)

	tlsState, err := t.getSessionTLSState(sessionID)
	if err != nil {
		return fmt.Errorf("failed to get TLS state: %v", err)
	}
	isTLS13 := minitls.IsTLS13CipherSuite(tlsState.CipherSuite)

	for seqNum := range session.ResponseState.ResponseLengthBySeq {
		seqNumbers = append(seqNumbers, seqNum)
	}

	// Sort sequence numbers to ensure deterministic processing order (matches TEE_T transcript order)
	sort.Slice(seqNumbers, func(i, j int) bool {
		return seqNumbers[i] < seqNumbers[j]
	})

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
			length := session.ResponseState.ResponseLengthBySeq[seqNum]
			if isTLS13 {
				length = length - 1 // !!! Remove content type byte
			}
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
		length := session.ResponseState.ResponseLengthBySeq[seqNum]

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

		if minitls.IsTLS13CipherSuite(tlsState.CipherSuite) {
			redactedStream = redactedStream[:length-1] // !!! remove content type byte from redacted stream
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

	// Consolidate REDACTED streams for signing and public sharing
	// These have random bytes in sensitive positions to protect privacy
	session.StreamsMutex.Lock()

	// Sort the redacted streams by sequence number to ensure correct order
	sort.Slice(session.RedactedStreams, func(i, j int) bool {
		return session.RedactedStreams[i].SeqNum < session.RedactedStreams[j].SeqNum
	})

	// Build consolidated keystream from the REDACTED streams (with random bytes in redacted ranges)
	var consolidatedKeystream []byte
	for _, stream := range session.RedactedStreams {
		consolidatedKeystream = append(consolidatedKeystream, stream.RedactedStream...)
	}

	session.ConsolidatedResponseKeystream = consolidatedKeystream

	t.logger.WithSession(sessionID).Info("Consolidated response keystreams",
		zap.Int("individual_streams", len(session.RedactedStreams)),
		zap.Int("consolidated_keystream_bytes", len(consolidatedKeystream)))

	// Mark redaction processing as complete
	session.RedactionProcessingComplete = true
	session.StreamsMutex.Unlock()

	t.logger.WithSession(sessionID).Info("Redaction processing complete, checking if ready to send signature")

	// Check if all processing is complete and we can send signature
	if err := t.checkAndSendSignatureIfReady(sessionID); err != nil {
		return fmt.Errorf("failed to check signature readiness: %v", err)
	}

	return nil
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
	return t.generateSingleDecryptionStream(sessionID, responseLength, seqNum)
}

// generateAndSendRedactedDecryptionStreamResponse creates redacted decryption streams for response redaction
func (t *TEEK) generateAndSendRedactedDecryptionStreamResponse(sessionID string, spec shared.ResponseRedactionSpec) error {
	// Direct call to the main implementation
	return t.generateAndSendRedactedDecryptionStream(sessionID, spec)
}
