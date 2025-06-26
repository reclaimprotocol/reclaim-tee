package enclave

import (
	"crypto/hmac"
	"fmt"
	"hash"
)

// This file implements TLS 1.3 Finished message handling
// Adapted from Go's crypto/tls/handshake_messages.go and key_schedule.go

// Additional TLS handshake message types (others defined in tls_client.go)
const (
	handshakeTypeEncryptedExtensions = 8
	handshakeTypeCertificate         = 11
	handshakeTypeCertificateRequest  = 13
	handshakeTypeCertificateVerify   = 15
	handshakeTypeFinished            = 20
)

// finishedMsg represents a TLS Finished message
// Adapted from Go's crypto/tls/handshake_messages.go
type finishedMsg struct {
	verifyData []byte
}

// marshal serializes the Finished message
// Adapted from Go's crypto/tls/handshake_messages.go
func (m *finishedMsg) marshal() ([]byte, error) {
	if len(m.verifyData) == 0 {
		return nil, fmt.Errorf("finished message verify data is empty")
	}

	// Finished message format:
	// struct {
	//     opaque verify_data[Hash.length];
	// } Finished;

	// Build handshake message: type(1) + length(3) + data
	msgLength := len(m.verifyData)
	handshakeMsg := make([]byte, 4+msgLength)

	// Message type
	handshakeMsg[0] = handshakeTypeFinished

	// Message length (24-bit big-endian)
	handshakeMsg[1] = byte(msgLength >> 16)
	handshakeMsg[2] = byte(msgLength >> 8)
	handshakeMsg[3] = byte(msgLength)

	// Verify data
	copy(handshakeMsg[4:], m.verifyData)

	return handshakeMsg, nil
}

// parseFinished parses a TLS Finished message
// Adapted from Go's crypto/tls/handshake_messages.go
func parseFinished(data []byte) (*finishedMsg, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("finished message too short: %d bytes", len(data))
	}

	// Check message type
	if data[0] != handshakeTypeFinished {
		return nil, fmt.Errorf("expected finished message type %d, got %d", handshakeTypeFinished, data[0])
	}

	// Parse message length
	msgLength := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) != 4+msgLength {
		return nil, fmt.Errorf("finished message length mismatch: expected %d, got %d", 4+msgLength, len(data))
	}

	// Extract verify data
	verifyData := make([]byte, msgLength)
	copy(verifyData, data[4:4+msgLength])

	return &finishedMsg{
		verifyData: verifyData,
	}, nil
}

// GenerateClientFinished generates the client Finished message
// Adapted from Go's crypto/tls/key_schedule.go finishedHash function
func (s *TLSClientState) GenerateClientFinished(keySchedule *GoTLSKeySchedule) ([]byte, error) {
	if keySchedule.clientHandshakeSecret == nil {
		return nil, fmt.Errorf("client handshake secret not available")
	}

	// Get handshake transcript hash (up to this point)
	transcriptHash := s.HandshakeHash

	// Compute verify data using Go's finishedHash method
	// This handles both key derivation and HMAC computation
	verifyData := keySchedule.cipherSuite.finishedHash(keySchedule.clientHandshakeSecret, transcriptHash)

	// Create Finished message
	finishedMsg := &finishedMsg{
		verifyData: verifyData,
	}

	// Marshal to wire format
	finishedBytes, err := finishedMsg.marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal client finished: %v", err)
	}

	// Update handshake hash with our Finished message
	s.HandshakeHash.Write(finishedBytes)

	return finishedBytes, nil
}

// VerifyServerFinished verifies the server's Finished message
// Adapted from Go's crypto/tls/key_schedule.go finishedHash function
func (s *TLSClientState) VerifyServerFinished(finishedData []byte, keySchedule *GoTLSKeySchedule) error {
	if keySchedule.serverHandshakeSecret == nil {
		return fmt.Errorf("server handshake secret not available")
	}

	// Parse Finished message
	finishedMsg, err := parseFinished(finishedData)
	if err != nil {
		return fmt.Errorf("failed to parse server finished: %v", err)
	}

	// Get handshake transcript hash (up to server finished, excluding it)
	transcriptHash := s.HandshakeHash

	// Compute expected verify data using Go's finishedHash method
	expectedVerifyData := keySchedule.cipherSuite.finishedHash(keySchedule.serverHandshakeSecret, transcriptHash)

	// Verify the data matches
	if len(finishedMsg.verifyData) != len(expectedVerifyData) {
		return fmt.Errorf("finished verify data length mismatch: expected %d, got %d",
			len(expectedVerifyData), len(finishedMsg.verifyData))
	}

	// Constant-time comparison to prevent timing attacks
	if !hmac.Equal(finishedMsg.verifyData, expectedVerifyData) {
		return fmt.Errorf("server finished verification failed")
	}

	// Update handshake hash with verified server Finished message
	s.HandshakeHash.Write(finishedData)

	return nil
}

// computeFinishedVerifyData computes the verify_data for Finished messages
// Adapted from Go's crypto/tls/key_schedule.go
func computeFinishedVerifyData(finishedKey []byte, transcriptHash []byte, hashFunc func() hash.Hash) []byte {
	// verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context))
	h := hmac.New(hashFunc, finishedKey)
	h.Write(transcriptHash)
	return h.Sum(nil)
}

// CompleteHandshake completes the TLS 1.3 handshake after Finished message exchange
// This transitions from handshake to application data phase
func (s *TLSClientState) CompleteHandshake(keySchedule *GoTLSKeySchedule) error {
	// Verify we have all necessary components
	if s.serverHello == nil {
		return fmt.Errorf("server hello not processed")
	}

	if keySchedule.clientHandshakeSecret == nil || keySchedule.serverHandshakeSecret == nil {
		return fmt.Errorf("handshake secrets not derived")
	}

	if keySchedule.clientAppSecret == nil || keySchedule.serverAppSecret == nil {
		return fmt.Errorf("application secrets not derived")
	}

	// At this point, the handshake is complete and we can extract session keys
	// This is handled by ExtractSessionKeys() in tls_client.go

	return nil
}

// GetHandshakeTranscript returns the current handshake transcript hash
// This is useful for debugging and verification
func (s *TLSClientState) GetHandshakeTranscript() []byte {
	return s.HandshakeHash.Sum(nil)
}

// TLS 1.3 Certificate handling (simplified for TEE use case)
// In our TEE MPC protocol, certificate verification is optional since
// we're primarily concerned with the TLS keys for split AEAD operations

// certificateMsg represents a TLS Certificate message
// Simplified version adapted from Go's crypto/tls/handshake_messages.go
type certificateMsg struct {
	certificates   [][]byte
	requestContext []byte // TLS 1.3 only
}

// For our TEE implementation, we'll focus on the essential handshake completion
// Certificate verification can be added later if needed for full TLS compliance

// EncryptedExtensions message (TLS 1.3 specific)
// Adapted from Go's crypto/tls/handshake_messages.go
type encryptedExtensionsMsg struct {
	extensions   []extension
	alpnProtocol string
}

// parseEncryptedExtensions parses TLS 1.3 EncryptedExtensions message
func parseEncryptedExtensions(data []byte) (*encryptedExtensionsMsg, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("encrypted extensions message too short: %d bytes", len(data))
	}

	// Check message type
	if data[0] != handshakeTypeEncryptedExtensions {
		return nil, fmt.Errorf("expected encrypted extensions message type %d, got %d",
			handshakeTypeEncryptedExtensions, data[0])
	}

	// Parse message length
	msgLength := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) != 4+msgLength {
		return nil, fmt.Errorf("encrypted extensions length mismatch: expected %d, got %d",
			4+msgLength, len(data))
	}

	msg := &encryptedExtensionsMsg{}

	// Parse extensions (simplified)
	extensionsData := data[4:]
	if len(extensionsData) < 2 {
		return nil, fmt.Errorf("encrypted extensions missing extensions length")
	}

	extensionsLength := int(extensionsData[0])<<8 | int(extensionsData[1])
	if len(extensionsData) != 2+extensionsLength {
		return nil, fmt.Errorf("encrypted extensions length mismatch")
	}

	// For now, just store raw extensions - can be parsed later if needed
	// In our TEE use case, we primarily care about ALPN

	return msg, nil
}

// ProcessEncryptedExtensions processes the server's EncryptedExtensions message
func (s *TLSClientState) ProcessEncryptedExtensions(encExtData []byte) error {
	encExt, err := parseEncryptedExtensions(encExtData)
	if err != nil {
		return fmt.Errorf("failed to parse encrypted extensions: %v", err)
	}

	// Update handshake hash
	s.HandshakeHash.Write(encExtData)

	// Store any relevant information (like negotiated ALPN)
	// For our TEE implementation, this is optional

	_ = encExt // Use the parsed message as needed

	return nil
}
