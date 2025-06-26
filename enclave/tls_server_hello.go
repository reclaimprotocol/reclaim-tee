package enclave

import (
	"bytes"
	"fmt"
)

// Type definitions are now in tls_client.go

// parseUint16 reads a big-endian uint16 from the buffer
func parseUint16(data []byte, offset int) (uint16, error) {
	if offset+2 > len(data) {
		return 0, fmt.Errorf("buffer too short for uint16 at offset %d", offset)
	}
	return uint16(data[offset])<<8 | uint16(data[offset+1]), nil
}

// parseUint24 reads a big-endian uint24 from the buffer
func parseUint24(data []byte, offset int) (uint32, error) {
	if offset+3 > len(data) {
		return 0, fmt.Errorf("buffer too short for uint24 at offset %d", offset)
	}
	return uint32(data[offset])<<16 | uint32(data[offset+1])<<8 | uint32(data[offset+2]), nil
}

// parseUint8LengthPrefixed reads a length-prefixed byte slice with 1-byte length
func parseUint8LengthPrefixed(data []byte, offset int) ([]byte, int, error) {
	if offset >= len(data) {
		return nil, 0, fmt.Errorf("buffer too short for length byte at offset %d", offset)
	}

	length := int(data[offset])
	offset++

	if offset+length > len(data) {
		return nil, 0, fmt.Errorf("buffer too short for %d bytes at offset %d", length, offset)
	}

	return data[offset : offset+length], offset + length, nil
}

// parseUint16LengthPrefixed reads a length-prefixed byte slice with 2-byte length
func parseUint16LengthPrefixed(data []byte, offset int) ([]byte, int, error) {
	if offset+2 > len(data) {
		return nil, 0, fmt.Errorf("buffer too short for length field at offset %d", offset)
	}

	length := int(parseUint16NoError(data, offset))
	offset += 2

	if offset+length > len(data) {
		return nil, 0, fmt.Errorf("buffer too short for %d bytes at offset %d", length, offset)
	}

	return data[offset : offset+length], offset + length, nil
}

// parseUint16NoError is a helper that assumes the buffer is long enough
func parseUint16NoError(data []byte, offset int) uint16 {
	return uint16(data[offset])<<8 | uint16(data[offset+1])
}

// parseServerHelloExtensions parses the extensions section of Server Hello
func parseServerHelloExtensions(data []byte) ([]extension, *KeyShare, uint16, error) {
	var extensions []extension
	var keyShare *KeyShare
	var supportedVersion uint16

	offset := 0
	for offset < len(data) {
		if offset+4 > len(data) {
			return nil, nil, 0, fmt.Errorf("incomplete extension header at offset %d", offset)
		}

		extType := parseUint16NoError(data, offset)
		extLength := int(parseUint16NoError(data, offset+2))
		offset += 4

		if offset+extLength > len(data) {
			return nil, nil, 0, fmt.Errorf("incomplete extension data for type %d", extType)
		}

		extData := data[offset : offset+extLength]
		offset += extLength

		ext := extension{
			extensionType: extType,
			data:          extData,
		}
		extensions = append(extensions, ext)

		// Parse specific extensions we care about
		switch extType {
		case ExtensionKeyShare:
			ks, err := parseKeyShareExtension(extData)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("failed to parse key share extension: %v", err)
			}
			keyShare = ks

		case ExtensionSupportedVersions:
			version, err := parseSupportedVersionExtension(extData)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("failed to parse supported version extension: %v", err)
			}
			supportedVersion = version
		}
	}

	return extensions, keyShare, supportedVersion, nil
}

// parseKeyShareExtension parses the key share extension from Server Hello
func parseKeyShareExtension(data []byte) (*KeyShare, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("key share extension too short")
	}

	// Server Hello key share has: group (2 bytes) + length (2 bytes) + data
	group := CurveID(parseUint16NoError(data, 0))
	keyLength := int(parseUint16NoError(data, 2))

	if len(data) != 4+keyLength {
		return nil, fmt.Errorf("key share extension length mismatch: expected %d, got %d", 4+keyLength, len(data))
	}

	keyData := data[4 : 4+keyLength]

	return &KeyShare{
		Group: group,
		Data:  keyData,
	}, nil
}

// parseSupportedVersionExtension parses the supported version extension
func parseSupportedVersionExtension(data []byte) (uint16, error) {
	if len(data) != 2 {
		return 0, fmt.Errorf("supported version extension should be 2 bytes, got %d", len(data))
	}

	return parseUint16NoError(data, 0), nil
}

// parseServerHello parses a TLS 1.3 Server Hello message
func parseServerHello(data []byte) (*serverHelloMsg, error) {
	if len(data) < 38 { // Minimum: version(2) + random(32) + session_id_len(1) + cipher(2) + compression(1)
		return nil, fmt.Errorf("Server Hello message too short: %d bytes", len(data))
	}

	msg := &serverHelloMsg{}
	offset := 0

	// Parse protocol version (2 bytes)
	var err error
	msg.vers, err = parseUint16(data, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to parse version: %v", err)
	}
	offset += 2

	// Parse server random (32 bytes)
	if offset+32 > len(data) {
		return nil, fmt.Errorf("insufficient data for server random")
	}
	msg.random = make([]byte, 32)
	copy(msg.random, data[offset:offset+32])
	offset += 32

	// Parse session ID
	msg.sessionId, offset, err = parseUint8LengthPrefixed(data, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to parse session ID: %v", err)
	}

	// Parse cipher suite (2 bytes)
	if offset+2 > len(data) {
		return nil, fmt.Errorf("insufficient data for cipher suite")
	}
	msg.cipherSuite, err = parseUint16(data, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cipher suite: %v", err)
	}
	offset += 2

	// Parse compression method (1 byte)
	if offset >= len(data) {
		return nil, fmt.Errorf("insufficient data for compression method")
	}
	msg.compressionMethod = data[offset]
	offset++

	// Parse extensions (if present)
	if offset < len(data) {
		extensionsData, _, err := parseUint16LengthPrefixed(data, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to parse extensions: %v", err)
		}

		msg.extensions, msg.keyShare, msg.supportedVersion, err = parseServerHelloExtensions(extensionsData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse extensions: %v", err)
		}
	}

	return msg, nil
}

// ProcessServerHello processes a Server Hello message and updates the TLS client state
func (s *TLSClientState) ProcessServerHello(serverHelloBytes []byte) error {
	// Validate input
	if len(serverHelloBytes) < 5 {
		return fmt.Errorf("server hello data too short")
	}

	// Check if this is a TLS record or just the handshake message
	var handshakeData []byte
	if serverHelloBytes[0] == recordTypeHandshake {
		// This is a complete TLS record, extract the handshake message
		if len(serverHelloBytes) < 5 {
			return fmt.Errorf("invalid TLS record: too short")
		}

		recordLength := int(parseUint16NoError(serverHelloBytes, 3))
		if len(serverHelloBytes) < 5+recordLength {
			return fmt.Errorf("incomplete TLS record")
		}

		handshakeData = serverHelloBytes[5 : 5+recordLength]
	} else {
		// This is just the handshake message
		handshakeData = serverHelloBytes
	}

	// Validate handshake message header
	if len(handshakeData) < 4 {
		return fmt.Errorf("handshake message too short")
	}

	if handshakeData[0] != handshakeTypeServerHello {
		return fmt.Errorf("expected Server Hello message type (%d), got %d",
			handshakeTypeServerHello, handshakeData[0])
	}

	// Extract handshake message length
	messageLength, err := parseUint24(handshakeData, 1)
	if err != nil {
		return fmt.Errorf("failed to parse handshake message length: %v", err)
	}

	if len(handshakeData) < 4+int(messageLength) {
		return fmt.Errorf("incomplete handshake message")
	}

	// Parse the Server Hello message content
	serverHelloData := handshakeData[4 : 4+messageLength]
	serverHello, err := parseServerHello(serverHelloData)
	if err != nil {
		return fmt.Errorf("failed to parse Server Hello: %v", err)
	}

	// Validate Server Hello contents
	if err := s.validateServerHello(serverHello); err != nil {
		return fmt.Errorf("Server Hello validation failed: %v", err)
	}

	// Store the handshake message for potential replay
	s.serverHelloMessage = make([]byte, len(handshakeData))
	copy(s.serverHelloMessage, handshakeData)

	// Store server hello data in client state
	s.serverHello = serverHello

	// Update handshake hash - switch to correct hash function if needed
	if err := s.updateHandshakeHashForCipherSuite(serverHello.cipherSuite); err != nil {
		return fmt.Errorf("failed to update handshake hash: %v", err)
	}

	// Update handshake hash with the complete handshake message
	s.HandshakeHash.Write(handshakeData)

	return nil
}

// validateServerHello validates the Server Hello message against our client state
func (s *TLSClientState) validateServerHello(serverHello *serverHelloMsg) error {
	// Check for Hello Retry Request
	if bytes.Equal(serverHello.random, TLS13HelloRetryRequest[:]) {
		return fmt.Errorf("Hello Retry Request not supported in this implementation")
	}

	// Validate TLS version
	if serverHello.supportedVersion != 0 {
		// TLS 1.3 uses supported_versions extension
		if serverHello.supportedVersion != VersionTLS13 {
			return fmt.Errorf("unsupported TLS version: 0x%04x", serverHello.supportedVersion)
		}
	} else {
		// Fallback to legacy version field (should be TLS 1.2 for compatibility)
		if serverHello.vers != 0x0303 { // TLS 1.2
			return fmt.Errorf("unexpected legacy version: 0x%04x", serverHello.vers)
		}
	}

	// Validate cipher suite
	supportedCipher := false
	for _, cipher := range s.SupportedCiphers {
		if cipher == serverHello.cipherSuite {
			supportedCipher = true
			break
		}
	}
	if !supportedCipher {
		return fmt.Errorf("server selected unsupported cipher suite: 0x%04x", serverHello.cipherSuite)
	}

	// Validate compression method (must be null for TLS 1.3)
	if serverHello.compressionMethod != 0 {
		return fmt.Errorf("server selected non-null compression: %d", serverHello.compressionMethod)
	}

	// Validate key share
	if serverHello.keyShare == nil {
		return fmt.Errorf("server did not provide key share")
	}

	// Check if we support the server's chosen group
	clientKeyPair := s.GetKeyPairForGroup(serverHello.keyShare.Group)
	if clientKeyPair == nil {
		return fmt.Errorf("server selected unsupported group: %d", serverHello.keyShare.Group)
	}

	// Validate key share data length
	expectedLength := 32 // X25519
	if serverHello.keyShare.Group == CurveP256 {
		expectedLength = 65 // P-256 uncompressed
	}

	if len(serverHello.keyShare.Data) != expectedLength {
		return fmt.Errorf("invalid key share length for group %d: expected %d, got %d",
			serverHello.keyShare.Group, expectedLength, len(serverHello.keyShare.Data))
	}

	return nil
}

// GetServerHello returns the parsed Server Hello message (for testing/debugging)
func (s *TLSClientState) GetServerHello() *serverHelloMsg {
	return s.serverHello
}

// GetSelectedCipherSuite returns the cipher suite selected by the server
func (s *TLSClientState) GetSelectedCipherSuite() uint16 {
	if s.serverHello != nil {
		return s.serverHello.cipherSuite
	}
	return 0
}

// GetServerKeyShare returns the server's key share
func (s *TLSClientState) GetServerKeyShare() *KeyShare {
	if s.serverHello != nil {
		return s.serverHello.keyShare
	}
	return nil
}
