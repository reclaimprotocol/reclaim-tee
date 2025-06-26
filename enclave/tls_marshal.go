package enclave

import (
	"encoding/binary"
	"fmt"
)

// TLS record and message type constants
const (
	recordTypeHandshake      = 22
	handshakeTypeClientHello = 1
)

// marshalUint24 writes a 24-bit integer in big-endian format
func marshalUint24(b []byte, v uint32) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

// addUint8 appends a uint8 to the byte slice
func addUint8(b []byte, v uint8) []byte {
	return append(b, v)
}

// addUint16 appends a uint16 in big-endian format
func addUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

// addUint24 appends a uint24 in big-endian format
func addUint24(b []byte, v uint32) []byte {
	return append(b, byte(v>>16), byte(v>>8), byte(v))
}

// addUint8LengthPrefixed adds a length-prefixed byte slice with 1-byte length
func addUint8LengthPrefixed(b []byte, v []byte) []byte {
	b = addUint8(b, uint8(len(v)))
	return append(b, v...)
}

// addUint16LengthPrefixed adds a length-prefixed byte slice with 2-byte length
func addUint16LengthPrefixed(b []byte, v []byte) []byte {
	b = addUint16(b, uint16(len(v)))
	return append(b, v...)
}

// marshalExtension marshals a TLS extension
func marshalExtension(extType uint16, data []byte) []byte {
	ext := make([]byte, 0, 4+len(data))
	ext = addUint16(ext, extType)
	ext = addUint16(ext, uint16(len(data)))
	ext = append(ext, data...)
	return ext
}

// marshalServerNameExtension marshals the Server Name Indication extension
func marshalServerNameExtension(serverName string) []byte {
	if serverName == "" {
		return nil
	}

	// Server name list entry: type (1) + length (2) + name
	nameBytes := []byte(serverName)
	entry := make([]byte, 0, 3+len(nameBytes))
	entry = addUint8(entry, 0) // name type: host_name
	entry = addUint16(entry, uint16(len(nameBytes)))
	entry = append(entry, nameBytes...)

	// Server name list: length (2) + entries
	list := addUint16LengthPrefixed(nil, entry)

	return marshalExtension(ExtensionServerName, list)
}

// marshalSupportedVersionsExtension marshals the supported versions extension
func marshalSupportedVersionsExtension(versions []uint16) []byte {
	data := make([]byte, 0, 1+2*len(versions))
	data = addUint8(data, uint8(2*len(versions))) // length of versions list
	for _, version := range versions {
		data = addUint16(data, version)
	}
	return marshalExtension(ExtensionSupportedVersions, data)
}

// marshalSupportedGroupsExtension marshals the supported groups extension
func marshalSupportedGroupsExtension(groups []CurveID) []byte {
	data := make([]byte, 0, 2+2*len(groups))
	data = addUint16(data, uint16(2*len(groups))) // length of groups list
	for _, group := range groups {
		data = addUint16(data, uint16(group))
	}
	return marshalExtension(ExtensionSupportedGroups, data)
}

// marshalKeyShareExtension marshals the key share extension
func marshalKeyShareExtension(keyShares []KeyShare) []byte {
	if len(keyShares) == 0 {
		return nil
	}

	// Calculate total length needed
	totalLen := 0
	for _, ks := range keyShares {
		totalLen += 4 + len(ks.Data) // group (2) + length (2) + data
	}

	data := make([]byte, 0, 2+totalLen)
	data = addUint16(data, uint16(totalLen)) // length of key shares list

	for _, ks := range keyShares {
		data = addUint16(data, uint16(ks.Group))     // group
		data = addUint16(data, uint16(len(ks.Data))) // length
		data = append(data, ks.Data...)              // key exchange data
	}

	return marshalExtension(ExtensionKeyShare, data)
}

// marshalSignatureAlgorithmsExtension marshals the signature algorithms extension
func marshalSignatureAlgorithmsExtension(algorithms []SignatureScheme) []byte {
	data := make([]byte, 0, 2+2*len(algorithms))
	data = addUint16(data, uint16(2*len(algorithms))) // length of algorithms list
	for _, alg := range algorithms {
		data = addUint16(data, uint16(alg))
	}
	return marshalExtension(ExtensionSignatureAlgorithms, data)
}

// marshalALPNExtension marshals the ALPN extension
func marshalALPNExtension(protocols []string) []byte {
	if len(protocols) == 0 {
		return nil
	}

	// Calculate total length
	totalLen := 0
	for _, proto := range protocols {
		totalLen += 1 + len(proto) // length byte + protocol name
	}

	data := make([]byte, 0, 2+totalLen)
	data = addUint16(data, uint16(totalLen)) // length of protocol list

	for _, proto := range protocols {
		data = addUint8LengthPrefixed(data, []byte(proto))
	}

	return marshalExtension(ExtensionALPN, data)
}

// marshal serializes the Client Hello message to TLS wire format
// Based on Go's crypto/tls/handshake_messages.go
func (m *clientHelloMsg) marshal() ([]byte, error) {
	if m.vers == 0 {
		return nil, fmt.Errorf("TLS version not set")
	}

	// Start building the message
	hello := make([]byte, 0, 512) // Initial capacity estimate

	// Protocol version (2 bytes)
	hello = addUint16(hello, m.vers)

	// Random (32 bytes)
	if len(m.random) != 32 {
		return nil, fmt.Errorf("client random must be 32 bytes, got %d", len(m.random))
	}
	hello = append(hello, m.random...)

	// Session ID (1 byte length + data)
	hello = addUint8LengthPrefixed(hello, m.sessionId)

	// Cipher suites (2 byte length + data)
	cipherSuitesLen := 2 * len(m.cipherSuites)
	hello = addUint16(hello, uint16(cipherSuitesLen))
	for _, suite := range m.cipherSuites {
		hello = addUint16(hello, suite)
	}

	// Compression methods (1 byte length + data)
	hello = addUint8LengthPrefixed(hello, m.compressionMethods)

	// Extensions
	extensions := make([]byte, 0, 256)

	// Server Name Indication
	if ext := marshalServerNameExtension(m.serverName); ext != nil {
		extensions = append(extensions, ext...)
	}

	// Supported Versions (TLS 1.3)
	if len(m.supportedVersions) > 0 {
		ext := marshalSupportedVersionsExtension(m.supportedVersions)
		extensions = append(extensions, ext...)
	}

	// Supported Groups
	if len(m.supportedGroups) > 0 {
		ext := marshalSupportedGroupsExtension(m.supportedGroups)
		extensions = append(extensions, ext...)
	}

	// Key Share
	if len(m.keyShares) > 0 {
		ext := marshalKeyShareExtension(m.keyShares)
		if ext != nil {
			extensions = append(extensions, ext...)
		}
	}

	// Signature Algorithms
	if len(m.supportedSignatureAlgorithms) > 0 {
		ext := marshalSignatureAlgorithmsExtension(m.supportedSignatureAlgorithms)
		extensions = append(extensions, ext...)
	}

	// ALPN
	if len(m.alpnProtocols) > 0 {
		ext := marshalALPNExtension(m.alpnProtocols)
		if ext != nil {
			extensions = append(extensions, ext...)
		}
	}

	// Add extensions length and data
	if len(extensions) > 0 {
		hello = addUint16LengthPrefixed(hello, extensions)
	} else {
		// No extensions - add zero length
		hello = addUint16(hello, 0)
	}

	// Wrap in handshake message format:
	// - Message type (1 byte): ClientHello = 1
	// - Length (3 bytes): length of hello data
	// - Data: hello

	handshakeMsg := make([]byte, 0, 4+len(hello))
	handshakeMsg = addUint8(handshakeMsg, handshakeTypeClientHello)
	handshakeMsg = addUint24(handshakeMsg, uint32(len(hello)))
	handshakeMsg = append(handshakeMsg, hello...)

	return handshakeMsg, nil
}

// marshalTLSRecord wraps a handshake message in a TLS record
func marshalTLSRecord(contentType uint8, version uint16, data []byte) []byte {
	record := make([]byte, 5+len(data))
	record[0] = contentType
	binary.BigEndian.PutUint16(record[1:3], version)
	binary.BigEndian.PutUint16(record[3:5], uint16(len(data)))
	copy(record[5:], data)
	return record
}

// MarshalClientHelloRecord creates a complete TLS record containing the Client Hello
func (s *TLSClientState) MarshalClientHelloRecord() ([]byte, error) {
	// Build Client Hello message
	hello := &clientHelloMsg{
		vers:               s.Config.MaxVersion,
		random:             s.ClientRandom[:],
		sessionId:          s.SessionID,
		cipherSuites:       s.SupportedCiphers,
		compressionMethods: []uint8{0}, // No compression
		serverName:         s.Config.ServerName,
		alpnProtocols:      s.Config.ALPNProtocols,
		supportedVersions:  []uint16{VersionTLS13},
		keyShares:          s.KeyShares,
		supportedGroups:    []CurveID{X25519, CurveP256},
		supportedSignatureAlgorithms: []SignatureScheme{
			PSSWithSHA256,
			ECDSAWithP256AndSHA256,
			Ed25519,
		},
	}

	// Marshal the handshake message
	handshakeData, err := hello.marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Client Hello: %v", err)
	}

	// Wrap in TLS record
	record := marshalTLSRecord(recordTypeHandshake, VersionTLS13, handshakeData)

	return record, nil
}
