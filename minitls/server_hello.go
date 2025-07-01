package minitls

import (
	"fmt"
)

type ServerHelloMsg struct {
	vers                 uint16
	random               []byte
	sessionId            []byte
	cipherSuite          uint16
	compressionMethod    uint8
	supportedVersion     uint16
	serverShare          keyShare
	preSharedKeyIdentity uint16
}

type keyShare struct {
	group uint16
	data  []byte
}

func unmarshalServerHello(data []byte) (*ServerHelloMsg, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("invalid ServerHello record")
	}

	if recordType(data[0]) != recordTypeHandshake {
		return nil, fmt.Errorf("expected handshake record, got %d", data[0])
	}

	// Skip record header (5 bytes)
	msgLen := int(data[3])<<8 | int(data[4])
	if msgLen > len(data)-5 {
		return nil, fmt.Errorf("handshake message too short")
	}
	d := data[5 : 5+msgLen]

	if HandshakeType(d[0]) != typeServerHello {
		return nil, fmt.Errorf("expected ServerHello, got %d", d[0])
	}

	// Parse ServerHello message
	msg := &ServerHelloMsg{}

	// Skip handshake header (4 bytes: type + length)
	d = d[4:]

	if len(d) < 38 { // minimum: version(2) + random(32) + session_id_len(1) + cipher(2) + compression(1)
		return nil, fmt.Errorf("ServerHello too short")
	}

	// Server version
	msg.vers = uint16(d[0])<<8 | uint16(d[1])
	d = d[2:]

	// Server random
	msg.random = make([]byte, 32)
	copy(msg.random, d[:32])
	d = d[32:]

	// Session ID
	sessionIdLen := int(d[0])
	d = d[1:]
	if len(d) < sessionIdLen {
		return nil, fmt.Errorf("invalid session ID length")
	}
	msg.sessionId = make([]byte, sessionIdLen)
	copy(msg.sessionId, d[:sessionIdLen])
	d = d[sessionIdLen:]

	// Cipher suite
	if len(d) < 2 {
		return nil, fmt.Errorf("missing cipher suite")
	}
	msg.cipherSuite = uint16(d[0])<<8 | uint16(d[1])
	d = d[2:]

	// Compression method
	if len(d) < 1 {
		return nil, fmt.Errorf("missing compression method")
	}
	msg.compressionMethod = d[0]
	d = d[1:]

	// Extensions
	if len(d) >= 2 {
		extLen := int(d[0])<<8 | int(d[1])
		d = d[2:]

		if len(d) >= extLen {
			if err := parseServerHelloExtensions(msg, d[:extLen]); err != nil {
				return nil, fmt.Errorf("failed to parse extensions: %v", err)
			}
		}
	}

	return msg, nil
}

func parseServerHelloExtensions(msg *ServerHelloMsg, data []byte) error {
	for len(data) >= 4 {
		extType := uint16(data[0])<<8 | uint16(data[1])
		extLen := int(data[2])<<8 | int(data[3])
		data = data[4:]

		if len(data) < extLen {
			return fmt.Errorf("extension data too short")
		}

		extData := data[:extLen]
		data = data[extLen:]

		switch extType {
		case extensionSupportedVersions:
			if len(extData) >= 2 {
				msg.supportedVersion = uint16(extData[0])<<8 | uint16(extData[1])
			}
		case extensionKeyShare:
			if len(extData) >= 4 {
				msg.serverShare.group = uint16(extData[0])<<8 | uint16(extData[1])
				keyLen := int(extData[2])<<8 | int(extData[3])
				if len(extData) >= 4+keyLen {
					msg.serverShare.data = make([]byte, keyLen)
					copy(msg.serverShare.data, extData[4:4+keyLen])
				}
			}
		}
	}

	return nil
}
