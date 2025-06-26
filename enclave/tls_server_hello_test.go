package enclave

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// createMockServerHelloMessage creates a valid Server Hello message for testing
func createMockServerHelloMessage(cipherSuite uint16, group CurveID) []byte {
	// Build a valid Server Hello message
	hello := make([]byte, 0, 200)

	// Protocol version (TLS 1.2 for compatibility)
	hello = addUint16(hello, 0x0303)

	// Server random (32 bytes)
	serverRandom := make([]byte, 32)
	rand.Read(serverRandom)
	hello = append(hello, serverRandom...)

	// Session ID (empty for TLS 1.3)
	hello = addUint8(hello, 0)

	// Cipher suite
	hello = addUint16(hello, cipherSuite)

	// Compression method (null)
	hello = addUint8(hello, 0)

	// Extensions
	extensions := make([]byte, 0, 100)

	// Supported Versions extension (TLS 1.3)
	supportedVersionsData := make([]byte, 2)
	supportedVersionsData = addUint16(supportedVersionsData[:0], VersionTLS13)
	extensions = append(extensions, marshalExtension(ExtensionSupportedVersions, supportedVersionsData)...)

	// Key Share extension
	var keyShareData []byte
	if group == X25519 {
		keyShareData = make([]byte, 32)
		rand.Read(keyShareData)
	} else if group == CurveP256 {
		// Generate a valid P-256 key pair for the mock server
		p256KeyPair, err := generateP256KeyPair()
		if err != nil {
			panic("Failed to generate P-256 key pair for mock server: " + err.Error())
		}
		keyShareData = p256KeyPair.PublicKey
	}

	keyShareExtData := make([]byte, 0, 4+len(keyShareData))
	keyShareExtData = addUint16(keyShareExtData, uint16(group))
	keyShareExtData = addUint16(keyShareExtData, uint16(len(keyShareData)))
	keyShareExtData = append(keyShareExtData, keyShareData...)
	extensions = append(extensions, marshalExtension(ExtensionKeyShare, keyShareExtData)...)

	// Add extensions to hello
	hello = addUint16LengthPrefixed(hello, extensions)

	// Wrap in handshake message
	handshakeMsg := make([]byte, 0, 4+len(hello))
	handshakeMsg = addUint8(handshakeMsg, handshakeTypeServerHello)
	handshakeMsg = addUint24(handshakeMsg, uint32(len(hello)))
	handshakeMsg = append(handshakeMsg, hello...)

	// Wrap in TLS record
	record := marshalTLSRecord(recordTypeHandshake, VersionTLS13, handshakeMsg)

	return record
}

func TestParseServerHello(t *testing.T) {
	// Create a mock Server Hello
	serverHelloRecord := createMockServerHelloMessage(TLS_AES_128_GCM_SHA256, X25519)

	// Extract handshake message from TLS record
	if len(serverHelloRecord) < 5 {
		t.Fatal("Mock Server Hello record too short")
	}

	handshakeData := serverHelloRecord[5:]
	if len(handshakeData) < 4 {
		t.Fatal("Mock handshake message too short")
	}

	// Extract Server Hello content
	messageLength := int(parseUint24NoError(handshakeData, 1))
	serverHelloData := handshakeData[4 : 4+messageLength]

	// Parse Server Hello
	serverHello, err := parseServerHello(serverHelloData)
	if err != nil {
		t.Fatalf("Failed to parse Server Hello: %v", err)
	}

	// Validate parsed data
	if serverHello.vers != 0x0303 {
		t.Errorf("Expected version 0x0303, got 0x%04x", serverHello.vers)
	}

	if len(serverHello.random) != 32 {
		t.Errorf("Expected 32-byte random, got %d bytes", len(serverHello.random))
	}

	if serverHello.cipherSuite != TLS_AES_128_GCM_SHA256 {
		t.Errorf("Expected cipher suite 0x%04x, got 0x%04x", TLS_AES_128_GCM_SHA256, serverHello.cipherSuite)
	}

	if serverHello.compressionMethod != 0 {
		t.Errorf("Expected null compression, got %d", serverHello.compressionMethod)
	}

	if serverHello.supportedVersion != VersionTLS13 {
		t.Errorf("Expected TLS 1.3 version 0x%04x, got 0x%04x", VersionTLS13, serverHello.supportedVersion)
	}

	if serverHello.keyShare == nil {
		t.Fatal("Key share should not be nil")
	}

	if serverHello.keyShare.Group != X25519 {
		t.Errorf("Expected X25519 group %d, got %d", X25519, serverHello.keyShare.Group)
	}

	if len(serverHello.keyShare.Data) != 32 {
		t.Errorf("Expected 32-byte X25519 key, got %d bytes", len(serverHello.keyShare.Data))
	}

	t.Logf("Successfully parsed Server Hello with cipher 0x%04x and X25519 key share", serverHello.cipherSuite)
}

func TestProcessServerHello(t *testing.T) {
	// Create TLS client state
	config := &TLSClientConfig{
		ServerName:    "test.example.com",
		ALPNProtocols: []string{"h2"},
		MaxVersion:    VersionTLS13,
	}

	client, err := NewTLSClientState(config)
	if err != nil {
		t.Fatalf("Failed to create TLS client: %v", err)
	}

	// Generate Client Hello to initialize handshake hash
	_, err = client.GenerateClientHello()
	if err != nil {
		t.Fatalf("Failed to generate Client Hello: %v", err)
	}

	// Create mock Server Hello
	serverHelloRecord := createMockServerHelloMessage(TLS_AES_128_GCM_SHA256, X25519)

	// Process Server Hello
	err = client.ProcessServerHello(serverHelloRecord)
	if err != nil {
		t.Fatalf("Failed to process Server Hello: %v", err)
	}

	// Verify client state was updated
	if client.GetSelectedCipherSuite() != TLS_AES_128_GCM_SHA256 {
		t.Errorf("Expected cipher suite 0x%04x, got 0x%04x",
			TLS_AES_128_GCM_SHA256, client.GetSelectedCipherSuite())
	}

	serverKeyShare := client.GetServerKeyShare()
	if serverKeyShare == nil {
		t.Fatal("Server key share should not be nil")
	}

	if serverKeyShare.Group != X25519 {
		t.Errorf("Expected X25519 group %d, got %d", X25519, serverKeyShare.Group)
	}

	t.Logf("Successfully processed Server Hello and updated client state")
}

func TestServerHelloValidation(t *testing.T) {
	config := &TLSClientConfig{
		ServerName:    "test.example.com",
		ALPNProtocols: []string{"h2"},
		MaxVersion:    VersionTLS13,
	}

	client, err := NewTLSClientState(config)
	if err != nil {
		t.Fatalf("Failed to create TLS client: %v", err)
	}

	// Test unsupported cipher suite
	t.Run("UnsupportedCipherSuite", func(t *testing.T) {
		serverHelloRecord := createMockServerHelloMessage(0x9999, X25519) // Invalid cipher
		err := client.ProcessServerHello(serverHelloRecord)
		if err == nil {
			t.Error("Should reject unsupported cipher suite")
		}
		if !bytes.Contains([]byte(err.Error()), []byte("unsupported cipher suite")) {
			t.Errorf("Wrong error message: %v", err)
		}
	})

	// Test unsupported key group
	t.Run("UnsupportedKeyGroup", func(t *testing.T) {
		serverHelloRecord := createMockServerHelloMessage(TLS_AES_128_GCM_SHA256, 999) // Invalid group
		err := client.ProcessServerHello(serverHelloRecord)
		if err == nil {
			t.Error("Should reject unsupported key group")
		}
		if !bytes.Contains([]byte(err.Error()), []byte("unsupported group")) {
			t.Errorf("Wrong error message: %v", err)
		}
	})

	// Test Hello Retry Request detection
	t.Run("HelloRetryRequest", func(t *testing.T) {
		// Create Server Hello with HRR random
		hello := make([]byte, 0, 200)
		hello = addUint16(hello, 0x0303)
		hello = append(hello, TLS13HelloRetryRequest[:]...) // HRR random
		hello = addUint8(hello, 0)                          // Empty session ID
		hello = addUint16(hello, TLS_AES_128_GCM_SHA256)
		hello = addUint8(hello, 0)  // Null compression
		hello = addUint16(hello, 0) // No extensions

		// Wrap in handshake message
		handshakeMsg := make([]byte, 0, 4+len(hello))
		handshakeMsg = addUint8(handshakeMsg, handshakeTypeServerHello)
		handshakeMsg = addUint24(handshakeMsg, uint32(len(hello)))
		handshakeMsg = append(handshakeMsg, hello...)

		// Wrap in TLS record
		record := marshalTLSRecord(recordTypeHandshake, VersionTLS13, handshakeMsg)

		err := client.ProcessServerHello(record)
		if err == nil {
			t.Error("Should reject Hello Retry Request")
		}
		if !bytes.Contains([]byte(err.Error()), []byte("Hello Retry Request")) {
			t.Errorf("Wrong error message: %v", err)
		}
	})
}

func TestServerHelloErrorHandling(t *testing.T) {
	config := &TLSClientConfig{
		ServerName: "test.example.com",
		MaxVersion: VersionTLS13,
	}

	client, err := NewTLSClientState(config)
	if err != nil {
		t.Fatalf("Failed to create TLS client: %v", err)
	}

	// Test various malformed inputs
	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "TooShort",
			data: []byte{0x16, 0x03, 0x03, 0x00, 0x01, 0x02}, // Too short
		},
		{
			name: "WrongMessageType",
			data: func() []byte {
				hello := make([]byte, 50)
				hello[0] = 0x16 // Record type
				hello[5] = 0x01 // Wrong message type (Client Hello instead of Server Hello)
				return hello
			}(),
		},
		{
			name: "IncompleteMessage",
			data: func() []byte {
				record := make([]byte, 10)
				record[0] = 0x16 // Handshake record
				record[3] = 0x00 // Length high
				record[4] = 0x20 // Length low (32 bytes)
				record[5] = 0x02 // Server Hello type
				// But only 10 bytes total
				return record
			}(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := client.ProcessServerHello(tc.data)
			if err == nil {
				t.Errorf("Should reject malformed input: %s", tc.name)
			}
			t.Logf("Correctly rejected %s: %v", tc.name, err)
		})
	}
}

func TestP256ServerHello(t *testing.T) {
	config := &TLSClientConfig{
		ServerName: "test.example.com",
		MaxVersion: VersionTLS13,
	}

	client, err := NewTLSClientState(config)
	if err != nil {
		t.Fatalf("Failed to create TLS client: %v", err)
	}

	// Generate Client Hello
	_, err = client.GenerateClientHello()
	if err != nil {
		t.Fatalf("Failed to generate Client Hello: %v", err)
	}

	// Create Server Hello with P-256
	serverHelloRecord := createMockServerHelloMessage(TLS_AES_256_GCM_SHA384, CurveP256)

	err = client.ProcessServerHello(serverHelloRecord)
	if err != nil {
		t.Fatalf("Failed to process P-256 Server Hello: %v", err)
	}

	// Verify P-256 key share
	serverKeyShare := client.GetServerKeyShare()
	if serverKeyShare == nil {
		t.Fatal("Server key share should not be nil")
	}

	if serverKeyShare.Group != CurveP256 {
		t.Errorf("Expected P-256 group %d, got %d", CurveP256, serverKeyShare.Group)
	}

	if len(serverKeyShare.Data) != 65 {
		t.Errorf("Expected 65-byte P-256 key, got %d bytes", len(serverKeyShare.Data))
	}

	if serverKeyShare.Data[0] != 0x04 {
		t.Errorf("P-256 key should start with 0x04 (uncompressed), got 0x%02x", serverKeyShare.Data[0])
	}

	t.Logf("Successfully processed P-256 Server Hello")
}

// Helper function for tests
func parseUint24NoError(data []byte, offset int) uint32 {
	return uint32(data[offset])<<16 | uint32(data[offset+1])<<8 | uint32(data[offset+2])
}

func TestServerHelloIntegration(t *testing.T) {
	// Full integration test: Client Hello -> Server Hello -> Key Agreement
	config := &TLSClientConfig{
		ServerName:    "secure.example.com",
		ALPNProtocols: []string{"h2", "http/1.1"},
		MaxVersion:    VersionTLS13,
	}

	client, err := NewTLSClientState(config)
	if err != nil {
		t.Fatalf("Failed to create TLS client: %v", err)
	}

	// Step 1: Generate Client Hello
	clientHello, err := client.GenerateClientHello()
	if err != nil {
		t.Fatalf("Failed to generate Client Hello: %v", err)
	}

	t.Logf("Generated Client Hello (%d bytes)", len(clientHello))

	// Step 2: Process Server Hello
	serverHelloRecord := createMockServerHelloMessage(TLS_AES_128_GCM_SHA256, X25519)
	err = client.ProcessServerHello(serverHelloRecord)
	if err != nil {
		t.Fatalf("Failed to process Server Hello: %v", err)
	}

	t.Logf("Processed Server Hello successfully")

	// Step 3: Verify we can perform ECDH
	serverKeyShare := client.GetServerKeyShare()
	if serverKeyShare == nil {
		t.Fatal("No server key share available")
	}

	clientKeyPair := client.GetKeyPairForGroup(serverKeyShare.Group)
	if clientKeyPair == nil {
		t.Fatal("No matching client key pair")
	}

	// Perform ECDH to get shared secret
	sharedSecret, err := clientKeyPair.performECDH(serverKeyShare.Data)
	if err != nil {
		t.Fatalf("ECDH failed: %v", err)
	}

	if len(sharedSecret) != 32 {
		t.Errorf("Expected 32-byte shared secret, got %d bytes", len(sharedSecret))
	}

	t.Logf("ECDH successful, shared secret: %s", hex.EncodeToString(sharedSecret[:8])+"...")
	t.Logf("Integration test completed successfully")
}
