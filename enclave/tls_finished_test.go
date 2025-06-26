package enclave

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestFinishedMessageMarshal(t *testing.T) {
	// Test marshaling a Finished message
	verifyData := make([]byte, 32) // SHA-256 hash size
	for i := range verifyData {
		verifyData[i] = byte(i)
	}

	finishedMsg := &finishedMsg{
		verifyData: verifyData,
	}

	marshaled, err := finishedMsg.marshal()
	if err != nil {
		t.Fatalf("Failed to marshal finished message: %v", err)
	}

	// Check structure: type(1) + length(3) + data(32) = 36 bytes
	expectedLength := 4 + 32
	if len(marshaled) != expectedLength {
		t.Errorf("Expected marshaled length %d, got %d", expectedLength, len(marshaled))
	}

	// Check message type
	if marshaled[0] != handshakeTypeFinished {
		t.Errorf("Expected message type %d, got %d", handshakeTypeFinished, marshaled[0])
	}

	// Check length field (24-bit big-endian)
	msgLength := int(marshaled[1])<<16 | int(marshaled[2])<<8 | int(marshaled[3])
	if msgLength != 32 {
		t.Errorf("Expected message length 32, got %d", msgLength)
	}

	// Check verify data
	if !bytes.Equal(marshaled[4:], verifyData) {
		t.Error("Verify data doesn't match")
	}

	t.Logf("Successfully marshaled Finished message (%d bytes)", len(marshaled))
}

func TestFinishedMessageParse(t *testing.T) {
	// Create test data
	verifyData := make([]byte, 32)
	rand.Read(verifyData)

	// Build raw message
	rawMsg := make([]byte, 4+32)
	rawMsg[0] = handshakeTypeFinished // Type
	rawMsg[1] = 0                     // Length high
	rawMsg[2] = 0                     // Length mid
	rawMsg[3] = 32                    // Length low
	copy(rawMsg[4:], verifyData)

	// Parse the message
	parsed, err := parseFinished(rawMsg)
	if err != nil {
		t.Fatalf("Failed to parse finished message: %v", err)
	}

	// Verify parsed data
	if !bytes.Equal(parsed.verifyData, verifyData) {
		t.Error("Parsed verify data doesn't match original")
	}

	t.Logf("Successfully parsed Finished message")
}

func TestFinishedMessageRoundTrip(t *testing.T) {
	// Test marshal -> parse -> marshal consistency
	originalVerifyData := make([]byte, 32)
	rand.Read(originalVerifyData)

	// Create and marshal
	original := &finishedMsg{verifyData: originalVerifyData}
	marshaled, err := original.marshal()
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Parse back
	parsed, err := parseFinished(marshaled)
	if err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	// Marshal again
	remarshaled, err := parsed.marshal()
	if err != nil {
		t.Fatalf("Failed to remarshal: %v", err)
	}

	// Should be identical
	if !bytes.Equal(marshaled, remarshaled) {
		t.Error("Round-trip marshaling produced different results")
	}

	t.Logf("Finished message round-trip test passed")
}

func TestGenerateClientFinished(t *testing.T) {
	// Create TLS client state
	config := &TLSClientConfig{
		ServerName: "finished.example.com",
		MaxVersion: VersionTLS13,
	}

	client, err := NewTLSClientState(config)
	if err != nil {
		t.Fatalf("Failed to create TLS client: %v", err)
	}

	// Generate Client Hello and process mock Server Hello
	_, err = client.GenerateClientHello()
	if err != nil {
		t.Fatalf("Failed to generate Client Hello: %v", err)
	}

	serverHelloRecord := createMockServerHelloMessage(TLS_AES_128_GCM_SHA256, X25519)
	err = client.ProcessServerHello(serverHelloRecord)
	if err != nil {
		t.Fatalf("Failed to process Server Hello: %v", err)
	}

	// Create key schedule and derive handshake secrets
	keySchedule, err := NewGoTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create key schedule: %v", err)
	}

	// Get shared secret for ECDH
	serverKeyShare := client.GetServerKeyShare()
	clientKeyPair := client.GetKeyPairForGroup(serverKeyShare.Group)
	sharedSecret, err := clientKeyPair.performECDH(serverKeyShare.Data)
	if err != nil {
		t.Fatalf("ECDH failed: %v", err)
	}

	// Derive handshake secrets
	keySchedule.InitializeEarlySecret()
	err = keySchedule.DeriveHandshakeSecret(sharedSecret)
	if err != nil {
		t.Fatalf("Failed to derive handshake secret: %v", err)
	}

	keySchedule.UpdateTranscript(client.HandshakeHash.Sum(nil))
	err = keySchedule.DeriveHandshakeTrafficSecrets()
	if err != nil {
		t.Fatalf("Failed to derive handshake traffic secrets: %v", err)
	}

	// Generate client Finished message
	clientFinished, err := client.GenerateClientFinished(keySchedule)
	if err != nil {
		t.Fatalf("Failed to generate client finished: %v", err)
	}

	// Verify structure
	if len(clientFinished) < 4 {
		t.Fatalf("Client finished too short: %d bytes", len(clientFinished))
	}

	if clientFinished[0] != handshakeTypeFinished {
		t.Errorf("Expected finished message type %d, got %d", handshakeTypeFinished, clientFinished[0])
	}

	// Parse to verify it's well-formed
	_, err = parseFinished(clientFinished)
	if err != nil {
		t.Fatalf("Generated client finished is malformed: %v", err)
	}

	t.Logf("Successfully generated client Finished message (%d bytes)", len(clientFinished))
	t.Logf("Verify data: %s", hex.EncodeToString(clientFinished[4:12])+"...")
}

func TestServerFinishedVerification(t *testing.T) {
	// Create TLS client state and complete handshake setup
	config := &TLSClientConfig{
		ServerName: "verify.example.com",
		MaxVersion: VersionTLS13,
	}

	client, err := NewTLSClientState(config)
	if err != nil {
		t.Fatalf("Failed to create TLS client: %v", err)
	}

	// Complete handshake setup
	_, err = client.GenerateClientHello()
	if err != nil {
		t.Fatalf("Failed to generate Client Hello: %v", err)
	}

	serverHelloRecord := createMockServerHelloMessage(TLS_AES_128_GCM_SHA256, X25519)
	err = client.ProcessServerHello(serverHelloRecord)
	if err != nil {
		t.Fatalf("Failed to process Server Hello: %v", err)
	}

	// Create key schedule
	keySchedule, err := NewGoTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create key schedule: %v", err)
	}

	// Derive secrets
	serverKeyShare := client.GetServerKeyShare()
	clientKeyPair := client.GetKeyPairForGroup(serverKeyShare.Group)
	sharedSecret, err := clientKeyPair.performECDH(serverKeyShare.Data)
	if err != nil {
		t.Fatalf("ECDH failed: %v", err)
	}

	keySchedule.InitializeEarlySecret()
	err = keySchedule.DeriveHandshakeSecret(sharedSecret)
	if err != nil {
		t.Fatalf("Failed to derive handshake secret: %v", err)
	}

	keySchedule.UpdateTranscript(client.HandshakeHash.Sum(nil))
	err = keySchedule.DeriveHandshakeTrafficSecrets()
	if err != nil {
		t.Fatalf("Failed to derive handshake traffic secrets: %v", err)
	}

	// Create a mock server Finished message
	serverFinishedKey := keySchedule.cipherSuite.expandLabel(keySchedule.serverHandshakeSecret, "finished", nil, keySchedule.cipherSuite.hash.Size())
	transcriptHash := client.HandshakeHash.Sum(nil)
	serverVerifyData := computeFinishedVerifyData(serverFinishedKey, transcriptHash, keySchedule.cipherSuite.hash.New)

	serverFinishedMsg := &finishedMsg{verifyData: serverVerifyData}
	serverFinishedBytes, err := serverFinishedMsg.marshal()
	if err != nil {
		t.Fatalf("Failed to marshal server finished: %v", err)
	}

	// Verify the server Finished message
	err = client.VerifyServerFinished(serverFinishedBytes, keySchedule)
	if err != nil {
		t.Fatalf("Failed to verify server finished: %v", err)
	}

	t.Logf("Successfully verified server Finished message")

	// Test with invalid verify data
	invalidFinishedMsg := &finishedMsg{verifyData: make([]byte, 32)}
	invalidFinishedBytes, _ := invalidFinishedMsg.marshal()

	err = client.VerifyServerFinished(invalidFinishedBytes, keySchedule)
	if err == nil {
		t.Error("Should have failed to verify invalid server finished")
	}

	t.Logf("Correctly rejected invalid server Finished message")
}

func TestFinishedVerifyDataComputation(t *testing.T) {
	// Test the core verify data computation
	finishedKey := make([]byte, 32)
	for i := range finishedKey {
		finishedKey[i] = byte(i)
	}

	transcriptHash := sha256.Sum256([]byte("test transcript data"))

	verifyData := computeFinishedVerifyData(finishedKey, transcriptHash[:], sha256.New)

	// Verify data should be 32 bytes for SHA-256
	if len(verifyData) != 32 {
		t.Errorf("Expected 32-byte verify data, got %d", len(verifyData))
	}

	// Should be deterministic
	verifyData2 := computeFinishedVerifyData(finishedKey, transcriptHash[:], sha256.New)
	if !bytes.Equal(verifyData, verifyData2) {
		t.Error("Verify data computation should be deterministic")
	}

	// Different inputs should produce different outputs
	differentKey := make([]byte, 32)
	for i := range differentKey {
		differentKey[i] = byte(i + 1)
	}

	differentVerifyData := computeFinishedVerifyData(differentKey, transcriptHash[:], sha256.New)
	if bytes.Equal(verifyData, differentVerifyData) {
		t.Error("Different keys should produce different verify data")
	}

	t.Logf("Verify data computation working correctly")
	t.Logf("Verify data: %s", hex.EncodeToString(verifyData[:8])+"...")
}

func TestCompleteHandshake(t *testing.T) {
	// Test complete handshake flow including Finished messages
	config := &TLSClientConfig{
		ServerName: "complete.example.com",
		MaxVersion: VersionTLS13,
	}

	client, err := NewTLSClientState(config)
	if err != nil {
		t.Fatalf("Failed to create TLS client: %v", err)
	}

	// Step 1: Client Hello
	_, err = client.GenerateClientHello()
	if err != nil {
		t.Fatalf("Failed to generate Client Hello: %v", err)
	}

	// Step 2: Server Hello
	serverHelloRecord := createMockServerHelloMessage(TLS_AES_128_GCM_SHA256, X25519)
	err = client.ProcessServerHello(serverHelloRecord)
	if err != nil {
		t.Fatalf("Failed to process Server Hello: %v", err)
	}

	// Step 3: Key derivation
	keySchedule, err := NewGoTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create key schedule: %v", err)
	}

	serverKeyShare := client.GetServerKeyShare()
	clientKeyPair := client.GetKeyPairForGroup(serverKeyShare.Group)
	sharedSecret, err := clientKeyPair.performECDH(serverKeyShare.Data)
	if err != nil {
		t.Fatalf("ECDH failed: %v", err)
	}

	keySchedule.InitializeEarlySecret()
	err = keySchedule.DeriveHandshakeSecret(sharedSecret)
	if err != nil {
		t.Fatalf("Failed to derive handshake secret: %v", err)
	}

	keySchedule.UpdateTranscript(client.HandshakeHash.Sum(nil))
	err = keySchedule.DeriveHandshakeTrafficSecrets()
	if err != nil {
		t.Fatalf("Failed to derive handshake traffic secrets: %v", err)
	}

	err = keySchedule.DeriveMasterSecret()
	if err != nil {
		t.Fatalf("Failed to derive master secret: %v", err)
	}

	err = keySchedule.DeriveApplicationTrafficSecrets()
	if err != nil {
		t.Fatalf("Failed to derive application traffic secrets: %v", err)
	}

	// Step 4: Generate client Finished
	clientFinished, err := client.GenerateClientFinished(keySchedule)
	if err != nil {
		t.Fatalf("Failed to generate client finished: %v", err)
	}

	// Step 5: Verify server Finished (mock)
	serverFinishedKey := keySchedule.cipherSuite.expandLabel(keySchedule.serverHandshakeSecret, "finished", nil, keySchedule.cipherSuite.hash.Size())
	transcriptHash := client.HandshakeHash.Sum(nil)
	serverVerifyData := computeFinishedVerifyData(serverFinishedKey, transcriptHash, keySchedule.cipherSuite.hash.New)

	serverFinishedMsg := &finishedMsg{verifyData: serverVerifyData}
	serverFinishedBytes, err := serverFinishedMsg.marshal()
	if err != nil {
		t.Fatalf("Failed to marshal server finished: %v", err)
	}

	err = client.VerifyServerFinished(serverFinishedBytes, keySchedule)
	if err != nil {
		t.Fatalf("Failed to verify server finished: %v", err)
	}

	// Step 6: Complete handshake
	err = client.CompleteHandshake(keySchedule)
	if err != nil {
		t.Fatalf("Failed to complete handshake: %v", err)
	}

	// Step 7: Extract session keys
	sessionKeys, err := client.ExtractSessionKeys()
	if err != nil {
		t.Fatalf("Failed to extract session keys: %v", err)
	}

	// Verify we have valid session keys
	if len(sessionKeys.ClientWriteKey) != 16 {
		t.Errorf("Expected 16-byte client key, got %d", len(sessionKeys.ClientWriteKey))
	}

	if len(sessionKeys.ServerWriteKey) != 16 {
		t.Errorf("Expected 16-byte server key, got %d", len(sessionKeys.ServerWriteKey))
	}

	t.Logf("Complete TLS 1.3 handshake with Finished messages SUCCESSFUL!")
	t.Logf("Client finished: %s", hex.EncodeToString(clientFinished[4:12])+"...")
	t.Logf("Session keys extracted - ready for TEE MPC operations")
}

func TestFinishedErrorHandling(t *testing.T) {
	// Test various error conditions
	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "TooShort",
			data: []byte{0x14, 0x00, 0x00}, // Only 3 bytes
		},
		{
			name: "WrongType",
			data: []byte{0x01, 0x00, 0x00, 0x20}, // Client Hello type instead of Finished
		},
		{
			name: "LengthMismatch",
			data: []byte{0x14, 0x00, 0x00, 0x20}, // Says 32 bytes but message is only 4
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseFinished(tc.data)
			if err == nil {
				t.Errorf("Should have failed to parse malformed finished message: %s", tc.name)
			}
			t.Logf("Correctly rejected %s: %v", tc.name, err)
		})
	}

	// Test empty verify data
	emptyFinished := &finishedMsg{verifyData: nil}
	_, err := emptyFinished.marshal()
	if err == nil {
		t.Error("Should have failed to marshal finished with empty verify data")
	}

	t.Logf("Finished message error handling working correctly")
}

// Note: createMockServerHelloMessage is defined in tls_server_hello_test.go
// and is available for use in these tests
