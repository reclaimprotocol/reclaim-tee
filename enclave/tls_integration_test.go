package enclave

import (
	"encoding/hex"
	"testing"
)

// TestTLS13HandshakeIntegration tests the complete TLS 1.3 handshake flow
func TestTLS13HandshakeIntegration(t *testing.T) {
	// Step 1: Create TLS client configuration
	config := &TLSClientConfig{
		ServerName:    "secure.example.com",
		ALPNProtocols: []string{"h2", "http/1.1"},
		MaxVersion:    VersionTLS13,
	}

	// Step 2: Initialize TLS client state
	client, err := NewTLSClientState(config)
	if err != nil {
		t.Fatalf("Failed to create TLS client state: %v", err)
	}

	// Step 3: Generate Client Hello
	clientHello, err := client.GenerateClientHello()
	if err != nil {
		t.Fatalf("Failed to generate Client Hello: %v", err)
	}

	t.Logf("Generated Client Hello (%d bytes)", len(clientHello))

	// Verify Client Hello structure
	if len(clientHello) < 50 {
		t.Fatalf("Client Hello too short: %d bytes", len(clientHello))
	}

	if clientHello[0] != recordTypeHandshake {
		t.Errorf("Expected handshake record type, got %d", clientHello[0])
	}

	// Step 4: Create mock Server Hello response
	serverHelloRecord := createMockServerHelloMessage(TLS_AES_128_GCM_SHA256, X25519)

	// Step 5: Process Server Hello
	err = client.ProcessServerHello(serverHelloRecord)
	if err != nil {
		t.Fatalf("Failed to process Server Hello: %v", err)
	}

	t.Logf("Processed Server Hello successfully")

	// Verify server hello was processed correctly
	selectedCipher := client.GetSelectedCipherSuite()
	if selectedCipher != TLS_AES_128_GCM_SHA256 {
		t.Errorf("Expected cipher suite 0x%04x, got 0x%04x", TLS_AES_128_GCM_SHA256, selectedCipher)
	}

	serverKeyShare := client.GetServerKeyShare()
	if serverKeyShare == nil {
		t.Fatal("Server key share should not be nil")
	}

	if serverKeyShare.Group != X25519 {
		t.Errorf("Expected X25519 group %d, got %d", X25519, serverKeyShare.Group)
	}

	// Step 6: Extract session keys (this is the critical step for our TEE MPC protocol)
	sessionKeys, err := client.ExtractSessionKeys()
	if err != nil {
		t.Fatalf("Failed to extract session keys: %v", err)
	}

	t.Logf("Successfully extracted TLS 1.3 session keys")

	// Step 7: Validate session keys
	if sessionKeys.CipherSuite != TLS_AES_128_GCM_SHA256 {
		t.Errorf("Wrong cipher suite in session keys: expected 0x%04x, got 0x%04x",
			TLS_AES_128_GCM_SHA256, sessionKeys.CipherSuite)
	}

	// For AES-128-GCM-SHA256, we expect:
	// - 16-byte keys (AES-128)
	// - 12-byte IVs (GCM)
	if len(sessionKeys.ClientWriteKey) != 16 {
		t.Errorf("Client write key wrong length: expected 16, got %d", len(sessionKeys.ClientWriteKey))
	}

	if len(sessionKeys.ServerWriteKey) != 16 {
		t.Errorf("Server write key wrong length: expected 16, got %d", len(sessionKeys.ServerWriteKey))
	}

	if len(sessionKeys.ClientWriteIV) != 12 {
		t.Errorf("Client write IV wrong length: expected 12, got %d", len(sessionKeys.ClientWriteIV))
	}

	if len(sessionKeys.ServerWriteIV) != 12 {
		t.Errorf("Server write IV wrong length: expected 12, got %d", len(sessionKeys.ServerWriteIV))
	}

	// All keys and IVs should be different
	if isEqual(sessionKeys.ClientWriteKey, sessionKeys.ServerWriteKey) {
		t.Error("Client and server write keys should be different")
	}

	if isEqual(sessionKeys.ClientWriteIV, sessionKeys.ServerWriteIV) {
		t.Error("Client and server write IVs should be different")
	}

	// Keys should not be all zeros
	if isAllZero(sessionKeys.ClientWriteKey) {
		t.Error("Client write key should not be all zeros")
	}

	if isAllZero(sessionKeys.ServerWriteKey) {
		t.Error("Server write key should not be all zeros")
	}

	if isAllZero(sessionKeys.ClientWriteIV) {
		t.Error("Client write IV should not be all zeros")
	}

	if isAllZero(sessionKeys.ServerWriteIV) {
		t.Error("Server write IV should not be all zeros")
	}

	// Step 8: Log the extracted keys (first 8 bytes for security)
	t.Logf("Client write key: %s", hex.EncodeToString(sessionKeys.ClientWriteKey[:8])+"...")
	t.Logf("Server write key: %s", hex.EncodeToString(sessionKeys.ServerWriteKey[:8])+"...")
	t.Logf("Client write IV:  %s", hex.EncodeToString(sessionKeys.ClientWriteIV[:8])+"...")
	t.Logf("Server write IV:  %s", hex.EncodeToString(sessionKeys.ServerWriteIV[:8])+"...")

	t.Logf("Complete TLS 1.3 handshake integration test PASSED!")
	t.Logf("Ready for TEE MPC split AEAD operations")
}

// TestTLS13HandshakeWithP256 tests the handshake with P-256 curve
func TestTLS13HandshakeWithP256(t *testing.T) {
	config := &TLSClientConfig{
		ServerName: "p256.example.com",
		MaxVersion: VersionTLS13,
	}

	client, err := NewTLSClientState(config)
	if err != nil {
		t.Fatalf("Failed to create TLS client state: %v", err)
	}

	// Generate Client Hello
	_, err = client.GenerateClientHello()
	if err != nil {
		t.Fatalf("Failed to generate Client Hello: %v", err)
	}

	// Create Server Hello with P-256 and AES-256-GCM
	serverHelloRecord := createMockServerHelloMessage(TLS_AES_256_GCM_SHA384, CurveP256)

	err = client.ProcessServerHello(serverHelloRecord)
	if err != nil {
		t.Fatalf("Failed to process Server Hello: %v", err)
	}

	// Extract session keys
	sessionKeys, err := client.ExtractSessionKeys()
	if err != nil {
		t.Fatalf("Failed to extract session keys: %v", err)
	}

	// For AES-256-GCM-SHA384, we expect:
	// - 32-byte keys (AES-256)
	// - 12-byte IVs (GCM)
	if len(sessionKeys.ClientWriteKey) != 32 {
		t.Errorf("Client write key wrong length: expected 32, got %d", len(sessionKeys.ClientWriteKey))
	}

	if len(sessionKeys.ServerWriteKey) != 32 {
		t.Errorf("Server write key wrong length: expected 32, got %d", len(sessionKeys.ServerWriteKey))
	}

	if sessionKeys.CipherSuite != TLS_AES_256_GCM_SHA384 {
		t.Errorf("Wrong cipher suite: expected 0x%04x, got 0x%04x",
			TLS_AES_256_GCM_SHA384, sessionKeys.CipherSuite)
	}

	t.Logf("P-256 + AES-256-GCM handshake successful")
}

// TestTLS13HandshakeWithChaCha20 tests the handshake with ChaCha20-Poly1305
func TestTLS13HandshakeWithChaCha20(t *testing.T) {
	config := &TLSClientConfig{
		ServerName: "chacha.example.com",
		MaxVersion: VersionTLS13,
	}

	client, err := NewTLSClientState(config)
	if err != nil {
		t.Fatalf("Failed to create TLS client state: %v", err)
	}

	// Generate Client Hello
	_, err = client.GenerateClientHello()
	if err != nil {
		t.Fatalf("Failed to generate Client Hello: %v", err)
	}

	// Create Server Hello with ChaCha20-Poly1305
	serverHelloRecord := createMockServerHelloMessage(TLS_CHACHA20_POLY1305_SHA256, X25519)

	err = client.ProcessServerHello(serverHelloRecord)
	if err != nil {
		t.Fatalf("Failed to process Server Hello: %v", err)
	}

	// Extract session keys
	sessionKeys, err := client.ExtractSessionKeys()
	if err != nil {
		t.Fatalf("Failed to extract session keys: %v", err)
	}

	// For ChaCha20-Poly1305-SHA256, we expect:
	// - 32-byte keys (ChaCha20)
	// - 12-byte IVs (Poly1305)
	if len(sessionKeys.ClientWriteKey) != 32 {
		t.Errorf("Client write key wrong length: expected 32, got %d", len(sessionKeys.ClientWriteKey))
	}

	if len(sessionKeys.ServerWriteKey) != 32 {
		t.Errorf("Server write key wrong length: expected 32, got %d", len(sessionKeys.ServerWriteKey))
	}

	if sessionKeys.CipherSuite != TLS_CHACHA20_POLY1305_SHA256 {
		t.Errorf("Wrong cipher suite: expected 0x%04x, got 0x%04x",
			TLS_CHACHA20_POLY1305_SHA256, sessionKeys.CipherSuite)
	}

	t.Logf("ChaCha20-Poly1305 handshake successful")
}

// TestTLS13ErrorHandling tests error conditions in the handshake flow
func TestTLS13ErrorHandling(t *testing.T) {
	config := &TLSClientConfig{
		ServerName: "error.example.com",
		MaxVersion: VersionTLS13,
	}

	client, err := NewTLSClientState(config)
	if err != nil {
		t.Fatalf("Failed to create TLS client state: %v", err)
	}

	// Test extracting keys without Server Hello
	_, err = client.ExtractSessionKeys()
	if err == nil {
		t.Error("Should fail to extract keys without Server Hello")
	}

	// Generate Client Hello
	_, err = client.GenerateClientHello()
	if err != nil {
		t.Fatalf("Failed to generate Client Hello: %v", err)
	}

	// Test with unsupported cipher suite
	unsupportedServerHello := createMockServerHelloMessage(0x9999, X25519)
	err = client.ProcessServerHello(unsupportedServerHello)
	if err == nil {
		t.Error("Should fail with unsupported cipher suite")
	}

	t.Logf("Error handling tests passed")
}

// TestSessionKeysDeterminism tests that the same inputs produce the same keys
func TestSessionKeysDeterminism(t *testing.T) {
	config := &TLSClientConfig{
		ServerName: "determinism.example.com",
		MaxVersion: VersionTLS13,
	}

	// Create two identical clients
	client1, err := NewTLSClientState(config)
	if err != nil {
		t.Fatalf("Failed to create first client: %v", err)
	}

	client2, err := NewTLSClientState(config)
	if err != nil {
		t.Fatalf("Failed to create second client: %v", err)
	}

	// Use the same random values for both (for deterministic testing)
	copy(client2.ClientRandom[:], client1.ClientRandom[:])
	copy(client2.SessionID, client1.SessionID)
	client2.KeyShares = client1.KeyShares
	client2.keyPairs = client1.keyPairs

	// Generate identical Client Hellos
	clientHello1, err := client1.GenerateClientHello()
	if err != nil {
		t.Fatalf("Failed to generate first Client Hello: %v", err)
	}

	// Reset handshake hash for second client to match first
	client2.HandshakeHash.Reset()
	client2.HandshakeHash.Write(clientHello1[5:]) // Skip TLS record header

	// Process identical Server Hellos
	serverHelloRecord := createMockServerHelloMessage(TLS_AES_128_GCM_SHA256, X25519)

	err = client1.ProcessServerHello(serverHelloRecord)
	if err != nil {
		t.Fatalf("Failed to process first Server Hello: %v", err)
	}

	err = client2.ProcessServerHello(serverHelloRecord)
	if err != nil {
		t.Fatalf("Failed to process second Server Hello: %v", err)
	}

	// Extract session keys from both
	keys1, err := client1.ExtractSessionKeys()
	if err != nil {
		t.Fatalf("Failed to extract first session keys: %v", err)
	}

	keys2, err := client2.ExtractSessionKeys()
	if err != nil {
		t.Fatalf("Failed to extract second session keys: %v", err)
	}

	// Keys should be identical
	if !isEqual(keys1.ClientWriteKey, keys2.ClientWriteKey) {
		t.Error("Client write keys should be identical with same inputs")
	}

	if !isEqual(keys1.ServerWriteKey, keys2.ServerWriteKey) {
		t.Error("Server write keys should be identical with same inputs")
	}

	if !isEqual(keys1.ClientWriteIV, keys2.ClientWriteIV) {
		t.Error("Client write IVs should be identical with same inputs")
	}

	if !isEqual(keys1.ServerWriteIV, keys2.ServerWriteIV) {
		t.Error("Server write IVs should be identical with same inputs")
	}

	t.Logf("Determinism test passed - identical inputs produce identical keys")
}

// Helper function to compare byte slices
func isEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
