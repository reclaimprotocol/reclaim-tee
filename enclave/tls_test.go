package enclave

import (
	"encoding/hex"
	"testing"
)

func TestTLSClientHelloGeneration(t *testing.T) {
	// Create TLS client configuration
	config := &TLSClientConfig{
		ServerName:    "example.com",
		ALPNProtocols: []string{"h2", "http/1.1"},
		MaxVersion:    VersionTLS13,
	}

	// Create TLS client state
	client, err := NewTLSClientState(config)
	if err != nil {
		t.Fatalf("Failed to create TLS client state: %v", err)
	}

	// Generate Client Hello
	clientHello, err := client.GenerateClientHello()
	if err != nil {
		t.Fatalf("Failed to generate Client Hello: %v", err)
	}

	// Basic validation
	if len(clientHello) < 50 {
		t.Fatalf("Client Hello too short: %d bytes", len(clientHello))
	}

	// Check TLS record header
	if clientHello[0] != recordTypeHandshake {
		t.Errorf("Expected handshake record type (%d), got %d", recordTypeHandshake, clientHello[0])
	}

	// Check TLS version in record header (should be TLS 1.3)
	recordVersion := (uint16(clientHello[1]) << 8) | uint16(clientHello[2])
	if recordVersion != VersionTLS13 {
		t.Errorf("Expected TLS 1.3 version (%x) in record, got %x", VersionTLS13, recordVersion)
	}

	// Check handshake message type (should be Client Hello)
	if clientHello[5] != handshakeTypeClientHello {
		t.Errorf("Expected Client Hello message type (%d), got %d", handshakeTypeClientHello, clientHello[5])
	}

	// Print hex dump for manual inspection
	t.Logf("Generated Client Hello (%d bytes):\n%s", len(clientHello), hex.Dump(clientHello))
}

func TestKeyGeneration(t *testing.T) {
	// Test X25519 key generation
	x25519KeyPair, err := generateX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate X25519 key pair: %v", err)
	}

	if len(x25519KeyPair.PublicKey) != 32 {
		t.Errorf("X25519 public key should be 32 bytes, got %d", len(x25519KeyPair.PublicKey))
	}

	if len(x25519KeyPair.PrivateKey) != 32 {
		t.Errorf("X25519 private key should be 32 bytes, got %d", len(x25519KeyPair.PrivateKey))
	}

	// Test P-256 key generation
	p256KeyPair, err := generateP256KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate P-256 key pair: %v", err)
	}

	if len(p256KeyPair.PublicKey) != 65 {
		t.Errorf("P-256 public key should be 65 bytes (uncompressed), got %d", len(p256KeyPair.PublicKey))
	}

	if p256KeyPair.PublicKey[0] != 0x04 {
		t.Errorf("P-256 public key should start with 0x04 (uncompressed), got 0x%02x", p256KeyPair.PublicKey[0])
	}

	if len(p256KeyPair.PrivateKey) != 32 {
		t.Errorf("P-256 private key should be 32 bytes, got %d", len(p256KeyPair.PrivateKey))
	}

	t.Logf("X25519 public key: %x", x25519KeyPair.PublicKey)
	t.Logf("P-256 public key: %x", p256KeyPair.PublicKey)
}

func TestECDH(t *testing.T) {
	// Test X25519 ECDH
	alice, err := generateX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Alice's X25519 key: %v", err)
	}

	bob, err := generateX25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Bob's X25519 key: %v", err)
	}

	// Alice computes shared secret using Bob's public key
	aliceShared, err := alice.performECDH(bob.PublicKey)
	if err != nil {
		t.Fatalf("Alice's ECDH failed: %v", err)
	}

	// Bob computes shared secret using Alice's public key
	bobShared, err := bob.performECDH(alice.PublicKey)
	if err != nil {
		t.Fatalf("Bob's ECDH failed: %v", err)
	}

	// Shared secrets should be identical
	if len(aliceShared) != len(bobShared) {
		t.Fatalf("Shared secret lengths differ: Alice=%d, Bob=%d", len(aliceShared), len(bobShared))
	}

	for i := range aliceShared {
		if aliceShared[i] != bobShared[i] {
			t.Fatalf("Shared secrets differ at byte %d: Alice=0x%02x, Bob=0x%02x", i, aliceShared[i], bobShared[i])
		}
	}

	t.Logf("X25519 ECDH successful, shared secret: %x", aliceShared)
}

func TestTLSClientStateIntegration(t *testing.T) {
	// Test the complete flow
	config := &TLSClientConfig{
		ServerName:    "api.example.com",
		ALPNProtocols: []string{"h2"},
		MaxVersion:    VersionTLS13,
	}

	client, err := NewTLSClientState(config)
	if err != nil {
		t.Fatalf("Failed to create TLS client: %v", err)
	}

	// Verify key shares were generated
	if len(client.KeyShares) == 0 {
		t.Fatal("No key shares generated")
	}

	// Verify we have both X25519 and P-256
	hasX25519 := false
	hasP256 := false

	for _, ks := range client.KeyShares {
		switch ks.Group {
		case X25519:
			hasX25519 = true
			if len(ks.Data) != 32 {
				t.Errorf("X25519 key share should be 32 bytes, got %d", len(ks.Data))
			}
		case CurveP256:
			hasP256 = true
			if len(ks.Data) != 65 {
				t.Errorf("P-256 key share should be 65 bytes, got %d", len(ks.Data))
			}
		}
	}

	if !hasX25519 {
		t.Error("Missing X25519 key share")
	}

	if !hasP256 {
		t.Error("Missing P-256 key share")
	}

	// Test key pair retrieval
	x25519KeyPair := client.GetKeyPairForGroup(X25519)
	if x25519KeyPair == nil {
		t.Fatal("Failed to retrieve X25519 key pair")
	}

	p256KeyPair := client.GetKeyPairForGroup(CurveP256)
	if p256KeyPair == nil {
		t.Fatal("Failed to retrieve P-256 key pair")
	}

	t.Logf("Integration test successful - client ready for handshake")
}
