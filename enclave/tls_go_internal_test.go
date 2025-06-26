package enclave

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestGoTLSKeyScheduleBasic(t *testing.T) {
	// Test basic key schedule creation
	ks, err := NewGoTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create Go TLS key schedule: %v", err)
	}

	if ks.GetCipherSuite() != TLS_AES_128_GCM_SHA256 {
		t.Errorf("Wrong cipher suite: expected 0x%04x, got 0x%04x",
			TLS_AES_128_GCM_SHA256, ks.GetCipherSuite())
	}

	// Verify properties
	if ks.GetKeyLength() != 16 {
		t.Errorf("Wrong key length: expected 16, got %d", ks.GetKeyLength())
	}

	if ks.GetHashSize() != 32 {
		t.Errorf("Wrong hash size: expected 32, got %d", ks.GetHashSize())
	}

	t.Logf("Go TLS key schedule created successfully")
}

func TestGoTLSKeyScheduleFullFlow(t *testing.T) {
	// Test complete key derivation flow
	ks, err := NewGoTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create Go TLS key schedule: %v", err)
	}

	// Create mock shared secret
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	// Initialize and derive handshake secrets
	ks.InitializeEarlySecret()
	err = ks.DeriveHandshakeSecret(sharedSecret)
	if err != nil {
		t.Fatalf("Failed to derive handshake secret: %v", err)
	}

	ks.UpdateTranscript([]byte("mock handshake data"))
	err = ks.DeriveHandshakeTrafficSecrets()
	if err != nil {
		t.Fatalf("Failed to derive handshake traffic secrets: %v", err)
	}

	// Get handshake keys
	clientKey, clientIV, serverKey, serverIV, err := ks.GetHandshakeTrafficKeys()
	if err != nil {
		t.Fatalf("Failed to get handshake traffic keys: %v", err)
	}
	if len(clientKey) != 16 || len(serverKey) != 16 {
		t.Errorf("Wrong handshake key lengths: client=%d, server=%d", len(clientKey), len(serverKey))
	}
	if len(clientIV) != 12 || len(serverIV) != 12 {
		t.Errorf("Wrong handshake IV lengths: client=%d, server=%d", len(clientIV), len(serverIV))
	}

	// Derive master secret and application secrets
	err = ks.DeriveMasterSecret()
	if err != nil {
		t.Fatalf("Failed to derive master secret: %v", err)
	}

	err = ks.DeriveApplicationTrafficSecrets()
	if err != nil {
		t.Fatalf("Failed to derive application traffic secrets: %v", err)
	}

	// Get application keys
	appClientKey, appClientIV, appServerKey, appServerIV, err := ks.GetApplicationTrafficKeys()
	if err != nil {
		t.Fatalf("Failed to get application traffic keys: %v", err)
	}
	if len(appClientKey) != 16 || len(appServerKey) != 16 {
		t.Errorf("Wrong application key lengths: client=%d, server=%d", len(appClientKey), len(appServerKey))
	}
	if len(appClientIV) != 12 || len(appServerIV) != 12 {
		t.Errorf("Wrong application IV lengths: client=%d, server=%d", len(appClientIV), len(appServerIV))
	}

	// All keys should be different
	if bytes.Equal(clientKey, serverKey) {
		t.Error("Client and server handshake keys should be different")
	}
	if bytes.Equal(appClientKey, appServerKey) {
		t.Error("Client and server application keys should be different")
	}
	if bytes.Equal(clientKey, appClientKey) {
		t.Error("Handshake and application keys should be different")
	}

	t.Logf("Go TLS full key schedule flow completed successfully")
	t.Logf("Handshake - Client key: %s, Server key: %s",
		hex.EncodeToString(clientKey[:8])+"...",
		hex.EncodeToString(serverKey[:8])+"...")
	t.Logf("Application - Client key: %s, Server key: %s",
		hex.EncodeToString(appClientKey[:8])+"...",
		hex.EncodeToString(appServerKey[:8])+"...")
}

func TestGoTLSKeyScheduleAllCipherSuites(t *testing.T) {
	cipherSuites := []struct {
		name   string
		id     uint16
		keyLen int
		ivLen  int
	}{
		{"AES-128-GCM", TLS_AES_128_GCM_SHA256, 16, 12},
		{"AES-256-GCM", TLS_AES_256_GCM_SHA384, 32, 12},
		{"ChaCha20-Poly1305", TLS_CHACHA20_POLY1305_SHA256, 32, 12},
	}

	for _, cs := range cipherSuites {
		t.Run(cs.name, func(t *testing.T) {
			ks, err := NewGoTLSKeySchedule(cs.id)
			if err != nil {
				t.Fatalf("Failed to create key schedule for %s: %v", cs.name, err)
			}

			// Mock ECDH
			sharedSecret := make([]byte, 32)
			rand.Read(sharedSecret)

			ks.UpdateTranscript([]byte("test data for " + cs.name))

			// Full key schedule
			ks.InitializeEarlySecret()
			err = ks.DeriveHandshakeSecret(sharedSecret)
			if err != nil {
				t.Fatalf("Handshake secret derivation failed for %s: %v", cs.name, err)
			}

			err = ks.DeriveHandshakeTrafficSecrets()
			if err != nil {
				t.Fatalf("Handshake traffic derivation failed for %s: %v", cs.name, err)
			}

			err = ks.DeriveMasterSecret()
			if err != nil {
				t.Fatalf("Master secret derivation failed for %s: %v", cs.name, err)
			}

			err = ks.DeriveApplicationTrafficSecrets()
			if err != nil {
				t.Fatalf("Application traffic derivation failed for %s: %v", cs.name, err)
			}

			// Check key lengths
			clientKey, clientIV, serverKey, serverIV, err := ks.GetApplicationTrafficKeys()
			if err != nil {
				t.Fatalf("Failed to get application keys for %s: %v", cs.name, err)
			}
			if len(clientKey) != cs.keyLen {
				t.Errorf("%s: wrong client key length: expected %d, got %d",
					cs.name, cs.keyLen, len(clientKey))
			}
			if len(serverKey) != cs.keyLen {
				t.Errorf("%s: wrong server key length: expected %d, got %d",
					cs.name, cs.keyLen, len(serverKey))
			}
			if len(clientIV) != cs.ivLen {
				t.Errorf("%s: wrong client IV length: expected %d, got %d",
					cs.name, cs.ivLen, len(clientIV))
			}
			if len(serverIV) != cs.ivLen {
				t.Errorf("%s: wrong server IV length: expected %d, got %d",
					cs.name, cs.ivLen, len(serverIV))
			}

			t.Logf("%s key schedule successful", cs.name)
		})
	}
}

func TestGoTLSKeyScheduleDeterminism(t *testing.T) {
	// Test that same inputs produce same outputs
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	// Create two identical key schedules
	ks1, err := NewGoTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create first key schedule: %v", err)
	}

	ks2, err := NewGoTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create second key schedule: %v", err)
	}

	// Derive keys with identical inputs
	for _, ks := range []*GoTLSKeySchedule{ks1, ks2} {
		ks.InitializeEarlySecret()
		ks.DeriveHandshakeSecret(sharedSecret)
		ks.UpdateTranscript([]byte("deterministic test data"))
		ks.DeriveHandshakeTrafficSecrets()
		ks.DeriveMasterSecret()
		ks.DeriveApplicationTrafficSecrets()
	}

	// Keys should be identical
	c1, ci1, s1, si1, _ := ks1.GetApplicationTrafficKeys()
	c2, ci2, s2, si2, _ := ks2.GetApplicationTrafficKeys()

	if !bytes.Equal(c1, c2) {
		t.Error("Client keys should be identical with same inputs")
	}
	if !bytes.Equal(s1, s2) {
		t.Error("Server keys should be identical with same inputs")
	}
	if !bytes.Equal(ci1, ci2) {
		t.Error("Client IVs should be identical with same inputs")
	}
	if !bytes.Equal(si1, si2) {
		t.Error("Server IVs should be identical with same inputs")
	}

	t.Log("Determinism test passed")
}

func TestGoTLSKeyScheduleSecureZero(t *testing.T) {
	ks, err := NewGoTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create key schedule: %v", err)
	}

	// Set up some secrets
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	ks.InitializeEarlySecret()
	ks.DeriveHandshakeSecret(sharedSecret)
	ks.UpdateTranscript([]byte("test data"))
	ks.DeriveHandshakeTrafficSecrets()

	// Verify secrets exist and are non-zero
	if ks.earlySecret == nil || len(ks.earlySecret) == 0 {
		t.Fatal("Early secret not initialized")
	}
	if ks.handshakeSecret == nil || len(ks.handshakeSecret) == 0 {
		t.Fatal("Handshake secret not initialized")
	}

	// Check that secrets contain non-zero data
	hasNonZero := false
	for _, b := range ks.earlySecret {
		if b != 0 {
			hasNonZero = true
			break
		}
	}
	if !hasNonZero {
		t.Error("Early secret appears to be all zeros before SecureZero")
	}

	// Zero out secrets
	ks.SecureZero()

	// Verify all secrets are zeroed
	for i, b := range ks.earlySecret {
		if b != 0 {
			t.Errorf("Early secret byte %d not properly zeroed: %d", i, b)
		}
	}

	for i, b := range ks.handshakeSecret {
		if b != 0 {
			t.Errorf("Handshake secret byte %d not properly zeroed: %d", i, b)
		}
	}

	t.Log("Secure zero test passed")
}

func TestGoTLSKeyScheduleTranscript(t *testing.T) {
	ks, err := NewGoTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create key schedule: %v", err)
	}

	// Test transcript hash
	data1 := []byte("ClientHello")
	data2 := []byte("ServerHello")

	ks.UpdateTranscript(data1)
	ks.UpdateTranscript(data2)

	hash := ks.GetTranscriptHash()
	if len(hash) != 32 {
		t.Errorf("Transcript hash length: got %d, want 32", len(hash))
	}

	// Verify it matches direct SHA-256
	expected := sha256.New()
	expected.Write(data1)
	expected.Write(data2)
	expectedHash := expected.Sum(nil)

	if !bytes.Equal(hash, expectedHash) {
		t.Error("Transcript hash doesn't match expected SHA-256")
	}

	t.Log("Transcript test passed")
}

func TestGoTLSKeyScheduleErrorConditions(t *testing.T) {
	ks, err := NewGoTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create key schedule: %v", err)
	}

	// Test error cases
	sharedSecret := make([]byte, 32)

	// Try to derive handshake secret without early secret
	err = ks.DeriveHandshakeSecret(sharedSecret)
	if err == nil {
		t.Error("Expected error when deriving handshake secret without early secret")
	}

	// Try to derive traffic secrets without handshake secret
	err = ks.DeriveHandshakeTrafficSecrets()
	if err == nil {
		t.Error("Expected error when deriving traffic secrets without handshake secret")
	}

	// Try to get keys without deriving secrets
	_, _, _, _, err = ks.GetHandshakeTrafficKeys()
	if err == nil {
		t.Error("Expected error when getting keys without deriving secrets")
	}

	t.Log("Error condition tests passed")
}

func TestGoTLSKeyScheduleUnsupportedCipher(t *testing.T) {
	// Test unsupported cipher suite
	_, err := NewGoTLSKeySchedule(0x9999)
	if err == nil {
		t.Error("Expected error for unsupported cipher suite")
	}

	t.Log("Unsupported cipher test passed")
}
