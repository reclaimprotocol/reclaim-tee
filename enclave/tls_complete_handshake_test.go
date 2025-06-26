package enclave

import (
	"encoding/hex"
	"testing"
)

// TestTLS13CompleteHandshakeWithFinished tests the complete TLS 1.3 handshake flow
// including Finished message generation and verification using Go's internal TLS approach
func TestTLS13CompleteHandshakeWithFinished(t *testing.T) {
	t.Logf("Starting complete TLS 1.3 handshake with Finished messages")

	// Step 1: Create TLS client configuration
	config := &TLSClientConfig{
		ServerName:    "complete.example.com",
		ALPNProtocols: []string{"h2", "http/1.1"},
		MaxVersion:    VersionTLS13,
	}

	// Step 2: Initialize TLS client state
	client, err := NewTLSClientState(config)
	if err != nil {
		t.Fatalf("Failed to create TLS client state: %v", err)
	}

	t.Logf("Step 1: TLS client state initialized")

	// Step 3: Generate Client Hello
	clientHello, err := client.GenerateClientHello()
	if err != nil {
		t.Fatalf("Failed to generate Client Hello: %v", err)
	}

	t.Logf("Step 2: Generated Client Hello (%d bytes)", len(clientHello))

	// Step 4: Process Server Hello
	serverHelloRecord := createMockServerHelloMessage(TLS_AES_128_GCM_SHA256, X25519)
	err = client.ProcessServerHello(serverHelloRecord)
	if err != nil {
		t.Fatalf("Failed to process Server Hello: %v", err)
	}

	t.Logf("Step 3: Processed Server Hello successfully")

	// Step 5: Create key schedule using Go's TLS 1.3 implementation
	keySchedule, err := NewGoTLSKeySchedule(TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatalf("Failed to create key schedule: %v", err)
	}

	// Step 6: Perform ECDH and derive handshake secrets
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

	t.Logf("Step 4: Derived handshake secrets from ECDH")

	// Step 7: Derive application secrets
	err = keySchedule.DeriveMasterSecret()
	if err != nil {
		t.Fatalf("Failed to derive master secret: %v", err)
	}

	err = keySchedule.DeriveApplicationTrafficSecrets()
	if err != nil {
		t.Fatalf("Failed to derive application traffic secrets: %v", err)
	}

	t.Logf("Step 5: Derived application traffic secrets")

	// Step 8: Generate client Finished message
	clientFinished, err := client.GenerateClientFinished(keySchedule)
	if err != nil {
		t.Fatalf("Failed to generate client finished: %v", err)
	}

	t.Logf("Step 6: Generated client Finished message (%d bytes)", len(clientFinished))

	// Step 9: Verify server Finished message (mock)
	// In a real implementation, this would come from the server
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

	t.Logf("Step 7: Verified server Finished message")

	// Step 10: Complete handshake
	err = client.CompleteHandshake(keySchedule)
	if err != nil {
		t.Fatalf("Failed to complete handshake: %v", err)
	}

	t.Logf("Step 8: Handshake completed successfully")

	// Step 11: Extract session keys for TEE MPC operations
	sessionKeys, err := client.ExtractSessionKeys()
	if err != nil {
		t.Fatalf("Failed to extract session keys: %v", err)
	}

	// Verify session keys are properly extracted
	if len(sessionKeys.ClientWriteKey) != 16 {
		t.Errorf("Expected 16-byte client write key, got %d", len(sessionKeys.ClientWriteKey))
	}

	if len(sessionKeys.ServerWriteKey) != 16 {
		t.Errorf("Expected 16-byte server write key, got %d", len(sessionKeys.ServerWriteKey))
	}

	if len(sessionKeys.ClientWriteIV) != 12 {
		t.Errorf("Expected 12-byte client write IV, got %d", len(sessionKeys.ClientWriteIV))
	}

	if len(sessionKeys.ServerWriteIV) != 12 {
		t.Errorf("Expected 12-byte server write IV, got %d", len(sessionKeys.ServerWriteIV))
	}

	if sessionKeys.CipherSuite != TLS_AES_128_GCM_SHA256 {
		t.Errorf("Expected cipher suite 0x%04x, got 0x%04x",
			TLS_AES_128_GCM_SHA256, sessionKeys.CipherSuite)
	}

	t.Logf("Step 9: Session keys extracted successfully")

	// Log the results
	t.Logf("")
	t.Logf("TLS 1.3 Handshake Summary:")
	t.Logf("   Cipher Suite: 0x%04x (AES-128-GCM-SHA256)", sessionKeys.CipherSuite)
	t.Logf("   Key Exchange: X25519 ECDH")
	t.Logf("   Client Finished: %s", hex.EncodeToString(clientFinished[4:12])+"...")
	t.Logf("   Client Write Key: %s", hex.EncodeToString(sessionKeys.ClientWriteKey[:8])+"...")
	t.Logf("   Server Write Key: %s", hex.EncodeToString(sessionKeys.ServerWriteKey[:8])+"...")
	t.Logf("   Client Write IV:  %s", hex.EncodeToString(sessionKeys.ClientWriteIV[:8])+"...")
	t.Logf("   Server Write IV:  %s", hex.EncodeToString(sessionKeys.ServerWriteIV[:8])+"...")
	t.Logf("")
	t.Logf("COMPLETE TLS 1.3 HANDSHAKE WITH FINISHED MESSAGES SUCCESSFUL!")
	t.Logf("Session keys ready for TEE MPC split AEAD operations")
}

// TestTLS13HandshakeWithDifferentCipherSuites tests the complete handshake with all supported cipher suites
func TestTLS13HandshakeWithDifferentCipherSuites(t *testing.T) {
	cipherSuites := []struct {
		name      string
		cipherID  uint16
		keyGroup  CurveID
		keyLength int
		ivLength  int
	}{
		{"AES-128-GCM + X25519", TLS_AES_128_GCM_SHA256, X25519, 16, 12},
		{"AES-256-GCM + P-256", TLS_AES_256_GCM_SHA384, CurveP256, 32, 12},
		{"ChaCha20-Poly1305 + X25519", TLS_CHACHA20_POLY1305_SHA256, X25519, 32, 12},
	}

	for _, cs := range cipherSuites {
		t.Run(cs.name, func(t *testing.T) {
			config := &TLSClientConfig{
				ServerName: "multi-cipher.example.com",
				MaxVersion: VersionTLS13,
			}

			client, err := NewTLSClientState(config)
			if err != nil {
				t.Fatalf("Failed to create TLS client: %v", err)
			}

			// Complete handshake flow
			_, err = client.GenerateClientHello()
			if err != nil {
				t.Fatalf("Failed to generate Client Hello: %v", err)
			}

			serverHelloRecord := createMockServerHelloMessage(cs.cipherID, cs.keyGroup)
			err = client.ProcessServerHello(serverHelloRecord)
			if err != nil {
				t.Fatalf("Failed to process Server Hello: %v", err)
			}

			keySchedule, err := NewGoTLSKeySchedule(cs.cipherID)
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

			// Generate and verify Finished messages
			clientFinished, err := client.GenerateClientFinished(keySchedule)
			if err != nil {
				t.Fatalf("Failed to generate client finished: %v", err)
			}

			// Mock server finished verification
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

			// Extract session keys
			sessionKeys, err := client.ExtractSessionKeys()
			if err != nil {
				t.Fatalf("Failed to extract session keys: %v", err)
			}

			// Verify key lengths
			if len(sessionKeys.ClientWriteKey) != cs.keyLength {
				t.Errorf("Expected %d-byte client key, got %d", cs.keyLength, len(sessionKeys.ClientWriteKey))
			}

			if len(sessionKeys.ServerWriteKey) != cs.keyLength {
				t.Errorf("Expected %d-byte server key, got %d", cs.keyLength, len(sessionKeys.ServerWriteKey))
			}

			if len(sessionKeys.ClientWriteIV) != cs.ivLength {
				t.Errorf("Expected %d-byte client IV, got %d", cs.ivLength, len(sessionKeys.ClientWriteIV))
			}

			if len(sessionKeys.ServerWriteIV) != cs.ivLength {
				t.Errorf("Expected %d-byte server IV, got %d", cs.ivLength, len(sessionKeys.ServerWriteIV))
			}

			t.Logf("%s handshake completed successfully", cs.name)
			t.Logf("   Client finished: %s", hex.EncodeToString(clientFinished[4:12])+"...")
			t.Logf("   Session keys: %d-byte keys, %d-byte IVs", cs.keyLength, cs.ivLength)
		})
	}
}

// TestTLS13HandshakeTranscriptIntegrity verifies the handshake transcript is correctly maintained
func TestTLS13HandshakeTranscriptIntegrity(t *testing.T) {
	config := &TLSClientConfig{
		ServerName: "transcript.example.com",
		MaxVersion: VersionTLS13,
	}

	client, err := NewTLSClientState(config)
	if err != nil {
		t.Fatalf("Failed to create TLS client: %v", err)
	}

	// Track transcript at each step
	initialTranscript := client.GetHandshakeTranscript()
	if len(initialTranscript) != 32 { // SHA-256 empty hash
		t.Errorf("Expected 32-byte initial transcript, got %d", len(initialTranscript))
	}

	// After Client Hello
	_, err = client.GenerateClientHello()
	if err != nil {
		t.Fatalf("Failed to generate Client Hello: %v", err)
	}

	afterClientHello := client.GetHandshakeTranscript()
	if len(afterClientHello) != 32 {
		t.Errorf("Expected 32-byte transcript after Client Hello, got %d", len(afterClientHello))
	}

	// After Server Hello
	serverHelloRecord := createMockServerHelloMessage(TLS_AES_128_GCM_SHA256, X25519)
	err = client.ProcessServerHello(serverHelloRecord)
	if err != nil {
		t.Fatalf("Failed to process Server Hello: %v", err)
	}

	afterServerHello := client.GetHandshakeTranscript()
	if len(afterServerHello) != 32 {
		t.Errorf("Expected 32-byte transcript after Server Hello, got %d", len(afterServerHello))
	}

	// Transcript should change at each step
	if hex.EncodeToString(initialTranscript) == hex.EncodeToString(afterClientHello) {
		t.Error("Transcript should change after Client Hello")
	}

	if hex.EncodeToString(afterClientHello) == hex.EncodeToString(afterServerHello) {
		t.Error("Transcript should change after Server Hello")
	}

	t.Logf("Handshake transcript integrity verified")
	t.Logf("   Initial:      %s", hex.EncodeToString(initialTranscript[:8])+"...")
	t.Logf("   After CH:     %s", hex.EncodeToString(afterClientHello[:8])+"...")
	t.Logf("   After SH:     %s", hex.EncodeToString(afterServerHello[:8])+"...")
}
