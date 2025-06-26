package enclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

func TestNewTranscriptSigner(t *testing.T) {
	t.Run("RSA Private Key", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		signer, err := NewTranscriptSigner(rsaKey)
		if err != nil {
			t.Fatalf("Failed to create transcript signer: %v", err)
		}

		if signer.algorithm != "RSA-PSS" {
			t.Errorf("Expected RSA-PSS algorithm, got %s", signer.algorithm)
		}

		if signer.GetAlgorithm() != "RSA-PSS" {
			t.Errorf("Expected RSA-PSS algorithm from getter, got %s", signer.GetAlgorithm())
		}
	})

	t.Run("ECDSA Private Key", func(t *testing.T) {
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		signer, err := NewTranscriptSigner(ecdsaKey)
		if err != nil {
			t.Fatalf("Failed to create transcript signer: %v", err)
		}

		if signer.algorithm != "ECDSA" {
			t.Errorf("Expected ECDSA algorithm, got %s", signer.algorithm)
		}
	})

	t.Run("Nil Key (Demo Mode)", func(t *testing.T) {
		signer, err := NewTranscriptSigner(nil)
		if err != nil {
			t.Fatalf("Failed to create transcript signer: %v", err)
		}

		if signer.algorithm != "RSA-PSS" {
			t.Errorf("Expected RSA-PSS algorithm for demo mode, got %s", signer.algorithm)
		}

		// Verify the public key is accessible
		publicKey := signer.GetPublicKey()
		if publicKey == nil {
			t.Error("Public key should not be nil")
		}
	})

	t.Run("Unsupported Key Type", func(t *testing.T) {
		_, err := NewTranscriptSigner("invalid_key")
		if err == nil {
			t.Error("Expected error for unsupported key type")
		}
	})
}

func TestGenerateDemoKey(t *testing.T) {
	signer, err := GenerateDemoKey()
	if err != nil {
		t.Fatalf("Failed to generate demo key: %v", err)
	}

	if signer.algorithm != "ECDSA" {
		t.Errorf("Expected ECDSA algorithm for demo key, got %s", signer.algorithm)
	}

	// Verify we can get the public key
	publicKey := signer.GetPublicKey()
	if publicKey == nil {
		t.Error("Public key should not be nil")
	}

	// Verify it's actually an ECDSA public key
	if _, ok := publicKey.(*ecdsa.PublicKey); !ok {
		t.Error("Expected ECDSA public key")
	}
}

func TestSignRequestTranscript(t *testing.T) {
	signer, err := GenerateDemoKey()
	if err != nil {
		t.Fatalf("Failed to generate demo key: %v", err)
	}

	sessionID := "test-session-123"
	requests := [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		[]byte("POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello"),
	}
	commitments := map[string][]byte{
		"commitment_sp": []byte("test_commitment_data"),
	}

	signedTranscript, err := signer.SignRequestTranscript(sessionID, requests, commitments)
	if err != nil {
		t.Fatalf("Failed to sign request transcript: %v", err)
	}

	// Verify the structure
	if signedTranscript.Data.SessionID != sessionID {
		t.Errorf("Expected session ID %s, got %s", sessionID, signedTranscript.Data.SessionID)
	}

	if signedTranscript.Data.Type != "request" {
		t.Errorf("Expected type 'request', got %s", signedTranscript.Data.Type)
	}

	if signedTranscript.Algorithm != "ECDSA" {
		t.Errorf("Expected ECDSA algorithm, got %s", signedTranscript.Algorithm)
	}

	// Verify metadata
	if signedTranscript.Data.Metadata["request_count"] != 2 {
		t.Errorf("Expected request count 2, got %v", signedTranscript.Data.Metadata["request_count"])
	}

	// Verify the concatenated data
	expectedData := append(requests[0], requests[1]...)
	if len(signedTranscript.Data.Data) != len(expectedData) {
		t.Errorf("Expected data length %d, got %d", len(expectedData), len(signedTranscript.Data.Data))
	}

	// Verify commitments
	if len(signedTranscript.Data.Commitments) != 1 {
		t.Errorf("Expected 1 commitment, got %d", len(signedTranscript.Data.Commitments))
	}
}

func TestSignResponseTranscript(t *testing.T) {
	signer, err := GenerateDemoKey()
	if err != nil {
		t.Fatalf("Failed to generate demo key: %v", err)
	}

	sessionID := "test-session-456"
	responses := [][]byte{
		[]byte("encrypted_response_1"),
		[]byte("encrypted_response_2"),
		[]byte("encrypted_response_3"),
	}

	signedTranscript, err := signer.SignResponseTranscript(sessionID, responses)
	if err != nil {
		t.Fatalf("Failed to sign response transcript: %v", err)
	}

	// Verify the structure
	if signedTranscript.Data.SessionID != sessionID {
		t.Errorf("Expected session ID %s, got %s", sessionID, signedTranscript.Data.SessionID)
	}

	if signedTranscript.Data.Type != "response" {
		t.Errorf("Expected type 'response', got %s", signedTranscript.Data.Type)
	}

	if signedTranscript.Algorithm != "ECDSA" {
		t.Errorf("Expected ECDSA algorithm, got %s", signedTranscript.Algorithm)
	}

	// Verify metadata
	if signedTranscript.Data.Metadata["response_count"] != 3 {
		t.Errorf("Expected response count 3, got %v", signedTranscript.Data.Metadata["response_count"])
	}

	// Verify the concatenated data
	expectedData := append(append(responses[0], responses[1]...), responses[2]...)
	if len(signedTranscript.Data.Data) != len(expectedData) {
		t.Errorf("Expected data length %d, got %d", len(expectedData), len(signedTranscript.Data.Data))
	}
}

func TestVerifyTranscript(t *testing.T) {
	signer, err := GenerateDemoKey()
	if err != nil {
		t.Fatalf("Failed to generate demo key: %v", err)
	}

	sessionID := "test-session-verify"
	requests := [][]byte{
		[]byte("test_request_data"),
	}
	commitments := map[string][]byte{
		"commitment_sp": []byte("test_commitment"),
	}

	// Sign a transcript
	signedTranscript, err := signer.SignRequestTranscript(sessionID, requests, commitments)
	if err != nil {
		t.Fatalf("Failed to sign transcript: %v", err)
	}

	// Verify it
	err = VerifyTranscript(signedTranscript)
	if err != nil {
		t.Fatalf("Failed to verify valid transcript: %v", err)
	}

	t.Log("Valid transcript verification passed")

	// Test with corrupted signature
	corruptedTranscript := *signedTranscript
	corruptedTranscript.Signature = []byte("corrupted_signature")

	err = VerifyTranscript(&corruptedTranscript)
	if err == nil {
		t.Error("Expected verification to fail for corrupted signature")
	}

	t.Log("Corrupted signature verification correctly failed")

	// Test with corrupted data
	corruptedDataTranscript := *signedTranscript
	corruptedDataTranscript.Data = &TranscriptData{
		SessionID: "different_session",
		Timestamp: time.Now(),
		Type:      "request",
		Data:      []byte("corrupted_data"),
	}

	err = VerifyTranscript(&corruptedDataTranscript)
	if err == nil {
		t.Error("Expected verification to fail for corrupted data")
	}

	t.Log("Corrupted data verification correctly failed")
}

func TestTranscriptBuilders(t *testing.T) {
	t.Run("RequestTranscriptBuilder", func(t *testing.T) {
		sessionID := "test-session-builder"
		builder := NewRequestTranscriptBuilder(sessionID)

		// Add some requests
		builder.AddRequest([]byte("request1"))
		builder.AddRequest([]byte("request2"))

		// Add commitments
		builder.AddCommitment("commitment_s", []byte("commit_s_data"))
		builder.AddCommitment("commitment_sp", []byte("commit_sp_data"))

		// Sign the transcript
		signer, err := GenerateDemoKey()
		if err != nil {
			t.Fatalf("Failed to generate demo key: %v", err)
		}

		signedTranscript, err := builder.Sign(signer)
		if err != nil {
			t.Fatalf("Failed to sign transcript: %v", err)
		}

		// Verify the result
		if signedTranscript.Data.SessionID != sessionID {
			t.Errorf("Expected session ID %s, got %s", sessionID, signedTranscript.Data.SessionID)
		}

		if len(signedTranscript.Data.Commitments) != 2 {
			t.Errorf("Expected 2 commitments, got %d", len(signedTranscript.Data.Commitments))
		}

		expectedData := append([]byte("request1"), []byte("request2")...)
		if len(signedTranscript.Data.Data) != len(expectedData) {
			t.Errorf("Expected data length %d, got %d", len(expectedData), len(signedTranscript.Data.Data))
		}
	})

	t.Run("ResponseTranscriptBuilder", func(t *testing.T) {
		sessionID := "test-session-response-builder"
		builder := NewResponseTranscriptBuilder(sessionID)

		// Add some responses
		builder.AddEncryptedResponse([]byte("encrypted_response1"))
		builder.AddEncryptedResponse([]byte("encrypted_response2"))
		builder.AddEncryptedResponse([]byte("encrypted_response3"))

		// Sign the transcript
		signer, err := GenerateDemoKey()
		if err != nil {
			t.Fatalf("Failed to generate demo key: %v", err)
		}

		signedTranscript, err := builder.Sign(signer)
		if err != nil {
			t.Fatalf("Failed to sign transcript: %v", err)
		}

		// Verify the result
		if signedTranscript.Data.SessionID != sessionID {
			t.Errorf("Expected session ID %s, got %s", sessionID, signedTranscript.Data.SessionID)
		}

		if signedTranscript.Data.Type != "response" {
			t.Errorf("Expected type 'response', got %s", signedTranscript.Data.Type)
		}

		expectedData := append(append([]byte("encrypted_response1"), []byte("encrypted_response2")...), []byte("encrypted_response3")...)
		if len(signedTranscript.Data.Data) != len(expectedData) {
			t.Errorf("Expected data length %d, got %d", len(expectedData), len(signedTranscript.Data.Data))
		}
	})
}

func TestNewTranscriptSignerFromCertificate(t *testing.T) {
	// Generate a test certificate and private key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create a simple certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	t.Run("Valid Certificate and Key", func(t *testing.T) {
		signer, err := NewTranscriptSignerFromCertificate(cert, rsaKey)
		if err != nil {
			t.Fatalf("Failed to create signer from certificate: %v", err)
		}

		if signer.algorithm != "RSA-PSS" {
			t.Errorf("Expected RSA-PSS algorithm, got %s", signer.algorithm)
		}
	})

	t.Run("Nil Private Key", func(t *testing.T) {
		_, err := NewTranscriptSignerFromCertificate(cert, nil)
		if err == nil {
			t.Error("Expected error for nil private key")
		}
	})

	t.Run("Mismatched Key", func(t *testing.T) {
		differentKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate different RSA key: %v", err)
		}

		_, err = NewTranscriptSignerFromCertificate(cert, differentKey)
		if err == nil {
			t.Error("Expected error for mismatched private key")
		}
	})
}

func TestTranscriptSerialization(t *testing.T) {
	signer, err := GenerateDemoKey()
	if err != nil {
		t.Fatalf("Failed to generate demo key: %v", err)
	}

	sessionID := "test-session-serialization"
	requests := [][]byte{
		[]byte("serialization_test_request"),
	}

	signedTranscript, err := signer.SignRequestTranscript(sessionID, requests, nil)
	if err != nil {
		t.Fatalf("Failed to sign transcript: %v", err)
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(signedTranscript)
	if err != nil {
		t.Fatalf("Failed to marshal transcript to JSON: %v", err)
	}

	t.Logf("Serialized transcript: %d bytes", len(jsonData))

	// Deserialize from JSON
	var deserializedTranscript SignedTranscript
	err = json.Unmarshal(jsonData, &deserializedTranscript)
	if err != nil {
		t.Fatalf("Failed to unmarshal transcript from JSON: %v", err)
	}

	// Verify the deserialized transcript
	err = VerifyTranscript(&deserializedTranscript)
	if err != nil {
		t.Fatalf("Failed to verify deserialized transcript: %v", err)
	}

	t.Log("Transcript serialization and deserialization successful")
}

func TestRSASigningFlow(t *testing.T) {
	// Test with RSA keys specifically
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	signer, err := NewTranscriptSigner(rsaKey)
	if err != nil {
		t.Fatalf("Failed to create RSA transcript signer: %v", err)
	}

	sessionID := "test-rsa-session"
	requests := [][]byte{
		[]byte("RSA signing test request"),
	}

	signedTranscript, err := signer.SignRequestTranscript(sessionID, requests, nil)
	if err != nil {
		t.Fatalf("Failed to sign transcript with RSA: %v", err)
	}

	if signedTranscript.Algorithm != "RSA-PSS" {
		t.Errorf("Expected RSA-PSS algorithm, got %s", signedTranscript.Algorithm)
	}

	// Verify the transcript
	err = VerifyTranscript(signedTranscript)
	if err != nil {
		t.Fatalf("Failed to verify RSA-signed transcript: %v", err)
	}

	t.Log("RSA signing flow completed successfully")
}
