package clientlib

import (
	"testing"

	teeproto "tee-mpc/proto"
	"tee-mpc/proto/attestor"

	"google.golang.org/protobuf/proto"
)

func TestReconstructTranscriptForClaimTunnel(t *testing.T) {
	// Create a minimal test bundle
	bundle := &teeproto.VerificationBundlePB{
		TeekSigned: &teeproto.SignedMessage{
			Body: createTestKOutput(),
		},
		TeetSigned: &teeproto.SignedMessage{
			Body: createTestTOutput(),
		},
		Opening: &teeproto.Opening{
			ProofStream: []byte("test-proof-stream"),
		},
		HandshakeKeys: &teeproto.HandshakeSecrets{
			HandshakeKey: []byte("test-key"),
			HandshakeIv:  []byte("test-iv"),
		},
	}

	// Test reconstruction
	transcript, err := ReconstructTranscriptForClaimTunnel(bundle)
	if err != nil {
		t.Fatalf("ReconstructTranscriptForClaimTunnel failed: %v", err)
	}

	// Verify we got some transcript messages
	if len(transcript) == 0 {
		t.Error("Expected non-empty transcript")
	}

	// Verify transcript messages have correct structure
	for i, msg := range transcript {
		if msg.Sender == attestor.TranscriptMessageSenderType_TRANSCRIPT_MESSAGE_SENDER_TYPE_UNKNOWN {
			t.Errorf("Message %d has unknown sender type", i)
		}
		if len(msg.Message) == 0 {
			t.Errorf("Message %d has empty message", i)
		}
	}
}

func TestExtractHostFromBundle(t *testing.T) {
	// Create a test bundle
	bundle := &teeproto.VerificationBundlePB{
		TeekSigned: &teeproto.SignedMessage{
			Body: createTestKOutput(),
		},
	}

	// Test host extraction
	host := ExtractHostFromBundle(bundle)
	if host == "" {
		t.Error("Expected non-empty host")
	}
}

// Helper function to create test K output
func createTestKOutput() []byte {
	kPayload := &teeproto.KOutputPayload{
		RedactedRequest: []byte("GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		Packets: [][]byte{
			{0x16, 0x03, 0x03, 0x00, 0x10, 0x01, 0x00, 0x00, 0x0C}, // ClientHello
			{0x16, 0x03, 0x03, 0x00, 0x10, 0x02, 0x00, 0x00, 0x0C}, // ServerHello
		},
		RequestRedactionRanges: []*teeproto.RequestRedactionRange{
			{
				Start:  4,
				Length: 8,
				Type:   "sensitive_proof",
			},
		},
		RedactedStreams: []*teeproto.SignedRedactedDecryptionStream{
			{
				SeqNum:         1,
				RedactedStream: []byte("test-redacted-stream"),
			},
		},
	}

	// Simple marshal - ignore errors for test
	data, _ := proto.Marshal(kPayload)
	return data
}

// Helper function to create test T output
func createTestTOutput() []byte {
	tPayload := &teeproto.TOutputPayload{
		Packets: [][]byte{
			{0x17, 0x03, 0x03, 0x00, 0x20}, // ApplicationData header
		},
	}

	// Simple marshal - ignore errors for test
	data, _ := proto.Marshal(tPayload)
	return data
}
