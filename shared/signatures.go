package shared

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
)

// Single Session Mode: Cryptographic signing infrastructure

// SigningKeyPair represents a cryptographic ECDSA signing key pair
type SigningKeyPair struct {
	PrivateKey *ecdsa.PrivateKey `json:"private_key"`
	PublicKey  *ecdsa.PublicKey  `json:"public_key"`
}

// GenerateSigningKeyPair generates a new ECDSA signing key pair using P-256 curve
func GenerateSigningKeyPair() (*SigningKeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key pair: %v", err)
	}

	return &SigningKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// SignData signs the given data using ECDSA and returns the signature
func (kp *SigningKeyPair) SignData(data []byte) ([]byte, error) {
	// Hash the data with SHA-256
	hash := sha256.Sum256(data)

	// Sign the hash
	r, s, err := ecdsa.Sign(rand.Reader, kp.PrivateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %v", err)
	}

	// Encode r and s as a simple concatenation (32 bytes each for P-256)
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])

	return signature, nil
}

// VerifySignature verifies a signature against the given data using a public key
func VerifySignature(data []byte, signature []byte, publicKey *ecdsa.PublicKey) error {
	if len(signature) != 64 {
		return fmt.Errorf("invalid signature length: expected 64 bytes, got %d", len(signature))
	}

	// Hash the data with SHA-256
	hash := sha256.Sum256(data)

	// Extract r and s from signature
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	// Verify the signature
	if !ecdsa.Verify(publicKey, hash[:], r, s) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// VerifySignature method on SigningKeyPair
func (kp *SigningKeyPair) VerifySignature(data []byte, signature []byte) bool {
	err := VerifySignature(data, signature, kp.PublicKey)
	return err == nil
}

// GetPublicKeyDER returns the public key in DER format for JSON serialization
func (kp *SigningKeyPair) GetPublicKeyDER() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(kp.PublicKey)
}

// ParsePublicKeyFromDER parses a public key from DER format
func ParsePublicKeyFromDER(derBytes []byte) (*ecdsa.PublicKey, error) {
	pubKeyInterface, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER public key: %v", err)
	}

	ecdsaPubKey, ok := pubKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an ECDSA key")
	}

	return ecdsaPubKey, nil
}

// VerifySignatureWithDER verifies a signature using a public key in DER format
func VerifySignatureWithDER(data []byte, signature []byte, publicKeyDER []byte) error {
	// Parse public key from DER
	pubKey, err := ParsePublicKeyFromDER(publicKeyDER)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	// Verify signature
	return VerifySignature(data, signature, pubKey)
}

// VerifyTranscriptSignature verifies a signed transcript's signature
func VerifyTranscriptSignature(transcript *SignedTranscript) error {
	// Reconstruct the original data that was signed (TLS packets only)
	var buffer bytes.Buffer

	// Write each TLS packet to buffer
	for _, packet := range transcript.Packets {
		buffer.Write(packet)
	}

	originalData := buffer.Bytes()

	// Verify signature using the public key
	return VerifySignatureWithDER(originalData, transcript.Signature, transcript.PublicKey)
}

// VerifyComprehensiveSignature verifies TEE_K's comprehensive signature over all data
func VerifyComprehensiveSignature(transcript *SignedTranscript, redactedStreams []SignedRedactedDecryptionStream) error {
	if transcript == nil {
		return fmt.Errorf("transcript is nil")
	}

	if len(transcript.Signature) == 0 {
		return fmt.Errorf("signature is empty")
	}

	// Reconstruct the original data that was signed
	var buffer bytes.Buffer

	// Add request metadata
	if transcript.RequestMetadata != nil {
		buffer.Write(transcript.RequestMetadata.RedactedRequest)
		buffer.Write(transcript.RequestMetadata.CommSP)

		// Include redaction ranges in signature verification (same as signing)
		if len(transcript.RequestMetadata.RedactionRanges) > 0 {
			redactionRangesBytes, err := json.Marshal(transcript.RequestMetadata.RedactionRanges)
			if err != nil {
				return fmt.Errorf("failed to marshal redaction ranges for verification: %v", err)
			}
			buffer.Write(redactionRangesBytes)
		}
	}

	// Add concatenated redacted streams
	for _, stream := range redactedStreams {
		buffer.Write(stream.RedactedStream)
	}

	// Add TLS packets
	for _, packet := range transcript.Packets {
		buffer.Write(packet)
	}

	originalData := buffer.Bytes()

	// Verify signature using the public key
	return VerifySignatureWithDER(originalData, transcript.Signature, transcript.PublicKey)
}

// SignTranscript signs a transcript of packets and returns the signature
func (kp *SigningKeyPair) SignTranscript(packets [][]byte) ([]byte, error) {
	// Concatenate all packets for signing
	var allData []byte
	for _, packet := range packets {
		allData = append(allData, packet...)
	}

	return kp.SignData(allData)
}
