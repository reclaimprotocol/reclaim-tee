package shared

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"math/big"
	teeproto "tee-mpc/proto"

	"google.golang.org/protobuf/proto"
)

// Single Session Mode: Cryptographic signing infrastructure

// Simple protobuf marshaling functions for internal transcript storage
// (These are NOT used for signing - only for storing/loading transcript data)

// MarshalRequestRedactionRangesProtobuf marshals request redaction ranges for transcript storage
func MarshalRequestRedactionRangesProtobuf(ranges []RequestRedactionRange) ([]byte, error) {
	if len(ranges) == 0 {
		return nil, nil
	}

	var pbRanges []*teeproto.RequestRedactionRange
	for _, r := range ranges {
		pbRanges = append(pbRanges, &teeproto.RequestRedactionRange{
			Start:          int32(r.Start),
			Length:         int32(r.Length),
			Type:           r.Type,
			RedactionBytes: r.RedactionBytes,
		})
	}

	wrapper := &teeproto.RedactedRequest{RedactionRanges: pbRanges}
	return proto.Marshal(wrapper)
}

// UnmarshalRequestRedactionRangesProtobuf unmarshals request redaction ranges from transcript storage
func UnmarshalRequestRedactionRangesProtobuf(data []byte) ([]RequestRedactionRange, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var wrapper teeproto.RedactedRequest
	if err := proto.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to unmarshal protobuf wrapper: %v", err)
	}

	if len(wrapper.RedactionRanges) == 0 {
		return nil, nil
	}

	ranges := make([]RequestRedactionRange, len(wrapper.RedactionRanges))
	for i, pbRange := range wrapper.RedactionRanges {
		ranges[i] = RequestRedactionRange{
			Start:          int(pbRange.Start),
			Length:         int(pbRange.Length),
			Type:           pbRange.Type,
			RedactionBytes: pbRange.RedactionBytes,
		}
	}

	return ranges, nil
}

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

// REMOVED: VerifyComprehensiveSignature and SignTranscript - obsolete functions
// SignedMessage verification is now done directly against protobuf bodies
