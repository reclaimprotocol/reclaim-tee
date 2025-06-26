package enclave

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// TranscriptSigner handles signing of request and response transcripts
type TranscriptSigner struct {
	privateKey interface{} // *rsa.PrivateKey or *ecdsa.PrivateKey
	publicKey  interface{} // *rsa.PublicKey or *ecdsa.PublicKey
	algorithm  string      // "RSA-PSS" or "ECDSA"
}

// TranscriptData represents the data structure to be signed
type TranscriptData struct {
	SessionID   string                 `json:"session_id"`
	Timestamp   time.Time              `json:"timestamp"`
	Type        string                 `json:"type"` // "request" or "response"
	Data        []byte                 `json:"data"`
	Commitments map[string][]byte      `json:"commitments,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// SignedTranscript represents a signed transcript
type SignedTranscript struct {
	Data      *TranscriptData `json:"data"`
	Signature []byte          `json:"signature"`
	Algorithm string          `json:"algorithm"`
	PublicKey []byte          `json:"public_key"`
}

// NewTranscriptSigner creates a new transcript signer
// If privateKey is nil, generates a new random key for demo purposes
func NewTranscriptSigner(privateKey interface{}) (*TranscriptSigner, error) {
	var signer *TranscriptSigner

	if privateKey == nil {
		// Generate random key for demo
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate demo RSA key: %v", err)
		}
		signer = &TranscriptSigner{
			privateKey: rsaKey,
			publicKey:  &rsaKey.PublicKey,
			algorithm:  "RSA-PSS",
		}
	} else {
		switch key := privateKey.(type) {
		case *rsa.PrivateKey:
			signer = &TranscriptSigner{
				privateKey: key,
				publicKey:  &key.PublicKey,
				algorithm:  "RSA-PSS",
			}
		case *ecdsa.PrivateKey:
			signer = &TranscriptSigner{
				privateKey: key,
				publicKey:  &key.PublicKey,
				algorithm:  "ECDSA",
			}
		default:
			return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
		}
	}

	return signer, nil
}

// NewTranscriptSignerFromCertificate creates a signer from a certificate's private key
func NewTranscriptSignerFromCertificate(cert *x509.Certificate, privateKey interface{}) (*TranscriptSigner, error) {
	if privateKey == nil {
		return nil, errors.New("private key is required")
	}

	// Verify the private key matches the certificate
	switch certPubKey := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if rsaPrivKey, ok := privateKey.(*rsa.PrivateKey); ok {
			if certPubKey.N.Cmp(rsaPrivKey.N) != 0 || certPubKey.E != rsaPrivKey.E {
				return nil, errors.New("private key does not match certificate")
			}
			return &TranscriptSigner{
				privateKey: rsaPrivKey,
				publicKey:  certPubKey,
				algorithm:  "RSA-PSS",
			}, nil
		}
	case *ecdsa.PublicKey:
		if ecdsaPrivKey, ok := privateKey.(*ecdsa.PrivateKey); ok {
			if certPubKey.X.Cmp(ecdsaPrivKey.X) != 0 || certPubKey.Y.Cmp(ecdsaPrivKey.Y) != 0 {
				return nil, errors.New("private key does not match certificate")
			}
			return &TranscriptSigner{
				privateKey: ecdsaPrivKey,
				publicKey:  certPubKey,
				algorithm:  "ECDSA",
			}, nil
		}
	}

	return nil, fmt.Errorf("unsupported key type or key mismatch")
}

// SignRequestTranscript signs a request transcript according to the TEE+MPC protocol
func (ts *TranscriptSigner) SignRequestTranscript(sessionID string, requests [][]byte, commitments map[string][]byte) (*SignedTranscript, error) {
	// Concatenate all redacted requests as specified in the protocol
	var concatenatedRequests []byte
	for _, request := range requests {
		concatenatedRequests = append(concatenatedRequests, request...)
	}

	transcriptData := &TranscriptData{
		SessionID:   sessionID,
		Timestamp:   time.Now().UTC(),
		Type:        "request",
		Data:        concatenatedRequests,
		Commitments: commitments,
		Metadata: map[string]interface{}{
			"request_count": len(requests),
			"total_size":    len(concatenatedRequests),
		},
	}

	return ts.signTranscript(transcriptData)
}

// SignResponseTranscript signs a response transcript according to the TEE+MPC protocol
func (ts *TranscriptSigner) SignResponseTranscript(sessionID string, encryptedResponses [][]byte) (*SignedTranscript, error) {
	// Concatenate all encrypted ciphertexts as specified in the protocol
	var concatenatedResponses []byte
	for _, response := range encryptedResponses {
		concatenatedResponses = append(concatenatedResponses, response...)
	}

	transcriptData := &TranscriptData{
		SessionID: sessionID,
		Timestamp: time.Now().UTC(),
		Type:      "response",
		Data:      concatenatedResponses,
		Metadata: map[string]interface{}{
			"response_count": len(encryptedResponses),
			"total_size":     len(concatenatedResponses),
		},
	}

	return ts.signTranscript(transcriptData)
}

// signTranscript performs the actual signing of transcript data
func (ts *TranscriptSigner) signTranscript(data *TranscriptData) (*SignedTranscript, error) {
	// Serialize the transcript data
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transcript data: %v", err)
	}

	// Hash the data
	hash := sha256.Sum256(jsonData)

	// Sign the hash
	var signature []byte
	switch ts.algorithm {
	case "RSA-PSS":
		rsaKey := ts.privateKey.(*rsa.PrivateKey)
		signature, err = rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, hash[:], nil)
		if err != nil {
			return nil, fmt.Errorf("failed to sign with RSA-PSS: %v", err)
		}
	case "ECDSA":
		ecdsaKey := ts.privateKey.(*ecdsa.PrivateKey)
		signature, err = ecdsa.SignASN1(rand.Reader, ecdsaKey, hash[:])
		if err != nil {
			return nil, fmt.Errorf("failed to sign with ECDSA: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported signing algorithm: %s", ts.algorithm)
	}

	// Serialize the public key
	var publicKeyBytes []byte
	switch ts.algorithm {
	case "RSA-PSS":
		publicKeyBytes, err = x509.MarshalPKIXPublicKey(ts.publicKey)
	case "ECDSA":
		publicKeyBytes, err = x509.MarshalPKIXPublicKey(ts.publicKey)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}

	return &SignedTranscript{
		Data:      data,
		Signature: signature,
		Algorithm: ts.algorithm,
		PublicKey: publicKeyBytes,
	}, nil
}

// VerifyTranscript verifies a signed transcript
func VerifyTranscript(signedTranscript *SignedTranscript) error {
	// Serialize the transcript data
	jsonData, err := json.Marshal(signedTranscript.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal transcript data: %v", err)
	}

	// Hash the data
	hash := sha256.Sum256(jsonData)

	// Parse the public key
	publicKey, err := x509.ParsePKIXPublicKey(signedTranscript.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	// Verify the signature
	switch signedTranscript.Algorithm {
	case "RSA-PSS":
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("public key is not RSA for RSA-PSS algorithm")
		}
		err = rsa.VerifyPSS(rsaKey, crypto.SHA256, hash[:], signedTranscript.Signature, nil)
		if err != nil {
			return fmt.Errorf("RSA-PSS signature verification failed: %v", err)
		}
	case "ECDSA":
		ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("public key is not ECDSA for ECDSA algorithm")
		}
		if !ecdsa.VerifyASN1(ecdsaKey, hash[:], signedTranscript.Signature) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
	default:
		return fmt.Errorf("unsupported verification algorithm: %s", signedTranscript.Algorithm)
	}

	return nil
}

// GetPublicKey returns the public key for verification
func (ts *TranscriptSigner) GetPublicKey() interface{} {
	return ts.publicKey
}

// GetAlgorithm returns the signing algorithm
func (ts *TranscriptSigner) GetAlgorithm() string {
	return ts.algorithm
}

// GenerateDemoKey generates a demo signing key for testing
func GenerateDemoKey() (*TranscriptSigner, error) {
	// Generate ECDSA key for better performance in demos
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate demo ECDSA key: %v", err)
	}

	return &TranscriptSigner{
		privateKey: ecdsaKey,
		publicKey:  &ecdsaKey.PublicKey,
		algorithm:  "ECDSA",
	}, nil
}

// RequestTranscriptBuilder helps build request transcripts incrementally
type RequestTranscriptBuilder struct {
	sessionID   string
	requests    [][]byte
	commitments map[string][]byte
}

// NewRequestTranscriptBuilder creates a new request transcript builder
func NewRequestTranscriptBuilder(sessionID string) *RequestTranscriptBuilder {
	return &RequestTranscriptBuilder{
		sessionID:   sessionID,
		requests:    make([][]byte, 0),
		commitments: make(map[string][]byte),
	}
}

// AddRequest adds a redacted request to the transcript
func (rtb *RequestTranscriptBuilder) AddRequest(request []byte) {
	rtb.requests = append(rtb.requests, request)
}

// AddCommitment adds a commitment to the transcript
func (rtb *RequestTranscriptBuilder) AddCommitment(key string, commitment []byte) {
	rtb.commitments[key] = commitment
}

// Sign signs the accumulated transcript data
func (rtb *RequestTranscriptBuilder) Sign(signer *TranscriptSigner) (*SignedTranscript, error) {
	return signer.SignRequestTranscript(rtb.sessionID, rtb.requests, rtb.commitments)
}

// ResponseTranscriptBuilder helps build response transcripts incrementally
type ResponseTranscriptBuilder struct {
	sessionID          string
	encryptedResponses [][]byte
}

// NewResponseTranscriptBuilder creates a new response transcript builder
func NewResponseTranscriptBuilder(sessionID string) *ResponseTranscriptBuilder {
	return &ResponseTranscriptBuilder{
		sessionID:          sessionID,
		encryptedResponses: make([][]byte, 0),
	}
}

// AddEncryptedResponse adds an encrypted response to the transcript
func (rtb *ResponseTranscriptBuilder) AddEncryptedResponse(response []byte) {
	rtb.encryptedResponses = append(rtb.encryptedResponses, response)
}

// Sign signs the accumulated transcript data
func (rtb *ResponseTranscriptBuilder) Sign(signer *TranscriptSigner) (*SignedTranscript, error) {
	return signer.SignResponseTranscript(rtb.sessionID, rtb.encryptedResponses)
}
