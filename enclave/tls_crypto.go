package enclave

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// KeyPair represents a public/private key pair for ECDH
type KeyPair struct {
	Group      CurveID
	PublicKey  []byte
	PrivateKey []byte
}

// generateX25519KeyPair generates a X25519 key pair for ECDH
func generateX25519KeyPair() (*KeyPair, error) {
	// Generate private key (32 random bytes)
	var privateKey [32]byte
	if _, err := rand.Read(privateKey[:]); err != nil {
		return nil, fmt.Errorf("failed to generate X25519 private key: %v", err)
	}

	// Compute public key
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	return &KeyPair{
		Group:      X25519,
		PublicKey:  publicKey[:],
		PrivateKey: privateKey[:],
	}, nil
}

// generateP256KeyPair generates a P-256 ECDH key pair
func generateP256KeyPair() (*KeyPair, error) {
	// Generate ECDH key pair on P-256 curve using modern crypto/ecdh
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate P-256 private key: %v", err)
	}

	// Get public key bytes (uncompressed point format)
	publicKeyBytes := privateKey.PublicKey().Bytes()

	// Get private key bytes
	privateKeyBytes := privateKey.Bytes()

	return &KeyPair{
		Group:      CurveP256,
		PublicKey:  publicKeyBytes,
		PrivateKey: privateKeyBytes,
	}, nil
}

// generateKeyShares generates key shares for the supported groups
func generateKeyShares() ([]KeyShare, []*KeyPair, error) {
	var keyShares []KeyShare
	var keyPairs []*KeyPair

	// Generate X25519 key pair
	x25519KeyPair, err := generateX25519KeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate X25519 key pair: %v", err)
	}

	keyShares = append(keyShares, KeyShare{
		Group: X25519,
		Data:  x25519KeyPair.PublicKey,
	})
	keyPairs = append(keyPairs, x25519KeyPair)

	// Generate P-256 key pair
	p256KeyPair, err := generateP256KeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate P-256 key pair: %v", err)
	}

	keyShares = append(keyShares, KeyShare{
		Group: CurveP256,
		Data:  p256KeyPair.PublicKey,
	})
	keyPairs = append(keyPairs, p256KeyPair)

	return keyShares, keyPairs, nil
}

// performECDH performs ECDH key agreement
func (kp *KeyPair) performECDH(peerPublicKey []byte) ([]byte, error) {
	switch kp.Group {
	case X25519:
		if len(peerPublicKey) != 32 {
			return nil, fmt.Errorf("X25519 public key must be 32 bytes, got %d", len(peerPublicKey))
		}
		if len(kp.PrivateKey) != 32 {
			return nil, fmt.Errorf("X25519 private key must be 32 bytes, got %d", len(kp.PrivateKey))
		}

		var sharedSecret [32]byte
		var privateKey [32]byte
		var publicKey [32]byte

		copy(privateKey[:], kp.PrivateKey)
		copy(publicKey[:], peerPublicKey)

		curve25519.ScalarMult(&sharedSecret, &privateKey, &publicKey)
		return sharedSecret[:], nil

	case CurveP256:
		// Reconstruct private key from bytes
		privateKey, err := ecdh.P256().NewPrivateKey(kp.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to reconstruct P-256 private key: %v", err)
		}

		// Reconstruct peer public key from bytes
		peerPublic, err := ecdh.P256().NewPublicKey(peerPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse P-256 peer public key: %v", err)
		}

		// Perform ECDH
		sharedSecret, err := privateKey.ECDH(peerPublic)
		if err != nil {
			return nil, fmt.Errorf("ECDH operation failed: %v", err)
		}

		return sharedSecret, nil

	default:
		return nil, fmt.Errorf("unsupported curve group: %d", kp.Group)
	}
}

// UpdateTLSClientStateWithRealKeys updates the TLS client state with properly generated keys
func (s *TLSClientState) UpdateTLSClientStateWithRealKeys() error {
	// Generate real key shares
	keyShares, keyPairs, err := generateKeyShares()
	if err != nil {
		return fmt.Errorf("failed to generate key shares: %v", err)
	}

	// Update the client state
	s.KeyShares = keyShares

	// Store key pairs for later ECDH operations
	// We'll add this field to TLSClientState
	s.keyPairs = keyPairs

	return nil
}

// GetKeyPairForGroup returns the key pair for a specific group
func (s *TLSClientState) GetKeyPairForGroup(group CurveID) *KeyPair {
	for _, kp := range s.keyPairs {
		if kp.Group == group {
			return kp
		}
	}
	return nil
}
