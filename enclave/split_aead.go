// Package enclave implements Split AEAD operations for the TEE MPC protocol
// Based on Go's crypto/cipher package implementations
package enclave

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

// Split AEAD implementation based on Go's crypto/cipher/gcm.go and chacha20poly1305 package
// This allows TEE_K to handle encryption while TEE_T handles authentication tag computation

// SplitAEADMode represents the AEAD cipher mode
type SplitAEADMode int

const (
	SplitAEAD_AES_GCM SplitAEADMode = iota
	SplitAEAD_CHACHA20_POLY1305
)

// TagSecrets contains the secrets needed by TEE_T to compute authentication tags
type TagSecrets struct {
	Mode  SplitAEADMode
	Nonce []byte
	AAD   []byte

	// For AES-GCM: H (auth key) and Y0 (initial counter block)
	GCM_H  []byte // E_K(0^128) - authentication subkey
	GCM_Y0 []byte // E_K(IV || 0^31 || 1) - initial counter block

	// For ChaCha20-Poly1305: one-time Poly1305 key
	Poly1305_Key []byte // First 32 bytes of ChaCha20 keystream
}

// SplitAEADEncryptor handles encryption part of Split AEAD (runs in TEE_K)
type SplitAEADEncryptor struct {
	mode        SplitAEADMode
	key         []byte
	aesBlock    cipher.Block // For AES-GCM
	chacha20Key []byte       // For ChaCha20-Poly1305
}

// SplitAEADTagComputer handles tag computation part of Split AEAD (runs in TEE_T)
type SplitAEADTagComputer struct {
	mode SplitAEADMode
}

// NewSplitAEADEncryptor creates a new Split AEAD encryptor
// Based on Go's cipher.NewGCM() and chacha20poly1305.New()
func NewSplitAEADEncryptor(mode SplitAEADMode, key []byte) (*SplitAEADEncryptor, error) {
	encryptor := &SplitAEADEncryptor{
		mode: mode,
		key:  make([]byte, len(key)),
	}
	copy(encryptor.key, key)

	switch mode {
	case SplitAEAD_AES_GCM:
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			return nil, errors.New("invalid AES key size")
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %v", err)
		}
		encryptor.aesBlock = block

	case SplitAEAD_CHACHA20_POLY1305:
		if len(key) != chacha20poly1305.KeySize {
			return nil, errors.New("invalid ChaCha20-Poly1305 key size")
		}
		encryptor.chacha20Key = make([]byte, len(key))
		copy(encryptor.chacha20Key, key)

	default:
		return nil, errors.New("unsupported Split AEAD mode")
	}

	return encryptor, nil
}

// EncryptWithoutTag encrypts plaintext and generates tag secrets for TEE_T
// This is the core Split AEAD operation - encryption without tag computation
func (e *SplitAEADEncryptor) EncryptWithoutTag(nonce, plaintext, aad []byte) (ciphertext []byte, tagSecrets *TagSecrets, err error) {
	switch e.mode {
	case SplitAEAD_AES_GCM:
		return e.encryptAESGCMWithoutTag(nonce, plaintext, aad)
	case SplitAEAD_CHACHA20_POLY1305:
		return e.encryptChaCha20Poly1305WithoutTag(nonce, plaintext, aad)
	default:
		return nil, nil, errors.New("unsupported Split AEAD mode")
	}
}

// encryptAESGCMWithoutTag implements AES-GCM encryption without tag computation
// Based on Go's crypto/cipher/gcm.go implementation
func (e *SplitAEADEncryptor) encryptAESGCMWithoutTag(nonce, plaintext, aad []byte) ([]byte, *TagSecrets, error) {
	if len(nonce) == 0 {
		return nil, nil, errors.New("cipher: the nonce can't have zero length")
	}

	// Generate authentication subkey H = E_K(0^128)
	// This is from Go's gcm.go - the GHASH authentication key
	var h [16]byte
	e.aesBlock.Encrypt(h[:], h[:])

	// Generate initial counter block Y0
	// Based on Go's gcm.go deriveCounter implementation
	var y0 [16]byte
	if len(nonce) == 12 {
		// Standard 96-bit nonce case
		copy(y0[:12], nonce)
		y0[15] = 1
	} else {
		// Non-standard nonce length - use GHASH
		// This follows RFC 5116 Section 5.1
		copy(y0[:], e.gHashNonce(h[:], nonce))
	}

	// Encrypt Y0 to get E_K(Y0) for tag computation
	var encY0 [16]byte
	e.aesBlock.Encrypt(encY0[:], y0[:])

	// Encrypt plaintext using CTR mode starting from Y1
	ciphertext := make([]byte, len(plaintext))
	if len(plaintext) > 0 {
		// Increment counter for Y1, Y2, etc.
		y1 := y0
		e.gcmInc32(&y1)

		// Create CTR mode cipher starting from Y1
		ctr := cipher.NewCTR(e.aesBlock, y1[:])
		ctr.XORKeyStream(ciphertext, plaintext)
	}

	return ciphertext, &TagSecrets{
		Mode:   SplitAEAD_AES_GCM,
		Nonce:  append([]byte(nil), nonce...),
		AAD:    append([]byte(nil), aad...),
		GCM_H:  h[:],
		GCM_Y0: encY0[:],
	}, nil
}

// encryptChaCha20Poly1305WithoutTag implements ChaCha20-Poly1305 encryption without tag
// Based on golang.org/x/crypto/chacha20poly1305 implementation
func (e *SplitAEADEncryptor) encryptChaCha20Poly1305WithoutTag(nonce, plaintext, aad []byte) ([]byte, *TagSecrets, error) {
	if len(nonce) != chacha20poly1305.NonceSize {
		return nil, nil, errors.New("chacha20poly1305: bad nonce length")
	}

	// Create ChaCha20 cipher for counter = 0
	counter0Cipher, err := chacha20.NewUnauthenticatedCipher(e.chacha20Key, nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create ChaCha20 cipher: %v", err)
	}

	// Generate Poly1305 one-time key (first 32 bytes of keystream at counter 0)
	// This is from chacha20poly1305.go - the one-time authentication key
	var poly1305Key [32]byte
	counter0Cipher.XORKeyStream(poly1305Key[:], poly1305Key[:])

	// Create new cipher for counter = 1 (for data encryption)
	// The ChaCha20 spec uses counter 0 for Poly1305 key, counter 1+ for data
	counter1Cipher, err := chacha20.NewUnauthenticatedCipher(e.chacha20Key, nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create ChaCha20 cipher for data: %v", err)
	}

	// Skip the first 64 bytes (counter 0 block) to start at counter 1
	skipBlock := make([]byte, 64)
	counter1Cipher.XORKeyStream(skipBlock, skipBlock)

	// Encrypt plaintext starting from counter 1
	ciphertext := make([]byte, len(plaintext))
	counter1Cipher.XORKeyStream(ciphertext, plaintext)

	return ciphertext, &TagSecrets{
		Mode:         SplitAEAD_CHACHA20_POLY1305,
		Nonce:        append([]byte(nil), nonce...),
		AAD:          append([]byte(nil), aad...),
		Poly1305_Key: poly1305Key[:],
	}, nil
}

// NewSplitAEADTagComputer creates a new Split AEAD tag computer for TEE_T
func NewSplitAEADTagComputer() *SplitAEADTagComputer {
	return &SplitAEADTagComputer{}
}

// ComputeTag computes the authentication tag using secrets from TEE_K
// This runs in TEE_T and completes the Split AEAD operation
func (t *SplitAEADTagComputer) ComputeTag(ciphertext []byte, secrets *TagSecrets) ([]byte, error) {
	switch secrets.Mode {
	case SplitAEAD_AES_GCM:
		return t.computeGCMTag(ciphertext, secrets)
	case SplitAEAD_CHACHA20_POLY1305:
		return t.computePoly1305Tag(ciphertext, secrets)
	default:
		return nil, errors.New("unsupported Split AEAD mode")
	}
}

// computeGCMTag computes GCM authentication tag using H and Y0 from TEE_K
// Based on Go's crypto/cipher/gcm.go auth() method
func (t *SplitAEADTagComputer) computeGCMTag(ciphertext []byte, secrets *TagSecrets) ([]byte, error) {
	if len(secrets.GCM_H) != 16 || len(secrets.GCM_Y0) != 16 {
		return nil, errors.New("invalid GCM secrets")
	}

	// Compute GHASH(H, AAD || 0* || C || 0* || len(AAD) || len(C))
	// This follows RFC 4106 Section 4 - GCM authentication

	var s [16]byte // GHASH state

	// Process AAD
	if len(secrets.AAD) > 0 {
		t.gHashUpdate(&s, secrets.GCM_H, secrets.AAD)
	}

	// Process ciphertext
	if len(ciphertext) > 0 {
		t.gHashUpdate(&s, secrets.GCM_H, ciphertext)
	}

	// Process length fields (AAD length || ciphertext length)
	var lengths [16]byte
	binary.BigEndian.PutUint64(lengths[:8], uint64(len(secrets.AAD))*8)
	binary.BigEndian.PutUint64(lengths[8:], uint64(len(ciphertext))*8)
	t.gHashBlockUpdate(&s, secrets.GCM_H, lengths[:])

	// Final tag = GHASH result XOR E_K(Y0)
	tag := make([]byte, 16)
	for i := 0; i < 16; i++ {
		tag[i] = s[i] ^ secrets.GCM_Y0[i]
	}

	return tag, nil
}

// computePoly1305Tag computes Poly1305 authentication tag
// Based on golang.org/x/crypto/poly1305 implementation
func (t *SplitAEADTagComputer) computePoly1305Tag(ciphertext []byte, secrets *TagSecrets) ([]byte, error) {
	if len(secrets.Poly1305_Key) != 32 {
		return nil, errors.New("invalid Poly1305 key")
	}

	// Compute Poly1305(key, AAD || pad16(AAD) || C || pad16(C) || len(AAD) || len(C))
	// This follows RFC 7539 Section 2.8 - ChaCha20-Poly1305 AEAD construction

	var poly1305Input []byte

	// Add AAD
	poly1305Input = append(poly1305Input, secrets.AAD...)

	// Pad AAD to 16-byte boundary
	if pad := 16 - (len(secrets.AAD) % 16); pad != 16 {
		poly1305Input = append(poly1305Input, make([]byte, pad)...)
	}

	// Add ciphertext
	poly1305Input = append(poly1305Input, ciphertext...)

	// Pad ciphertext to 16-byte boundary
	if pad := 16 - (len(ciphertext) % 16); pad != 16 {
		poly1305Input = append(poly1305Input, make([]byte, pad)...)
	}

	// Add lengths (little-endian)
	var lengths [16]byte
	binary.LittleEndian.PutUint64(lengths[:8], uint64(len(secrets.AAD)))
	binary.LittleEndian.PutUint64(lengths[8:], uint64(len(ciphertext)))
	poly1305Input = append(poly1305Input, lengths[:]...)

	// Compute Poly1305 MAC
	var key [32]byte
	copy(key[:], secrets.Poly1305_Key)

	var tag [16]byte
	poly1305.Sum(&tag, poly1305Input, &key)
	return tag[:], nil
}

// VerifyTag verifies an authentication tag (for decryption)
func (t *SplitAEADTagComputer) VerifyTag(ciphertext, expectedTag []byte, secrets *TagSecrets) error {
	computedTag, err := t.ComputeTag(ciphertext, secrets)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(computedTag, expectedTag) != 1 {
		return errors.New("authentication tag verification failed")
	}

	return nil
}

// Helper functions adapted from Go's crypto/cipher/gcm.go

// gHashNonce computes GHASH for non-standard nonce lengths
func (e *SplitAEADEncryptor) gHashNonce(h, nonce []byte) []byte {
	var s [16]byte
	t := &SplitAEADTagComputer{} // Helper instance for GHASH operations
	t.gHashUpdate(&s, h, nonce)

	// Add nonce length
	var lengthBlock [16]byte
	binary.BigEndian.PutUint64(lengthBlock[8:], uint64(len(nonce))*8)
	t.gHashBlockUpdate(&s, h, lengthBlock[:])

	return s[:]
}

// gcmInc32 increments the rightmost 32-bit word of a 128-bit block
func (e *SplitAEADEncryptor) gcmInc32(counterBlock *[16]byte) {
	c := binary.BigEndian.Uint32(counterBlock[12:16])
	c++
	binary.BigEndian.PutUint32(counterBlock[12:16], c)
}

// gHashUpdate processes data through GHASH
func (t *SplitAEADTagComputer) gHashUpdate(s *[16]byte, h []byte, data []byte) {
	for len(data) >= 16 {
		t.gHashBlockUpdate(s, h, data[:16])
		data = data[16:]
	}

	if len(data) > 0 {
		var block [16]byte
		copy(block[:], data)
		t.gHashBlockUpdate(s, h, block[:])
	}
}

// gHashBlockUpdate processes a single 16-byte block through GHASH
// Simplified implementation - in production, use assembly optimized version from Go
func (t *SplitAEADTagComputer) gHashBlockUpdate(s *[16]byte, h, block []byte) {
	// XOR block into state
	for i := 0; i < 16; i++ {
		s[i] ^= block[i]
	}

	// Multiply by H in GF(2^128)
	// This is a simplified version - Go's implementation uses optimized assembly
	t.gfMul(s, h)
}

// gfMul performs multiplication in GF(2^128) - simplified version
// Production should use Go's optimized assembly implementations
func (t *SplitAEADTagComputer) gfMul(a *[16]byte, b []byte) {
	// This is a reference implementation
	// Go's actual implementation uses optimized assembly for performance
	var result [16]byte

	for i := 0; i < 128; i++ {
		if (b[i/8]>>(7-(i%8)))&1 == 1 {
			for j := 0; j < 16; j++ {
				result[j] ^= a[j]
			}
		}

		// Right shift a
		carry := byte(0)
		for j := 0; j < 16; j++ {
			newCarry := a[j] & 1
			a[j] = (a[j] >> 1) | (carry << 7)
			carry = newCarry
		}

		// If carry, XOR with reduction polynomial
		if carry != 0 {
			a[0] ^= 0xe1
		}
	}

	*a = result
}

// SecureZero securely zeros sensitive data
func (e *SplitAEADEncryptor) SecureZero() {
	if e.key != nil {
		secureZeroBytes(e.key)
	}
	if e.chacha20Key != nil {
		secureZeroBytes(e.chacha20Key)
	}
}

func (ts *TagSecrets) SecureZero() {
	secureZeroBytes(ts.GCM_H)
	secureZeroBytes(ts.GCM_Y0)
	secureZeroBytes(ts.Poly1305_Key)
	secureZeroBytes(ts.Nonce)
	secureZeroBytes(ts.AAD)
}

// Note: secureZeroBytes is already defined in tls_key_schedule.go
