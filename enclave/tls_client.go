package enclave

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"net"
	"time"

	"bytes"
	"crypto/tls"
	"encoding/pem"
)

// TLS 1.3 constants - simplified for our needs
const (
	VersionTLS13 = 0x0304
)

// TLS13HelloRetryRequest is the special random value for Hello Retry Request
var TLS13HelloRetryRequest = [32]byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// Cipher suites we support (TLS 1.3 only)
const (
	TLS_AES_128_GCM_SHA256       = 0x1301
	TLS_AES_256_GCM_SHA384       = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 = 0x1303
)

// Supported groups (elliptic curves)
const (
	CurveP256 = 23
	CurveP384 = 24
	X25519    = 29
)

// TLS Extensions
const (
	ExtensionServerName          = 0
	ExtensionSupportedGroups     = 10
	ExtensionSignatureAlgorithms = 13
	ExtensionALPN                = 16
	ExtensionSupportedVersions   = 43
	ExtensionKeyShare            = 51
)

// TLSClientConfig holds configuration for TLS handshake
type TLSClientConfig struct {
	ServerName    string   // SNI
	ALPNProtocols []string // ALPN protocols
	MaxVersion    uint16   // Should be VersionTLS13
}

// TLSClientState holds the state during handshake
type TLSClientState struct {
	Config           *TLSClientConfig
	ClientRandom     [32]byte
	SessionID        []byte
	SupportedCiphers []uint16
	KeyShares        []KeyShare
	HandshakeHash    hash.Hash       // For transcript hash
	keyPairs         []*KeyPair      // Private key pairs for ECDH (unexported for security)
	serverHello      *serverHelloMsg // Parsed Server Hello message (unexported for security)

	// Store handshake messages for hash replay if needed
	clientHelloMessage []byte
	serverHelloMessage []byte

	// Store actual certificate chain from TLS handshake
	certificateChain [][]byte // DER-encoded certificates
}

// KeyShare represents a key share in TLS 1.3
type KeyShare struct {
	Group CurveID
	Data  []byte
}

type CurveID uint16

// NewTLSClientState creates a new TLS client state for handshake
func NewTLSClientState(config *TLSClientConfig) (*TLSClientState, error) {
	state := &TLSClientState{
		Config: config,
	}

	// Generate client random (32 bytes)
	if _, err := rand.Read(state.ClientRandom[:]); err != nil {
		return nil, fmt.Errorf("failed to generate client random: %v", err)
	}

	// Generate session ID (32 bytes for compatibility)
	state.SessionID = make([]byte, 32)
	if _, err := rand.Read(state.SessionID); err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %v", err)
	}

	// Set supported cipher suites (TLS 1.3 only)
	state.SupportedCiphers = []uint16{
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
		TLS_CHACHA20_POLY1305_SHA256,
	}

	// Generate real key shares using proper cryptography
	if err := state.UpdateTLSClientStateWithRealKeys(); err != nil {
		return nil, fmt.Errorf("failed to generate key shares: %v", err)
	}

	// Initialize handshake hash with SHA-256 (default)
	// This will be updated if the server selects a cipher suite that uses a different hash
	state.HandshakeHash = sha256.New()

	return state, nil
}

// generateKeyShares is now replaced by UpdateTLSClientStateWithRealKeys in tls_crypto.go

// GenerateClientHello creates a TLS 1.3 Client Hello message
func (s *TLSClientState) GenerateClientHello() ([]byte, error) {
	// Use the new marshaling method that creates a complete TLS record
	clientHelloRecord, err := s.MarshalClientHelloRecord()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Client Hello record: %v", err)
	}

	// Extract just the handshake message (skip the 5-byte TLS record header)
	if len(clientHelloRecord) < 5 {
		return nil, fmt.Errorf("invalid Client Hello record: too short")
	}

	handshakeMessage := clientHelloRecord[5:]

	// Store the handshake message for potential replay
	s.clientHelloMessage = make([]byte, len(handshakeMessage))
	copy(s.clientHelloMessage, handshakeMessage)

	// Update handshake hash with the handshake message
	s.HandshakeHash.Write(handshakeMessage)

	return clientHelloRecord, nil
}

// clientHelloMsg represents a TLS Client Hello message
// Based on Go's crypto/tls implementation
type clientHelloMsg struct {
	vers                         uint16
	random                       []byte
	sessionId                    []byte
	cipherSuites                 []uint16
	compressionMethods           []uint8
	serverName                   string
	alpnProtocols                []string
	supportedVersions            []uint16
	keyShares                    []KeyShare
	supportedGroups              []CurveID
	supportedSignatureAlgorithms []SignatureScheme
}

type SignatureScheme uint16

const (
	PSSWithSHA256          SignatureScheme = 0x0804
	ECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	Ed25519                SignatureScheme = 0x0807
)

// TLS handshake message types
const (
	handshakeTypeServerHello = 2
)

// serverHelloMsg represents a TLS 1.3 Server Hello message
type serverHelloMsg struct {
	vers              uint16
	random            []byte
	sessionId         []byte
	cipherSuite       uint16
	compressionMethod uint8
	extensions        []extension
	keyShare          *KeyShare
	supportedVersion  uint16
}

// extension represents a TLS extension
type extension struct {
	extensionType uint16
	data          []byte
}

// marshal is now implemented in tls_marshal.go

// ProcessServerHello is now implemented in tls_server_hello.go

// ExtractSessionKeys extracts the TLS 1.3 session keys after handshake completion
// This is the critical function for our protocol
func (s *TLSClientState) ExtractSessionKeys() (*TLSSessionKeys, error) {
	if s.serverHello == nil {
		return nil, fmt.Errorf("server hello not processed")
	}

	// Get the server's key share
	serverKeyShare := s.GetServerKeyShare()
	if serverKeyShare == nil {
		return nil, fmt.Errorf("no server key share available")
	}

	// Get our corresponding key pair
	clientKeyPair := s.GetKeyPairForGroup(serverKeyShare.Group)
	if clientKeyPair == nil {
		return nil, fmt.Errorf("no matching client key pair for group %d", serverKeyShare.Group)
	}

	// Perform ECDH to get shared secret
	sharedSecret, err := clientKeyPair.performECDH(serverKeyShare.Data)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %v", err)
	}

	// Create key schedule using Go's TLS 1.3 implementation
	keySchedule, err := NewGoTLSKeySchedule(s.GetSelectedCipherSuite())
	if err != nil {
		return nil, fmt.Errorf("failed to create key schedule: %v", err)
	}
	defer keySchedule.SecureZero() // Clean up sensitive data

	// Initialize early secret and derive handshake secret from ECDH
	keySchedule.InitializeEarlySecret()
	err = keySchedule.DeriveHandshakeSecret(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to derive handshake secret: %v", err)
	}

	// Update transcript with handshake hash
	keySchedule.UpdateTranscript(s.HandshakeHash.Sum(nil))

	// Derive handshake traffic secrets
	err = keySchedule.DeriveHandshakeTrafficSecrets()
	if err != nil {
		return nil, fmt.Errorf("failed to derive handshake traffic secrets: %v", err)
	}

	// Derive master secret and application traffic secrets
	err = keySchedule.DeriveMasterSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to derive master secret: %v", err)
	}

	err = keySchedule.DeriveApplicationTrafficSecrets()
	if err != nil {
		return nil, fmt.Errorf("failed to derive application traffic secrets: %v", err)
	}

	// Get application traffic keys (these are what we need for our protocol)
	clientAppKey, clientAppIV, serverAppKey, serverAppIV, err := keySchedule.GetApplicationTrafficKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to get application traffic keys: %v", err)
	}

	// Return the session keys
	sessionKeys := &TLSSessionKeys{
		ClientWriteKey: make([]byte, len(clientAppKey)),
		ServerWriteKey: make([]byte, len(serverAppKey)),
		ClientWriteIV:  make([]byte, len(clientAppIV)),
		ServerWriteIV:  make([]byte, len(serverAppIV)),
		CipherSuite:    s.GetSelectedCipherSuite(),
	}

	// Copy keys to avoid referencing internal key schedule data
	copy(sessionKeys.ClientWriteKey, clientAppKey)
	copy(sessionKeys.ServerWriteKey, serverAppKey)
	copy(sessionKeys.ClientWriteIV, clientAppIV)
	copy(sessionKeys.ServerWriteIV, serverAppIV)

	// Keys are automatically zeroed when keySchedule.SecureZero() is called

	return sessionKeys, nil
}

// ExtractHandshakeKey extracts the handshake key for certificate verification
// This implements Protocol Step 2.3: TEE_K reveals handshake key to User
func (s *TLSClientState) ExtractHandshakeKey() ([]byte, error) {
	if s.serverHello == nil {
		return nil, fmt.Errorf("server hello not processed")
	}

	// Get the server's key share
	serverKeyShare := s.GetServerKeyShare()
	if serverKeyShare == nil {
		return nil, fmt.Errorf("no server key share available")
	}

	// Get our corresponding key pair
	clientKeyPair := s.GetKeyPairForGroup(serverKeyShare.Group)
	if clientKeyPair == nil {
		return nil, fmt.Errorf("no matching client key pair for group %d", serverKeyShare.Group)
	}

	// Perform ECDH to get shared secret
	sharedSecret, err := clientKeyPair.performECDH(serverKeyShare.Data)
	if err != nil {
		return nil, fmt.Errorf("ECDH failed: %v", err)
	}

	// Create key schedule to derive handshake secret
	keySchedule, err := NewGoTLSKeySchedule(s.GetSelectedCipherSuite())
	if err != nil {
		return nil, fmt.Errorf("failed to create key schedule: %v", err)
	}
	defer keySchedule.SecureZero()

	// Initialize early secret and derive handshake secret from ECDH
	keySchedule.InitializeEarlySecret()
	err = keySchedule.DeriveHandshakeSecret(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to derive handshake secret: %v", err)
	}

	// Update transcript with handshake hash
	keySchedule.UpdateTranscript(s.HandshakeHash.Sum(nil))

	// Derive handshake traffic secrets
	err = keySchedule.DeriveHandshakeTrafficSecrets()
	if err != nil {
		return nil, fmt.Errorf("failed to derive handshake traffic secrets: %v", err)
	}

	// Extract client handshake traffic secret (this is the "handshake key")
	// The User can use this to verify certificate authenticity
	clientHandshakeKey, _, _, _, err := keySchedule.GetHandshakeTrafficKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to get handshake traffic keys: %v", err)
	}

	// Return a copy of the handshake key
	handshakeKey := make([]byte, len(clientHandshakeKey))
	copy(handshakeKey, clientHandshakeKey)

	return handshakeKey, nil
}

// GetCertificateChain returns the server's certificate chain if available
// This supports Protocol Step 2.3: certificate chain revelation for verification
func (s *TLSClientState) GetCertificateChain() []byte {
	if len(s.certificateChain) == 0 {
		return nil
	}

	// Convert DER certificates to PEM format for easier parsing
	var pemBuffer bytes.Buffer
	for i, certDER := range s.certificateChain {
		// Create PEM block for each certificate
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		}

		// Write PEM block to buffer
		if err := pem.Encode(&pemBuffer, pemBlock); err != nil {
			// If PEM encoding fails, fall back to DER concatenation
			var totalLength int
			for _, cert := range s.certificateChain {
				totalLength += len(cert)
			}

			result := make([]byte, 0, totalLength)
			for _, cert := range s.certificateChain {
				result = append(result, cert...)
			}
			return result
		}

		// Add a newline between certificates for clarity
		if i < len(s.certificateChain)-1 {
			pemBuffer.WriteString("\n")
		}
	}

	return pemBuffer.Bytes()
}

// updateHandshakeHashForCipherSuite updates the handshake hash to use the correct
// hash function for the selected cipher suite, replaying previous messages
func (s *TLSClientState) updateHandshakeHashForCipherSuite(cipherSuite uint16) error {
	// Determine the required hash function
	var newHashFunc func() hash.Hash
	switch cipherSuite {
	case TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256:
		newHashFunc = sha256.New
	case TLS_AES_256_GCM_SHA384:
		newHashFunc = sha512.New384
	default:
		return fmt.Errorf("unsupported cipher suite: 0x%04x", cipherSuite)
	}

	// If we're already using the correct hash function, no change needed
	currentHash := s.HandshakeHash.Sum(nil)
	testHash := newHashFunc()
	if len(currentHash) == testHash.Size() {
		// Same hash size, likely the same hash function
		return nil
	}

	// We need to switch hash functions - replay all messages
	s.HandshakeHash = newHashFunc()

	// Replay Client Hello if we have it
	if len(s.clientHelloMessage) > 0 {
		s.HandshakeHash.Write(s.clientHelloMessage)
	}

	return nil
}

// TLSSessionKeys holds the extracted session keys
type TLSSessionKeys struct {
	ClientWriteKey []byte
	ServerWriteKey []byte
	ClientWriteIV  []byte
	ServerWriteIV  []byte
	CipherSuite    uint16
}

// ExtractCertificateChainFromTLS extracts the certificate chain from a real TLS connection
// This populates the certificateChain field with actual DER-encoded certificates
func (s *TLSClientState) ExtractCertificateChainFromTLS(hostname string, port int) error {
	// Create a real TLS connection to extract the certificate chain
	config := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: false,            // Use real certificate verification
		MinVersion:         tls.VersionTLS13, // Force TLS 1.3
	}

	// Establish TCP connection
	address := fmt.Sprintf("%s:%d", hostname, port)
	tcpConn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", address, err)
	}
	defer tcpConn.Close()

	// Establish TLS connection
	tlsConn := tls.Client(tcpConn, config)
	defer tlsConn.Close()

	// Perform handshake
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake failed: %v", err)
	}

	// Get connection state and extract certificate chain
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("no peer certificates available")
	}

	// Store the DER-encoded certificates
	s.certificateChain = make([][]byte, len(state.PeerCertificates))
	for i, cert := range state.PeerCertificates {
		s.certificateChain[i] = make([]byte, len(cert.Raw))
		copy(s.certificateChain[i], cert.Raw)
	}

	return nil
}
