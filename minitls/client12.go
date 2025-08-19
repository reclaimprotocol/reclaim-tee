package minitls

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"hash"
	"io"

	"go.uber.org/zap"
)

// TLS 1.2 Client Handshake Implementation
// Implements the 2-RTT handshake flow as specified in RFC 5246

// handshakeTLS12 performs a complete TLS 1.2 handshake
func (c *Client) handshakeTLS12(serverName string) error {
	c.logger.Debug("Starting TLS 1.2 Handshake")

	// Step 1: Send ClientHello (pure TLS 1.2 without keyShares)
	clientHello, err := c.buildPureTLS12ClientHello(serverName)
	if err != nil {
		return fmt.Errorf("failed to build ClientHello: %v", err)
	}

	c.logger.Debug("Sending TLS 1.2 ClientHello", zap.Int("bytes", len(clientHello)))
	if _, err := c.conn.Write(clientHello); err != nil {
		return fmt.Errorf("failed to send ClientHello: %v", err)
	}

	// Initialize handshake transcript with ClientHello
	c.transcript = append(c.transcript, clientHello[5:]...) // Skip record header

	// Step 2: Read and process ServerHello
	serverHello, err := c.readServerHello()
	if err != nil {
		return fmt.Errorf("failed to read ServerHello: %v", err)
	}

	c.transcript = append(c.transcript, serverHello...)

	// Parse ServerHello to get cipher suite and server random
	cipherSuite, err := c.parseServerHelloTLS12(serverHello)
	if err != nil {
		return fmt.Errorf("failed to parse ServerHello: %v", err)
	}

	c.cipherSuite = cipherSuite
	c.negotiatedVersion = VersionTLS12
	c.logger.Debug("Negotiated TLS 1.2 cipher suite", zap.Uint16("cipher_suite", cipherSuite))

	// Step 3: Read Certificate message
	certificate, err := c.readHandshakeMessage()
	if err != nil {
		return fmt.Errorf("failed to read Certificate: %v", err)
	}
	c.transcript = append(c.transcript, certificate...)

	// Process and verify the certificate
	if err := c.processServerCertificateTLS12(certificate); err != nil {
		return fmt.Errorf("failed to process server certificate: %v", err)
	}

	// Step 4: Read ServerKeyExchange message
	serverKeyExchange, err := c.readHandshakeMessage()
	if err != nil {
		return fmt.Errorf("failed to read ServerKeyExchange: %v", err)
	}
	c.transcript = append(c.transcript, serverKeyExchange...)

	serverPublicKey, err := c.parseServerKeyExchange(serverKeyExchange)
	if err != nil {
		return fmt.Errorf("failed to parse ServerKeyExchange: %v", err)
	}

	// Step 4.5: Generate client ECDH key pair matching server's curve
	msg, err := ParseServerKeyExchange(serverKeyExchange)
	if err != nil {
		return fmt.Errorf("failed to re-parse ServerKeyExchange for curve: %v", err)
	}

	var clientCurve ecdh.Curve
	switch msg.GetNamedCurve() {
	case X25519:
		clientCurve = ecdh.X25519()
	case secp256r1:
		clientCurve = ecdh.P256()
	case secp384r1:
		clientCurve = ecdh.P384()
	case secp521r1:
		clientCurve = ecdh.P521()
	default:
		return fmt.Errorf("unsupported client curve: %d", msg.GetNamedCurve())
	}

	// Generate new client key pair using the same curve as server
	clientPrivateKey, err := clientCurve.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate client ECDH key: %v", err)
	}

	c.logger.Debug("Generated client ECDH key pair", zap.Uint16("curve", msg.GetNamedCurve()))

	// Step 5: Read ServerHelloDone message
	serverHelloDone, err := c.readHandshakeMessage()
	if err != nil {
		return fmt.Errorf("failed to read ServerHelloDone: %v", err)
	}
	c.transcript = append(c.transcript, serverHelloDone...)

	if _, err := ParseServerHelloDone(serverHelloDone); err != nil {
		return fmt.Errorf("failed to parse ServerHelloDone: %v", err)
	}

	c.logger.Debug("Received Server Hello Done")

	// Step 6: Generate pre-master secret using ECDH
	sharedSecret, err := clientPrivateKey.ECDH(serverPublicKey)
	if err != nil {
		return fmt.Errorf("ECDH failed: %v", err)
	}

	// fmt.Printf("Shared secret (%d bytes): %x\n", len(sharedSecret), sharedSecret)

	// Step 7: Calculate session hash for Extended Master Secret BEFORE adding ClientKeyExchange
	var sessionHash []byte
	if c.extendedMasterSecret {
		// RFC 7627: session_hash = Hash(ClientHello...ServerHelloDone)
		// The transcript at this point contains exactly that (no ClientKeyExchange yet)
		hashFunc := c.getHashFuncForCipher(cipherSuite)
		hasher := hashFunc()
		hasher.Write(c.transcript)
		sessionHash = hasher.Sum(nil)
		c.logger.Debug("Extended Master Secret session hash",
			zap.Int("bytes", len(sessionHash)),
			zap.String("hash", fmt.Sprintf("%x", sessionHash)))
	}

	// Step 8: Initialize TLS 1.2 key schedule and derive master secret
	c.tls12KeySchedule = NewTLS12KeySchedule(cipherSuite, nil, c.clientRandom, c.serverRandom)

	if c.extendedMasterSecret {
		// RFC 7627: Use Extended Master Secret
		// fmt.Println("Using Extended Master Secret (RFC 7627)")
		// fmt.Printf("DEBUG: Pre-master secret (%d bytes): %x\n", len(sharedSecret), sharedSecret)
		// fmt.Printf("DEBUG: Session hash (%d bytes): %x\n", len(sessionHash), sessionHash)
		c.tls12KeySchedule.DeriveMasterSecretExtended(sharedSecret, sessionHash)
		// fmt.Printf("DEBUG: Derived master secret (%d bytes): %x\n", len(c.tls12KeySchedule.masterSecret), c.tls12KeySchedule.masterSecret)
	} else {
		// Standard master secret derivation
		// fmt.Println("Using standard master secret derivation")
		// fmt.Printf("DEBUG: Pre-master secret (%d bytes): %x\n", len(sharedSecret), sharedSecret)
		// fmt.Printf("DEBUG: Client random: %x\n", c.clientRandom)
		// fmt.Printf("DEBUG: Server random: %x\n", c.serverRandom)
		c.tls12KeySchedule.DeriveMasterSecret(sharedSecret)
		// fmt.Printf("DEBUG: Derived master secret (%d bytes): %x\n", len(c.tls12KeySchedule.masterSecret), c.tls12KeySchedule.masterSecret)
	}

	c.logger.Debug("Master secret derived successfully")

	// Step 8: Send ClientKeyExchange
	clientKeyExchange := NewClientKeyExchange(clientPrivateKey.PublicKey().Bytes())
	clientKeyExchangeMsg := clientKeyExchange.Marshal()

	// Wrap in TLS record
	clientKeyExchangeRecord := c.wrapHandshakeMessage(clientKeyExchangeMsg)
	if _, err := c.conn.Write(clientKeyExchangeRecord); err != nil {
		return fmt.Errorf("failed to send ClientKeyExchange: %v", err)
	}

	c.transcript = append(c.transcript, clientKeyExchangeMsg...)
	c.logger.Debug("Sent ClientKeyExchange")

	// Step 9: Send ChangeCipherSpec
	changeCipherSpec := &ChangeCipherSpecMsg{}
	changeCipherSpecRecord := changeCipherSpec.Marshal()
	if _, err := c.conn.Write(changeCipherSpecRecord); err != nil {
		return fmt.Errorf("failed to send ChangeCipherSpec: %v", err)
	}

	c.logger.Debug("Sent ChangeCipherSpec")

	// Step 10: Derive session keys and initialize AEAD
	if err := c.initTLS12AEAD(); err != nil {
		return fmt.Errorf("failed to initialize TLS 1.2 AEAD: %v", err)
	}

	// Step 11: Send Finished message (encrypted)
	if err := c.sendTLS12Finished(true); err != nil {
		return fmt.Errorf("failed to send client Finished: %v", err)
	}

	// Step 12: Read server ChangeCipherSpec
	if err := c.readChangeCipherSpec(); err != nil {
		return fmt.Errorf("failed to read server ChangeCipherSpec: %v", err)
	}

	// Step 13: Read and verify server Finished message
	if err := c.readAndVerifyTLS12Finished(false); err != nil {
		return fmt.Errorf("failed to verify server Finished: %v", err)
	}

	// Step 14: TLS 1.2 sequence numbers continue from handshake (no reset needed)
	// Client has sent 1 encrypted message (Finished), so writeSeq=1
	// Server has sent 1 encrypted message (Finished), so readSeq=1
	c.logger.Debug("TLS 1.2 sequence numbers after handshake",
		zap.Uint64("read_seq", c.tls12AEAD.GetReadSequence()),
		zap.Uint64("write_seq", c.tls12AEAD.GetWriteSequence()))

	c.logger.Debug("TLS 1.2 Handshake Completed Successfully")
	return nil
}

// continueTLS12HandshakeAfterServerHello continues TLS 1.2 handshake after ServerHello has been processed
func (c *Client) continueTLS12HandshakeAfterServerHello(clientPrivateKey *ecdh.PrivateKey) error {
	c.logger.Debug("Continuing TLS 1.2 handshake after ServerHello")

	// Step 3: Read Certificate message
	certificate, err := c.readHandshakeMessage()
	if err != nil {
		return fmt.Errorf("failed to read Certificate: %v", err)
	}
	c.transcript = append(c.transcript, certificate...)

	// Process and verify the certificate (TLS 1.2 format)
	if err := c.processServerCertificateTLS12(certificate); err != nil {
		return fmt.Errorf("failed to process server certificate: %v", err)
	}

	// Step 4: Read ServerKeyExchange message
	serverKeyExchange, err := c.readHandshakeMessage()
	if err != nil {
		return fmt.Errorf("failed to read ServerKeyExchange: %v", err)
	}
	c.transcript = append(c.transcript, serverKeyExchange...)

	serverPublicKey, err := c.parseServerKeyExchange(serverKeyExchange)
	if err != nil {
		return fmt.Errorf("failed to parse ServerKeyExchange: %v", err)
	}

	// Step 4.5: Generate client ECDH key pair matching server's curve
	msg, err := ParseServerKeyExchange(serverKeyExchange)
	if err != nil {
		return fmt.Errorf("failed to re-parse ServerKeyExchange for curve: %v", err)
	}

	var clientCurve ecdh.Curve
	switch msg.GetNamedCurve() {
	case X25519:
		clientCurve = ecdh.X25519()
	case secp256r1:
		clientCurve = ecdh.P256()
	case secp384r1:
		clientCurve = ecdh.P384()
	case secp521r1:
		clientCurve = ecdh.P521()
	default:
		return fmt.Errorf("unsupported client curve: %d", msg.GetNamedCurve())
	}

	// Generate new client key pair using the same curve as server (ignore passed-in key from version negotiation)
	clientPrivateKey, err = clientCurve.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate client ECDH key: %v", err)
	}

	c.logger.Debug("Generated client ECDH key pair", zap.Uint16("curve", msg.GetNamedCurve()))

	// Step 5: Read ServerHelloDone message
	serverHelloDone, err := c.readHandshakeMessage()
	if err != nil {
		return fmt.Errorf("failed to read ServerHelloDone: %v", err)
	}
	c.transcript = append(c.transcript, serverHelloDone...)

	if _, err := ParseServerHelloDone(serverHelloDone); err != nil {
		return fmt.Errorf("failed to parse ServerHelloDone: %v", err)
	}

	c.logger.Debug("Received Server Hello Done")

	// Step 6: Generate pre-master secret using ECDH
	sharedSecret, err := clientPrivateKey.ECDH(serverPublicKey)
	if err != nil {
		return fmt.Errorf("ECDH failed: %v", err)
	}

	// fmt.Printf("Shared secret (%d bytes): %x\n", len(sharedSecret), sharedSecret)

	// Step 7: Calculate session hash for Extended Master Secret BEFORE adding ClientKeyExchange
	var sessionHash []byte
	if c.extendedMasterSecret {
		// RFC 7627: session_hash = Hash(ClientHello...ServerHelloDone)
		// The transcript at this point contains exactly that (no ClientKeyExchange yet)
		hashFunc := c.getHashFuncForCipher(c.cipherSuite)
		hasher := hashFunc()
		hasher.Write(c.transcript)
		sessionHash = hasher.Sum(nil)
		c.logger.Debug("Extended Master Secret session hash",
			zap.Int("bytes", len(sessionHash)),
			zap.String("hash", fmt.Sprintf("%x", sessionHash)))
	}

	// Step 8: Initialize TLS 1.2 key schedule and derive master secret
	c.tls12KeySchedule = NewTLS12KeySchedule(c.cipherSuite, nil, c.clientRandom, c.serverRandom)

	if c.extendedMasterSecret {
		// RFC 7627: Use Extended Master Secret
		c.logger.Debug("Using Extended Master Secret (RFC 7627)")
		c.logger.Debug("Pre-master secret", zap.Int("bytes", len(sharedSecret)), zap.String("secret", fmt.Sprintf("%x", sharedSecret)))
		c.logger.Debug("Session hash", zap.Int("bytes", len(sessionHash)), zap.String("hash", fmt.Sprintf("%x", sessionHash)))
		c.tls12KeySchedule.DeriveMasterSecretExtended(sharedSecret, sessionHash)
		c.logger.Debug("Derived master secret", zap.Int("bytes", len(c.tls12KeySchedule.masterSecret)), zap.String("secret", fmt.Sprintf("%x", c.tls12KeySchedule.masterSecret)))
	} else {
		// Standard master secret derivation
		c.logger.Debug("Using standard master secret derivation")
		c.logger.Debug("Pre-master secret", zap.Int("bytes", len(sharedSecret)), zap.String("secret", fmt.Sprintf("%x", sharedSecret)))
		c.logger.Debug("Client random", zap.String("random", fmt.Sprintf("%x", c.clientRandom)))
		c.logger.Debug("Server random", zap.String("random", fmt.Sprintf("%x", c.serverRandom)))
		c.tls12KeySchedule.DeriveMasterSecret(sharedSecret)
		c.logger.Debug("Derived master secret", zap.Int("bytes", len(c.tls12KeySchedule.masterSecret)), zap.String("secret", fmt.Sprintf("%x", c.tls12KeySchedule.masterSecret)))
	}

	c.logger.Debug("Master secret derived successfully")

	// Step 8: Send ClientKeyExchange
	clientKeyExchange := NewClientKeyExchange(clientPrivateKey.PublicKey().Bytes())
	clientKeyExchangeMsg := clientKeyExchange.Marshal()

	// Wrap in TLS record
	clientKeyExchangeRecord := c.wrapHandshakeMessage(clientKeyExchangeMsg)
	if _, err := c.conn.Write(clientKeyExchangeRecord); err != nil {
		return fmt.Errorf("failed to send ClientKeyExchange: %v", err)
	}

	c.transcript = append(c.transcript, clientKeyExchangeMsg...)
	c.logger.Debug("Sent ClientKeyExchange")

	// Step 9: Send ChangeCipherSpec
	changeCipherSpec := &ChangeCipherSpecMsg{}
	changeCipherSpecRecord := changeCipherSpec.Marshal()
	if _, err := c.conn.Write(changeCipherSpecRecord); err != nil {
		return fmt.Errorf("failed to send ChangeCipherSpec: %v", err)
	}

	c.logger.Debug("Sent ChangeCipherSpec")

	// Step 10: Derive session keys and initialize AEAD
	if err := c.initTLS12AEAD(); err != nil {
		return fmt.Errorf("failed to initialize TLS 1.2 AEAD: %v", err)
	}

	// Step 11: Send Finished message (encrypted)
	if err := c.sendTLS12Finished(true); err != nil {
		return fmt.Errorf("failed to send client Finished: %v", err)
	}

	// Step 12: Read server ChangeCipherSpec
	if err := c.readChangeCipherSpec(); err != nil {
		return fmt.Errorf("failed to read server ChangeCipherSpec: %v", err)
	}

	// Step 13: Read and verify server Finished message
	if err := c.readAndVerifyTLS12Finished(false); err != nil {
		return fmt.Errorf("failed to verify server Finished: %v", err)
	}

	// Step 14: TLS 1.2 sequence numbers continue from handshake (no reset needed)
	// Client has sent 1 encrypted message (Finished), so writeSeq=1
	// Server has sent 1 encrypted message (Finished), so readSeq=1
	fmt.Printf("TLS 1.2 sequence numbers after handshake (read seq=%d, write seq=%d)\n",
		c.tls12AEAD.GetReadSequence(), c.tls12AEAD.GetWriteSequence())

	fmt.Println("=== TLS 1.2 Handshake Completed Successfully ===")
	return nil
}

// processServerCertificateTLS12 processes a TLS 1.2 server certificate message
func (c *Client) processServerCertificateTLS12(data []byte) error {
	c.logger.Debug("Processing TLS 1.2 Server Certificate")
	// data is the entire handshake message, including its 4-byte header.
	payload := data[4:]

	// TLS 1.2 Certificate message format (no certificate request context):
	// - Certificate list length (3 bytes)
	// - Certificate list (variable length)

	// 1. Parse Certificate List (3-byte length prefix)
	if len(payload) < 3 {
		return fmt.Errorf("payload too short for certificate list length")
	}
	certListLen := uint32(payload[0])<<16 | uint32(payload[1])<<8 | uint32(payload[2])
	if uint32(len(payload)-3) < certListLen {
		return fmt.Errorf("certificate list length (%d) is larger than remaining payload (%d)",
			certListLen, len(payload)-3)
	}
	// Advance payload to the start of the actual list entries
	listBytes := payload[3 : 3+certListLen]

	// 2. Parse each certificate from the list (TLS 1.2 format)
	var certs []*x509.Certificate
	offset := 0
	for offset < len(listBytes) {
		// In TLS 1.2, each certificate entry is just:
		// - Certificate length (3 bytes)
		// - Certificate data (variable length)

		if len(listBytes[offset:]) < 3 {
			return fmt.Errorf("not enough data for certificate length")
		}
		certLen := int(listBytes[offset])<<16 | int(listBytes[offset+1])<<8 | int(listBytes[offset+2])
		offset += 3
		if len(listBytes[offset:]) < certLen {
			return fmt.Errorf("not enough data for certificate body")
		}
		certData := listBytes[offset : offset+certLen]
		offset += certLen

		// Parse the X.509 certificate
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %v", err)
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return fmt.Errorf("no certificates received")
	}

	fmt.Printf(" Received %d certificates. Server's Common Name: %s\n", len(certs), certs[0].Subject.CommonName)

	// NEW: Extract structured certificate info immediately
	c.certificateInfo = c.extractCertificateInfo(certs)

	// 3. Verify the certificate chain
	serverCert := certs[0]
	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intermediates.AddCert(certs[i])
		fmt.Printf(" - Validating cert #%d (%s) against issuer #%d (%s)\n",
			i-1, certs[i-1].Subject.CommonName, i, certs[i].Subject.CommonName)
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("failed to load system cert pool: %v", err)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	_, err = serverCert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate verification failed: %v", err)
	}

	fmt.Println(" Certificate chain signatures are valid.")
	return nil
}

// buildClientHelloTLS12 builds a TLS 1.2 ClientHello message (with keyShares for version negotiation)
func (c *Client) buildClientHelloTLS12(serverName string) ([]byte, *ecdh.PrivateKey, error) {
	// Generate X25519 key pair for TLS 1.3 negotiation
	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate X25519 key: %v", err)
	}

	publicKeyBytes := privateKey.PublicKey().Bytes()
	// fmt.Printf("Generated X25519 public key (%d bytes): %x\n", len(publicKeyBytes), publicKeyBytes)

	// Generate client random
	c.clientRandom = make([]byte, 32)
	if _, err := rand.Read(c.clientRandom); err != nil {
		return nil, nil, fmt.Errorf("failed to generate client random: %v", err)
	}

	// Build ClientHello with TLS 1.2 cipher suites for better Google compatibility
	// Include both RSA and ECDSA variants to support all certificate types
	cipherSuites := c.getCipherSuites()
	if len(cipherSuites) == 0 {
		// Use TLS 1.2 cipher suites that servers can understand for both TLS 1.2 and 1.3
		cipherSuites = []uint16{
			TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,   // ChaCha20 with RSA certs
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, // ChaCha20 with ECDSA certs
			TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,         // AES-256 with RSA certs
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,       // AES-256 with ECDSA certs
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,         // AES-128 with RSA certs
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,       // AES-128 with ECDSA certs
		}
	}

	// Build supported versions list based on configuration
	var supportedVersions []uint16
	minVersion := c.Config.MinVersion
	maxVersion := c.Config.MaxVersion

	// Default to TLS 1.2 and 1.3 if not configured
	if minVersion == 0 {
		minVersion = VersionTLS12
	}
	if maxVersion == 0 {
		maxVersion = VersionTLS13
	}

	// Add versions from max down to min (preferred order)
	if maxVersion >= VersionTLS13 && minVersion <= VersionTLS13 {
		supportedVersions = append(supportedVersions, VersionTLS13)
	}
	if maxVersion >= VersionTLS12 && minVersion <= VersionTLS12 {
		supportedVersions = append(supportedVersions, VersionTLS12)
	}

	// Include keyShares whenever TLS 1.3 is supported
	// keyShares extension is mandatory when advertising TLS 1.3 support
	var keyShares []keyShare
	for _, version := range supportedVersions {
		if version == VersionTLS13 {
			keyShares = []keyShare{
				{group: X25519, data: publicKeyBytes},
			}
			break
		}
	}

	hello := &ClientHelloMsg{
		vers:               VersionTLS12, // Legacy version in record
		random:             c.clientRandom,
		sessionId:          make([]byte, 32),
		cipherSuites:       cipherSuites,
		compressionMethods: []uint8{0},
		serverName:         serverName,
		supportedCurves:    []uint16{X25519, secp256r1}, // X25519 for ECDHE, secp256r1 for ECDSA signatures
		supportedVersions:  supportedVersions,           // Use configuration-based versions
		supportedSignatureAlgorithms: []uint16{
			rsa_pss_rsae_sha256,
			ecdsa_secp256r1_sha256,
			rsa_pss_rsae_sha384,
			ecdsa_secp384r1_sha384,
			rsa_pss_rsae_sha512,
		},
		keyShares:            keyShares,
		extendedMasterSecret: false, // Temporarily disable Extended Master Secret for testing
	}

	// Fill session ID with random bytes
	if _, err := rand.Read(hello.sessionId); err != nil {
		return nil, nil, fmt.Errorf("failed to generate session ID: %v", err)
	}

	return hello.Marshal(), privateKey, nil
}

// buildPureTLS12ClientHello builds a pure TLS 1.2 ClientHello without keyShares
func (c *Client) buildPureTLS12ClientHello(serverName string) ([]byte, error) {
	// Generate client random
	c.clientRandom = make([]byte, 32)
	if _, err := rand.Read(c.clientRandom); err != nil {
		return nil, fmt.Errorf("failed to generate client random: %v", err)
	}

	// TLS 1.2 cipher suites only
	cipherSuites := []uint16{
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}

	hello := &ClientHelloMsg{
		vers:               VersionTLS12, // Legacy version in record
		random:             c.clientRandom,
		sessionId:          make([]byte, 32),
		cipherSuites:       cipherSuites,
		compressionMethods: []uint8{0},
		serverName:         serverName,
		supportedCurves:    []uint16{X25519, secp256r1}, // X25519 for ECDHE, secp256r1 for ECDSA signatures
		supportedVersions:  []uint16{VersionTLS12},      // TLS 1.2 only
		supportedSignatureAlgorithms: []uint16{
			rsa_pss_rsae_sha256,
			ecdsa_secp256r1_sha256,
			rsa_pss_rsae_sha384,
			ecdsa_secp384r1_sha384,
			rsa_pss_rsae_sha512,
		},
		// No keyShares for pure TLS 1.2
		extendedMasterSecret: false, // Temporarily disable Extended Master Secret for testing
	}

	// Fill session ID with random bytes
	if _, err := rand.Read(hello.sessionId); err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %v", err)
	}

	return hello.Marshal(), nil
}

// parseServerHelloTLS12 parses a TLS 1.2 ServerHello and extracts server random
func (c *Client) parseServerHelloTLS12(data []byte) (uint16, error) {
	if len(data) < 4 {
		return 0, fmt.Errorf("ServerHello too short")
	}

	if HandshakeType(data[0]) != typeServerHello {
		return 0, fmt.Errorf("invalid message type: expected ServerHello")
	}

	msgLen := uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if len(data) < int(4+msgLen) {
		return 0, fmt.Errorf("ServerHello message truncated")
	}

	payload := data[4:]

	// Parse ServerHello: version(2) + random(32) + session_id_len(1) + session_id + cipher_suite(2) + compression(1)
	if len(payload) < 38 { // 2 + 32 + 1 + 2 + 1 = minimum 38 bytes
		return 0, fmt.Errorf("ServerHello payload too short")
	}

	offset := 0

	// Parse version
	version := uint16(payload[offset])<<8 | uint16(payload[offset+1])
	offset += 2

	fmt.Printf("Server negotiated version: 0x%04x\n", version)

	// Extract server random
	c.serverRandom = make([]byte, 32)
	copy(c.serverRandom, payload[offset:offset+32])
	offset += 32

	// Parse session ID
	sessionIDLen := payload[offset]
	offset += 1 + int(sessionIDLen)

	if len(payload) < offset+2 {
		return 0, fmt.Errorf("ServerHello missing cipher suite")
	}

	// Parse cipher suite
	cipherSuite := uint16(payload[offset])<<8 | uint16(payload[offset+1])
	offset += 2

	// Skip compression method
	if len(payload) < offset+1 {
		return 0, fmt.Errorf("ServerHello missing compression method")
	}
	offset += 1

	// Parse extensions (if present)
	c.extendedMasterSecret = false // Default to false
	fmt.Printf("DEBUG: Before extensions - offset=%d, payload length=%d, need %d\n", offset, len(payload), offset+2)
	if len(payload) > offset+2 {
		extensionsLen := int(payload[offset])<<8 | int(payload[offset+1])
		offset += 2

		fmt.Printf("DEBUG: ServerHello has %d bytes of extensions\n", extensionsLen)

		if len(payload) >= offset+extensionsLen {
			extensionsData := payload[offset : offset+extensionsLen]

			// Check for Extended Master Secret extension
			extOffset := 0
			for extOffset < len(extensionsData) {
				if extOffset+4 > len(extensionsData) {
					break
				}

				extType := uint16(extensionsData[extOffset])<<8 | uint16(extensionsData[extOffset+1])
				extLen := int(extensionsData[extOffset+2])<<8 | int(extensionsData[extOffset+3])
				extOffset += 4

				fmt.Printf("DEBUG: Found extension type %d (0x%04x), length %d\n", extType, extType, extLen)

				if extType == extensionExtendedMasterSecret {
					c.extendedMasterSecret = true
					fmt.Println("Server supports Extended Master Secret (RFC 7627)")
					break
				}

				extOffset += extLen
			}
		}
	} else {
		fmt.Println("DEBUG: ServerHello has no extensions")
	}

	return cipherSuite, nil
}

// parseServerKeyExchange parses the ServerKeyExchange message and returns the server's public key
func (c *Client) parseServerKeyExchange(data []byte) (*ecdh.PublicKey, error) {
	msg, err := ParseServerKeyExchange(data)
	if err != nil {
		return nil, err
	}

	// Use the curve specified by the server
	var curve ecdh.Curve
	switch msg.GetNamedCurve() {
	case X25519:
		curve = ecdh.X25519()
	case secp256r1:
		curve = ecdh.P256()
	case secp384r1:
		curve = ecdh.P384()
	case secp521r1:
		curve = ecdh.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %d", msg.GetNamedCurve())
	}

	// Convert the raw public key bytes to an ECDH public key
	publicKey, err := curve.NewPublicKey(msg.GetPublicKey())
	if err != nil {
		return nil, fmt.Errorf("failed to parse server public key: %v", err)
	}

	fmt.Printf("Server public key (%d bytes) using curve %d: %x\n", len(msg.GetPublicKey()), msg.GetNamedCurve(), msg.GetPublicKey())
	return publicKey, nil
}

// initTLS12AEAD initializes the TLS 1.2 AEAD context with derived keys
func (c *Client) initTLS12AEAD() error {
	// Derive keys using TLS 1.2 key schedule
	clientWriteKey, clientWriteIV, serverWriteKey, serverWriteIV, err := c.tls12KeySchedule.DeriveKeys()
	if err != nil {
		return fmt.Errorf("failed to derive TLS 1.2 keys: %v", err)
	}

	// Initialize TLS 1.2 AEAD context
	c.tls12AEAD, err = NewTLS12AEADContext(clientWriteKey, clientWriteIV, serverWriteKey, serverWriteIV, c.cipherSuite)
	if err != nil {
		return fmt.Errorf("failed to create TLS 1.2 AEAD context: %v", err)
	}

	fmt.Println("TLS 1.2 AEAD initialized successfully")
	return nil
}

// sendTLS12Finished sends a TLS 1.2 Finished message
func (c *Client) sendTLS12Finished(isClient bool) error {
	// Calculate handshake hash for finished message
	transcriptHash := c.calculateHandshakeHash()

	// DEBUG: Print transcript details
	fmt.Printf("DEBUG: TLS 1.2 Finished verification:\n")
	fmt.Printf("  Transcript length: %d bytes\n", len(c.transcript))

	// Debug: Print what's in the transcript
	fmt.Printf("  Transcript messages:\n")
	offset := 0
	msgCount := 0
	for offset < len(c.transcript) && msgCount < 10 { // Limit to prevent spam
		if offset+4 > len(c.transcript) {
			break
		}
		msgType := c.transcript[offset]
		msgLen := uint32(c.transcript[offset+1])<<16 | uint32(c.transcript[offset+2])<<8 | uint32(c.transcript[offset+3])
		fmt.Printf("    Message %d: type=%d (%s), length=%d\n", msgCount+1, msgType, handshakeTypeString(HandshakeType(msgType)), msgLen)
		offset += 4 + int(msgLen)
		msgCount++
		if offset > len(c.transcript) {
			fmt.Printf("    WARNING: Message extends beyond transcript\n")
			break
		}
	}

	fmt.Printf("  Transcript hash (%d bytes): %x\n", len(transcriptHash), transcriptHash)
	fmt.Printf("  Client random: %x\n", c.clientRandom)
	fmt.Printf("  Server random: %x\n", c.serverRandom)
	fmt.Printf("  Master secret: %x\n", c.tls12KeySchedule.masterSecret)

	// Derive finished data using TLS 1.2 PRF
	finishedData := c.tls12KeySchedule.DeriveFinishedData(transcriptHash, isClient)
	fmt.Printf("  Verify data (%d bytes): %x\n", len(finishedData), finishedData)

	// Create finished message
	finishedMsg := NewTLS12Finished(finishedData)
	finishedMsgBytes := finishedMsg.Marshal()

	// Calculate the expected ciphertext length
	plaintext := finishedMsgBytes // Encrypt the entire handshake message (header + verify_data)

	// For AES-GCM: explicit_iv(8) + plaintext + AEAD_tag(16)
	// For ChaCha20: plaintext + AEAD_tag(16)
	var expectedCiphertextLen int
	if c.cipherSuite == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
		c.cipherSuite == TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ||
		c.cipherSuite == TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
		c.cipherSuite == TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 {
		expectedCiphertextLen = 8 + len(plaintext) + 16 // AES-GCM: explicit_iv + plaintext + auth_tag
	} else {
		expectedCiphertextLen = len(plaintext) + 16 // ChaCha20: plaintext + auth_tag
	}

	// Create record header for AAD with PLAINTEXT length (RFC 5246)
	aadRecordHeader := []byte{recordTypeHandshake, 0x03, 0x03,
		byte(len(plaintext) >> 8), byte(len(plaintext))}

	// Create actual record header for sending with CIPHERTEXT length
	sendRecordHeader := []byte{recordTypeHandshake, 0x03, 0x03,
		byte(expectedCiphertextLen >> 8), byte(expectedCiphertextLen)}

	// DEBUG: Print details before encryption
	fmt.Printf("DEBUG: Encrypting Finished message:\n")
	fmt.Printf("  Plaintext (%d bytes): %x\n", len(plaintext), plaintext)
	fmt.Printf("  AAD record header: %x\n", aadRecordHeader)
	fmt.Printf("  Send record header: %x\n", sendRecordHeader)
	fmt.Printf("  Expected ciphertext length: %d\n", expectedCiphertextLen)

	// Encrypt the finished message using TLS 1.2 AEAD with correct AAD
	encryptedFinished, err := c.tls12AEAD.Encrypt(plaintext, aadRecordHeader)
	if err != nil {
		return fmt.Errorf("failed to encrypt Finished message: %v", err)
	}

	// Verify the actual ciphertext length matches our expectation
	if len(encryptedFinished) != expectedCiphertextLen {
		return fmt.Errorf("unexpected ciphertext length: got %d, expected %d",
			len(encryptedFinished), expectedCiphertextLen)
	}

	// DEBUG: Print encrypted result
	fmt.Printf("  Actual ciphertext (%d bytes): %x\n", len(encryptedFinished), encryptedFinished)

	// Send the encrypted record
	record := append(sendRecordHeader, encryptedFinished...)
	fmt.Printf("  Sending TLS record (%d bytes): %x\n", len(record), record)
	if _, err := c.conn.Write(record); err != nil {
		return fmt.Errorf("failed to send Finished message: %v", err)
	}

	// Add to transcript AFTER encryption (for future server Finished verification)
	c.transcript = append(c.transcript, finishedMsgBytes...)

	fmt.Println("Sent encrypted Finished message")
	return nil
}

// readAndVerifyTLS12Finished reads and verifies the server's Finished message
func (c *Client) readAndVerifyTLS12Finished(isClient bool) error {
	// Read encrypted handshake record
	header := make([]byte, 5)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return fmt.Errorf("failed to read Finished record header: %v", err)
	}

	recordLength := int(header[3])<<8 | int(header[4])
	encryptedPayload := make([]byte, recordLength)
	if _, err := io.ReadFull(c.conn, encryptedPayload); err != nil {
		return fmt.Errorf("failed to read encrypted Finished: %v", err)
	}

	// For AAD, we need the plaintext length, not ciphertext length
	// AES-GCM: record = explicit_iv(8) + encrypted_data + auth_tag(16)
	// ChaCha20: record = encrypted_data + auth_tag(16)
	var plaintextLength int
	if c.cipherSuite == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ||
		c.cipherSuite == TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ||
		c.cipherSuite == TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ||
		c.cipherSuite == TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 {
		// AES-GCM: subtract explicit_iv(8) + auth_tag(16)
		plaintextLength = recordLength - 8 - 16
	} else {
		// ChaCha20: subtract only auth_tag(16)
		plaintextLength = recordLength - 16
	}

	aadHeader := []byte{header[0], header[1], header[2],
		byte(plaintextLength >> 8), byte(plaintextLength)}

	// Decrypt the Finished message using correct AAD
	plaintext, err := c.tls12AEAD.Decrypt(encryptedPayload, aadHeader)
	if err != nil {
		return fmt.Errorf("failed to decrypt Finished message: %v", err)
	}

	// Parse the Finished message
	// The plaintext should be the complete handshake message (header + verify_data)
	finishedMsg, err := ParseTLS12Finished(plaintext)
	if err != nil {
		return fmt.Errorf("failed to parse Finished message: %v", err)
	}

	// Verify the finished data
	expectedFinishedData := c.tls12KeySchedule.DeriveFinishedData(c.calculateHandshakeHash(), isClient)
	if !compareBytes(finishedMsg.GetVerifyData(), expectedFinishedData) {
		return fmt.Errorf("Finished message verification failed")
	}

	// Add to transcript
	c.transcript = append(c.transcript, plaintext...)

	fmt.Println("Server Finished message verified successfully")
	return nil
}

// calculateHandshakeHash calculates the handshake hash for TLS 1.2
func (c *Client) calculateHandshakeHash() []byte {
	var hasher hash.Hash

	// Choose hash function based on cipher suite
	switch c.cipherSuite {
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		hasher = sha256.New()
	case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		hasher = sha512.New384()
	default:
		hasher = sha256.New() // Default to SHA-256
	}

	hasher.Write(c.transcript)
	return hasher.Sum(nil)
}

// getHashFuncForCipher returns the hash function for a given cipher suite
func (c *Client) getHashFuncForCipher(cipherSuite uint16) func() hash.Hash {
	switch cipherSuite {
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return sha256.New
	case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return sha512.New384 // SHA-384
	default:
		// Default to SHA-256 for unknown cipher suites
		return sha256.New
	}
}

// readChangeCipherSpec reads and validates a ChangeCipherSpec message
func (c *Client) readChangeCipherSpec() error {
	header := make([]byte, 5)
	if _, err := io.ReadFull(c.conn, header); err != nil {
		return fmt.Errorf("failed to read ChangeCipherSpec header: %v", err)
	}

	if header[0] != recordTypeChangeCipherSpec {
		if header[0] == recordTypeAlert {
			// Read and decode the alert
			recordLength := int(header[3])<<8 | int(header[4])
			alertData := make([]byte, recordLength)
			if _, err := io.ReadFull(c.conn, alertData); err != nil {
				return fmt.Errorf("failed to read alert data: %v", err)
			}
			if len(alertData) >= 2 {
				alertLevel := alertData[0]
				alertDescription := alertData[1]
				return fmt.Errorf("server sent alert: level=%d, description=%d (expected ChangeCipherSpec)", alertLevel, alertDescription)
			}
			return fmt.Errorf("server sent malformed alert (expected ChangeCipherSpec)")
		}
		return fmt.Errorf("expected ChangeCipherSpec record, got %d", header[0])
	}

	recordLength := int(header[3])<<8 | int(header[4])
	if recordLength != 1 {
		return fmt.Errorf("ChangeCipherSpec should be 1 byte, got %d", recordLength)
	}

	payload := make([]byte, 1)
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return fmt.Errorf("failed to read ChangeCipherSpec payload: %v", err)
	}

	if payload[0] != 1 {
		return fmt.Errorf("invalid ChangeCipherSpec value: %d", payload[0])
	}

	fmt.Println("Received ChangeCipherSpec")
	return nil
}

// wrapHandshakeMessage wraps a handshake message in a TLS record
func (c *Client) wrapHandshakeMessage(msg []byte) []byte {
	record := make([]byte, 5+len(msg))
	record[0] = recordTypeHandshake
	record[1] = 0x03 // TLS 1.2 version
	record[2] = 0x03
	record[3] = byte(len(msg) >> 8)
	record[4] = byte(len(msg))
	copy(record[5:], msg)
	return record
}

// compareBytes securely compares two byte slices
func compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
