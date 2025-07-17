package minitls

import (
	"fmt"
)

// TLS version constants (following Go's crypto/tls conventions)
const (
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304
)

// Config contains configuration for TLS clients and servers.
// Following Go's crypto/tls.Config design patterns.
type Config struct {
	// MinVersion contains minimum TLS version that is acceptable.
	// If zero, TLS 1.2 is currently taken as the minimum.
	MinVersion uint16

	// MaxVersion contains maximum TLS version that is acceptable.
	// If zero, TLS 1.3 is currently taken as the maximum.
	MaxVersion uint16

	// CipherSuites is a list of enabled TLS cipher suites.
	// If nil, a default safe list is used.
	CipherSuites []uint16

	// ServerName is the hostname used to verify the server certificate.
	// For clients only.
	ServerName string

	// NextProtos is a list of supported application level protocols,
	// in order of preference. (ALPN)
	NextProtos []string

	// InsecureSkipVerify controls whether a client verifies the
	// server's certificate chain and host name.
	InsecureSkipVerify bool
}

// supportedVersions returns the list of supported TLS versions for this config
func (c *Config) supportedVersions() []uint16 {
	minVer := c.MinVersion
	if minVer == 0 {
		minVer = VersionTLS12 // Default minimum
	}

	maxVer := c.MaxVersion
	if maxVer == 0 {
		maxVer = VersionTLS13 // Default maximum
	}

	var versions []uint16
	for ver := minVer; ver <= maxVer; ver++ {
		if ver == VersionTLS12 || ver == VersionTLS13 {
			versions = append(versions, ver)
		}
	}
	return versions
}

// maxSupportedVersion returns the maximum supported version for this config
func (c *Config) maxSupportedVersion() uint16 {
	versions := c.supportedVersions()
	if len(versions) == 0 {
		return VersionTLS13 // Default
	}
	return versions[len(versions)-1]
}

// defaultCipherSuites returns the default cipher suites for a given TLS version
func defaultCipherSuites(version uint16) []uint16 {
	switch version {
	case VersionTLS13:
		return []uint16{
			TLS_AES_128_GCM_SHA256,
			TLS_AES_256_GCM_SHA384,
			TLS_CHACHA20_POLY1305_SHA256,
		}
	case VersionTLS12:
		return []uint16{
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		}
	default:
		return nil
	}
}

// cipherSuites returns the cipher suites to use for this config
func (c *Config) cipherSuites() []uint16 {
	if c.CipherSuites != nil {
		return c.CipherSuites
	}

	// Return default cipher suites for the maximum supported version
	maxVer := c.maxSupportedVersion()
	return defaultCipherSuites(maxVer)
}

// TLS 1.3 Record Layer
const (
	recordTypeChangeCipherSpec = 20
	recordTypeAlert            = 21
	recordTypeHandshake        = 22
	recordTypeApplicationData  = 23
)

type recordType uint8
type HandshakeType uint8

// TLS Handshake Message Types (shared between TLS 1.2 and 1.3)
const (
	typeClientHello      HandshakeType = 1
	typeServerHello      HandshakeType = 2
	typeNewSessionTicket HandshakeType = 4
	// TLS 1.2 specific messages
	typeCertificateRequest HandshakeType = 13
	typeServerKeyExchange  HandshakeType = 12
	typeClientKeyExchange  HandshakeType = 16
	typeServerHelloDone    HandshakeType = 14
	// TLS 1.3 specific messages
	typeEncryptedExtensions HandshakeType = 8
	// Shared messages
	typeCertificate       HandshakeType = 11
	typeCertificateVerify HandshakeType = 15
	typeFinished          HandshakeType = 20
)

// TLS 1.3 Cipher Suites
const (
	TLS_AES_128_GCM_SHA256       = 0x1301
	TLS_AES_256_GCM_SHA384       = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 = 0x1303
)

// TLS 1.2 AEAD Cipher Suites (following Go's crypto/tls constants)
const (
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         = 0xc02f
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       = 0xc02b
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         = 0xc030
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       = 0xc02c
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = 0xcca8
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9
)

// TLS 1.3 Extension Types
const (
	extensionServerName           = 0
	extensionSupportedGroups      = 10
	extensionECPointFormats       = 11
	extensionSignatureAlgorithms  = 13
	extensionExtendedMasterSecret = 23
	extensionSessionTicket        = 35
	extensionSupportedVersions    = 43
	extensionKeyShare             = 51
)

// TLS 1.3 Supported Groups
const (
	secp256r1 = 23
	secp384r1 = 24
	secp521r1 = 25
	X25519    = 29
)

// Signature Algorithms
const (
	rsa_pss_rsae_sha256    = 0x0804
	ecdsa_secp256r1_sha256 = 0x0403
	rsa_pss_rsae_sha384    = 0x0805
	ecdsa_secp384r1_sha384 = 0x0503
	rsa_pss_rsae_sha512    = 0x0806
)

// TLS 1.3 Alert Levels
const (
	alertLevelWarning = 1
	alertLevelFatal   = 2
)

// TLS 1.3 Alert Descriptions (from RFC 8446, Section 6)
const (
	alertCloseNotify                  = 0
	alertUnexpectedMessage            = 10
	alertBadRecordMAC                 = 20
	alertDecryptionFailed             = 21
	alertRecordOverflow               = 22
	alertDecompressionFailure         = 30
	alertHandshakeFailure             = 40
	alertBadCertificate               = 42
	alertUnsupportedCertificate       = 43
	alertCertificateRevoked           = 44
	alertCertificateExpired           = 45
	alertCertificateUnknown           = 46
	alertIllegalParameter             = 47
	alertUnknownCA                    = 48
	alertAccessDenied                 = 49
	alertDecodeError                  = 50
	alertDecryptError                 = 51
	alertProtocolVersion              = 70
	alertInsufficientSecurity         = 71
	alertInternalError                = 80
	alertInappropriateFallback        = 86
	alertUserCanceled                 = 90
	alertMissingExtension             = 109
	alertUnsupportedExtension         = 110
	alertCertificateUnobtainable      = 111
	alertUnrecognizedName             = 112
	alertBadCertificateStatusResponse = 113
	alertBadCertificateHashValue      = 114
	alertUnknownPSKIdentity           = 115
	alertCertificateRequired          = 116
	alertNoApplicationProtocol        = 120
)

type ClientHelloMsg struct {
	vers                             uint16
	random                           []byte
	sessionId                        []byte
	cipherSuites                     []uint16
	compressionMethods               []uint8
	serverName                       string
	supportedCurves                  []uint16
	supportedPoints                  []uint8
	ticketSupported                  bool
	sessionTicket                    []byte
	supportedSignatureAlgorithms     []uint16
	supportedSignatureAlgorithmsCert []uint16
	secureRenegotiationSupported     bool
	secureRenegotiation              []byte
	alpnProtocols                    []string
	scts                             bool
	supportedVersions                []uint16
	cookie                           []byte
	pskModes                         []uint8
	keyShares                        []keyShare
	extendedMasterSecret             bool
}

func (m *ClientHelloMsg) Marshal() []byte {
	var b []byte
	// Handshake protocol header
	b = append(b, byte(typeClientHello), 0, 0, 0) // Message type and placeholder for length

	fmt.Printf("DEBUG: Starting ClientHello marshal\n")

	// TLS 1.2 compatibility version
	b = append(b, 0x03, 0x03)
	// Random
	b = append(b, m.random...)
	// Session ID
	b = append(b, byte(len(m.sessionId)))
	b = append(b, m.sessionId...)
	// Cipher suites
	b = append(b, byte(len(m.cipherSuites)*2>>8), byte(len(m.cipherSuites)*2))
	for _, suite := range m.cipherSuites {
		b = append(b, byte(suite>>8), byte(suite))
	}
	// Compression methods
	b = append(b, byte(len(m.compressionMethods)))
	b = append(b, m.compressionMethods...)

	// Extensions
	var extensions []byte
	// Server Name Indication
	if len(m.serverName) > 0 {
		extensions = append(extensions, byte(extensionServerName>>8), byte(extensionServerName)) // Extension type
		extLen := len(m.serverName) + 5
		extensions = append(extensions, byte(extLen>>8), byte(extLen))
		listLen := len(m.serverName) + 3
		extensions = append(extensions, byte(listLen>>8), byte(listLen))
		extensions = append(extensions, 0) // Name type: host_name
		extensions = append(extensions, byte(len(m.serverName)>>8), byte(len(m.serverName)))
		extensions = append(extensions, m.serverName...)
	}

	// Supported Versions
	if len(m.supportedVersions) > 0 {
		extensions = append(extensions, byte(extensionSupportedVersions>>8), byte(extensionSupportedVersions)) // Extension type: supported_versions
		versionsLen := len(m.supportedVersions) * 2
		extensions = append(extensions, byte((versionsLen+1)>>8), byte(versionsLen+1))
		extensions = append(extensions, byte(versionsLen))
		for _, v := range m.supportedVersions {
			extensions = append(extensions, byte(v>>8), byte(v))
		}
	}

	// Supported Groups
	if len(m.supportedCurves) > 0 {
		extensions = append(extensions, byte(extensionSupportedGroups>>8), byte(extensionSupportedGroups))
		groupsLen := len(m.supportedCurves) * 2
		extensions = append(extensions, byte((groupsLen+2)>>8), byte(groupsLen+2))
		extensions = append(extensions, byte(groupsLen>>8), byte(groupsLen))
		for _, group := range m.supportedCurves {
			extensions = append(extensions, byte(group>>8), byte(group))
		}
	}

	// Signature Algorithms
	if len(m.supportedSignatureAlgorithms) > 0 {
		extensions = append(extensions, byte(extensionSignatureAlgorithms>>8), byte(extensionSignatureAlgorithms))
		sigAlgosLen := len(m.supportedSignatureAlgorithms) * 2
		extensions = append(extensions, byte((sigAlgosLen+2)>>8), byte(sigAlgosLen+2))
		extensions = append(extensions, byte(sigAlgosLen>>8), byte(sigAlgosLen))
		for _, algo := range m.supportedSignatureAlgorithms {
			extensions = append(extensions, byte(algo>>8), byte(algo))
		}
	}

	// Key Share
	if len(m.keyShares) > 0 {
		extensions = append(extensions, byte(extensionKeyShare>>8), byte(extensionKeyShare))
		var keySharesLen uint16
		for _, ks := range m.keyShares {
			keySharesLen += 2 + 2 + uint16(len(ks.data))
		}
		extensions = append(extensions, byte((keySharesLen+2)>>8), byte(keySharesLen+2))
		extensions = append(extensions, byte(keySharesLen>>8), byte(keySharesLen))
		for _, ks := range m.keyShares {
			extensions = append(extensions, byte(ks.group>>8), byte(ks.group))
			extensions = append(extensions, byte(len(ks.data)>>8), byte(len(ks.data)))
			extensions = append(extensions, ks.data...)
		}
	}

	// Extended Master Secret
	if m.extendedMasterSecret {
		extensions = append(extensions, byte(extensionExtendedMasterSecret>>8), byte(extensionExtendedMasterSecret))
		extensions = append(extensions, 0) // Extension length: 0
		extensions = append(extensions, 0) // Extension data: empty
	}

	// Append extensions
	b = append(b, byte(len(extensions)>>8), byte(len(extensions)))
	b = append(b, extensions...)

	// Set message length
	putUint24(b[1:4], uint32(len(b)-4))

	// Prepend record header - use TLS 1.2 for the record layer
	record := []byte{recordTypeHandshake, 0x03, 0x03, byte(len(b) >> 8), byte(len(b))}
	record = append(record, b...)

	return record
}

func putUint24(b []byte, v uint32) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

func alertDescriptionString(d uint8) string {
	switch d {
	case alertCloseNotify:
		return "close_notify"
	case alertUnexpectedMessage:
		return "unexpected_message"
	case alertBadRecordMAC:
		return "bad_record_mac"
	case alertDecryptionFailed:
		return "decryption_failed"
	case alertRecordOverflow:
		return "record_overflow"
	case alertDecompressionFailure:
		return "decompression_failure"
	case alertHandshakeFailure:
		return "handshake_failure"
	case alertBadCertificate:
		return "bad_certificate"
	case alertUnsupportedCertificate:
		return "unsupported_certificate"
	case alertCertificateRevoked:
		return "certificate_revoked"
	case alertCertificateExpired:
		return "certificate_expired"
	case alertCertificateUnknown:
		return "certificate_unknown"
	case alertIllegalParameter:
		return "illegal_parameter"
	case alertUnknownCA:
		return "unknown_ca"
	case alertAccessDenied:
		return "access_denied"
	case alertDecodeError:
		return "decode_error"
	case alertDecryptError:
		return "decrypt_error"
	case alertProtocolVersion:
		return "protocol_version"
	case alertInsufficientSecurity:
		return "insufficient_security"
	case alertInternalError:
		return "internal_error"
	case alertInappropriateFallback:
		return "inappropriate_fallback"
	case alertUserCanceled:
		return "user_canceled"
	case alertMissingExtension:
		return "missing_extension"
	case alertUnsupportedExtension:
		return "unsupported_extension"
	case alertCertificateUnobtainable:
		return "certificate_unobtainable"
	case alertUnrecognizedName:
		return "unrecognized_name"
	case alertBadCertificateStatusResponse:
		return "bad_certificate_status_response"
	case alertBadCertificateHashValue:
		return "bad_certificate_hash_value"
	case alertUnknownPSKIdentity:
		return "unknown_psk_identity"
	case alertCertificateRequired:
		return "certificate_required"
	case alertNoApplicationProtocol:
		return "no_application_protocol"
	default:
		return "unknown"
	}
}
