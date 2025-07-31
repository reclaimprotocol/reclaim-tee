package shared

import (
	"fmt"
	"strconv"
	"strings"
)

// TLS version constants
const (
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304
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

// CipherSuiteInfo contains metadata about a cipher suite
type CipherSuiteInfo struct {
	ID         uint16
	Name       string
	ShortName  string
	TLSVersion uint16 // VersionTLS12 or VersionTLS13
	Algorithm  string // "AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305"
	KeyLength  int    // Key length in bytes
	IVLength   int    // IV length in bytes
	AuthMethod string // "RSA", "ECDSA", or "ANY" for TLS 1.3
}

// AllCipherSuites contains complete information about all supported cipher suites
var AllCipherSuites = []CipherSuiteInfo{
	// TLS 1.3 cipher suites
	{
		ID:         TLS_AES_128_GCM_SHA256,
		Name:       "TLS_AES_128_GCM_SHA256",
		ShortName:  "AES_128_GCM",
		TLSVersion: VersionTLS13,
		Algorithm:  "AES-128-GCM",
		KeyLength:  16,
		IVLength:   12,
		AuthMethod: "ANY",
	},
	{
		ID:         TLS_AES_256_GCM_SHA384,
		Name:       "TLS_AES_256_GCM_SHA384",
		ShortName:  "AES_256_GCM",
		TLSVersion: VersionTLS13,
		Algorithm:  "AES-256-GCM",
		KeyLength:  32,
		IVLength:   12,
		AuthMethod: "ANY",
	},
	{
		ID:         TLS_CHACHA20_POLY1305_SHA256,
		Name:       "TLS_CHACHA20_POLY1305_SHA256",
		ShortName:  "CHACHA20_POLY1305",
		TLSVersion: VersionTLS13,
		Algorithm:  "ChaCha20-Poly1305",
		KeyLength:  32,
		IVLength:   12,
		AuthMethod: "ANY",
	},
	// TLS 1.2 cipher suites
	{
		ID:         TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		Name:       "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		ShortName:  "ECDHE-RSA-AES128-GCM-SHA256",
		TLSVersion: VersionTLS12,
		Algorithm:  "AES-128-GCM",
		KeyLength:  16,
		IVLength:   4, // TLS 1.2 uses 4-byte implicit IV
		AuthMethod: "RSA",
	},
	{
		ID:         TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		Name:       "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		ShortName:  "ECDHE-ECDSA-AES128-GCM-SHA256",
		TLSVersion: VersionTLS12,
		Algorithm:  "AES-128-GCM",
		KeyLength:  16,
		IVLength:   4,
		AuthMethod: "ECDSA",
	},
	{
		ID:         TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		Name:       "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		ShortName:  "ECDHE-RSA-AES256-GCM-SHA384",
		TLSVersion: VersionTLS12,
		Algorithm:  "AES-256-GCM",
		KeyLength:  32,
		IVLength:   4,
		AuthMethod: "RSA",
	},
	{
		ID:         TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		Name:       "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		ShortName:  "ECDHE-ECDSA-AES256-GCM-SHA384",
		TLSVersion: VersionTLS12,
		Algorithm:  "AES-256-GCM",
		KeyLength:  32,
		IVLength:   4,
		AuthMethod: "ECDSA",
	},
	{
		ID:         TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		Name:       "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		ShortName:  "ECDHE-RSA-CHACHA20-POLY1305",
		TLSVersion: VersionTLS12,
		Algorithm:  "ChaCha20-Poly1305",
		KeyLength:  32,
		IVLength:   12, // TLS 1.2 ChaCha20 uses 12-byte IV (same as TLS 1.3)
		AuthMethod: "RSA",
	},
	{
		ID:         TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		Name:       "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		ShortName:  "ECDHE-ECDSA-CHACHA20-POLY1305",
		TLSVersion: VersionTLS12,
		Algorithm:  "ChaCha20-Poly1305",
		KeyLength:  32,
		IVLength:   12,
		AuthMethod: "ECDSA",
	},
}

// CipherSuiteMapping maps cipher suite names to their hex IDs
var CipherSuiteMapping map[string]uint16

// CipherSuiteInfoMap maps cipher suite IDs to their info
var CipherSuiteInfoMap map[uint16]*CipherSuiteInfo

// Initialize the maps
func init() {
	CipherSuiteMapping = make(map[string]uint16)
	CipherSuiteInfoMap = make(map[uint16]*CipherSuiteInfo)

	for i := range AllCipherSuites {
		info := &AllCipherSuites[i]
		CipherSuiteInfoMap[info.ID] = info

		// Add all name variants to the mapping
		CipherSuiteMapping[info.Name] = info.ID
		CipherSuiteMapping[info.ShortName] = info.ID
	}
}

// ParseCipherSuite converts a cipher suite string (hex or name) to uint16 ID
func ParseCipherSuite(cipherSuite string) (uint16, error) {
	if cipherSuite == "" {
		return 0, fmt.Errorf("empty cipher suite")
	}

	// Handle hex format (0x1234)
	if strings.HasPrefix(cipherSuite, "0x") {
		val, err := strconv.ParseUint(cipherSuite[2:], 16, 16)
		if err != nil {
			return 0, fmt.Errorf("invalid hex cipher suite '%s': %v", cipherSuite, err)
		}
		return uint16(val), nil
	}

	// Handle named cipher suites
	if id, found := CipherSuiteMapping[cipherSuite]; found {
		return id, nil
	}

	return 0, fmt.Errorf("unknown cipher suite '%s'", cipherSuite)
}

// GetCipherSuiteName returns the human-readable name for a cipher suite ID
func GetCipherSuiteName(id uint16) string {
	if info, found := CipherSuiteInfoMap[id]; found {
		return info.Name
	}
	return fmt.Sprintf("0x%04x", id)
}

// GetCipherSuiteInfo returns detailed information about a cipher suite
func GetCipherSuiteInfo(id uint16) (*CipherSuiteInfo, error) {
	if info, found := CipherSuiteInfoMap[id]; found {
		return info, nil
	}
	return nil, fmt.Errorf("unknown cipher suite: 0x%04x", id)
}

// IsValidCipherSuite checks if a cipher suite string is valid
func IsValidCipherSuite(cipherSuite string) bool {
	_, err := ParseCipherSuite(cipherSuite)
	return err == nil
}

// ValidateCipherSuiteCompatibility checks if a cipher suite is compatible with a TLS version
func ValidateCipherSuiteCompatibility(cipherSuiteID uint16, tlsVersion string) error {
	info, err := GetCipherSuiteInfo(cipherSuiteID)
	if err != nil {
		return err
	}

	switch tlsVersion {
	case "1.2":
		if info.TLSVersion != VersionTLS12 {
			return fmt.Errorf("cipher suite 0x%04x (%s) is not compatible with TLS 1.2",
				cipherSuiteID, info.Name)
		}
	case "1.3":
		if info.TLSVersion != VersionTLS13 {
			return fmt.Errorf("cipher suite 0x%04x (%s) is not compatible with TLS 1.3",
				cipherSuiteID, info.Name)
		}
	case "":
		// Auto-negotiation - allow any cipher suite
		break
	default:
		return fmt.Errorf("unknown TLS version: %s", tlsVersion)
	}

	return nil
}

// GetSupportedCipherSuites returns a list of supported cipher suites for a TLS version
func GetSupportedCipherSuites(tlsVersion string) []CipherSuiteInfo {
	var suites []CipherSuiteInfo

	for _, info := range AllCipherSuites {
		if err := ValidateCipherSuiteCompatibility(info.ID, tlsVersion); err == nil {
			suites = append(suites, info)
		}
	}

	return suites
}

// GetCipherSuiteIDs returns just the IDs for a TLS version (for use in TLS config)
func GetCipherSuiteIDs(tlsVersion string) []uint16 {
	var ids []uint16

	for _, info := range GetSupportedCipherSuites(tlsVersion) {
		ids = append(ids, info.ID)
	}

	return ids
}

// GetAlgorithmName returns the algorithm name for a cipher suite
func GetAlgorithmName(cipherSuite uint16) string {
	if info, found := CipherSuiteInfoMap[cipherSuite]; found {
		return info.Algorithm
	}
	return fmt.Sprintf("Unknown-0x%04x", cipherSuite)
}

// GetKeyAndIVLengths returns key and IV lengths for a cipher suite
func GetKeyAndIVLengths(cipherSuite uint16) (keyLen, ivLen int, err error) {
	info, err := GetCipherSuiteInfo(cipherSuite)
	if err != nil {
		return 0, 0, err
	}
	return info.KeyLength, info.IVLength, nil
}

// IsTLS12CipherSuite checks if a cipher suite belongs to TLS 1.2
func IsTLS12CipherSuite(cipherSuite uint16) bool {
	info, found := CipherSuiteInfoMap[cipherSuite]
	if !found {
		return false
	}
	return info.TLSVersion == VersionTLS12
}

// IsTLS12AESGCMCipherSuite checks if a cipher suite is a TLS 1.2 AES-GCM cipher suite
func IsTLS12AESGCMCipherSuite(cipherSuite uint16) bool {
	switch cipherSuite {
	case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, // 0xc02f
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, // 0xc02b
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,   // 0xc030
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: // 0xc02c
		return true
	default:
		return false
	}
}

// IsTLS12ChaCha20Poly1305CipherSuite checks if a cipher suite is a TLS 1.2 ChaCha20-Poly1305 cipher suite
func IsTLS12ChaCha20Poly1305CipherSuite(cipherSuite uint16) bool {
	switch cipherSuite {
	case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, // 0xcca8
		TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: // 0xcca9
		return true
	default:
		return false
	}
}

// IsTLS13CipherSuite checks if a cipher suite belongs to TLS 1.3
func IsTLS13CipherSuite(cipherSuite uint16) bool {
	info, found := CipherSuiteInfoMap[cipherSuite]
	if !found {
		return false
	}
	return info.TLSVersion == VersionTLS13
}

// GetTLSVersion returns the TLS version for a cipher suite
func GetTLSVersion(cipherSuite uint16) uint16 {
	info, found := CipherSuiteInfoMap[cipherSuite]
	if !found {
		return 0 // Unknown
	}
	return info.TLSVersion
}
