package client

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"tee-mpc/shared"

	jwt "github.com/golang-jwt/jwt/v5"
)

// GCP JWKS endpoints for public keys
const (
	gcpConfidentialSpaceJWKSURL = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"
)

// JWK represents a JSON Web Key
type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWTHeader represents the JWT header
type JWTHeader struct {
	Alg string        `json:"alg"`
	Kid string        `json:"kid"`
	Typ string        `json:"typ"`
	X5c []interface{} `json:"x5c"` // Certificate chain for PKI tokens
}

// GCPAttestationClaims represents the JWT claims
type GCPAttestationClaims struct {
	Aud string `json:"aud"` // Audience - contains our custom data
	Azp string `json:"azp"` // Authorized party
	Exp int64  `json:"exp"` // Expiration time
	Iat int64  `json:"iat"` // Issued at
	Iss string `json:"iss"` // Issuer
	Sub string `json:"sub"` // Subject (service account ID)
}

// VerifyGCPConfidentialSpaceAttestation verifies a Confidential Space attestation token
// Supports both x5c (PKI) and kid (OIDC) token types
func VerifyGCPConfidentialSpaceAttestation(jwtToken string) (publicKey []byte, err error) {
	// Parse JWT header to determine token type
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// Verify based on token type (x5c vs kid)
	// Check for x5c first since PKI tokens may also have kid field
	if len(header.X5c) > 0 {
		// PKI token with x5c - use certificate chain verification
		attestor, err := shared.NewGoogleAttestor()
		if err != nil {
			return nil, fmt.Errorf("failed to create Google attestor: %w", err)
		}

		if err = attestor.Validate([]byte(jwtToken)); err != nil {
			return nil, fmt.Errorf("GCP Confidential Space attestation validation failed: %w", err)
		}
	} else {
		return nil, errors.New("x5c header missing")
	}

	// Parse claims to extract ETH address
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	var claims jwt.MapClaims
	_, _, err = parser.ParseUnverified(jwtToken, &claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// Extract ETH address from eat_nonce (custom tokens) or audience (default tokens)
	if eatNonce, ok := claims["eat_nonce"].(string); ok && eatNonce != "" {
		// Custom token with nonce as a string
		ethAddr := strings.TrimSpace(eatNonce)

		// Check if nonce contains the prefix pattern (tee_k_public_key: or tee_t_public_key:)
		if strings.Contains(ethAddr, "public_key:") {
			// Extract just the address part after the colon
			parts := strings.Split(ethAddr, ":")
			if len(parts) >= 2 {
				ethAddr = parts[len(parts)-1] // Take the last part in case of multiple colons
			}
		}
		// Convert hex string to bytes
		if strings.HasPrefix(ethAddr, "0x") || strings.HasPrefix(ethAddr, "0X") {
			ethAddr = ethAddr[2:]
		}
		// Convert to lowercase for hex parsing (handles EIP-55 checksum addresses)
		ethAddr = strings.ToLower(ethAddr)

		if len(ethAddr) == 40 {
			addr := make([]byte, 20)
			for i := 0; i < 20; i++ {
				_, err = fmt.Sscanf(ethAddr[i*2:i*2+2], "%02x", &addr[i])
				if err != nil {
					return nil, err
				}
			}
			return addr, nil
		}
	}

	return nil, errors.New("invalid JWT claims")

}
