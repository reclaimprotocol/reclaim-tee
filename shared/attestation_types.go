package shared

// AttestationReport represents a generic attestation envelope with runtime signing key
// Type: "nitro" (AWS Nitro) or "gcp" (Google CVM)
// Report: raw provider-specific attestation bytes
// SigningKey: TEE_T runtime ECDSA public key (DER) to be used by clients
type AttestationReport struct {
	Type       string `json:"type"` // "nitro" or "gcp"
	Report     []byte `json:"report"`
	SigningKey []byte `json:"signing_key"`
}
