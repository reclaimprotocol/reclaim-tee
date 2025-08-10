package clientlib

import (
	"fmt"
	"tee-mpc/shared"

	"go.uber.org/zap"
)

// handleAttestationResponse handles attestation response messages from TEE_K or TEE_T
func (c *Client) handleAttestationResponse(msg *shared.Message) {
	var attestResp shared.AttestationResponseData
	if err := msg.UnmarshalData(&attestResp); err != nil {
		c.logger.Error("Failed to unmarshal attestation response", zap.Error(err))
		return
	}

	if !attestResp.Success {
		// Only log attestation failures in enclave mode - they're expected in standalone mode
		if c.isEnclaveMode() {
			c.logger.Error("Attestation request failed", zap.String("error_message", attestResp.ErrorMessage))
		}
		return
	}

	// Single-path verification using Source
	var sourceTEE string
	var publicKey []byte
	var err error
	switch attestResp.Source {
	case "tee_k":
		publicKey, err = c.verifyAttestation(attestResp.AttestationDoc, "tee_k")
		if err != nil {
			c.logger.Error("TEE_K attestation verification failed", zap.Error(err))
			return
		}
		sourceTEE = "TEE_K"
		c.teekAttestationPublicKey = publicKey
		c.logger.Info("TEE_K attestation verified successfully")
	case "tee_t":
		publicKey, err = c.verifyAttestation(attestResp.AttestationDoc, "tee_t")
		if err != nil {
			c.logger.Error("TEE_T attestation verification failed", zap.Error(err))
			return
		}
		sourceTEE = "TEE_T"
		c.teetAttestationPublicKey = publicKey
		c.logger.Info("TEE_T attestation verified successfully")
	default:
		c.logger.Error("Unknown attestation source", zap.String("source", attestResp.Source))
		return
	}

	c.logger.Info("Received successful attestation response", zap.String("source_tee", sourceTEE), zap.Int("attestation_bytes", len(attestResp.AttestationDoc)))

	// Check if we have both attestations and can proceed
	if c.teekAttestationPublicKey != nil && c.teetAttestationPublicKey != nil {
		c.attestationVerified = true
		c.logger.Info("Successfully verified both TEE_K and TEE_T attestations via WebSocket")

		// Display public keys in a more distinguishable way
		// For P-256 keys, skip the common DER header (first ~26 bytes) and show the actual key material
		teekDisplayBytes := c.teekAttestationPublicKey
		if len(c.teekAttestationPublicKey) > 26 {
			teekDisplayBytes = c.teekAttestationPublicKey[26:] // Skip DER header, show actual key material
		}

		teetDisplayBytes := c.teetAttestationPublicKey
		if len(c.teetAttestationPublicKey) > 26 {
			teetDisplayBytes = c.teetAttestationPublicKey[26:] // Skip DER header, show actual key material
		}

		c.logger.Info("TEE_K public key (key material)", zap.String("key_material", fmt.Sprintf("%x", teekDisplayBytes[:min(32, len(teekDisplayBytes))])))
		c.logger.Info("TEE_T public key (key material)", zap.String("key_material", fmt.Sprintf("%x", teetDisplayBytes[:min(32, len(teetDisplayBytes))])))
		c.logger.Info("TEE_K full key length", zap.Int("key_bytes", len(c.teekAttestationPublicKey)))
		c.logger.Info("TEE_T full key length", zap.Int("key_bytes", len(c.teetAttestationPublicKey)))

		// DEPRECATED: Attestation verification now done directly in SignedMessage
		c.logger.Info("Attestation public key verification successful")
		fmt.Printf("[Client] ATTESTATION VERIFICATION SUCCESSFUL - transcripts are from verified enclaves\n")
	}
}
