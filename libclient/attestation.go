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

	// Try to verify as TEE_K first
	var sourceTEE string
	var publicKey []byte
	var err error

	publicKey, err = c.verifyAttestation(attestResp.AttestationDoc, "tee_k")
	if err == nil {
		sourceTEE = "TEE_K"
		c.teekAttestationPublicKey = publicKey
		c.logger.Info("TEE_K attestation verified successfully")
	} else {
		// Try as TEE_T
		publicKey, err = c.verifyAttestation(attestResp.AttestationDoc, "tee_t")
		if err == nil {
			sourceTEE = "TEE_T"
			c.teetAttestationPublicKey = publicKey
			c.logger.Info("TEE_T attestation verified successfully")
		} else {
			c.logger.Error("Failed to verify attestation as either TEE_K or TEE_T", zap.Error(err))
			return
		}
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

		// Check if we now have transcript public keys and can compare
		if c.teekTranscriptPublicKey != nil && c.teetTranscriptPublicKey != nil && !c.publicKeyComparisonDone {
			c.logger.Info("Both attestation and transcript public keys available - verifying")
			if err := c.verifyAttestationPublicKeys(); err != nil {
				c.logger.Error("Attestation public key verification failed", zap.Error(err))
				fmt.Printf("[Client] ATTESTATION VERIFICATION FAILED: %v\n", err)
			} else {
				c.logger.Info("Attestation public key verification successful")
				fmt.Printf("[Client] ATTESTATION VERIFICATION SUCCESSFUL - transcripts are from verified enclaves\n")
			}
		}
	}
}
