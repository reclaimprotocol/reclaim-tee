package clientlib

import (
	"fmt"
	"log"
	"tee-mpc/shared"
)

// handleAttestationResponse handles attestation response messages from TEE_K or TEE_T
func (c *Client) handleAttestationResponse(msg *shared.Message) {
	var attestResp shared.AttestationResponseData
	if err := msg.UnmarshalData(&attestResp); err != nil {
		log.Printf("[Client] Failed to unmarshal attestation response: %v", err)
		return
	}

	if !attestResp.Success {
		// Only log attestation failures in enclave mode - they're expected in standalone mode
		if c.isEnclaveMode() {
			log.Printf("[Client] Attestation request failed: %s", attestResp.ErrorMessage)
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
		log.Printf("[Client] TEE_K attestation verified successfully")
	} else {
		// Try as TEE_T
		publicKey, err = c.verifyAttestation(attestResp.AttestationDoc, "tee_t")
		if err == nil {
			sourceTEE = "TEE_T"
			c.teetAttestationPublicKey = publicKey
			log.Printf("[Client] TEE_T attestation verified successfully")
		} else {
			log.Printf("[Client] Failed to verify attestation as either TEE_K or TEE_T: %v", err)
			return
		}
	}

	fmt.Printf("[Client] Received successful attestation response from %s (%d bytes)\n", sourceTEE, len(attestResp.AttestationDoc))

	// Check if we have both attestations and can proceed
	if c.teekAttestationPublicKey != nil && c.teetAttestationPublicKey != nil {
		c.attestationVerified = true
		fmt.Printf("[Client] Successfully verified both TEE_K and TEE_T attestations via WebSocket\n")

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

		fmt.Printf("[Client] TEE_K public key (key material): %x\n", teekDisplayBytes[:min(32, len(teekDisplayBytes))])
		fmt.Printf("[Client] TEE_T public key (key material): %x\n", teetDisplayBytes[:min(32, len(teetDisplayBytes))])
		fmt.Printf("[Client] TEE_K full key length: %d bytes\n", len(c.teekAttestationPublicKey))
		fmt.Printf("[Client] TEE_T full key length: %d bytes\n", len(c.teetAttestationPublicKey))

		// Check if we now have transcript public keys and can compare
		if c.teekTranscriptPublicKey != nil && c.teetTranscriptPublicKey != nil && !c.publicKeyComparisonDone {
			log.Printf("[Client] Both attestation and transcript public keys available - verifying...")
			if err := c.verifyAttestationPublicKeys(); err != nil {
				log.Printf("[Client] Attestation public key verification failed: %v", err)
				fmt.Printf("[Client] ATTESTATION VERIFICATION FAILED: %v\n", err)
			} else {
				log.Printf("[Client] Attestation public key verification successful")
				fmt.Printf("[Client] ATTESTATION VERIFICATION SUCCESSFUL - transcripts are from verified enclaves\n")
			}
		}
	}
}
