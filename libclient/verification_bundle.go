package clientlib

import (
	"fmt"
	"os"

	teeproto "tee-mpc/proto"

	"google.golang.org/protobuf/proto"
)

// BuildVerificationBundle collects all artefacts gathered during protocol
// execution and serialises them to a protobuf file. The function returns the
// path of the file written or an error.
// SECURITY: This function validates that required data is present before creating bundle
func (c *Client) BuildVerificationBundle(path string) error {
	bundle := &teeproto.VerificationBundlePB{}

	// SECURITY: Validate that we have the required signed messages
	if c.teekSignedMessage == nil {
		return fmt.Errorf("SECURITY ERROR: missing TEE_K signed message - protocol incomplete")
	}
	if c.teetSignedMessage == nil {
		return fmt.Errorf("SECURITY ERROR: missing TEE_T signed message - protocol incomplete")
	}

	// Handshake keys (may be nil in standalone mode until enclave support)
	if c.handshakeDisclosure != nil {
		bundle.HandshakeKeys = &teeproto.HandshakeSecrets{
			HandshakeKey: c.handshakeDisclosure.HandshakeKey,
			HandshakeIv:  c.handshakeDisclosure.HandshakeIV,
			CipherSuite:  uint32(c.handshakeDisclosure.CipherSuite),
			Algorithm:    c.handshakeDisclosure.Algorithm,
		}
	}

	// TEE_K signed message (K_OUTPUT) - use original protobuf SignedMessage
	bundle.TeekSigned = c.teekSignedMessage

	// TEE_T signed message (T_OUTPUT) - use original protobuf SignedMessage
	bundle.TeetSigned = c.teetSignedMessage

	// Proof commitment opening
	if c.proofStream != nil || c.proofKey != nil {
		bundle.Opening = &teeproto.Opening{
			ProofStream: c.proofStream,
			ProofKey:    c.proofKey,
		}
	}

	// Attestations not included
	bundle.AttestationTeeK = nil
	bundle.AttestationTeeT = nil

	// Write protobuf to file
	data, err := proto.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("failed to marshal bundle: %v", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write bundle file: %v", err)
	}

	return nil
}
