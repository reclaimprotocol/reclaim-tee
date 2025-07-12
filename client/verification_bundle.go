package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"tee-mpc/shared"
)

// BuildVerificationBundle collects all artefacts gathered during protocol
// execution and serialises them to a JSON file. The function returns the
// path of the file written or an error.
func (c *Client) BuildVerificationBundle(path string) error {
	bundle := shared.VerificationBundle{}

	// Handshake keys (may be nil in standalone mode until enclave support)
	if c.handshakeDisclosure != nil {
		// Convert to shared type (they share identical fields)
		bundle.HandshakeKeys = shared.HandshakeSecrets{
			HandshakeKey: c.handshakeDisclosure.HandshakeKey,
			HandshakeIV:  c.handshakeDisclosure.HandshakeIV,
			CipherSuite:  c.handshakeDisclosure.CipherSuite,
			Algorithm:    c.handshakeDisclosure.Algorithm,
		}
	}

	// TEE_K transcript – convert from SignedTranscript to TEEKTranscript
	if c.teekSignedTranscript != nil {
		// Order streams by seq for deterministic output
		orderedStreams := make([]shared.SignedRedactedDecryptionStream, len(c.signedRedactedStreams))
		copy(orderedStreams, c.signedRedactedStreams)
		if len(orderedStreams) > 0 {
			sort.Slice(orderedStreams, func(i, j int) bool {
				return orderedStreams[i].SeqNum < orderedStreams[j].SeqNum
			})
		}

		// Use comprehensive signature (covers all data including redacted streams)
		signature := c.teekSignedTranscript.Signature

		bundle.Transcripts.TEEK = &shared.TEEKTranscript{
			Packets:         c.teekSignedTranscript.Packets,
			RequestMetadata: c.teekSignedTranscript.RequestMetadata,
			RedactedStreams: orderedStreams,
			Signature:       signature,
			PublicKey:       c.teekSignedTranscript.PublicKey,
		}
	}

	// TEE_T transcript – convert from SignedTranscript to TEETTranscript
	if c.teetSignedTranscript != nil {
		bundle.Transcripts.TEET = &shared.TEETTranscript{
			Packets:   c.teetSignedTranscript.Packets,
			Signature: c.teetSignedTranscript.Signature,
			PublicKey: c.teetSignedTranscript.PublicKey,
		}
	}

	// Proof commitment opening
	if c.proofStream != nil || c.proofKey != nil {
		bundle.Opening = &shared.Opening{
			ProofStream: c.proofStream,
			ProofKey:    c.proofKey,
		}
	}

	// Attestations (if any; nil slices marshal as null, omit empty)
	bundle.AttestationTEEK = c.teekAttestationPublicKey // TODO: replace with full doc when available
	bundle.AttestationTEET = c.teetAttestationPublicKey

	// Write to file
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create bundle file: %v", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&bundle); err != nil {
		return fmt.Errorf("failed to encode bundle: %v", err)
	}

	return nil
}
