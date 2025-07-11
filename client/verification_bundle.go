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

	// Transcripts – only include if received
	if c.teekSignedTranscript != nil {
		bundle.Transcripts.TEEK = c.teekSignedTranscript
	}
	if c.teetSignedTranscript != nil {
		bundle.Transcripts.TEET = c.teetSignedTranscript
	}

	// Streams (order by seq for deterministic output)
	if len(c.signedRedactedStreams) > 0 {
		sort.Slice(c.signedRedactedStreams, func(i, j int) bool {
			return c.signedRedactedStreams[i].SeqNum < c.signedRedactedStreams[j].SeqNum
		})
		bundle.RedactedStreams = c.signedRedactedStreams
	}

	// Proof commitment opening
	if c.proofStream != nil {
		bundle.ProofStream = c.proofStream
	}
	if c.proofKey != nil {
		bundle.ProofKey = c.proofKey
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
