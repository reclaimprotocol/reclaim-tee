package proofverifier

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"tee-mpc/shared"
)

// Validate loads the verification bundle from the given file path and performs
// a minimal set of checks (transcript signature verification, redacted stream
// XOR match against redacted response). It returns an error if any check fails.
func Validate(bundlePath string) error {
	fmt.Printf("[Verifier] Loading verification bundle: %s\n", bundlePath)

	f, err := os.Open(bundlePath)
	if err != nil {
		return fmt.Errorf("cannot open bundle: %v", err)
	}
	defer f.Close()

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return fmt.Errorf("failed to read bundle: %v", err)
	}

	var bundle shared.VerificationBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("failed to decode bundle JSON: %v", err)
	}

	// --- Transcript signature verification ---
	if bundle.Transcripts.TEEK != nil {
		if err := shared.VerifyTranscriptSignature(bundle.Transcripts.TEEK); err != nil {
			return fmt.Errorf("TEE_K transcript signature invalid: %v", err)
		}

		// Verify master signature over all TEE_K data
		if len(bundle.Transcripts.TEEK.MasterSignature) > 0 {
			if err := shared.VerifyMasterSignature(bundle.Transcripts.TEEK, bundle.RedactedStreams); err != nil {
				return fmt.Errorf("TEE_K master signature invalid: %v", err)
			}
		}
	}
	if bundle.Transcripts.TEET != nil {
		if err := shared.VerifyTranscriptSignature(bundle.Transcripts.TEET); err != nil {
			return fmt.Errorf("TEE_T transcript signature invalid: %v", err)
		}
	}

	if len(bundle.Transcripts.TEEK.MasterSignature) > 0 {
		fmt.Println("[Verifier] Master signature verification successful")
	} else {
		fmt.Println("[Verifier] Transcript signatures valid")
	}

	// --- Commitment verification for proof stream ---
	if bundle.ProofStream != nil && bundle.ProofKey != nil && bundle.Transcripts.TEEK != nil {
		mac := hmac.New(sha256.New, bundle.ProofKey)
		mac.Write(bundle.ProofStream)
		expectedCommitment := mac.Sum(nil)

		// Verify commitment directly from request metadata
		if bundle.Transcripts.TEEK.RequestMetadata == nil {
			return fmt.Errorf("TEE_K request metadata missing")
		}

		actualCommitment := bundle.Transcripts.TEEK.RequestMetadata.CommSP
		if len(actualCommitment) != len(expectedCommitment) {
			return fmt.Errorf("commitment length mismatch: expected %d bytes, got %d bytes",
				len(expectedCommitment), len(actualCommitment))
		}

		if !bytes.Equal(expectedCommitment, actualCommitment) {
			return fmt.Errorf("commitment verification failed: values do not match")
		}

		fmt.Printf("[Verifier] Commitment verified ✅ (len=%d, first16=%x)\n",
			len(expectedCommitment), expectedCommitment[:min(16, len(expectedCommitment))])
		fmt.Printf("[Verifier]   ProofStream len=%d, ProofKey len=%d\n", len(bundle.ProofStream), len(bundle.ProofKey))
	} else {
		fmt.Println("[Verifier] Proof stream/key or TEE_K transcript missing – skipping commitment verification")
	}

	// --- Redacted response reconstruction check ---
	if bundle.Transcripts.TEET == nil {
		fmt.Println("[Verifier] No TEET transcript present – skipping stream check")
		return nil
	}
	// Build ordered slice of ciphertexts (application data) from TEET transcript
	var ciphertexts [][]byte
	for _, pkt := range bundle.Transcripts.TEET.Packets {
		if len(pkt) < 5+16 || pkt[0] != 0x17 {
			continue
		}
		ctLen := len(pkt) - 5 - 16
		if ctLen <= 0 {
			continue
		}
		ciphertexts = append(ciphertexts, pkt[5:5+ctLen])
	}

	// Reconstruct plaintext by walking streams and finding the next ciphertext with matching length
	var reconstructed []byte
	cipherIdx := 0
	for _, stream := range bundle.RedactedStreams {
		// advance cipherIdx until length matches
		for cipherIdx < len(ciphertexts) && len(ciphertexts[cipherIdx]) != len(stream.RedactedStream) {
			cipherIdx++
		}
		if cipherIdx >= len(ciphertexts) {
			return fmt.Errorf("no ciphertext of length %d found for stream seq %d", len(stream.RedactedStream), stream.SeqNum)
		}
		cipher := ciphertexts[cipherIdx]
		plain := make([]byte, len(cipher))
		for i := range cipher {
			plain[i] = cipher[i] ^ stream.RedactedStream[i]
		}
		reconstructed = append(reconstructed, plain...)
		cipherIdx++
	}

	fmt.Println("[Verifier] Reconstructed redacted response:\n---\n" + string(reconstructed) + "\n---")
	fmt.Println("[Verifier] Redacted streams applied successfully ✅")

	// --- Verify redaction ranges authenticity ---
	if bundle.Transcripts.TEEK != nil && bundle.Transcripts.TEEK.RequestMetadata != nil {
		signedRanges := bundle.Transcripts.TEEK.RequestMetadata.RedactionRanges
		bundleRanges := bundle.RedactionRanges

		// Check if redaction ranges in bundle match the ones signed by TEE_K
		if len(bundleRanges) != len(signedRanges) {
			return fmt.Errorf("redaction ranges mismatch: bundle has %d ranges, TEE_K signed %d ranges", len(bundleRanges), len(signedRanges))
		}

		for i, bundleRange := range bundleRanges {
			signedRange := signedRanges[i]
			if bundleRange.Start != signedRange.Start || bundleRange.Length != signedRange.Length || bundleRange.Type != signedRange.Type {
				return fmt.Errorf("redaction range %d mismatch: bundle=[%d:%d,%s] vs signed=[%d:%d,%s]",
					i, bundleRange.Start, bundleRange.Length, bundleRange.Type,
					signedRange.Start, signedRange.Length, signedRange.Type)
			}
		}

		fmt.Printf("[Verifier] Redaction ranges verified ✅ (TEE_K signed %d ranges)\n", len(signedRanges))
	} else if len(bundle.RedactionRanges) > 0 {
		fmt.Println("[Verifier] Warning: Bundle contains redaction ranges but no signed ranges from TEE_K")
	}

	// --- Display the redacted HTTP request ---
	if len(bundle.RedactedRequest) > 0 {
		// Create pretty-printed version with redactions applied
		pretty := append([]byte(nil), bundle.RedactedRequest...)
		for _, r := range bundle.RedactionRanges {
			end := r.Start + r.Length
			if r.Start < 0 || end > len(pretty) {
				continue
			}
			for i := r.Start; i < end; i++ {
				pretty[i] = '*'
			}
		}
		fmt.Println("[Verifier] Redacted HTTP request (pretty):\n---")
		fmt.Println(string(pretty))
		fmt.Println("---")
	} else if bundle.Transcripts.TEEK != nil && bundle.Transcripts.TEEK.RequestMetadata != nil {
		// Display redacted request from transcript metadata
		fmt.Println("[Verifier] Redacted HTTP request (from metadata):\n---")
		fmt.Println(string(bundle.Transcripts.TEEK.RequestMetadata.RedactedRequest))
		fmt.Println("---")
	} else {
		fmt.Println("[Verifier] No redacted request data available")
	}

	fmt.Println("[Verifier] Offline verification complete – success 🥳")
	return nil
}
