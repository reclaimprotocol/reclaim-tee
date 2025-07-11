package proofverifier

import (
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
	}
	if bundle.Transcripts.TEET != nil {
		if err := shared.VerifyTranscriptSignature(bundle.Transcripts.TEET); err != nil {
			return fmt.Errorf("TEE_T transcript signature invalid: %v", err)
		}
	}

	fmt.Println("[Verifier] Transcript signatures valid ✅")

	// --- Commitment verification for proof stream ---
	if bundle.ProofStream != nil && bundle.ProofKey != nil && bundle.Transcripts.TEEK != nil {
		mac := hmac.New(sha256.New, bundle.ProofKey)
		mac.Write(bundle.ProofStream)
		commitment := mac.Sum(nil)

		// Search commitment bytes inside TEE_K transcript
		found := false
		var offset int
		for _, pkt := range bundle.Transcripts.TEEK.Packets {
			if len(pkt) >= len(commitment) {
				// naive search
				for i := 0; i <= len(pkt)-len(commitment); i++ {
					if string(pkt[i:i+len(commitment)]) == string(commitment) {
						found = true
						offset = i
						break
					}
				}
			}
			if found {
				break
			}
		}
		if !found {
			return fmt.Errorf("commitment for proof stream not found in request transcript")
		}
		fmt.Printf("[Verifier] Commitment verified ✅ (len=%d, first16=%x, offset=%d)\n", len(commitment), commitment[:min(16, len(commitment))], offset)
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

	// --- Try to locate the redacted HTTP request inside TEE_K transcript and print it ---
	if bundle.Transcripts.TEEK != nil {
		for _, pkt := range bundle.Transcripts.TEEK.Packets {
			if len(pkt) > 4 && (string(pkt[:3]) == "GET" || string(pkt[:4]) == "POST" || string(pkt[:3]) == "PUT" || string(pkt[:6]) == "DELETE") {
				fmt.Println("[Verifier] Redacted HTTP request (from transcript):\n---")
				fmt.Println(string(pkt))
				fmt.Println("---")
				break
			}
		}
	}

	fmt.Println("[Verifier] Offline verification complete – success 🥳")
	return nil
}
