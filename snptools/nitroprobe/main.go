// nitroprobe validates shared.RequestNitroTPMDocument (the Go port of
// nitro-tpm-attest) on a NitroTPM instance: it requests a document with a fixed
// nonce and writes it out for comparison against the AWS Rust tool's output.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

func main() {
	nonce := sha256.Sum256([]byte("reclaim-nitroprobe-nonce"))
	if err := os.WriteFile("/tmp/nonce.bin", nonce[:], 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write nonce:", err)
		os.Exit(1)
	}
	doc, err := shared.RequestNitroTPMDocument(nil, nonce[:], nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
	if err := os.WriteFile("/tmp/go-doc.bin", doc, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write doc:", err)
		os.Exit(1)
	}
	fmt.Printf("OK: %d-byte NitroTPM document (nonce sha256=%s)\n", len(doc), hex.EncodeToString(nonce[:8]))
}
