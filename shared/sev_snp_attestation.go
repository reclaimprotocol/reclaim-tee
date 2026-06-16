//go:build !mobile

package shared

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	"google.golang.org/protobuf/proto"
)

// SEVSNPIdentityPrefix namespaces a SEV-SNP launch measurement in the router
// allowlist and the EXPECTED_PEER_IMAGE_DIGEST pin, the way "sha256:" namespaces
// a Confidential Space container digest. The value after the prefix is the
// 48-byte launch measurement as 96 lowercase hex chars.
const SEVSNPIdentityPrefix = "snp-measurement:"

// SEVSNPIdentity formats a launch measurement as an allowlist identity string.
func SEVSNPIdentity(measurement []byte) string {
	return SEVSNPIdentityPrefix + hex.EncodeToString(measurement)
}

// BuildSEVSNPReportData lays out the 64-byte user-controlled report_data field:
//
//	[ 0..32) sha256(SPKI)  — binds the TLS keypair, same role as the CS eat_nonce
//	[32..64) binaryHash    — cross-cloud-stable binary identity (dm-verity era)
//
// In minimal-hardening mode binaryHash is the TEE's self-reported binary hash
// and is not yet anchored by the launch measurement; see Appendix C.
func BuildSEVSNPReportData(spkiHash [32]byte, binaryHash [32]byte) [64]byte {
	var rd [64]byte
	copy(rd[:32], spkiHash[:])
	copy(rd[32:], binaryHash[:])
	return rd
}

// SEVSNPReportData carries the parsed halves of a verified report_data field.
type SEVSNPReportData struct {
	SPKIHash   [32]byte
	BinaryHash [32]byte
}

// VerifySEVSNPAttestation unmarshals a marshaled go-sev-guest Attestation,
// verifies the VCEK->ASK->ARK chain to the AMD root, and returns the launch
// measurement and the parsed report_data. The cert chain is embedded in the
// attestation (extended report), so verification works without contacting the
// AMD KDS when allowOffline is true.
//
// It does NOT check the SPKI binding or the launch measurement against any
// expected value — that policy lives in the RA-TLS verifier, mirroring how the
// CS path returns image_digest for the caller to pin.
func VerifySEVSNPAttestation(raw []byte, allowOffline bool) (measurement []byte, rd SEVSNPReportData, err error) {
	if len(raw) == 0 {
		return nil, rd, fmt.Errorf("empty SEV-SNP attestation")
	}
	att := &spb.Attestation{}
	if err := proto.Unmarshal(raw, att); err != nil {
		return nil, rd, fmt.Errorf("unmarshal SEV-SNP attestation: %w", err)
	}

	opts := verify.DefaultOptions()
	if allowOffline {
		opts.DisableCertFetching = true
	}
	if err := verify.SnpAttestation(att, opts); err != nil {
		return nil, rd, fmt.Errorf("SEV-SNP chain verification failed: %w", err)
	}

	report := att.GetReport()
	rdBytes := report.GetReportData()
	if len(rdBytes) != 64 {
		return nil, rd, fmt.Errorf("report_data is %d bytes, want 64", len(rdBytes))
	}
	copy(rd.SPKIHash[:], rdBytes[:32])
	copy(rd.BinaryHash[:], rdBytes[32:])
	return report.GetMeasurement(), rd, nil
}

// marshalSEVSNPAttestation serializes an Attestation for embedding in the cert
// extension. Kept here so generate (linux-only) and any future tooling share
// one wire encoding.
func marshalSEVSNPAttestation(att *spb.Attestation) ([]byte, error) {
	return proto.Marshal(att)
}

// SelfBinaryHash returns sha256 of the currently-running executable. Used to
// fill report_data[32:64] until dm-verity anchors binary identity in the launch
// measurement.
func SelfBinaryHash() ([32]byte, error) {
	var sum [32]byte
	exe, err := os.Executable()
	if err != nil {
		return sum, fmt.Errorf("locate self: %w", err)
	}
	f, err := os.Open(exe)
	if err != nil {
		return sum, fmt.Errorf("open self: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return sum, fmt.Errorf("hash self: %w", err)
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// spkiSha256 is a thin alias used by the RA-TLS verifier so SEV-SNP and CS
// paths compute the SPKI hash identically.
func spkiSha256(spkiDER []byte) [32]byte {
	return sha256.Sum256(spkiDER)
}
