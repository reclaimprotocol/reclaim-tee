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
	"github.com/google/go-sev-guest/verify/trust"
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
//	[32..64) binaryHash    — the app/binary identity hash
//
// binaryHash is a convenience copy in the AMD-signed report; the authoritative,
// non-forgeable app identity is the loader-measured PCR 8 (see the two-tier
// image: stable base UKI -> PCR 11, app -> PCR 8).
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
	// Trust both VCEK (per-chip, e.g. GCP) and VLEK (per-CSP, e.g. AWS) signing
	// keys: GCP embeds the VCEK chain in the report, but AWS signs with VLEK and
	// ships only the VLEK leaf, so the ASVK intermediate must come from our
	// roots. go-sev-guest embeds both AMD bundles; merge them per product line.
	roots, err := amdTrustedRoots()
	if err != nil {
		return nil, rd, fmt.Errorf("build AMD trusted roots: %w", err)
	}
	opts.TrustedRoots = roots
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

// amdTrustedRoots builds per-product-line AMD roots that trust BOTH VCEK and
// VLEK report signers, using go-sev-guest's embedded AMD CA bundles (no KDS
// fetch). The VCEK bundle supplies Ask+Ark; the VLEK bundle supplies the Asvk
// intermediate; merged into one ProductCerts whose X509Options picks Ask (VCEK)
// or Asvk (VLEK) per the report's signer.
func amdTrustedRoots() (map[string][]*trust.AMDRootCerts, error) {
	bundles := map[string][2][]byte{
		"Milan": {trust.AskArkMilanVcekBytes, trust.AskArkMilanVlekBytes},
		"Genoa": {trust.AskArkGenoaVcekBytes, trust.AskArkGenoaVlekBytes},
		"Turin": {trust.AskArkTurinVcekBytes, trust.AskArkTurinVlekBytes},
	}
	roots := make(map[string][]*trust.AMDRootCerts, len(bundles))
	for line, b := range bundles {
		pc := &trust.ProductCerts{}
		vlek := &trust.ProductCerts{}
		// Skip a product line whose embedded bundle won't parse (some upstream
		// bundles have trailing bytes); the lines we run on (Milan) parse fine.
		if pc.FromKDSCertBytes(b[0]) != nil || vlek.FromKDSCertBytes(b[1]) != nil {
			continue
		}
		pc.Asvk = vlek.Asvk
		roots[line] = []*trust.AMDRootCerts{{ProductLine: line, ProductCerts: pc}}
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("no AMD product roots could be built from embedded bundles")
	}
	return roots, nil
}

// marshalSEVSNPAttestation serializes an Attestation for embedding in the cert
// extension. Kept here so generate (linux-only) and any future tooling share
// one wire encoding.
func marshalSEVSNPAttestation(att *spb.Attestation) ([]byte, error) {
	return proto.Marshal(att)
}

// SelfBinaryHash returns sha256 of the currently-running executable. Used to
// fill report_data[32:64] as a convenience copy of the app identity (the
// authoritative identity is the loader-measured PCR 8).
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
