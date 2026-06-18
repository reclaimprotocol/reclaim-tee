//go:build !mobile

package shared

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"fmt"

	"github.com/google/go-sev-guest/verify"
	tpmpb "github.com/google/go-tpm-tools/proto/attest"
	tpmprotopb "github.com/google/go-tpm-tools/proto/tpm"
	gquote "github.com/google/go-tpm-tools/quote"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/proto"
)

// Google's vTPM EK/AK CA (DER). The GCE attestation key cert chains to these;
// trusting them is what proves the AK is a genuine, restricted GCE vTPM key
// (so its PCR quote can't be forged). This is the residual Google trust root
// for code identity on GCP — unavoidable on a managed cloud.
//
//go:embed gcp_vtpm_ca_root.crt
var gcpVTPMRootDER []byte

//go:embed gcp_vtpm_ca_intermediate.crt
var gcpVTPMIntermediateDER []byte

// PCRs holding the two-tier code identity: PCR 8 = app bundle (loader-measured),
// PCR 11 = base UKI (sd-stub-measured).
const (
	combinedAppPCR  = 8
	combinedBasePCR = 11
)

// SEVSNPPCRIdentityPrefix namespaces the combined code identity in the allowlist
// and EXPECTED_PEER_IMAGE_DIGEST pin. The value is sha256(PCR11 || PCR8) hex —
// committing to BOTH the base UKI and the app. Changing either changes it.
const SEVSNPPCRIdentityPrefix = "snp-pcr:"

// VerifyCombinedGCPAttestation verifies a marshaled go-tpm-tools Attestation and
// returns the code identity (snp-pcr:<hex(sha256(PCR11||PCR8))>). It checks, in
// order: (1) the AK cert chains to Google's vTPM CA and matches AkPub; (2) the
// SEV-SNP report verifies to the AMD root; (3) report_data == sha512(AkPub||SPKI)
// — the anti-splice binding that welds the AMD-signed report to THIS vTPM key;
// (4) the vTPM quote is signed by that AK over the PCRs with nonce sha256(SPKI).
// Only after (3)+(4) are the quoted PCR 8/11 trustworthy code measurements.
func VerifyCombinedGCPAttestation(attBytes, spkiDER []byte) (string, error) {
	att := &tpmpb.Attestation{}
	if err := proto.Unmarshal(attBytes, att); err != nil {
		return "", fmt.Errorf("unmarshal combined attestation: %w", err)
	}

	// (1) AK cert -> Google vTPM roots, and AkPub matches the cert.
	akCert, err := x509.ParseCertificate(att.GetAkCert())
	if err != nil {
		return "", fmt.Errorf("parse AK cert: %w", err)
	}
	if err := verifyAKCertChain(akCert, att.GetIntermediateCerts()); err != nil {
		return "", fmt.Errorf("AK cert not Google-rooted: %w", err)
	}
	akArea, err := tpm2.DecodePublic(att.GetAkPub())
	if err != nil {
		return "", fmt.Errorf("decode AkPub: %w", err)
	}
	akKey, err := akArea.Key()
	if err != nil {
		return "", fmt.Errorf("AkPub key: %w", err)
	}
	certKey, ok := akCert.PublicKey.(*ecdsa.PublicKey)
	akPubKey, ok2 := akKey.(*ecdsa.PublicKey)
	if !ok || !ok2 || !certKey.Equal(akPubKey) {
		return "", fmt.Errorf("AkPub does not match AK cert")
	}

	// (2) SEV-SNP report -> AMD root (genuine SEV-SNP hardware).
	sevAtt := att.GetSevSnpAttestation()
	if sevAtt == nil {
		return "", fmt.Errorf("attestation carries no SEV-SNP report")
	}
	opts := verify.DefaultOptions()
	opts.DisableCertFetching = true
	roots, err := amdTrustedRoots()
	if err != nil {
		return "", fmt.Errorf("AMD roots: %w", err)
	}
	opts.TrustedRoots = roots
	if err := verify.SnpAttestation(sevAtt, opts); err != nil {
		return "", fmt.Errorf("SEV-SNP chain verification failed: %w", err)
	}

	// (3) Binding: report_data == sha512(AkPub || SPKI). Welds the AMD-signed
	// report to this exact vTPM AK, so a report from one VM can't be spliced
	// with another VM's quote.
	expected := CombinedReportData(att.GetAkPub(), spkiDER)
	if subtle.ConstantTimeCompare(sevAtt.GetReport().GetReportData(), expected[:]) != 1 {
		return "", fmt.Errorf("report_data does not bind AK+SPKI (splice attempt?)")
	}

	// (4) vTPM quote: signed by the AK over the PCRs, nonce = sha256(SPKI).
	nonce := sha256.Sum256(spkiDER)
	pcr8, pcr11, err := verifiedPCRs(att, akCert.PublicKey, nonce[:])
	if err != nil {
		return "", err
	}

	h := sha256.New()
	h.Write(pcr11)
	h.Write(pcr8)
	return SEVSNPPCRIdentityPrefix + hex.EncodeToString(h.Sum(nil)), nil
}

// verifiedPCRs finds the SHA-256 quote, verifies its signature + nonce + PCR
// digest under akPub (via go-tpm-tools' quote.Verify), and returns the trusted
// PCR 8 and PCR 11 values.
func verifiedPCRs(att *tpmpb.Attestation, akPub interface{}, nonce []byte) (pcr8, pcr11 []byte, err error) {
	for _, q := range att.GetQuotes() {
		if q.GetPcrs().GetHash() != tpmprotopb.HashAlgo_SHA256 {
			continue
		}
		if err := gquote.Verify(q, akPub, nonce); err != nil {
			return nil, nil, fmt.Errorf("quote verification failed: %w", err)
		}
		m := q.GetPcrs().GetPcrs()
		pcr8, pcr11 = m[combinedAppPCR], m[combinedBasePCR]
		if len(pcr8) == 0 || len(pcr11) == 0 {
			return nil, nil, fmt.Errorf("quote missing PCR %d/%d", combinedAppPCR, combinedBasePCR)
		}
		return pcr8, pcr11, nil
	}
	return nil, nil, fmt.Errorf("no SHA-256 vTPM quote in attestation")
}

// verifyAKCertChain checks akCert chains to the embedded Google vTPM root, using
// the attestation-carried intermediates (GCE intermediates are regionalized +
// rotated; the producer fetches and embeds them). Only the root is pinned.
func verifyAKCertChain(akCert *x509.Certificate, carriedInters [][]byte) error {
	root, err := x509.ParseCertificate(gcpVTPMRootDER)
	if err != nil {
		return fmt.Errorf("parse embedded root: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inters := x509.NewCertPool()
	// The known intermediate (best-effort) plus whatever the attestation carries.
	if inter, err := x509.ParseCertificate(gcpVTPMIntermediateDER); err == nil {
		inters.AddCert(inter)
	}
	for _, der := range carriedInters {
		if c, err := x509.ParseCertificate(der); err == nil {
			inters.AddCert(c)
		}
	}
	_, err = akCert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}
