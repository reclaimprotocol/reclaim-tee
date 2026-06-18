//go:build !mobile

package shared

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	"google.golang.org/protobuf/proto"
)

// Tags prefixing the SEV-SNP cert-extension payload so the verifier can dispatch
// per cloud (GCP carries a go-tpm-tools Attestation proto; AWS carries a CBOR
// envelope of the NitroTPM document + the SEV report).
const (
	snpAttestTagGCP = 0x01
	snpAttestTagAWS = 0x02
)

// AWS Nitro Enclaves root CA (pinned trust anchor for the NitroTPM attestation
// document's cabundle). NitroTPM uses the same Nitro Attestation PKI as Enclaves.
//
//go:embed aws_nitro_root.pem
var awsNitroRootPEM []byte

// awsCombinedEnvelope is the CBOR envelope an AWS TEE puts in the cert extension:
// the Nitro-signed attestation document + the AMD-signed SEV-SNP report.
type awsCombinedEnvelope struct {
	NitroTPM []byte `cbor:"nitrotpm"`
	SEV      []byte `cbor:"sev"`
}

// VerifyCombinedSEVSNPAttestation dispatches a tagged SEV-SNP attestation to the
// per-cloud verifier and returns the code identity (snp-pcr:<hex>).
func VerifyCombinedSEVSNPAttestation(att, spkiDER []byte) (string, error) {
	if len(att) < 1 {
		return "", fmt.Errorf("empty SEV-SNP attestation")
	}
	switch att[0] {
	case snpAttestTagGCP:
		return VerifyCombinedGCPAttestation(att[1:], spkiDER)
	case snpAttestTagAWS:
		return VerifyCombinedAWSAttestation(att[1:], spkiDER)
	default:
		return "", fmt.Errorf("unknown SEV-SNP attestation tag 0x%02x", att[0])
	}
}

// VerifyCombinedAWSAttestation verifies an AWS combined attestation and returns
// the PCR code identity. It checks: (1) the SEV-SNP report -> AMD root and
// report_data == sha512(SPKI); (2) the NitroTPM document's COSE_Sign1 signature
// + cabundle -> the pinned Nitro root, and its user_data == sha512(SPKI); then
// pins PCR 8 (app) + PCR 11 (base) from nitrotpm_pcrs. The shared sha512(SPKI)
// in BOTH report_data and user_data welds the AMD hardware proof to the
// Nitro-rooted code proof for one key.
func VerifyCombinedAWSAttestation(att, spkiDER []byte) (string, error) {
	var env awsCombinedEnvelope
	if err := cbor.Unmarshal(att, &env); err != nil {
		return "", fmt.Errorf("decode AWS envelope: %w", err)
	}
	bind := sha512.Sum512(spkiDER)

	// (1) SEV-SNP report -> AMD root (genuine SEV-SNP hardware), report_data binding.
	sevAtt := &spb.Attestation{}
	if err := proto.Unmarshal(env.SEV, sevAtt); err != nil {
		return "", fmt.Errorf("unmarshal SEV report: %w", err)
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
	if subtle.ConstantTimeCompare(sevAtt.GetReport().GetReportData(), bind[:]) != 1 {
		return "", fmt.Errorf("SEV report_data does not bind the SPKI")
	}

	// (2) NitroTPM document: COSE_Sign1 -> Nitro root, user_data binding.
	doc, pcrs, userData, err := verifyNitroTPMDocument(env.NitroTPM)
	if err != nil {
		return "", err
	}
	_ = doc
	if subtle.ConstantTimeCompare(userData, bind[:]) != 1 {
		return "", fmt.Errorf("NitroTPM user_data does not bind the SPKI")
	}

	pcr8, pcr11 := pcrs[combinedAppPCR], pcrs[combinedBasePCR]
	if len(pcr8) == 0 || len(pcr11) == 0 {
		return "", fmt.Errorf("NitroTPM doc missing PCR %d/%d", combinedAppPCR, combinedBasePCR)
	}
	h := sha256.New()
	h.Write(pcr11)
	h.Write(pcr8)
	return SEVSNPPCRIdentityPrefix + hex.EncodeToString(h.Sum(nil)), nil
}

// coseSign1 is a COSE_Sign1 structure (untagged CBOR 4-array).
type coseSign1 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

// nitroAttestationDoc is the NitroTPM attestation document payload.
type nitroAttestationDoc struct {
	ModuleID    string            `cbor:"module_id"`
	Digest      string            `cbor:"digest"`
	Timestamp   uint64            `cbor:"timestamp"`
	PCRs        map[uint32][]byte `cbor:"nitrotpm_pcrs"`
	Certificate []byte            `cbor:"certificate"`
	CABundle    [][]byte          `cbor:"cabundle"`
	PublicKey   []byte            `cbor:"public_key"`
	UserData    []byte            `cbor:"user_data"`
	Nonce       []byte            `cbor:"nonce"`
}

// verifyNitroTPMDocument verifies the COSE_Sign1 signature (ES384) with the
// leaf cert, chains the leaf -> cabundle -> pinned Nitro root, and returns the
// parsed doc, its PCR map, and user_data.
func verifyNitroTPMDocument(docBytes []byte) (*nitroAttestationDoc, map[uint32][]byte, []byte, error) {
	var cose coseSign1
	if err := cbor.Unmarshal(docBytes, &cose); err != nil {
		return nil, nil, nil, fmt.Errorf("decode COSE_Sign1: %w", err)
	}
	var doc nitroAttestationDoc
	if err := cbor.Unmarshal(cose.Payload, &doc); err != nil {
		return nil, nil, nil, fmt.Errorf("decode attestation doc: %w", err)
	}

	leaf, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse leaf cert: %w", err)
	}
	if err := verifyNitroChain(leaf, doc.CABundle); err != nil {
		return nil, nil, nil, fmt.Errorf("NitroTPM cert chain: %w", err)
	}
	leafPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, nil, fmt.Errorf("NitroTPM leaf is not ECDSA")
	}

	// COSE_Sign1 ToBeSigned = ["Signature1", protected(bstr), external_aad h'', payload(bstr)].
	tbs, err := cbor.Marshal([]interface{}{"Signature1", cose.Protected, []byte{}, cose.Payload})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode Sig_structure: %w", err)
	}
	digest := sha512.Sum384(tbs)
	if len(cose.Signature) != 96 {
		return nil, nil, nil, fmt.Errorf("COSE signature is %d bytes, want 96 (ES384)", len(cose.Signature))
	}
	r := new(big.Int).SetBytes(cose.Signature[:48])
	s := new(big.Int).SetBytes(cose.Signature[48:])
	if !ecdsa.Verify(leafPub, digest[:], r, s) {
		return nil, nil, nil, fmt.Errorf("COSE_Sign1 signature invalid")
	}
	return &doc, doc.PCRs, doc.UserData, nil
}

func verifyNitroChain(leaf *x509.Certificate, cabundle [][]byte) error {
	block, _ := pem.Decode(awsNitroRootPEM)
	if block == nil {
		return fmt.Errorf("parse embedded Nitro root PEM")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse embedded Nitro root: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	inters := x509.NewCertPool()
	for _, der := range cabundle {
		if c, err := x509.ParseCertificate(der); err == nil {
			inters.AddCert(c)
		}
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}
