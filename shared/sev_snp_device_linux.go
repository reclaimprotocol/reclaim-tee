//go:build linux && !mobile

package shared

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/google/go-sev-guest/client"
	tpmclient "github.com/google/go-tpm-tools/client"
	legacytpm "github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/proto"
)

// GenerateCombinedGCPAttestation produces a marshaled go-tpm-tools Attestation
// binding the GCE vTPM to the AMD SEV-SNP report. It loads the GCE-provided
// attestation key (Google-certified), sets the SEV report_data to
// sha512(AkPub || spkiDER) so the AMD-signed report commits to this exact vTPM
// key (anti-splice), and quotes the PCRs (incl. PCR 8 = app, PCR 11 = base).
// GCP-only: relies on the GCE AK. AWS (NitroTPM) needs its own producer.
func GenerateCombinedGCPAttestation(spkiDER []byte) ([]byte, error) {
	rwc, err := legacytpm.OpenTPM("/dev/tpmrm0")
	if err != nil {
		return nil, fmt.Errorf("open tpm: %w", err)
	}
	defer rwc.Close()

	ak, err := tpmclient.GceAttestationKeyECC(rwc)
	if err != nil {
		return nil, fmt.Errorf("load GCE attestation key: %w", err)
	}
	defer ak.Close()

	akPub, err := ak.PublicArea().Encode()
	if err != nil {
		return nil, fmt.Errorf("encode AK public area: %w", err)
	}
	rd := CombinedReportData(akPub, spkiDER)
	nonce := sha256.Sum256(spkiDER)

	sev, err := tpmclient.CreateSevSnpQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("create SEV-SNP quote provider: %w", err)
	}
	defer sev.Close()

	// TCGEventLog set to empty (non-nil) to skip reading the firmware event log
	// (our minimal UKI has no standard log); the verifier pins PCRs from the quote.
	// CertChainFetcher embeds the AK cert's issuing chain (GCE intermediates are
	// regionalized + rotated, so the verifier can't hardcode them) — it fetches
	// once here so the verifier stays offline, trusting only the stable root.
	att, err := ak.Attest(tpmclient.AttestOpts{
		Nonce:            nonce[:],
		TEENonce:         rd[:],
		TEEDevice:        sev,
		TCGEventLog:      []byte{},
		CertChainFetcher: &http.Client{Timeout: 30 * time.Second},
	})
	if err != nil {
		return nil, fmt.Errorf("attest: %w", err)
	}
	return proto.Marshal(att)
}

// sevGuestDevice is where the SEV-SNP guest driver exposes the report ioctl.
// Its presence is how we detect "running on a SEV-SNP CVM", the SEV-SNP
// counterpart to the Confidential Space launcher socket.
const sevGuestDevice = "/dev/sev-guest"

// IsSEVSNPMode reports whether this process is running on a SEV-SNP guest
// (the guest device node is present).
func IsSEVSNPMode() bool {
	_, err := os.Stat(sevGuestDevice)
	return err == nil
}

// GenerateSEVSNPAttestation pulls an extended attestation report (report +
// cached VCEK/ASK/ARK chain) bound to the given report_data, and returns it
// marshaled for embedding in the RA-TLS cert extension.
func GenerateSEVSNPAttestation(reportData [64]byte) ([]byte, error) {
	qp, err := client.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("get SEV-SNP quote provider: %w", err)
	}
	att, err := client.GetQuoteProto(qp, reportData)
	if err != nil {
		return nil, fmt.Errorf("get SEV-SNP attestation: %w", err)
	}
	return marshalSEVSNPAttestation(att)
}
