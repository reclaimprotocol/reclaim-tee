//go:build linux && !mobile

package shared

import (
	"fmt"
	"os"

	"github.com/google/go-sev-guest/client"
)

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
