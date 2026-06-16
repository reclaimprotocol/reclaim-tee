//go:build !linux && !mobile

package shared

import "fmt"

// IsSEVSNPMode is always false off Linux — the SEV-SNP guest device is a Linux
// kernel interface. Lets client/dev builds on macOS compile the verify path.
func IsSEVSNPMode() bool { return false }

// GenerateSEVSNPAttestation is unavailable off Linux; TEEs only run on Linux.
func GenerateSEVSNPAttestation(reportData [64]byte) ([]byte, error) {
	return nil, fmt.Errorf("SEV-SNP attestation generation is only supported on Linux")
}
