//go:build mobile

package client

import (
	"fmt"
	"tee-mpc/shared"

	teeproto "tee-mpc/proto"

	"go.uber.org/zap"
)

// verifyAttestationReportETH extracts the ETH address from a protobuf AttestationReport
// Mobile version: skips verification (attestor handles verification server-side)
func (c *Client) verifyAttestationReportETH(report *teeproto.AttestationReport, expectedSource string) (shared.Address, error) {
	c.logger.Info("verifyAttestationReportETH called (mobile - skipping verification)", zap.String("type", report.Type), zap.String("source", expectedSource), zap.Int("report_bytes", len(report.Report)))

	switch report.Type {
	case "nitro":
		// Mobile: Parse attestation data without cryptographic verification
		// The attestor service handles actual verification
		c.logger.Info("Extracting ETH address from Nitro attestation (mobile)", zap.String("source", expectedSource))

		// For nitro, we need to parse the CBOR document to extract user data
		// This is a simplified extraction that doesn't verify the cryptographic signature
		// In production mobile, attestor validates everything server-side
		return shared.Address{}, fmt.Errorf("nitro attestation not supported on mobile - use standalone mode with ETH address")

	case "gcp":
		// GCP attestation - extract ETH address without full JWT verification
		// The attestor service handles actual verification
		return shared.Address{}, fmt.Errorf("gcp attestation not supported on mobile - use standalone mode with ETH address")

	default:
		return shared.Address{}, fmt.Errorf("unsupported attestation type: %s", report.Type)
	}
}

// VerifyGCPConfidentialSpaceAttestation is a stub for mobile builds
// Mobile doesn't verify GCP attestations - the attestor handles this
func VerifyGCPConfidentialSpaceAttestation(token string) ([]byte, error) {
	return nil, fmt.Errorf("GCP attestation verification not available on mobile")
}
