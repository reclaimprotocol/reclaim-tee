//go:build !mobile

package client

import (
	"fmt"
	"strings"
	"tee-mpc/shared"

	teeproto "tee-mpc/proto"

	"github.com/anjuna-security/go-nitro-attestation/verifier"
	"go.uber.org/zap"
)

// verifyAttestationReportETH verifies a protobuf AttestationReport and extracts the ETH address from the report itself
func (c *Client) verifyAttestationReportETH(report *teeproto.AttestationReport, expectedSource string) (shared.Address, error) {
	c.logger.Info("verifyAttestationReportETH called", zap.String("type", report.Type), zap.String("source", expectedSource), zap.Int("report_bytes", len(report.Report)))
	switch report.Type {
	case "nitro":
		c.logger.Info("Attempting to parse Nitro attestation report for ETH address", zap.String("source", expectedSource))
		sr, err := verifier.NewSignedAttestationReport(strings.NewReader(string(report.Report)))
		if err != nil {
			c.logger.Error("Failed to parse Nitro attestation report", zap.Error(err))
			return shared.Address{}, fmt.Errorf("failed to parse nitro report: %v", err)
		}
		if err := verifier.Validate(sr, nil); err != nil {
			return shared.Address{}, fmt.Errorf("nitro validation failed: %v", err)
		}

		// Extract ETH address from user data in the attestation document
		userDataStr := string(sr.Document.UserData)
		expectedPrefix := fmt.Sprintf("%s_public_key:", strings.ToLower(expectedSource))
		if !strings.HasPrefix(userDataStr, expectedPrefix) {
			return shared.Address{}, fmt.Errorf("invalid user data format, expected prefix %s", expectedPrefix)
		}

		ethAddressHex := userDataStr[len(expectedPrefix):]
		if !strings.HasPrefix(ethAddressHex, "0x") {
			return shared.Address{}, fmt.Errorf("invalid ETH address format, expected 0x prefix")
		}

		if !shared.IsHexAddress(ethAddressHex) {
			return shared.Address{}, fmt.Errorf("invalid ETH address format: %s", ethAddressHex)
		}

		ethAddress := shared.HexToAddress(ethAddressHex)
		c.logger.Info("Extracted ETH address from Nitro attestation", zap.String("source", expectedSource), zap.String("eth_address", ethAddress.Hex()))
		return ethAddress, nil

	case "gcp":
		// GCP Confidential Space attestation - verify x5c JWT and extract ETH address
		pubKeyBytes, err := VerifyGCPConfidentialSpaceAttestation(string(report.Report))
		if err != nil {
			return shared.Address{}, fmt.Errorf("GCP Confidential Space attestation validation failed: %v", err)
		}

		// pubKeyBytes is the ETH address (20 bytes)
		if len(pubKeyBytes) != 20 {
			return shared.Address{}, fmt.Errorf("invalid ETH address length: %d bytes", len(pubKeyBytes))
		}

		ethAddress := shared.BytesToAddress(pubKeyBytes)
		c.logger.Info("Extracted ETH address from GCP Confidential Space attestation", zap.String("source", expectedSource), zap.String("eth_address", ethAddress.Hex()))
		return ethAddress, nil

	default:
		return shared.Address{}, fmt.Errorf("unsupported attestation type: %s", report.Type)
	}
}
