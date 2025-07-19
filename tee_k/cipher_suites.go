package main

import (
	"fmt"
	"tee-mpc/minitls"
	"tee-mpc/shared"
)

// parseCipherSuite converts a cipher suite string (hex or name) to uint16 ID
// This is a wrapper around the shared function
func parseCipherSuite(cipherSuite string) (uint16, error) {
	return shared.ParseCipherSuite(cipherSuite)
}

// getCipherSuiteName returns the human-readable name for a cipher suite ID
// This is a wrapper around the shared function
func getCipherSuiteName(id uint16) string {
	return shared.GetCipherSuiteName(id)
}

// configureCipherSuites configures the TLS config with specific cipher suites
func configureCipherSuites(config *minitls.Config, forceCipherSuite string, tlsVersion string) error {
	if forceCipherSuite == "" {
		// No specific cipher suite requested, use defaults
		return nil
	}

	cipherSuiteID, err := shared.ParseCipherSuite(forceCipherSuite)
	if err != nil {
		return fmt.Errorf("failed to parse cipher suite: %v", err)
	}

	// Validate cipher suite compatibility with TLS version
	if err := shared.ValidateCipherSuiteCompatibility(cipherSuiteID, tlsVersion); err != nil {
		return err
	}

	// Set cipher suites in config
	config.CipherSuites = []uint16{cipherSuiteID}

	return nil
}

// validateCipherSuiteCompatibility checks if a cipher suite is compatible with a TLS version
// This is a wrapper around the shared function
func validateCipherSuiteCompatibility(cipherSuiteID uint16, tlsVersion string) error {
	return shared.ValidateCipherSuiteCompatibility(cipherSuiteID, tlsVersion)
}

// getSupportedCipherSuites returns a list of supported cipher suites for a TLS version
func getSupportedCipherSuites(tlsVersion string) []string {
	var suites []string

	for _, info := range shared.GetSupportedCipherSuites(tlsVersion) {
		suites = append(suites, info.Name)
	}

	return suites
}
