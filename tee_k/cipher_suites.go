package main

import (
	"fmt"
	"tee-mpc/minitls"
	"tee-mpc/shared"
)

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
