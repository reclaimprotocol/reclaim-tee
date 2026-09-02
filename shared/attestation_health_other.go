//go:build !linux || mobile

package shared

// Non-Linux / mobile builds don't run in a SEV-SNP enclave; diagnostics and
// self-reset are no-ops so the shared package still compiles for the client.
func captureAttestationDiag(err error) attestationDiagnostics {
	return attestationDiagnostics{}
}

func attestSelfReset(logger *Logger) {}

func isTerminalAttestWedge(err error) bool { return false }
