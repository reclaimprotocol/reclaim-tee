//go:build linux && !mobile

package shared

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

func TestIsTerminalAttestWedge(t *testing.T) {
	if isTerminalAttestWedge(nil) {
		t.Fatal("nil is not a wedge")
	}
	wrapped := fmt.Errorf("ratls refresh: attest: collecting TEE attestation report: %w", syscall.ENOTTY)
	if !isTerminalAttestWedge(wrapped) {
		t.Fatal("wrapped ENOTTY should be terminal")
	}
	if !isTerminalAttestWedge(errors.New("attest: inappropriate ioctl for device")) {
		t.Fatal("string ENOTTY should be terminal")
	}
	if isTerminalAttestWedge(errors.New("dial tcp: connection refused")) {
		t.Fatal("unrelated error must not be terminal")
	}
}

func TestHasTerminalVMPCKDisable(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  bool
	}{
		{
			name:  "incident VMPCK zero",
			lines: []string{"6,1,123,-;SEV: Disabling VMPCK0 communication key to prevent IV reuse."},
			want:  true,
		},
		{
			name:  "vmpck id",
			lines: []string{"SEV-SNP: disabling the vmpck_id after firmware error"},
			want:  true,
		},
		{
			name:  "case insensitive",
			lines: []string{"sev: DISABLING THE VmPcK_ID"},
			want:  true,
		},
		{
			name:  "ordinary VMPCK line",
			lines: []string{"sev-guest: using vmpck_id 0"},
			want:  false,
		},
		{
			name:  "unrelated disabling line",
			lines: []string{"sev: disabling interrupts"},
			want:  false,
		},
		{
			name:  "terms on different lines",
			lines: []string{"sev: disabling interrupts", "sev-guest: using vmpck_id 0"},
			want:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := hasTerminalVMPCKDisable(test.lines); got != test.want {
				t.Fatalf("hasTerminalVMPCKDisable() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestKmsgScanRetainsTerminalEvidenceOutsideLogTail(t *testing.T) {
	var scan kmsgScan
	scan.add("SEV: Disabling VMPCK0 communication key to prevent IV reuse.", "sev", "vmpck")
	for i := range attestationKmsgTailLines + 5 {
		scan.add(fmt.Sprintf("sev: later matching line %d", i), "sev", "vmpck")
	}

	if !scan.terminalVMPCK {
		t.Fatal("terminal VMPCK evidence must survive truncation of the logging tail")
	}
	if len(scan.tail) != attestationKmsgTailLines {
		t.Fatalf("retained kmsg lines = %d, want %d", len(scan.tail), attestationKmsgTailLines)
	}
	if hasTerminalVMPCKDisable(scan.tail) {
		t.Fatal("test setup must push the terminal marker outside the retained tail")
	}
}

func TestAttestationHealthTerminalWedgeRequestsStickyDrain(t *testing.T) {
	h := newAttestationHealthForTest(nil)
	drain := h.DrainRequested()
	h.RecordFailure(syscall.ENOTTY)
	if h.Healthy() {
		t.Fatal("a single terminal ENOTTY must gate unhealthy immediately")
	}
	select {
	case <-drain:
	default:
		t.Fatal("a single terminal ENOTTY must request drain")
	}
	h.RecordSuccess()
	if h.Healthy() {
		t.Fatal("success must not clear the terminal wedge")
	}
}

func TestAttestationHealthENOTTYRequestsDrainBeforeDiagnostics(t *testing.T) {
	h := newAttestationHealthForTest(nil)
	drain := h.DrainRequested()
	captureStarted := make(chan struct{})
	releaseCapture := make(chan struct{})
	done := make(chan struct{})
	go func() {
		h.recordFailure(syscall.ENOTTY, func(error) attestationDiagnostics {
			close(captureStarted)
			<-releaseCapture
			return attestationDiagnostics{}
		})
		close(done)
	}()
	<-captureStarted

	select {
	case <-drain:
	default:
		close(releaseCapture)
		<-done
		t.Fatal("ENOTTY must request drain before diagnostic capture completes")
	}
	close(releaseCapture)
	<-done
}

func TestAttestationHealthWedgeSuppressesThresholdReset(t *testing.T) {
	h := newAttestationHealthForTest(nil)
	noDiagnostics := func(error) attestationDiagnostics { return attestationDiagnostics{} }
	for range attestSelfHealAfter - 1 {
		h.recordFailure(errors.New("temporary failure"), noDiagnostics)
	}
	h.recordFailure(syscall.ENOTTY, noDiagnostics)
	if !h.lastSelfHeal.IsZero() {
		t.Fatal("terminal evidence at the threshold must not request an immediate reset")
	}

	h.recordFailure(errors.New("failure after wedge"), noDiagnostics)
	if !h.lastSelfHeal.IsZero() {
		t.Fatal("failures after a terminal wedge must not request a threshold reset")
	}
}
