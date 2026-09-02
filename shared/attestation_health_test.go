package shared

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestAttestationHealthConsecutive(t *testing.T) {
	h := newAttestationHealthForTest(nil)
	if !h.Healthy() {
		t.Fatal("fresh health should be healthy")
	}
	blip := errors.New("temporary network blip")
	noDiagnostics := func(error) attestationDiagnostics { return attestationDiagnostics{} }
	h.recordFailure(blip, noDiagnostics)
	h.recordFailure(blip, noDiagnostics)
	if !h.Healthy() {
		t.Fatal("2 non-terminal failures should still be healthy")
	}
	h.recordFailure(blip, noDiagnostics)
	if h.Healthy() {
		t.Fatal("3 non-terminal failures should gate unhealthy")
	}
	h.RecordSuccess()
	if !h.Healthy() {
		t.Fatal("success should reset the streak")
	}
}

func TestAttestationHealthGenericThresholdStillRequestsReset(t *testing.T) {
	h := newAttestationHealthForTest(nil)
	resetStarted := make(chan struct{})
	allowResetReturn := make(chan struct{})
	resetDone := make(chan struct{})
	h.selfReset = func(*Logger) {
		close(resetStarted)
		<-allowResetReturn
		close(resetDone)
	}
	noDiagnostics := func(error) attestationDiagnostics { return attestationDiagnostics{} }
	for range attestSelfHealAfter {
		h.recordFailure(errors.New("temporary failure"), noDiagnostics)
	}
	<-resetStarted
	close(allowResetReturn)
	<-resetDone
	if h.lastSelfHeal.IsZero() {
		t.Fatal("generic failure threshold must retain the self-reset behavior")
	}
}

func TestAttestationHealthLaterSuccessWinsOverSlowEarlierFailure(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	h := newAttestationHealthForTest(&Logger{Logger: zap.New(core)})
	noDiagnostics := func(error) attestationDiagnostics { return attestationDiagnostics{} }
	for range attestSelfHealAfter - 1 {
		h.recordFailure(errors.New("temporary failure"), noDiagnostics)
	}
	failureLogsBeforeSlowFailure := observed.FilterMessage("attestation generation failed").Len()

	captureStarted := make(chan struct{})
	releaseCapture := make(chan struct{})
	done := make(chan struct{})
	go func() {
		h.recordFailure(errors.New("slow failure"), func(error) attestationDiagnostics {
			close(captureStarted)
			<-releaseCapture
			return attestationDiagnostics{}
		})
		close(done)
	}()
	<-captureStarted
	if h.consecFails != attestSelfHealAfter {
		t.Fatalf("failure count before diagnostic completion = %d, want %d", h.consecFails, attestSelfHealAfter)
	}

	h.RecordSuccess()
	close(releaseCapture)
	<-done
	if h.consecFails != 0 {
		t.Fatalf("failure count after later success = %d, want 0", h.consecFails)
	}
	if !h.lastSelfHeal.IsZero() {
		t.Fatal("an earlier failure must not request reset after a later success")
	}
	if h.diagLogged {
		t.Fatal("an earlier failure must not modify diagnostic state after a later success")
	}
	if got := observed.FilterMessage("attestation generation failed").Len(); got != failureLogsBeforeSlowFailure {
		t.Fatalf("failure log count after superseded slow failure = %d, want %d", got, failureLogsBeforeSlowFailure)
	}
	if !h.Healthy() {
		t.Fatal("a later success must leave attestation healthy")
	}
}

func TestAttestationHealthTerminalEvidenceSurvivesLaterSuccess(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	h := newAttestationHealthForTest(&Logger{Logger: zap.New(core)})
	drain := h.DrainRequested()
	captureStarted := make(chan struct{})
	releaseCapture := make(chan struct{})
	done := make(chan struct{})
	go func() {
		h.recordFailure(errors.New("slow terminal failure"), func(error) attestationDiagnostics {
			close(captureStarted)
			<-releaseCapture
			return attestationDiagnostics{terminalVMPCK: true}
		})
		close(done)
	}()
	<-captureStarted
	h.RecordSuccess()
	close(releaseCapture)
	<-done

	if h.Healthy() {
		t.Fatal("terminal evidence must survive a later success")
	}
	select {
	case <-drain:
	default:
		t.Fatal("terminal evidence must request drain across generations")
	}
	failureLogs := observed.FilterMessage("attestation generation failed").All()
	if len(failureLogs) != 1 {
		t.Fatalf("terminal failure log count across generations = %d, want 1", len(failureLogs))
	}
	if got := failureLogs[0].ContextMap()["terminal_wedge"]; got != true {
		t.Fatalf("terminal_wedge log field across generations = %v, want true", got)
	}
	if got := observed.FilterMessage("terminal attestation failure diagnostics").Len(); got != 1 {
		t.Fatalf("terminal diagnostic log count across generations = %d, want 1", got)
	}
}

func TestAttestationHealthNilSafe(t *testing.T) {
	var h *AttestationHealth
	h.RecordFailure(errors.New("x"))
	h.RecordSuccess()
	if h.DrainRequested() != nil {
		t.Fatal("nil AttestationHealth must return a nil drain channel")
	}
	if !h.Healthy() {
		t.Fatal("nil AttestationHealth must report healthy")
	}
}

func TestAttestationHealthDetectsVMPCKDiagnosticOnLaterFailure(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	h := newAttestationHealthForTest(&Logger{Logger: zap.New(core)})
	drain := h.DrainRequested()
	captures := 0
	h.recordFailure(errors.New("firmware error"), func(error) attestationDiagnostics {
		captures++
		return attestationDiagnostics{}
	})
	if captures != 1 {
		t.Fatalf("diagnostics captured %d times, want 1", captures)
	}
	select {
	case <-drain:
		t.Fatal("an ordinary first failure must not request drain")
	default:
	}

	h.recordFailure(errors.New("later firmware error"), func(error) attestationDiagnostics {
		captures++
		return attestationDiagnostics{
			fields:        []zap.Field{zap.String("kmsg", "decisive marker")},
			terminalVMPCK: true,
		}
	})
	if captures != 2 {
		t.Fatalf("diagnostics captured %d times after a repeated failure, want 2", captures)
	}
	if got := observed.FilterMessage("attestation failure diagnostics").Len(); got != 1 {
		t.Fatalf("diagnostic log count = %d, want 1", got)
	}
	terminalDiagnostics := observed.FilterMessage("terminal attestation failure diagnostics").All()
	if len(terminalDiagnostics) != 1 {
		t.Fatalf("terminal diagnostic log count = %d, want 1", len(terminalDiagnostics))
	}
	if got := terminalDiagnostics[0].ContextMap()["kmsg"]; got != "decisive marker" {
		t.Fatalf("terminal diagnostic kmsg = %v, want decisive marker", got)
	}
	if h.Healthy() {
		t.Fatal("VMPCK-disable evidence must gate unhealthy immediately")
	}
	select {
	case <-drain:
	default:
		t.Fatal("VMPCK-disable evidence must request drain")
	}
	h.recordFailure(errors.New("ordinary failure after wedge"), func(error) attestationDiagnostics {
		captures++
		return attestationDiagnostics{}
	})
	if captures != 3 {
		t.Fatalf("diagnostic captures after post-wedge failure = %d, want 3", captures)
	}
	failureLogs := observed.FilterMessage("attestation generation failed").All()
	if got := failureLogs[len(failureLogs)-1].ContextMap()["terminal_wedge"]; got != true {
		t.Fatalf("post-wedge terminal_wedge log field = %v, want true", got)
	}

	consecFails := h.consecFails
	generation := h.generation
	diagLogged := h.diagLogged
	terminalDiagLogged := h.terminalDiagLogged
	h.RecordSuccess()
	if h.Healthy() {
		t.Fatal("success must not clear a confirmed terminal wedge")
	}
	if h.consecFails != consecFails || h.generation != generation || h.diagLogged != diagLogged || h.terminalDiagLogged != terminalDiagLogged {
		t.Fatal("success must not clear failure state after a terminal wedge")
	}
	if got := observed.FilterMessage("attestation recovered").Len(); got != 0 {
		t.Fatalf("recovery log count after terminal wedge = %d, want 0", got)
	}
	if h.DrainRequested() != drain {
		t.Fatal("DrainRequested must return a stable channel")
	}
}

func TestAttestationHealthDrainRequestedConcurrentOneShot(t *testing.T) {
	h := newAttestationHealthForTest(nil)
	drain := h.DrainRequested()
	var wg sync.WaitGroup
	var captures atomic.Int32
	for range 5 {
		wg.Go(func() {
			h.recordFailure(errors.New("terminal"), func(error) attestationDiagnostics {
				captures.Add(1)
				return attestationDiagnostics{terminalVMPCK: true}
			})
		})
	}
	wg.Wait()
	if got := captures.Load(); got != 5 {
		t.Fatalf("diagnostic captures = %d, want 5", got)
	}

	select {
	case <-drain:
	default:
		t.Fatal("terminal failures must close the drain channel")
	}
}

func newAttestationHealthForTest(logger *Logger) *AttestationHealth {
	health := NewAttestationHealth(logger)
	health.selfReset = func(*Logger) {}
	return health
}
