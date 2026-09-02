package shared

import (
	"sync"
	"time"

	"go.uber.org/zap"
)

// AttestationHealth tracks consecutive attestation-generation failures so a TEE
// can gate itself off the router (report unhealthy) and self-reset when the SEV
// report path wedges — the only known recovery, observed 2026-07-13 when GCP
// us-central1 SEV guests returned ENOTTY until a VM reset. Concurrency-safe and
// nil-safe (a nil receiver reports healthy and no-ops).
type AttestationHealth struct {
	mu                 sync.Mutex
	consecFails        int
	generation         uint64
	diagLogged         bool
	terminalDiagLogged bool
	wedged             bool
	drainRequested     chan struct{}
	drainNotified      bool
	lastSelfHeal       time.Time
	logger             *Logger
	selfReset          func(*Logger)
}

type attestationDiagnostics struct {
	fields        []zap.Field
	terminalVMPCK bool
}

const (
	attestUnhealthyAfter = 3
	attestSelfHealAfter  = 6
	attestSelfHealMinGap = 15 * time.Minute
)

func NewAttestationHealth(logger *Logger) *AttestationHealth {
	return &AttestationHealth{logger: logger, selfReset: attestSelfReset}
}

// RecordSuccess clears a recoverable failure streak. A confirmed terminal
// wedge is sticky and leaves all failure state unchanged.
func (a *AttestationHealth) RecordSuccess() {
	if a == nil {
		return
	}
	a.mu.Lock()
	if a.wedged {
		a.mu.Unlock()
		return
	}
	if a.consecFails > 0 && a.logger != nil {
		a.logger.Info("attestation recovered", zap.Int("after_consecutive_failures", a.consecFails))
	}
	a.consecFails = 0
	a.generation++
	a.diagLogged = false
	a.terminalDiagLogged = false
	a.mu.Unlock()
}

// RecordFailure increments the streak, checks device/kernel diagnostics for a
// terminal wedge, requests a drain when found, and triggers a rate-limited
// self-reset once a recoverable failure streak crosses the self-heal threshold.
func (a *AttestationHealth) RecordFailure(err error) {
	a.recordFailure(err, captureAttestationDiag)
}

func (a *AttestationHealth) recordFailure(err error, captureDiag func(error) attestationDiagnostics) {
	if a == nil {
		return
	}
	directTerminal := isTerminalAttestWedge(err)
	drainRequested := false
	a.mu.Lock()
	a.consecFails++
	failureGeneration := a.generation
	if directTerminal {
		drainRequested = a.markTerminalWedgeLocked()
	}
	a.mu.Unlock()

	// Read kmsg on every failure so a VMPCK-disable marker written after an
	// earlier failure is not missed. The returned fields reuse that same read.
	diagnostics := captureDiag(err)
	terminalEvidence := directTerminal || diagnostics.terminalVMPCK

	a.mu.Lock()
	logger := a.logger
	selfReset := a.selfReset
	if selfReset == nil {
		selfReset = attestSelfReset
	}
	if diagnostics.terminalVMPCK {
		if a.markTerminalWedgeLocked() {
			drainRequested = true
		}
	}
	sameGeneration := failureGeneration == a.generation
	logDiagnostics := false
	logTerminalDiagnostics := false
	if logger != nil && diagnostics.terminalVMPCK && !a.terminalDiagLogged {
		a.terminalDiagLogged = true
		a.diagLogged = true
		logTerminalDiagnostics = true
	} else if logger != nil && sameGeneration && !a.diagLogged {
		a.diagLogged = true
		logDiagnostics = true
	}
	consecutiveFailures := a.consecFails
	terminalWedge := a.wedged
	healthy := !terminalWedge && consecutiveFailures < attestUnhealthyAfter
	selfHeal := sameGeneration && !terminalWedge && consecutiveFailures >= attestSelfHealAfter && time.Since(a.lastSelfHeal) >= attestSelfHealMinGap
	logFailure := sameGeneration || terminalEvidence
	if selfHeal {
		a.lastSelfHeal = time.Now()
	}
	a.mu.Unlock()

	if logger != nil && logFailure {
		logger.Error("attestation generation failed",
			zap.Int("consecutive_failures", consecutiveFailures),
			zap.Bool("healthy", healthy),
			zap.Bool("terminal_wedge", terminalWedge),
			zap.Error(err))
	}
	if drainRequested && logger != nil {
		logger.Error("terminal attestation wedge detected; drain requested",
			zap.Int("consecutive_failures", consecutiveFailures))
	}
	if selfHeal {
		if logger != nil {
			logger.Error("attestation wedged past self-heal threshold; self-resetting VM",
				zap.Int("consecutive_failures", consecutiveFailures), zap.Bool("terminal_wedge", terminalWedge))
			logger.Sync()
		}
		go selfReset(logger)
	}
	if logTerminalDiagnostics {
		logger.Error("terminal attestation failure diagnostics", diagnostics.fields...)
	}
	if logDiagnostics {
		logger.Error("attestation failure diagnostics", diagnostics.fields...)
	}
}

func (a *AttestationHealth) markTerminalWedgeLocked() bool {
	a.wedged = true
	if a.drainRequested == nil {
		a.drainRequested = make(chan struct{})
	}
	if a.drainNotified {
		return false
	}
	close(a.drainRequested)
	a.drainNotified = true
	return true
}

// DrainRequested returns a channel that closes when a terminal attestation
// wedge is detected. The channel is stable and closes at most once. A nil
// receiver returns a nil channel.
func (a *AttestationHealth) DrainRequested() <-chan struct{} {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.drainRequested == nil {
		a.drainRequested = make(chan struct{})
	}
	return a.drainRequested
}

// Healthy reports whether the TEE can currently attest. Folded into the
// heartbeat's control-health so the router gates sessions off an unhealthy TEE.
func (a *AttestationHealth) Healthy() bool {
	if a == nil {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.wedged && a.consecFails < attestUnhealthyAfter
}
