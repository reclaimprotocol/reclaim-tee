package shared

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// AttestationDrainConfig supplies the process-specific operations used by an
// AttestationDrainController. Requested is a close-only broadcast channel;
// callers must close it rather than send a value. StopLoops must request loop
// cancellation without blocking and return a channel closed after all relevant
// loops stop. A nil channel reports missing acknowledgment: zero local work
// cannot cause reset, but the cache deadline still can. CachedAttestationExpiry
// and ActiveSessions must be safe for concurrent use and must not block. Reset
// is an optional test seam; when nil, the controller calls the package's
// platform reset primitive. Reset may return when reset is disabled or denied.
type AttestationDrainConfig struct {
	Requested               <-chan struct{}
	StopLoops               func() <-chan struct{}
	CachedAttestationExpiry func() time.Time
	ActiveSessions          func() int
	Reset                   func()
	Logger                  *Logger
}

// AttestationDrainController gates new session admission and drains local
// sessions after a terminal attestation failure. It makes one reset attempt at
// most and never reopens admission after draining starts.
type AttestationDrainController struct {
	mu                    sync.Mutex
	requested             <-chan struct{}
	stopLoops             func() <-chan struct{}
	cachedExpiry          func() time.Time
	activeSessions        func() int
	reset                 func()
	logger                *Logger
	changed               chan struct{}
	runDone               chan struct{}
	runStarted            bool
	draining              bool
	admissionReservations int
	resetAttempted        bool
}

// NewAttestationDrainController constructs a drain controller. Requested,
// StopLoops, CachedAttestationExpiry, and ActiveSessions are required. Reset
// defaults to the package's platform reset primitive.
func NewAttestationDrainController(config AttestationDrainConfig) *AttestationDrainController {
	if config.Requested == nil {
		panic("shared: attestation drain Requested channel is nil")
	}
	if config.StopLoops == nil {
		panic("shared: attestation drain StopLoops callback is nil")
	}
	if config.CachedAttestationExpiry == nil {
		panic("shared: attestation drain CachedAttestationExpiry callback is nil")
	}
	if config.ActiveSessions == nil {
		panic("shared: attestation drain ActiveSessions callback is nil")
	}
	reset := config.Reset
	if reset == nil {
		reset = func() { attestSelfReset(config.Logger) }
	}

	return &AttestationDrainController{
		requested:      config.Requested,
		stopLoops:      config.StopLoops,
		cachedExpiry:   config.CachedAttestationExpiry,
		activeSessions: config.ActiveSessions,
		reset:          reset,
		logger:         config.Logger,
		changed:        make(chan struct{}, 1),
		runDone:        make(chan struct{}),
	}
}

// Run waits for a drain request, closes admission, requests loop cancellation,
// and snapshots the cached-attestation deadline. A normal zero-work reset waits
// for loop-stop acknowledgment. A missing, past, or subsequently expired
// deadline resets after the cancellation request without waiting for that
// acknowledgment. Only the first Run call operates the controller; later calls
// wait for it or their own context cancellation.
func (c *AttestationDrainController) Run(ctx context.Context) {
	if !c.startRun() {
		select {
		case <-ctx.Done():
		case <-c.runDone:
		}
		return
	}
	defer close(c.runDone)

	select {
	case <-ctx.Done():
		return
	case <-c.requested:
	}
	if ctx.Err() != nil {
		return
	}

	reservations := c.beginDrain()
	loopsDone := c.stopLoops()
	expiry := c.cachedExpiry()
	expiryLog := expiry.UTC().Format(time.RFC3339Nano)
	c.logInfo("attestation drain started",
		zap.String("cached_attestation_expiry", expiryLog),
		zap.Int("admission_reservations", reservations))
	c.logInfo("attestation drain loop cancellation requested")
	if loopsDone == nil {
		c.logError("attestation drain loop stop acknowledgment unavailable")
	}
	if ctx.Err() != nil {
		return
	}

	if expiry.IsZero() || !time.Now().Before(expiry) {
		c.attemptReset("cached_attestation_expired")
		return
	}

	timer := time.NewTimer(time.Until(expiry))
	defer timer.Stop()
	loopsStopped := false
	for {
		if ctx.Err() != nil {
			return
		}

		reservations = c.reservationCount()
		active := c.activeSessions()
		if loopsStopped && reservations == 0 && active == 0 {
			c.attemptReset("sessions_drained")
			return
		}

		c.logInfo("attestation drain waiting for sessions",
			zap.Bool("loops_stopped", loopsStopped),
			zap.Int("active_sessions", active),
			zap.Int("admission_reservations", reservations),
			zap.String("cached_attestation_expiry", expiryLog))

		select {
		case <-ctx.Done():
			return
		case <-c.changed:
		case <-loopsDone:
			loopsDone = nil
			loopsStopped = true
			c.logInfo("attestation drain loops stopped")
		case <-timer.C:
			if ctx.Err() == nil {
				c.attemptReset("cached_attestation_expired")
			}
			return
		}
	}
}

// BeginAdmission reserves an in-progress admission. It returns false after
// draining starts or after Requested closes, even when Run has not observed the
// request yet. A successful reservation returns an idempotent release function
// suitable for defer. Release it after the session is either rejected or
// included in ActiveSessions.
func (c *AttestationDrainController) BeginAdmission() (release func(), ok bool) {
	c.mu.Lock()
	select {
	case <-c.requested:
		c.draining = true
	default:
	}
	if c.draining {
		c.mu.Unlock()
		return nil, false
	}
	c.admissionReservations++
	c.mu.Unlock()
	return sync.OnceFunc(c.endAdmission), true
}

func (c *AttestationDrainController) endAdmission() {
	c.mu.Lock()
	c.admissionReservations--
	c.mu.Unlock()
	c.notifyChanged()
}

// IsDraining reports whether this controller has permanently closed session
// admission.
func (c *AttestationDrainController) IsDraining() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.draining
}

// SessionCountChanged wakes the controller after ActiveSessions changes.
func (c *AttestationDrainController) SessionCountChanged() {
	c.notifyChanged()
}

func (c *AttestationDrainController) startRun() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.runStarted {
		return false
	}
	c.runStarted = true
	return true
}

func (c *AttestationDrainController) beginDrain() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.draining = true
	return c.admissionReservations
}

func (c *AttestationDrainController) reservationCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.admissionReservations
}

func (c *AttestationDrainController) notifyChanged() {
	select {
	case c.changed <- struct{}{}:
	default:
	}
}

func (c *AttestationDrainController) attemptReset(reason string) {
	c.mu.Lock()
	if c.resetAttempted {
		c.mu.Unlock()
		return
	}
	c.resetAttempted = true
	c.mu.Unlock()

	c.logError("attestation drain attempting VM reset", zap.String("reason", reason))
	if c.logger != nil {
		_ = c.logger.Sync()
	}
	c.reset()
	c.logError("attestation drain reset returned; TEE remains draining", zap.String("reason", reason))
}

func (c *AttestationDrainController) logInfo(message string, fields ...zap.Field) {
	if c.logger != nil {
		c.logger.Info(message, fields...)
	}
}

func (c *AttestationDrainController) logError(message string, fields ...zap.Field) {
	if c.logger != nil {
		c.logger.Error(message, fields...)
	}
}
