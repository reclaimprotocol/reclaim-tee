package shared

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestOnSessionExpiredCallback locks in the contract added in 2026-06-09:
// cleanupExpiredSessions must invoke the registered onSessionExpired
// callback for every session it removes, so owning TEEs can decrement
// their activeSessions atomic + run per-session cleanup that
// SessionManager itself can't reach.
//
// Without this guarantee the active_sessions field in the router's /pairs
// response leaks on every expiry — see project_active_sessions_counter_leak.
func TestOnSessionExpiredCallback(t *testing.T) {
	sm := NewSessionManager()
	// Force every session to look "stale" immediately. cleanupExpiredSessions
	// will then sweep them on the next tick.
	sm.sessionTimeout = -1 * time.Second

	var callbackCount atomic.Int64
	seen := make(map[string]bool)
	sm.SetOnSessionExpired(func(sessionID string) {
		callbackCount.Add(1)
		seen[sessionID] = true
	})

	const N = 5
	created := make([]string, 0, N)
	for range N {
		sid, err := sm.CreateSession(nil)
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		// CreateSession leaves State=SessionStateNew with ClientConn nil,
		// which the cleanup code treats as "pending" (2-minute grace).
		// Push the session into the active branch by activating it.
		sm.mutex.Lock()
		s := sm.sessions[sid]
		s.State = SessionStateActive
		s.LastActiveAt = time.Now().Add(-1 * time.Hour)
		sm.mutex.Unlock()
		created = append(created, sid)
	}

	sm.cleanupExpiredSessions()

	if got := callbackCount.Load(); got != int64(N) {
		t.Fatalf("callback fired %d times, want %d", got, N)
	}
	for _, sid := range created {
		if !seen[sid] {
			t.Errorf("callback never saw session %s", sid)
		}
	}

	// Sessions should also be gone from the map.
	sm.mutex.Lock()
	leftover := len(sm.sessions)
	sm.mutex.Unlock()
	if leftover != 0 {
		t.Errorf("expected 0 sessions in map after cleanup, got %d", leftover)
	}
}

// TestOnSessionExpiredCallback_NilSafe — when no callback is registered,
// cleanupExpiredSessions must still work (backward-compat for any caller
// that hasn't opted in yet).
func TestOnSessionExpiredCallback_NilSafe(t *testing.T) {
	sm := NewSessionManager()
	sm.sessionTimeout = -1 * time.Second

	sid, err := sm.CreateSession(nil)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sm.mutex.Lock()
	s := sm.sessions[sid]
	s.State = SessionStateActive
	s.LastActiveAt = time.Now().Add(-1 * time.Hour)
	sm.mutex.Unlock()

	// Must not panic with no callback registered.
	sm.cleanupExpiredSessions()
}

// TestOnSessionExpiredCallback_NoDeadlock — the callback is invoked
// AFTER the SessionManager mutex is released, so it must be safe for the
// callback to call back into SessionManager. Validate by having the
// callback call CreateSession (acquires the same mutex).
func TestOnSessionExpiredCallback_NoDeadlock(t *testing.T) {
	sm := NewSessionManager()
	sm.sessionTimeout = -1 * time.Second

	sid, err := sm.CreateSession(nil)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sm.mutex.Lock()
	s := sm.sessions[sid]
	s.State = SessionStateActive
	s.LastActiveAt = time.Now().Add(-1 * time.Hour)
	sm.mutex.Unlock()

	done := make(chan struct{})
	sm.SetOnSessionExpired(func(string) {
		// If cleanupExpiredSessions still held the mutex this would deadlock.
		_, _ = sm.CreateSession(nil)
		close(done)
	})

	go sm.cleanupExpiredSessions()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("callback deadlocked — mutex not released before invocation")
	}
}
