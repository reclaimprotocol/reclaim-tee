package main

import (
	"sync"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/shared"
)

// TestCleanupSession_ConcurrentIsIdempotent locks in the fix from
// 2026-06-09: cleanupSession can be called many times for the same
// session, but the activeSessions counter must drop by exactly 1.
//
// Before the fix, the function bailed when sessionManager.CloseSession
// returned "session already gone", which meant the decrement was gated
// on being the FIRST caller. Two cleanup paths legitimately fire in
// the normal flow (websocket exit + per-session WS handler exit), so
// every session left one increment uncounted. Under load this surfaced
// as 600+ phantom sessions in /pairs.active_sessions long after the
// SessionManager map had drained.
func TestCleanupSession_ConcurrentIsIdempotent(t *testing.T) {
	logger := shared.NewNopLogger()
	teek := &TEEK{
		sessionManager:    NewTEEKSessionManager(),
		sessionTerminator: shared.NewSessionTerminator(logger),
		logger:            logger,
	}

	// Create one session.
	sid, err := teek.sessionManager.CreateSession(nil)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	teek.sessionManager.SetTEEKSessionState(sid, &TEEKSessionState{})
	teek.activeSessions.Add(1)

	// Fire many concurrent cleanupSession calls for that one session.
	const N = 64
	var wg sync.WaitGroup
	wg.Add(N)
	for range N {
		go func() {
			defer wg.Done()
			teek.cleanupSession(sid)
		}()
	}
	wg.Wait()

	if got := teek.activeSessions.Load(); got != 0 {
		t.Fatalf("activeSessions = %d, want 0 (counter leaked: %d cleanup calls double-decremented or skipped)", got, N)
	}
}

// TestCleanupSession_DifferentSessions_NoCrossEffect makes sure the
// CleanedUp flag is per-session, not per-process — cleaning session A
// must not block cleanup of session B.
func TestCleanupSession_DifferentSessions_NoCrossEffect(t *testing.T) {
	logger := shared.NewNopLogger()
	teek := &TEEK{
		sessionManager:    NewTEEKSessionManager(),
		sessionTerminator: shared.NewSessionTerminator(logger),
		logger:            logger,
	}

	const N = 32
	sids := make([]string, N)
	for i := range N {
		sid, err := teek.sessionManager.CreateSession(nil)
		if err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		teek.sessionManager.SetTEEKSessionState(sid, &TEEKSessionState{})
		teek.activeSessions.Add(1)
		sids[i] = sid
	}

	// Each session gets several concurrent cleanup attempts.
	var wg sync.WaitGroup
	for _, sid := range sids {
		sid := sid
		for range 3 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				teek.cleanupSession(sid)
			}()
		}
	}
	wg.Wait()

	if got := teek.activeSessions.Load(); got != 0 {
		t.Fatalf("activeSessions = %d, want 0 after cleaning %d sessions", got, N)
	}
}
