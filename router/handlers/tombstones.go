package handlers

import (
	"sync"
	"time"
)

// tombstoneTTL bounds how long a /dead'd pair_id is remembered. Sized to
// outlive any in-flight TEE heartbeat-loop retry cycle so the TEE can't
// re-register the same pair_id after /dead succeeded.
const tombstoneTTL = 5 * time.Minute

// tombstones is an in-memory set of recently-killed pair_ids. /dead adds;
// /register rejects. Per-replica (Cloud Run scales router to ≤10) — if a
// re-register hits a different replica that doesn't know about the kill,
// the stale-row GC catches the resurrected row within ~2.5 minutes.
type tombstones struct {
	mu      sync.Mutex
	entries map[string]time.Time // pair_id → expiry
}

func newTombstones() *tombstones {
	return &tombstones{entries: make(map[string]time.Time)}
}

// add marks pair_id as tombstoned. Idempotent.
func (t *tombstones) add(pairID string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries[pairID] = now.Add(tombstoneTTL)
}

// contains reports whether pair_id is currently tombstoned. Sweeps expired
// entries opportunistically.
func (t *tombstones) contains(pairID string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	exp, ok := t.entries[pairID]
	if !ok {
		return false
	}
	if !now.Before(exp) {
		delete(t.entries, pairID)
		return false
	}
	return true
}
