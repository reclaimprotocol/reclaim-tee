package handlers

import (
	"testing"
	"time"
)

func TestTombstones_AddedThenContains(t *testing.T) {
	ts := newTombstones()
	now := time.Unix(1_700_000_000, 0)
	ts.add("pair-A", now)
	if !ts.contains("pair-A", now.Add(time.Second)) {
		t.Fatal("tombstoned pair should be contained")
	}
	if ts.contains("pair-B", now.Add(time.Second)) {
		t.Fatal("untombstoned pair should not be contained")
	}
}

func TestTombstones_ExpiresAfterTTL(t *testing.T) {
	ts := newTombstones()
	now := time.Unix(1_700_000_000, 0)
	ts.add("pair-A", now)
	if ts.contains("pair-A", now.Add(tombstoneTTL+time.Second)) {
		t.Fatal("expired tombstone should not be contained")
	}
}

func TestTombstones_OpportunisticSweepOnContains(t *testing.T) {
	ts := newTombstones()
	now := time.Unix(1_700_000_000, 0)
	ts.add("expired", now)
	ts.add("fresh", now.Add(4*time.Minute))
	_ = ts.contains("expired", now.Add(tombstoneTTL+time.Second))
	if len(ts.entries) != 1 {
		t.Fatalf("expected expired entry to be swept, got %d entries", len(ts.entries))
	}
}
