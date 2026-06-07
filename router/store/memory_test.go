package store

import (
	"errors"
	"sync"
	"testing"
)

func TestMemoryStore_GetMissing(t *testing.T) {
	s := NewMemoryStore()
	_, err := s.GetPair(t.Context(), "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryStore_UpsertRoundTrip(t *testing.T) {
	s := NewMemoryStore()
	p := &Pair{ID: "p1", TEEKAddr: "10.0.0.1:443"}
	if err := s.UpsertPair(t.Context(), p); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err := s.GetPair(t.Context(), "p1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.TEEKAddr != "10.0.0.1:443" {
		t.Fatalf("addr round-trip: %+v", got)
	}
}

func TestMemoryStore_DefensiveCopyOnRead(t *testing.T) {
	// Mutating a returned Pair must not affect what's in the store.
	s := NewMemoryStore()
	_ = s.UpsertPair(t.Context(), &Pair{ID: "p1", TEEKAddr: "original"})
	got, _ := s.GetPair(t.Context(), "p1")
	got.TEEKAddr = "tampered"
	got2, _ := s.GetPair(t.Context(), "p1")
	if got2.TEEKAddr != "original" {
		t.Fatalf("defensive copy failed: store mutated to %q", got2.TEEKAddr)
	}
}

func TestMemoryStore_DefensiveCopyOnWrite(t *testing.T) {
	// Mutating a Pair after upserting it must not affect what's in the store.
	s := NewMemoryStore()
	p := &Pair{ID: "p1", TEEKAddr: "original"}
	_ = s.UpsertPair(t.Context(), p)
	p.TEEKAddr = "tampered"
	got, _ := s.GetPair(t.Context(), "p1")
	if got.TEEKAddr != "original" {
		t.Fatalf("defensive copy failed: store mutated to %q", got.TEEKAddr)
	}
}

func TestMemoryStore_DeleteMissing(t *testing.T) {
	s := NewMemoryStore()
	err := s.DeletePair(t.Context(), "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryStore_List(t *testing.T) {
	s := NewMemoryStore()
	_ = s.UpsertPair(t.Context(), &Pair{ID: "p1"})
	_ = s.UpsertPair(t.Context(), &Pair{ID: "p2"})
	pairs, err := s.ListPairs(t.Context())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d", len(pairs))
	}
}

func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	// Sanity check under -race. 100 concurrent upserts and reads must not
	// produce data races or panics.
	s := NewMemoryStore()
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			id := "p"
			_ = s.UpsertPair(t.Context(), &Pair{ID: id, ActiveSessions: i})
			_, _ = s.GetPair(t.Context(), id)
			_, _ = s.ListPairs(t.Context())
		})
	}
	wg.Wait()
}
