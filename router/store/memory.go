package store

import (
	"context"
	"sync"
)

// MemoryStore is an in-process implementation of Store, used for local
// development and tests. The production deployment uses a Firestore-backed
// Store that is added later.
type MemoryStore struct {
	mu    sync.RWMutex
	pairs map[string]*Pair
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{pairs: make(map[string]*Pair)}
}

func (s *MemoryStore) GetPair(_ context.Context, id string) (*Pair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.pairs[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *p
	return &cp, nil
}

func (s *MemoryStore) UpsertPair(_ context.Context, p *Pair) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *p
	s.pairs[p.ID] = &cp
	return nil
}

func (s *MemoryStore) ListPairs(_ context.Context) ([]*Pair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Pair, 0, len(s.pairs))
	for _, p := range s.pairs {
		cp := *p
		out = append(out, &cp)
	}
	return out, nil
}

func (s *MemoryStore) DeletePair(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.pairs[id]; !ok {
		return ErrNotFound
	}
	delete(s.pairs, id)
	return nil
}
