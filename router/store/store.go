package store

import (
	"context"
	"errors"
)

// ErrNotFound is returned when a Pair lookup or delete targets an unknown ID.
var ErrNotFound = errors.New("pair not found")

// Store is the persistence interface for the pair registry. The router
// holds no in-process state of its own; everything observable lives here.
//
// Implementations must be safe for concurrent use.
type Store interface {
	GetPair(ctx context.Context, id string) (*Pair, error)
	UpsertPair(ctx context.Context, p *Pair) error
	ListPairs(ctx context.Context) ([]*Pair, error)
	DeletePair(ctx context.Context, id string) error
}
