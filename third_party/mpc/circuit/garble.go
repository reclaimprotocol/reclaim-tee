//
// Copyright (c) 2019-2025 Markku Rossi
//
// All rights reserved.
//

package circuit

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/markkurossi/mpc/ot"
)

func idxUnary(l0 ot.Label) int {
	if l0.S() {
		return 1
	}
	return 0
}

func idx(l0, l1 ot.Label) int {
	var ret int

	if l0.S() {
		ret |= 0x2
	}
	if l1.S() {
		ret |= 0x1
	}

	return ret
}

func encrypt(alg cipher.Block, a, b, c ot.Label, t uint32,
	data *ot.LabelData) ot.Label {

	k := makeK(a, b, t)

	k.GetData(data)
	alg.Encrypt(data[:], data[:])

	var pi ot.Label
	pi.SetData(data)

	pi.Xor(k)
	pi.Xor(c)

	return pi
}

func decrypt(alg cipher.Block, a, b ot.Label, t uint32, c ot.Label,
	data *ot.LabelData) ot.Label {

	k := makeK(a, b, t)

	k.GetData(data)
	alg.Encrypt(data[:], data[:])

	var crypted ot.Label
	crypted.SetData(data)

	c.Xor(crypted)
	c.Xor(k)

	return c
}

func makeK(a, b ot.Label, t uint32) ot.Label {
	a.Mul2()

	b.Mul4()
	a.Xor(b)

	a.Xor(ot.NewTweak(t))

	return a
}

// Hash function for half gates: Hπ(x, i) to be π(K) ⊕ K where K = 2x ⊕ i
func encryptHalfReference(alg cipher.Block, x ot.Label, i uint32,
	data *ot.LabelData) ot.Label {

	k := makeKHalf(x, i)

	k.GetData(data)
	alg.Encrypt(data[:], data[:])

	var pi ot.Label
	pi.SetData(data)

	pi.Xor(k)

	return pi
}

// Optimized version of encryptHalfReference. Label operations are
// inlined below, producing about 11% performance improvements.
func encryptHalf(alg cipher.Block, x ot.Label, i uint32,
	data *ot.LabelData) ot.Label {

	// k := makeKHalf(x, i) {
	k := x
	//   k.Mul2()
	k.D0 <<= 1
	k.D0 |= (k.D1 >> 63)
	k.D1 <<= 1
	//   k.Xor(ot.NewTweak(i))
	k.D1 ^= uint64(i)
	// }

	// k.GetData(data) {
	binary.BigEndian.PutUint64(data[0:8], k.D0)
	binary.BigEndian.PutUint64(data[8:16], k.D1)
	// }

	alg.Encrypt(data[:], data[:])

	var pi ot.Label
	// pi.SetData(data) {
	pi.D0 = binary.BigEndian.Uint64((*data)[0:8])
	pi.D1 = binary.BigEndian.Uint64((*data)[8:16])
	// }

	// pi.Xor(k) {
	pi.D0 ^= k.D0
	pi.D1 ^= k.D1
	// }

	return pi
}

// K = 2x ⊕ i
func makeKHalf(x ot.Label, i uint32) ot.Label {
	x.Mul2()
	x.Xor(ot.NewTweak(i))
	return x
}

func makeLabels(rand io.Reader, r ot.Label) (ot.Wire, error) {
	l0, err := ot.NewLabel(rand)
	if err != nil {
		return ot.Wire{}, err
	}
	l1 := l0
	l1.Xor(r)

	return ot.Wire{
		L0: l0,
		L1: l1,
	}, nil
}

// Garbled contains garbled circuit information.
//
// When a *Garbled is produced by Circuit.Garble, its Wires and Gates
// slices are backed by buffers checked out from a per-circuit sync.Pool.
// Callers SHOULD invoke Release() once they are done reading from it
// (typically after serializing to the wire). After Release the slices
// may be reused for a subsequent garble — the *Garbled MUST NOT be
// touched. Releasing is optional: skipping it just forgoes the pooling
// benefit, equivalent to the pre-pool behavior.
type Garbled struct {
	R     ot.Label
	Wires []ot.Wire
	Gates [][]ot.Label

	// scratch holds the buffers this Garbled's slices are carved from.
	// Release returns scratch to its origin pool. nil means this
	// Garbled was not produced from a pool (e.g. zero value, or pool
	// disabled — neither happens in the current implementation but
	// keeping the field nil-safe avoids a panic on stray Releases).
	scratch *garbledScratch
	pool    *sync.Pool
}

// Release returns the underlying scratch buffers to the per-circuit
// pool. Safe to call multiple times. After Release, the *Garbled must
// not be used.
func (g *Garbled) Release() {
	if g == nil || g.pool == nil {
		return
	}
	g.pool.Put(g.scratch)
	g.scratch = nil
	g.pool = nil
	g.Wires = nil
	g.Gates = nil
}

// garbledScratch holds the heap-resident buffers that Garble reuses
// across calls on the same *Circuit. The label slab is sized exactly
// for the circuit's garbled-table output: 2 labels per AND gate, 3
// per OR (after row reduction), 1 per INV. The slice-of-slices header
// array, the wire array, and the slab are all rooted in this struct
// so a single sync.Pool put/get cycles all three together.
type garbledScratch struct {
	wires []ot.Wire
	slab  []ot.Label
	gates [][]ot.Label
}

// scratchPools holds one *sync.Pool per *Circuit. Different circuits
// have different gate counts and slab sizes, so they cannot share a
// pool. Lookup is keyed by pointer identity — Circuit values are
// expected to be long-lived (compiled once and reused).
var scratchPools sync.Map // map[*Circuit]*sync.Pool

func (c *Circuit) scratchPool() *sync.Pool {
	if v, ok := scratchPools.Load(c); ok {
		return v.(*sync.Pool)
	}
	// Sum the label slots each gate type writes into the output table.
	// XOR/XNOR are "free" — no table entry. AND emits 2 (half-gate),
	// OR emits 3 (row-reduced from 4), INV emits 1.
	var slabSize int
	for i := range c.Gates {
		switch c.Gates[i].Op {
		case AND:
			slabSize += 2
		case OR:
			slabSize += 3
		case INV:
			slabSize += 1
		}
	}
	p := &sync.Pool{
		New: func() any {
			return &garbledScratch{
				wires: make([]ot.Wire, c.NumWires),
				slab:  make([]ot.Label, slabSize),
				gates: make([][]ot.Label, c.NumGates),
			}
		},
	}
	actual, _ := scratchPools.LoadOrStore(c, p)
	return actual.(*sync.Pool)
}

// Lambda returns the lambda value of the wire.
func (g *Garbled) Lambda(wire Wire) uint {
	if g.Wires[wire].L0.S() {
		return 1
	}
	return 0
}

// SetLambda sets the lambda value of the wire.
func (g *Garbled) SetLambda(wire Wire, val uint) {
	w := g.Wires[wire]
	if val == 0 {
		w.L0.SetS(false)
	} else {
		w.L0.SetS(true)
	}
	g.Wires[wire] = w
}

// Garble garbles the circuit.
//
// The returned *Garbled is backed by a slab + wire array checked out
// from a per-circuit sync.Pool. Callers should invoke Release() when
// done — see the Garbled doc comment. Calling Release is optional:
// without it the GC handles the buffers normally (same behavior as the
// pre-pool version of this function, just one extra reference in the
// pool's New until next GC).
func (c *Circuit) Garble(rand io.Reader, key []byte) (*Garbled, error) {
	pool := c.scratchPool()
	scratch := pool.Get().(*garbledScratch)

	// Create R.
	r, err := ot.NewLabel(rand)
	if err != nil {
		pool.Put(scratch)
		return nil, err
	}
	r.SetS(true)

	alg, err := aes.NewCipher(key)
	if err != nil {
		pool.Put(scratch)
		return nil, err
	}

	wires := scratch.wires
	slab := scratch.slab
	gates := scratch.gates

	// Assign all input wires.
	for i := 0; i < c.Inputs.Size(); i++ {
		w, err := makeLabels(rand, r)
		if err != nil {
			pool.Put(scratch)
			return nil, err
		}
		wires[i] = w
	}

	// Garble gates. Each call writes its labels into a 4-slot stack
	// table and returns (start, count); we copy those count labels
	// into a fresh slice of the slab and stash the view in gates[i].
	// The per-gate slice header allocation of the old API is gone —
	// gates[i] now points into the pooled slab.
	var data ot.LabelData
	var id uint32
	slabOff := 0
	var table [4]ot.Label
	for i := 0; i < len(c.Gates); i++ {
		gate := &c.Gates[i]
		start, count, err := gate.garbleInto(wires, alg, r, &id, &data, &table)
		if err != nil {
			pool.Put(scratch)
			return nil, err
		}
		if count == 0 {
			gates[i] = nil
			continue
		}
		copy(slab[slabOff:slabOff+count], table[start:start+count])
		gates[i] = slab[slabOff : slabOff+count : slabOff+count]
		slabOff += count
	}

	return &Garbled{
		R:       r,
		Wires:   wires,
		Gates:   gates,
		scratch: scratch,
		pool:    pool,
	}, nil
}

// garbleInto garbles the gate, writing its output table into the
// caller-provided fixed-size buffer. Returns (start, count) such that
// table[start : start+count] are the labels the caller should add to
// its garbled output. table must be zeroed by the caller (the function
// indexes into it both for read and write — pre-zeroing isn't strictly
// required because every path that reads `table[...]` first writes it,
// but keeping the convention reduces foot-gun risk).
//
// This replaces the pre-pool variant that allocated and returned its
// own []ot.Label every call. Callers carve a view of their own buffer
// using start/count and copy from `table`.
func (g *Gate) garbleInto(wires []ot.Wire, enc cipher.Block, r ot.Label,
	idp *uint32, data *ot.LabelData, table *[4]ot.Label) (start, count int, err error) {

	var a, b, c ot.Wire

	// Inputs.
	switch g.Op {
	case XOR, XNOR, AND, OR:
		b = wires[g.Input1]
		fallthrough

	case INV:
		a = wires[g.Input0]

	default:
		return 0, 0, fmt.Errorf("invalid gate type %s", g.Op)
	}

	// Output.
	switch g.Op {
	case XOR:
		l0 := a.L0
		l0.Xor(b.L0)

		l1 := l0
		l1.Xor(r)
		c = ot.Wire{
			L0: l0,
			L1: l1,
		}

	case XNOR:
		l0 := a.L0
		l0.Xor(b.L0)

		l1 := l0
		l1.Xor(r)
		c = ot.Wire{
			L0: l1,
			L1: l0,
		}

	case AND:
		pa := a.L0.S()
		pb := b.L0.S()

		j0 := *idp
		j1 := *idp + 1
		*idp = *idp + 2

		// First half gate.
		tg := encryptHalf(enc, a.L0, j0, data)
		tg.Xor(encryptHalf(enc, a.L1, j0, data))
		if pb {
			tg.Xor(r)
		}
		wg0 := encryptHalf(enc, a.L0, j0, data)
		if pa {
			wg0.Xor(tg)
		}

		// Second half gate.
		te := encryptHalf(enc, b.L0, j1, data)
		te.Xor(encryptHalf(enc, b.L1, j1, data))
		te.Xor(a.L0)
		we0 := encryptHalf(enc, b.L0, j1, data)
		if pb {
			we0.Xor(te)
			we0.Xor(a.L0)
		}

		// Combine halves
		l0 := wg0
		l0.Xor(we0)

		l1 := l0
		l1.Xor(r)

		c = ot.Wire{
			L0: l0,
			L1: l1,
		}
		table[0] = tg
		table[1] = te
		count = 2

	case OR, INV:
		// Row reduction creates labels below so that the first row is
		// all zero.

	default:
		panic("invalid gate type")
	}

	switch g.Op {
	case XOR, XNOR:
		// Free XOR.

	case AND:
		// Half AND garbled above.

	case OR:
		// a b c
		// -----
		// 0 0 0
		// 0 1 1
		// 1 0 1
		// 1 1 1
		id := *idp
		*idp = *idp + 1
		table[idx(a.L0, b.L0)] = encrypt(enc, a.L0, b.L0, c.L0, id, data)
		table[idx(a.L0, b.L1)] = encrypt(enc, a.L0, b.L1, c.L1, id, data)
		table[idx(a.L1, b.L0)] = encrypt(enc, a.L1, b.L0, c.L1, id, data)
		table[idx(a.L1, b.L1)] = encrypt(enc, a.L1, b.L1, c.L1, id, data)

		l0Index := idx(a.L0, b.L0)

		c.L0 = table[0]
		c.L1 = table[0]

		if l0Index == 0 {
			c.L1.Xor(r)
		} else {
			c.L0.Xor(r)
		}
		for i := 0; i < 4; i++ {
			if i == l0Index {
				table[i].Xor(c.L0)
			} else {
				table[i].Xor(c.L1)
			}
		}
		start = 1
		count = 3

	case INV:
		// a b c
		// -----
		// 0   1
		// 1   0
		id := *idp
		*idp = *idp + 1
		table[idxUnary(a.L0)] = encrypt(enc, a.L0, ot.Label{}, c.L1, id, data)
		table[idxUnary(a.L1)] = encrypt(enc, a.L1, ot.Label{}, c.L0, id, data)

		l0Index := idxUnary(a.L0)

		c.L0 = table[0]
		c.L1 = table[0]

		if l0Index == 0 {
			c.L0.Xor(r)
		} else {
			c.L1.Xor(r)
		}
		for i := 0; i < 2; i++ {
			if i == l0Index {
				table[i].Xor(c.L1)
			} else {
				table[i].Xor(c.L0)
			}
		}
		start = 1
		count = 1

	default:
		return 0, 0, fmt.Errorf("invalid operand %s", g.Op)
	}
	wires[g.Output] = c

	return start, count, nil
}
