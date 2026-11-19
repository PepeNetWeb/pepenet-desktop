package main

import "math/bits"

// 128-bit helpers. Go has no native 128-bit integer; the spec pins two unsigned
// ≥128-bit intermediate products (price·bps, burn·LEASE_QUANTUM) and the §8
// property fingerprint's order-independent u128 Σs. We use math/bits for the
// products and a hand-rolled {hi,lo} for the unsigned accumulator.

// mul64 returns the full 128-bit product a*b as (hi, lo).
func mul64(a, b uint64) (hi, lo uint64) { return bits.Mul64(a, b) }

// div128by64 divides the 128-bit numerator (hi,lo) by den, returning the 64-bit
// quotient. PRECONDITION: hi < den (else bits.Div64 panics on overflow). Callers
// MUST gate hi >= den first (it encodes "quotient >= 2^64") — see lease water-fill.
func div128by64(hi, lo, den uint64) uint64 {
	q, _ := bits.Div64(hi, lo, den)
	return q
}

// ---- unsigned 128-bit accumulator (property fingerprint Σs) ----

type u128 struct {
	hi uint64
	lo uint64
}

func u128FromU64(v uint64) u128 { return u128{hi: 0, lo: v} }

func (a u128) add(b u128) u128 {
	lo, carry := bits.Add64(a.lo, b.lo, 0)
	hi, _ := bits.Add64(a.hi, b.hi, carry)
	return u128{hi: hi, lo: lo}
}

// bytesLE returns the 16-byte little-endian encoding.
func (a u128) bytesLE() [16]byte {
	var out [16]byte
	for i := 0; i < 8; i++ {
		out[i] = byte(a.lo >> (8 * uint(i)))
		out[8+i] = byte(a.hi >> (8 * uint(i)))
	}
	return out
}
