package main

import "crypto/sha256"

// SplitMix64 PRNG, pinned by SPEC-conformance.md §1. Not in the stdlib; rolled here.
// All arithmetic is wrapping uint64. The seed IS the state (no warm-up).
type splitMix64 struct{ state uint64 }

func newPRNG(seed uint64) *splitMix64 { return &splitMix64{state: seed} }

func (p *splitMix64) next() uint64 {
	p.state = p.state + 0x9E3779B97F4A7C15 // wraps mod 2^64
	z := p.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// bounded(n): plain modulo, PINNED as identity (not low-bias). n==0 → 0.
func (p *splitMix64) bounded(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	return p.next() % n
}

// hash160 = RIPEMD160(SHA256(x)) — the legacy identity hash (§0, §4).
func hash160(x []byte) [20]byte {
	s := sha256.Sum256(x)
	return ripemd160(s[:])
}
