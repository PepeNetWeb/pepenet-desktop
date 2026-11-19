// SplitMix64 — the pinned cross-language PRNG (SPEC-conformance.md §PRNG).
//
// Integer-only, 64-bit state, exact constants. Every reference implementation
// MUST reproduce this bit-for-bit: all arithmetic is wrapping uint64, there is
// NO floating point, and bounded() is a plain modulo. A seed expands directly
// into the state (SplitMix64 is its own seeder).
#ifndef SM_PRNG_H
#define SM_PRNG_H

#include <stdint.h>

typedef struct { uint64_t s; } SmRng;

// Seed the generator. The state IS the seed (SplitMix64 needs no warm-up).
static inline void sm_rng_seed(SmRng *r, uint64_t seed) { r->s = seed; }

// Next 64-bit output. Wrapping add of the golden-ratio increment, then the
// two fixed xor-shift-multiply finalizers.
static inline uint64_t sm_rng_next(SmRng *r) {
    uint64_t z = (r->s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

// Unbiased-enough bounded draw, PINNED as next() % n (identity across languages
// matters; statistical bias does not for a test generator). n == 0 returns 0.
static inline uint64_t sm_rng_bounded(SmRng *r, uint64_t n) {
    return n ? sm_rng_next(r) % n : 0;
}

#endif
