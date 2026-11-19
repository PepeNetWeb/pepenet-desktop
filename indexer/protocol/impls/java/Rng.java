// SplitMix64 PRNG — derived from protocol-sm/SPEC-conformance.md §1.
//
// 64-bit state, integer-only, no floating point. All arithmetic is wrapping
// uint64. Java `long` is two's-complement 64-bit; `+` and `*` wrap with the
// identical bit pattern as unsigned, so they are reused directly. The only
// places signedness matters are the right shift (MUST be the unsigned `>>>`)
// and `bounded` (an UNSIGNED modulo — Long.remainderUnsigned).
//
// Conformance anchor (§1): next() from seed=0 returns 0xE220A8397B1DCDAF first.
final class Rng {
    private long state;

    Rng(long seed) { this.state = seed; }   // the seed IS the state (no warm-up)

    long next() {
        state = state + 0x9E3779B97F4A7C15L;            // wrapping add
        long z = state;
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;     // unsigned shift, wrapping mul
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        return z ^ (z >>> 31);
    }

    // bounded(n) := next() mod n   (n>0; n==0 -> 0). PINNED as a plain unsigned
    // modulo (the identity reduction, not a low-bias rejection sampler).
    long bounded(long n) {
        if (n == 0) return 0;
        return Long.remainderUnsigned(next(), n);
    }

    // Convenience: a bounded draw whose result is known to fit a small int.
    int bnd(long n) { return (int) bounded(n); }

    long getState() { return state; }
    void setState(long s) { this.state = s; }
}
