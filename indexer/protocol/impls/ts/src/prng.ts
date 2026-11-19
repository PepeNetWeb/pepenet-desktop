// SplitMix64 (SPEC-conformance.md §1) — pinned, integer-only, wrapping uint64 via `& MASK64`.
// Conformance check (§1): next() from seed=0 returns 0xE220A8397B1DCDAF first (asserted in selftest).
import { MASK64 } from "./bytes.ts";

export class SplitMix64 {
  state: bigint;
  constructor(seed: bigint) {
    this.state = seed & MASK64; // "the seed IS the state (no warm-up)"
  }
  next(): bigint {
    this.state = (this.state + 0x9e3779b97f4a7c15n) & MASK64;
    let z = this.state;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK64;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK64;
    return (z ^ (z >> 31n)) & MASK64;
  }
  // bounded(n) := next() mod n  (n>0; n==0 → 0). PINNED plain modulo (§1: "identity, not low-bias").
  bounded(n: number | bigint): bigint {
    const m = BigInt(n);
    if (m === 0n) return 0n;
    return this.next() % m;
  }
  boundedN(n: number): number {
    // convenience for ≤32-bit control draws (counts, indices) — value stays small & exact.
    return Number(this.bounded(n));
  }
}
