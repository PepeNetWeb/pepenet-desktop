using System;

namespace Pepenet;

/// <summary>
/// SplitMix64 (SPEC-conformance.md §1). 64-bit state, integer only.
/// All arithmetic is wrapping uint64 — in C# that means an `unchecked` context,
/// because the BCL has no SplitMix64 type and C# `ulong` * / + WRAP only inside
/// `unchecked` (which is the default for `ulong`, but stated explicitly here to
/// make the wrap intentional — see SPEC-RATIONALE.md).
/// Conformance: next() from seed=0 returns 0xE220A8397B1DCDAF first.
/// </summary>
public sealed class SplitMix64
{
    private ulong _state;

    public SplitMix64(ulong seed) { _state = seed; } // the seed IS the state (no warm-up)

    public ulong Next()
    {
        unchecked
        {
            _state = _state + 0x9E3779B97F4A7C15UL;
            ulong z = _state;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
            return z ^ (z >> 31);
        }
    }

    /// <summary>bounded(n) := next() mod n ; n==0 → 0. Pinned plain modulo (not low-bias).</summary>
    public ulong Bounded(ulong n) => n == 0 ? 0UL : Next() % n;

    /// <summary>Convenience for the common small bounds used by the generator/fuzzer.</summary>
    public int Bnd(int n) => n <= 0 ? 0 : (int)(Next() % (ulong)n);
}
