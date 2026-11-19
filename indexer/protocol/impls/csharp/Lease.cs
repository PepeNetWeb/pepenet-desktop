using System;
using System.Collections.Generic;

namespace Pepenet;

/// <summary>
/// Lease day computation (§3.4) and water-fill allocation (§3.5).
/// The exact water-fill algorithm is deferred by the spec to impls/c (forbidden);
/// this is an independent reading of the prose. See SPEC-RATIONALE.md.
/// </summary>
public static class Lease
{
    /// <summary>
    /// T = ⌊burn · LEASE_QUANTUM / (rate · BILLING_UNIT)⌋ name·days.
    /// Numerator computed in 128-bit (burn·LEASE_QUANTUM overflows u64). Returns
    /// UInt128 — the water-fill clamps it to total headroom, so the wide value is
    /// never narrowed/stored (SPEC-conformance §2).
    /// </summary>
    public static UInt128 TotalNameDays(ulong burn, ulong rate)
    {
        UInt128 num = (UInt128)burn * (UInt128)(ulong)K.LEASE_QUANTUM;
        UInt128 den = (UInt128)rate * (UInt128)(ulong)K.BILLING_UNIT;
        if (den == UInt128.Zero) return UInt128.Zero;   // fail closed (rate≥DUST_FLOOR makes this unreachable)
        return num / den;
    }

    /// <summary>Headroom in days for a name with current expiry, evaluated at `now` (MTP).</summary>
    public static long HeadroomDays(long expiry, long now)
    {
        long remaining = expiry - now;            // ≥0 for an owned name; ≤ MAX_LEASE by invariant
        long slack = K.MAX_LEASE - remaining;     // ≥0 by the MAX_LEASE invariant
        if (slack < 0) slack = 0;
        return slack / K.BILLING_UNIT;            // floor (slack ≥ 0 ⇒ truncation == floor)
    }

    /// <summary>
    /// Water-fill T name·days over names already sorted ascending-lexicographically.
    /// `headroom[i]` is name i's day cap. Returns add[i] (days). Names with
    /// headroom 0 are skipped (never counted, never awarded — §3.5).
    /// </summary>
    public static long[] WaterFill(UInt128 T, long[] headroom)
    {
        int nAll = headroom.Length;
        long[] add = new long[nAll];

        // Eligible = headroom>0, in the same (already-lex) order.
        var idx = new List<int>();
        long sumH = 0;
        long maxH = 0;
        foreach (var (h, i) in EnumerateWithIndex(headroom))
        {
            if (h > 0) { idx.Add(i); sumH += h; if (h > maxH) maxH = h; }
        }
        if (idx.Count == 0) return add; // nothing eligible

        // If T ≥ Σheadroom: every eligible name caps; surplus forfeited.
        if (T >= (UInt128)(ulong)sumH)
        {
            foreach (int i in idx) add[i] = headroom[i];
            return add;
        }

        // Now T fits in long (T < sumH ≤ ~207k). Find largest level λ with Σ min(h,λ) ≤ T.
        long Tl = (long)T;
        long lo = 0, hi = maxH;
        while (lo < hi)
        {
            long mid = lo + (hi - lo + 1) / 2;
            if (LevelSum(headroom, idx, mid) <= Tl) lo = mid; else hi = mid - 1;
        }
        long lambda = lo;
        long used = 0;
        foreach (int i in idx) { add[i] = Math.Min(headroom[i], lambda); used += add[i]; }

        long remainder = Tl - used; // < count of names with headroom > λ
        // +1 day to first `remainder` headroom-having names (with h>λ) in ascending-lex order.
        foreach (int i in idx)
        {
            if (remainder == 0) break;
            if (headroom[i] > lambda) { add[i] += 1; remainder--; }
        }
        return add;
    }

    private static long LevelSum(long[] headroom, List<int> idx, long lambda)
    {
        long s = 0;
        foreach (int i in idx) s += Math.Min(headroom[i], lambda);
        return s;
    }

    private static IEnumerable<(long h, int i)> EnumerateWithIndex(long[] a)
    {
        for (int i = 0; i < a.Length; i++) yield return (a[i], i);
    }
}
