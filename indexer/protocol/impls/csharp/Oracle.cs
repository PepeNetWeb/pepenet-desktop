using System;
using System.Collections.Generic;

namespace Pepenet;

/// <summary>
/// The coinbase fee oracle (§3.4) and the MTP median (§5). Both are pure
/// functions tested directly; the random fold injects `rate` per block (the
/// abstract SM does not recompute the oracle in the soak — see
/// SPEC-RATIONALE.md).
/// </summary>
public static class Oracle
{
    /// <summary>
    /// Participant median (§3.4): P = { ⌊max(0, coinbaseᵢ − subsidy)/bytesᵢ⌋ : value ≥ 1 };
    /// rate = |P| &lt; MIN_FEE_SAMPLE ? DUST_FLOOR
    ///                              : clamp(sorted_P[(|P|−1)/2] × REF_SIZE, DUST_FLOOR, RATE_CAP).
    /// The numerator is SIGNED in ≥128-bit (a miner may under-claim; unsigned would wrap and
    /// enroll the block as a huge participant — the clamp reads it as 0 fees = NON-participant);
    /// membership is decided AFTER the floor division (tiny fees flooring to 0 do not
    /// participate); the MIN_FEE_SAMPLE boundary is INCLUSIVE (exactly 1000 takes the median
    /// path); (|P|−1)/2 is the LOWER median — odd |P| ⇒ the true middle, even |P| ⇒ the lower
    /// of the two middles, always an observed element, never an average.
    /// </summary>
    public static ulong Rate(ulong[] coinbase, ulong[] blockBytes)
    {
        int n = coinbase.Length;
        if (n == 0 || blockBytes.Length != n) return K.DUST_FLOOR;
        var p = new List<ulong>(n);                                       // participant list P
        for (int i = 0; i < n; i++)
        {
            Int128 fees = (Int128)coinbase[i] - (Int128)K.SUBSIDY_KOINU; // signed
            if (fees < 0) fees = 0;                                       // clamp at 0 BEFORE dividing
            ulong bytes = blockBytes[i] > 0 ? blockBytes[i] : 1;
            ulong v = (ulong)(fees / (Int128)bytes);                      // floor
            if (v >= 1) p.Add(v);                                         // fee-bearing blocks only
        }
        if (p.Count < K.MIN_FEE_SAMPLE) return K.DUST_FLOOR;              // degrade, don't extrapolate
        p.Sort();
        ulong median = p[(p.Count - 1) / 2];                              // LOWER median
        UInt128 scaled = (UInt128)median * (UInt128)K.REF_SIZE;
        if (scaled < (UInt128)K.DUST_FLOOR) return K.DUST_FLOOR;
        if (scaled > (UInt128)K.RATE_CAP) return K.RATE_CAP;
        return (ulong)scaled;
    }

    /// <summary>
    /// MTP(H) = median of the timestamps of the ≤11 blocks strictly before H
    /// (block H excluded). Upper-middle (index ⌊k/2⌋) for even k; MTP(0) = 0.
    /// </summary>
    public static long Mtp(IReadOnlyList<long> timestamps, long H)
    {
        if (H <= 0) return 0;
        int k = (int)Math.Min(11, H);
        var win = new List<long>(k);
        for (long i = H - k; i < H; i++) win.Add(timestamps[(int)i]);
        win.Sort();
        return win[k / 2];
    }
}
