import java.math.BigInteger;

// Lease water-fill (§3.5) — one of the §2 "load-bearing anti-fork" computations.
//
//   T = floor(value * LEASE_QUANTUM / (rate * BILLING_UNIT))   name-days, >=128-bit numerator
//   fail-closed if T == 0
//   per-name headroom h_i = floor((MAX_LEASE - (expiry_i - now)) / BILLING_UNIT) days
//   raise a uniform level λ (each takes min(h_i, λ)); capped names redistribute;
//   integer remainder +1 day to the first headroom-having names in ASCENDING-LEX order;
//   if every name caps while T>0, the surplus is forfeited.
//
// Caller passes curExpiry[] already in ascending-lex name order, so index order IS
// the lex order the remainder step walks. Returns add[] days (aligned), or null if
// T == 0 (fail-closed).
final class Lease {

    static long[] waterfill(long[] curExpiry, long mtp, BigInteger value, BigInteger rate) {
        BigInteger T = value.multiply(BigInteger.valueOf(Const.LEASE_QUANTUM))
                            .divide(rate.multiply(BigInteger.valueOf(Const.BILLING_UNIT)));
        if (T.signum() == 0) return null;     // must cover >=1 day (fail-closed)

        int n = curExpiry.length;
        long[] h = new long[n];
        long maxh = 0;
        for (int i = 0; i < n; i++) {
            long held = curExpiry[i] - mtp;          // remaining lease seconds (>=0 for owned; 0 for fresh)
            long hi = (Const.MAX_LEASE - held) / Const.BILLING_UNIT;
            if (hi < 0) hi = 0;                       // already at/over the ceiling
            h[i] = hi;
            if (hi > maxh) maxh = hi;
        }

        // largest λ in [0, maxh] with Σ min(h_i, λ) <= T
        long lo = 0, hi = maxh, lambda = 0;
        while (lo <= hi) {
            long mid = (lo + hi) >>> 1;
            long sum = 0;
            for (long hv : h) sum += Math.min(hv, mid);
            if (BigInteger.valueOf(sum).compareTo(T) <= 0) { lambda = mid; lo = mid + 1; }
            else hi = mid - 1;
        }

        long[] add = new long[n];
        BigInteger used = BigInteger.ZERO;
        for (int i = 0; i < n; i++) { add[i] = Math.min(h[i], lambda); used = used.add(BigInteger.valueOf(add[i])); }

        // remainder: +1 day to names that still have headroom (h_i > λ), ascending-lex (index) order
        BigInteger give = T.subtract(used);
        for (int i = 0; i < n && give.signum() > 0; i++) {
            if (h[i] > lambda) { add[i] += 1; give = give.subtract(BigInteger.ONE); }
        }
        // any leftover `give` here means every remaining name capped → forfeited
        return add;
    }
}
