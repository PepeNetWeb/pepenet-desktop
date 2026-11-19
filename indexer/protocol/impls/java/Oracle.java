import java.math.BigInteger;

// §3.4 coinbase fee oracle — the participant-median rate function. The §5 generator
// INJECTS `rate` per block, so the fold never runs this; it is the separate,
// spec-mandated stateless computation, exercised by the hand vectors in Behav.
// Every step is fixed-width integer math with the SIGNED under-claim clamp, the
// fee-bearing participant filter (MIN_FEE_SAMPLE degrade, boundary INCLUSIVE), and
// the LOWER-median single-element index rule pinned.
final class Oracle {

    static BigInteger rate(long[] coinbase, long[] subsidy, long[] blockBytes) {
        int n = coinbase.length;
        if (n == 0) return Const.DUST_FLOOR;
        long[] fpb = new long[n];
        int k = 0;                                           // participant count |P|
        for (int i = 0; i < n; i++) {
            // fees = max(0, coinbase − subsidy) in SIGNED wide math (BigInteger never
            // wraps): a miner may under-claim (coinbase < subsidy); an unsigned
            // subtraction would wrap and wrongly enroll the block as a huge
            // participant. Clamp at 0 → an under-claim reads as 0 fees, i.e. a
            // NON-participant.
            BigInteger fees = BigInteger.valueOf(coinbase[i]).subtract(BigInteger.valueOf(subsidy[i]));
            if (fees.signum() < 0) fees = BigInteger.ZERO;
            long b = blockBytes[i] > 0 ? blockBytes[i] : 1;
            long v = fees.divide(BigInteger.valueOf(b)).longValueExact();  // floor, whole koinu/byte
            // §3.4 participant list P: fee-bearing blocks only, membership decided
            // AFTER the floor division (tiny fees flooring to 0 do not participate).
            if (v >= 1) fpb[k++] = v;
        }
        // Degrade, don't extrapolate: a small sample is spoofably cheap to own.
        // Boundary INCLUSIVE — exactly MIN_FEE_SAMPLE participants take the median.
        if (k < Const.MIN_FEE_SAMPLE) return Const.DUST_FLOOR;
        java.util.Arrays.sort(fpb, 0, k);
        // LOWER median, one index rule for any |P| ≥ 1: odd → the true middle; even →
        // the lower of the two middles. Always an observed element, never an average —
        // no rounding rule exists for indexers to split on.
        BigInteger med = BigInteger.valueOf(fpb[(k - 1) / 2]);
        BigInteger r = med.multiply(BigInteger.valueOf(Const.REF_SIZE));
        return r.max(Const.DUST_FLOOR).min(Const.RATE_CAP);  // floor (defensive; med ≥ 1 here) + cap
    }

    private Oracle() {}
}
