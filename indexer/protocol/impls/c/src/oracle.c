// §3.4 / §5 oracle helpers — MTP and the coinbase fee-rate. Pure functions the
// harness feeds into begin_block; the fold itself takes (mtp, rate) as givens, so
// statelessness/chain-abstraction holds. Every step is fixed-width integer math
// with the under-claim clamp, the fee-bearing participant filter (MIN_FEE_SAMPLE
// degrade), and the lower-median single-element index rule pinned.
#include "sm.h"
#include <stdlib.h>

static int cmp_i64(const void *a, const void *b) {
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

// MTP(H) = median of the timestamps of the (up to 11) blocks strictly before H.
// For n>11 the most recent 11 are used; for n<11 the available ones. The median
// of k values is the sorted middle element at index k/2 (BIP113-style).
int64_t sm_mtp(const int64_t *timestamps, int n) {
    if (n <= 0) return 0;
    if (n > 11) { timestamps += (n - 11); n = 11; }
    int64_t tmp[11];
    for (int i = 0; i < n; i++) tmp[i] = timestamps[i];
    qsort(tmp, (size_t)n, sizeof(int64_t), cmp_i64);
    return tmp[n / 2];
}

uint64_t sm_oracle_rate(const int64_t *coinbase, const int64_t *subsidy,
                        const int64_t *block_bytes, int n) {
    if (n <= 0) return (uint64_t)SM_DUST_FLOOR;
    int64_t *fpb = malloc((size_t)n * sizeof(int64_t));
    int k = 0;                                           // participant count |P|
    for (int i = 0; i < n; i++) {
        // fees = max(0, coinbase − subsidy) in ≥128-bit SIGNED: a miner may
        // under-claim (coinbase < subsidy); an unsigned subtraction would wrap to
        // ~2^64 and wrongly enroll the block as a huge participant. Clamp at 0 →
        // an under-claim reads as 0 fees, i.e. a NON-participant.
        __int128 fees = (__int128)coinbase[i] - (__int128)subsidy[i];
        if (fees < 0) fees = 0;
        int64_t b = block_bytes[i] > 0 ? block_bytes[i] : 1;
        int64_t v = (int64_t)(fees / (__int128)b);       // floor, whole koinu/byte
        // §3.4 participant list P: fee-bearing blocks only, membership decided
        // AFTER the floor division (tiny fees flooring to 0 do not participate).
        if (v >= 1) fpb[k++] = v;
    }
    // Degrade, don't extrapolate: a small sample is spoofably cheap to own.
    // Boundary INCLUSIVE — exactly MIN_FEE_SAMPLE participants take the median.
    if (k < (int)SM_MIN_FEE_SAMPLE) { free(fpb); return (uint64_t)SM_DUST_FLOOR; }
    qsort(fpb, (size_t)k, sizeof(int64_t), cmp_i64);
    // LOWER median, one index rule for any |P| ≥ 1: odd → the true middle; even →
    // the lower of the two middles. Always an observed element, never an average —
    // no rounding rule exists for indexers to split on.
    int64_t med = fpb[(k - 1) / 2];
    free(fpb);
    __int128 r = (__int128)med * (__int128)SM_REF_SIZE;
    if (r < (__int128)SM_DUST_FLOOR) r = SM_DUST_FLOOR;  // floor (defensive; med ≥ 1 here)
    if (r > (__int128)SM_RATE_CAP)   r = SM_RATE_CAP;    // cap (bounds miner grief)
    return (uint64_t)r;
}
