// fee.c — see fee.h. Deliberately a line-for-line cousin of the protocol's
// oracle.c (sm_oracle_rate): same fee inference, same under-claim clamp, same
// participant rule, same observed-element quantile discipline. What changes
// is the QUESTION — a payer picking a fee wants the recent 3rd quartile (be
// above most of what's clearing right now), not a week's lower median.
#include "fee.h"
#include <stdlib.h>

static int cmp_i64(const void *a, const void *b) {
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

int64_t fee_estimate(const int64_t *coinbase, const int64_t *block_bytes,
                     int n, int64_t subsidy) {
    if (n <= 0) return FEE_FLOOR_K;
    int64_t fpb[FEE_EST_WINDOW];
    if (n > FEE_EST_WINDOW) n = FEE_EST_WINDOW;
    int k = 0;
    for (int i = 0; i < n; i++) {
        // fees = max(0, coinbase − subsidy) in SIGNED ≥128-bit — oracle.c's
        // under-claim clamp: an unsigned wrap would enroll the block as a
        // huge participant instead of a non-participant
        __int128 fees = (__int128)coinbase[i] - (__int128)subsidy;
        if (fees < 0) fees = 0;
        int64_t b = block_bytes[i] > 0 ? block_bytes[i] : 1;
        int64_t v = (int64_t)(fees / (__int128)b);
        // participants are fee-bearing AFTER the floor division, §3.4's rule
        if (v >= 1) fpb[k++] = v;
    }
    if (k < FEE_MIN_SAMPLE) return FEE_FLOOR_K;     // degrade, don't extrapolate
    qsort(fpb, (size_t)k, sizeof *fpb, cmp_i64);
    // 3rd quartile by nearest rank: ceil(3k/4)th smallest — like the rate's
    // lower-median rule it is always an observed element, never an average
    int64_t q3 = fpb[(3 * k - 1) / 4];
    __int128 fee = (__int128)q3 * FEE_TX_BYTES;
    if (fee < FEE_FLOOR_K) fee = FEE_FLOOR_K;
    if (fee > FEE_CAP_K)   fee = FEE_CAP_K;
    return (int64_t)fee;
}
