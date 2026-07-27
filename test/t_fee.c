/* t_fee.c — the fee quote. Every send attaches whatever this returns, so a
 * quote that can go to zero underpays into a stuck tx, and one that can run
 * away drains the wallet a miner-inflated coinbase at a time.
 *
 * Proves the constants fee.h pins are the ones fee.c actually applies: the
 * 0.001 relay FLOOR, the 100× CAP, the 144-block window, the 4-block minimum
 * sample, and the 480-byte reference tx (which must be ≥ the 464 B the header
 * derives from the wallet's own shape: 10 + 2×148 + 2×34 + 90).
 *
 * Proves the quote's ALGEBRA against an independent re-implementation of §3.4's
 * rule written here from the header text alone (128-bit fee inference, the
 * under-claim clamp, floor-division BEFORE the participant test, nearest-rank
 * 3rd quartile, then clamp) — agreement on thousands of random block feeds,
 * including feeds built to sit exactly on the floor and cap boundaries.
 *
 * Proves the invariants a payer depends on:
 *   · the answer is ALWAYS in [FLOOR, CAP] and never zero — for every input,
 *     including n ≤ 0, NULL arrays, zero/negative block sizes, coinbases below
 *     the subsidy, and a whole feed of non-participants;
 *   · it is monotonic — raising every coinbase never lowers the quote, raising
 *     every block size never raises it;
 *   · it is an OBSERVED element × 480, never an average, unless clamped;
 *   · it never overflows: a coinbase of INT64_MAX with the real subsidy clamps
 *     to the cap instead of wrapping, and an under-claiming block enrolls as a
 *     non-participant instead of as a 2^64-sized one;
 *   · it never writes through its const inputs.
 *
 * SCOPE NOTE: the task's "monotonic in size" does not apply literally — this
 * API takes no tx size, it PINS one (FEE_TX_BYTES). The monotonicity that
 * exists is in the block feed, and it is proved above; the pinned size is
 * asserted against the header's own arithmetic.
 */
#include "fee.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail, g_ok, g_nfail;
#define CHECK(cond, name) do { \
    if (cond) { printf("ok   %s\n", name); g_ok++; } \
    else      { printf("FAIL %s\n", name); g_fail = 1; g_nfail++; } \
} while (0)

/* deterministic PRNG — never rand() */
static uint64_t g_rng = 0xFEE5EED0BADC0DEULL;
static uint64_t sm64(void) {
    uint64_t z = (g_rng += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* ── independent reference: §3.4's rule, re-derived from fee.h's prose ───── */
static int cmp64(const void *a, const void *b) {
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}
static int64_t ref_estimate(const int64_t *cb, const int64_t *bz, int n, int64_t subsidy) {
    if (n <= 0) return FEE_FLOOR_K;
    if (n > FEE_EST_WINDOW) n = FEE_EST_WINDOW;
    int64_t *v = malloc((size_t)n * sizeof *v);
    int k = 0;
    for (int i = 0; i < n; i++) {
        __int128 fees = (__int128)cb[i] - (__int128)subsidy;   /* under-claim clamp */
        if (fees < 0) fees = 0;
        int64_t b = bz[i] > 0 ? bz[i] : 1;
        __int128 q = fees / (__int128)b;                       /* floor first … */
        int64_t qq = (int64_t)q;
        if (qq >= 1) v[k++] = qq;                              /* … then enrol */
    }
    int64_t out;
    if (k < FEE_MIN_SAMPLE) out = FEE_FLOOR_K;
    else {
        qsort(v, (size_t)k, sizeof *v, cmp64);
        __int128 f = (__int128)v[(3 * k - 1) / 4] * FEE_TX_BYTES;
        if (f < FEE_FLOOR_K) f = FEE_FLOOR_K;
        if (f > FEE_CAP_K)   f = FEE_CAP_K;
        out = (int64_t)f;
    }
    free(v);
    return out;
}

/* the production subsidy engine.c feeds in: 10 000 × KOINU */
#define SUBSIDY 1000000000000LL

int main(void) {
    int64_t cb[600], bz[600];
    char name[160];

    /* ═══ 1. the pinned constants ═══════════════════════════════════════ */
    printf("-- pinned rate constants --\n");
    CHECK(FEE_FLOOR_K == 100000LL,        "FEE_FLOOR_K is the 0.001 relay floor (100000 koinu)");
    CHECK(FEE_CAP_K == 100 * FEE_FLOOR_K, "FEE_CAP_K is 100x the floor (0.1)");
    CHECK(FEE_EST_WINDOW == 144,          "FEE_EST_WINDOW is 144 blocks (~2.5 h)");
    CHECK(FEE_MIN_SAMPLE == 4,            "FEE_MIN_SAMPLE is 4 fee-bearing blocks");
    CHECK(FEE_TX_BYTES == 480,            "FEE_TX_BYTES is 480");
    CHECK(FEE_TX_BYTES >= 10 + 2*148 + 2*34 + 90,
          "FEE_TX_BYTES covers the header's own shape (10 + 2x148 + 2x34 + 90 = 464)");
    /* the floor must be reachable as a quote, i.e. below the cap and above 0 */
    CHECK(FEE_FLOOR_K > 0 && FEE_FLOOR_K < FEE_CAP_K, "floor is positive and below the cap");

    /* ═══ 2. degenerate feeds all degrade to the floor ══════════════════ */
    printf("-- degrade, never extrapolate --\n");
    CHECK(fee_estimate(NULL, NULL, 0, SUBSIDY) == FEE_FLOOR_K,
          "n == 0 with NULL arrays returns the floor (no dereference)");
    CHECK(fee_estimate(NULL, NULL, -1, SUBSIDY) == FEE_FLOOR_K, "n == -1 returns the floor");
    CHECK(fee_estimate(NULL, NULL, -2147483647, SUBSIDY) == FEE_FLOOR_K,
          "hugely negative n returns the floor");
    for (int nb = 1; nb < FEE_MIN_SAMPLE; nb++) {
        for (int i = 0; i < nb; i++) { cb[i] = SUBSIDY + 5000 * 1000; bz[i] = 1000; }
        snprintf(name, sizeof name, "%d fee-bearing block(s) < FEE_MIN_SAMPLE → floor", nb);
        CHECK(fee_estimate(cb, bz, nb, SUBSIDY) == FEE_FLOOR_K, name);
    }
    /* a full window of non-participants (fees < size ⇒ v == 0 after floor div) */
    for (int i = 0; i < 144; i++) { cb[i] = SUBSIDY + 999; bz[i] = 1000; }
    CHECK(fee_estimate(cb, bz, 144, SUBSIDY) == FEE_FLOOR_K,
          "144 blocks whose fees floor-divide to 0 are all non-participants → floor");
    /* exactly at the participant boundary: fees == size ⇒ v == 1 ⇒ participant */
    for (int i = 0; i < 144; i++) { cb[i] = SUBSIDY + 1000; bz[i] = 1000; }
    CHECK(fee_estimate(cb, bz, 144, SUBSIDY) == FEE_FLOOR_K,
          "144 blocks at exactly 1 koinu/byte participate but quote below the floor → floor");
    /* every block under-claims (coinbase below subsidy): must be treated as a
     * non-participant, NOT as a 2^64-sized one (the unsigned-wrap trap) */
    for (int i = 0; i < 144; i++) { cb[i] = 0; bz[i] = 1000; }
    CHECK(fee_estimate(cb, bz, 144, SUBSIDY) == FEE_FLOOR_K,
          "coinbase == 0 (under-claim) enrols as a non-participant, not a huge one");
    for (int i = 0; i < 144; i++) cb[i] = -SUBSIDY;
    CHECK(fee_estimate(cb, bz, 144, SUBSIDY) == FEE_FLOOR_K,
          "negative coinbase clamps to zero fees, not to a wrapped maximum");

    /* ═══ 3. hand-computed known answers ════════════════════════════════ */
    printf("-- nearest-rank 3rd quartile, hand-computed --\n");
    {
        /* subsidy 0, 1 byte per block ⇒ coinbase IS the koinu/byte */
        int64_t v4[4] = { 1000, 4000, 3000, 2000 };            /* sorted: 1,2,3,4 k */
        for (int i = 0; i < 4; i++) { cb[i] = v4[i]; bz[i] = 1; }
        /* k=4 ⇒ rank (3*4-1)/4 = 2 ⇒ 3rd smallest = 3000 */
        CHECK(fee_estimate(cb, bz, 4, 0) == 3000 * FEE_TX_BYTES,
              "k=4: q3 is the 3rd smallest (3000 x 480 = 1440000)");

        for (int i = 0; i < 8; i++) { cb[i] = (8 - i) * 1000; bz[i] = 1; }
        /* k=8 ⇒ rank (24-1)/4 = 5 ⇒ 6th smallest = 6000 */
        CHECK(fee_estimate(cb, bz, 8, 0) == 6000 * FEE_TX_BYTES,
              "k=8: q3 is the 6th smallest (6000 x 480 = 2880000)");

        for (int i = 0; i < 100; i++) { cb[i] = (int64_t)(i + 1) * 100; bz[i] = 1; }
        /* k=100 ⇒ rank (300-1)/4 = 74 ⇒ 75th smallest = 7500 */
        CHECK(fee_estimate(cb, bz, 100, 0) == 7500 * FEE_TX_BYTES,
              "k=100: q3 is the 75th smallest (7500 x 480 = 3600000)");

        /* q3 is an OBSERVED element: a lone outlier must not drag it up */
        for (int i = 0; i < 100; i++) { cb[i] = 1000; bz[i] = 1; }
        cb[0] = 1000000000LL;
        CHECK(fee_estimate(cb, bz, 100, 0) == 1000 * FEE_TX_BYTES,
              "one enormous outlier does not move an observed-element quantile");

        /* floor division happens BEFORE the participant test */
        for (int i = 0; i < 10; i++) { cb[i] = 1999; bz[i] = 1000; }   /* 1999/1000 = 1 */
        CHECK(fee_estimate(cb, bz, 10, 0) == FEE_FLOOR_K,
              "1999 koinu over 1000 bytes floors to 1/byte (participant, but below floor)");
        for (int i = 0; i < 10; i++) { cb[i] = 999; bz[i] = 1000; }    /* 999/1000  = 0 */
        CHECK(fee_estimate(cb, bz, 10, 0) == FEE_FLOOR_K,
              "999 koinu over 1000 bytes floors to 0/byte (not a participant)");

        /* the floor and cap boundaries, exactly */
        int64_t q_floor = FEE_FLOOR_K / FEE_TX_BYTES;         /* 208 → 99840 < floor */
        for (int i = 0; i < 8; i++) { cb[i] = q_floor; bz[i] = 1; }
        CHECK(fee_estimate(cb, bz, 8, 0) == FEE_FLOOR_K,
              "q3 x 480 just under the floor clamps up to the floor");
        for (int i = 0; i < 8; i++) { cb[i] = q_floor + 1; bz[i] = 1; }
        CHECK(fee_estimate(cb, bz, 8, 0) == (q_floor + 1) * FEE_TX_BYTES &&
              fee_estimate(cb, bz, 8, 0) > FEE_FLOOR_K,
              "one koinu/byte more clears the floor and is reported unclamped");
        int64_t q_cap = FEE_CAP_K / FEE_TX_BYTES;             /* 20833 */
        for (int i = 0; i < 8; i++) { cb[i] = q_cap; bz[i] = 1; }
        CHECK(fee_estimate(cb, bz, 8, 0) == q_cap * FEE_TX_BYTES &&
              fee_estimate(cb, bz, 8, 0) <= FEE_CAP_K,
              "q3 x 480 just under the cap is reported unclamped");
        for (int i = 0; i < 8; i++) { cb[i] = q_cap + 1; bz[i] = 1; }
        CHECK(fee_estimate(cb, bz, 8, 0) == FEE_CAP_K,
              "one koinu/byte more is clamped down to the cap");
    }

    /* ═══ 4. the 144-block window ═══════════════════════════════════════ */
    printf("-- the window --\n");
    {
        /* engine.c feeds newest-first; the tail past 144 must not be read */
        for (int i = 0; i < 144; i++)  { cb[i] = 1000; bz[i] = 1; }
        for (int i = 144; i < 600; i++) { cb[i] = 1000000; bz[i] = 1; }
        int64_t q = fee_estimate(cb, bz, 600, 0);
        CHECK(q == 1000 * FEE_TX_BYTES,
              "only the first FEE_EST_WINDOW entries are read (600 in, 144 used)");
        CHECK(fee_estimate(cb, bz, 144, 0) == q, "n=600 and n=144 agree on the same prefix");
        CHECK(fee_estimate(cb, bz, 145, 0) == q, "n=145 is clamped to 144");

        /* no read past the caller's array either: a 144-long feed is enough */
        int64_t small_cb[144], small_bz[144];
        for (int i = 0; i < 144; i++) { small_cb[i] = 1000; small_bz[i] = 1; }
        CHECK(fee_estimate(small_cb, small_bz, 100000, 0) == 1000 * FEE_TX_BYTES,
              "a huge n on a 144-element array still stops at 144");
    }

    /* ═══ 5. overflow and adversarial magnitudes ════════════════════════ */
    printf("-- overflow and adversarial magnitudes --\n");
    {
        for (int i = 0; i < 8; i++) { cb[i] = INT64_MAX; bz[i] = 1; }
        int64_t q = fee_estimate(cb, bz, 8, SUBSIDY);
        CHECK(q == FEE_CAP_K, "coinbase INT64_MAX with the real subsidy clamps to the cap");
        CHECK(q > 0, "the clamped answer is still positive (no wrap through zero)");

        for (int i = 0; i < 8; i++) { cb[i] = INT64_MAX; bz[i] = INT64_MAX; }
        CHECK(fee_estimate(cb, bz, 8, 0) == FEE_FLOOR_K,
              "INT64_MAX koinu over INT64_MAX bytes is 1/byte → floor (no division blow-up)");

        for (int i = 0; i < 8; i++) { cb[i] = INT64_MIN; bz[i] = 1; }
        CHECK(fee_estimate(cb, bz, 8, SUBSIDY) == FEE_FLOOR_K,
              "coinbase INT64_MIN clamps to zero fees (128-bit subtraction, no wrap)");

        /* zero and negative block sizes are documented to read as 1 byte */
        for (int i = 0; i < 8; i++) { cb[i] = SUBSIDY + 5000; bz[i] = 0; }
        int64_t z = fee_estimate(cb, bz, 8, SUBSIDY);
        for (int i = 0; i < 8; i++) bz[i] = 1;
        CHECK(z == fee_estimate(cb, bz, 8, SUBSIDY), "block_bytes == 0 is read as 1 byte");
        for (int i = 0; i < 8; i++) bz[i] = INT64_MIN;
        CHECK(fee_estimate(cb, bz, 8, SUBSIDY) == z, "block_bytes == INT64_MIN is read as 1 byte");

        /* mixed feed: under-claimers must not enrol and lift the quantile */
        for (int i = 0; i < 100; i++) {
            if (i % 2) { cb[i] = SUBSIDY + 1000; bz[i] = 1; }        /* 1000/byte */
            else       { cb[i] = 0;              bz[i] = 1; }        /* under-claim */
        }
        CHECK(fee_estimate(cb, bz, 100, SUBSIDY) == 1000 * FEE_TX_BYTES,
              "50 under-claiming blocks beside 50 real ones do not move the quote");
    }

    /* ═══ 6. properties over random feeds ═══════════════════════════════ */
    printf("-- properties over 20000 random block feeds --\n");
    {
        int out_of_range = 0, zero = 0, disagree = 0, not_observed = 0, mutated = 0;
        int mono_cb = 0, mono_bz = 0;
        for (int t = 0; t < 20000; t++) {
            int n = (int)(sm64() % 200) + 1;                  /* spans the window edge */
            int64_t sub = (t % 4 == 0) ? 0 : SUBSIDY;
            /* magnitudes chosen to straddle floor, mid-range and cap */
            for (int i = 0; i < n; i++) {
                uint64_t r = sm64();
                switch (t % 5) {
                case 0: cb[i] = sub + (int64_t)(r % 3000);        bz[i] = 1; break;
                case 1: cb[i] = sub + (int64_t)(r % 50000);       bz[i] = 1; break;
                case 2: cb[i] = sub + (int64_t)(r % 100000000);   bz[i] = (int64_t)(r % 5000) + 1; break;
                case 3: cb[i] = (int64_t)(r % (uint64_t)(2 * SUBSIDY)); bz[i] = (int64_t)(r % 400) - 100; break;
                default: cb[i] = (int64_t)r;                      bz[i] = (int64_t)(r >> 40) + 1; break;
                }
            }
            int64_t save_cb[600], save_bz[600];
            memcpy(save_cb, cb, (size_t)n * sizeof cb[0]);
            memcpy(save_bz, bz, (size_t)n * sizeof bz[0]);

            int64_t got = fee_estimate(cb, bz, n, sub);

            if (memcmp(save_cb, cb, (size_t)n * sizeof cb[0]) ||
                memcmp(save_bz, bz, (size_t)n * sizeof bz[0])) mutated++;
            if (got < FEE_FLOOR_K || got > FEE_CAP_K) out_of_range++;
            if (got <= 0) zero++;
            if (got != ref_estimate(cb, bz, n, sub)) disagree++;

            /* an observed element × 480, unless clamped */
            if (got != FEE_FLOOR_K && got != FEE_CAP_K) {
                if (got % FEE_TX_BYTES) not_observed++;
                else {
                    int64_t q = got / FEE_TX_BYTES, seen = 0;
                    int m = n > FEE_EST_WINDOW ? FEE_EST_WINDOW : n;
                    for (int i = 0; i < m && !seen; i++) {
                        __int128 f = (__int128)cb[i] - (__int128)sub;
                        if (f < 0) f = 0;
                        int64_t b = bz[i] > 0 ? bz[i] : 1;
                        if ((int64_t)(f / (__int128)b) == q) seen = 1;
                    }
                    if (!seen) not_observed++;
                }
            }

            /* monotone up in coinbase */
            int64_t up_cb[600];
            for (int i = 0; i < n; i++) up_cb[i] = cb[i] > INT64_MAX - 4096 ? cb[i] : cb[i] + 4096;
            if (fee_estimate(up_cb, bz, n, sub) < got) mono_cb++;
            /* monotone down in block size */
            int64_t up_bz[600];
            for (int i = 0; i < n; i++) up_bz[i] = (bz[i] > 0 ? bz[i] : 1) * 4;
            if (fee_estimate(cb, up_bz, n, sub) > got) mono_bz++;
        }
        CHECK(out_of_range == 0, "every quote lands in [FEE_FLOOR_K, FEE_CAP_K]");
        CHECK(zero == 0,         "no quote is ever zero or negative");
        CHECK(disagree == 0,     "matches an independent re-implementation of the rule, 20000/20000");
        CHECK(not_observed == 0, "an unclamped quote is always an observed koinu/byte x 480");
        CHECK(mutated == 0,      "the caller's const arrays are never written through");
        CHECK(mono_cb == 0,      "raising every coinbase never lowers the quote");
        CHECK(mono_bz == 0,      "raising every block size never raises the quote");
    }

    /* determinism */
    printf("-- determinism --\n");
    {
        for (int i = 0; i < 144; i++) { cb[i] = SUBSIDY + (int64_t)(sm64() % 200000); bz[i] = 300; }
        int64_t first = fee_estimate(cb, bz, 144, SUBSIDY), same = 1;
        for (int t = 0; t < 500; t++) if (fee_estimate(cb, bz, 144, SUBSIDY) != first) same = 0;
        CHECK(same, "the same feed always yields the same quote");
    }

    printf("\nt_fee: %d ok, %d failed\n", g_ok, g_nfail);
    return g_fail;
}
