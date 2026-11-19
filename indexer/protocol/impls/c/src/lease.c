// §3.3–§3.5 pay-for-duration leases: the burn IS the duration.
//
// A burn `B` at `rate` buys T = ⌊B·LEASE_QUANTUM / (rate·BILLING_UNIT)⌋ whole
// name·days (128-bit numerator — B is an attacker-typed u64). T is spread across
// the targeted names by the water-fill: a uniform level, names that would exceed
// now+MAX_LEASE cap and redirect their share, an integer remainder of +1 day to
// the first headroom-having names in ascending-lex order, and any all-capped
// surplus forfeited. Deterministic integer math, pinned in SPEC-conformance.md.
#include "sm.h"

#include <stdlib.h>
#include <string.h>

// T as a 128-bit value (it can exceed u64 for a huge burn / tiny rate; the
// water-fill clamps it to the total headroom, so the wide value is never stored).
static unsigned __int128 raw_T(uint64_t burn, uint64_t rate) {
    if (rate == 0) rate = 1;                          // rate is clamped ≥ DUST_FLOOR upstream
    unsigned __int128 num = (unsigned __int128)burn * (unsigned __int128)SM_LEASE_QUANTUM;
    unsigned __int128 den = (unsigned __int128)rate * (unsigned __int128)SM_BILLING_UNIT;
    return num / den;
}

int sm_lease_covers_day(uint64_t burn, uint64_t rate) {
    if (rate == 0) rate = 1;
    unsigned __int128 num = (unsigned __int128)burn * (unsigned __int128)SM_LEASE_QUANTUM;
    unsigned __int128 den = (unsigned __int128)rate * (unsigned __int128)SM_BILLING_UNIT;
    return num >= den;                                // T ≥ 1
}

static int cmp_rowptr_name(const void *a, const void *b) {
    const SmNameRow *x = *(SmNameRow *const *)a, *y = *(SmNameRow *const *)b;
    return strcmp(x->name, y->name);
}

void sm_waterfill(SmState *s, int64_t now_mtp, uint64_t rate, uint64_t burn,
                  SmNameRow **rows, int n) {
    if (n <= 0) return;
    qsort(rows, (size_t)n, sizeof(SmNameRow *), cmp_rowptr_name);   // ascending-lex

    int64_t *h   = malloc((size_t)n * sizeof(int64_t));   // per-name headroom (days)
    int64_t *add = calloc((size_t)n, sizeof(int64_t));    // per-name days awarded
    unsigned __int128 total_head = 0;
    for (int i = 0; i < n; i++) {
        int64_t remaining = rows[i]->lease_expiry - now_mtp;
        if (remaining < 0) remaining = 0;
        int64_t hd = (SM_MAX_LEASE - remaining) / SM_BILLING_UNIT;
        if (hd < 0) hd = 0;
        h[i] = hd; total_head += (unsigned __int128)hd;
    }

    unsigned __int128 T = raw_T(burn, rate);
    if (T >= total_head) {
        for (int i = 0; i < n; i++) add[i] = h[i];        // everyone caps; surplus forfeited
        if (T > total_head && total_head > 0) s->ev[SM_EV_WATERFILL_FORFEIT]++;
    } else {
        int64_t pool = (int64_t)T;                        // T < total_head ⇒ fits int64
        for (;;) {                                        // even water-fill
            int active = 0;
            for (int i = 0; i < n; i++) if (add[i] < h[i]) active++;
            if (active == 0 || pool == 0) break;
            int64_t share = pool / active;
            if (share == 0) break;                        // → remainder step
            for (int i = 0; i < n; i++) {
                if (add[i] < h[i]) {
                    int64_t give = h[i] - add[i];
                    if (give > share) give = share;
                    add[i] += give; pool -= give;
                }
            }
        }
        for (int i = 0; i < n && pool > 0; i++)            // +1 day, ascending-lex
            if (add[i] < h[i]) { add[i] += 1; pool -= 1; }
    }

    for (int i = 0; i < n; i++) {
        if (h[i] > 0 && add[i] == h[i]) s->ev[SM_EV_WATERFILL_CAP]++;   // hit the MAX_LEASE ceiling
        rows[i]->lease_expiry += add[i] * SM_BILLING_UNIT;
    }
    free(h); free(add);
}
