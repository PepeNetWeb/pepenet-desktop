// oracle_feed.c — see oracle_feed.h. Buffers per-block oracle inputs and derives
// (mtp, rate) via the engine's pinned sm_mtp / sm_oracle_rate (so the indexer's
// rate is byte-identical to the reference's §3.4).
#include "oracle_feed.h"
#include "sm.h"
#include <stdlib.h>
#include <string.h>

// §3.4: the host chain's consensus subsidy across the reachable window — now a
// per-host PROFILE value (oracle_set_subsidy), not a hardcoded constant, so porting
// to a chain with a different flat-tail subsidy is a one-field change. The default
// below is Dogecoin/Pepecoin's flat 10,000/block (both tail from height 600,000),
// correct only when every window block is in the flat tail, i.e. the deployment pins
// ACTIVATION_HEIGHT ≥ tail_start + FEE_WINDOW (docs/notes/host-profiles.md). A chain
// with a DIFFERENT tail subsidy MUST set it via the profile or the rate forks.
#define SUBSIDY_KOINU_DEFAULT  (10000LL * SM_KOINU_PER_DOGE)

typedef struct { int64_t height, time, coinbase, bytes; } Blk;

struct OracleFeed {
    Blk   *v; int n, cap;
    int64_t subsidy;                 // per-host flat-tail subsidy (koinu/block)
};

OracleFeed *oracle_new(void) { OracleFeed *o = calloc(1, sizeof *o); if (o) o->subsidy = SUBSIDY_KOINU_DEFAULT; return o; }
void oracle_set_subsidy(OracleFeed *o, int64_t subsidy_koinu) { if (o && subsidy_koinu > 0) o->subsidy = subsidy_koinu; }
void oracle_free(OracleFeed *o) { if (o) { free(o->v); free(o); } }

void oracle_record(OracleFeed *o, int64_t height, int64_t timestamp,
                   int64_t coinbase_out_total, int64_t block_bytes) {
    // Idempotent by height (buffer stays strictly ascending, last write wins):
    // crash recovery re-folds blocks the warm feed already loaded, and a reorg
    // re-records replaced heights — a duplicated height would fill the §3.4
    // window with repeated rows and fork the rate for every block folded that
    // pass. Normal append pops nothing (tail height < height): O(1).
    oracle_rollback(o, height);
    if (o->n == o->cap) { o->cap = o->cap ? o->cap * 2 : 1024; o->v = realloc(o->v, (size_t)o->cap * sizeof *o->v); }
    o->v[o->n++] = (Blk){ height, timestamp, coinbase_out_total, block_bytes };
}

void oracle_rollback(OracleFeed *o, int64_t height) {
    while (o->n > 0 && o->v[o->n - 1].height >= height) o->n--;
}

void oracle_for_height(OracleFeed *o, int64_t height, int64_t *mtp, uint64_t *rate) {
    // MTP: the (up to) 11 timestamps strictly below `height`.
    int64_t ts[11]; int nt = 0;
    for (int i = o->n - 1; i >= 0 && nt < 11; i--)
        if (o->v[i].height < height) ts[nt++] = o->v[i].time;
    // sm_mtp wants them in chronological order; we collected newest-first → reverse.
    for (int a = 0, b = nt - 1; a < b; a++, b--) { int64_t t = ts[a]; ts[a] = ts[b]; ts[b] = t; }
    *mtp = sm_mtp(ts, nt);

    // Rate: the FEE_WINDOW blocks strictly below `height` (i ∈ [h−FEE_WINDOW, h−1]).
    int64_t lo = height - SM_FEE_WINDOW;
    int cap = (int)SM_FEE_WINDOW;
    int64_t *cb = malloc((size_t)cap * sizeof *cb);
    int64_t *sb = malloc((size_t)cap * sizeof *sb);
    int64_t *bz = malloc((size_t)cap * sizeof *bz);
    int nr = 0;
    for (int i = 0; i < o->n && nr < cap; i++) {
        int64_t h = o->v[i].height;
        if (h >= lo && h < height) { cb[nr] = o->v[i].coinbase; sb[nr] = o->subsidy; bz[nr] = o->v[i].bytes; nr++; }
    }
    *rate = sm_oracle_rate(cb, sb, bz, nr);   // nr < FEE_WINDOW near genesis → clamps to floor
    free(cb); free(sb); free(bz);
}
