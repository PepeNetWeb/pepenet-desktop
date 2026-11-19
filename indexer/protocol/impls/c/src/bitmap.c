// RENEW / TRANSFER / RELEASE — bitmaps over the owner's owned set — and their
// by-name singleton forms RENEW_NAME / TRANSFER_NAME / RELEASE_NAME (§3.5/§3.6).
//
// The owned set is every name the actor controls (plain OWNED, plus LISTED/
// OFFERED/RESERVED where they are the seller — a listing stays in the owned set,
// §3.7), sorted ascending-lexicographic; bit i (LSB-first) selects the i-th
// name. Out-of-bounds bits (index ≥ K) are ignored, never fatal. The anchor
// guard (last_mutation ≤ H ≤ confirm ≤ H+MAX_ANCHOR_AGE) fails CLOSED so a stale
// set view rejects-and-resends rather than touching the wrong name. RENEW also
// renews listed names; TRANSFER/RELEASE skip locked names (movement-frozen).
#include "sm.h"

#include <stdlib.h>
#include <string.h>

static int cmp_rowptr_name(const void *a, const void *b) {
    const SmNameRow *x = *(SmNameRow *const *)a, *y = *(SmNameRow *const *)b;
    return strcmp(x->name, y->name);
}

int sm_collect_owned(SmState *s, const uint8_t who[20], SmNameRow **out, int max) {
    int n = 0;
    for (int i = 0; i < s->n_names && n < max; i++) {
        SmNameRow *r = &s->names[i];
        int mine = (r->st == SM_OWNED) ? (memcmp(r->owner, who, 20) == 0)
                                       : (memcmp(r->seller, who, 20) == 0);
        if (mine) out[n++] = r;
    }
    if (n > 1) qsort(out, (size_t)n, sizeof(SmNameRow *), cmp_rowptr_name);
    return n;
}

// LSB-first bit test, bounded by the flag-field length.
static int bit_set(const uint8_t *flags, int flags_len, int i) {
    int byte = i >> 3;
    return byte < flags_len && ((flags[byte] >> (i & 7)) & 1);
}

// §3.5 anchor guard. H = anchor (absolute height). Fail-closed.
static int anchor_ok(SmState *s, const uint8_t who[20], uint64_t anchor, int64_t confirm) {
    int64_t lm = sm_last_mutation(s, who), H = (int64_t)anchor;
    return lm <= H && H <= confirm && (confirm - H) <= SM_MAX_ANCHOR_AGE;
}

// ── RENEW (§3.5) — extends leases; does NOT mutate the set (no anchor bump) ──
void sm_op_renew(SmState *s, SmTxCtx *cx, const SmAction *a) {
    uint64_t burn = cx->car_value;
    int cap = s->n_names ? s->n_names : 1;
    SmNameRow **buf = malloc((size_t)cap * sizeof(*buf));
    int K = sm_collect_owned(s, cx->actor, buf, s->n_names);

    if (!a->has_anchor && a->flags_len == 0) {
        sm_waterfill(s, cx->mtp, cx->rate, burn, buf, K);            // renew-all
    } else if (a->has_anchor && anchor_ok(s, cx->actor, a->anchor, cx->height)) {
        if (a->flags_len == 0) {
            sm_waterfill(s, cx->mtp, cx->rate, burn, buf, K);        // renew-all (safe)
        } else {
            SmNameRow **sel = malloc((size_t)(K ? K : 1) * sizeof(*sel));
            int ns = 0;
            for (int i = 0; i < K; i++) if (bit_set(a->flags, a->flags_len, i)) sel[ns++] = buf[i];
            sm_waterfill(s, cx->mtp, cx->rate, burn, sel, ns);
            free(sel);
        }
    }
    free(buf);   // anchor present but invalid → fall through (drop): nothing renewed
}

// ── TRANSFER (§3.6) — gift owned (unlocked) names to one target; lease conveys ──
void sm_op_transfer(SmState *s, SmTxCtx *cx, const SmAction *a) {
    int sel_all = !a->has_anchor;                          // [target] = all; [target][anchor][flags] = selective
    if (a->has_anchor && !anchor_ok(s, cx->actor, a->anchor, cx->height)) return;

    int cap = s->n_names ? s->n_names : 1;
    SmNameRow **buf = malloc((size_t)cap * sizeof(*buf));
    int K = sm_collect_owned(s, cx->actor, buf, s->n_names);

    int moved = 0;
    for (int i = 0; i < K; i++) {
        if (!(sel_all || bit_set(a->flags, a->flags_len, i))) continue;
        SmNameRow *r = buf[i];
        if (r->st != SM_OWNED) continue;                   // locked (listed/offered) → skip
        memcpy(r->owner, a->addr, 20); r->owner_type = SM_P2PKH;   // type meaningless for a gift (not digested)
        moved++;                                           // lease conveys (lease_expiry unchanged)
    }
    free(buf);
    if (moved) {                                           // both parties' set/ordering changed (§3.5)
        sm_bump_mutation(s, cx->actor, cx->height);
        sm_bump_mutation(s, a->addr, cx->height);
    }
}

// ── the by-name forms (§3.5) — the singleton siblings of the bitmap ops ──────
// Each applies its bitmap sibling's exact state semantics to the one name the
// payload spells out. A name string is its own position-independent address
// into the owned set, so there is no anchor and no anchor guard — by-name ops
// are valid under any concurrent set churn. The name MUST be in the actor's
// owned set (same membership test as sm_collect_owned); else drop.

// The row for `name` iff the actor controls it (owner, or seller when locked).
static SmNameRow *find_mine(SmState *s, const uint8_t who[20], const SmAction *a) {
    if (a->name_len < 1) return NULL;
    SmNameRow *r = sm_find_name(s, a->name);
    if (!r) return NULL;
    const uint8_t *holder = (r->st == SM_OWNED) ? r->owner : r->seller;
    return memcmp(holder, who, 20) == 0 ? r : NULL;
}

// RENEW_NAME (§3.5) — water-fill over the singleton; listed/offered names are
// still renewable by their seller. Renewal never mutates the set: no bump.
void sm_op_renew_name(SmState *s, SmTxCtx *cx, const SmAction *a) {
    SmNameRow *r = find_mine(s, cx->actor, a);
    if (!r) return;
    sm_waterfill(s, cx->mtp, cx->rate, cx->car_value, &r, 1);
}

// TRANSFER_NAME (§3.5/§3.6) — gift exactly one owned (unlocked) name; lease
// conveys. Locked → no-op (the one-name skip), no bump. A move bumps BOTH
// parties (self-target included: still a move, both resolve to one owner).
void sm_op_transfer_name(SmState *s, SmTxCtx *cx, const SmAction *a) {
    SmNameRow *r = find_mine(s, cx->actor, a);
    if (!r || r->st != SM_OWNED) return;                   // absent / not mine / locked
    memcpy(r->owner, a->addr, 20); r->owner_type = SM_P2PKH;   // type meaningless for a gift (not digested)
    sm_bump_mutation(s, cx->actor, cx->height);            // lease conveys (lease_expiry unchanged)
    sm_bump_mutation(s, a->addr, cx->height);
}

// RELEASE_NAME (§3.5/§3.6) — return exactly one owned (unlocked) name to the
// pool now, under RELEASE's full semantics. Locked → no-op, no bump.
void sm_op_release_name(SmState *s, SmTxCtx *cx, const SmAction *a) {
    SmNameRow *r = find_mine(s, cx->actor, a);
    if (!r || r->st != SM_OWNED) return;                   // absent / not mine / locked
    sm_remove_name(s, r); s->ev[SM_EV_RELEASE_NAME]++;     // → pool (immediately reclaimable)
    sm_bump_mutation(s, cx->actor, cx->height);
}

// ── RELEASE (§3.6) — return selected owned (unlocked) names to the pool now ──
void sm_op_release(SmState *s, SmTxCtx *cx, const SmAction *a) {
    if (!a->has_anchor) return;                            // RELEASE is always anchor + flags
    if (!anchor_ok(s, cx->actor, a->anchor, cx->height)) return;

    int cap = s->n_names ? s->n_names : 1;
    SmNameRow **buf = malloc((size_t)cap * sizeof(*buf));
    int K = sm_collect_owned(s, cx->actor, buf, s->n_names);

    // Collect names first — sm_remove_name swaps rows, invalidating buf pointers.
    char (*rel)[SM_NAME_MAX + 1] = malloc((size_t)(K ? K : 1) * sizeof(*rel));
    int nr = 0;
    for (int i = 0; i < K; i++)
        if (bit_set(a->flags, a->flags_len, i) && buf[i]->st == SM_OWNED)
            memcpy(rel[nr++], buf[i]->name, SM_NAME_MAX + 1);
    free(buf);

    for (int i = 0; i < nr; i++) {
        SmNameRow *r = sm_find_name(s, rel[i]);
        if (r) { sm_remove_name(s, r); s->ev[SM_EV_RELEASE_NAME]++; }   // → pool (immediately reclaimable)
    }
    if (nr) sm_bump_mutation(s, cx->actor, cx->height);
    free(rel);
}
