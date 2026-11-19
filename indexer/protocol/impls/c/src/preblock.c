// §5 time-triggered transitions, applied BEFORE a block's transactions.
//
// For a single name the boundaries nest reserve_expiry ≤ offer_expiry ≤
// lease_expiry − REORG_BUFFER (the RESERVE clamp, §3.7), so a per-row pass that
// checks reserve → offer → lease IN THAT ORDER cascades correctly when one MTP
// advance crosses several at once. Distinct names are independent; commit
// pruning is independent of the market chain. All bounds are EXCLUSIVE (a name
// is owned iff MTP < lease_expiry). See sm.h / protocol-spec.md §5.
#include "sm.h"
#include <string.h>

// Return a sale row (LISTED/OFFERED/RESERVED) to its seller as plain owned.
static void return_to_seller(SmNameRow *r) {
    memcpy(r->owner, r->seller, 20);
    r->owner_type = r->seller_type;
    r->st = SM_OWNED;
    r->price = 0; r->offer_expiry = 0; r->reserve_expiry = 0;
    r->burn_leg = r->pay_leg = 0;
    memset(r->seller, 0, 20); r->seller_type = 0;
    memset(r->buyer, 0, 20);
    // lease_expiry carried unchanged (offer_expiry < lease_expiry, §5).
}

void sm_preblock(SmState *s, int64_t height, int64_t mtp) {
    // ── owned-set transitions, per-row reserve → offer → lease ──
    for (int i = 0; i < s->n_names; ) {
        SmNameRow *r = &s->names[i];

        // 1. RESERVED: reserve window closed.
        if (r->st == SM_RESERVED && mtp >= r->reserve_expiry) {
            if (r->reserve_expiry < r->offer_expiry) {
                // re-listable: back to the OPEN listing (a reserve only ever comes
                // from a SELL, never a directed offer); seller keeps the forfeited legs.
                r->st = SM_LISTED;
                r->reserve_expiry = 0; r->burn_leg = r->pay_leg = 0;
                memset(r->buyer, 0, 20);
            } else {
                return_to_seller(r);   // offer dead (reserve_expiry == offer_expiry)
            }
        }
        // 2. LISTED or OFFERED: listing/offer closed → back to seller.
        if ((r->st == SM_LISTED || r->st == SM_OFFERED) && mtp >= r->offer_expiry) {
            return_to_seller(r);
        }
        // 3. Lease lapse → pool (remove). Applies in any state once it reverts to owned.
        if (mtp >= r->lease_expiry) {
            // §3.5: a lapse mutates the owner's set, so stamp last_set_mutation_height to
            // the connecting block H. A bitmap op anchored before the lapse then fails the
            // anchor guard (reject-and-resend) instead of acting on a now-shifted ordering
            // and touching the wrong name. (By here steps 1–2 have restored owner==the real
            // owner: the §5 nesting offer_expiry < lease_expiry guarantees a sale row already
            // reverted via return_to_seller before its lease can lapse.)
            sm_bump_mutation(s, r->owner, height);
            sm_remove_name(s, r); s->ev[SM_EV_LAPSE]++;
            continue;   // do not advance: a row was swapped into slot i
        }
        i++;
    }

    // ── COMMIT_EXPIRY pruning (independent of the market chain) ──
    for (int i = 0; i < s->n_commits; ) {
        if (mtp > s->commits[i].commit_time + SM_COMMIT_EXPIRY)
            s->commits[i] = s->commits[--s->n_commits];
        else
            i++;
    }
}
