// The names market — open (SELL/RESERVE/SETTLE) + directed (SELL_TO/PAY), §3.7.
//
// Escrow-first (a listed/offered name is movement-locked: TRANSFER/RELEASE/
// re-SELL/SELL_TO on it are rejected via the OWNED guard) and fixed-price
// (committed on-chain at SELL/SELL_TO). Payments ride in spendable outputs,
// matched consume-once, exact-value, in vout order — never summed.
#include "sm.h"
#include <string.h>

// §3.5 per-tx output matching: lowest-vout unconsumed output paying EXACTLY
// (dest of `type`, amount). Marks it consumed. A summed output matches nothing.
int sm_consume_output(SmState *s, SmTxCtx *cx, const uint8_t dest[20],
                      uint8_t type, uint64_t amount) {
    (void)s;
    const SmTx *tx = cx->tx;
    int best = -1;
    for (int i = 0; i < tx->n_outs; i++) {
        if (cx->out_consumed[i]) continue;
        const SmOut *o = &tx->outs[i];
        if (o->value == amount && o->type == type && memcmp(o->h160, dest, 20) == 0)
            if (best < 0 || o->vout < tx->outs[best].vout) best = i;
    }
    if (best < 0) return 0;
    cx->out_consumed[best] = 1;
    return 1;
}

// Deposit leg = max(DUST_FLOOR, ⌊price·bps/10000⌋), computed in 128-bit (price is
// an attacker-typed u64; price·bps overflows int64 — THE load-bearing rule, §3.7).
static uint64_t deposit_leg(uint64_t price, unsigned bps) {
    unsigned __int128 v = (unsigned __int128)price * bps / 10000u;
    uint64_t leg = (uint64_t)v;
    return leg < (uint64_t)SM_DUST_FLOOR ? (uint64_t)SM_DUST_FLOOR : leg;
}

static void to_owned(SmNameRow *r) {                 // clear all market fields → plain owned
    r->st = SM_OWNED;
    r->price = 0; r->offer_expiry = 0; r->reserve_expiry = 0; r->burn_leg = r->pay_leg = 0;
    memset(r->seller, 0, 20); r->seller_type = 0; memset(r->buyer, 0, 20);
}

// ── open market ──────────────────────────────────────────────────────────────

void sm_op_sell(SmState *s, SmTxCtx *cx, const SmAction *a) {
    if (!sm_name_valid(a->name, a->name_len)) return;
    if (a->price < (uint64_t)SM_SELL_PRICE_FLOOR) return;          // §3.7 fold-safety floor
    SmNameRow *r = sm_find_name(s, a->name);
    if (!r || r->st != SM_OWNED || memcmp(r->owner, cx->actor, 20) != 0) return;  // own + unlocked

    int64_t w = a->window ? (int64_t)a->window : SM_RESERVE_WINDOW;
    if (w < SM_RESERVE_WINDOW) return;
    if (cx->mtp + w + SM_REORG_BUFFER > r->lease_expiry) return;   // add-form (no unsigned underflow)

    r->st = SM_LISTED;
    memcpy(r->seller, cx->actor, 20); r->seller_type = cx->actor_type;
    r->price = a->price; r->offer_expiry = cx->mtp + w;
    memset(r->buyer, 0, 20); r->burn_leg = r->pay_leg = 0; r->reserve_expiry = 0;
    s->ev[SM_EV_SELL_OK]++;
    // owner stays the seller (listed name remains in the owned set); NOT a mutation (§3.5).
}

void sm_op_reserve(SmState *s, SmTxCtx *cx, const SmAction *a) {
    if (!sm_name_valid(a->name, a->name_len)) return;
    SmNameRow *r = sm_find_name(s, a->name);
    if (!r || r->st != SM_LISTED) return;            // need an OPEN listing; already-reserved → lose (no-op)

    uint64_t burn_leg = deposit_leg(r->price, SM_RESERVE_BURN_BPS);
    uint64_t pay_leg  = deposit_leg(r->price, SM_RESERVE_PAY_BPS);
    if (cx->car_value < burn_leg) return;                              // burn-leg short → drop
    if (!sm_consume_output(s, cx, r->seller, r->seller_type, pay_leg)) return;  // pay-leg → seller

    r->st = SM_RESERVED;
    memcpy(r->buyer, cx->actor, 20);                 // first-in-chain-order wins the exclusive option
    r->burn_leg = burn_leg; r->pay_leg = pay_leg;
    int64_t rexp = cx->mtp + SM_RESERVE_WINDOW;
    if (rexp >= r->offer_expiry) { r->reserve_expiry = r->offer_expiry; s->ev[SM_EV_RESERVE_CLAMP]++; }
    else                          r->reserve_expiry = rexp;            // clamp to offer_expiry (load-bearing)
    s->ev[SM_EV_RESERVE_WIN]++;
}

void sm_op_settle(SmState *s, SmTxCtx *cx, const SmAction *a) {
    if (!sm_name_valid(a->name, a->name_len)) return;
    SmNameRow *r = sm_find_name(s, a->name);
    if (!r || r->st != SM_RESERVED) return;
    if (memcmp(r->buyer, cx->actor, 20) != 0) return;        // the exclusive reserver only
    if (cx->mtp >= r->reserve_expiry) return;                // only protocol timing gate

    uint64_t remainder = r->price - r->burn_leg - r->pay_leg; // ≥ DUST_FLOOR by the price floor
    if (!sm_consume_output(s, cx, r->seller, r->seller_type, remainder)) return;

    uint8_t seller[20]; memcpy(seller, r->seller, 20);
    memcpy(r->owner, cx->actor, 20); r->owner_type = cx->actor_type;
    to_owned(r);                                             // lease conveys (lease_expiry unchanged)
    sm_bump_mutation(s, cx->actor, cx->height);
    sm_bump_mutation(s, seller, cx->height);
    s->ev[SM_EV_SETTLE_OK]++;
}

// ── directed market ──────────────────────────────────────────────────────────

void sm_op_sell_to(SmState *s, SmTxCtx *cx, const SmAction *a) {
    if (!sm_name_valid(a->name, a->name_len)) return;
    if (a->price < (uint64_t)SM_DUST_FLOOR) return;          // SELL_TO floor is DUST_FLOOR (no deposit split)
    SmNameRow *r = sm_find_name(s, a->name);
    if (!r || r->st != SM_OWNED || memcmp(r->owner, cx->actor, 20) != 0) return;
    if (cx->mtp + SM_DIRECT_WINDOW + SM_REORG_BUFFER > r->lease_expiry) return;  // lease-tail

    r->st = SM_OFFERED;
    memcpy(r->seller, cx->actor, 20); r->seller_type = cx->actor_type;
    memcpy(r->buyer, a->addr, 20);                           // the named buyer (may be P2SH)
    r->price = a->price; r->offer_expiry = cx->mtp + SM_DIRECT_WINDOW;
    r->burn_leg = r->pay_leg = 0; r->reserve_expiry = 0;
    s->ev[SM_EV_SELLTO_OK]++;
}

void sm_op_pay(SmState *s, SmTxCtx *cx, const SmAction *a) {
    if (!sm_name_valid(a->name, a->name_len)) return;
    SmNameRow *r = sm_find_name(s, a->name);
    if (!r || r->st != SM_OFFERED) return;
    if (memcmp(r->buyer, cx->actor, 20) != 0) return;        // only the named buyer (no snipe)
    if (cx->mtp >= r->offer_expiry) return;
    if (!sm_consume_output(s, cx, r->seller, r->seller_type, r->price)) return;  // full price → seller

    uint8_t seller[20]; memcpy(seller, r->seller, 20);
    memcpy(r->owner, cx->actor, 20); r->owner_type = cx->actor_type;
    to_owned(r);                                             // lease conveys
    sm_bump_mutation(s, cx->actor, cx->height);
    sm_bump_mutation(s, seller, cx->height);
    s->ev[SM_EV_PAY_OK]++;
}
