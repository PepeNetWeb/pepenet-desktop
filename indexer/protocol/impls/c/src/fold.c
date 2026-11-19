// The §5 fold driver: begin_block + the per-tx carrier walk.
//
// apply_tx is a single forward pass over a tx's OP_RETURN carriers in vout
// order. It tracks the acting identity (vin[0] by default; re-pointed by AS
// markers, §3.9/Rule 1b). COMMIT is handled inline; heavier identity/market/
// trade ops dispatch to their modules. Consensus classifies no content —
// only name-action carriers mutate state.
#include "sm.h"
#include <string.h>
#include <stdlib.h>

// ── synthetic per-tx id (pinned): txid = height(8 LE) ‖ txindex(4 LE) ‖ 0… ────
static void synth_txid(uint8_t out[32], int64_t height, uint32_t txindex) {
    memset(out, 0, 32);
    uint64_t h = (uint64_t)height;
    for (int i = 0; i < 8; i++) out[i]     = (uint8_t)(h >> (8 * i));
    for (int i = 0; i < 4; i++) out[8 + i] = (uint8_t)(txindex >> (8 * i));
}

// ── driver ────────────────────────────────────────────────────────────────────

void sm_begin_block(SmState *s, int64_t height, int64_t mtp, uint64_t rate) {
    sm_preblock(s, height, mtp);                     // transitions BEFORE the block's txs (§5)
    s->cur_height = height; s->cur_mtp = mtp; s->cur_rate = rate;
    s->n_claimsc = 0;                                // §3.2 claim scratch is per-block
}

void sm_apply_tx(SmState *s, const SmTx *tx) {
    SmTxCtx cx;
    memset(&cx, 0, sizeof(cx));
    cx.tx = tx; cx.height = s->cur_height; cx.mtp = s->cur_mtp; cx.rate = s->cur_rate;
    cx.txindex = tx->txindex;
    synth_txid(cx.txid, s->cur_height, tx->txindex);

    // §3.5 consume-once flags: one per spendable output. A tx has no output cap
    // (§0), so size to n_outs — a fixed buffer would corrupt state / read stale
    // flags on a tx with >SM_INLINE_OUTS outputs. Inline for the common case.
    uint8_t consumed_inline[SM_INLINE_OUTS];
    if (tx->n_outs > SM_INLINE_OUTS) {
        cx.out_consumed = calloc((size_t)tx->n_outs, 1);
        if (!cx.out_consumed) abort();               // deterministic fail (cf. GROW assert)
    } else {
        cx.out_consumed = consumed_inline;
        memset(consumed_inline, 0, sizeof(consumed_inline));
    }

    // acting identity = vin[0] by default; valid iff it signs SIGHASH_ALL (Rule 3).
    if (tx->n_inputs > 0 && tx->in_sighash_all[0]) {
        memcpy(cx.actor, tx->inputs[0].h160, 20);
        cx.actor_type = tx->inputs[0].type;
        cx.actor_valid = 1;
    }

    for (int c = 0; c < tx->n_carriers; c++) {
        const SmCarrier *car = &tx->carriers[c];
        cx.car_value = car->value; cx.car_vout = car->vout;

        if (car->kind != SM_CAR_ACTION) continue;    // IGNORE (or anything non-action)

        const SmAction *a = &car->act;
        const int op = a->op;

        // forward-only activation gate (§3.0): all ops gate at one height.
        if (s->cur_height < (int64_t)s->activation_height)
            continue;

        if (op == SM_OP_AS) {                        // re-point acting identity (Rule 1b)
            uint8_t k = a->as_index;
            if (k < tx->n_inputs && tx->in_sighash_all[k]) {
                memcpy(cx.actor, tx->inputs[k].h160, 20);
                cx.actor_type = tx->inputs[k].type;
                cx.actor_valid = 1;
            } else {
                cx.actor_valid = 0;                  // ⊥ → this segment's actions drop
                s->ev[SM_EV_AS_DROP]++;
            }
            continue;
        }

        // TRADE is attributed to its OWN named inputs (idxA/idxB), not the acting
        // identity, so it dispatches regardless of cx.actor_valid (§3.9).
        if (op == SM_OP_TRADE) { sm_op_trade(s, &cx, a); continue; }

        if (!cx.actor_valid) continue;               // every other op acts as the acting identity

        switch (op) {
        case SM_OP_COMMIT:
            sm_commit_add(s, a->commitment, s->cur_height, tx->txindex, s->cur_mtp);
            break;
        case SM_OP_CLAIM:    sm_op_claim(s, &cx, a);    break;
        case SM_OP_RENEW:    sm_op_renew(s, &cx, a);    break;
        case SM_OP_TRANSFER: sm_op_transfer(s, &cx, a); break;
        case SM_OP_RENEW_NAME:    sm_op_renew_name(s, &cx, a);    break;
        case SM_OP_TRANSFER_NAME: sm_op_transfer_name(s, &cx, a); break;
        case SM_OP_RELEASE_NAME:  sm_op_release_name(s, &cx, a);  break;
        case SM_OP_SELL:     sm_op_sell(s, &cx, a);     break;
        case SM_OP_RESERVE:  sm_op_reserve(s, &cx, a);  break;
        case SM_OP_SETTLE:   sm_op_settle(s, &cx, a);   break;
        case SM_OP_RELEASE:  sm_op_release(s, &cx, a);  break;
        case SM_OP_SELL_TO:  sm_op_sell_to(s, &cx, a);  break;
        case SM_OP_PAY:      sm_op_pay(s, &cx, a);      break;
        default: break;                              // unknown opcode → ignore
        }
    }

    if (cx.out_consumed != consumed_inline) free(cx.out_consumed);
}
