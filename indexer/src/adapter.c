// adapter.c — see adapter.h.
#include "adapter.h"
#include "attrib.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int idx_adapt_tx(SmState *s, const IdxTx *tx, uint32_t txindex) {
    SmTx smtx;
    memset(&smtx, 0, sizeof smtx);
    smtx.txindex = txindex;

    // 0. Pre-scan: does any OP_RETURN decode to a carrier at all? A carrier-less tx
    //    is "nothing for the fold" regardless of its shape — return 0. (No count cap:
    //    §0 pins no per-tx limit, so the SmTx spills to the heap for a large tx.)
    int have_carrier = 0;
    for (int o = 0; o < tx->n_out && !have_carrier; o++) {
        const IdxOut *out = &tx->outs[o];
        const uint8_t *payload; size_t plen;
        if (!idx_op_return_payload(out->spk, out->spklen, &payload, &plen)) continue;
        SmCarrier car; memset(&car, 0, sizeof car);
        sm_decode_payload(payload, plen, (uint64_t)out->value, s->onchain_magic, &car);
        if (car.kind != SM_CAR_IGNORE) have_carrier = 1;
    }
    if (!have_carrier) return 0;

    // 1. Carriers (OP_RETURN single-minimal-push → ACTION) + spendable outs,
    //    both in vout order. Track which inputs a carrier NAMES for §4 attribution.
    //    `named` is a per-input flag sized to the real input count (no cap).
    uint8_t named_stk[64]; uint8_t *named = named_stk;
    if (tx->n_in > (int)sizeof named_stk) named = calloc((size_t)tx->n_in, 1);
    else memset(named, 0, sizeof named_stk);
    for (int o = 0; o < tx->n_out; o++) {
        const IdxOut *out = &tx->outs[o];
        const uint8_t *payload; size_t plen;
        if (idx_op_return_payload(out->spk, out->spklen, &payload, &plen)) {
            SmCarrier car; memset(&car, 0, sizeof car);
            sm_decode_payload(payload, plen, (uint64_t)out->value, s->onchain_magic, &car);
            if (car.kind != SM_CAR_ACTION) continue;          // §1: only name-action carriers
            car.value = (uint64_t)out->value;
            car.vout  = out->vout;
            // Mark every input a carrier NAMES so §4 attribution covers it (not just
            // vin[0]): AS names one input, TRADE names two. Missing the TRADE pair was
            // a real bug — the engine drops a trade whose idx_a/idx_b are ⊥, so every
            // on-chain TRADE silently failed to settle (spec §3.9 requires it fold).
            if (car.act.op == SM_OP_AS) {
                int k = car.act.as_index; if (k >= 0 && k < tx->n_in) named[k] = 1;
            } else if (car.act.op == SM_OP_TRADE) {
                int ka = car.act.idx_a, kb = car.act.idx_b;
                if (ka >= 0 && ka < tx->n_in) named[ka] = 1;
                if (kb >= 0 && kb < tx->n_in) named[kb] = 1;
            }
            *sm_tx_carrier(&smtx) = car;
        } else {
            uint8_t h160[20], type;
            if (idx_script_payee(out->spk, out->spklen, h160, &type)) {
                SmOut *so = sm_tx_out(&smtx);
                memcpy(so->h160, h160, 20); so->type = type;
                so->value = (uint64_t)out->value; so->vout = out->vout;
            }
            // nonstandard / unspendable → not a §4 payee, skip
        }
    }

    // 2. §4 attribution. Always attribute vin[0]; attribute any carrier-named input
    //    (AS target / TRADE pair). in_sighash_all[k] = 1 iff fully verified (FOUND ⇒
    //    also signs SIGHASH_ALL, since der_parse requires hashtype 0x01). Every input
    //    slot is materialised so idx_a/idx_b past a lazy horizon can never read ⊥ by
    //    accident (no cap: idx up to n_in-1 is a real, spec-valid index).
    for (int k = 0; k < tx->n_in; k++) {
        SmId *in = sm_tx_input(&smtx);
        if (k != 0 && !named[k]) continue;                    // lazy: only vin[0] + named
        IdxAttr a;
        if (idx_attribute(tx->raw, tx->rawlen, k, &a) == IDX_ATTR_FOUND) {
            memcpy(in->h160, a.identity, 20);
            in->type = a.type;
            smtx.in_sighash_all[k] = 1;
        }
        // else: leave zeroed + in_sighash_all[k] = 0 → engine treats vin[k] as ⊥
    }

    sm_apply_tx(s, &smtx);
    sm_tx_free(&smtx);
    if (named != named_stk) free(named);
    return 1;
}
