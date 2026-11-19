// TRADE (§3.10) — atomic 1-1 name swap between two co-signing inputs.
//
// Payload [idxA][idxB] + nameA,nameB. The two inputs are the parties; each MUST
// sign SIGHASH_ALL. Validity is re-checked against LIVE state at confirm (the
// anti-rug, like SETTLE/PAY): vin[idxA] must still own nameA and vin[idxB]
// nameB, both unlocked. It is one opcode — it applies in FULL or DROPS in full;
// there is no partial or one-sided outcome. Leases convey; both parties' mutation
// heights bump.
#include "sm.h"
#include <string.h>

void sm_op_trade(SmState *s, SmTxCtx *cx, const SmAction *a) {
    const SmTx *tx = cx->tx;
    uint8_t ia = a->idx_a, ib = a->idx_b;

    if (ia >= tx->n_inputs || ib >= tx->n_inputs) return;            // index out of range
    if (ia == ib) return;                                            // one party, not two
    if (!tx->in_sighash_all[ia] || !tx->in_sighash_all[ib]) return;  // both must sign SIGHASH_ALL
    if (!sm_name_valid(a->name, a->name_len) ||
        !sm_name_valid(a->name_b, a->name_b_len)) return;            // §3.1 both sides
    if (strcmp(a->name, a->name_b) == 0) return;                     // nameA == nameB

    const uint8_t *PA = tx->inputs[ia].h160, *PB = tx->inputs[ib].h160;
    SmNameRow *rA = sm_find_name(s, a->name);
    SmNameRow *rB = sm_find_name(s, a->name_b);

    // live-ownership anti-rug re-check: each party still owns its pledged name, unlocked.
    if (!rA || rA->st != SM_OWNED || memcmp(rA->owner, PA, 20) != 0) return;
    if (!rB || rB->st != SM_OWNED || memcmp(rB->owner, PB, 20) != 0) return;

    // atomic swap (full-or-nothing): nameA → PB, nameB → PA; leases convey.
    memcpy(rA->owner, PB, 20); rA->owner_type = tx->inputs[ib].type;
    memcpy(rB->owner, PA, 20); rB->owner_type = tx->inputs[ia].type;
    sm_bump_mutation(s, PA, cx->height);
    sm_bump_mutation(s, PB, cx->height);
    s->ev[SM_EV_TRADE_OK]++;
}
