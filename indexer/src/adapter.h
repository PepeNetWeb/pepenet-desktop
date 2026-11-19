// adapter.h — the one new consensus-relevant layer: project a real Dogecoin tx
// into the engine's abstract SmTx (decode each OP_RETURN carrier §1, attribute
// vin[0] + any AS-named input §4, gather spendable outputs §3.5) and fold it.
#ifndef IDX_ADAPTER_H
#define IDX_ADAPTER_H

#include "sm.h"
#include "chain.h"

#ifdef __cplusplus
extern "C" {
#endif

// Fold one parsed tx into `s` (call in txindex order, after sm_begin_block).
//   1 = folded, 0 = skipped (no protocol carrier). No count-cap path: the SmTx
//   sizes to the real tx (§0 pins no per-tx cap), spilling to the heap if large.
int idx_adapt_tx(SmState *s, const IdxTx *tx, uint32_t txindex);

#ifdef __cplusplus
}
#endif

#endif
