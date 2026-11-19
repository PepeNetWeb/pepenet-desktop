// oracle_feed.h — §3.4 fee-rate oracle + §6 MTP, fed from connected blocks.
//
// The protocol-sm fold is chain-abstracted: it takes (height, mtp, rate) per
// block. This module is the production source of those two derived numbers,
// maintaining the rolling per-block data the spec's stateless oracle needs:
//   rate = §3.4 over the FEE_WINDOW blocks STRICTLY BELOW h ({coinbase, bytes}),
//   mtp  = §6 median of the 11 timestamps STRICTLY BELOW h.
// subsidy is Dogecoin's flat 10,000 DOGE across the reachable window (§3.4).
#ifndef IDX_ORACLE_FEED_H
#define IDX_ORACLE_FEED_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct OracleFeed OracleFeed;

OracleFeed *oracle_new(void);
void        oracle_free(OracleFeed *o);
// §3.4 host flat-tail subsidy (koinu/block). Default = Dogecoin/Pepecoin 10,000×KOINU;
// a chain with a different tail MUST set it (profile) or its rent rate forks.
void        oracle_set_subsidy(OracleFeed *o, int64_t subsidy_koinu);

// Record block `height`'s oracle inputs (call as each block connects, in order).
void oracle_record(OracleFeed *o, int64_t height, int64_t timestamp,
                   int64_t coinbase_out_total, int64_t block_bytes);

// Drop everything at/above `height` (reorg rollback).
void oracle_rollback(OracleFeed *o, int64_t height);

// Compute (mtp, rate) for connecting block `height` from the STRICTLY-BELOW
// window already recorded. Degrades gracefully near the start (short window →
// available predecessors; empty → rate clamps to DUST_FLOOR, mtp 0).
void oracle_for_height(OracleFeed *o, int64_t height, int64_t *mtp, uint64_t *rate);

#ifdef __cplusplus
}
#endif

#endif
