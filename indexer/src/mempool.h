// mempool.h — the relay transaction pool. A process-global, thread-safe singleton
// (no init needed — static zero-state). Three threads touch it in a live node:
//   • the net thread (idx_serve): mempool_accept on an inbound `tx`, mempool_get
//     to answer a `getdata`, mempool_txids/has for `inv` dedup.
//   • the sync thread (block fold): mempool_on_confirmed_tx to evict a tx once it
//     lands in a block, plus any tx it now conflicts with.
//   • the UI thread (desktop): mempool_scan to total unconfirmed credits.
// Every entry keeps a private COPY of the raw tx bytes (the parser is zero-copy,
// so the pool must own the memory it hands back to getdata).
#ifndef IDX_MEMPOOL_H
#define IDX_MEMPOOL_H

#include <stdint.h>
#include <stddef.h>
#include "chain.h"       // IdxTx (for the block-fold eviction hook)

#define MEMPOOL_MAX_TXS     5000
#define MEMPOOL_MAX_BYTES   (64u * 1024 * 1024)   // 64 MiB
#define MEMPOOL_EXPIRY_SEC  (72 * 3600)           // drop unconfirmed after 72h

// Validate (txcheck_stateless) + dedup + within-pool conflict check + insert.
// Returns 1 on accept, 0 on reject (reason filled if non-NULL). `txid_out` is
// filled with the tx hash whenever the bytes parse (accept OR a post-parse
// reject) so the caller can dedup/relay; it is zeroed on a parse failure.
int  mempool_accept(const uint8_t *raw, size_t len, uint8_t txid_out[32],
                    char *reason, size_t reason_cap);

int  mempool_has(const uint8_t txid[32]);
// Malloc a copy of the stored tx bytes for `txid` (caller frees), or NULL.
uint8_t *mempool_get_copy(const uint8_t txid[32], size_t *len_out);

// "Recently seen" ring (accepted OR rejected) — suppresses re-requesting a tx we
// already processed and dropped. mempool_has() also counts as seen.
int  mempool_seen(const uint8_t txid[32]);
void mempool_note_seen(const uint8_t txid[32]);

// Block-fold hook: a confirmed tx leaves the pool, and so does anything that now
// conflicts with it (spends one of its inputs). Cheap no-op while the pool is
// empty (the common case during initial sync).
void mempool_on_confirmed_tx(const uint8_t txid[32], const IdxTx *tx);

// Drop entries older than MEMPOOL_EXPIRY_SEC. Call from the serve tick.
void mempool_sweep(int64_t now);

int    mempool_count(void);
// Copy up to `max` txids out (for answering a `mempool` message / tests).
size_t mempool_txids(uint8_t (*out)[32], size_t max);
// Iterate every pooled tx under the lock — cb must not call back into mempool.
void   mempool_scan(void (*cb)(void *ud, const uint8_t txid[32],
                               const uint8_t *raw, size_t len), void *ud);

// Free everything (test teardown / clean shutdown). Not required before use.
void mempool_reset(void);

#endif
