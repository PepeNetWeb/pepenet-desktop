// serve_store.h — the NODE_NETWORK_LIMITED serving cache (peer-discovery
// slice 3, step 2). A dedicated aux db, SEPARATE from the fold db (pep.db):
//   • headers  — the full 80-byte header chain from the checkpoint forward,
//     the getheaders answer + (future) the cumulative-work substrate;
//   • blockwin — a rolling window of the last ~288 raw blocks, the
//     getdata(block) answer for a limited node.
// It is a pure NETWORK CACHE: deleting the file costs nothing but a re-sync
// (the fold db is the consensus truth, refoldable on its own). The sync path
// writes it as it connects blocks; the serve loop only reads it.
#ifndef IDX_SERVE_STORE_H
#define IDX_SERVE_STORE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ServeStore ServeStore;

// BIP159 NODE_NETWORK_LIMITED promises the last 288 blocks.
#define SERVE_BLOCK_WINDOW 288

ServeStore *serve_store_open(const char *path);   // NULL on failure
void        serve_store_close(ServeStore *ss);

// Record block `height`: header always; raw into the window, then trim the
// window to the last SERVE_BLOCK_WINDOW behind `tip`. Idempotent per height
// (INSERT OR REPLACE) so a reorg overwrites cleanly.
void serve_store_put(ServeStore *ss, int64_t height, const uint8_t hash[32],
                     const uint8_t hdr[80], const uint8_t *raw, size_t rawlen,
                     int64_t tip);

// Reorg: drop everything above `height` from both tables.
void serve_store_prune_above(ServeStore *ss, int64_t height);

int64_t serve_store_tip(ServeStore *ss);          // MAX(height), -1 if empty

// getheaders: the first locator hash we recognize → its height (else -1, "send
// from my earliest"). headers_from: up to `max` headers strictly ABOVE
// `after_height`, concatenated 80-byte, count in *n. Returns bytes written.
int64_t serve_store_locate(ServeStore *ss, const uint8_t *locator, int nloc);
size_t  serve_store_headers_from(ServeStore *ss, int64_t after_height,
                                 uint8_t *out, size_t outcap, int max, int *n);

// getblocks: up to `max` block HASHES strictly above `after_height`, ascending
// (the inv answer). win_floor: the oldest raw block still in the window, -1 if
// none — a getblocks fork below it cannot be answered without gapping the
// requester's sequential fold, so the server stays silent instead.
int     serve_store_hashes_from(ServeStore *ss, int64_t after_height,
                                uint8_t (*out)[32], int max);
int     serve_store_hash_at(ServeStore *ss, int64_t height, uint8_t out[32]);
int64_t serve_store_win_floor(ServeStore *ss);

// getdata(block): the raw block for `hash` if it is still in the window.
// Returns malloc'd bytes in *raw (caller frees) + *len, or 0 if not held.
int serve_store_block(ServeStore *ss, const uint8_t hash[32],
                      uint8_t **raw, size_t *len);

// ── blockstage: the sync-over-one-connection mailbox ─────────────────────────
// The serve thread getdatas every unknown block inv it sees on its (mesh)
// connections and parks the raw bytes here, UNVALIDATED; the sync pass folds
// rows that extend its tip through the same validation as socket blocks, so a
// node at tip follows the chain over its one mesh connection with no per-pass
// transient socket. Junk-tolerant by construction: capped to the freshest 32
// rows, aged out after an hour, deleted on fold or validation failure. Rows
// are never served to peers (blockwin is; it only takes fold-validated puts).
// have: known anywhere (headers OR stage) — the inv-fetch dedup.
int  serve_store_have(ServeStore *ss, const uint8_t hash[32]);
int  serve_store_stage_put(ServeStore *ss, const uint8_t hash[32], const uint8_t prev[32],
                           const uint8_t *raw, size_t len, int64_t now);   // 1 = newly staged
int  serve_store_stage_next(ServeStore *ss, const uint8_t prev[32],       // a row chaining to prev:
                            uint8_t hash_out[32], uint8_t **raw, size_t *len);  // 1 + malloc'd raw
void serve_store_stage_del(ServeStore *ss, const uint8_t hash[32]);
// staged blocks we hold but could NOT chain (their hash is no known header):
// the winning side of an orphan race, or a child whose parent's body was
// lost. Non-zero tells the sync pass its tip is suspect — run the socket
// ladder (where the reorg machinery lives) instead of skipping it.
int  serve_store_stage_pending(ServeStore *ss);

#ifdef __cplusplus
}
#endif

#endif
