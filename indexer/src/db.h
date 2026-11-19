// db.h — sqlite projection of the engine's fold state + sync/reorg bookkeeping.
//
// link-as-engine + DB-projection: the in-RAM SmState is authoritative (the
// conformant fold mutates it); sqlite is a write-through projection — a queryable
// replica, a restart cache, and the reorg substrate. The projection is lossless:
// load(save(state)) reproduces the same canonical digest (asserted in selftest).
#ifndef IDX_DB_H
#define IDX_DB_H

#include <stdint.h>
#include <sqlite3.h>
#include "sm.h"

#ifdef __cplusplus
extern "C" {
#endif

sqlite3 *idx_db_open(const char *path);
void     idx_db_close(sqlite3 *db);

// sync cursor (height + tip hash, wire order) and activation height.
void idx_db_save_sync(sqlite3 *db, int64_t height, const uint8_t tip_hash[32]);
int  idx_db_load_sync(sqlite3 *db, int64_t *height, uint8_t tip_hash[32]);   // 1 if present
// last observed peer start_height from a version handshake — the fail-closed
// error page (and anything else in another process) reads this; 0 if never seen
void    idx_db_set_peer_height(sqlite3 *db, int64_t h);   // monotonic max (same as raise)
void    idx_db_raise_peer_height(sqlite3 *db, int64_t h);   // monotonic max
int64_t idx_db_get_peer_height(sqlite3 *db);
void idx_db_set_activation(sqlite3 *db, int64_t activation);
int64_t idx_db_get_activation(sqlite3 *db, int64_t dflt);
void    idx_db_set_subsidy(sqlite3 *db, int64_t subsidy_koinu);
int64_t idx_db_get_subsidy(sqlite3 *db, int64_t dflt);
// name-carrier magic (two bytes). Missing key → 0, so an old pep.db stays pep
// via the caller's default. An extra meta row is not part of the name digest.
void idx_db_set_onchain_magic(sqlite3 *db, const uint8_t mag[2]);
int  idx_db_get_onchain_magic(sqlite3 *db, uint8_t mag[2]);   // 1 if present
// one-shot meta markers (migrations/repairs that must run once per db)
int  idx_db_flag_get(sqlite3 *db, const char *k);
void idx_db_flag_set(sqlite3 *db, const char *k);

// chain peers harvested from addr gossip ("ip:port" text): the sync-failover
// pool and the pepenet crawl frontier. note = seen in gossip (upserts services
// + last_seen, keeps last_good); seen = WE completed a handshake (records
// services + agent + last_good); tried = dial attempted (crawl politeness);
// best = sync/broadcast candidates — proven peers first, then harvested
// NODE_NETWORK addrs by recency; crawl = the exploration frontier (never-tried
// first, then stalest); agent = addrs whose subver starts with `prefix`
// ("/pepenet-" = the dns-mesh bucket), freshest handshake first.
void idx_db_peer_note(sqlite3 *db, const char *addr, int64_t services, int64_t now);
void idx_db_peer_seen(sqlite3 *db, const char *addr, int64_t services,
                      const char *agent, int64_t now);
void idx_db_peer_tried(sqlite3 *db, const char *addr, int64_t now);
void idx_db_peers_scrub(sqlite3 *db);   // boot: drop pre-fix hostname rows
void idx_db_peer_bad(sqlite3 *db, const char *addr);   // served invalid data: demote
int  idx_db_peers_best(sqlite3 *db, char (*out)[80], int max);
int  idx_db_peers_crawl(sqlite3 *db, char (*out)[80], int max);
int  idx_db_peers_agent(sqlite3 *db, const char *prefix, char (*out)[80], int max);
// overlay (pepenet) peer discovery: dnet_note records an addr a pepenet peer
// vouched for over dnaddr (sets the dnet hint, doesn't touch agent/last_good);
// peers_dnet returns the mesh dial pool — confirmed-agent pepenet peers first,
// then vouched-only hints — so a restarting node re-embeds into the mesh from
// its own persisted memory instead of re-discovering it by chain-crawl luck.
void idx_db_peer_dnet_note(sqlite3 *db, const char *addr, int64_t services, int64_t now);
// retry_cut > 0: skip proven (last_good>0) rows in dial-failure backoff
// (last_try > last_good and newer than the cutoff). vouch_cut > 0: skip
// never-connected vouches (last_good=0, last_try>0) newer than that cutoff.
// 0 disables that filter (gossip answers vouch regardless of our dial luck).
int  idx_db_peers_dnet(sqlite3 *db, char (*out)[80], int max,
                       int64_t retry_cut, int64_t vouch_cut);
/* tried / dnaddr: agent LIKE IDX_DNET_MARK '%', regardless of dnet. */
int  idx_db_peers_dnet_confirmed(sqlite3 *db, char (*out)[80], int max,
                                 int64_t retry_cut);
/* new / feeler: dnet=1 AND agent NOT LIKE mark. vouch_cut skips last_try. */
int  idx_db_peers_dnet_new(sqlite3 *db, char (*out)[80], int max,
                           int64_t vouch_cut);
// drop every peers row for this IPv4 (self, after we learn our external ip)
void idx_db_peers_drop_host(sqlite3 *db, const char *host);
// stamp agent on existing rows for this IPv4 (inbound marked handshake —
// listen-port row, not the ephemeral). Does not set last_good. If no row
// exists, INSERT host:<port> so the observation can enter dnaddr.
void idx_db_peer_touch_agent(sqlite3 *db, const char *host, uint16_t port,
                             const char *agent, int64_t now);
// full rows for addr advertisement (freshest sighting first)
typedef struct { char addr[80]; int64_t services, last_seen; } IdxPeerRow;
int  idx_db_peers_rows(sqlite3 *db, IdxPeerRow *out, int max);
// addrman-lite dial candidates (Core's tried/new split): tried=1 → proven
// peers (last_good>0), freshest-proven first; tried=0 → unproven harvested
// block-servers (services bit0 set, never handshaken), random order so the
// frontier gets explored rather than the same head re-dialed. last_try rides
// along for the caller's failure backoff.
typedef struct { char addr[80]; int64_t last_good, last_try; } IdxPeerSel;
int  idx_db_peers_select(sqlite3 *db, IdxPeerSel *out, int max, int tried);
// TTL/cap the peers table: drop rows whose last useful sighting (max of
// last_seen/last_good) predates now-ttl_secs, then hard-cap to the freshest
// `cap` rows. A working peer re-stamps last_good every good handshake, so an
// addr only ages out once it has actually gone quiet. ttl_secs/cap ≤0 = skip.
void idx_db_peers_prune(sqlite3 *db, int64_t now, int64_t ttl_secs, int cap);

// per-block index (reorg step-back + oracle restore on restart). bits = the
// header's compact target, kept as Digishield retarget context.
void idx_db_block_put(sqlite3 *db, int64_t height, const uint8_t hash[32],
                      int64_t time, int64_t coinbase, int64_t bytes, uint32_t bits);
int  idx_db_block_get(sqlite3 *db, int64_t height, uint8_t hash[32]);        // 1 if found
int  idx_db_block_hdr(sqlite3 *db, int64_t height, int64_t *time, uint32_t *bits);
int  idx_db_block_times(sqlite3 *db, int64_t height, int64_t out[11]);       // ≤11 below height, newest first
void idx_db_block_prune_above(sqlite3 *db, int64_t height);                  // reorg: drop > height (blocks + raw_blocks)
int64_t idx_db_block_height_by_hash(sqlite3 *db, const uint8_t hash[32]);    // -1 if unknown

// raw bytes of carrier-bearing blocks only (the reorg-replay substrate: state
// replays from these; carrier-less blocks need only their oracle row above).
void idx_db_rawblock_put(sqlite3 *db, int64_t height, const uint8_t *raw, size_t len);
// ascending by height, up to max_height. cb returns 0 to abort → iter returns -1.
int  idx_db_rawblock_iter(sqlite3 *db, int64_t max_height,
                          int (*cb)(void *u, int64_t height, const uint8_t *raw, size_t len), void *u);
// Feed all recorded (height ≤ tip) blocks into the oracle, oldest-first, so the
// fee/MTP window is warm after a restart. Returns count fed.
int  idx_db_oracle_warm(sqlite3 *db, void *oracle);

// Full write-through projection of the live fold state (clears + re-dumps the
// names/commits/muts tables) atomically with the proj_height sentinel. Call after a
// block (or batch) is folded. Returns 1 on commit, 0 if it rolled back (disk/I-O
// error) — on 0 the prior projection + proj_height are left intact for retry.
int idx_db_project(sqlite3 *db, SmState *s);
int64_t idx_db_projected_height(sqlite3 *db);   // height the last projection reflects, -1 if none
// Restore a fold state from the projection (inverse of project). Caller passes a
// fresh sm_new(activation); fields are loaded verbatim. Returns rows loaded.
int  idx_db_load_state(sqlite3 *db, SmState *s);

// Rollback checkpoints — local replay shortcut, never digested or sent. A row is
// the projected fold state at a height; idx_db_project takes one every
// idx_db_ckpt_every() heights (meta rb_ckpt_every; 0 = off) and keeps the last 4.
// ckpt_load restores the newest valid row <= max_height whose activation matches
// s->activation_height into *s (a fresh sm_new); it returns that height, or -1.
int64_t idx_db_ckpt_every(sqlite3 *db);
void    idx_db_ckpt_set_every(sqlite3 *db, int64_t every);
int     idx_db_ckpt_save(sqlite3 *db, SmState *s);
int64_t idx_db_ckpt_load(sqlite3 *db, int64_t max_height, SmState *s);
int     idx_db_ckpt_prune_above(sqlite3 *db, int64_t height);
int     idx_db_ckpt_wipe(sqlite3 *db);
int     idx_db_ckpt_count(sqlite3 *db);
// Empty table + loaded projection >= activation+every: take one now (1), else 0; -1 error.
int     idx_db_ckpt_seed(sqlite3 *db, SmState *s);
extern size_t idx_ckpt_max_bytes;   // state blob cap (tests may lower it)

// ── epochs projection (ownership history — substrate for overlay layers) ─
// An append-only per-block record of every ownership CHANGE: (name, start_height,
// owner) rows, owner NULL = the name lapsed/left the state at that height. Written
// from the fold path (per block, gated to blocks that could change ownership),
// height-bounded so reorg replay and refold re-derive it idempotently.
//
// Diff the live state against recorded history at `height`: for every name whose
// owner differs from its latest row ≤ height (or that has none) an epoch row is
// inserted; open epochs whose name left the state get a NULL (lapse) row.
void idx_db_epochs_update(sqlite3 *db, SmState *s, int64_t height);
// owner_of(name @ height) from recorded history.
//   1 = owned (owner/owner_type filled) · 0 = known-unowned at that height ·
//  -1 = history does not cover (height < epochs_from, or no rows for the name on a
//       DB that predates the projection) — caller may fall back to current owner.
int  idx_db_owner_at(sqlite3 *db, const char *name, int name_len, int64_t height,
                     uint8_t owner[20], uint8_t *owner_type);
// set meta `epochs_from` = height iff absent (the height history is continuous from)
void idx_db_epochs_mark(sqlite3 *db, int64_t height);
// drop all epoch rows + the epochs_from marker (refold under re-pinned rules)
void idx_db_epochs_wipe(sqlite3 *db);

// wallet watch list + UTXO tracking (P2PKH only — the sync records outputs paying
// a watched hash160 and marks their spends; pruned/un-marked with blocks on reorg).
void idx_db_watch_add(sqlite3 *db, const uint8_t h160[20]);
int  idx_db_watch_list(sqlite3 *db, uint8_t (*out)[20], int max);            // returns count
void idx_db_utxo_put(sqlite3 *db, const uint8_t txid[32], uint32_t vout,
                     const uint8_t h160[20], int64_t value, int64_t height);
// mark txid:vout spent at height; returns rows hit (1 = it was a watched utxo)
int  idx_db_utxo_spend(sqlite3 *db, const uint8_t txid[32], uint32_t vout, int64_t height);
// MIN(height) over unspent rows (all watched addresses), -1 if none
int64_t idx_db_utxo_min_unspent(sqlite3 *db);
// unspent rows for h160, largest-first. Returns count.
int  idx_db_utxos(sqlite3 *db, const uint8_t h160[20],
                  void (*cb)(void *u, const uint8_t txid[32], uint32_t vout, int64_t value, int64_t height),
                  void *u);

// ── queries (display) ─────────────────────────────────────────────────────────
// owner hash160 hex of `name` (any state), "" if unowned. 1 if found.
// read-only open for display readers (no schema/migration writes); NULL if the
// file is missing or has no names table yet.
sqlite3 *idx_db_open_ro(const char *path);
int  idx_db_resolve(sqlite3 *db, const char *name, char owner_hex[41], char *state_out);
// full projected name record, market fields included — the wallet's market data
// source (price/seller/legs read from the fold's own view, never hand-typed).
typedef struct {
    uint8_t  owner[20];  uint8_t owner_type;  int64_t lease_expiry; int st;
    uint8_t  seller[20]; uint8_t seller_type; uint64_t price;
    int64_t  offer_expiry; uint8_t buyer[20];
    uint64_t burn_leg, pay_leg; int64_t reserve_expiry;
} IdxNameRow;
int  idx_db_name_row(sqlite3 *db, const char *name, IdxNameRow *out);            // 1 if found
// names owned by hash160-hex `h160hex`; callback per row. Returns count.
int  idx_db_owned(sqlite3 *db, const char *h160hex,
                  void (*cb)(void *u, const char *name, int64_t lease_expiry, int st), void *u);
// dane-09: page of names in BINARY name order, optionally restricted to a
// prefix (the range [prefix, prefix+1) so the name PRIMARY KEY index serves both
// the count and the page — no table scan). owner is NULL for an unowned row.
// Returns the total rows matching the prefix, or -1 on error.
int64_t idx_db_names(sqlite3 *db, const char *prefix, int64_t offset, int limit,
                     void (*cb)(void *u, const char *name, const uint8_t *owner,
                                int64_t lease_expiry, int st, uint64_t price), void *u);

#ifdef __cplusplus
}
#endif

#endif
