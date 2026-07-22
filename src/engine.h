// engine.h — the desktop client's sync-engine seam.
//
// The engine IS indexers/c compiled into this app: the protocol-sm fold + the
// live-validated P2P sync loop run on a background thread (repeated `sync`
// passes via indexer_main), writing the same SQLite database the headless
// indexerd writes. The UI thread never touches consensus — it reads the
// projections through this header (WAL mode: concurrent reads are safe).
#ifndef DESKTOP_ENGINE_H
#define DESKTOP_ENGINE_H

#include <stdint.h>

typedef struct {
    int64_t  height;        // our folded tip (0 until first status read)
    int64_t  activation;    // fold activation height (db meta; ops mined below
                            // it never fold — names go live AT this height)
    uint64_t rate;          // live §3.4 rate, koinu/name-quantum (next block)
    int64_t  year_cost;     // 13 quanta = 1 name-year, koinu
    int64_t  fee;           // per-tx network-fee quote, koinu (fee.h: the
                            // §3.4 feed over the recent window, 3rd quartile)
    int      running;       // engine thread alive
    int      pass_active;   // a sync pass is on the wire right now
    int      last_rc;       // last sync pass exit code (0 = clean catch-up)
    int64_t  passes;        // completed sync passes
    int64_t  peer_height;   // peer's declared tip (version.start_height) from
                            // the current pass's handshake; 0 = unknown.
                            // height ≥ peer_height is the live at-tip signal —
                            // pass boundaries lag it by the ~30 s a no-op pass
                            // needs to time out against getblocks-silence.
} EngineStatus;

// one names-projection row, GUI-shaped (states are sm.h SM_OWNED..SM_RESERVED)
typedef struct {
    char     name[24];
    int      st;
    int64_t  lease_expiry;
    uint64_t price;         // LISTED/OFFERED/RESERVED
    int64_t  offer_expiry;  // listing / directed-offer window end
    int64_t  reserve_expiry;
    uint8_t  buyer[20];     // OFFERED: who may pay; RESERVED: who won
    uint8_t  owner[20];     // current owner (LISTED: the seller) — the is-mine test
} EngineName;

// Start the sync thread: repeated indexer_main("sync", coin, db, ip) passes
// with a poll pause between them. Strings are copied. Returns 1, 0 on error.
int  engine_start(const char *coin, const char *dbpath, const char *ip);

// Signal the running pass to wind down (idx_sync_stop) and join the thread.
void engine_stop(void);

// UI-thread reads (own read connection, opened lazily). engine_status is cheap
// (one row); the rate is recomputed only when the height moved.
void engine_status(EngineStatus *out);

// Manual chain walk (the Peers screen's Start/Stop button). Start is refused —
// and the UI greys the button — while a marked peer is connected (the walk
// exists to FIND one) or on the seed itself. Runs between sync passes on the
// sync thread; busy = requested or on the wire right now (pair with
// idx_crawl_status().running for live progress).
void engine_crawl_start(void);
void engine_crawl_stop(void);
int  engine_crawl_busy(void);

// Dev-wallet plumbing. engine_watch registers the address in the indexer's
// watch list — call BEFORE engine_start (it opens/creates the db briefly on
// the calling thread; utxos index from the next synced block, so a fresh
// address catches all its funding). engine_balance sums the watched utxos on
// the UI read connection.
int     engine_watch(const char *dbpath, const uint8_t h160[20]);
int64_t engine_balance(const uint8_t h160[20]);

// Unconfirmed incoming: sum of relay-mempool outputs paying h160 that are NOT
// our own change (a mempool tx spending one of our utxos is a send we made, so
// its change back to us doesn't count). 0 until a payment reaches the pool; it
// moves into engine_balance once its block folds. This is the "incoming coins"
// the status bar surfaces — only possible because we now run a mempool.
int64_t engine_incoming(const uint8_t h160[20]);

// Names projection (UI read connection). engine_my_names: rows owned by h160
// (lex order — the fold's own bitmap/water-fill order). engine_market_mine:
// rows where h160 is the named BUYER (directed offers to me; reserves I won).
// Both return the row count.
int engine_my_names(const uint8_t h160[20], EngineName *out, int max);
int engine_market_mine(const uint8_t h160[20], EngineName *out, int max);

// The whole open marketplace: every §3.7 LISTED + RESERVED name across the
// projection (the buy side anyone can browse), highest price first. owner and
// buyer are filled so the caller can flag its own listings and the reserves it
// won. Returns the row count.
int engine_listings(EngineName *out, int max);

// One-name lookup: 0 = not in the projection (free), 1 = found (owner160/st
// filled if non-NULL), -1 = found but the owner isn't P2PKH (taken; can't be
// a send-to-name destination). Send-to-name resolves through this.
int engine_name_lookup(const char *name, uint8_t owner160[20], int *st);

// One row of the persisted peers table (addr-gossip harvest + crawl handshakes)
// — the Peers page's "known peers" card. agent is the subver captured at the
// last good handshake ("" = never handshaken, addr only vouched/harvested);
// dnet = a marked peer vouched for this addr over dnaddr.
typedef struct {
    char    addr[80];
    char    agent[128];
    int64_t last_seen;      // last sighting in gossip
    int64_t last_good;      // last completed handshake (0 = never)
    int     dnet;
} EnginePeer;

// The mesh bucket of the peers table off the UI read connection: confirmed
// marked (IDX_DNET_MARK) agents first, then dnaddr-vouched addrs, freshest — the
// plain chain harvest is NOT listed (thousands of addrs; total count only).
// total/pepenet (may be NULL) get the whole table's counts regardless of max.
// Returns rows written.
int engine_peers(EnginePeer *out, int max, int *total, int *pepenet);

// Is this outpoint still in the watched-utxo set? (ops.c confirmation watch —
// a broadcast tx has folded once its inputs leave the set.)
int engine_outpoint_unspent(const uint8_t h160[20], const uint8_t txid[32],
                            uint32_t vout);

// Enumerate the watched-utxo set (ops.c chain forensics: a malleated link's
// substitute change shows up here — same value, a txid we never built).
// Returns the row count; cb runs on the caller's read connection.
typedef void (*EngineUtxoCb)(void *ud, const uint8_t txid[32], uint32_t vout,
                             int64_t value);
int engine_utxos(const uint8_t h160[20], EngineUtxoCb cb, void *ud);

#endif
