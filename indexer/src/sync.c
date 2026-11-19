// sync.c — CLI driver: offline `index`, the `resolve`/`owned`/`digest` queries,
// and the live P2P `sync` loop. The fold + projection are the proven path
// (selftest); P2P here connects a Dogecoin-family node (doge/pep), pulls blocks
// via getblocks/inv/getdata, and drives the same adapter→engine→projection
// pipeline per block.
#include "indexer.h"
#include "chain.h"
#include "adapter.h"
#include "base58.h"
#include "db.h"
#include "oracle_feed.h"
#include "pow.h"
#include "serve_store.h"
#include "mempool.h"
#include "txcheck.h"
#include "net_policy.h"
#include "snapshot.h"
#include "sha256.h"
#include "sm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "dbcheck.h"
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <poll.h>
#include <pthread.h>
#include <sys/random.h>
#include <time.h>
#ifndef _WIN32
#include <signal.h>
#endif

// subver classifier: does this agent carry the overlay discovery mark?
// (IDX_DNET_MARK, indexer.h — build-time per deployment, "/pepenet-" default)
#define AGENT_MARKED(a) (!strncmp((a), IDX_DNET_MARK, sizeof IDX_DNET_MARK - 1))

// ── coin params (host-chain profile — see docs/notes/host-profiles.md) ────────
// `start` = the pinned sync-bootstrap checkpoint: a fresh DB stands on this
// (height, hash) and the first getblocks locator anchors there, so the peer serves
// start+1 onward and our height counter matches real chain heights. The checkpoint
// is profile-pinned because rates are only network-deterministic when every indexer
// has the same oracle window — ACTIVATION_HEIGHT must be ≥ start + FEE_WINDOW + 1.
// Hash is in internal (little-endian) byte order.
typedef struct {
    const char *name; uint8_t magic[4]; uint16_t port; int64_t activation;
    int64_t start; uint8_t start_hash[32];
    int64_t subsidy;         // §3.4 flat-tail subsidy (koinu/block); consensus-critical per host
    const char *seeds[4];    // the host chain's own DNS seeds (Core's vSeeds hosts),
                             // NULL-terminated — the last-resort sync candidates
    // PoW validation profile (pow.h): powlimit == 0 skips validation entirely
    // (test profiles sync synthetic fixture chains). start_bits/start_time/
    // start_prev_time pin the checkpoint header — the Digishield + MTP anchor
    // for the first blocks a fresh db accepts (fetched from the live chains,
    // scripts/fetchblk-style, when the checkpoint was pinned).
    uint32_t powlimit, aux_chain_id, start_bits;
    int64_t  start_time, start_prev_time;
    uint8_t  onchain_magic[2];   // name-carrier prefix after 0xFF (per chain)
} Coin;
#define SUBSIDY_10K  (10000LL * SM_KOINU_PER_DOGE)
static const Coin COINS[] = {
    // Dogecoin mainnet (DogeNet). Names activate at block 6,429,500 (target
    // wall-clock 2026-10-25 ~04:40 UTC; re-pinned 2026-10-24 for live
    // testing, keeping the 11,000 gap). Prefix 0xFF 'D' 'N'.
    // Fold checkpoint (start) is 6,418,500 (header baebf7e7…df7ad1, 2026-10-17)
    // — 11,000 below activation so the §3.4 oracle window (FEE_WINDOW 10,081,
    // fed from start+1) is FULL from block 6,428,582. Internal (LE) byte order.
    // onchain magic is 'D' 'N'. (dane-07: matches namespace-indexer ce68a5c.)
    { "doge",    { 0xC0, 0xC0, 0xC0, 0xC0 }, 22556, 6429500, 6418500,
      { 0xd1, 0x7a, 0xdf, 0xfc, 0xa8, 0x67, 0x30, 0x68, 0xbf, 0xbc, 0x7d, 0x95, 0x36, 0x9c, 0xec, 0x17,
        0x1c, 0x12, 0x3f, 0xa4, 0xe6, 0xf0, 0x42, 0xa6, 0x6a, 0xe4, 0x7d, 0x5b, 0xe7, 0xf7, 0xeb, 0xba }, SUBSIDY_10K,
      { "seed.dogecoin.surf", "seed.multidoge.org", "seed2.multidoge.org", NULL },
      0x1e0fffff, 0x62, 0x19547b37, 1792213564, 1792213486, { 0x44, 0x4E } },
    // Pepecoin mainnet (Dogecoin 1.14 fork; same 1-min blocks + flat 10k tail subsidy).
    // Names activate at block 1,130,000 (re-pinned 2026-07-20 for the PN
    // prefix relaunch); the fold checkpoint (start) is pinned at 1,119,000 (header
    // cda615cf…fad1bb, 2026-07-11 — genesis-walked and chain-linked up to the
    // prior 1,122,000 pin before adoption). start sits 11,000 blocks below
    // activation, so the §3.4 oracle window (FEE_WINDOW 10,081, fed from
    // start+1) is FULL from block 1,129,082 — every rate the fold ever computes
    // is a full-window rate; no partial-window launch case. Re-pinning start
    // ORPHANS dbs synced from the old 1,122,000 pin (their rates at
    // 1,130,000..1,132,081 were partial-window): delete the db and resync.
    // Internal (little-endian) byte order. onchain magic is 'P' 'N'.
    { "pep",     { 0xC0, 0xA0, 0xF0, 0xE0 }, 33874, 1130000, 1119000,
      { 0xbb,0xd1,0xfa,0xd7,0x7f,0xd3,0xf2,0x40,0x05,0xfc,0x5f,0x62,0xc4,0x1d,0xb7,0x8b,
        0xc2,0xf2,0x19,0x0e,0x44,0x2c,0x45,0xbd,0xb7,0x57,0xe5,0x68,0xcf,0x15,0xa6,0xcd }, SUBSIDY_10K,
      { "seeds.pepecoin.org", "seeds.pepeblocks.com", NULL },
      0x1e0fffff, 0x3f, 0x196ac0dc, 1783774438, 1783774393, { 0x50, 0x4E } },
    { "testnet", { 0xFC, 0xC1, 0xB7, 0xDC }, 44556, 0, 0,
      { 0x9e,0x55,0x50,0x73,0xd0,0xc4,0xf3,0x64,0x56,0xdb,0x89,0x51,0xf4,0x49,0x70,0x4d,
        0x54,0x4d,0x28,0x26,0xd9,0xaa,0x60,0x63,0x6b,0x40,0x37,0x46,0x26,0x78,0x0a,0xbb }, SUBSIDY_10K,
      { NULL }, 0, 0, 0, 0, 0, { 0x50, 0x4E } },       // powlimit 0 = validation off (fixtures); PN magic
    { "regtest", { 0xFA, 0xBF, 0xB5, 0xDA }, 18444, 0, 0,
      { 0xa5,0x73,0xe9,0x1c,0x17,0x72,0x07,0x6c,0x0d,0x40,0xf7,0x0e,0x44,0x08,0xc8,0x3a,
        0x31,0x70,0x5f,0x29,0x6a,0xe6,0xe7,0x62,0x9d,0x4a,0xdc,0xb5,0xa3,0x60,0x21,0x3d }, SUBSIDY_10K,
      { NULL }, 0, 0, 0, 0, 0, { 0x50, 0x4E } },       // powlimit 0 = validation off (fixtures); PN magic
};
static const Coin *coin_by_name(const char *n) {
    for (unsigned i = 0; i < sizeof COINS / sizeof COINS[0]; i++) if (!strcmp(COINS[i].name, n)) return &COINS[i];
    return NULL;
}

uint16_t idx_coin_port(const char *coin) {
    const Coin *c = coin_by_name(coin);
    return c ? c->port : 0;
}

int idx_coin_onchain_magic(const char *name, uint8_t out[2]) {
    const Coin *c = coin_by_name(name);
    if (!c || !out) return 0;
    memcpy(out, c->onchain_magic, 2);
    return 1;
}

// idx-10: which on-chain prefix a db folds under. Never guesses pep.
//   1. an explicit coin (--coin / the snapshot coin arg) wins; a stored magic
//      that disagrees is refused (refold may override it: it rebuilds all);
//   2. else the stored meta onchain_magic, unless the db's activation/start
//      pins identify a coin with a DIFFERENT magic (a poisoned db, e.g. the
//      old doge db a pre-idx-10 refold stamped 'PN') -> refuse;
//   3. else inferred from meta activation, or from the first stored block
//      height, matching a coin profile pin (every matching profile must agree:
//      activation 0 = testnet/regtest, both 'PN');
//   4. else refuse with a clear error.
// Returns 1 = explicit/stored (safe to persist), 2 = inferred (do not
// persist), 0 = refused (message printed).
static void stamp_magic(SmState *s, const uint8_t mag[2]) {
    if (s && mag) memcpy(s->onchain_magic, mag, 2);
}
static int infer_magic(sqlite3 *db, uint8_t out[2], char *why, size_t cap) {
    int64_t act = idx_db_get_activation(db, -1), first = -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT MIN(height) FROM blocks", -1, &st, NULL) == SQLITE_OK &&
        sqlite3_step(st) == SQLITE_ROW && sqlite3_column_type(st, 0) != SQLITE_NULL)
        first = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    int found = 0; const char *who = NULL;
    for (unsigned i = 0; i < sizeof COINS / sizeof COINS[0]; i++) {
        const Coin *c = &COINS[i];
        int hit = (act >= 0 && act == c->activation) ||
                  (act < 0 && first >= 0 && c->start > 0 && (first == c->start || first == c->start + 1));
        if (!hit) continue;
        if (found && memcmp(out, c->onchain_magic, 2)) return -1;     // ambiguous
        memcpy(out, c->onchain_magic, 2); found = 1; who = c->name;
    }
    if (found) snprintf(why, cap, "inferred from %s pins (%s %lld)", who,
                        act >= 0 ? "activation" : "first block", (long long)(act >= 0 ? act : first));
    return found;
}
static int resolve_magic(SmState *s, sqlite3 *db, const char *coin, int allow_override, const char *cmd) {
    uint8_t stored[2], inf[2], use[2]; char why[96] = "";
    int has = db && idx_db_get_onchain_magic(db, stored);
    int ih = db ? infer_magic(db, inf, why, sizeof why) : 0;
    const Coin *c = coin ? coin_by_name(coin) : NULL;
    if (coin && !c) { fprintf(stderr, "%s: REFUSED: unknown coin '%s'\n", cmd, coin); return 0; }
    if (c) {
        memcpy(use, c->onchain_magic, 2);
        if (has && memcmp(stored, use, 2)) {
            if (!allow_override) {
                fprintf(stderr, "%s: REFUSED: db onchain_magic %c%c does not match coin %s (%c%c)\n",
                        cmd, stored[0], stored[1], coin, use[0], use[1]);
                return 0;
            }
            fprintf(stderr, "%s: note: db onchain_magic %c%c replaced by %s's %c%c\n",
                    cmd, stored[0], stored[1], coin, use[0], use[1]);
        }
        stamp_magic(s, use); return 1;
    }
    if (has) {
        if (ih == 1 && memcmp(inf, stored, 2)) {
            fprintf(stderr, "%s: REFUSED: db onchain_magic %c%c contradicts its pins (%s -> %c%c); "
                            "pass --coin <name> explicitly\n", cmd, stored[0], stored[1], why, inf[0], inf[1]);
            return 0;
        }
        stamp_magic(s, stored); return 1;
    }
    if (ih == 1) { stamp_magic(s, inf); fprintf(stderr, "%s: note: db has no onchain_magic; %s\n", cmd, why); return 2; }
    fprintf(stderr, "%s: REFUSED: db has no onchain_magic and its activation/start pins %s; "
                    "pass --coin <doge|pep|testnet|regtest>\n", cmd,
            ih < 0 ? "match coins with different prefixes" : "match no known coin");
    return 0;
}
// strip "--coin NAME" from argv (any position); returns NAME or NULL
static const char *take_coin_opt(int *argc, char **argv) {
    const char *coin = NULL;
    for (int i = 2; i < *argc; i++)
        if (!strcmp(argv[i], "--coin")) {
            if (i + 1 >= *argc) { argv[i] = NULL; (*argc)--; return ""; }   // dangling: "" = unknown coin
            coin = argv[i + 1];
            for (int j = i; j + 2 <= *argc; j++) argv[j] = argv[j + 2];
            *argc -= 2; i--;
        }
    return coin;
}

// ── fold-block context (shared by offline + P2P) ─────────────────────────────
#define IDX_MAX_WATCH 16
typedef struct { SmState *s; sqlite3 *db; OracleFeed *oracle; int folded;
                 int64_t height;
                 int wallet_touched;   // this block put or spent a watched utxo
                 ServeStore *serve;    // NULL unless this pass feeds the serve cache
                 uint8_t watch[IDX_MAX_WATCH][20]; int nwatch; } FoldCtx;
static void fold_load_watch(FoldCtx *fc) {
    fc->nwatch = fc->db ? idx_db_watch_list(fc->db, fc->watch, IDX_MAX_WATCH) : 0;
}
static void tx_cb(void *u, const IdxTx *tx, uint32_t txindex) {
    FoldCtx *fc = (FoldCtx *)u;
    int r = idx_adapt_tx(fc->s, tx, txindex);
    if (r == 1) fc->folded++;
    // wallet watch: record outputs paying a watched P2PKH, mark spends of known
    // utxos. Only from the block AFTER the watch is registered — register (and
    // the wallet address) before funding it.
    if (fc->nwatch && fc->db) {
        for (int o = 0; o < tx->n_out; o++) {
            uint8_t h160[20], type;
            if (!idx_script_payee(tx->outs[o].spk, tx->outs[o].spklen, h160, &type) || type != 0) continue;
            for (int w = 0; w < fc->nwatch; w++)
                if (!memcmp(h160, fc->watch[w], 20)) {
                    idx_db_utxo_put(fc->db, tx->txid, tx->outs[o].vout, h160,
                                    tx->outs[o].value, fc->height);
                    fc->wallet_touched = 1;
                    break;
                }
        }
        for (int i = 0; i < tx->n_in; i++) {      // prevout = txid(32) + vout(4 LE)
            const uint8_t *po = tx->ins[i].prevout;
            uint32_t vout = (uint32_t)po[32] | (uint32_t)po[33] << 8 |
                            (uint32_t)po[34] << 16 | (uint32_t)po[35] << 24;
            if (vout == 0xFFFFFFFF) continue;     // coinbase
            if (idx_db_utxo_spend(fc->db, po, vout, fc->height) > 0)
                fc->wallet_touched = 1;
        }
    }
    // relay mempool: this tx just confirmed — drop it (and anything that now
    // double-spends it) from the pool. No-op while the pool is empty (fast path).
    mempool_on_confirmed_tx(tx->txid, tx);
}

// Connect one block at `height`: oracle → begin_block → parse+fold → record/persist.
static int connect_block(FoldCtx *fc, int64_t height, const uint8_t *raw, size_t len) {
    IdxBlockMeta meta;
    int64_t mtp; uint64_t rate;
    fc->height = height;
    oracle_for_height(fc->oracle, height, &mtp, &rate);
    int64_t lapses_before = fc->s->ev[SM_EV_LAPSE];
    sm_begin_block(fc->s, height, mtp, rate);
    int folded_before = fc->folded;
    fc->wallet_touched = 0;
    if (!idx_parse_block(raw, len, &meta, tx_cb, fc)) { fprintf(stderr, "block %lld malformed\n", (long long)height); return 0; }
    oracle_record(fc->oracle, height, meta.time, meta.coinbase_out_total, meta.block_bytes);
    if (fc->db) {
        idx_db_block_put(fc->db, height, meta.block_hash, meta.time, meta.coinbase_out_total, meta.block_bytes, meta.bits);
        // reorg-replay substrate: keep the raw bytes of carrier blocks AND
        // wallet-touching blocks — replay must re-see wallet spends too, or a
        // rollback would leave spent outputs looking unspent (they were, once:
        // the pre-repair builds' resurrected-balance bug).
        if (fc->folded > folded_before || fc->wallet_touched)
            idx_db_rawblock_put(fc->db, height, raw, len);
        // serve cache (NODE_NETWORK_LIMITED): every header + a rolling 288-block
        // window, in its own aux db. len >= 80 guaranteed (parse succeeded).
        if (fc->serve) serve_store_put(fc->serve, height, meta.block_hash, raw, raw, len, height);
        // epochs projection: ownership can only change in a block that folded a
        // carrier tx or fired a lapse — diff those blocks against recorded history
        if (fc->folded > folded_before || fc->s->ev[SM_EV_LAPSE] != lapses_before)
            idx_db_epochs_update(fc->db, fc->s, height);
        idx_db_save_sync(fc->db, height, meta.block_hash);
        idx_test_crash_point(height);
    }
    return 1;
}

// idx-03 test-only fault injection: IDX_TEST_CRASH_AT=<height> makes the process
// SIGKILL itself right after block <height>'s autocommitted rows land and BEFORE the
// batch projection — the exact crash window recovery has to heal. Unset = no-op
// (one getenv per process).
void idx_test_crash_point(int64_t height) {
    const char *e = getenv("IDX_TEST_CRASH_AT");   // one getenv per block: negligible
    if (!e || !*e) return;
    int64_t at = strtoll(e, NULL, 10);
    if (at >= 0 && height == at) { kill(getpid(), SIGKILL); _exit(137); }
}

// idx-03 crash recovery, shared by sync and index. The fold state loads from the
// projection (proj_height); per-block rows (blocks/raw_blocks/epochs/utxos/meta
// cursor) autocommit ahead of it. If the cursor is ahead of the projection, rewind
// the cursor to it AND drop every height-keyed row above it — re-folding the gap
// re-derives them, and if the chain moved while we were down, stale rows from the
// abandoned branch (utxo spend marks, epochs, block hashes the fork search would
// match) must not survive. A cursor with NO projection at all (crash before the
// first batch committed) rewinds to `start` when the projection is empty.
// Returns 1 if it rewound (caller must also roll its oracle back to *height+1 and
// prune any serve cache above *height), 0 if the db was consistent.
int idx_sync_recover(sqlite3 *db, int64_t start, const uint8_t start_hash[32],
                     int64_t *height, uint8_t tip[32]) {
    int64_t proj_h = idx_db_projected_height(db), to;
    if (proj_h < 0) {
        int64_t rows = 0; sqlite3_stmt *st;
        if (sqlite3_prepare_v2(db, "SELECT (SELECT COUNT(*) FROM names)+(SELECT COUNT(*) FROM commits)+(SELECT COUNT(*) FROM muts)", -1, &st, NULL) == SQLITE_OK) {
            if (sqlite3_step(st) == SQLITE_ROW) rows = sqlite3_column_int64(st, 0);
            sqlite3_finalize(st);
        }
        if (rows || *height <= start) return 0;   // legacy pre-sentinel db: trust it
        to = start;
    } else if (proj_h < *height) to = proj_h < start ? start : proj_h;
    else return 0;
    fprintf(stderr, "recovery: sync height %lld is ahead of the projection %lld (prior crash) — resuming from %lld\n",
            (long long)*height, (long long)proj_h, (long long)to);
    idx_db_block_prune_above(db, to);
    *height = to;
    if (to <= start || !idx_db_block_get(db, to, tip)) memcpy(tip, start_hash, 32);
    idx_db_save_sync(db, to, tip);
    return 1;
}

// ── reorg rollback ────────────────────────────────────────────────────────────
static int rollback_replay_cb(void *u, int64_t height, const uint8_t *raw, size_t len) {
    FoldCtx *fc = (FoldCtx *)u;
    IdxBlockMeta meta; int64_t mtp; uint64_t rate;
    fc->height = height;
    oracle_for_height(fc->oracle, height, &mtp, &rate);
    int64_t lapses_before = fc->s->ev[SM_EV_LAPSE];
    sm_begin_block(fc->s, height, mtp, rate);
    int folded_before = fc->folded;
    if (!idx_parse_block(raw, len, &meta, tx_cb, fc)) return 0;
    // re-derive epoch rows (height-bounded ⇒ idempotent over what already stands).
    // Replay walks carrier blocks only, so a lapse between them lands at the NEXT
    // carrier block's height — after a refold wipe, lapse edges carry that
    // granularity (the live fold, which sees every block, records them exactly).
    if (fc->db && (fc->folded > folded_before || fc->s->ev[SM_EV_LAPSE] != lapses_before))
        idx_db_epochs_update(fc->db, fc->s, height);
    return 1;
}
// Roll the fold back to `to_height` (kept): prune every height-keyed projection
// above it, drop its oracle rows, and rebuild the state from local data.
// idx-13 (PROPOSAL): the rebuild is the idx-12 exact replay — every blocks row
// <= to_height gets the sm_begin_block the live fold gave it (raw rows replay
// their txs), so expiry pruning, lease lapses, lapse epochs and lapse-stamped
// muts land at the live heights. The old carrier-only replay moved them to the
// next carrier block (or dropped them after the last one), so a reorg could
// leave a node's state diverged from a fresh sync of the winning branch.
// Replaces *s (old state freed). Returns 1, 0 on failure.
static int refold_replay_exact(SmState **s, sqlite3 *db, OracleFeed *oracle,
                               int64_t activation, int64_t to_height, int use_ckpt);
// Test-only fault hook: called inside the rollback transaction just before
// COMMIT. NULL in every production path.
void (*idx_sync_rollback_test_hook)(sqlite3 *db, int64_t to_height) = NULL;
// The prune (blocks/raw_blocks/checkpoints above to_height), the replay's db
// side effects (utxo/epoch rows) and the projection + proj_height run in ONE
// BEGIN IMMEDIATE..COMMIT: a crash or failure anywhere in between leaves the
// pre-reorg db exactly as it was (blocks, projection and cursor still agree),
// never a pruned chain under a stale projection. oracle_rollback is in-RAM
// only; on failure the oracle and *s are reloaded from the untouched db, so the
// caller sees the committed pre-rollback state. Nested inside a caller's open
// transaction it uses a SAVEPOINT instead.
int idx_sync_rollback(SmState **s, sqlite3 *db, OracleFeed *oracle,
                      int64_t activation, int64_t to_height) {
    int outer = sqlite3_get_autocommit(db) != 0;
    if (sqlite3_exec(db, outer ? "BEGIN IMMEDIATE" : "SAVEPOINT idx_rollback", NULL, NULL, NULL) != SQLITE_OK)
        return 0;
    int ok = refold_replay_exact(s, db, oracle, activation, to_height, 1);
    if (ok && idx_sync_rollback_test_hook) idx_sync_rollback_test_hook(db, to_height);
    if (ok) ok = sqlite3_exec(db, outer ? "COMMIT" : "RELEASE idx_rollback", NULL, NULL, NULL) == SQLITE_OK;
    if (ok) return 1;
    if (outer) sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    else { sqlite3_exec(db, "ROLLBACK TO idx_rollback", NULL, NULL, NULL); sqlite3_exec(db, "RELEASE idx_rollback", NULL, NULL, NULL); }
    // restore RAM from the unchanged db
    uint8_t mag[2] = { 0, 0 };
    if (*s) memcpy(mag, (*s)->onchain_magic, 2);
    sm_free(*s);
    *s = sm_new((uint64_t)activation);
    if (*s) {
        memcpy((*s)->onchain_magic, mag, 2);
        idx_db_load_state(db, *s);
        int64_t ph = idx_db_projected_height(db);
        if (ph >= 0) (*s)->cur_height = ph;
    }
    oracle_rollback(oracle, INT64_MIN);
    idx_db_oracle_warm(db, oracle);
    return 0;
}

// ── file helpers ──────────────────────────────────────────────────────────────
// Sanity bound on anything we slurp whole (block files, raw or hex-text). Far
// above any real Doge block even hex-doubled; keeps a bogus/huge path from
// turning into a blind malloc.
#define IDX_READ_FILE_MAX  (256u * 1024 * 1024)
static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb"); if (!f) return NULL;
    // ftell returns -1 on an unseekable stream or a directory; unchecked, the
    // (size_t)n + 1 below wraps to malloc(0) and fread is then asked for
    // SIZE_MAX bytes into it. Check every seek/tell and bail cleanly.
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0 || (unsigned long)n > IDX_READ_FILE_MAX) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc((size_t)n + 1); if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
    fclose(f); buf[n] = 0; *len = (size_t)n; return buf;
}
// Accept a hex-text or raw-binary block file. Returns malloc'd bytes.
static uint8_t *load_block(const char *path, size_t *len) {
    size_t n; uint8_t *raw = read_file(path, &n); if (!raw) return NULL;
    int ishex = (n >= 160) && (n % 2 == 0);
    for (size_t i = 0; i < n && ishex; i++) { char c = (char)raw[i]; if (!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F')||c=='\n'||c=='\r'||c==' ')) ishex = 0; }
    if (!ishex) { *len = n; return raw; }
    // strip whitespace + hex-decode
    char *h = (char *)raw; size_t hn = 0; for (size_t i = 0; i < n; i++) { char c = h[i]; if (c=='\n'||c=='\r'||c==' '||c=='\t') continue; h[hn++] = c; }
    uint8_t *out = malloc(hn / 2 + 1); size_t ol;
    if (!idx_hex_to_bytes(h, out, hn / 2, &ol)) { free(raw); free(out); return NULL; }
    free(raw); *len = ol; return out;
}

// ── commands ──────────────────────────────────────────────────────────────────
static void print_digest(SmState *s) {
    uint8_t d[32], e[32]; char hd[65], he[65];
    sm_state_digest(s, d); sm_state_ecmh(s, e);
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { hd[2*i] = H[d[i]>>4]; hd[2*i+1] = H[d[i]&15]; he[2*i] = H[e[i]>>4]; he[2*i+1] = H[e[i]&15]; }
    hd[64] = he[64] = 0;
    printf("state_digest %s\nstate_ecmh   %s\n", hd, he);
}

static int cmd_index(int argc, char **argv) {
    // index <db> <activation> <blockfile> [blockfile...] [--coin NAME]  (heights start at 0)
    const char *coin = take_coin_opt(&argc, argv);
    if (coin && !coin_by_name(coin)) { fprintf(stderr, "unknown coin %s\n", coin); return 2; }
    if (argc < 5) { fprintf(stderr, "usage: index <db> <activation_height> <blockfile> [more...] [--coin NAME]\n"); return 2; }
    const char *dbpath = argv[2]; int64_t activation = strtoll(argv[3], NULL, 10);
    sqlite3 *db = idx_db_open(dbpath); if (!db) { fprintf(stderr, "cannot open %s\n", dbpath); return 1; }
    idx_db_set_activation(db, activation);
    SmState *s = sm_new((uint64_t)activation);
    int rm = resolve_magic(s, db, coin, 0, "index");
    if (!rm) { sm_free(s); idx_db_close(db); return 1; }
    if (rm == 1) idx_db_set_onchain_magic(db, s->onchain_magic);   // never persist an inference
    OracleFeed *oracle = oracle_new();
    idx_db_load_state(db, s); idx_db_oracle_warm(db, oracle); oracle_set_subsidy(oracle, idx_db_get_subsidy(db, SUBSIDY_10K));
    int64_t height = 0; uint8_t tip[32];
    if (idx_db_load_sync(db, &height, tip)) {           // resume after stored tip
        static const uint8_t z[32];
        if (idx_sync_recover(db, -1, z, &height, tip)) oracle_rollback(oracle, height + 1);
        height++;
    }
    else idx_db_epochs_mark(db, 0);                     // fresh DB: coverage from genesis
    FoldCtx fc = { .s = s, .db = db, .oracle = oracle };
    fold_load_watch(&fc);
    for (int i = 4; i < argc; i++, height++) {
        size_t len; uint8_t *raw = load_block(argv[i], &len);
        if (!raw) { fprintf(stderr, "cannot read block %s\n", argv[i]); idx_db_close(db); return 1; }
        if (!connect_block(&fc, height, raw, len)) { free(raw); idx_db_close(db); return 1; }
        free(raw);
    }
    idx_db_project(db, s);
    printf("indexed to height %lld (%d action-txs folded)\n", (long long)(height - 1), fc.folded);
    print_digest(s);
    oracle_free(oracle); sm_free(s); idx_db_close(db);
    return 0;
}

static SmState *open_state(const char *dbpath, const char *coin, sqlite3 **db_out) {
    sqlite3 *db = idx_db_open(dbpath); if (!db) return NULL;
    SmState *s = sm_new((uint64_t)idx_db_get_activation(db, 0));
    if (!resolve_magic(s, db, coin, 0, "open")) { sm_free(s); idx_db_close(db); return NULL; }
    idx_db_load_state(db, s);
    *db_out = db; return s;
}

static void hex20(const uint8_t *b, char out[41]) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 20; i++) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 15]; }
    out[40] = 0;
}
static void print_ts(const char *label, int64_t t) {
    char when[32] = "";
    if (t > 0) { time_t tt = (time_t)t; struct tm tm; gmtime_r(&tt, &tm); strftime(when, sizeof when, "%Y-%m-%d %H:%M", &tm); }
    printf("  %-15s %lld  (%s)\n", label, (long long)t, when);
}
static int cmd_resolve(int argc, char **argv) {
    (void)take_coin_opt(&argc, argv);   // accepted for symmetry; resolve reads projected rows only
    if (argc < 4) { fprintf(stderr, "usage: resolve <db> <name> [--coin NAME]\n"); return 2; }
    sqlite3 *db = idx_db_open(argv[2]); if (!db) { fprintf(stderr, "cannot open db\n"); return 1; }
    IdxNameRow r;
    if (idx_db_name_row(db, argv[3], &r)) {
        static const char *names[] = { "OWNED", "LISTED", "OFFERED", "RESERVED" };
        char h[41]; hex20(r.owner, h);
        printf("%s  state=%s\n  %-15s %s (type %u)\n", argv[3],
               (r.st >= 0 && r.st < 4) ? names[r.st] : "?", "owner", h, r.owner_type);
        print_ts("lease_expiry", r.lease_expiry);
        if (r.st != SM_OWNED) {                                  // §3.7 market fields
            hex20(r.seller, h);
            printf("  %-15s %s (type %u)\n", "seller", h, r.seller_type);
            printf("  %-15s %llu koinu\n", "price", (unsigned long long)r.price);
            print_ts("offer_expiry", r.offer_expiry);
            if (r.st == SM_OFFERED || r.st == SM_RESERVED) {
                hex20(r.buyer, h);
                printf("  %-15s %s\n", r.st == SM_OFFERED ? "buyer (SELL_TO)" : "reserver", h);
            }
            if (r.st == SM_RESERVED) {
                printf("  %-15s burn=%llu pay=%llu (credited at settle)\n", "deposit legs",
                       (unsigned long long)r.burn_leg, (unsigned long long)r.pay_leg);
                printf("  %-15s %llu koinu\n", "remainder", (unsigned long long)(r.price - r.burn_leg - r.pay_leg));
                print_ts("reserve_expiry", r.reserve_expiry);
            }
        }
    } else printf("%s  (unowned)\n", argv[3]);
    idx_db_close(db); return 0;
}

static void owned_cb(void *u, const char *name, int64_t lease, int st) { (void)u; (void)st; printf("  %-20s lease_expiry=%lld\n", name, (long long)lease); }
static int cmd_owned(int argc, char **argv) {
    const char *coin = take_coin_opt(&argc, argv);
    if (argc < 4) { fprintf(stderr, "usage: owned <db> <hash160hex> [--coin NAME]\n"); return 2; }
    sqlite3 *db; SmState *s = open_state(argv[2], coin, &db); if (!s) { fprintf(stderr, "cannot open db\n"); return 1; }
    int n = idx_db_owned(db, argv[3], owned_cb, NULL);
    if (!n) printf("  (no names)\n");
    sm_free(s); idx_db_close(db); return 0;
}

static int cmd_digest(int argc, char **argv) {
    const char *coin = take_coin_opt(&argc, argv);
    if (argc < 3) { fprintf(stderr, "usage: digest <db> [--coin NAME]\n"); return 2; }
    sqlite3 *db; SmState *s = open_state(argv[2], coin, &db); if (!s) { fprintf(stderr, "cannot open db\n"); return 1; }
    int64_t h = 0; uint8_t tip[32];
    if (idx_db_load_sync(db, &h, tip)) {
        printf("height %lld\n", (long long)h);
        OracleFeed *o = oracle_new();                     // live §3.4 rate for the NEXT block
        idx_db_oracle_warm(db, o);
        int64_t mtp; uint64_t rate;
        oracle_for_height(o, h + 1, &mtp, &rate);
        printf("rate   %llu koinu/name-quantum (%lld koinu buys 1 name-year)\n",
               (unsigned long long)rate, (long long)(13 * (int64_t)rate));
        oracle_free(o);
    }
    print_digest(s);
    sm_free(s); idx_db_close(db); return 0;
}

// refold <db> — rebuild the fold state from LOCAL data under the current engine
// rules: the oracle re-warmed from the blocks table, the state replayed from the
// stored raw carrier blocks. The consensus-change tool: after a rule re-pin the
// projection is rebuilt in seconds without touching the network.
// idx-10: refold replays raw_blocks only. A height that commits / muts / an
// owned epoch row points at but raw_blocks lacks would silently vanish from the
// rebuilt state. Count them (lapse epochs, owner NULL, are excluded: the live
// fold records those at non-carrier heights and refold re-derives them; so are
// commits already expired at the tip, which no later claim can use).
// Returns the number missing (-1 on query error); first few into `first`.
static long long refold_missing_heights(sqlite3 *db, char *first, size_t cap) {
    const char *q =
        "SELECT h FROM (SELECT commit_height AS h FROM commits"
        // expired, unclaimed commits are dead state a refold prunes anyway
        " WHERE commit_time + ?1 >= coalesce((SELECT max(time) FROM blocks), 0)"
        " UNION SELECT start_height FROM epochs WHERE owner IS NOT NULL"
        // idx-12: a mut stamped by a lapse at a non-carrier height is re-derived
        // exactly (refold now runs the per-block preblock on every blocks row)
        " UNION SELECT height FROM muts WHERE height NOT IN"
        "   (SELECT start_height FROM epochs WHERE owner IS NULL)) WHERE h IS NOT NULL"
        " AND h NOT IN (SELECT height FROM raw_blocks) ORDER BY h";
    sqlite3_stmt *st = NULL; long long n = 0; size_t off = 0; first[0] = 0;
    if (sqlite3_prepare_v2(db, q, -1, &st, NULL) != SQLITE_OK) return -1;
    // +7200 s: max(block time) can run ahead of the MTP the expiry rule uses
    sqlite3_bind_int64(st, 1, (sqlite3_int64)SM_COMMIT_EXPIRY + 7200);
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (n < 8 && off + 24 < cap)
            off += (size_t)snprintf(first + off, cap - off, "%s%lld", n ? "," : "", (long long)sqlite3_column_int64(st, 0));
        n++;
    }
    sqlite3_finalize(st);
    return n;
}
// idx-12: exact refold replay. The live fold calls sm_begin_block (→ sm_preblock:
// lease lapses + COMMIT_EXPIRY pruning, both keyed on MTP) on EVERY connected
// block; the reorg replay (idx_sync_rollback) only sees stored raw blocks, so
// pruning and lapses land at the next carrier height. Refold walks every blocks
// row ≤ to_height instead: raw rows replay through rollback_replay_cb exactly as
// before; non-raw rows get the same begin_block the live fold gave them (a block
// with no carrier tx folds nothing else). MTP comes from the blocks table — the
// same rows idx_db_oracle_warm feeds the oracle — via an 11-deep ring (O(1) per
// height; oracle_for_height's rate scan is O(n) and the rate is unused by
// preblock). Lapse epochs are then recorded at the exact live height.
// Live sync and idx_sync_rollback are unchanged. Returns 1, 0 on failure.
static int refold_replay_exact(SmState **s, sqlite3 *db, OracleFeed *oracle,
                               int64_t activation, int64_t to_height, int use_ckpt) {
    idx_db_block_prune_above(db, to_height);
    if (!idx_db_ckpt_prune_above(db, to_height)) return 0;
    oracle_rollback(oracle, to_height + 1);
    uint8_t mag[2] = { 0, 0 };
    if (*s) memcpy(mag, (*s)->onchain_magic, 2);
    sm_free(*s);
    *s = sm_new((uint64_t)activation);
    memcpy((*s)->onchain_magic, mag, 2);
    // checkpoint: start from the newest stored state <= to_height (or from
    // activation when there is none). Heights <= base were folded into it.
    int64_t base = use_ckpt ? idx_db_ckpt_load(db, to_height, *s) : -1;
    if (base < 0) base = INT64_MIN;
    FoldCtx fc = { .s = *s, .db = db, .oracle = oracle };
    fold_load_watch(&fc);
    sqlite3_stmt *st = NULL;
    int64_t ring[11]; int nr = 0, ok = 1;
    if (base != INT64_MIN) {                 // MTP ring = the 11 blocks-row times <= base
        if (sqlite3_prepare_v2(db, "SELECT time FROM (SELECT height,time FROM blocks WHERE height<=?1"
                                   " AND time IS NOT NULL ORDER BY height DESC LIMIT 11) ORDER BY height",
                               -1, &st, NULL) != SQLITE_OK) return 0;
        sqlite3_bind_int64(st, 1, base);
        while (sqlite3_step(st) == SQLITE_ROW) ring[nr++] = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st); st = NULL;
    }
    // raw rows without a blocks row are still replayed (ordered merge via UNION)
    if (sqlite3_prepare_v2(db,
            "SELECT u.h, b.time, r.raw FROM (SELECT height AS h FROM blocks WHERE height<=?1 AND height>?2"
            " UNION SELECT height FROM raw_blocks WHERE height<=?1 AND height>?2) u"
            " LEFT JOIN blocks b ON b.height=u.h LEFT JOIN raw_blocks r ON r.height=u.h ORDER BY u.h",
            -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int64(st, 1, to_height);
    sqlite3_bind_int64(st, 2, base);
    while (ok && sqlite3_step(st) == SQLITE_ROW) {
        int64_t h = sqlite3_column_int64(st, 0);
        if (sqlite3_column_type(st, 2) != SQLITE_NULL) {
            ok = rollback_replay_cb(&fc, h, (const uint8_t *)sqlite3_column_blob(st, 2),
                                    (size_t)sqlite3_column_bytes(st, 2));
        } else {
            int64_t mtp = sm_mtp(ring, nr);
            int64_t lapses_before = (*s)->ev[SM_EV_LAPSE];
            sm_begin_block(*s, h, mtp, (*s)->cur_rate);   // preblock is rate-free
            if ((*s)->ev[SM_EV_LAPSE] != lapses_before) idx_db_epochs_update(db, *s, h);
        }
        if (sqlite3_column_type(st, 1) != SQLITE_NULL) {   // oracle feed = blocks rows only
            if (nr == 11) { memmove(ring, ring + 1, 10 * sizeof *ring); nr = 10; }
            ring[nr++] = sqlite3_column_int64(st, 1);
        }
    }
    sqlite3_finalize(st);
    if (!ok) return 0;
    (*s)->cur_height = to_height;
    return idx_db_project(db, *s);
}
static int cmd_refold(int argc, char **argv) {
    int force = 0;
    const char *coin = take_coin_opt(&argc, argv);
    if (coin && !coin_by_name(coin)) { fprintf(stderr, "unknown coin %s\n", coin); return 2; }
    for (int i = 2; i < argc; i++)
        if (!strcmp(argv[i], "--force")) { for (int j = i; j + 1 <= argc; j++) argv[j] = argv[j + 1]; argc--; i--; force = 1; }
    if (argc < 3) { fprintf(stderr, "usage: refold <db> [--coin NAME] [--force]\n"); return 2; }
    sqlite3 *db = idx_db_open(argv[2]); if (!db) { fprintf(stderr, "cannot open db\n"); return 1; }
    int64_t height = 0; uint8_t tip[32];
    if (!idx_db_load_sync(db, &height, tip)) { fprintf(stderr, "db has no sync state\n"); idx_db_close(db); return 1; }
    {
        char first[256]; long long miss = refold_missing_heights(db, first, sizeof first);
        if (miss < 0) { fprintf(stderr, "refold: REFUSED: cannot check raw_blocks coverage\n"); idx_db_close(db); return 1; }
        if (miss > 0 && !force) {
            fprintf(stderr, "refold: REFUSED: %lld height(s) referenced by commits/epochs/muts are missing from raw_blocks"
                            " (first: %s%s) — a refold would silently drop that state. Nothing changed."
                            " Re-sync those blocks, or pass --force to refold anyway.\n", miss, first, miss > 8 ? ",..." : "");
            idx_db_close(db); return 1;
        }
        if (miss > 0)
            fprintf(stderr, "refold: WARNING (--force): %lld referenced height(s) missing from raw_blocks (first: %s%s);"
                            " the rebuilt state will be SMALLER than the recorded one\n", miss, first, miss > 8 ? ",..." : "");
    }
    int64_t activation = idx_db_get_activation(db, 0);
    SmState *s = sm_new((uint64_t)activation);
    int rm = resolve_magic(s, db, coin, 1, "refold");
    if (!rm) { fprintf(stderr, "refold: nothing changed\n"); sm_free(s); idx_db_close(db); return 1; }
    if (rm == 1) idx_db_set_onchain_magic(db, s->onchain_magic);   // never persist an inference
    OracleFeed *oracle = oracle_new();
    idx_db_oracle_warm(db, oracle); oracle_set_subsidy(oracle, idx_db_get_subsidy(db, SUBSIDY_10K));
    // refold = the rules may have changed: recorded epochs could be wrong under the
    // new fold. Wipe and re-derive the whole history from the raw carrier blocks
    // (complete coverage — mark from genesis; idx-12: every blocks row gets its
    // preblock, so expiry pruning and lapse edges land at the exact live heights).
    idx_db_epochs_wipe(db);
    idx_db_epochs_mark(db, 0);
    idx_db_ckpt_wipe(db);                    // rules may have changed: old states are void
    if (!refold_replay_exact(&s, db, oracle, activation, height, 0)) {
        fprintf(stderr, "refold failed\n");
        oracle_free(oracle); sm_free(s); idx_db_close(db); return 1;
    }
    printf("refolded to height %lld (activation %lld)\n", (long long)height, (long long)activation);
    print_digest(s);
    oracle_free(oracle); sm_free(s); idx_db_close(db);
    return 0;
}

static int cmd_watch(int argc, char **argv) {
    // watch <db> <address|hash160hex> — register a wallet address for UTXO
    // tracking. Takes effect from the NEXT synced block: register before funding.
    if (argc < 4) { fprintf(stderr, "usage: watch <db> <address|hash160hex>\n"); return 2; }
    uint8_t h160[20];
    if (strlen(argv[3]) == 40) {
        size_t n; if (!idx_hex_to_bytes(argv[3], h160, 20, &n) || n != 20) { fprintf(stderr, "bad hash160 hex\n"); return 1; }
    } else {
        uint8_t ver, payload[32]; size_t plen;
        if (!idx_b58check_decode(argv[3], &ver, payload, sizeof payload, &plen) || plen != 20) {
            fprintf(stderr, "bad address (base58check)\n"); return 1;
        }
        memcpy(h160, payload, 20);
    }
    sqlite3 *db = idx_db_open(argv[2]); if (!db) { fprintf(stderr, "cannot open db\n"); return 1; }
    idx_db_watch_add(db, h160);
    char hh[41]; static const char *H = "0123456789abcdef";
    for (int i = 0; i < 20; i++) { hh[2*i] = H[h160[i]>>4]; hh[2*i+1] = H[h160[i]&15]; } hh[40] = 0;
    printf("watching %s (hash160 %s) — utxos recorded from the next synced block\n", argv[3], hh);
    idx_db_close(db); return 0;
}

// ── minimal Dogecoin P2P (self-contained; framing on protocol-sm SHA-256) ─────
static void ignore_sigpipe(void) {
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
}
static void sock_nosigpipe(int fd) {
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
}
static int write_all(int fd, const uint8_t *b, size_t n) {
    size_t off = 0;
    while (off < n) {
#ifdef MSG_NOSIGNAL
        ssize_t w = send(fd, b + off, n - off, MSG_NOSIGNAL);
#else
        ssize_t w = write(fd, b + off, n - off);
#endif
        if (w <= 0) { if (w < 0 && errno == EINTR) continue; return 0; }
        off += (size_t)w;
    }
    return 1;
}
static int net_send(int fd, const uint8_t magic[4], const char *cmd, const uint8_t *payload, uint32_t len) {
    uint8_t hdr[24]; memset(hdr, 0, 24); memcpy(hdr, magic, 4);
    strncpy((char *)hdr + 4, cmd, 12);
    hdr[16] = (uint8_t)len; hdr[17] = (uint8_t)(len >> 8); hdr[18] = (uint8_t)(len >> 16); hdr[19] = (uint8_t)(len >> 24);
    uint8_t ck[32]; idx_sha256d(payload ? payload : (const uint8_t *)"", len, ck); memcpy(hdr + 20, ck, 4);
    // one buffered write: a large addr payload must not tear across two write()s
    // on a peer that reads a frame at a time (and write_all handles partials)
    if (!write_all(fd, hdr, 24)) return 0;
    if (len && !write_all(fd, payload, len)) return 0;
    return 1;
}
// Wait up to timeout_ms for `ev` on fd in short slices, giving up early when
// the embedding host sets idx_sync_stop: a stop must not sit behind a 15 s
// peer timeout. Local timing only; nothing on the wire changes.
static int stop_poll(int fd, short ev, int timeout_ms) {
    int left = timeout_ms;
    while (left > 0 && !idx_sync_stop) {
        int slice = left < 100 ? left : 100;
        struct pollfd p = { fd, ev, 0 };
        int pr = poll(&p, 1, slice);
        if (pr > 0) return 1;
        if (pr < 0 && errno != EINTR) return 0;
        left -= slice;
    }
    return 0;
}
// ── receive deadlines (slow-loris bounds) ─────────────────────────────────────
// net_recv's timeout_ms is an INACTIVITY timeout: it restarts on every message
// in the callers' loops, and on every read() inside read_n. A peer that is
// never silent — ping/addr/inv chatter, or one frame trickled a byte at a time
// — never trips it, so a wait for a specific reply (blocks after getdata,
// headers after getheaders, inv after getblocks, version/verack) could last
// forever. Each such wait also carries an absolute CLOCK_MONOTONIC deadline
// (ms; 0 = none): the inactivity timeout still catches a dead peer fast, the
// deadline catches a busy-but-useless one. Overridable at build time only for
// the regression test (indexerd-stalltest); not a runtime knob.
//   batch: ≤600 blocks per getdata, Doge/Pepe blocks ≤1 MB, typically tens of
//          KB. 600 s = 1 s/block for a full batch. Blocks connect as they
//          arrive, so a peer cut at the deadline loses no folded work — the
//          next pass resumes from the new tip. (The old honest bound was only
//          "≤15 s between messages", i.e. none.)
//   weigh: one branch_outweighs (all pages). Its drain may first have to
//          swallow the rest of the in-flight batch backlog; 300 s covers that
//          plus ≥1 headers page (2000 headers ≈ 160 KB, ≲ a few MB with
//          AuxPoW). A real reorg is short (forks below the 288 raw floor are
//          refused anyway), so it outweighs on page one.
//   round: the existing 10 s "no inv → idle round" wait after getblocks, now
//          held across interleaved ping/addr instead of restarting per message.
//   shake: whole sync-pass version/verack exchange (was ≤10 msgs × 8 s
//          inactivity, unbounded with a trickled frame). Two RTTs on any honest
//          link. (The serve plane's outbound handshake is already multiplexed
//          with its own SERVE_DIAL_SHAKE_S budget.)
#ifndef IDX_SYNC_BATCH_DEADLINE_S
#define IDX_SYNC_BATCH_DEADLINE_S 600
#endif
#ifndef IDX_SYNC_WEIGH_DEADLINE_S
#define IDX_SYNC_WEIGH_DEADLINE_S 300
#endif
#ifndef IDX_SYNC_ROUND_MS
#define IDX_SYNC_ROUND_MS 10000
#endif
#ifndef IDX_NET_SHAKE_DEADLINE_MS
#define IDX_NET_SHAKE_DEADLINE_MS 20000
#endif
static int64_t mono_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static int dl_passed(int64_t dl) { return dl && mono_ms() >= dl; }
static int read_n(int fd, uint8_t *buf, size_t n, int timeout_ms, int64_t dl) {
    size_t got = 0;
    while (got < n) {
        int wait = timeout_ms;
        if (dl) {                                    // clamp to the deadline
            int64_t left = dl - mono_ms(); if (left <= 0) return 0;
            if (left < wait) wait = (int)left;
        }
        if (!stop_poll(fd, POLLIN, wait)) return 0;
        ssize_t r = read(fd, buf + got, n - got); if (r <= 0) return 0; got += (size_t)r;
    }
    return 1;
}
// 1 = message, 0 = dead/timeout/deadline (dl_passed(dl) tells which), -1 = bad frame
static int net_recv_dl(int fd, const uint8_t magic[4], char cmd_out[13], uint8_t **payload, uint32_t *len,
                       int timeout_ms, int64_t dl) {
    uint8_t hdr[24]; if (!read_n(fd, hdr, 24, timeout_ms, dl)) return 0;
    if (memcmp(hdr, magic, 4) != 0) return -1;
    memcpy(cmd_out, hdr + 4, 12); cmd_out[12] = 0;
    uint32_t l = (uint32_t)hdr[16] | (uint32_t)hdr[17] << 8 | (uint32_t)hdr[18] << 16 | (uint32_t)hdr[19] << 24;
    if (l > IDX_MSG_MAX) return -1;
    uint8_t *buf = malloc(l ? l : 1);
    if (l && !read_n(fd, buf, l, timeout_ms, dl)) { free(buf); return 0; }
    uint8_t ck[32]; idx_sha256d(l ? buf : (const uint8_t *)"", l, ck);
    if (memcmp(hdr + 20, ck, 4) != 0) { free(buf); return -1; }
    *payload = buf; *len = l; return 1;
}
// Resolve `host` (name or literal) and connect to the first address that
// answers — a multi-A DNS seed's record set IS a failover list, so walk it.
// Each attempt is bounded (non-blocking connect + poll): a dead candidate must
// cost seconds, not a kernel-default 75 s stall per address.
static int net_connect(const char *host, uint16_t port) {
    char ps[8]; snprintf(ps, sizeof ps, "%u", port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, ps, &hints, &res) != 0 || !res) return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai && !idx_sync_stop; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        sock_nosigpipe(fd);
        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        int r = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (r != 0 && errno == EINPROGRESS) {
            int err = 0; socklen_t el = sizeof err;
            if (stop_poll(fd, POLLOUT, 5000) &&
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0) r = 0;
        }
        if (r == 0) { fcntl(fd, F_SETFL, fl); break; }
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}
// The connected socket's remote address as "ip:port" text (the concrete peer
// behind a seed name — what the last-good cache must remember).
static void net_peer_str(int fd, char *out, size_t cap) {
    struct sockaddr_storage ss; socklen_t sl = sizeof ss;
    char ip[INET6_ADDRSTRLEN] = "?"; unsigned port = 0;
    if (getpeername(fd, (struct sockaddr *)&ss, &sl) == 0) {
        if (ss.ss_family == AF_INET) {
            struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
            inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof ip); port = ntohs(s4->sin_port);
        } else if (ss.ss_family == AF_INET6) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
            inet_ntop(AF_INET6, &s6->sin6_addr, ip, sizeof ip); port = ntohs(s6->sin6_port);
        }
    }
    snprintf(out, cap, "%s:%u", ip, port);
}
// Resolve a dial target to its first numeric address — no connect. Lets the
// per-host dedup and the serve-live check see THROUGH a hostname before paying
// a TCP dial + handshake to learn what it resolves to. 1 ok (out = numeric ip
// text), 0 = resolution failed (caller just proceeds to dial and finds out).
static int net_resolve_str(const char *host, char *out, size_t cap) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return 0;
    int ok = 0;
    for (struct addrinfo *ai = res; ai && !ok; ai = ai->ai_next) {
        if (ai->ai_family == AF_INET) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)ai->ai_addr)->sin_addr,
                      out, (socklen_t)cap); ok = 1;
        } else if (ai->ai_family == AF_INET6) {
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr,
                      out, (socklen_t)cap); ok = 1;
        }
    }
    freeaddrinfo(res);
    return ok;
}
static void put_varint(uint8_t *b, int *o, uint64_t v) { if (v < 0xFD) b[(*o)++] = (uint8_t)v; else if (v <= 0xFFFF) { b[(*o)++] = 0xFD; b[(*o)++] = v & 0xff; b[(*o)++] = (v >> 8) & 0xff; } else { b[(*o)++] = 0xFE; for (int i = 0; i < 4; i++) b[(*o)++] = (v >> (8*i)) & 0xff; } }

// ── self-connect guard (Bitcoin/Dogecoin Core's version-nonce trick) ─────────
// This node is (or can be) its own seed: the seed hostname resolves to our own
// address, so both the sync thread and the serve thread may dial themselves. We
// stamp one per-process random nonce into every version we send; a version that
// echoes it back means the peer is us. pthread_once so the sync and serve
// threads agree on the same nonce.
static uint64_t g_self_nonce = 0;
static void self_nonce_gen(void) {
    while (!g_self_nonce)                                             // never 0 (0 = "unset")
        if (getentropy(&g_self_nonce, sizeof g_self_nonce) != 0) g_self_nonce = (uint64_t)time(NULL);
}
static uint64_t self_nonce(void) {
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, self_nonce_gen);
    return g_self_nonce;
}
// The version nonce sits at a fixed payload offset: version(4)+services(8)+
// timestamp(8)+addr_recv(26)+addr_from(26) = 72. Returns 0 if too short.
static int ver_nonce(const uint8_t *pl, uint32_t pln, uint64_t *out) {
    const uint32_t off = 4 + 8 + 8 + 26 + 26;
    if (pln < off + 8) return 0;
    uint64_t n = 0; for (int i = 0; i < 8; i++) n |= (uint64_t)pl[off + i] << (8 * i);
    *out = n; return 1;
}
// Our own external IPv4, learned from a real peer's version.addr_recv (the ip
// THEY dialed us on). Written by whichever thread first handshakes a genuine
// peer, read by the serve dial loop to skip a seed that points back at us even
// when the dial can't complete (no NAT hairpin → no handshake → the nonce check
// can't fire). Best-effort cross-thread hint; a torn read just costs one extra
// dial attempt.
static char g_self_ip[INET_ADDRSTRLEN] = "";
// Record our external ip from a received version payload, if it carries a plausible
// non-local IPv4 in addr_recv (0xFFFF-mapped at offset 38, quad at 40).
static int ipv4_globally_routable(unsigned a, unsigned b) {
    if (!a || a == 127 || a == 10 || a >= 224) return 0;
    if (a == 169 && b == 254) return 0;
    if (a == 172 && b >= 16 && b <= 31) return 0;
    if (a == 192 && b == 168) return 0;
    return 1;
}
static void learn_self_ip(const uint8_t *pl, uint32_t pln) {
    if (pln < 46 || pl[38] != 0xFF || pl[39] != 0xFF) return;
    if (!ipv4_globally_routable(pl[40], pl[41])) return;
    snprintf(g_self_ip, sizeof g_self_ip, "%u.%u.%u.%u", pl[40], pl[41], pl[42], pl[43]);
}
// serve-loop `self` ("ip:port") is the address we advertise. Keep g_self_ip
// in lockstep so addr_harvest / addr_is_self see it even when pepenet
// versions leave addr_recv empty.
static void note_self_host(const char *self) {
    if (!self || !*self) return;
    char sip[64]; snprintf(sip, sizeof sip, "%s", self);
    { char *c = strrchr(sip, ':'); if (c) *c = 0; }
    if (sip[0]) snprintf(g_self_ip, sizeof g_self_ip, "%s", sip);
}
// True when `host` resolves to the IPv4 we advertise as ourselves. `self` is the
// serve loop's own learned addr ("ip:port", from an inbound peer); if it's NULL
// or empty we fall back to g_self_ip (learned by whichever thread first reached
// a real peer). This catches a seed that points back at us even when the dial
// can't complete — no NAT hairpin means no handshake, so the version-nonce check
// can't fire. A no-op until one of the two has been learned.
static int host_is_self(const char *host, const char *self) {
    char sip[64] = "";
    if (self && *self) { snprintf(sip, sizeof sip, "%s", self); char *c = strrchr(sip, ':'); if (c) *c = 0; }
    else if (g_self_ip[0]) snprintf(sip, sizeof sip, "%s", g_self_ip);
    else return 0;
    struct addrinfo hints, *res = NULL; memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return 0;
    int match = 0;
    for (struct addrinfo *ai = res; ai && !match; ai = ai->ai_next)
        if (ai->ai_family == AF_INET) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &((struct sockaddr_in *)ai->ai_addr)->sin_addr, ip, sizeof ip);
            if (!strcmp(ip, sip)) match = 1;
        }
    freeaddrinfo(res); return match;
}

// Cheap self-test for a harvested "ip:port" literal — plain compare against the
// ip we advertise, no resolver (addr_harvest runs per gossiped entry, up to
// 1000 an addr message, on both threads). Port-insensitive on purpose, same as
// host_is_self: our own host is our own host whichever port it names.
static int addr_is_self(const char *addr) {
    if (!g_self_ip[0] || !addr) return 0;
    size_t n = strlen(g_self_ip);
    return !strncmp(addr, g_self_ip, n) && (addr[n] == ':' || addr[n] == '\0');
}

static int p2p_handshake(int fd, const uint8_t magic[4], int64_t our_height) {
    uint8_t v[256]; int o = 0;
    for (int i = 0; i < 4; i++) v[o++] = (70015 >> (8*i)) & 0xff;     // version
    for (int i = 0; i < 8; i++) v[o++] = 0;                          // services
    int64_t now = (int64_t)time(NULL); for (int i = 0; i < 8; i++) v[o++] = (now >> (8*i)) & 0xff;  // timestamp
    memset(v + o, 0, 26); o += 26;                                   // addr_recv
    memset(v + o, 0, 26); o += 26;                                   // addr_from
    uint64_t sn = self_nonce();                                      // nonce (self-connect guard)
    for (int i = 0; i < 8; i++) v[o++] = (uint8_t)(sn >> (8*i));
    size_t ual = strlen(idx_sync_agent); if (ual > 100) ual = 100;   // user-agent: the
    v[o++] = (uint8_t)ual;                                           // "/pepenet-…/" subver is
    memcpy(v + o, idx_sync_agent, ual); o += (int)ual;               // the mesh's discovery mark
    for (int i = 0; i < 4; i++) v[o++] = (our_height >> (8*i)) & 0xff; // start_height
    v[o++] = 1;                                                      // relay: we accept tx invs (mempool)
    if (!net_send(fd, magic, "version", v, (uint32_t)o)) return 0;
    // exchange until we see verack
    int got_verack = 0, sent_verack = 0;
    int64_t sdl = mono_ms() + IDX_NET_SHAKE_DEADLINE_MS;
    for (int i = 0; i < 10; i++) {
        char cmd[13]; uint8_t *pl; uint32_t pl_len;
        int r = net_recv_dl(fd, magic, cmd, &pl, &pl_len, 8000, sdl); if (r != 1) { if (r == -1) continue; return got_verack && sent_verack; }
        if (!strcmp(cmd, "version")) {
            uint64_t vn;                                 // did we just dial ourselves?
            if (ver_nonce(pl, pl_len, &vn) && vn == self_nonce()) { free(pl); return 2; }
            learn_self_ip(pl, pl_len);                   // the ip THEY see us as → our external addr
            net_send(fd, magic, "verack", NULL, 0); sent_verack = 1;
            // version.start_height: the peer's declared chain height — the wire's
            // only am-I-caught-up signal (a getblocks at tip is answered with
            // silence). Exported for embedding hosts (indexer.h).
            if (pl_len >= 12) {                          // services (crawl classifier)
                uint64_t sv = 0; for (int b = 0; b < 8; b++) sv |= (uint64_t)pl[4 + b] << (8 * b);
                idx_sync_peer_services = sv;
            }
            uint64_t off = 4 + 8 + 8 + 26 + 26 + 8, ua;  // fields before user_agent
            int ok = pl_len > off;
            ua = ok ? pl[off++] : 0;
            if (ok && ua == 0xFD) { ok = pl_len >= off + 2; if (ok) { ua = pl[off] | ((uint64_t)pl[off+1] << 8); off += 2; } }
            else if (ua > 0xFD) ok = 0;                  // 4/8-byte UA length: no real peer
            if (ok && pl_len >= off + ua + 4) {
                size_t an = ua < sizeof idx_sync_peer_agent - 1 ? ua : sizeof idx_sync_peer_agent - 1;
                memcpy((char *)idx_sync_peer_agent, pl + off, an);
                ((char *)idx_sync_peer_agent)[an] = 0;   // peer subver — the crawl's classifier
                off += ua;
                int32_t ph = (int32_t)((uint32_t)pl[off] | ((uint32_t)pl[off+1] << 8) |
                                       ((uint32_t)pl[off+2] << 16) | ((uint32_t)pl[off+3] << 24));
                if (ph > 0) idx_sync_peer_height = ph;
            }
        }
        else if (!strcmp(cmd, "verack")) got_verack = 1;
        else if (!strcmp(cmd, "ping")) net_send(fd, magic, "pong", pl, pl_len);
        free(pl);
        if (got_verack && sent_verack) return 1;
    }
    return got_verack && sent_verack;
}

volatile int idx_sync_stop = 0;                 // embedding hosts only (indexer.h)
volatile int idx_self_seed = 0;                 // set when a seed dial loops home (indexer.h)
static pthread_mutex_t g_ph_mu = PTHREAD_MUTEX_INITIALIZER;
static int64_t g_ph_best = 0, g_ph_disk = 0, g_ph_at = 0;
// Seed in-memory high-water from the DB so a post-restart note/handshake cannot
// transiently set g_ph_disk below the stored value (raise alone keeps the DB safe;
// load keeps the rate-limit cursor honest).
void idx_peer_height_load(sqlite3 *db) {
    int64_t h = db ? idx_db_get_peer_height(db) : 0;
    if (h <= 0) return;
    pthread_mutex_lock(&g_ph_mu);
    if (h > g_ph_best) g_ph_best = h;
    if (h > g_ph_disk) g_ph_disk = h;
    pthread_mutex_unlock(&g_ph_mu);
}
int64_t idx_peer_height_note(sqlite3 *db, int64_t h, int64_t now, int force) {
    int64_t w = 0, best;
    pthread_mutex_lock(&g_ph_mu);
    if (h > g_ph_best) g_ph_best = h;
    if (db && g_ph_best > g_ph_disk && (force || now - g_ph_at >= IDX_PH_WRITE_MIN_S)) {
        w = g_ph_best; g_ph_at = now;            // g_ph_disk updated after raise from DB
    }
    best = g_ph_best;
    pthread_mutex_unlock(&g_ph_mu);
    if (w) {
        idx_db_raise_peer_height(db, w);         // monotonic vs the stored value too
        int64_t got = idx_db_get_peer_height(db);
        pthread_mutex_lock(&g_ph_mu);
        if (got > g_ph_disk) g_ph_disk = got;
        if (got > g_ph_best) g_ph_best = got;
        best = g_ph_best;
        pthread_mutex_unlock(&g_ph_mu);
    }
    return best;
}
void idx_peer_height_reset(void) {
    pthread_mutex_lock(&g_ph_mu); g_ph_best = g_ph_disk = g_ph_at = 0; pthread_mutex_unlock(&g_ph_mu);
}
// a serve peer announced (or pushed) a block we can place at height h: it has
// at least that chain. Raise its live claim and the persisted peer_height.
static void serve_peer_announced(void *conn_peer_h, sqlite3 *db, int64_t h) {
    int64_t *ph = conn_peer_h;
    if (h <= 0) return;
    if (h > *ph) *ph = h;
    idx_peer_height_note(db, h, (int64_t)time(NULL), 0);
}
volatile int64_t idx_sync_peer_height = 0;      // embedding hosts only (indexer.h)
const char *idx_sync_agent = IDX_DNET_MARK "indexer:0.1/";   // hosts override (indexer.h)
volatile char idx_sync_peer_agent[128] = "";    // this pass's peer subver (indexer.h)
volatile uint64_t idx_sync_peer_services = 0;   // this pass's peer services (indexer.h)

// ── peer candidates + addr harvest ────────────────────────────────────────────
// "host[:port]" → host copy + port (dflt when absent). Bare IPv6 not supported
// here — harvested/dialed text addrs are IPv4 or hostnames.
static void peer_split(const char *s, char *host, size_t hcap, uint16_t *port, uint16_t dflt) {
    snprintf(host, hcap, "%s", s);
    *port = dflt;
    char *c = strrchr(host, ':');
    if (c && c[1] && strspn(c + 1, "0123456789") == strlen(c + 1)) { *c = 0; *port = (uint16_t)atoi(c + 1); }
}
static int cand_add(char (*cand)[80], int n, int max, const char *s) {
    if (!s || !*s || n >= max) return n;
    for (int i = 0; i < n; i++) if (!strcmp(cand[i], s)) return n;
    snprintf(cand[n], 80, "%s", s);
    return n + 1;
}
// addr payload: varint count, then per entry time(4) services(8LE) ip(16) port(2BE).
// Harvest routable IPv4 entries into the peers table — the failover pool the next
// pass draws on, and slice 2's crawl frontier. Bounds-checked like inv (peer bytes).
// `dnet`: this came over dnaddr (a pepenet peer vouched for these) → mark the rows
// so the overlay dialer re-seats from them; plain chain addr passes dnet=0.
static int addr_harvest(sqlite3 *db, const uint8_t *pl, uint32_t pl_len, int dnet) {
    if (!db || pl_len < 1) return 0;
    uint32_t po = 0; uint64_t cnt = pl[po++];
    if (cnt == 0xFD) { if (pl_len < 3) return 0; cnt = pl[po] | ((uint64_t)pl[po+1] << 8); po += 2; }
    else if (cnt >= 0xFE) return 0;
    if (cnt > 1000) cnt = 1000;                  // MAX_ADDR_TO_SEND
    int64_t now = (int64_t)time(NULL);
    int kept = 0;
    for (uint64_t i = 0; i < cnt && po + 30 <= pl_len; i++, po += 30) {
        const uint8_t *e = pl + po;
        int64_t svc = 0; for (int b = 0; b < 8; b++) svc |= (int64_t)e[4 + b] << (8 * b);
        const uint8_t *ip = e + 12;
        static const uint8_t v4map[12] = { 0,0,0,0,0,0,0,0,0,0,0xFF,0xFF };
        if (memcmp(ip, v4map, 12) != 0) continue;                    // IPv4 only for now
        uint8_t a = ip[12], b2 = ip[13];
        if (a == 0 || a == 127 || a == 10 || (a == 172 && b2 >= 16 && b2 <= 31) ||
            (a == 192 && b2 == 168) || (a == 169 && b2 == 254)) continue;   // unroutable
        uint16_t port = (uint16_t)(e[28] << 8 | e[29]);
        if (!port) continue;
        char addr[80]; snprintf(addr, sizeof addr, "%u.%u.%u.%u:%u", a, b2, ip[14], ip[15], port);
        // never harvest ourselves: we self-announce, so our own addr is gossiped
        // straight back at us and would otherwise land in the dial pool (as a
        // dnet=1 vouch off dnaddr, which the overlay dialer then seats).
        if (addr_is_self(addr)) continue;
        if (dnet) idx_db_peer_dnet_note(db, addr, svc, now);
        else      idx_db_peer_note(db, addr, svc, now);
        kept++;
    }
    return kept;
}

// ── block validation (peer bytes are hostile until proven) ───────────────────
// Stateless: tx-merkle root (meta.merkle_ok from the parse) + idx_pow_check
// (target sanity, scrypt work, full AuxPoW). Contextual: the Digishield-expected
// nBits and the median-time-past rule, anchored on the blocks table with the
// profile's pinned checkpoint header standing in for the two heights below a
// fresh db's start. Context rows with bits==0 (written before the column
// existed) skip the nBits equality for that one block — the work check stands.
static int block_validate(sqlite3 *db, const Coin *coin, int64_t pos,
                          const uint8_t *raw, size_t len, char *why, size_t cap) {
    if (!coin->powlimit) return 1;               // test profile: fixture chains
    IdxBlockMeta m;
    if (!idx_parse_block(raw, len, &m, NULL, NULL)) { snprintf(why, cap, "unparseable"); return 0; }
    if (!m.merkle_ok) { snprintf(why, cap, "tx merkle mismatch"); return 0; }
    PowParams pp = { coin->powlimit, coin->aux_chain_id };
    if (!idx_pow_check(raw, len, &pp, why, cap)) return 0;
    int64_t pt = 0, ppt = 0; uint32_t pbits = 0;
    if (pos - 1 == coin->start) { pt = coin->start_time; pbits = coin->start_bits; }
    else idx_db_block_hdr(db, pos - 1, &pt, &pbits);
    if (pos - 2 == coin->start) ppt = coin->start_time;
    else if (pos - 2 == coin->start - 1) ppt = coin->start_prev_time;
    else idx_db_block_hdr(db, pos - 2, &ppt, NULL);
    if (pbits && pt && ppt) {
        uint32_t want = idx_pow_next_bits(pbits, pt, ppt, coin->powlimit);
        if (m.bits != want) {
            snprintf(why, cap, "nBits 0x%08x != Digishield-expected 0x%08x", m.bits, want);
            return 0;
        }
    }
    int64_t times[12]; int n = idx_db_block_times(db, pos, times);
    if (n < 11 && pos - n - 1 == coin->start) times[n++] = coin->start_time;
    if (n < 11 && pos - n - 1 == coin->start - 1) times[n++] = coin->start_prev_time;
    if (n) {
        for (int i = 1; i < n; i++) {            // insertion sort, n ≤ 11
            int64_t v = times[i]; int j = i - 1;
            while (j >= 0 && times[j] > v) { times[j + 1] = times[j]; j--; }
            times[j + 1] = v;
        }
        if ((int64_t)m.time <= times[n / 2]) {
            snprintf(why, cap, "time %u <= median-time-past %lld", m.time, (long long)times[n / 2]);
            return 0;
        }
    }
    return 1;
}

// ── most-work chain selection (cumulative-work fork rule) ─────────────────────
// The forward sync is blocks-first (getblocks/inv/block), but a REORG must not be
// first-valid-peer-wins: a valid-but-lighter fork must never rewrite an
// established chain. When a peer serves a block extending an ancestor, we weigh
// its whole branch by cumulative work — fetched cheaply as headers — against ours
// above the fork, and only reorg if it is strictly heavier.
typedef struct {
    int64_t  h;              // height of the last accepted branch header
    uint8_t  prev_hash[32];  // its hash — the next header must chain to this
    int64_t  prev_time, prevprev_time;
    uint32_t prev_bits;
    uint8_t  work[32];       // Σ proof-of-work of accepted branch headers
    int      n;
} BranchCtx;

// Seed the walk at the fork point, sourcing the retarget context (fork_h and its
// parent's time/bits) exactly as block_validate does — checkpoint stand-ins for
// the two heights below a fresh db's start.
static void branch_seed(BranchCtx *bc, const Coin *coin, sqlite3 *db,
                        int64_t fork_h, const uint8_t fork_hash[32]) {
    memset(bc, 0, sizeof *bc);
    bc->h = fork_h; memcpy(bc->prev_hash, fork_hash, 32);
    int64_t pt = 0, ppt = 0; uint32_t pbits = 0;
    if (fork_h == coin->start) { pt = coin->start_time; pbits = coin->start_bits; }
    else idx_db_block_hdr(db, fork_h, &pt, &pbits);
    if (fork_h - 1 == coin->start) ppt = coin->start_time;
    else if (fork_h - 1 == coin->start - 1) ppt = coin->start_prev_time;
    else idx_db_block_hdr(db, fork_h - 1, &ppt, NULL);
    bc->prev_time = pt; bc->prevprev_time = ppt; bc->prev_bits = pbits;
}

// Validate + weigh one `headers` message onto bc. Each element is header[+auxpow]
// then a tx-count varint (0 in a headers message). Same checks Core applies to a
// header on a candidate chain — linkage, PoW (scrypt/auxpow ≤ target), and the
// per-block Digishield nBits — so a branch we accept as heavier is one whose
// blocks will also validate when we download them. Returns headers accepted, or
// -1 on the first invalid one.
static int branch_weigh(BranchCtx *bc, const Coin *coin, sqlite3 *db,
                        const uint8_t *pl, uint32_t pl_len, char *why, size_t cap) {
    (void)db;
    PowParams pp = { coin->powlimit, coin->aux_chain_id };
    if (pl_len < 1) return 0;
    int po = 0; uint64_t cnt = pl[po++];
    if (cnt == 0xFD) { if (pl_len < 3) return 0; cnt = pl[po] | (pl[po+1] << 8); po += 2; }
    else if (cnt >= 0xFE) { snprintf(why, cap, "headers count too large"); return -1; }
    int accepted = 0;
    for (uint64_t i = 0; i < cnt; i++) {
        if (po + 80 > (int)pl_len) { snprintf(why, cap, "headers truncated"); return -1; }
        const uint8_t *hdr = pl + po;
        if (memcmp(hdr + 4, bc->prev_hash, 32) != 0) { snprintf(why, cap, "branch header %d off-chain", accepted); return -1; }
        size_t span = 0;
        if (!idx_pow_check2(hdr, pl_len - po, &pp, &span, why, cap)) return -1;
        uint32_t bits = (uint32_t)hdr[72] | (uint32_t)hdr[73] << 8 | (uint32_t)hdr[74] << 16 | (uint32_t)hdr[75] << 24;
        if (bc->prev_bits && bc->prev_time && bc->prevprev_time) {
            uint32_t want = idx_pow_next_bits(bc->prev_bits, bc->prev_time, bc->prevprev_time, coin->powlimit);
            if (bits != want) { snprintf(why, cap, "branch nBits 0x%08x != Digishield 0x%08x at %lld", bits, want, (long long)(bc->h + 1)); return -1; }
        }
        int64_t t = (uint32_t)hdr[68] | (uint32_t)hdr[69] << 8 | (uint32_t)hdr[70] << 16 | (uint32_t)hdr[71] << 24;
        uint8_t hh[32]; idx_sha256d(hdr, 80, hh);
        uint8_t w[32]; idx_pow_work(bits, w); idx_pow_work_add(bc->work, w);
        bc->prevprev_time = bc->prev_time; bc->prev_time = t; bc->prev_bits = bits;
        memcpy(bc->prev_hash, hh, 32); bc->h++; bc->n++; accepted++;
        po += (int)span;                                   // header + auxpow
        if (po >= (int)pl_len) break;
        uint8_t tc = pl[po++];                             // tx-count varint (0 here)
        if (tc == 0xFD) po += 2; else if (tc == 0xFE) po += 4; else if (tc == 0xFF) po += 8;
    }
    return accepted;
}

// 1 = the peer's branch is strictly heavier than ours above fork_h (reorg),
// 0 = not heavier / unweighable (keep our chain), -1 = branch invalid (drop peer),
// -2 = peer stalled past the weigh deadline (drop peer, no invalidity verdict).
static int branch_outweighs(int fd, const Coin *coin, sqlite3 *db,
                            int64_t fork_h, const uint8_t fork_hash[32],
                            int64_t our_height, char *why, size_t cap) {
    // OUR cumulative work above the fork. A block with bits==0 (a legacy db from
    // before the PoW column) is unweighable → refuse the reorg: an established
    // chain is never rewritten from history we cannot weigh. A re-sync populates
    // bits and turns most-work reorgs back on.
    uint8_t our_work[32]; memset(our_work, 0, 32);
    for (int64_t h = fork_h + 1; h <= our_height; h++) {
        int64_t t; uint32_t bits;
        if (!idx_db_block_hdr(db, h, &t, &bits) || bits == 0) {
            snprintf(why, cap, "our block %lld has no recorded work — re-sync to enable most-work reorgs", (long long)h);
            return 0;
        }
        uint8_t w[32]; idx_pow_work(bits, w); idx_pow_work_add(our_work, w);
    }
    BranchCtx bc; branch_seed(&bc, coin, db, fork_h, fork_hash);
    int64_t wdl = mono_ms() + (int64_t)IDX_SYNC_WEIGH_DEADLINE_S * 1000;   // whole weigh, all pages
    for (int page = 0; page < 64 && !idx_sync_stop; page++) {  // ≤128k headers
        uint8_t gh[4 + 3 + 3*32]; int o = 0;
        for (int i = 0; i < 4; i++) gh[o++] = (70015 >> (8*i)) & 0xff;
        put_varint(gh, &o, 2);
        memcpy(gh + o, bc.prev_hash, 32); o += 32;         // locator: the branch cursor
        memcpy(gh + o, coin->start_hash, 32); o += 32;     // + the checkpoint anchor
        memset(gh + o, 0, 32); o += 32;                    // hash_stop
        net_send(fd, coin->magic, "getheaders", gh, (uint32_t)o);
        char cmd[13]; uint8_t *pl = NULL; uint32_t pl_len = 0; int got = 0;
        // Drain until the `headers` reply. This weigh runs INSIDE the block
        // receive loop, right after a getdata for a whole inv batch (≤600
        // blocks) — so the peer streams that block backlog ahead of the headers
        // it queues for our getheaders. An 8-message window gave up inside the
        // flood and returned "not heavier", wedging a node on a minority fork
        // forever (the branch it declined was the majority chain). The real
        // timeout still bounds a dead peer: net_recv returns 0 on a 15 s stall,
        // taking the `r != 1` exit below. Cap well above one batch as a
        // junk-flood backstop. A peer that is never silent but never sends
        // the headers is cut by the weigh deadline (wdl) → -2, drop the peer.
        for (int tries = 0; tries < 4096 && !got && !idx_sync_stop; tries++) {
            int r = net_recv_dl(fd, coin->magic, cmd, &pl, &pl_len, 15000, wdl);
            if (r != 1) {
                if (r == -1) continue;
                if (dl_passed(wdl)) {
                    snprintf(why, cap, "no headers within the %ds weigh deadline", IDX_SYNC_WEIGH_DEADLINE_S);
                    return -2;
                }
                return 0;                                            // dead/timeout → keep ours
            }
            if (!strcmp(cmd, "ping")) { net_send(fd, coin->magic, "pong", pl, pl_len); free(pl); continue; }
            if (!strcmp(cmd, "headers")) { got = 1; break; }
            free(pl);                                                // drop interleaved inv/addr/block backlog
        }
        if (!got) return 0;
        int n = branch_weigh(&bc, coin, db, pl, pl_len, why, cap);
        free(pl);
        if (n < 0) return -1;
        if (idx_pow_work_cmp(bc.work, our_work) > 0) return 1;       // already heavier
        if (n < 2000) break;                                        // branch ended, not heavier
    }
    return idx_pow_work_cmp(bc.work, our_work) > 0 ? 1 : 0;
}

// weigh <coin> <headers-file> — dev/test: validate + weigh a raw `headers`
// message body as a branch off the profile checkpoint (Digishield anchored on
// the pinned start header). Prints the accepted count + cumulative work, or the
// rejection reason. Lets the most-work validation pipeline be tested against
// real merged-mined headers pulled from a live node (no mining needed).
static int cmd_weigh(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: weigh <coin> <headers-file>\n"); return 2; }
    const Coin *coin = coin_by_name(argv[2]); if (!coin) { fprintf(stderr, "unknown coin %s\n", argv[2]); return 2; }
    if (!coin->powlimit) { fprintf(stderr, "coin %s has PoW validation off\n", coin->name); return 2; }
    size_t len; uint8_t *pl = read_file(argv[3], &len);
    if (!pl) { fprintf(stderr, "cannot read %s\n", argv[3]); return 1; }
    BranchCtx bc; branch_seed(&bc, coin, NULL, coin->start, coin->start_hash);
    char why[160] = "";
    int n = branch_weigh(&bc, coin, NULL, pl, (uint32_t)len, why, sizeof why);
    free(pl);
    if (n < 0) { fprintf(stderr, "REJECTED after %d accepted (at height %lld): %s\n",
                         bc.n, (long long)(bc.h + 1), why); return 1; }
    char wh[65]; static const char *H = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { wh[2*i] = H[bc.work[31-i] >> 4]; wh[2*i+1] = H[bc.work[31-i] & 15]; }
    wh[64] = 0;
    int allzero = 1; for (int i = 0; i < 32; i++) if (bc.work[i]) { allzero = 0; break; }
    printf("accepted %d headers off %s checkpoint %lld, cumulative work 0x%s\n",
           n, coin->name, (long long)coin->start, wh);
    return allzero ? 1 : 0;   // zero work on a non-empty accept = a bug
}

// Parity clock for the sync pass's skip-socket gate: the last wall time we had
// hard evidence of being at the network tip (a staged fold, or a socket pass
// measuring height ≥ the peer's claim). In-process across passes; the fresh
// value at boot doubles as the boot grace window.
#define SYNC_PARITY_GRACE_S 900
static time_t s_parity;

static int cmd_sync(int argc, char **argv) {
    // sync <coin> <db> [peers] [activation] — peers: comma-separated host[:port]
    // list tried first (hostnames ok), or "auto" for cache+seeds only.
    ignore_sigpipe();
    if (argc < 4) { fprintf(stderr, "usage: sync <doge|pep|testnet|regtest> <db> [peers=127.0.0.1|auto] [activation]\n"); return 2; }
    const Coin *coin = coin_by_name(argv[2]); if (!coin) { fprintf(stderr, "unknown coin %s\n", argv[2]); return 2; }
    const char *dbpath = argv[3]; const char *ip = argc > 4 ? argv[4] : "127.0.0.1";
    sqlite3 *db = idx_db_open(dbpath); if (!db) { fprintf(stderr, "cannot open %s\n", dbpath); return 1; }
    idx_peer_height_load(db);                 // seed g_ph_* from meta before any handshake/note
    // A stored activation always wins (changing it mid-state would fork the fold);
    // the CLI value only seeds a fresh DB.
    int64_t cli_act = argc > 5 ? strtoll(argv[5], NULL, 10) : coin->activation;
    int64_t activation = idx_db_get_activation(db, cli_act); idx_db_set_activation(db, activation);
    if (argc > 5 && activation != cli_act)
        fprintf(stderr, "note: db pins activation %lld; ignoring CLI %lld\n", (long long)activation, (long long)cli_act);
    SmState *s = sm_new((uint64_t)activation);
    stamp_magic(s, coin->onchain_magic);
    idx_db_set_onchain_magic(db, coin->onchain_magic);
    OracleFeed *oracle = oracle_new();
    oracle_set_subsidy(oracle, coin->subsidy); idx_db_set_subsidy(db, coin->subsidy);   // profile → feed + db pin
    idx_db_load_state(db, s); idx_db_oracle_warm(db, oracle); oracle_set_subsidy(oracle, idx_db_get_subsidy(db, SUBSIDY_10K));
    // Fresh DB: stand on the profile's start checkpoint (never folded itself) so the
    // peer serves start+1 as start+1 — heights in the fold are real chain heights.
    int64_t height = 0; uint8_t tip[32];
    if (!idx_db_load_sync(db, &height, tip)) {
        height = coin->start; memcpy(tip, coin->start_hash, 32);
        idx_db_epochs_mark(db, 0);   // complete-history DB: epoch coverage from genesis
    }
    // Crash-consistency: the loaded fold state is the projection, at proj_height. If a
    // prior run died after advancing the (autocommitted) sync height past the last
    // committed projection, resume from proj_height and re-fold the gap — never from a
    // height ahead of the state, which would silently skip those blocks' actions.
    int recovered = idx_sync_recover(db, coin->start, coin->start_hash, &height, tip);
    if (recovered) oracle_rollback(oracle, height + 1);
    // One-time wallet re-walk ("wallet_rewalk_v1"): earlier builds' rollback
    // replay re-INSERTed watched outputs with spent_height=NULL (OR REPLACE),
    // so an accepted reorg could resurrect an output whose spend sat in a
    // non-carrier block — a block the replay substrate never stored, leaving
    // nothing local to repair from. Heal by re-walking the chain: roll the fold
    // back to just below the oldest unspent watched output and let this same
    // pass re-download and refold from there — utxo_put now preserves standing
    // rows and the refold re-marks every lost spend, so the walk converges on
    // the true balance. Runs once per db; a no-wallet db just sets the flag.
    if (!idx_db_flag_get(db, "wallet_rewalk_v1")) {
        int64_t mh = idx_db_utxo_min_unspent(db);
        int64_t to = mh > 0 ? mh - 1 : -1;
        if (to >= 0 && to < coin->start) to = coin->start;
        if (to >= 0 && to < height) {
            fprintf(stderr, "wallet re-walk: re-verifying spends over blocks %lld..%lld\n",
                    (long long)(to + 1), (long long)height);
            if (idx_sync_rollback(&s, db, oracle, activation, to)) {
                height = to;
                if (height <= coin->start) { height = coin->start; memcpy(tip, coin->start_hash, 32); }
                else if (!idx_db_block_get(db, height, tip)) memcpy(tip, coin->start_hash, 32);
                idx_db_save_sync(db, height, tip);
                idx_db_flag_set(db, "wallet_rewalk_v1");
            }   // rollback failure: leave the flag unset, retry next pass
        } else
            idx_db_flag_set(db, "wallet_rewalk_v1");
    }
    // The loaded state IS the projection at `height` (post-recovery). Seed the
    // fold cursor: sm_new starts cur_height at 0 and idx_db_load_state never
    // sets it, so a pass that connects nothing (fully synced, quiet window)
    // would stamp proj_height=0 at pass end — which the NEXT boot reads as a
    // crash gap and "recovers" a synced db all the way back to the checkpoint.
    s->cur_height = height;
    if (idx_db_ckpt_seed(db, s) == 1)
        fprintf(stderr, "rb_ckpt: first checkpoint taken on open at height %lld\n", (long long)height);
    FoldCtx fc = { .s = s, .db = db, .oracle = oracle };
    fold_load_watch(&fc);
    // serve cache: the header chain + rolling block window, a separate aux db
    // (serve-<coin>.db) next to the fold db — populated as we connect blocks so
    // this node can answer getheaders/getdata for other pepenet peers.
    char serve_path[600];
    { const char *slash = strrchr(dbpath, '/');
      if (slash) snprintf(serve_path, sizeof serve_path, "%.*s/serve-%s.db",
                          (int)(slash - dbpath), dbpath, coin->name);
      else snprintf(serve_path, sizeof serve_path, "serve-%s.db", coin->name); }
    fc.serve = serve_store_open(serve_path);
    if (recovered) serve_store_prune_above(fc.serve, height);

    // ── phase 0: fold off the stage (sync-over-one-connection) ────────────────
    // The serve thread getdatas every unknown block inv on its (mesh) conns
    // into blockstage; rows that extend our tip fold HERE, through the same
    // validation as socket blocks. A node at tip thus follows the chain over
    // its one persistent connection, and — when the mesh's claimed best height
    // says we're caught up — this pass ends without opening a socket at all.
    // The socket ladder below remains the path for initial sync, catch-up
    // gaps deeper than the stage, and every reorg.
    int64_t stage_folded = 0;
    if (fc.serve) {
        uint8_t sh[32], *sraw; size_t slen; char swhy[128];
        int guard = 0;   // bound: a stage_del lost to sqlite contention must not spin the pass
        while (!idx_sync_stop && guard++ < 512 &&
               serve_store_stage_next(fc.serve, tip, sh, &sraw, &slen)) {
            if (!block_validate(db, coin, height + 1, sraw, slen, swhy, sizeof swhy)) {
                fprintf(stderr, "staged block for height %lld invalid: %s — dropping\n",
                        (long long)(height + 1), swhy);
                serve_store_stage_del(fc.serve, sh); free(sraw);
                continue;                           // another stage row may chain here
            }
            int ok = connect_block(&fc, height + 1, sraw, slen);
            serve_store_stage_del(fc.serve, sh); free(sraw);
            if (!ok) continue;
            height++; stage_folded++;
            { int64_t hh; idx_db_load_sync(db, &hh, tip); }   // refresh tip hash
        }
        if (stage_folded)
            fprintf(stderr, "folded %lld staged block(s) off the mesh line — height %lld\n",
                    (long long)stage_folded, (long long)height);

        // stage-side REORG (one connection, no socket): unchainable stage rows
        // may be the winning branch of an orphan race, delivered over the
        // standing conn by push/pull. If they tie to a recent ancestor and
        // chain contiguously in the stage, weigh them EXACTLY like the socket
        // path weighs a peer branch — branch_weigh per staged block's
        // header[+auxpow]: linkage, PoW, Digishield — and only a strictly
        // heavier branch rolls us back; the normal validate+fold then connects
        // it. A judged-lighter or invalid branch is deleted (never re-judged
        // every pass); anything unanchored just ages out of the stage.
        if (!idx_sync_stop && serve_store_stage_pending(fc.serve)) {
            int64_t fork_h = -1; uint8_t fh[32];
            { uint8_t ph[32], *praw; size_t plen;
              for (int64_t h = height - 1; h > height - 32 && h >= coin->start && fork_h < 0; h--)
                  if (idx_db_block_get(db, h, fh) &&
                      serve_store_stage_next(fc.serve, fh, ph, &praw, &plen)) {
                      free(praw);                       // probe only — re-read in the walk
                      fork_h = h;
                  } }
            if (fork_h >= 0) {
                uint8_t bhs[32][32]; uint8_t *raws[32]; size_t lens[32]; int bn = 0;
                uint8_t cur[32]; memcpy(cur, fh, 32);
                while (bn < 32 && serve_store_stage_next(fc.serve, cur, bhs[bn], &raws[bn], &lens[bn])) {
                    memcpy(cur, bhs[bn], 32); bn++;
                }
                int verdict = 0;                        // 1 reorg · -1 drop rows · 0 leave
                char bwhy[160] = "";
                if (bn > 0) {
                    uint8_t ours[32]; memset(ours, 0, 32); int weighable = 1;
                    for (int64_t h = fork_h + 1; h <= height && weighable; h++) {
                        int64_t t; uint32_t bits;
                        if (!idx_db_block_hdr(db, h, &t, &bits) || bits == 0) weighable = 0;
                        else { uint8_t w[32]; idx_pow_work(bits, w); idx_pow_work_add(ours, w); }
                    }
                    BranchCtx bc; branch_seed(&bc, coin, db, fork_h, fh);
                    int ok = weighable;
                    for (int i = 0; i < bn && ok; i++) {
                        // one staged block as a 1-element headers message:
                        // varint(1) + header[+auxpow] + tx-count… — branch_weigh
                        // reads exactly that prefix and ignores the tx bytes
                        uint8_t *one = malloc(1 + lens[i]);
                        if (!one) { ok = 0; break; }
                        one[0] = 1; memcpy(one + 1, raws[i], lens[i]);
                        if (branch_weigh(&bc, coin, db, one, (uint32_t)(1 + lens[i]),
                                         bwhy, sizeof bwhy) != 1) ok = 0;
                        free(one);
                    }
                    if (ok && idx_pow_work_cmp(bc.work, ours) > 0) verdict = 1;
                    else verdict = -1;                  // lighter, invalid, or unweighable
                }
                if (verdict == 1) {
                    fprintf(stderr, "reorg (mesh stage): branch at height %lld outweighs our tip %lld — rolling back\n",
                            (long long)fork_h, (long long)height);
                    if (!idx_sync_rollback(&s, db, oracle, activation, fork_h)) {
                        // state is not trustworthy past a failed replay — bail hard
                        fprintf(stderr, "rollback replay failed — aborting sync\n");
                        for (int i = 0; i < bn; i++) free(raws[i]);
                        serve_store_close(fc.serve); oracle_free(oracle); sm_free(s); idx_db_close(db);
                        return 1;
                    }
                    fc.s = s;
                    serve_store_prune_above(fc.serve, fork_h);
                    height = fork_h;
                    if (!idx_db_block_get(db, height, tip)) memcpy(tip, coin->start_hash, 32);
                    idx_db_save_sync(db, height, tip);
                    for (int i = 0; i < bn; i++) {
                        char rwhy[128];
                        int good = block_validate(db, coin, height + 1, raws[i], lens[i], rwhy, sizeof rwhy) &&
                                   connect_block(&fc, height + 1, raws[i], lens[i]);
                        serve_store_stage_del(fc.serve, bhs[i]);
                        if (!good) {
                            fprintf(stderr, "staged branch block for %lld refused: %s\n",
                                    (long long)(height + 1), rwhy);
                            break;
                        }
                        height++; stage_folded++;
                        { int64_t hh; idx_db_load_sync(db, &hh, tip); }
                    }
                    idx_db_project(db, s);
                } else if (verdict == -1) {
                    fprintf(stderr, "staged branch at %lld not heavier than tip %lld — dropping %d row(s)%s%s\n",
                            (long long)fork_h, (long long)height, bn,
                            bwhy[0] ? ": " : "", bwhy);
                    for (int i = 0; i < bn; i++) serve_store_stage_del(fc.serve, bhs[i]);
                }
                for (int i = 0; i < bn; i++) free(raws[i]);
            }
        }
    }
    if (stage_folded) idx_db_project(db, s);    // stage folds feed the projection
                                                // too — market/names must not lag
                                                // a pass that never opens a socket
    // At the mesh's claimed tip, recent parity evidence, and NOTHING left in
    // the stage we couldn't chain? Then there is nothing a socket could add.
    // Each guard closes its own stall:
    //  · stage_pending — an unchainable staged block is the winning side of an
    //    orphan race (its prev is our tip's PARENT) or a child whose parent's
    //    body got lost: our tip is suspect and only the socket path can weigh
    //    and reorg. The stage nudge already woke this pass seconds after that
    //    block arrived, so recovery is immediate — never parked behind a clock.
    //  · the parity clock — claimed heights are captured at handshake and go
    //    stale on a long-lived conn. Parity evidence = a staged fold, or a
    //    socket pass that measured height ≥ the peer's claim; at process start
    //    it winds up fresh (boot grace) so the serve plane's per-minute mesh
    //    PULL (getblocks on the standing conn) proves itself before this pass
    //    ever burns a transient socket. Only a quiet spell past the grace —
    //    many minutes without a block on a 1-min chain — forces a re-measure.
    if (stage_folded || !s_parity) s_parity = time(NULL);
    { int64_t best = idx_serve_best_height();
      if (best > 0 && height >= best &&
          !serve_store_stage_pending(fc.serve) &&
          time(NULL) - s_parity < SYNC_PARITY_GRACE_S) {
          serve_store_close(fc.serve); oracle_free(oracle); sm_free(s); idx_db_close(db);
          return 0;
      } }

    idx_sync_peer_height = 0;    // per-pass: a dead peer must not inherit the last answer
    idx_sync_peer_agent[0] = 0; idx_sync_peer_services = 0;
    // Candidates, in trust order: the explicit CLI peers ("auto" = none) → the
    // cached last-good + harvested NODE_NETWORK peers → the chain's DNS seeds.
    // First candidate that connects AND handshakes wins; the concrete address it
    // resolved to is cached so the next pass leads with a proven peer even if
    // every seed has rotted.
    char cand[24][80]; int nc = 0;
    if (strcmp(ip, "auto") != 0) {
        char list[256]; snprintf(list, sizeof list, "%s", ip);
        for (char *sv, *t = strtok_r(list, ",", &sv); t; t = strtok_r(NULL, ",", &sv))
            nc = cand_add(cand, nc, 24, t);
    }
    { char cached[8][80]; int n = idx_db_peers_best(db, cached, 8);
      for (int i = 0; i < n; i++) nc = cand_add(cand, nc, 24, cached[i]); }
    for (int i = 0; coin->seeds[i]; i++) nc = cand_add(cand, nc, 24, coin->seeds[i]);
    int fd = -1; char picked[80] = "";
    int fb_fd = -1; char fb_picked[80] = "";      // limited peer, held as last resort
    int64_t fb_h = 0, fb_svc = 0; char fb_agent[128] = "";
    for (int i = 0; i < nc && fd < 0 && !idx_sync_stop; i++) {
        char host[80]; uint16_t port;
        peer_split(cand[i], host, sizeof host, &port, coin->port);
        // once the first pass has proven the seed is us, stop burning a full
        // dial + handshake on it every pass — skip known-self candidates up front
        if (idx_self_seed && host_is_self(host, NULL)) continue;
        // ONE CONNECTION PER PEER, no exceptions: a peer the serve plane owns
        // (live conn or seat) is reached ONLY over that standing line — tip
        // follow, catch-up and reorgs all ride the stage (push + locator pull
        // + stage-side reorg), so a second socket buys nothing but the exact
        // duplicate-connection noise this design exists to kill. Skip in both
        // name and resolved form. Candidates we hold no conn to (archive
        // chain nodes) stay fair game — deep catch-up beyond a limited peer's
        // window can only come from them anyway.
        { char srip[80];
          if (idx_serve_peer_held(host) ||
              (net_resolve_str(host, srip, sizeof srip) && idx_serve_peer_held(srip)))
              continue; }
        fd = net_connect(host, port);
        if (fd < 0) { fprintf(stderr, "  %s:%u unreachable\n", host, port); continue; }
        int hr = p2p_handshake(fd, coin->magic, height);
        if (hr == 2) {   // the seed hostname points back at us — skip, use a real peer
            fprintf(stderr, "  %s:%u is ourselves — skipping self-seed\n", host, port);
            idx_self_seed = 1;
            close(fd); fd = -1; continue;
        }
        if (!hr) {
            fprintf(stderr, "  %s:%u handshake failed\n", host, port);
            close(fd); fd = -1; continue;
        }
        if (idx_sync_peer_height > 0) {   // a handshake claim, never below announced evidence
            int64_t ev = idx_peer_height_note(NULL, 0, 0, 0);
            idx_db_raise_peer_height(db, idx_sync_peer_height > ev ? idx_sync_peer_height : ev);  // db-monotonic
        }
        net_peer_str(fd, picked, sizeof picked);
        idx_db_peer_seen(db, picked, (int64_t)idx_sync_peer_services,
                         (const char *)idx_sync_peer_agent, (int64_t)time(NULL));
        // NODE_NETWORK gate (Core's limited-peer rule): a peer without service
        // bit 0 keeps only the last SERVE_BLOCK_WINDOW blocks (the pepenet
        // seed advertises NODE_NETWORK_LIMITED). If our fold is deeper behind
        // its claimed tip than that window, it cannot feed us — its answer to
        // our getblocks is pure silence, which reads as "caught up" and would
        // wedge this node at its checkpoint forever: connected, handshaken,
        // idle. Hold ONE such peer as a last resort and keep hunting for a
        // full-archive peer (the cached pool and the chain's DNS seeds).
        if (idx_sync_peer_height - height > SERVE_BLOCK_WINDOW &&
            !(idx_sync_peer_services & 1)) {
            fprintf(stderr, "  %s serves only recent blocks and we are %lld behind — seeking an archive peer\n",
                    picked, (long long)(idx_sync_peer_height - height));
            if (fb_fd < 0) {
                fb_fd = fd; snprintf(fb_picked, sizeof fb_picked, "%s", picked);
                fb_h = idx_sync_peer_height; fb_svc = (int64_t)idx_sync_peer_services;
                snprintf(fb_agent, sizeof fb_agent, "%s", (const char *)idx_sync_peer_agent);
            } else close(fd);
            fd = -1; continue;
        }
    }
    if (fd < 0 && fb_fd >= 0 && !idx_sync_stop) {
        // nothing better answered — take what the limited peer can give. While
        // we are deep behind that is nothing (the pass ends idle and the next
        // one hunts again); near the tip it serves us fully.
        fd = fb_fd; fb_fd = -1;
        snprintf(picked, sizeof picked, "%s", fb_picked);
        idx_sync_peer_height = fb_h; idx_sync_peer_services = (uint64_t)fb_svc;
        snprintf((char *)idx_sync_peer_agent, sizeof idx_sync_peer_agent, "%s", fb_agent);
        if (idx_sync_peer_height > 0) {   // a handshake claim, never below announced evidence
            int64_t ev = idx_peer_height_note(NULL, 0, 0, 0);
            idx_db_raise_peer_height(db, idx_sync_peer_height > ev ? idx_sync_peer_height : ev);  // db-monotonic
        }
        fprintf(stderr, "  no archive peer reachable — using limited peer %s\n", picked);
    }
    if (fb_fd >= 0) close(fb_fd);
    if (fd < 0) {
        // same teardown as every other exit: the serve store's sqlite handle,
        // the oracle feed and the fold state were leaked here on each pass
        // that found no peer (a daemon loop retrying a dead network grew
        // without bound). fb_fd is already closed above.
        fprintf(stderr, "no peer reachable (%d candidates)\n", nc);
        serve_store_close(fc.serve); oracle_free(oracle); sm_free(s); idx_db_close(db);
        return 1;
    }
    fprintf(stderr, "connected %s, syncing from height %lld (activation %lld, peer height %lld, agent %s)\n",
            picked, (long long)(height + 1), (long long)activation,
            (long long)idx_sync_peer_height, (const char *)idx_sync_peer_agent);
    net_send(fd, coin->magic, "getaddr", NULL, 0);   // harvest the peer's addr view

    int idle = 0;
    char vwhy[128];
    int64_t rdl = 0;            // getblocks round deadline: survives ping/addr `continue`s
    while (idle < 3 && !idx_sync_stop) {
        // getblocks: standard exponential locator over our stored chain, terminated
        // by the profile checkpoint — after a reorg past our tip the peer then finds
        // the deepest common ancestor instead of falling back to genesis.
        uint8_t loc[34][32]; int nloc = 0;
        memcpy(loc[nloc++], tip, 32);
        { int64_t step = 1, h = height;
          while (nloc < 32 && h - step > coin->start) {
              h -= step;
              if (idx_db_block_get(db, h, loc[nloc])) nloc++;
              if (nloc >= 10) step *= 2;
          }
          if (height > coin->start) memcpy(loc[nloc++], coin->start_hash, 32); }
        uint8_t gb[4 + 3 + 34*32 + 32]; int o = 0;
        for (int i = 0; i < 4; i++) gb[o++] = (70015 >> (8*i)) & 0xff;
        put_varint(gb, &o, (uint64_t)nloc);
        for (int i = 0; i < nloc; i++) { memcpy(gb + o, loc[i], 32); o += 32; }
        memset(gb + o, 0, 32); o += 32;                              // hash_stop
        net_send(fd, coin->magic, "getblocks", gb, (uint32_t)o);

        int got_any = 0;
        // collect block hashes from inv, request + fold each
        char cmd[13]; uint8_t *pl; uint32_t pl_len;
        if (!rdl) rdl = mono_ms() + IDX_SYNC_ROUND_MS;
        int r = net_recv_dl(fd, coin->magic, cmd, &pl, &pl_len, IDX_SYNC_ROUND_MS, rdl);
        if (r != 1) { if (r == -1) continue; idle++; rdl = 0; continue; }
        if (!strcmp(cmd, "ping")) { net_send(fd, coin->magic, "pong", pl, pl_len); free(pl); continue; }
        if (!strcmp(cmd, "addr")) { addr_harvest(db, pl, pl_len, 0); free(pl); continue; }
        if (strcmp(cmd, "inv") != 0) { free(pl); continue; }
        rdl = 0;                // an inv answers the round (idle or a batch follows)
        // parse inv: varint count, then [type(4)+hash(32)] — request blocks (type 2).
        // Bounds-check the count varint against pl_len before every read (a peer
        // controls these bytes). inv counts are ≤50000 (MAX_INV_SZ) so 0xFD+2 is the
        // only wide form that legitimately occurs; reject 0xFE/0xFF rather than OOB-read.
        if (pl_len < 1) { free(pl); continue; }
        int po = 0; uint64_t cnt = pl[po++];
        if (cnt == 0xFD) { if (pl_len < 3) { free(pl); continue; } cnt = pl[po] | (pl[po+1] << 8); po += 2; }
        else if (cnt >= 0xFE) { free(pl); continue; }
        uint8_t getd[3 + 36 * 600]; int go = 0; uint8_t want[600][32]; int nwant = 0;   // 3 = max varint prefix for ≤600
        for (uint64_t i = 0; i < cnt && (po + 36) <= (int)pl_len && nwant < 600; i++) {
            uint32_t type = pl[po] | (pl[po+1]<<8) | (pl[po+2]<<16) | ((uint32_t)pl[po+3]<<24); po += 4;
            const uint8_t *h = pl + po; po += 32;
            if (type == 2) { memcpy(want[nwant], h, 32); nwant++; }
        }
        free(pl);
        if (nwant == 0) { idle++; continue; }
        // build one getdata for all
        go = 0; put_varint(getd, &go, (uint64_t)nwant);
        for (int i = 0; i < nwant; i++) { getd[go++]=2; getd[go++]=0; getd[go++]=0; getd[go++]=0; memcpy(getd + go, want[i], 32); go += 32; }
        net_send(fd, coin->magic, "getdata", getd, (uint32_t)go);
        // receive nwant blocks (interleaved control messages tolerated, but
        // only inside the batch deadline — chatter no longer extends the wait)
        int recvd = 0;
        int64_t bdl = mono_ms() + (int64_t)IDX_SYNC_BATCH_DEADLINE_S * 1000;
        while (recvd < nwant && !idx_sync_stop) {
            r = net_recv_dl(fd, coin->magic, cmd, &pl, &pl_len, 15000, bdl);
            if (r != 1) {
                if (r == -1) continue;
                if (dl_passed(bdl)) {
                    fprintf(stderr, "peer %s stalled: %d of %d requested blocks within the %ds batch deadline — dropping peer\n",
                            picked, recvd, nwant, IDX_SYNC_BATCH_DEADLINE_S);
                    goto stalled_peer;
                }
                break;
            }
            if (!strcmp(cmd, "ping")) { net_send(fd, coin->magic, "pong", pl, pl_len); free(pl); continue; }
            if (!strcmp(cmd, "addr")) { addr_harvest(db, pl, pl_len, 0); free(pl); continue; }
            if (strcmp(cmd, "block") != 0) { free(pl); continue; }
            // Connect only a block that extends our tip (hashPrevBlock == tip) — the
            // peer's continue-inv pushes its TIP hash after a full 500-batch, and
            // fetching that would fold a ~tip-height block as height+1. A block whose
            // prev is one of our OLDER stored hashes is the peer's branch after a
            // reorg: roll back to that ancestor and connect. Anything else is dropped;
            // the next getblocks round re-anchors at our locator.
            if (pl_len < 80) { free(pl); recvd++; continue; }
            if (memcmp(pl + 4, tip, 32) != 0) {
                int64_t fork_h = idx_db_block_height_by_hash(db, pl + 4);
                if (fork_h < 0 || fork_h >= height) { free(pl); recvd++; continue; }
                // A block we ALREADY connected (peer tip echo after a full
                // batch, or a re-inv race on a fresh block) is not a reorg —
                // rolling back on it would refold the whole state for nothing.
                uint8_t bh[32], have[32];
                idx_sha256d(pl, 80, bh);
                if (idx_db_block_get(db, fork_h + 1, have) && !memcmp(bh, have, 32)) {
                    free(pl); recvd++; continue;
                }
                // validate BEFORE rolling back: a forged branch block must not
                // cost us a state refold, let alone the state itself
                if (!block_validate(db, coin, fork_h + 1, pl, pl_len, vwhy, sizeof vwhy)) {
                    fprintf(stderr, "invalid block for height %lld from %s: %s — abandoning peer\n",
                            (long long)(fork_h + 1), picked, vwhy);
                    free(pl);
                    goto invalid_peer;
                }
                // most-work gate: only reorg to a branch with strictly MORE
                // cumulative work than ours above the fork. A valid-but-lighter
                // fork (first-valid-peer-wins) must never rewrite the chain.
                { char rwhy[160] = "";
                  int ow = branch_outweighs(fd, coin, db, fork_h, pl + 4, height, rwhy, sizeof rwhy);
                  if (ow == -2) {
                      fprintf(stderr, "peer %s stalled in branch weigh: %s — dropping peer\n", picked, rwhy);
                      free(pl); goto stalled_peer;
                  }
                  if (ow < 0) {
                      fprintf(stderr, "reorg branch from %s invalid: %s — abandoning peer\n", picked, rwhy);
                      free(pl); goto invalid_peer;
                  }
                  if (ow == 0) {
                      fprintf(stderr, "reorg declined: peer branch at %lld not heavier than our tip %lld%s%s\n",
                              (long long)fork_h, (long long)height, rwhy[0] ? " — " : "", rwhy);
                      free(pl); recvd++; continue;              // keep our chain
                  } }
                fprintf(stderr, "reorg: peer branch at height %lld outweighs our tip %lld — rolling back\n",
                        (long long)fork_h, (long long)height);
                if (!idx_sync_rollback(&s, db, oracle, activation, fork_h)) {
                    // state is not trustworthy past a failed replay — bail hard
                    fprintf(stderr, "rollback replay failed — aborting sync\n");
                    free(pl); close(fd); serve_store_close(fc.serve); oracle_free(oracle); sm_free(s); idx_db_close(db); return 1;
                }
                fc.s = s;
                serve_store_prune_above(fc.serve, fork_h);   // drop stale served headers/blocks
                height = fork_h;
                if (!idx_db_block_get(db, height, tip)) memcpy(tip, coin->start_hash, 32);
                idx_db_save_sync(db, height, tip);
            }
            if (!block_validate(db, coin, height + 1, pl, pl_len, vwhy, sizeof vwhy)) {
                fprintf(stderr, "invalid block for height %lld from %s: %s — abandoning peer\n",
                        (long long)(height + 1), picked, vwhy);
                free(pl);
                goto invalid_peer;
            }
            if (connect_block(&fc, height + 1, pl, pl_len)) {
                height++;
                // the sync peer served this block: it is at least this high
                if (height > idx_sync_peer_height) idx_sync_peer_height = height;
                idx_peer_height_note(db, height, (int64_t)time(NULL), 0);
                int64_t hh; idx_db_load_sync(db, &hh, tip);   // refresh tip hash (hh == height)
                got_any = 1;
            }
            free(pl); recvd++;
        }
        idx_db_project(db, s);
        if (got_any) { idle = 0; fprintf(stderr, "  height %lld (%d txs folded)\n", (long long)height, fc.folded); }
        else idle++;
    }
    fprintf(stderr, "sync idle — caught up at height %lld\n", (long long)height);
    idx_peer_height_note(db, idx_sync_peer_height, (int64_t)time(NULL), 1);   // flush the rate-limited write
    if (idx_sync_peer_height > 0 && height >= idx_sync_peer_height)
        s_parity = time(NULL);          // hard parity, measured on a live socket
    idx_db_project(db, s);
    print_digest(s);
    idx_db_peers_prune(db, (int64_t)time(NULL), IDX_PEER_TTL_SECS, IDX_PEER_CAP);
    close(fd); serve_store_close(fc.serve); oracle_free(oracle); sm_free(s); idx_db_close(db);
    return 0;

invalid_peer:
    // the peer served a provably invalid block: everything further from it is
    // suspect. Demote it (the ladder stops preferring it), persist what folded
    // before the poison, and end the pass — the next pass dials someone else.
    idx_db_peer_bad(db, picked);
    idx_db_project(db, s);
    close(fd); serve_store_close(fc.serve); oracle_free(oracle); sm_free(s); idx_db_close(db);
    return 1;

stalled_peer:
    // never silent, never useful: the peer kept the socket busy past a batch or
    // weigh deadline without delivering what we asked for. Same exit as an
    // invalid peer (no invalidity is claimed): demote it so the ladder rotates
    // to another candidate, keep every block that already folded, end the pass.
    // A re-handshake re-proves it (peer_seen), so an honest peer loses nothing
    // but its place in the ladder.
    idx_db_peer_bad(db, picked);
    idx_db_project(db, s);
    close(fd); serve_store_close(fc.serve); oracle_free(oracle); sm_free(s); idx_db_close(db);
    return 1;
}

// ── serve: the inbound chain-wire presence (discovery slice 3, step 1) ────────
// A pepenet node is a first-class chain peer: it listens on the chain port,
// does the version handshake advertising our "/pepenet-" agent (so a crawler
// classifies it), answers getaddr from the peer table, harvests inbound addr,
// and ponds pings. This is what makes a node reachable + discoverable — it
// CLOSES the discovery loop (a crawl now finds a real dns-aware node). Chain
// data serving (NODE_NETWORK_LIMITED) and carrier gossip (dn* commands) bolt
// onto this same poll loop in later steps; for now services is advertised 0
// (honest: we serve no blocks yet — the agent string is the dns-aware marker).
#define SERVE_MAX_CONN 64
#define SERVE_MSG_MAX  IDX_MSG_MAX
// outbound slots we keep pointed at overlay (pepenet) peers drawn from the
// persisted dnet pool — the startup re-dial target. Well under SERVE_MAX_CONN so
// inbound + chain dial_peers keep ample room.
#define MESH_DIAL_SEATS 8
// inbound mesh_handle cap: the mark is a self-asserted user-agent, so a botnet
// of /pepenet- inbound must not fill SERVE_MAX_CONN and starve outbound seats.
#define MESH_INBOUND_MAX 16
// one failure-backoff window for every outbound seat kind (mesh + chain): a
// failed dial stamps last_try and the addr sits out this long before any
// topup offers it again (Core's GetChance decay, flattened to one step)
#define DIAL_RETRY_S    600
// never-connected dnet vouches (last_good=0) sit out this long after a fail.
// The 14-odd NAT/dead hints from a dnaddr used to re-seat every DIAL_RETRY_S
// and block the serve thread on 5s connects.
#define VOUCH_RETRY_S   3600
// re-ask a live marked peer for its overlay list this often. Handshake sends
// one dngetaddr; without a refresh the dnet pool freezes at that first answer
// and newly-discovered mesh peers never get a seat.
#define DNADDR_REFRESH_S 60
// liveness: a conn that never handshakes is cut at SHAKE; an established conn
// quiet past PING gets pinged; silent past DEAD it's dropped (Core: 2 min ping
// interval / 20 min timeout — tightened for a desktop node whose Peers page
// shouldn't show ghosts for long). Without this a peer that vanishes without a
// FIN (NAT expiry, sleep, crash) holds its slot forever — and each of its
// reconnects stacks a fresh conn next to the ghost.
#define SERVE_SHAKE_S   60
#define SERVE_PING_S    120
#define SERVE_DEAD_S    600
// per-host inbound BUDGET. A healthy peer legitimately shows up as one
// persistent conn (its serve plane's mesh seat) PLUS a brief transient (its
// pass-based sync dial or a crawl probe — those share a thread, never both at
// once). Budget both, with one seat of margin for a second node behind the
// same NAT or a closing transient still draining. At 1 this refused the sync
// pass of the very host whose mesh conn was parked on us — and on a small net
// (client + seed) that host has no other peer, so its sync starved until the
// mesh conn dropped and the two planes flapped forever. Still strict enough
// that one looping host can't eat the table (64 slots, 3 per host).
#define SERVE_INBOUND_PER_HOST 3
// outbound TCP connect budget (was blocking stop_poll 5000ms inside net_connect)
#define SERVE_CONNECT_S    5
// outbound version/verack budget after TCP is up (was serve_dial's 5×3000ms)
#define SERVE_DIAL_SHAKE_S 15

typedef struct {
    int fd;
    uint8_t *buf; size_t len, cap;    // accumulated inbound bytes (frames span reads)
    int up, sent_ver;
    int got_ver, got_verack;          // both required before up (legacy serve_dial)
    int connecting;                   // 1 = nonblocking TCP connect in progress
    time_t shake_by;                  // connect or outbound-handshake deadline
    uint8_t *out; size_t out_len, out_off, out_cap;  // queued complete frames
    int64_t peer_svc;                 // services from their version (applied at up)
    char peer[80];                    // remote ip:port (log + self-learn source)
    const uint8_t *magic;             // coin magic (the mesh send fn needs it)
    int  outbound;                    // dialed → keep the slot + redial
    char host[80]; uint16_t rport; time_t redial_at;
    char hip[46];                     // host's resolved numeric ip ("" till resolved).
                                      // THE seat identity: every dedup compares ips,
                                      // every dial connects to this. A hostname in
                                      // `host` (the configured seed) is only ever a
                                      // recipe for refreshing it — dns is a pre-step
                                      // of the dial, never a peer identity.
    time_t last_rx;                   // last byte received (liveness clock)
    time_t last_ping;                 // last ping we originated (idle probe)
    time_t last_pull;                 // last mesh getblocks we sent (tip pull)
    time_t last_dnget;                // last dngetaddr we sent (overlay refresh)
    char agent[128];                  // peer subver ("/pepenet-" ⇒ a mesh peer)
    int64_t peer_h;                   // peer's claimed start_height at handshake (0 unknown)
    void *mesh_handle;                // embedder's per-peer handle (NULL till peer_up)
    int  dn_asked;                    // we sent this pepenet peer a dngetaddr already
    int  got_dnaddr;                  // logged at least one dnaddr from this conn
    int  last_dnaddr_n;               // last harvested count (log only on change)
    int  self_sent;                   // we announced our own addr on this conn already
    int  mesh_seat;                   // outbound slot seated by overlay discovery
                                      // (idx_db_peers_dnet) — released if not pepenet
    int  chain_seat;                  // outbound slot seated by addrman-style selection
                                      // (chain_topup) — released on dial failure so the
                                      // next tick tries a different candidate
    int  feeler;                      // mesh seat probing a dnet=1 unconfirmed vouch
    int  score;                       // per-conn misbehavior; 100 → ban the IPv4
    int  mesh_kick;                   // the mesh carrier asked to close this conn (L6, no ban)
    time_t   gd_win_t;                // getdata 10 s window start
    int      gd_blocks;
    uint32_t gd_bytes;
} SConn;
static const IdxMeshHooks *g_serve_mesh;
static void conn_ip(const SConn *c, char *ip, size_t n) {
    if (c->hip[0]) { snprintf(ip, n, "%s", c->hip); return; }
    snprintf(ip, n, "%s", c->peer);
    char *col = strrchr(ip, ':'); if (col) *col = 0;
}
static int serve_send(SConn *c, const uint8_t *magic, const char *cmd,
                      const uint8_t *payload, uint32_t len);
// the mesh send fn handed to peer_up: emit a dn* command on this peer's conn
static void serve_mesh_send(void *peer, const char *cmd, const uint8_t *pay, size_t n) {
    SConn *sc = (SConn *)peer;
    if (sc->fd >= 0) serve_send(sc, sc->magic, cmd, pay, (uint32_t)n);
}
static void serve_drop(SConn *c, const IdxMeshHooks *mesh);
/* Serve sockets stay O_NONBLOCK. write_all/net_send must not be used on them:
 * EAGAIN after a partial send tears a header/payload on the wire. Queue whole
 * frames, flush on POLLOUT, drop the peer on hard error or overflow.
 *
 * SERVE_OUT_MAX is the userspace TX queue ceiling (not RSS):
 *   SERVE_MSG_MAX (2 MiB) + 24 + 64 KiB = 2162712 bytes (~2.06 MiB) per conn.
 * Arithmetic aggregate if all 64 seats held a full queue at once:
 *   64 * 2162712 ≈ 132 MiB of TX queue buffers. That is a worst-case
 * allocation ceiling, not measured resident set and not "free." Queues
 * grow via realloc only as bytes are actually queued, and are freed on
 * drop. Plus inbound recv buffers (capped at SERVE_MSG_MAX+1024 before
 * drop): a delayed slow reader can pin a large TX queue and an RX buffer
 * until overflow or timeout. Overflow / hard send failure drops that
 * peer. A legal multi-block reply that does not fit the remaining queue
 * therefore drops the peer rather than blocking accept or scheduling the
 * extra frames — compatibility with this queue design, not a new policy. */
#define SERVE_OUT_MAX (SERVE_MSG_MAX + 24u + 64u * 1024u)
int idx_serve_send_eagain;
int idx_serve_send_partial;
#ifdef IDX_SERVE_TEST
/* Compile-time test hook: production dnsd/indexerd are built without
 * IDX_SERVE_TEST, so startup cannot activate a send-buffer override.
 * The test binary passes -DIDX_SERVE_TEST and may set IDX_SERVE_TEST_SNDBUF. */
const char *idx_serve_inject_fail_cmd;
static void serve_apply_test_sndbuf(int fd) {
    const char *e = getenv("IDX_SERVE_TEST_SNDBUF");
    if (!e || !*e || fd < 0) return;
    int sz = atoi(e);
    if (sz > 0) setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
}
#else
static void serve_apply_test_sndbuf(int fd) { (void)fd; }
#endif
static void serve_bufs_clear(SConn *c) {
    if (!c) return;
    free(c->buf); c->buf = NULL; c->len = c->cap = 0;
    free(c->out); c->out = NULL; c->out_len = c->out_off = c->out_cap = 0;
}
static void serve_release_fd(SConn *c) {
    if (!c) return;
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    c->connecting = 0; c->up = 0; c->sent_ver = 0; c->got_ver = 0; c->got_verack = 0;
    c->shake_by = 0; c->peer_svc = 0;
    serve_bufs_clear(c);
}
static void serve_release_seat(SConn *c) {
    /* close + free in/out buffers; do not retain an outbound/feeler seat for redial */
    serve_release_fd(c);
    c->outbound = 0; c->mesh_seat = 0; c->chain_seat = 0; c->feeler = 0;
    c->host[0] = 0; c->hip[0] = 0; c->peer[0] = 0; c->agent[0] = 0;
    c->mesh_handle = NULL; c->peer_svc = 0;
}
static int serve_out_pending(const SConn *c) {
    return c && c->out_off < c->out_len;
}
static int serve_out_flush(SConn *c) {
    if (!c || c->fd < 0) return 0;
    while (c->out_off < c->out_len) {
        size_t left = c->out_len - c->out_off;
#ifdef MSG_NOSIGNAL
        ssize_t w = send(c->fd, c->out + c->out_off, left, MSG_NOSIGNAL);
#else
        ssize_t w = send(c->fd, c->out + c->out_off, left, 0);
#endif
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            idx_serve_send_eagain++;
            return 1;
        }
        if (w <= 0) return 0;
        if ((size_t)w < left) idx_serve_send_partial++;
        c->out_off += (size_t)w;
    }
    c->out_len = c->out_off = 0;
    return 1;
}
static int serve_out_append(SConn *c, const uint8_t *b, size_t n) {
    if (!c || !b || !n) return 0;
    if (c->out_off) {
        size_t pending = c->out_len - c->out_off;
        memmove(c->out, c->out + c->out_off, pending);
        c->out_len = pending; c->out_off = 0;
    }
    if (c->out_len + n > SERVE_OUT_MAX) return 0;
    if (c->out_len + n > c->out_cap) {
        size_t nc = c->out_cap ? c->out_cap : 2048;
        while (nc < c->out_len + n) nc *= 2;
        if (nc > SERVE_OUT_MAX) nc = SERVE_OUT_MAX;
        if (c->out_len + n > nc) return 0;
        uint8_t *nb = realloc(c->out, nc);
        if (!nb) return 0;
        c->out = nb; c->out_cap = nc;
    }
    memcpy(c->out + c->out_len, b, n);
    c->out_len += n;
    return 1;
}
static int serve_send(SConn *c, const uint8_t *magic, const char *cmd,
                      const uint8_t *payload, uint32_t len) {
    if (!c || c->fd < 0 || !magic || !cmd) return 0;
#ifdef IDX_SERVE_TEST
    if (idx_serve_inject_fail_cmd && !strcmp(cmd, idx_serve_inject_fail_cmd)) {
        idx_serve_inject_fail_cmd = NULL;
        serve_drop(c, g_serve_mesh);
        return 0;   /* same caller-visible result as overflow / hard fail */
    }
#endif
    size_t total = 24u + (size_t)len;
    size_t pending = c->out_len - c->out_off;
    if (pending + total > SERVE_OUT_MAX) { serve_drop(c, g_serve_mesh); return 0; }
    uint8_t hdr[24]; memset(hdr, 0, 24); memcpy(hdr, magic, 4);
    strncpy((char *)hdr + 4, cmd, 12);
    hdr[16] = (uint8_t)len; hdr[17] = (uint8_t)(len >> 8);
    hdr[18] = (uint8_t)(len >> 16); hdr[19] = (uint8_t)(len >> 24);
    uint8_t ck[32]; idx_sha256d(payload ? payload : (const uint8_t *)"", len, ck);
    memcpy(hdr + 20, ck, 4);
    if (!serve_out_append(c, hdr, 24)) { serve_drop(c, g_serve_mesh); return 0; }
    if (len && !serve_out_append(c, payload, len)) { serve_drop(c, g_serve_mesh); return 0; }
    if (!serve_out_flush(c)) { serve_drop(c, g_serve_mesh); return 0; }
    return 1;
}
static void sconn_reset(SConn *c) {   // wipe transient state, keep outbound redial info
    serve_bufs_clear(c);
    int ob = c->outbound, ms = c->mesh_seat, cs = c->chain_seat, fl = c->feeler;
    char host[80], hip[46]; uint16_t rp = c->rport;
    memcpy(host, c->host, sizeof host); memcpy(hip, c->hip, sizeof hip);
    c->fd = -1; c->up = c->sent_ver = c->got_ver = c->got_verack = 0;
    c->connecting = 0; c->shake_by = 0; c->peer_svc = 0;
    c->peer[0] = 0; c->agent[0] = 0; c->hip[0] = 0; c->peer_h = 0; c->mesh_handle = NULL; c->dn_asked = 0; c->mesh_seat = 0;
    c->self_sent = 0; c->chain_seat = 0; c->feeler = 0; c->score = 0; c->mesh_kick = 0;
    c->gd_win_t = 0; c->gd_blocks = 0; c->gd_bytes = 0;
    c->last_rx = 0; c->last_ping = 0; c->last_pull = 0;
    c->last_dnget = 0; c->got_dnaddr = 0; c->last_dnaddr_n = 0;
    c->outbound = ob; if (ob) { c->mesh_seat = ms; c->chain_seat = cs; c->feeler = fl;
        memcpy(c->host, host, sizeof c->host); memcpy(c->hip, hip, sizeof c->hip); c->rport = rp; c->redial_at = time(NULL) + 15; }
}
void serve_conn_misbehave(void *peer, int n, const char *why) {
    SConn *c = (SConn *)peer;
    if (!c || n <= 0) return;
    char ip[46]; conn_ip(c, ip, sizeof ip);
    if (!net_policy_score_add(&c->score, n)) {
        fprintf(stderr, "serve: misbehave %s +%d -> %d (%s)\n",
                ip[0] ? ip : c->peer, n, c->score, why ? why : "");
        return;
    }
    fprintf(stderr, "serve: ban %s score %d (%s)\n",
            ip[0] ? ip : c->peer, c->score, why ? why : "");
    if (ip[0]) net_policy_ban(ip, time(NULL));
    serve_drop(c, g_serve_mesh);
}
// transport hooks for the mesh carrier (indexer.h): `peer` is the pointer
// handed to peer_up; valid until peer_down. All three run on the serve thread.
size_t idx_serve_peer_pending(void *peer) {
    SConn *sc = (SConn *)peer;
    return sc->fd >= 0 && sc->out_len > sc->out_off ? sc->out_len - sc->out_off : 0;
}
void idx_serve_peer_kick(void *peer, const char *why) {
    SConn *sc = (SConn *)peer;
    if (sc->fd < 0 || sc->mesh_kick) return;
    sc->mesh_kick = 1;                               // closed right after the mesh tick; no ban, no score
    fprintf(stderr, "serve: %s dropped by the mesh carrier (%s)\n",
            sc->peer[0] ? sc->peer : "(peer)", why ? why : "-");
}
int idx_serve_peer_exempt(void *peer) {
    SConn *sc = (SConn *)peer;
    if (sc->outbound) return 1;                      // a seat we chose to dial
    return !strncmp(sc->peer, "127.", 4) || !strncmp(sc->peer, "::1", 3) || !sc->peer[0];
}
// close + notify the mesh (peer_down) if this was a live mesh peer
static void serve_drop(SConn *c, const IdxMeshHooks *mesh) {
    if (c->mesh_handle && mesh && mesh->peer_down) mesh->peer_down(mesh->ud, c->mesh_handle);
    if (c->fd >= 0) close(c->fd);
    sconn_reset(c);
}

// ── live status snapshots (indexer.h — an embedding host's Peers page) ───────
// Seqlock, not a mutex: one writer each (the serve loop / the crawl pass), so
// readers spin on the sequence instead of adding a pthread dependency to the
// headless CLI. Writer: seq++ (odd = mid-write), mutate, seq++ (even). Reader:
// copy, then retry if seq moved or was odd. Snapshots are tiny and 1 Hz.
static struct { volatile unsigned seq; int n; IdxServeConn c[SERVE_MAX_CONN]; } g_conns;
static struct { volatile unsigned seq; IdxCrawlStatus s; } g_crawl;

static void serve_snap(SConn *conns, int nconn, time_t now) {
    g_conns.seq++;
    int n = 0;
    for (int i = 0; i < nconn; i++) {
        SConn *c = &conns[i];
        if (c->fd < 0 && !c->outbound) continue;      // free slot
        IdxServeConn *o = &g_conns.c[n++];
        snprintf(o->peer, sizeof o->peer, "%s", c->peer);
        snprintf(o->host, sizeof o->host, "%s", c->host);
        o->rport = c->rport;
        snprintf(o->agent, sizeof o->agent, "%s", c->agent);
        o->connected = c->fd >= 0;
        o->up        = c->up;
        o->outbound  = c->outbound;
        o->mesh_seat = c->mesh_seat;
        o->mesh      = c->mesh_handle != NULL;
        o->peer_height = c->peer_h;
        o->redial_in = (c->fd < 0 && c->outbound && c->redial_at > now)
                     ? (int64_t)(c->redial_at - now) : 0;
    }
    g_conns.n = n;
    g_conns.seq++;
}

int idx_serve_conns(IdxServeConn *out, int max) {
    unsigned s1, s2;
    int n;
    do {
        s1 = g_conns.seq;
        n = g_conns.n;
        if (n > max) n = max;
        if (n > 0) memcpy(out, g_conns.c, (size_t)n * sizeof *out);
        s2 = g_conns.seq;
    } while (s1 != s2 || (s1 & 1));
    return n;
}

volatile int64_t idx_serve_stage_seq = 0;   // indexer.h — bumps per newly staged block

// 1 iff the serve plane OWNS a relationship with this dial target: a live conn
// whose remote ip matches, or an outbound seat (connected or parked) whose
// dial-target text matches. THE one-connection-per-peer rule (indexer.h):
// sync passes and tx broadcasts must never open a second socket to such a
// peer — everything they need from it rides the standing connection (stage
// push/pull, stage-side reorgs, mempool inv relay).
int idx_serve_peer_held(const char *target) {
    if (!target || !*target) return 0;
    char host[80]; snprintf(host, sizeof host, "%s", target);
    char *col = strrchr(host, ':');
    if (col && col[1] && strspn(col + 1, "0123456789") == strlen(col + 1)) *col = 0;
    size_t hl = strlen(host);
    IdxServeConn c[SERVE_MAX_CONN];
    int n = idx_serve_conns(c, SERVE_MAX_CONN);
    for (int i = 0; i < n; i++) {
        if (c[i].connected && c[i].peer[0] &&
            !strncmp(c[i].peer, host, hl) && c[i].peer[hl] == ':')
            return 1;
        if (c[i].outbound && c[i].host[0] && !strcmp(c[i].host, host))
            return 1;
    }
    return 0;
}

// Highest chain height any live serve-plane peer claimed at its handshake
// (indexer.h). With the stage, the sync pass's "am I at the network's tip
// without opening a socket" measure.
int64_t idx_serve_best_height(void) {
    IdxServeConn c[SERVE_MAX_CONN];
    int n = idx_serve_conns(c, SERVE_MAX_CONN);
    int64_t best = 0;
    for (int i = 0; i < n; i++)
        if (c[i].connected && c[i].up && c[i].peer_height > best) best = c[i].peer_height;
    return best;
}

void idx_crawl_status(IdxCrawlStatus *out) {
    unsigned s1, s2;
    do {
        s1 = g_crawl.seq;
        *out = g_crawl.s;
        s2 = g_crawl.seq;
    } while (s1 != s2 || (s1 & 1));
}

// one addr entry: time(4) services(8) ip(16, v4-mapped) port(2 BE). IPv4 only.
static int addr_entry(uint8_t *out, uint32_t *o, uint32_t cap,
                      const char *addr, int64_t services, int64_t t) {
    unsigned a, b, cc, d, port;
    if (sscanf(addr, "%u.%u.%u.%u:%u", &a, &b, &cc, &d, &port) != 5) return 0;
    if (a > 255 || b > 255 || cc > 255 || d > 255 || port > 65535) return 0;
    if (*o + 30 > cap) return 0;
    out[(*o)++] = (uint8_t)t; out[(*o)++] = (uint8_t)(t >> 8);
    out[(*o)++] = (uint8_t)(t >> 16); out[(*o)++] = (uint8_t)(t >> 24);
    for (int i = 0; i < 8; i++) out[(*o)++] = (uint8_t)(services >> (8 * i));
    for (int i = 0; i < 10; i++) out[(*o)++] = 0;
    out[(*o)++] = 0xFF; out[(*o)++] = 0xFF;
    out[(*o)++] = (uint8_t)a; out[(*o)++] = (uint8_t)b;
    out[(*o)++] = (uint8_t)cc; out[(*o)++] = (uint8_t)d;
    out[(*o)++] = (uint8_t)(port >> 8); out[(*o)++] = (uint8_t)port;
    return 1;
}

static int serve_build_version(uint8_t *v, int64_t our_height, int64_t services) {
    int o = 0;
    for (int i = 0; i < 4; i++) v[o++] = (70015 >> (8*i)) & 0xff;
    for (int i = 0; i < 8; i++) v[o++] = (services >> (8*i)) & 0xff;
    int64_t now = (int64_t)time(NULL); for (int i = 0; i < 8; i++) v[o++] = (now >> (8*i)) & 0xff;
    memset(v + o, 0, 26); o += 26;                                   // addr_recv
    memset(v + o, 0, 26); o += 26;                                   // addr_from
    uint64_t sn = self_nonce(); for (int i = 0; i < 8; i++) v[o++] = (uint8_t)(sn >> (8*i));  // nonce (self-connect guard)
    size_t ual = strlen(idx_sync_agent); if (ual > 100) ual = 100;
    v[o++] = (uint8_t)ual; memcpy(v + o, idx_sync_agent, ual); o += (int)ual;
    for (int i = 0; i < 4; i++) v[o++] = (our_height >> (8*i)) & 0xff;
    v[o++] = 1;                                                      // relay: we accept tx invs (mempool)
    return o;
}
static void serve_send_version(int fd, const Coin *coin, int64_t our_height, int64_t services) {
    uint8_t v[256]; int o = serve_build_version(v, our_height, services);
    net_send(fd, coin->magic, "version", v, (uint32_t)o);
}
static int serve_send_version_conn(SConn *c, const Coin *coin, int64_t our_height, int64_t services) {
    uint8_t v[256]; int o = serve_build_version(v, our_height, services);
    return serve_send(c, coin->magic, "version", v, (uint32_t)o);
}

// Overlay peer discovery (peer-discovery follow-up #1): dngetaddr / dnaddr.
// The host chain's addr gossip is subver-blind — it advertises IPs, not "this
// node speaks pepenet" — so a pepenet node otherwise finds its own kind only by
// chain-crawl luck + a hardcoded seed. These two ride the SAME chain wire as
// native commands (like getaddr/addr) but carry ONLY pepenet-aware peers: on
// handshake each side asks the other for its pepenet peer list, and the answer
// re-seats the dialer. Find one → find all. Native to the indexer (not the
// carrier mesh) so a standalone `serve`/dnsd participates with mesh == NULL.
#define SERVE_DNADDR_MAX 256
static void serve_send_dnaddr(SConn *c, const Coin *coin, sqlite3 *db,
                              const char *self, uint16_t port) {
    char pool[SERVE_DNADDR_MAX][80];
    int n = idx_db_peers_dnet_confirmed(db, pool, SERVE_DNADDR_MAX, 0);
    // advertise ourselves iff we listen and learned our external ip (a dial-only
    // node has neither, and correctly stays out of everyone's dnaddr)
    int adv_self = (port && self && *self) ? 1 : 0;
    int total = adv_self;
    for (int i = 0; i < n; i++) {
        if (self && *self && !strcmp(pool[i], self)) continue;
        total++;
    }
    if (total > SERVE_DNADDR_MAX) total = SERVE_DNADDR_MAX;
    uint8_t *out = malloc(3 + (size_t)SERVE_DNADDR_MAX * 30);
    if (!out) return;
    int vo = 0; put_varint(out, &vo, (uint64_t)total);
    uint32_t o = (uint32_t)vo; int put = 0;
    int64_t now = (int64_t)time(NULL);
    if (adv_self && put < total) put += addr_entry(out, &o, 3 + SERVE_DNADDR_MAX*30u, self, 1LL<<10, now);
    for (int i = 0; i < n && put < total; i++) {
        if (self && *self && !strcmp(pool[i], self)) continue;   // don't echo self twice
        put += addr_entry(out, &o, 3 + SERVE_DNADDR_MAX*30u, pool[i], 0, now);
    }
    serve_send(c, coin->magic, "dnaddr", out, o);
    free(out);
}

// Push our own addr (ONE entry) on this connection — Core's AdvertiseLocal.
// This is the only way a desktop node's address ever enters the host chain's
// addr gossip: core nodes never getaddr their INBOUND peers, so answering
// getaddr with self can't reach a node we dialed. Announce → the peer's
// addrman stores + relays it → another node's crawl harvests it → dials our
// chain port → reads the "/pepenet-" subver → the mesh finds itself. Gated
// on listening (port) + a learned external ip (version.addr_recv); actually
// REACHING the announced port is still the operator's port-forward.
static void serve_announce_self(SConn *c, const Coin *coin,
                                const char *self, int64_t services) {
    uint8_t out[3 + 30];
    int vo = 0;
    put_varint(out, &vo, 1);
    uint32_t o = (uint32_t)vo;
    if (!addr_entry(out, &o, sizeof out, self, services, (int64_t)time(NULL))) return;
    serve_send(c, coin->magic, "addr", out, o);
    fprintf(stderr, "serve: announced self %s to %s\n", self, c->peer);
}

static void serve_try_mesh_up(SConn *c, SConn *conns, const IdxMeshHooks *mesh, const char *via);

static void serve_dispatch(SConn *c, SConn *conns, const Coin *coin, sqlite3 *db, ServeStore *ss,
                           int64_t services, const char *cmd, uint8_t *pl, uint32_t pln,
                           char self[80], uint16_t port, const IdxMeshHooks *mesh) {
    // nothing but the handshake until both version and verack have landed
    // (c->up is set only when got_ver && got_verack) — otherwise
    // getdata/dnaddr/getaddr are a pre-auth bandwidth amp.
    if (!c->up && strcmp(cmd, "version") && strcmp(cmd, "verack")) return;
    if (!strcmp(cmd, "version")) {
        // a second version on a live conn must not flip the agent to /pepenet-
        // and steal a mesh slot
        if (c->up || c->got_ver) return;
        { uint64_t vn = 0;
          if (ver_nonce(pl, pln, &vn) && vn == self_nonce()) {
              fprintf(stderr, "serve: %s is ourselves (self-connect) — dropping self-seed\n",
                      c->peer[0] ? c->peer : (c->host[0] ? c->host : "(unknown)"));
              if (c->outbound && !c->chain_seat) idx_self_seed = 1;
              serve_release_seat(c);
              return;
          } }
        c->peer_svc = 0;
        if (pln >= 12) {
            uint64_t sv = 0; for (int b = 0; b < 8; b++) sv |= (uint64_t)pl[4 + b] << (8 * b);
            c->peer_svc = (int64_t)sv;
        }
        // learn our own address from their addr_recv (the ip THEY dialed) —
        // paired with our listen port, this is what we advertise as self
        if (!*self && pln >= 46 && pl[38] == 0xFF && pl[39] == 0xFF) {
            unsigned a = pl[40];
            if (ipv4_globally_routable(a, pl[41]) && c->outbound) {
                snprintf(self, 80, "%u.%u.%u.%u:%u", pl[40], pl[41], pl[42], pl[43], port);
                note_self_host(self);
                learn_self_ip(pl, pln);
                char sip[64]; snprintf(sip, sizeof sip, "%s", self);
                { char *sc = strrchr(sip, ':'); if (sc) *sc = 0; }
                idx_db_peers_drop_host(db, sip);
            }
        }
        // capture the peer's subver (agent) — "/pepenet-" marks a mesh peer —
        // and its claimed start_height (the varstr's tail), the serve plane's
        // own network-tip signal (idx_serve_best_height)
        { uint64_t off = 4+8+8+26+26+8, ua;
          if (pln > off) { ua = pl[off++];
              if (ua == 0xFD && pln >= off + 2) { ua = pl[off] | (pl[off+1] << 8); off += 2; }
              if (ua <= 100 && pln >= off + ua) { memcpy(c->agent, pl + off, ua); c->agent[ua] = 0; }
              if (ua <= 100 && pln >= off + ua + 4) {
                  uint64_t ho = off + ua;
                  c->peer_h = (int64_t)((uint32_t)pl[ho] | ((uint32_t)pl[ho+1] << 8) |
                                        ((uint32_t)pl[ho+2] << 16) | ((uint32_t)pl[ho+3] << 24));
              } } }
        if (!c->sent_ver) {
            int64_t h = 0; uint8_t tip[32]; idx_db_load_sync(db, &h, tip);
            if (!serve_send_version_conn(c, coin, h, services)) return;
            c->sent_ver = 1;
        }
        if (!serve_send(c, coin->magic, "verack", NULL, 0)) return;
        c->got_ver = 1;
        c->connecting = 0;
        /* peer_seen / mesh / dngetaddr / self-announce / unmarked-feeler only after verack too */
    } else if (!strcmp(cmd, "verack")) {
        c->got_verack = 1;
    }
    if ((!strcmp(cmd, "version") || !strcmp(cmd, "verack")) &&
        c->got_ver && c->got_verack && !c->up) {
        if (c->outbound && c->mesh_seat && !AGENT_MARKED(c->agent)) {
            idx_db_peer_tried(db, c->peer[0] ? c->peer : c->host, (int64_t)time(NULL));
            fprintf(stderr, "serve: feeler unmarked — release %s (agent %s)\n",
                    c->peer[0] ? c->peer : c->host, c->agent[0] ? c->agent : "(none)");
            serve_release_seat(c);
            return;
        }
        c->up = 1;
        c->connecting = 0;
        if (c->outbound) {
            if (c->peer[0]) idx_db_peer_seen(db, c->peer, c->peer_svc, c->agent, (int64_t)time(NULL));
            if (c->feeler) c->feeler = 0;
            fprintf(stderr, "serve: dialed %s (agent %s)%s%s\n", c->peer,
                    c->agent[0] ? c->agent : "(none)",
                    c->mesh_seat ? "  [mesh]" : "", c->chain_seat ? "  [chain]" : "");
        }
        if (!c->outbound)
            fprintf(stderr, "serve: inbound %s (agent %s)%s\n", c->peer,
                    c->agent[0] ? c->agent : "(none)",
                    AGENT_MARKED(c->agent) ? "  [mesh]" : "");
        // inbound marked: stamp agent on the listen-port row (not the ephemeral).
        // last_good stays 0 so we don't prefer dialing a NAT'd peer that found us.
        if (!c->outbound && AGENT_MARKED(c->agent) && c->peer[0]) {
            char ip[80]; snprintf(ip, sizeof ip, "%s", c->peer);
            { char *col = strrchr(ip, ':'); if (col) *col = 0; }
            if (ip[0]) idx_db_peer_touch_agent(db, ip, coin->port, c->agent, (int64_t)time(NULL));
        }
        // Outbound overlay dials may peer_up immediately: we opened this
        // socket from idx_serve, so it speaks dnz*. Inbound must wait until
        // the peer speaks dn* (see serve_try_mesh_up). A dual-instance
        // desktop's engine sync plane also presents a marked agent on a
        // dedicated inbound that has no overlay traffic; binding gossip to
        // that socket used to starve a later overlay inbound of dnzinv.
        // Unique-IP seating is intentionally not applied: two legitimate
        // overlay clients behind the same NAT are distinct admitted
        // connections. Gossip seats are bounded by MESH_INBOUND_MAX and by
        // already-accepted sockets (SERVE_INBOUND_PER_HOST), not by collapsing
        // every same-IP overlay peer into one slot.
        if (c->outbound)
            serve_try_mesh_up(c, conns, mesh, "dial");
        if (c->fd < 0) return;
        // overlay discovery (mesh-independent): solicit this marked peer's
        // overlay peer list. Handshake fires immediately; the serve loop
        // re-asks every DNADDR_REFRESH_S so a peer that later learns more
        // names actually grows our dnet pool.
        if (!c->dn_asked && AGENT_MARKED(c->agent)) {
            if (serve_send(c, coin->magic, "dngetaddr", NULL, 0)) {
                c->dn_asked = 1;
                c->last_dnget = time(NULL);
            }
            if (c->fd < 0) return;   /* drop reset the seat; do not stamp it */
        }
        // self-announcement (see serve_announce_self) — once per connection
        if (port && *self && !c->self_sent) {
            serve_announce_self(c, coin, self, services);
            c->self_sent = 1;
        }
        return;
    }
    if (!strcmp(cmd, "version") || !strcmp(cmd, "verack")) return;
    if (!strcmp(cmd, "dngetaddr")) {
        // overlay addr gossip is not chain-authenticated. Only a marked peer
        // (the same gate as mesh_handle) may ask or vouch — a random
        // pepetoshi otherwise poisons dnet=1 and we re-gossip the poison.
        if (!AGENT_MARKED(c->agent)) return;
        // Mark is an advertised subver prefix, not an authenticated identity.
        // Seating here (and on any other dn*) happens before zone-payload
        // ECDSA; dnaddr harvest is similarly mark-gated only. Existing bounded
        // risk: a peer that forges the prefix can take a mesh slot and inject
        // overlay addrs. Zone ops still fail admit without a valid signature.
        serve_try_mesh_up(c, conns, mesh, "dngetaddr");
        if (c->fd < 0) return;
        serve_send_dnaddr(c, coin, db, self, port);
    } else if (!strcmp(cmd, "dnaddr")) {
        if (!AGENT_MARKED(c->agent)) return;
        serve_try_mesh_up(c, conns, mesh, "dnaddr");
        if (c->fd < 0) return;
        { uint64_t cnt; uint32_t o;
          if (!net_policy_read_count(pl, pln, &cnt, &o)) return;
          if (cnt > IDX_MAX_ADDR) { serve_conn_misbehave(c, 20, "dnaddr count"); return; } }
        int n = addr_harvest(db, pl, pln, 1);                // vouched pepenet peers → dnet pool
        if (!c->got_dnaddr || n != c->last_dnaddr_n) {
            fprintf(stderr, "serve: dnaddr %d overlay peer(s) from %s\n", n, c->peer);
            c->got_dnaddr = 1;
            c->last_dnaddr_n = n;
        }
    } else if (!strncmp(cmd, "dn", 2) && cmd[2] && mesh && mesh->peer_msg) {
        if (!c->mesh_handle) serve_try_mesh_up(c, conns, mesh, cmd);
        if (c->fd < 0) return;
        if (c->mesh_handle)
            mesh->peer_msg(mesh->ud, c->mesh_handle, cmd + 2, pl, (int)pln);   // carrier dn* command
    } else if (!strcmp(cmd, "ping")) {
        serve_send(c, coin->magic, "pong", pl, pln);
    } else if (!strcmp(cmd, "getaddr")) {
        IdxPeerRow *rows = malloc(sizeof(IdxPeerRow) * 1000);
        if (!rows) return;
        int n = idx_db_peers_rows(db, rows, 1000);
        uint8_t *out = malloc(3 + 1001u * 30);
        if (!out) { free(rows); return; }
        int total = n + (*self ? 1 : 0); if (total > 1000) total = 1000;
        int vo = 0; put_varint(out, &vo, (uint64_t)total);
        uint32_t o = (uint32_t)vo;
        int64_t now = (int64_t)time(NULL); int put = 0;
        if (*self && put < total) put += addr_entry(out, &o, 3 + 1001u*30, self, 0, now);
        for (int i = 0; i < n && put < total; i++)
            put += addr_entry(out, &o, 3 + 1001u*30, rows[i].addr, rows[i].services, rows[i].last_seen);
        serve_send(c, coin->magic, "addr", out, o);
        free(out); free(rows);
    } else if (!strcmp(cmd, "addr")) {
        { uint64_t cnt; uint32_t o;
          if (!net_policy_read_count(pl, pln, &cnt, &o)) return;
          if (cnt > IDX_MAX_ADDR) { serve_conn_misbehave(c, 20, "addr count"); return; } }
        addr_harvest(db, pl, pln, 0);   // chain addr gossip — no overlay mark
    } else if (!strcmp(cmd, "getheaders") && ss) {
        // version(4) + varint nloc + nloc*32 locator (newest→oldest) + hash_stop(32)
        if (pln < 5) return;
        uint32_t o = 4; uint64_t nloc = pl[o++];
        if (nloc == 0xFD) { if (pln < o + 2) return; nloc = pl[o] | (pl[o+1] << 8); o += 2; }
        else if (nloc >= 0xFE) return;
        if (nloc > 2000) { serve_conn_misbehave(c, 10, "getheaders nloc"); return; }
        if (o + nloc * 32 + 32 > pln) return;
        int64_t start = serve_store_locate(ss, pl + o, (int)nloc);   // -1 → from earliest
        uint8_t *out = malloc(3 + 2000u * 81);
        if (!out) return;
        uint8_t hbuf[2000 * 80]; int nh = 0;
        serve_store_headers_from(ss, start, hbuf, sizeof hbuf, 2000, &nh);
        int vo = 0; put_varint(out, &vo, (uint64_t)nh);
        uint32_t oo = (uint32_t)vo;
        for (int i = 0; i < nh; i++) { memcpy(out + oo, hbuf + i * 80, 80); oo += 80; out[oo++] = 0x00; }  // 0 tx count
        if (nh) serve_send(c, coin->magic, "headers", out, oo);
        free(out);
    } else if (!strcmp(cmd, "getblocks") && ss) {
        // the sync path's forward walk (getblocks → inv → getdata → block) —
        // what a peer's per-pass sync actually speaks at us. Answer with the
        // block hashes above its deepest locator match, but ONLY while the raw
        // blocks are still inside our window: a limited node must serve the
        // whole run or stay silent, because a gapped inv would feed the
        // requester blocks its sequential fold can't connect (it would read as
        // an invalid peer and abandon us). Silence = "can't help / caught up",
        // exactly what the requester's ladder expects — it gates deep sync on
        // NODE_NETWORK and only leans on us near the tip.
        if (pln < 5) return;
        uint32_t o = 4; uint64_t nloc = pl[o++];
        if (nloc == 0xFD) { if (pln < o + 2) return; nloc = pl[o] | (pl[o+1] << 8); o += 2; }
        else if (nloc >= 0xFE) return;
        if (nloc > 2000) { serve_conn_misbehave(c, 10, "getblocks nloc"); return; }
        if (o + nloc * 32 + 32 > pln) return;
        int64_t start = serve_store_locate(ss, pl + o, (int)nloc);   // -1 = no common block: stay silent
        int64_t wfloor = serve_store_win_floor(ss);
        if (start < 0 || wfloor < 0 || start + 1 < wfloor) return;
        uint8_t (*hs)[32] = malloc(500 * 32);
        if (!hs) return;
        int nh = serve_store_hashes_from(ss, start, hs, 500);
        if (nh > 0) {
            uint8_t *out = malloc(3 + 500u * 36);
            if (out) {
                int vo = 0; put_varint(out, &vo, (uint64_t)nh);
                uint32_t oo = (uint32_t)vo;
                for (int i = 0; i < nh; i++) {
                    out[oo++] = 2; out[oo++] = 0; out[oo++] = 0; out[oo++] = 0;   // MSG_BLOCK
                    memcpy(out + oo, hs[i], 32); oo += 32;
                }
                serve_send(c, coin->magic, "inv", out, oo);
                free(out);
            }
        }
        free(hs);
    } else if (!strcmp(cmd, "getdata")) {
        uint64_t cnt; uint32_t o;
        if (!net_policy_read_count(pl, pln, &cnt, &o)) return;
        if (cnt > IDX_MAX_INV_SZ) { serve_conn_misbehave(c, 20, "getdata count"); return; }
        int examined = 0;
        time_t now = time(NULL);
        int skip_log = 0;
        for (uint64_t i = 0; i < cnt && o + 36 <= pln; i++, o += 36) {
            if (!net_policy_getdata_items_ok(examined)) break;
            examined++;
            uint32_t type = pl[o] | (pl[o+1]<<8) | (pl[o+2]<<16) | ((uint32_t)pl[o+3]<<24);
            if (type == 2 && ss) {                         // block (type 2) — from the serve store
                uint8_t *raw; size_t rl;
                if (serve_store_block(ss, pl + o + 4, &raw, &rl)) {
                    if (!net_policy_getdata_ok(&c->gd_blocks, &c->gd_bytes, &c->gd_win_t,
                                              now, 1, (uint32_t)rl)) {
                        free(raw);
                        if (!skip_log) {
                            fprintf(stderr, "serve: getdata budget %s blocks=%d bytes=%u\n",
                                    c->peer, c->gd_blocks, c->gd_bytes);
                            skip_log = 1;
                        }
                        break;
                    }
                    serve_send(c, coin->magic, "block", raw, (uint32_t)rl);
                    free(raw);
                }
            } else if (type == 1) {                        // tx (type 1) — from the mempool
                size_t rl; uint8_t *raw = mempool_get_copy(pl + o + 4, &rl);
                if (raw) {
                    if (!net_policy_getdata_ok(&c->gd_blocks, &c->gd_bytes, &c->gd_win_t,
                                              now, 0, (uint32_t)rl)) {
                        free(raw);
                        break;
                    }
                    serve_send(c, coin->magic, "tx", raw, (uint32_t)rl);
                    free(raw);
                }
            }
        }
    } else if (!strcmp(cmd, "inv")) {
        // a peer advertises inventory. Tx invs (type 1) we don't have → pull
        // for the mempool. Block invs (type 2) we don't know → pull into the
        // blockstage for the sync pass (sync-over-one-connection): the fold
        // stays on the sync side, this thread only ferries bytes off the
        // mesh line so no second socket is ever needed to follow the tip.
        uint64_t cnt; uint32_t o;
        if (!net_policy_read_count(pl, pln, &cnt, &o)) return;
        if (cnt > IDX_MAX_INV_SZ) { serve_conn_misbehave(c, 20, "inv count"); return; }
        uint8_t want[128][32]; int nreq = 0;
        uint8_t wblk[16][32]; int nblk = 0;
        for (uint64_t i = 0; i < cnt && o + 36 <= pln; i++, o += 36) {
            uint32_t type = pl[o] | (pl[o+1]<<8) | (pl[o+2]<<16) | ((uint32_t)pl[o+3]<<24);
            const uint8_t *h = pl + o + 4;
            if (type == 1 && nreq < 128) {
                if (mempool_has(h) || mempool_seen(h)) continue;
                memcpy(want[nreq++], h, 32);
            } else if (type == 2 && nblk < 16 && ss && c->up) {
                if (serve_store_have(ss, h)) {                 // headers or stage: known
                    serve_peer_announced(&c->peer_h, db, serve_store_locate(ss, h, 1));
                    continue;
                }
                memcpy(wblk[nblk++], h, 32);
            }
        }
        if (nreq + nblk) {
            uint8_t getd[3 + 36 * (128 + 16)]; int go = 0; put_varint(getd, &go, (uint64_t)(nreq + nblk));
            for (int i = 0; i < nreq; i++) { getd[go++]=1; getd[go++]=0; getd[go++]=0; getd[go++]=0; memcpy(getd + go, want[i], 32); go += 32; }
            for (int i = 0; i < nblk; i++) { getd[go++]=2; getd[go++]=0; getd[go++]=0; getd[go++]=0; memcpy(getd + go, wblk[i], 32); go += 32; }
            serve_send(c, coin->magic, "getdata", getd, (uint32_t)go);
        }
    } else if (!strcmp(cmd, "block")) {
        // a block body off a serve conn (answer to the inv-pull above, or an
        // unsolicited push): park it in the stage. Validation, folding and
        // reorg judgment all stay on the sync side — this thread never even
        // parses past the header. stage_put caps + ages the table, so junk
        // from a hostile peer costs bounded disk and zero state.
        if (!ss || pln < 80) return;
        uint8_t bh[32]; idx_sha256d(pl, 80, bh);
        { int64_t ph = serve_store_locate(ss, pl + 4, 1);       // prev on our chain → its height + 1
          if (ph >= 0) serve_peer_announced(&c->peer_h, db, ph + 1); }
        if (serve_store_stage_put(ss, bh, pl + 4, pl, pln, (int64_t)time(NULL)))
            idx_serve_stage_seq++;               // embedding hosts: fold-on-inv nudge
    } else if (!strcmp(cmd, "headers")) {
        // a header announcement (BIP130 peers). Only headers already on our
        // chain count (their height is known and their work was checked when
        // they folded) — an unverified run above our tip proves nothing, and
        // the block itself is placed when it arrives. Parsing stops at the
        // first AuxPoW header (variable length). Only peer_height learns.
        uint64_t cnt; uint32_t o;
        if (!ss || !net_policy_read_count(pl, pln, &cnt, &o) || cnt == 0 || cnt > 2000) return;
        int64_t best = -1;
        for (uint64_t i = 0; i < cnt && o + 81 <= pln; i++, o += 81) {
            uint32_t ver = pl[o] | (pl[o+1]<<8) | (pl[o+2]<<16) | ((uint32_t)pl[o+3]<<24);
            uint8_t hh[32]; idx_sha256d(pl + o, 80, hh);
            int64_t hgt = serve_store_locate(ss, hh, 1);
            if (hgt < 0) { int64_t pv = serve_store_locate(ss, pl + o + 4, 1); if (pv >= 0) hgt = pv + 1; }
            if (hgt > best) best = hgt;
            if (ver & 0x100) break;                        // AuxPoW follows: stride unknown
        }
        if (best > 0) serve_peer_announced(&c->peer_h, db, best);
    } else if (!strcmp(cmd, "tx")) {
        // validate + pool + relay. On accept, announce (inv type 1) to every other
        // live peer — the receiver's own has/seen guard breaks the echo loop.
        uint8_t txid[32]; char why[128];
        if (mempool_accept(pl, pln, txid, why, sizeof why)) {
            uint8_t inv[3 + 36]; int io = 0; put_varint(inv, &io, 1);
            inv[io++]=1; inv[io++]=0; inv[io++]=0; inv[io++]=0; memcpy(inv + io, txid, 32); io += 32;
            for (int i = 0; i < SERVE_MAX_CONN; i++) {
                SConn *o = &conns[i];
                if (o->fd >= 0 && o->up && o != c) serve_send(o, o->magic ? o->magic : coin->magic, "inv", inv, (uint32_t)io);
            }
        }
    } else if (!strcmp(cmd, "mempool")) {
        // answer with an inv of our whole pool (BIP35). Bounded to one message.
        uint8_t (*ids)[32] = malloc(sizeof *ids * 1000);
        if (!ids) return;
        size_t n = mempool_txids(ids, 1000);
        if (n) {
            uint8_t *inv = malloc(3 + n * 36);
            if (inv) { int io = 0; put_varint(inv, &io, (uint64_t)n);
                for (size_t i = 0; i < n; i++) { inv[io++]=1; inv[io++]=0; inv[io++]=0; inv[io++]=0; memcpy(inv + io, ids[i], 32); io += 32; }
                serve_send(c, coin->magic, "inv", inv, (uint32_t)io); free(inv); }
        }
        free(ids);
    }
    // dn* carrier commands: step 3
}

static int conn_host_live(SConn *conns, const SConn *except, const char *host);
// Start a nonblocking TCP connect to an already-resolved numeric seat (hip).
// Handshake (WE speak first) runs on the serve poll loop via serve_dispatch —
// the same path inbound peers use — so a slow/blackhole outbound cannot stall
// accept() or EOF cleanup. Returns 1 if connect completed immediately, 0 if
// EINPROGRESS, -1 on failure. Does not change wire bytes.
static void serve_outbound_fail(SConn *c, sqlite3 *db, time_t now) {
    serve_release_fd(c);
    c->agent[0] = 0; c->peer[0] = 0; c->mesh_handle = NULL;
    if (c->chain_seat || c->mesh_seat) {
        char addr[96]; snprintf(addr, sizeof addr, "%s:%u", c->host[0] ? c->host : c->hip, c->rport);
        if (db) idx_db_peer_tried(db, addr, (int64_t)now);
        if (c->mesh_seat)
            fprintf(stderr, "serve: dial %s failed  [mesh]\n", addr);
        c->outbound = 0; c->mesh_seat = 0; c->chain_seat = 0; c->feeler = 0;
        c->host[0] = 0; c->hip[0] = 0;
    } else {
        c->redial_at = now + 15;
    }
}
static int serve_start_connect(SConn *c) {
    if (!c || !c->hip[0] || !c->rport) return -1;
    char ps[8]; snprintf(ps, sizeof ps, "%u", c->rport);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_NUMERICHOST;
    if (getaddrinfo(c->hip, ps, &hints, &res) != 0 || !res) return -1;
    int fd = -1, imm = 0;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        sock_nosigpipe(fd);
        int fl = fcntl(fd, F_GETFL, 0);
        if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        serve_apply_test_sndbuf(fd);
        int r = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (r == 0) { imm = 1; break; }
        if (r < 0 && errno == EINPROGRESS) { imm = 0; break; }
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return -1;
    serve_bufs_clear(c);
    c->fd = fd; c->connecting = 1; c->up = 0; c->sent_ver = 0;
    c->got_ver = 0; c->got_verack = 0; c->peer_svc = 0;
    c->last_rx = time(NULL);
    c->shake_by = c->last_rx + SERVE_CONNECT_S;
    return imm ? 1 : 0;
}
static int serve_connect_ready(SConn *c, SConn *conns, const Coin *coin, sqlite3 *db,
                              int64_t services) {
    int err = 0; socklen_t el = sizeof err;
    if (c->fd < 0) return -1;
    if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) return -1;
    c->connecting = 0;
    c->magic = coin->magic;
    net_peer_str(c->fd, c->peer, sizeof c->peer);
    char pip[80]; snprintf(pip, sizeof pip, "%s", c->peer);
    { char *pc = strrchr(pip, ':'); if (pc) *pc = 0; }
    if (pip[0] && pip[0] != '?') snprintf(c->hip, sizeof c->hip, "%s", pip);
    if (pip[0] && pip[0] != '?' && conn_host_live(conns, c, pip)) {
        fprintf(stderr, "serve: %s is %s — already connected, dropping duplicate\n",
                c->host, c->peer);
        serve_release_fd(c);
        if (c->mesh_seat || c->chain_seat) {
            c->outbound = 0; c->mesh_seat = 0; c->chain_seat = 0; c->feeler = 0;
            c->host[0] = 0; c->hip[0] = 0;
        } else c->redial_at = time(NULL) + 60;
        return 0;
    }
    int64_t our_h = 0; uint8_t tip[32];
    if (db) idx_db_load_sync(db, &our_h, tip);
    if (!serve_send_version_conn(c, coin, our_h, services)) return -1;
    c->sent_ver = 1;
    c->last_rx = time(NULL);
    c->shake_by = c->last_rx + SERVE_DIAL_SHAKE_S;
    return 1;
}

// Bind gossip to a connection only after the peer speaks dn* on it (inbound)
// or immediately for outbound dials we initiated. Engine-sync inbounds advertise
// the same marked desktop agent but never send dngetaddr/dnz*; overlay sockets
// do. Do not unique-IP-collapse seats: each already-admitted connection that
// speaks dn* may take one gossip handle, still capped by MESH_INBOUND_MAX
// (inbound) and SERVE_INBOUND_PER_HOST (accept). Classification (marked + dn*)
// stays distinct from zone-op signature validation in sp_state_admit.
static void serve_try_mesh_up(SConn *c, SConn *conns, const IdxMeshHooks *mesh, const char *via) {
    if (!c || !mesh || !mesh->peer_up || c->mesh_handle || !AGENT_MARKED(c->agent)) return;
    int in_mesh = 0;
    if (!c->outbound) {
        for (int i = 0; i < SERVE_MAX_CONN; i++)
            if (conns[i].fd >= 0 && !conns[i].outbound && conns[i].mesh_handle)
                in_mesh++;
        if (in_mesh >= MESH_INBOUND_MAX) return;
    }
    void *h = mesh->peer_up(mesh->ud, c, serve_mesh_send);
    if (!h) return;
    /* peer_up may synchronously send (dnsnet_up → send_inv_all → dnzinv).
     * A send failure serve_drop's this SConn while mesh_handle is still
     * NULL, so serve_drop cannot peer_down. Attaching `h` after that reset
     * parks a live dnsnet Peer on a wiped slot; accept's memset then loses
     * the handle without peer_down, and later AE/announce can send through
     * the reused SConn. Transactional completion: if the callback dropped
     * or replaced this conn, release `h` and never attach. */
    if (c->fd < 0 || !c->up) {
        if (mesh->peer_down) mesh->peer_down(mesh->ud, h);
        return;
    }
    c->mesh_handle = h;
    // Real seat signal (peer_up / dnsnet_up). Distinct from the
    // version-handshake "inbound … [mesh]" classifier, which fires
    // before this and also tags engine-sync inbounds.
    fprintf(stderr, "serve: mesh seated %s (agent %s)%s via %s\n",
            c->peer, c->agent[0] ? c->agent : "(none)",
            c->outbound ? "  [out]" : "  [in]",
            via && via[0] ? via : "?");
}
// is any slot (other than `except`) already pointed at this machine? Live
// sockets compare by peer ip — the port always differs across directions (an
// inbound conn arrives from an ephemeral port, the pool row names the listen
// port), so an ip:port equality check can never see that they're the same
// machine. Disconnected seats compare by their resolved identity (hip) first,
// then the raw host text — so the configured seed's numeric addr row and the
// hostname seat read as ONE peer once either has resolved.
// One connection per machine is Core's rule too (ConnectNode → FindNode by
// CNetAddr): if a peer is connected — EITHER direction — we don't also dial
// it. That's what keeps an outbound-only (NAT'd) peer that dialed us in from
// being redialed forever off its own dnaddr self-announce.
static int conn_host_live(SConn *conns, const SConn *except, const char *host) {
    for (int i = 0; i < SERVE_MAX_CONN; i++) {
        SConn *c = &conns[i];
        if (c == except) continue;
        if (c->fd >= 0 && c->peer[0]) {
            char ip[80]; snprintf(ip, sizeof ip, "%s", c->peer);
            char *col = strrchr(ip, ':'); if (col) *col = 0;
            if (!strcmp(ip, host)) return 1;
        }
        if (c->fd < 0 && c->outbound &&
            ((c->hip[0]  && !strcmp(c->hip,  host)) ||
             (c->host[0] && !strcmp(c->host, host)))) return 1;
    }
    return 0;
}
// point an outbound seat at a dial target. A numeric target is its own dial
// identity immediately; a hostname target starts unresolved (hip "") and the
// dial loop resolves it per attempt.
static void seat_point(SConn *c, const char *host, uint16_t rp) {
    snprintf(c->host, sizeof c->host, "%s", host);
    c->rport = rp; c->redial_at = 0; c->hip[0] = 0;
    unsigned char a4[4]; struct in6_addr a6;
    if (inet_pton(AF_INET, host, a4) == 1 || inet_pton(AF_INET6, host, &a6) == 1)
        snprintf(c->hip, sizeof c->hip, "%s", host);
}
static int same_group16(const char *a, const char *b);   /* eclipse: one outbound /16 */
// Keep up to `target` outbound slots pointed at overlay peers from the persisted
// dnet pool. This is BOTH the startup re-dial (a returning node re-embeds into
// the mesh from its own memory) and the live reaction to freshly-gossiped
// dnaddr peers. ONE candidate per tick — same discipline as chain_topup:
// outbound dials share this thread's poll loop, and seating a swamp of dead vouched
// addrs at once stalled gossip and hid new discoveries behind minutes of
// connect/handshake timeouts.
static int mesh_try_seat(SConn *conns, int slot, const Coin *coin, const char *self,
                         char pool[][80], int n, int feeler) {
    time_t now = time(NULL);
    for (int i = 0; i < n; i++) {
        char host[80]; uint16_t rp; peer_split(pool[i], host, sizeof host, &rp, coin->port);
        if (conn_host_live(conns, NULL, host)) continue;
        if (host_is_self(host, self)) continue;
        if (net_policy_banned(host, now)) continue;
        int clash = 0;
        for (int k = 0; k < SERVE_MAX_CONN && !clash; k++)
            if (conns[k].mesh_seat && conns[k].host[0] && same_group16(conns[k].host, host))
                clash = 1;
        if (clash) continue;
        memset(&conns[slot], 0, sizeof conns[slot]);
        conns[slot].fd = -1; conns[slot].outbound = 1; conns[slot].mesh_seat = 1;
        conns[slot].feeler = feeler ? 1 : 0;
        seat_point(&conns[slot], host, rp);
        fprintf(stderr, "serve: seating %s %s:%u\n", feeler ? "feeler" : "mesh", host, rp);
        return 1;
    }
    return 0;
}
static void mesh_seat_topup(SConn *conns, sqlite3 *db, const Coin *coin, int target,
                            const char *self) {
    int seated = 0, tried = 0, feeler = 0, slot = -1;
    for (int i = 0; i < SERVE_MAX_CONN; i++) {
        if (conns[i].mesh_seat) {
            seated++;
            if (conns[i].feeler) feeler++;
            else tried++;
        } else if (slot < 0 && conns[i].fd < 0 && !conns[i].outbound) slot = i;
    }
    if (seated >= target || slot < 0) return;
    char pool[64][80];
    int64_t now = (int64_t)time(NULL);
    /* fill tried first (up to 7); never occupy every seat with unconfirmed vouches */
    if (tried < MESH_DIAL_SEATS - 1) {
        int n = idx_db_peers_dnet_confirmed(db, pool, 64, now - DIAL_RETRY_S);
        if (mesh_try_seat(conns, slot, coin, self, pool, n, 0)) return;
    }
    if (!feeler) {
        int n = idx_db_peers_dnet_new(db, pool, 64, now - VOUCH_RETRY_S);
        mesh_try_seat(conns, slot, coin, self, pool, n, 1);
    }
}

// Dogecoin-Core-style outbound maintenance (addrman-lite): keep up to
// CHAIN_DIAL_TARGET outbound chain connections beyond the mesh seats.
// Selection mirrors AddrMan::Select at desk scale: alternate proven ("tried",
// last_good>0, freshest-proven first) and unproven ("new", harvested
// NODE_NETWORK addrs, random order) — Core's ~50/50 — then filter: failure
// backoff (an addr whose last try didn't land a handshake sits out
// DIAL_RETRY_S), one outbound per /16 netgroup (Core's eclipse defense),
// never a host already connected or seated, never ourselves (we self-announce,
// so our own addr comes back in the harvest). ONE candidate seated per tick:
// one candidate per tick keeps seating bounded, so a swamp of dead addrs must not stall
// the loop — a failed dial stamps last_try and frees the seat.
#define CHAIN_DIAL_TARGET 8
// IPv4 /16 netgroup equality on "a.b.c.d[:port]" text (Core buckets by /16;
// a hostname never matches an ip, which is the right miss).
static int same_group16(const char *a, const char *b) {
    int dots = 0;
    for (size_t i = 0; a[i] && b[i]; i++) {
        if (a[i] != b[i]) return 0;
        if (a[i] == '.' && ++dots == 2) return 1;
    }
    return 0;
}
static void chain_topup(SConn *conns, sqlite3 *db, const Coin *coin, const char *self) {
    int have = 0, slot = -1;
    for (int i = 0; i < SERVE_MAX_CONN; i++) {
        SConn *c = &conns[i];
        if (c->outbound && !c->mesh_seat) have++;
        else if (slot < 0 && c->fd < 0 && !c->outbound) slot = i;
    }
    if (have >= CHAIN_DIAL_TARGET || slot < 0) return;
    static int flip = 0;                   // tried/new alternation (Core's ~50/50)
    int start = flip++ & 1;                // 0 → lead with tried; other class as fallback
    int64_t now = (int64_t)time(NULL);
    IdxPeerSel cand[32];
    for (int half = 0; half < 2; half++) {
        int n = idx_db_peers_select(db, cand, 32, ((start + half) & 1) == 0);
        for (int i = 0; i < n; i++) {
            IdxPeerSel *p = &cand[i];
            if (p->last_try > p->last_good && now - p->last_try < DIAL_RETRY_S) continue;
            char host[80]; uint16_t rp; peer_split(p->addr, host, sizeof host, &rp, coin->port);
            if (conn_host_live(conns, NULL, host)) continue;
            if (host_is_self(host, self)) continue;
            if (net_policy_banned(host, now)) continue;
            int clash = 0;
            for (int k = 0; k < SERVE_MAX_CONN && !clash; k++)
                if (conns[k].outbound && conns[k].host[0] && same_group16(conns[k].host, host)) clash = 1;
            if (clash) continue;
            memset(&conns[slot], 0, sizeof conns[slot]);
            conns[slot].fd = -1; conns[slot].outbound = 1; conns[slot].chain_seat = 1;
            seat_point(&conns[slot], host, rp);
            return;
        }
    }
}

// idx_serve_listen_status (indexer.h): last bind outcome, local diagnostics only.
static volatile int g_listen_state = IDX_LISTEN_PENDING, g_listen_port, g_listen_err;
static void listen_note(int state, int port, int err) {
    __atomic_store_n(&g_listen_port, port, __ATOMIC_RELAXED);
    __atomic_store_n(&g_listen_err, err, __ATOMIC_RELAXED);
    __atomic_store_n(&g_listen_state, state, __ATOMIC_RELEASE);
}
void idx_serve_listen_status(int *state, int *port, int *err) {
    int st = __atomic_load_n(&g_listen_state, __ATOMIC_ACQUIRE);
    if (state) *state = st;
    if (port) *port = __atomic_load_n(&g_listen_port, __ATOMIC_RELAXED);
    if (err) *err = __atomic_load_n(&g_listen_err, __ATOMIC_RELAXED);
}
static int sock_last_err(void) {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

// The chain-wire presence (indexer.h). port 0 = dial-only. `dial_peers` =
// comma host:port list kept connected. `mesh` non-NULL carries carrier gossip
// as dn* commands on pepenet peers.
int idx_serve(const char *coinname, const char *dbpath, uint16_t port,
              const char *dial_peers, volatile int *stop, const IdxMeshHooks *mesh) {
    ignore_sigpipe();
    const Coin *coin = coin_by_name(coinname); if (!coin) return -1;
    g_serve_mesh = mesh;
    (void)self_nonce();                      // generate the version nonce now (before threads race)
    sqlite3 *db = idx_db_open(dbpath); if (!db) return -1;
    idx_peer_height_load(db);                 // seed g_ph_* from meta before any handshake/note
    idx_db_peers_scrub(db);                  // drop pre-fix hostname addr rows
    int lfd = -1;
    if (port) {
        lfd = socket(AF_INET, SOCK_STREAM, 0);
        if (lfd < 0) { listen_note(IDX_LISTEN_FAILED, port, sock_last_err()); idx_db_close(db); return -1; }
        sock_nosigpipe(lfd);
        int yes = 1; setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
        struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET; sa.sin_addr.s_addr = INADDR_ANY; sa.sin_port = htons(port);
        if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(lfd, 16) != 0) {
            listen_note(IDX_LISTEN_FAILED, port, sock_last_err());
            // The port is already taken — almost always a full node (Pepecoin
            // Core) bound to the chain port on the same box. That must NOT kill
            // the serve plane: this thread also carries the DNS mesh gossip and
            // the publish drain, and returning here left the node unable to
            // issue or sync DNS records at all. Degrade to dial-only (what a
            // NAT'd node does anyway): we lose inbound crawl-discoverability —
            // which needs a forwarded, unshared port regardless — but keep the
            // outbound mesh, block staging, and publish drain fully alive.
            // (strerror(errno) reads "No error" on Windows: Winsock reports the
            // in-use bind via WSAGetLastError, not errno — so name the cause.)
            fprintf(stderr, "serve: port %u already in use (a full node on this "
                    "host?) — running dial-only, no inbound\n", port);
            close(lfd); lfd = -1;
        } else {
            int fl = fcntl(lfd, F_GETFL, 0);
            if (fl >= 0) fcntl(lfd, F_SETFL, fl | O_NONBLOCK);
            listen_note(IDX_LISTEN_OK, port, 0);
        }
    } else listen_note(IDX_LISTEN_OFF, 0, 0);
    char serve_path[600];
    { const char *slash = strrchr(dbpath, '/');
      if (slash) snprintf(serve_path, sizeof serve_path, "%.*s/serve-%s.db",
                          (int)(slash - dbpath), dbpath, coinname);
      else snprintf(serve_path, sizeof serve_path, "serve-%s.db", coinname); }
    ServeStore *ss = serve_store_open(serve_path);
    int64_t services = (ss && serve_store_tip(ss) >= 0) ? (1LL << 10) : 0;
    int64_t our_h = 0; { uint8_t tip[32]; idx_db_load_sync(db, &our_h, tip); }
    if (port) fprintf(stderr, "serve: listening on 0.0.0.0:%u (agent %s, services 0x%llx)\n",
                      port, idx_sync_agent, (unsigned long long)services);
    else fprintf(stderr, "serve: dial-only (agent %s, services 0x%llx)\n",
                 idx_sync_agent, (unsigned long long)services);

    SConn conns[SERVE_MAX_CONN];
    idx_serve_send_eagain = 0; idx_serve_send_partial = 0;
    for (int i = 0; i < SERVE_MAX_CONN; i++) { memset(&conns[i], 0, sizeof conns[i]); conns[i].fd = -1; }
    // our own advertised addr ("ip:port"), learned from the first peer that tells
    // us — declared up here because the startup mesh re-seat below already needs
    // it to keep our own row out of the seats
    char self[80] = "";
    // pre-seat outbound peers (dial on the first tick)
    if (dial_peers && *dial_peers) {
        char list[512]; snprintf(list, sizeof list, "%s", dial_peers);
        int slot = 0;
        for (char *sv, *t = strtok_r(list, ",", &sv); t && slot < SERVE_MAX_CONN; t = strtok_r(NULL, ",", &sv)) {
            char host[80]; uint16_t rp;
            peer_split(t, host, sizeof host, &rp, coin->port);
            conns[slot].outbound = 1; seat_point(&conns[slot], host, rp); slot++;
        }
    }
    // first mesh_seat_topup waits for the 5s dial grace: by then the sync
    // thread (or an inbound) may have filled g_self_ip, so a persisted self
    // row is not seated into a blocking self-connect.
    // hold the first outbound dial a few seconds: lets the sync thread reach a real
    // peer and learn our external ip (g_self_ip) first, so if the seed points back
    // at us the dial loop skips it up front instead of blocking on a self-connect.
    time_t next_dial = time(NULL) + 5, next_prune = time(NULL) + 3600, next_snap = 0;
    time_t next_announce = 0;
    int64_t announced_tip = serve_store_tip(ss);   // boot: only NEW blocks get announced
    while (!(stop && *stop)) {
        time_t now = time(NULL);
        // republish the connection snapshot (embedding hosts' Peers page)
        if (now >= next_snap) { next_snap = now + 1; serve_snap(conns, SERVE_MAX_CONN, now); }
        // announce new tip blocks (inv) to every up conn. This is the push half
        // of sync-over-one-connection: the receiver's serve thread getdatas the
        // inv into its stage and its sync pass folds from there — a peer at tip
        // follows the chain on its ONE mesh conn, no transient sync socket.
        // Big jumps (our own catch-up) are not blasted — a peer that far behind
        // uses the socket ladder anyway; the mark just snaps forward.
        if (ss && now >= next_announce) {
            next_announce = now + 2;
            // the PULL half of sync-over-one-connection: ask each marked peer
            // for anything above our chain (getblocks on the standing conn).
            // The locator is a real exponential walk over our stored headers,
            // so after a reorg the peer finds the true fork point instead of
            // missing our stale tip and staying silent. Answers ride the same
            // inv → stage → fold path as the push — a missed inv heals HERE,
            // never on a transient socket. Cadence: 60 s at parity (one tiny
            // frame a minute), 5 s while the peer's claimed height says we're
            // behind (stage-cap-sized batches per round → fast catch-up).
            // Core chain seats stay push-only: deep gaps are the socket
            // ladder's job, against peers we hold no connection to.
            { int64_t pt = serve_store_tip(ss);
              if (pt >= 0) {
                  uint8_t loc[16][32]; int nloc = 0;
                  int64_t lh = pt, step = 1;
                  while (nloc < 16 && lh >= 0 && serve_store_hash_at(ss, lh, loc[nloc])) {
                      nloc++;
                      if (nloc >= 4) step *= 2;
                      lh -= step;
                  }
                  if (nloc > 0) {
                      uint8_t gb[4 + 3 + 16 * 32 + 32]; int go = 0;
                      for (int b = 0; b < 4; b++) gb[go++] = (70015 >> (8*b)) & 0xff;
                      put_varint(gb, &go, (uint64_t)nloc);
                      for (int i = 0; i < nloc; i++) { memcpy(gb + go, loc[i], 32); go += 32; }
                      memset(gb + go, 0, 32); go += 32;             // hash_stop
                      for (int i = 0; i < SERVE_MAX_CONN; i++) {
                          SConn *pc = &conns[i];
                          if (pc->fd < 0 || !pc->up || !AGENT_MARKED(pc->agent)) continue;
                          time_t cad = (pc->peer_h > pt + 2) ? 5 : 60;
                          if (now - pc->last_pull < cad) continue;
                          serve_send(pc, coin->magic, "getblocks", gb, (uint32_t)go);
                          pc->last_pull = now;
                      }
                  }
              } }
            int64_t st = serve_store_tip(ss);
            if (st < announced_tip) announced_tip = st;          // reorg pruned below the mark
            if (st > announced_tip) {
                if (st - announced_tip <= 32) {
                    uint8_t hs[32][32];
                    int nh = serve_store_hashes_from(ss, announced_tip, hs, 32);
                    if (nh > 0) {
                        uint8_t out[3 + 32 * 36]; int vo = 0;
                        put_varint(out, &vo, (uint64_t)nh);
                        uint32_t oo = (uint32_t)vo;
                        for (int i = 0; i < nh; i++) {
                            out[oo++] = 2; out[oo++] = 0; out[oo++] = 0; out[oo++] = 0;   // MSG_BLOCK
                            memcpy(out + oo, hs[i], 32); oo += 32;
                        }
                        for (int i = 0; i < SERVE_MAX_CONN; i++)
                            if (conns[i].fd >= 0 && conns[i].up)
                                serve_send(&conns[i], coin->magic, "inv", out, oo);
                    }
                }
                announced_tip = st;
            }
        }
        // bound the peers table (addr harvest grows it every getaddr)
        if (now >= next_prune) {
            next_prune = now + 3600;
            idx_db_peers_prune(db, (int64_t)now, IDX_PEER_TTL_SECS, IDX_PEER_CAP);
            mempool_sweep((int64_t)now);          // drop txs unconfirmed past the expiry
        }
        // liveness: cut conns that never handshake; ping quiet peers; drop the
        // silent. A peer that vanished without a FIN otherwise holds its slot
        // forever, and its reconnects stack fresh conns next to the ghost.
        for (int i = 0; i < SERVE_MAX_CONN; i++) {
            SConn *c = &conns[i];
            if (c->fd < 0) continue;
            long idle = (long)(now - c->last_rx);
            if (c->connecting) {
                if (c->shake_by && now >= c->shake_by)
                    serve_outbound_fail(c, db, now);
                continue;
            }
            if (!c->up) {
                if (c->outbound && c->shake_by && now >= c->shake_by) {
                    serve_outbound_fail(c, db, now);
                } else if (!c->outbound && idle > SERVE_SHAKE_S) {
                    fprintf(stderr, "serve: %s stalled in handshake %lds — dropping\n",
                            c->peer[0] ? c->peer : "(inbound)", idle);
                    serve_drop(c, mesh);
                }
            } else if (idle > SERVE_DEAD_S) {
                fprintf(stderr, "serve: %s silent %lds — dropping dead conn\n", c->peer, idle);
                serve_drop(c, mesh);
            } else if (idle > SERVE_PING_S && now - c->last_ping > SERVE_PING_S) {
                uint8_t pn[8]; uint64_t nn = (uint64_t)now ^ ((uint64_t)i << 48);
                for (int b = 0; b < 8; b++) pn[b] = (uint8_t)(nn >> (8 * b));
                if (serve_send(c, coin->magic, "ping", pn, 8))
                    c->last_ping = now;  // any reply (pong or otherwise) feeds last_rx
            }
        }
        // maintain outbound connections
        if (now >= next_dial) {
            next_dial = now + 5;
            // pick up pepenet peers learned via dnaddr since the last tick
            mesh_seat_topup(conns, db, coin, MESH_DIAL_SEATS, self);
            // re-ask live marked peers so the dnet pool tracks their view, not
            // just the handshake-time snapshot
            for (int i = 0; i < SERVE_MAX_CONN; i++) {
                SConn *pc = &conns[i];
                if (pc->fd < 0 || !pc->up || !AGENT_MARKED(pc->agent)) continue;
                if (pc->last_dnget && now - pc->last_dnget < DNADDR_REFRESH_S) continue;
                if (serve_send(pc, coin->magic, "dngetaddr", NULL, 0)) {
                    pc->dn_asked = 1;
                    pc->last_dnget = now;
                }
            }
            // and keep ~8 outbound chain peers seated addrman-style
            chain_topup(conns, db, coin, self);
            for (int i = 0; i < SERVE_MAX_CONN; i++) {
                SConn *c = &conns[i];
                if (!c->outbound || c->fd >= 0 || now < c->redial_at) continue;
                // ONE CONNECTION PER PEER, either direction — and while it lives,
                // this seat just PARKS: no dial, no backoff clock, no churn. Pool
                // seats free instead (their pool holds other candidates); a
                // configured seat waits right here and fires within a tick of
                // that conn dropping. Checked on the cached identity, so parking
                // costs a string scan — never a resolver call.
                if ((c->hip[0]  && conn_host_live(conns, c, c->hip)) ||
                    (c->host[0] && conn_host_live(conns, c, c->host))) {
                    if (c->mesh_seat || c->chain_seat) {
                        c->outbound = 0; c->mesh_seat = 0; c->chain_seat = 0;
                        c->host[0] = 0; c->hip[0] = 0;
                    }
                    continue;
                }
                // actually dialing now — (re)resolve a hostname seat first, every
                // attempt, so the configured seed follows a DNS change across
                // redials. The numeric result is the dial target AND the identity
                // every dedup above compares; the hostname itself never reaches a
                // socket or the addr book.
                if (!c->hip[0] || strcmp(c->hip, c->host) != 0) {
                    if (!net_resolve_str(c->host, c->hip, sizeof c->hip)) {
                        c->hip[0] = 0;             // a stale ip must not pose as the identity
                        c->redial_at = now + 15;   // dns down: quiet retry (configured-seat idiom)
                        continue;
                    }
                    if (conn_host_live(conns, c, c->hip)) continue;   // fresh ip already held — park
                }
                // never dial a peer that resolves to ourselves — this node IS the
                // seed the hostname points at (no hairpin: the dial would just
                // time out on a loop back to us)
                if (host_is_self(c->hip, self)) {
                    fprintf(stderr, "serve: %s resolves to our own address %s — dropping self-seed\n",
                            c->host, *self ? self : g_self_ip);
                    if (!c->chain_seat) idx_self_seed = 1;   // a looping configured seed = we ARE the seed
                    c->outbound = 0; c->mesh_seat = 0; c->chain_seat = 0; c->host[0] = 0; c->hip[0] = 0; continue;
                }
                if (c->hip[0] && net_policy_banned(c->hip, now)) {
                    if (c->mesh_seat || c->chain_seat) {
                        char addr[96]; snprintf(addr, sizeof addr, "%s:%u", c->host, c->rport);
                        idx_db_peer_tried(db, addr, (int64_t)now);
                        c->outbound = 0; c->mesh_seat = 0; c->chain_seat = 0; c->feeler = 0;
                        c->host[0] = 0; c->hip[0] = 0;
                    } else c->redial_at = now + 60;
                    continue;
                }
                int st = serve_start_connect(c);
                if (st < 0) { serve_outbound_fail(c, db, now); continue; }
                c->magic = coin->magic;
                c->last_ping = 0;
                if (st > 0) {
                    int cr = serve_connect_ready(c, conns, coin, db, services);
                    if (cr < 0) serve_outbound_fail(c, db, now);
                }
                // handshake completion (version/verack, peer_seen, mesh, dngetaddr,
                // self-announce, unmarked-feeler release) runs in serve_dispatch
                // on this same poll loop so accepts and EOF keep flowing.
            }
        }
        if (mesh && mesh->tick) mesh->tick(mesh->ud);
        for (int i = 0; i < SERVE_MAX_CONN; i++)        // L6: closes the carrier asked for
            if (conns[i].fd >= 0 && conns[i].mesh_kick) serve_drop(&conns[i], mesh);

        struct pollfd pfd[SERVE_MAX_CONN + 1]; int map[SERVE_MAX_CONN + 1]; int np = 0;
        if (lfd >= 0) { pfd[np].fd = lfd; pfd[np].events = POLLIN; map[np] = -1; np++; }
        for (int i = 0; i < SERVE_MAX_CONN; i++)
            if (conns[i].fd >= 0) {
                pfd[np].fd = conns[i].fd;
                pfd[np].events = POLLIN | ((conns[i].connecting || serve_out_pending(&conns[i])) ? POLLOUT : 0);
                map[np] = i; np++;
            }
        if (poll(pfd, np, 1000) <= 0) continue;
        int start = 0;
        if (lfd >= 0 && (pfd[0].revents & POLLIN)) {
          for (;;) {
            int cfd = accept(lfd, NULL, NULL);
            if (cfd < 0) {
                if (errno == EINTR) continue;
                break;   /* EAGAIN/EWOULDBLOCK or hard error — next poll */
            }
            {
                sock_nosigpipe(cfd);
                { int fl = fcntl(cfd, F_GETFL, 0); if (fl >= 0) fcntl(cfd, F_SETFL, fl | O_NONBLOCK); }
                serve_apply_test_sndbuf(cfd);
                char ip[INET_ADDRSTRLEN] = ""; unsigned rport = 0;
                struct sockaddr_in pa; socklen_t pl2 = sizeof pa;
                if (getpeername(cfd, (struct sockaddr *)&pa, &pl2) == 0) {
                    inet_ntop(AF_INET, &pa.sin_addr, ip, sizeof ip);
                    rport = ntohs(pa.sin_port);
                }
                if (ip[0] && net_policy_banned(ip, now)) {
                    close(cfd);
                } else {
                int from_host = 0;
                for (int i = 0; i < SERVE_MAX_CONN; i++) {
                    /* inbound-only: a connecting outbound must not consume a
                     * SERVE_INBOUND_PER_HOST seat (baseline: serve_dial held
                     * the fd locally so outbound hip never counted here). */
                    if (conns[i].fd < 0 || !ip[0] || conns[i].outbound) continue;
                    size_t il = strlen(ip);
                    if (conns[i].hip[0] && !strcmp(conns[i].hip, ip)) from_host++;
                    else if (conns[i].peer[0] && !strncmp(conns[i].peer, ip, il) &&
                             conns[i].peer[il] == ':') from_host++;
                }
                int slot = -1;
                for (int i = 0; i < SERVE_MAX_CONN; i++) if (conns[i].fd < 0 && !conns[i].outbound) { slot = i; break; }
                if (slot < 0 || from_host >= SERVE_INBOUND_PER_HOST) {
                    // rate-limited: an old-build peer bounces its transients off
                    // the cap every few seconds — one line a minute, not a flood
                    static time_t refuse_log_at = 0;
                    if (from_host >= SERVE_INBOUND_PER_HOST && now - refuse_log_at >= 60) {
                        refuse_log_at = now;
                        fprintf(stderr, "serve: %s:%u refused — host already connected (%d/host cap)\n",
                                ip, rport, SERVE_INBOUND_PER_HOST);
                    }
                    close(cfd);
                } else {
                    serve_bufs_clear(&conns[slot]);
                    memset(&conns[slot], 0, sizeof conns[slot]);
                    conns[slot].fd = cfd; conns[slot].magic = coin->magic;
                    conns[slot].last_rx = time(NULL);   // handshake clock starts now
                    if (ip[0]) {
                        snprintf(conns[slot].peer, 80, "%s:%u", ip, rport);
                        snprintf(conns[slot].hip, sizeof conns[slot].hip, "%s", ip);
                    }
                }
                }
            }
          }
        }
        if (lfd >= 0) start = 1;
        for (int k = start; k < np; k++) {
            if (map[k] < 0 || !(pfd[k].revents & (POLLIN | POLLOUT | POLLHUP | POLLERR))) continue;
            SConn *c = &conns[map[k]];
            if (c->connecting && (pfd[k].revents & (POLLOUT | POLLERR | POLLHUP))) {
                int cr = serve_connect_ready(c, conns, coin, db, services);
                if (cr < 0) serve_outbound_fail(c, db, time(NULL));
                if (c->fd < 0 || c->connecting)
                    continue;
            }
            if (!c->connecting && serve_out_pending(c) && (pfd[k].revents & POLLOUT)) {
                if (!serve_out_flush(c)) { serve_drop(c, mesh); continue; }
            }
            if (!(pfd[k].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            uint8_t chunk[8192];
            ssize_t r = recv(c->fd, chunk, sizeof chunk, 0);
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
            if (r <= 0) { serve_drop(c, mesh); continue; }
            c->last_rx = time(NULL);
            size_t need = c->len + (size_t)r;
            if (need > SERVE_MSG_MAX + 1024u) { serve_drop(c, mesh); continue; }
            if (need > c->cap) {
                size_t nc = c->cap ? c->cap : 16384;
                while (nc < need) nc *= 2;
                uint8_t *nb = realloc(c->buf, nc);
                if (!nb) { serve_drop(c, mesh); continue; }
                c->buf = nb; c->cap = nc;
            }
            memcpy(c->buf + c->len, chunk, (size_t)r); c->len += (size_t)r;
            size_t off = 0; int dead = 0;
            while (c->len - off >= 24) {
                uint8_t *h = c->buf + off;
                if (memcmp(h, coin->magic, 4) != 0) { serve_drop(c, mesh); dead = 1; break; }
                uint32_t plen = (uint32_t)h[16] | (uint32_t)h[17] << 8 | (uint32_t)h[18] << 16 | (uint32_t)h[19] << 24;
                if (plen > SERVE_MSG_MAX) { serve_drop(c, mesh); dead = 1; break; }
                if (c->len - off < 24u + plen) break;
                uint8_t ck[32]; idx_sha256d(plen ? h + 24 : (const uint8_t *)"", plen, ck);
                if (memcmp(h + 20, ck, 4) != 0) { serve_drop(c, mesh); dead = 1; break; }
                char cmd[13]; memcpy(cmd, h + 4, 12); cmd[12] = 0;
                serve_dispatch(c, conns, coin, db, ss, services, cmd, h + 24, plen, self, port, mesh);
                if (c->fd < 0) { dead = 1; break; }   // dispatch dropped us
                off += 24u + plen;
            }
            if (!dead && off > 0) { memmove(c->buf, c->buf + off, c->len - off); c->len -= off; }
        }
    }
    for (int i = 0; i < SERVE_MAX_CONN; i++) if (conns[i].fd >= 0) serve_drop(&conns[i], mesh);
    if (lfd >= 0) close(lfd);
    g_conns.seq++; g_conns.n = 0; g_conns.seq++;      // serve is down — clear the page
    idx_peer_height_note(db, 0, (int64_t)time(NULL), 1);   // flush a rate-limited peer_height
    serve_store_close(ss); idx_db_close(db);
    return 0;
}

// ── crawl: explore the chain graph, classify peers by agent (discovery slice 2) ─
// One bounded pass: dial up to max_dials candidates — explicit `extra` targets
// first (comma list), then the table's least-recently-tried addrs — handshake,
// record services + agent + last_good, getaddr to grow the frontier. The
// classifier: the IDX_DNET_MARK subver prefix marks a dns-aware node (the mesh
// bucket); NODE_NETWORK services mark a block source (the sync bucket).
//
// Probes run CRAWL_PAR at a time on one poll loop (nonblocking connect, the
// same multiplexing idx_serve uses) with tight per-state budgets — a frontier
// full of dead addrs costs seconds per batch, not minutes per pass. Each
// probe: connect → version/verack (capture subver + services) → one getaddr,
// harvest the reply, close.
// Returns the number of marked peers now known in the db, -1 on open failure.
#define CRAWL_PAR         8            // concurrent probes
#define CRAWL_CONNECT_S   3            // connect budget
#define CRAWL_HANDSHAKE_S 5            // version/verack budget after connect
#define CRAWL_ADDR_S      2            // getaddr listen after handshake
#define CRAWL_BUF_MAX     (256 * 1024) // per-probe inbound cap (addr ≈ 30 KB)

typedef struct {
    int      fd;                       // -1 = slot free
    int      state;                    // 1 connecting · 2 handshaking · 3 addr wait
    int      got_ver, got_verack;
    time_t   deadline;
    char     cand[80], peer[80];       // dial target · resolved ip:port
    char     agent[128];
    uint64_t services;
    uint8_t *buf; size_t len, cap;     // frame accumulator (frames span reads)
} CrawlProbe;

static void probe_close(CrawlProbe *p) {
    if (p->fd >= 0) close(p->fd);
    free(p->buf);
    memset(p, 0, sizeof *p);
    p->fd = -1;
}

// start a nonblocking IPv4 connect; completion is signaled by POLLOUT. A
// hostname candidate (an explicit `extra` target) resolves synchronously —
// the db frontier is numeric ip:port text, so this stays off the hot path.
static int probe_connect_start(const char *host, uint16_t port) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &sa.sin_addr) != 1) {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        char ps[8]; snprintf(ps, sizeof ps, "%u", port);
        if (getaddrinfo(host, ps, &hints, &res) != 0 || !res) return -1;
        sa = *(struct sockaddr_in *)res->ai_addr;
        sa.sin_port = htons(port);
        freeaddrinfo(res);
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sock_nosigpipe(fd);
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    return fd;
}

int idx_crawl(const char *coinname, const char *dbpath, const char *extra,
              int max_dials, volatile int *stop) {
    ignore_sigpipe();
    const Coin *coin = coin_by_name(coinname); if (!coin) return -1;
    sqlite3 *db = idx_db_open(dbpath); if (!db) return -1;
    char cand[128][80]; int nc = 0;
    if (extra && *extra) {
        char list[512]; snprintf(list, sizeof list, "%s", extra);
        for (char *sv, *t = strtok_r(list, ",", &sv); t; t = strtok_r(NULL, ",", &sv))
            nc = cand_add(cand, nc, 128, t);
    }
    // frontier: never-tried first, then stalest — a fresh harvest gets explored
    // before yesterday's dead addrs get re-poked
    { char pool[128][80]; int n = idx_db_peers_crawl(db, pool, 128 - nc);
      for (int i = 0; i < n; i++) nc = cand_add(cand, nc, 128, pool[i]); }
    int dials = 0, up = 0, pepenet_hits = 0, next_cand = 0;
    CrawlProbe pr[CRAWL_PAR];
    for (int i = 0; i < CRAWL_PAR; i++) { memset(&pr[i], 0, sizeof pr[i]); pr[i].fd = -1; }
    g_crawl.seq++;                                    // pass starts (live progress)
    g_crawl.s.running = 1;
    g_crawl.s.dials = 0; g_crawl.s.up = 0; g_crawl.s.hits = 0;
    g_crawl.s.max_dials = max_dials < nc ? max_dials : nc;
    g_crawl.s.last_peer[0] = 0; g_crawl.s.last_agent[0] = 0;
    g_crawl.seq++;
    while (!(stop && *stop)) {
        time_t now = time(NULL);
        // kick candidates into free probe slots
        for (int i = 0; i < CRAWL_PAR && next_cand < nc && dials < max_dials; i++) {
            CrawlProbe *p = &pr[i];
            if (p->fd >= 0) continue;
            const char *ct = cand[next_cand++];
            dials++;
            idx_db_peer_tried(db, ct, (int64_t)now);
            g_crawl.seq++;                            // probing this candidate
            g_crawl.s.dials = dials;
            snprintf(g_crawl.s.last_peer, sizeof g_crawl.s.last_peer, "%s", ct);
            g_crawl.s.last_agent[0] = 0;
            g_crawl.seq++;
            char host[80]; uint16_t port;
            peer_split(ct, host, sizeof host, &port, coin->port);
            int fd = probe_connect_start(host, port);
            if (fd < 0) { fprintf(stderr, "  %s:%u down\n", host, port); continue; }
            memset(p, 0, sizeof *p);
            p->fd = fd; p->state = 1; p->deadline = now + CRAWL_CONNECT_S;
            snprintf(p->cand, sizeof p->cand, "%s:%u", host, port);
        }
        int live = 0;
        for (int i = 0; i < CRAWL_PAR; i++) if (pr[i].fd >= 0) live++;
        if (!live) {
            if (next_cand >= nc || dials >= max_dials) break;
            continue;                                 // every kick failed — refill
        }
        struct pollfd pfd[CRAWL_PAR]; int map[CRAWL_PAR]; int np = 0;
        for (int i = 0; i < CRAWL_PAR; i++)
            if (pr[i].fd >= 0) {
                pfd[np].fd = pr[i].fd;
                pfd[np].events = pr[i].state == 1 ? POLLOUT : POLLIN;
                pfd[np].revents = 0;
                map[np] = i; np++;
            }
        poll(pfd, np, 250);
        now = time(NULL);
        for (int k = 0; k < np; k++) {
            CrawlProbe *p = &pr[map[k]];
            if (p->state == 1) {                      // connect completing?
                if (!(pfd[k].revents & (POLLOUT | POLLERR | POLLHUP))) continue;
                int err = 0; socklen_t el = sizeof err;
                if ((pfd[k].revents & (POLLERR | POLLHUP)) ||
                    getsockopt(p->fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err != 0) {
                    fprintf(stderr, "  %s down\n", p->cand);
                    probe_close(p);
                    continue;
                }
                int fl = fcntl(p->fd, F_GETFL, 0);
                fcntl(p->fd, F_SETFL, fl & ~O_NONBLOCK);   // sends are tiny; block them
                net_peer_str(p->fd, p->peer, sizeof p->peer);
                serve_send_version(p->fd, coin, 0, 0);     // WE speak first
                p->state = 2; p->deadline = now + CRAWL_HANDSHAKE_S;
                continue;
            }
            if (!(pfd[k].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            uint8_t chunk[8192];
            ssize_t r = recv(p->fd, chunk, sizeof chunk, 0);
            if (r <= 0) {
                if (p->state == 2) fprintf(stderr, "  %s no handshake\n", p->cand);
                probe_close(p);
                continue;
            }
            size_t need = p->len + (size_t)r;
            if (need > CRAWL_BUF_MAX) { probe_close(p); continue; }
            if (need > p->cap) {
                size_t ncap = p->cap ? p->cap : 8192;
                while (ncap < need) ncap *= 2;
                uint8_t *nb = realloc(p->buf, ncap);
                if (!nb) { probe_close(p); continue; }
                p->buf = nb; p->cap = ncap;
            }
            memcpy(p->buf + p->len, chunk, (size_t)r); p->len += (size_t)r;
            size_t off = 0; int dead = 0, harvested = 0;
            while (p->len - off >= 24) {
                uint8_t *h = p->buf + off;
                if (memcmp(h, coin->magic, 4) != 0) { dead = 1; break; }
                uint32_t plen = (uint32_t)h[16] | (uint32_t)h[17] << 8 |
                                (uint32_t)h[18] << 16 | (uint32_t)h[19] << 24;
                if (plen > CRAWL_BUF_MAX) { dead = 1; break; }
                if (p->len - off < 24u + plen) break;
                char cmd[13]; memcpy(cmd, h + 4, 12); cmd[12] = 0;
                uint8_t *pl = h + 24;
                if (!strcmp(cmd, "version")) {
                    uint64_t vn;                          // crawled our own address?
                    if (ver_nonce(pl, plen, &vn) && vn == self_nonce()) { dead = 1; break; }
                    learn_self_ip(pl, plen);              // real peer's addr_recv = our external ip
                    if (plen >= 12) {
                        uint64_t sv = 0;
                        for (int b = 0; b < 8; b++) sv |= (uint64_t)pl[4 + b] << (8 * b);
                        p->services = sv;
                    }
                    uint64_t o2 = 4 + 8 + 8 + 26 + 26 + 8, ua;
                    if (plen > o2) {
                        ua = pl[o2++];
                        if (ua == 0xFD && plen >= o2 + 2) { ua = pl[o2] | (pl[o2+1] << 8); o2 += 2; }
                        if (ua <= 100 && plen >= o2 + ua) { memcpy(p->agent, pl + o2, ua); p->agent[ua] = 0; }
                    }
                    net_send(p->fd, coin->magic, "verack", NULL, 0);
                    p->got_ver = 1;
                } else if (!strcmp(cmd, "verack")) {
                    p->got_verack = 1;
                } else if (!strcmp(cmd, "ping")) {
                    net_send(p->fd, coin->magic, "pong", pl, plen);
                } else if (!strcmp(cmd, "addr") && p->state == 3) {
                    addr_harvest(db, pl, plen, 0);
                    harvested = 1;
                }
                off += 24u + plen;
            }
            if (dead) { probe_close(p); continue; }
            if (off > 0) { memmove(p->buf, p->buf + off, p->len - off); p->len -= off; }
            if (p->state == 2 && p->got_ver && p->got_verack) {
                up++;
                idx_db_peer_seen(db, p->peer, (int64_t)p->services, p->agent, (int64_t)now);
                int is_pepenet = AGENT_MARKED(p->agent);
                if (is_pepenet) pepenet_hits++;
                g_crawl.seq++;                        // handshake landed
                g_crawl.s.up = up; g_crawl.s.hits = pepenet_hits;
                snprintf(g_crawl.s.last_peer, sizeof g_crawl.s.last_peer, "%s", p->peer);
                snprintf(g_crawl.s.last_agent, sizeof g_crawl.s.last_agent, "%s", p->agent);
                g_crawl.seq++;
                fprintf(stderr, "  %s up  agent %s  services 0x%llx%s\n", p->peer,
                        p->agent[0] ? p->agent : "(none)",
                        (unsigned long long)p->services,
                        is_pepenet ? "  [" IDX_DNET_MARK "]" : "");
                // grow the frontier: one getaddr, listen briefly for the reply
                net_send(p->fd, coin->magic, "getaddr", NULL, 0);
                p->state = 3; p->deadline = now + CRAWL_ADDR_S;
            }
            if (harvested) probe_close(p);
        }
        for (int i = 0; i < CRAWL_PAR; i++) {         // expire per-state budgets
            CrawlProbe *p = &pr[i];
            if (p->fd < 0 || now < p->deadline) continue;
            if (p->state == 1)      fprintf(stderr, "  %s down (timeout)\n", p->cand);
            else if (p->state == 2) fprintf(stderr, "  %s no handshake\n", p->cand);
            probe_close(p);                           // state 3: already recorded up
        }
    }
    for (int i = 0; i < CRAWL_PAR; i++) probe_close(&pr[i]);
    char dn[16][80]; int ndn = idx_db_peers_agent(db, IDX_DNET_MARK, dn, 16);
    fprintf(stderr, "crawl: %d dialed, %d up, %d " IDX_DNET_MARK " this pass (%d known total)\n",
            dials, up, pepenet_hits, ndn);
    g_crawl.seq++;                                    // pass over
    g_crawl.s.running = 0;
    g_crawl.s.dials = dials; g_crawl.s.up = up; g_crawl.s.hits = pepenet_hits;
    g_crawl.s.known = ndn;
    g_crawl.s.last_pass = (int64_t)time(NULL);
    g_crawl.s.passes++;
    g_crawl.seq++;
    idx_db_close(db);
    return ndn;
}

static int cmd_serve(int argc, char **argv) {
    // serve <coin> <db> [port] [dial_peers]  (standalone: chain data only, no mesh)
    if (argc < 4) { fprintf(stderr, "usage: serve <doge|pep|testnet|regtest> <db> [port] [host:port,...]\n"); return 2; }
    const Coin *coin = coin_by_name(argv[2]); if (!coin) { fprintf(stderr, "unknown coin %s\n", argv[2]); return 2; }
    uint16_t port = argc > 4 ? (uint16_t)atoi(argv[4]) : coin->port;
    const char *dial = argc > 5 ? argv[5] : NULL;
    return idx_serve(argv[2], argv[3], port, dial, &idx_sync_stop, NULL) < 0 ? 1 : 0;
}

static int cmd_crawl(int argc, char **argv) {
    // crawl <coin> <db> [max_dials=8] [extra,targets]
    if (argc < 4) { fprintf(stderr, "usage: crawl <doge|pep|testnet|regtest> <db> [max_dials=8] [host:port,...]\n"); return 2; }
    int max_dials = argc > 4 ? atoi(argv[4]) : 8;
    int n = idx_crawl(argv[2], argv[3], argc > 5 ? argv[5] : NULL, max_dials, &idx_sync_stop);
    if (n < 0) { fprintf(stderr, "cannot open %s\n", argv[3]); return 1; }
    char dn[16][80]; sqlite3 *db = idx_db_open(argv[3]);
    if (db) {
        int k = idx_db_peers_agent(db, IDX_DNET_MARK, dn, 16);
        for (int i = 0; i < k; i++) printf("%s %s\n", IDX_DNET_MARK, dn[i]);
        idx_db_close(db);
    }
    return 0;
}

// ── offline snapshots (idx-01) — never called from sync; see docs/SNAPSHOT.md ──
// snapshot-export <coin> <db> <outdir>: outdir/state.db (a VACUUM INTO copy of
// the lossless projection at its sync height H) + outdir/MANIFEST (coin, H, tip,
// activation, state_digest, state_ecmh of the fold loaded from that copy).
// snapshot-verify <coin> <snapdir> [headers-file]: reload the fold from
// state.db, recompute both digests and compare to MANIFEST, check the db's own
// sync tip = MANIFEST, then walk headers checkpoint+1..H (linkage, PoW, nBits)
// and require the last hash = tip. Exit 0 only if every check passed.
static void snap_hex(const uint8_t *b, int n, char *out) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 15]; }
    out[2*n] = 0;
}
static int snap_digests(const char *coin, const char *dbpath, int64_t *h, uint8_t tip[32], int64_t *act,
                        char d_hex[65], char e_hex[65]) {
    sqlite3 *db; SmState *s = open_state(dbpath, coin, &db); if (!s) return 0;
    int ok = idx_db_load_sync(db, h, tip);
    *act = idx_db_get_activation(db, 0);
    uint8_t d[32], e[32]; sm_state_digest(s, d); sm_state_ecmh(s, e);
    snap_hex(d, 32, d_hex); snap_hex(e, 32, e_hex);
    sm_free(s); idx_db_close(db); return ok;
}
// idx-06: canonical export. A plain VACUUM INTO keeps the hidden rowids of
// tables with no INTEGER PRIMARY KEY (meta, names, commits, epochs, utxos, ...),
// and those depend on the db's history: INSERT OR REPLACE, crash recovery and
// resume order all hand out different rowids for the same logical rows, so two
// honest builds at the same height gave different whole-file sha256s. Here the
// same schema (sqlite_master SQL, original order) is replayed into a fresh
// scratch db with fixed pragmas, every table is copied in primary-key order (all
// columns when there is no PK), and that scratch db is then VACUUM INTO'd.
// Schema, rows and the journal mode in the header are unchanged; only the
// hidden rowids are renumbered, and nothing reads them.
static int snap_exec(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) == SQLITE_OK) return 1;
    fprintf(stderr, "snapshot-export: %s: %s\n", sql, err ? err : "?"); sqlite3_free(err); return 0;
}
static int snap_export_canonical(const char *src, const char *dir, const char *out) {
    char tmp[1200]; snprintf(tmp, sizeof tmp, "%s/.state.db.canon", dir);
    unlink(tmp);
    sqlite3 *c = NULL, *s = idx_db_open_ro(src);
    if (!s) { fprintf(stderr, "cannot open %s read-only\n", src); return 0; }
    int ok = 0; sqlite3_stmt *st = NULL, *q = NULL; char *sql = NULL;
    char jm[16] = "delete";
    if (sqlite3_prepare_v2(s, "PRAGMA journal_mode", -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW)
        snprintf(jm, sizeof jm, "%s", (const char *)sqlite3_column_text(st, 0));
    sqlite3_finalize(st); st = NULL;
    if (sqlite3_open(tmp, &c) != SQLITE_OK) { fprintf(stderr, "cannot create %s\n", tmp); goto done; }
    if (!snap_exec(c, "PRAGMA page_size=4096; PRAGMA auto_vacuum=0; PRAGMA encoding='UTF-8';"
                      " PRAGMA synchronous=OFF; PRAGMA journal_mode=OFF")) goto done;
    // user_version / application_id travel with the file: copy them verbatim.
    for (int k = 0; k < 2; k++) {
        const char *pn = k ? "application_id" : "user_version"; char b[96];
        snprintf(b, sizeof b, "PRAGMA %s", pn);
        long long v = 0;
        if (sqlite3_prepare_v2(s, b, -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st); st = NULL;
        snprintf(b, sizeof b, "PRAGMA %s=%lld", pn, v); if (!snap_exec(c, b)) goto done;
    }
    if (!snap_exec(c, "BEGIN")) goto done;
    // schema in its original creation order (sqlite_master rowid), autoindexes implied
    if (sqlite3_prepare_v2(s, "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY rowid",
                           -1, &st, NULL) != SQLITE_OK) goto done;
    while (sqlite3_step(st) == SQLITE_ROW) if (!snap_exec(c, (const char *)sqlite3_column_text(st, 0))) goto done;
    sqlite3_finalize(st); st = NULL;
    if (sqlite3_prepare_v2(s, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY rowid",
                           -1, &st, NULL) != SQLITE_OK) goto done;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *t = (const char *)sqlite3_column_text(st, 0);
        // idx-07: node-local tables keep their schema but ship with zero rows:
        // peers (gossip cache), watch + utxos (this node's wallet watch set).
        // None feeds state_digest/state_ecmh, the fold or import.
        if (!strcmp(t, "peers") || !strcmp(t, "watch") || !strcmp(t, "utxos")) continue;
        // ORDER BY: primary-key columns in pk order, then every column (total order)
        char *ord = sqlite3_mprintf(""), *ins = NULL;
        for (int pass = 0; pass < 2; pass++) {
            char *qs = sqlite3_mprintf("SELECT name, pk FROM pragma_table_info(%Q) %s", t,
                                       pass ? "ORDER BY cid" : "WHERE pk > 0 ORDER BY pk");
            sqlite3_prepare_v2(s, qs, -1, &q, NULL); sqlite3_free(qs);
            while (q && sqlite3_step(q) == SQLITE_ROW) {
                char *n = sqlite3_mprintf("%s%s\"%w\"", ord, *ord ? ", " : "", (const char *)sqlite3_column_text(q, 0));
                sqlite3_free(ord); ord = n;
            }
            sqlite3_finalize(q); q = NULL;
        }
        // idx-11: meta onchain_magic is node-local (the importer re-stamps it from
        // its coin) and is not in state_digest/state_ecmh; leave it out so a db
        // stamped by idx-10 and an older unstamped db export byte-identically.
        ins = sqlite3_mprintf("INSERT INTO main.\"%w\" SELECT * FROM src.\"%w\"%s ORDER BY %s", t, t,
                              !strcmp(t, "meta") ? " WHERE k <> 'onchain_magic'" : "", ord);
        sqlite3_free(ord);
        sql = ins;
        if (!sql) goto done;
        // ATTACH the source once (read-only)
        sqlite3_stmt *a = NULL; int attached = 0;
        if (sqlite3_prepare_v2(c, "SELECT 1 FROM pragma_database_list WHERE name='src'", -1, &a, NULL) == SQLITE_OK)
            attached = sqlite3_step(a) == SQLITE_ROW;
        sqlite3_finalize(a);
        if (!attached) {
            char *at = sqlite3_mprintf("ATTACH 'file:%q?mode=ro' AS src", src);
            int r = sqlite3_exec(c, at, NULL, NULL, NULL); sqlite3_free(at);
            if (r != SQLITE_OK) {   // non-URI build: plain path, read through the tx only
                at = sqlite3_mprintf("ATTACH %Q AS src", src); r = snap_exec(c, at) ? SQLITE_OK : SQLITE_ERROR; sqlite3_free(at);
                if (r != SQLITE_OK) goto done;
            }
        }
        if (!snap_exec(c, sql)) goto done;
        sqlite3_free(sql); sql = NULL;
    }
    sqlite3_finalize(st); st = NULL;
    if (!snap_exec(c, "COMMIT") || !snap_exec(c, "DETACH src")) goto done;
    // keep the header's journal-mode bytes exactly as a plain export had them
    { char b[64]; snprintf(b, sizeof b, "PRAGMA journal_mode=%s", jm); snap_exec(c, b); }
    if (sqlite3_prepare_v2(c, "VACUUM INTO ?", -1, &st, NULL) != SQLITE_OK) goto done;
    sqlite3_bind_text(st, 1, out, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) { fprintf(stderr, "VACUUM INTO failed: %s\n", sqlite3_errmsg(c)); goto done; }
    ok = 1;
done:
    sqlite3_free(sql); sqlite3_finalize(q); sqlite3_finalize(st);
    sqlite3_close(s); if (c) sqlite3_close(c);
    char aux[1300];
    unlink(tmp); snprintf(aux, sizeof aux, "%s-wal", tmp); unlink(aux); snprintf(aux, sizeof aux, "%s-shm", tmp); unlink(aux);
    snprintf(aux, sizeof aux, "%s-journal", tmp); unlink(aux);
    if (!ok) unlink(out);
    return ok;
}
static int cmd_snapshot_export(int argc, char **argv) {
    if (argc < 5) { fprintf(stderr, "usage: snapshot-export <coin> <db> <outdir>\n"); return 2; }
    const Coin *coin = coin_by_name(argv[2]); if (!coin) { fprintf(stderr, "unknown coin %s\n", argv[2]); return 2; }
    const char *src = argv[3], *dir = argv[4];
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) { perror(dir); return 1; }
    char sp[1100], mp[1100];
    snprintf(sp, sizeof sp, "%s/state.db", dir); snprintf(mp, sizeof mp, "%s/MANIFEST", dir);
    if (access(sp, F_OK) == 0) { fprintf(stderr, "%s exists — refusing to overwrite\n", sp); return 1; }
    if (!snap_export_canonical(src, dir, sp)) return 1;
    int64_t h = 0, act = 0; uint8_t tip[32]; char d[65], e[65], th[65];
    if (!snap_digests(argv[2], sp, &h, tip, &act, d, e)) { fprintf(stderr, "db has no sync state\n"); return 1; }
    snap_hex(tip, 32, th);
    FILE *f = fopen(mp, "wb"); if (!f) { perror(mp); return 1; }   // idx-10: LF on every platform
    fprintf(f, "pepenet-snapshot 1\ncoin %s\nheight %lld\ntip %s\nactivation %lld\ncheckpoint %lld\n"
               "state_digest %s\nstate_ecmh %s\n",
            coin->name, (long long)h, th, (long long)act, (long long)coin->start, d, e);
    // idx-09: informational — which sqlite wrote state.db (the pin still decides)
    fprintf(f, "sqlite_version %s\n", sqlite3_libversion());
    fclose(f);
    uint8_t fh[32]; char fhx[65]; int64_t fsz = 0;
    if (!idx_snap_file_sha256(sp, fh, &fsz)) { fprintf(stderr, "cannot hash %s\n", sp); return 1; }
    snap_hex(fh, 32, fhx);
    printf("snapshot %s at height %lld\nstate_digest %s\nstate_ecmh   %s\n", dir, (long long)h, d, e);
    // idx-04: the whole-file pin. Publish this out of band; consumers pass it as
    // --snapshot-sha256 / --sha256 (MANIFEST format unchanged — it is not in it).
    printf("sha256 %s  state.db (%lld bytes)\n", fhx, (long long)fsz);
    printf("sqlite %s (the exporter's library: pin it to reproduce this hash)\n", sqlite3_libversion());
    return 0;
}
static int snap_field(const char *mf, const char *key, char *out, size_t cap) {
    size_t kl = strlen(key);
    for (const char *p = mf; p && *p; p = strchr(p, '\n') ? strchr(p, '\n') + 1 : NULL) {
        if (!strncmp(p, key, kl) && p[kl] == ' ') {
            const char *v = p + kl + 1; size_t n = strcspn(v, "\n");
            if (n >= cap) return 0; memcpy(out, v, n); out[n] = 0; return 1;
        }
    }
    return 0;
}
// idx-09: log the MANIFEST's sqlite_version against this binary's sqlite.
// Informational only: never refuses — the whole-file sha256 pin decides. A
// MANIFEST without the key (pre-idx-09 export) is accepted.
static void snap_note_sqlite(FILE *o, const char *pfx, const char *mf) {
    char v[64]; const char *mine = sqlite3_libversion();
    if (!snap_field(mf, "sqlite_version", v, sizeof v))
        fprintf(o, "%sMANIFEST has no sqlite_version (pre-idx-09 export) — accepted; this node links sqlite %s\n", pfx, mine);
    else if (strcmp(v, mine))
        fprintf(o, "%sWARNING: snapshot exported with sqlite %s, this node links sqlite %s"
                   " (informational; the sha256 pin decides)\n", pfx, v, mine);
    else fprintf(o, "%ssqlite_version %s matches this node\n", pfx, v);
}
// pull "--sha256 <hex>" out of argv (any position after the command); returns
// the hex or NULL. *bad = 1 if the flag has no value.
static const char *snap_take_pin(int *argc, char **argv, int *bad) {
    const char *pin = NULL; *bad = 0;
    for (int i = 2; i < *argc; i++) {
        if (strcmp(argv[i], "--sha256") && strcmp(argv[i], "--snapshot-sha256")) continue;
        if (i + 1 >= *argc) { *bad = 1; return NULL; }
        pin = argv[i + 1];
        for (int j = i; j + 2 <= *argc; j++) argv[j] = argv[j + 2];
        *argc -= 2; i--;
    }
    return pin;
}
static int cmd_snapshot_verify(int argc, char **argv) {
    int badflag; const char *flag_pin = snap_take_pin(&argc, argv, &badflag);
    int allow_unpinned = 0;                          // idx-05: dev-only escape hatch
    for (int i = 2; i < argc; i++)
        if (!strcmp(argv[i], "--allow-unpinned")) {
            allow_unpinned = 1;
            for (int j = i; j + 1 <= argc; j++) argv[j] = argv[j + 1];
            argc--; i--;
        }
    if (argc < 4 || badflag) { fprintf(stderr, "usage: snapshot-verify <coin> <snapdir> [headers-file] (--sha256 <hex> | --allow-unpinned)\n"); return 2; }
    const Coin *coin = coin_by_name(argv[2]); if (!coin) { fprintf(stderr, "unknown coin %s\n", argv[2]); return 2; }
    char sp[1100], mp[1100];
    snprintf(sp, sizeof sp, "%s/state.db", argv[3]); snprintf(mp, sizeof mp, "%s/MANIFEST", argv[3]);
    // idx-04: the whole-file pin gates everything — checked before MANIFEST or
    // state.db is parsed. Flag overrides the compiled-in default; with neither,
    // verify REFUSES (idx-05, same as import) unless --allow-unpinned (dev use:
    // run the idx-01 checks only, result labelled UNPINNED).
    const char *pin = idx_snap_effective_pin(coin->name, flag_pin);
    if (pin) {
        char why[300];
        if (!idx_snap_pin_check(sp, pin, why, sizeof why)) {
            printf("  FAIL %s\nsnapshot-verify: REFUSED (pin)\n", why); return 1; }
        printf("  ok   state.db whole-file sha256 = pin%s\n", flag_pin ? "" : " (compiled default)");
    } else if (!allow_unpinned) {
        printf("  FAIL no snapshot pin (no --sha256 and no compiled default)\n"
               "snapshot-verify: REFUSED (no pin; --allow-unpinned for dev-only integrity checks)\n");
        return 1;
    } else printf("  warn --allow-unpinned: integrity checks only, snapshot is UNPINNED (untrusted)\n");
    size_t ml; uint8_t *mraw = read_file(mp, &ml);
    if (!mraw || ml > 4096) { fprintf(stderr, "cannot read %s\n", mp); free(mraw); return 1; }
    char mf[4097]; memcpy(mf, mraw, ml); mf[ml] = 0; free(mraw);
    char m_coin[32], m_h[32], m_tip[80], m_d[80], m_e[80];
    if (strncmp(mf, "pepenet-snapshot 1\n", 19) || !snap_field(mf, "coin", m_coin, sizeof m_coin) ||
        !snap_field(mf, "height", m_h, sizeof m_h) || !snap_field(mf, "tip", m_tip, sizeof m_tip) ||
        !snap_field(mf, "state_digest", m_d, sizeof m_d) || !snap_field(mf, "state_ecmh", m_e, sizeof m_e)) {
        fprintf(stderr, "FAIL manifest malformed\n"); return 1; }
    snap_note_sqlite(stdout, "  info ", mf);
    int fail = 0;
    #define SNAPCHK(c, msg) do { if (c) printf("  ok   %s\n", msg); else { printf("  FAIL %s\n", msg); fail++; } } while (0)
    SNAPCHK(!strcmp(m_coin, coin->name), "manifest coin matches");
    if (access(sp, R_OK) != 0) { printf("  FAIL state.db missing\n"); return 1; }
    int64_t h = 0, act = 0; uint8_t tip[32]; char d[65], e[65], th[65];
    int have = snap_digests(argv[2], sp, &h, tip, &act, d, e);
    SNAPCHK(have, "state.db has a sync tip");
    if (!have) return 1;
    snap_hex(tip, 32, th);
    SNAPCHK(strtoll(m_h, NULL, 10) == h, "state.db height = manifest height");
    SNAPCHK(!strcmp(m_tip, th), "state.db tip = manifest tip");
    SNAPCHK(!strcmp(m_d, d), "recomputed state_digest = manifest");
    SNAPCHK(!strcmp(m_e, e), "recomputed state_ecmh = manifest");
    if (argc > 4) {
        size_t len; uint8_t *buf = read_file(argv[4], &len);
        if (!buf) { fprintf(stderr, "cannot read %s\n", argv[4]); return 1; }
        IdxSnapWalk w; memset(&w, 0, sizeof w);
        w.h = coin->start; memcpy(w.hash, coin->start_hash, 32);
        w.bits = coin->start_bits; w.time = coin->start_time; w.prev_time = coin->start_prev_time;
        w.powlimit = coin->powlimit; w.aux_chain_id = coin->aux_chain_id; w.check_pow = coin->powlimit != 0;
        char why[200] = "";
        int ok = idx_snap_walk(&w, buf, len, why, sizeof why); free(buf);
        if (!ok) printf("  FAIL header walk: %s\n", why), fail++;
        else {
            char msg[160]; snprintf(msg, sizeof msg, "%lld headers %s from checkpoint %lld", (long long)w.n,
                                    w.check_pow ? "PoW-valid" : "linked (PoW off for this profile)", (long long)coin->start);
            SNAPCHK(1, msg);
            SNAPCHK(w.h == h, "header walk ends at snapshot height");
            SNAPCHK(!memcmp(w.hash, tip, 32), "last header hash = snapshot tip");
        }
    } else if (coin->powlimit) { printf("  FAIL headers-file required for %s (PoW profile)\n", coin->name); fail++; }
    else printf("  skip header walk (no headers-file; %s has PoW off)\n", coin->name);
    #undef SNAPCHK
    printf(fail ? "snapshot-verify: %d FAILED\n" : "snapshot-verify: OK\n", fail);
    return fail ? 1 : 0;
}

// ── idx-04 import: pinned, fail-closed ───────────────────────────────────────
// Apply <snapdir>/state.db as a fresh db at dbpath, only if (in order):
//   1. a pin exists (flag overrides the compiled default) and is 64 hex;
//   2. dbpath does not exist (never clobbers a live db);
//   3. the whole-file SHA-256 of state.db equals the pin — before sqlite ever
//      opens it;
//   4. the bytes actually COPIED (to dbpath.snap-tmp) hash to the pin again
//      (closes the check-then-copy race);
//   5. the copy's MANIFEST coin/height/tip/state_digest/state_ecmh agree.
// Then rename into place. Any failure: temp removed, nothing applied, returns 0
// with `why`; the caller just runs a normal full sync. 1 = applied.
int idx_snapshot_import(const char *coin_name, const char *snapdir, const char *dbpath,
                        const char *flag_pin, char *why, size_t cap) {
    const Coin *coin = coin_by_name(coin_name);
    if (!coin) { snprintf(why, cap, "unknown coin %s", coin_name ? coin_name : "?"); return 0; }
    const char *pin = idx_snap_effective_pin(coin->name, flag_pin);
    uint8_t want[32];
    if (!pin) { snprintf(why, cap, "no snapshot pin (no --snapshot-sha256 and no compiled default)"); return 0; }
    if (!idx_snap_parse_pin(pin, want)) { snprintf(why, cap, "malformed snapshot pin (need 64 hex digits)"); return 0; }
    if (access(dbpath, F_OK) == 0) { snprintf(why, cap, "%s already exists — snapshot not applied over a live db", dbpath); return 0; }
    char sp[1100], mp[1100], tmp[1100];
    snprintf(sp, sizeof sp, "%s/state.db", snapdir); snprintf(mp, sizeof mp, "%s/MANIFEST", snapdir);
    snprintf(tmp, sizeof tmp, "%s.snap-tmp", dbpath);
    if (!idx_snap_pin_check(sp, pin, why, cap)) return 0;
    // copy while hashing
    FILE *in = fopen(sp, "rb"), *out = in ? fopen(tmp, "wb") : NULL;
    if (!in || !out) { if (in) fclose(in); snprintf(why, cap, "cannot copy %s", sp); return 0; }
    SHA256_CTX c; sha256_init(&c); uint8_t buf[65536]; size_t n; int ioerr = 0;
    while ((n = fread(buf, 1, sizeof buf, in)) > 0) {
        sha256_update(&c, buf, (unsigned)n);
        if (fwrite(buf, 1, n, out) != n) { ioerr = 1; break; }
    }
    ioerr |= ferror(in); fclose(in);
    if (fflush(out) || fsync(fileno(out))) ioerr = 1;
    fclose(out);
    uint8_t got[32]; sha256_final(&c, got);
    #define IMPFAIL(...) do { snprintf(why, cap, __VA_ARGS__); unlink(tmp); return 0; } while (0)
    if (ioerr) IMPFAIL("i/o error copying %s", sp);
    if (memcmp(got, want, 32)) IMPFAIL("sha256 mismatch on the copied bytes (file changed during import)");
    size_t ml; uint8_t *mraw = read_file(mp, &ml);
    if (!mraw || ml > 4096) { free(mraw); IMPFAIL("cannot read %s", mp); }
    char mf[4097]; memcpy(mf, mraw, ml); mf[ml] = 0; free(mraw);
    char m_coin[32], m_h[32], m_tip[80], m_d[80], m_e[80];
    if (strncmp(mf, "pepenet-snapshot 1\n", 19) || !snap_field(mf, "coin", m_coin, sizeof m_coin) ||
        !snap_field(mf, "height", m_h, sizeof m_h) || !snap_field(mf, "tip", m_tip, sizeof m_tip) ||
        !snap_field(mf, "state_digest", m_d, sizeof m_d) || !snap_field(mf, "state_ecmh", m_e, sizeof m_e))
        IMPFAIL("MANIFEST malformed");
    snap_note_sqlite(stderr, "snapshot: ", mf);
    if (strcmp(m_coin, coin->name)) IMPFAIL("MANIFEST coin %s != %s", m_coin, coin->name);
    int64_t h = 0, act = 0; uint8_t tip[32]; char d[65], e[65], th[65];
    if (!snap_digests(coin->name, tmp, &h, tip, &act, d, e)) IMPFAIL("state.db has no sync tip");
    snap_hex(tip, 32, th);
    if (strtoll(m_h, NULL, 10) != h || strcmp(m_tip, th) || strcmp(m_d, d) || strcmp(m_e, e))
        IMPFAIL("state.db does not reproduce MANIFEST height/tip/digests");
    // idx-11: the export omits onchain_magic; stamp this coin's after every
    // pin/digest check passed (the magic is not digested, so nothing above changes).
    { sqlite3 *sdb = idx_db_open(tmp); if (!sdb) IMPFAIL("cannot open %s to stamp onchain_magic", tmp);
      idx_db_set_onchain_magic(sdb, coin->onchain_magic); idx_db_close(sdb); }
    { char x[1200]; snprintf(x, sizeof x, "%s-wal", tmp); unlink(x); snprintf(x, sizeof x, "%s-shm", tmp); unlink(x); }
    if (rename(tmp, dbpath) != 0) IMPFAIL("rename to %s failed", dbpath);
    #undef IMPFAIL
    snprintf(why, cap, "applied %s snapshot at height %lld (sha256 pinned)", coin->name, (long long)h);
    return 1;
}
// snapshot-import <coin> <snapdir> <db> [--sha256 <hex>]: exit 0 applied, 1 refused.
static int cmd_snapshot_import(int argc, char **argv) {
    int badflag; const char *flag_pin = snap_take_pin(&argc, argv, &badflag);
    if (argc < 5 || badflag) { fprintf(stderr, "usage: snapshot-import <coin> <snapdir> <db> [--sha256 <hex>]\n"); return 2; }
    char why[400];
    int ok = idx_snapshot_import(argv[2], argv[3], argv[4], flag_pin, why, sizeof why);
    fprintf(stderr, ok ? "snapshot: %s\n" : "snapshot: REFUSED: %s — not applied; full sync instead\n", why);
    return ok ? 0 : 1;
}

int indexer_main(int argc, char **argv) {
    const char *cmd = argv[1];
    if (!strcmp(cmd, "index"))   return cmd_index(argc, argv);
    if (!strcmp(cmd, "resolve")) return cmd_resolve(argc, argv);
    if (!strcmp(cmd, "owned"))   return cmd_owned(argc, argv);
    if (!strcmp(cmd, "digest"))  return cmd_digest(argc, argv);
    if (!strcmp(cmd, "refold"))  return cmd_refold(argc, argv);
    if (!strcmp(cmd, "watch"))   return cmd_watch(argc, argv);
    if (!strcmp(cmd, "sync"))    return cmd_sync(argc, argv);
    if (!strcmp(cmd, "crawl"))   return cmd_crawl(argc, argv);
    if (!strcmp(cmd, "serve"))   return cmd_serve(argc, argv);
    if (!strcmp(cmd, "weigh"))   return cmd_weigh(argc, argv);
    if (!strcmp(cmd, "snapshot-export")) return cmd_snapshot_export(argc, argv);
    if (!strcmp(cmd, "snapshot-verify")) return cmd_snapshot_verify(argc, argv);
    if (!strcmp(cmd, "snapshot-import")) return cmd_snapshot_import(argc, argv);
    if (!strcmp(cmd, "check")) {
        if (argc < 3) { fprintf(stderr, "usage: check <db> [serve-db]\n"); return 2; }
        IdxCheckReport r;
        return idx_db_check(argv[2], argc > 3 ? argv[3] : NULL, stdout, &r) ? 1 : 0;
    }
    return 2;
}
