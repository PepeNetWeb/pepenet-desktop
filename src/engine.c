// engine.c — background sync thread + UI-thread projection reads.
//
// Threading model (mirrors the old client's indexer.c, but over indexers/c):
//   sync thread : owns the DB write handle for the duration of each pass —
//                 it literally runs indexer_main("sync", ...), the same code
//                 path as the headless indexerd, then sleeps and repeats.
//   UI thread   : its own SQLite connection, reads projections only. WAL mode
//                 (set by idx_db_open's schema pragmas) makes this safe.
// The only shared mutable state is the tiny status block under g_mu.
#include "engine.h"
#include "appconf.h"
#include "indexer.h"
#include "db.h"
#include "chain.h"
#include "mempool.h"
#include "oracle_feed.h"
#include "sm.h"             // SM_OWNED.. name states
#include "fee.h"            // the network-fee quote (recent-window Q3)

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PASS_PAUSE_S 20          // pep blocks ~1/min; a pass ends when caught up

static struct {
    char coin[16], dbpath[512], ip[64];
    pthread_t th;
    pthread_mutex_t mu;
    volatile int stop, running, pass_active;
    volatile int crawl_req, crawl_stop, crawl_active;   // manual chain walk (Peers screen)
    int last_rc;
    int dn_known;       // discovery-marked peers known per the last crawl (0 = dark)
    int64_t passes;
} g;

static sqlite3 *g_read;          // UI-thread read connection (lazy)
static int64_t g_rate_h = -1;    // height the cached rate + fee were computed at
static uint64_t g_rate;
static int64_t g_fee;

// pep's flat-tail subsidy — MUST match oracle_feed.c's SUBSIDY_KOINU_DEFAULT
// (the sync fold and this quote read the same blocks table; a different host
// chain would change both in lockstep via the profile).
#define SUBSIDY_KOINU (10000LL * SM_KOINU_PER_DOGE)

// the fee quote's inputs: the newest FEE_EST_WINDOW folded blocks — the same
// per-block (coinbase, bytes) feed §3.4 reads, just the recent slice of it
static int64_t fee_quote_at(sqlite3 *db, int64_t tip) {
    int64_t cb[FEE_EST_WINDOW], bz[FEE_EST_WINDOW];
    int n = 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT coinbase, bytes FROM blocks WHERE height <= ?1 "
            "ORDER BY height DESC LIMIT ?2",
            -1, &st, NULL) != SQLITE_OK)
        return FEE_FLOOR_K;
    sqlite3_bind_int64(st, 1, tip);
    sqlite3_bind_int64(st, 2, FEE_EST_WINDOW);
    while (n < FEE_EST_WINDOW && sqlite3_step(st) == SQLITE_ROW) {
        cb[n] = sqlite3_column_int64(st, 0);
        bz[n] = sqlite3_column_int64(st, 1);
        n++;
    }
    sqlite3_finalize(st);
    return fee_estimate(cb, bz, n, SUBSIDY_KOINU);
}

// live mesh links: serve-plane conns, either direction, whose peer carries the
// IDX_DNET_MARK agent (or is already seated on the mesh carrier). The crawl's
// job is finding mesh peers — while ≥1 link is up there is nothing to hunt.
// This is deliberately NOT g.dn_known: that counts crawl-discovered addrs in
// the db, and a node embedded through its CONFIGURED seed (the normal client)
// has a lit mesh with dn_known still 0.
static int mesh_links_live(void) {
    IdxServeConn c[64];
    int n = idx_serve_conns(c, 64);
    int live = 0;
    for (int i = 0; i < n; i++)
        if (c[i].connected && c[i].up &&
            (c[i].mesh || !strncmp(c[i].agent, IDX_DNET_MARK, strlen(IDX_DNET_MARK))))
            live++;
    return live;
}

static void *sync_thread(void *arg) {
    (void)arg;
    // head start: let the serve plane seat its configured peers and publish a
    // connection snapshot before the first pass — the ladder's one-connection
    // rule reads that snapshot, and without the pause both planes would race
    // to dial the seed at boot (the exact double-connection this app forbids)
    for (int i = 0; i < 3 && !g.stop; i++) sleep(1);
    while (!g.stop) {
        char *argv[5] = { "pepenet-desktop", "sync", g.coin, g.dbpath, g.ip };
        pthread_mutex_lock(&g.mu); g.pass_active = 1; pthread_mutex_unlock(&g.mu);
        int rc = indexer_main(5, argv);
        pthread_mutex_lock(&g.mu);
        g.pass_active = 0; g.last_rc = rc; g.passes++;
        pthread_mutex_unlock(&g.mu);
        // chain walk (peer-discovery slice 2): OPERATOR-DRIVEN only — the
        // Peers screen's Start queues it, Stop winds it down. It runs here,
        // between passes, on purpose: one db writer cadence, never concurrent
        // with a sync. Hard interlocks mirror the UI's disabled Start: never
        // while a marked peer is connected (the walk exists to FIND one — a
        // live mesh makes it pure transient-connection noise at every probed
        // peer), and never on the seed itself (clients dial us; marked peers
        // arrive via inbound + dnaddr).
        if (!g.stop && g.crawl_req) {
            g.crawl_req = 0;
            if (!idx_self_seed && !mesh_links_live()) {
                g.crawl_stop = 0;
                g.crawl_active = 1;
                g.dn_known = idx_crawl(g.coin, g.dbpath, NULL, 64, &g.crawl_stop);
                g.crawl_active = 0;
            }
        }
        // a block landing in the serve plane's stage — or a walk request —
        // ends the pause early: blocks fold within ~a second of the mesh inv,
        // and Start acts promptly instead of at the timer
        int64_t sseq = idx_serve_stage_seq;
        for (int i = 0; i < PASS_PAUSE_S && !g.stop && !g.crawl_req &&
                        idx_serve_stage_seq == sseq; i++) sleep(1);
    }
    pthread_mutex_lock(&g.mu); g.running = 0; pthread_mutex_unlock(&g.mu);
    return NULL;
}


int engine_start(const char *coin, const char *dbpath, const char *ip) {
    if (g.running) return 1;
    idx_sync_agent = APP_CHAIN_AGENT;   // our P2P subver, before the first pass
    snprintf(g.coin, sizeof g.coin, "%s", coin);
    snprintf(g.dbpath, sizeof g.dbpath, "%s", dbpath);
    snprintf(g.ip, sizeof g.ip, "%s", ip);
    pthread_mutex_init(&g.mu, NULL);
    g.stop = 0; g.running = 1; g.last_rc = -1; g.passes = 0;
    idx_sync_stop = 0;
    if (pthread_create(&g.th, NULL, sync_thread, NULL) != 0) { g.running = 0; return 0; }
    return 1;
}

// Manual chain walk (the Peers screen's Start/Stop). Start is refused under
// the same interlocks the UI greys the button for; it takes effect within a
// second (the pause loop watches the flag) at the next pass boundary.
void engine_crawl_start(void) {
    if (!g.running || idx_self_seed || mesh_links_live()) return;
    g.crawl_req = 1;
}
void engine_crawl_stop(void) {
    g.crawl_req = 0;
    g.crawl_stop = 1;
}
int engine_crawl_busy(void) {
    return g.crawl_req || g.crawl_active;
}

void engine_stop(void) {
    if (!g.running && !g.th) return;
    g.stop = 1;
    g.crawl_stop = 1;            // wind down a walk that's mid-flight
    idx_sync_stop = 1;           // wind down a pass that's mid-flight
    pthread_join(g.th, NULL);
    idx_sync_stop = 0;
    if (g_read) { idx_db_close(g_read); g_read = NULL; }
}

static sqlite3 *read_db(void) {
    if (!g_read) g_read = idx_db_open(g.dbpath);
    return g_read;
}

// ── dev-wallet plumbing ──────────────────────────────────────────────────────
int engine_watch(const char *dbpath, const uint8_t h160[20]) {
    sqlite3 *db = idx_db_open(dbpath);           // pre-engine_start: no writer yet
    if (!db) return 0;
    idx_db_watch_add(db, h160);
    idx_db_close(db);
    return 1;
}

static void bal_cb(void *u, const uint8_t txid[32], uint32_t vout,
                   int64_t value, int64_t height) {
    (void)txid; (void)vout; (void)height;
    *(int64_t *)u += value;
}

int64_t engine_balance(const uint8_t h160[20]) {
    sqlite3 *db = read_db();
    if (!db) return 0;
    int64_t sum = 0;
    idx_db_utxos(db, h160, bal_cb, &sum);
    return sum;
}

// ── unconfirmed incoming (relay mempool) ─────────────────────────────────────
typedef struct { const uint8_t *h160; int64_t sum; } IncCtx;
static void inc_cb(void *u, const uint8_t txid[32], const uint8_t *raw, size_t len) {
    (void)txid;
    IncCtx *c = u;
    IdxTx tx;
    if (!idx_tx_parse(raw, len, &tx)) return;
    // our own send? any input spending one of our (still-unspent-in-db) utxos
    // means we authored this tx — its outputs back to us are change, not income.
    int mine = 0;
    for (int i = 0; i < tx.n_in && !mine; i++) {
        const uint8_t *po = tx.ins[i].prevout;
        uint32_t vout = (uint32_t)po[32] | (uint32_t)po[33] << 8 |
                        (uint32_t)po[34] << 16 | (uint32_t)po[35] << 24;
        if (engine_outpoint_unspent(c->h160, po, vout)) mine = 1;
    }
    if (!mine)
        for (int o = 0; o < tx.n_out; o++) {
            uint8_t hh[20], type;
            if (idx_script_payee(tx.outs[o].spk, tx.outs[o].spklen, hh, &type) &&
                type == 0 && !memcmp(hh, c->h160, 20))
                c->sum += tx.outs[o].value;
        }
    idx_tx_free(&tx);
}

int64_t engine_incoming(const uint8_t h160[20]) {
    IncCtx c = { h160, 0 };
    mempool_scan(inc_cb, &c);     // holds the pool lock; inc_cb reads our own db connection
    return c.sum;
}

// ── names projection reads (UI thread) ───────────────────────────────────────
static void to_hex40(const uint8_t h160[20], char out[41]) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 20; i++) { out[2*i] = H[h160[i] >> 4]; out[2*i+1] = H[h160[i] & 15]; }
    out[40] = 0;
}

typedef struct { EngineName *out; int max, n; } NameCtx;
static void my_names_cb(void *u, const char *name, int64_t lease, int st) {
    NameCtx *c = u;
    if (c->n >= c->max) return;
    EngineName *e = &c->out[c->n++];
    memset(e, 0, sizeof *e);
    snprintf(e->name, sizeof e->name, "%s", name);
    e->st = st;
    e->lease_expiry = lease;
}

int engine_my_names(const uint8_t h160[20], EngineName *out, int max) {
    sqlite3 *db = read_db();
    if (!db) return 0;
    char hh[41];
    to_hex40(h160, hh);
    NameCtx c = { out, max, 0 };
    idx_db_owned(db, hh, my_names_cb, &c);
    for (int i = 0; i < c.n; i++) {         // market fields for the locked rows
        if (out[i].st == SM_OWNED) continue;
        IdxNameRow r;
        if (!idx_db_name_row(db, out[i].name, &r)) continue;
        out[i].price = r.price;
        out[i].offer_expiry = r.offer_expiry;
        out[i].reserve_expiry = r.reserve_expiry;
        memcpy(out[i].buyer, r.buyer, 20);
    }
    return c.n;
}

int engine_market_mine(const uint8_t h160[20], EngineName *out, int max) {
    sqlite3 *db = read_db();
    if (!db) return 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT name,st,lease_expiry,price,offer_expiry,reserve_expiry"
            " FROM names WHERE buyer=? ORDER BY name", -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_blob(st, 1, h160, 20, SQLITE_STATIC);
    int n = 0;
    while (n < max && sqlite3_step(st) == SQLITE_ROW) {
        int s = sqlite3_column_int(st, 1);
        if (s != SM_OFFERED && s != SM_RESERVED) continue;   // stale buyer column
        EngineName *e = &out[n++];
        memset(e, 0, sizeof *e);
        snprintf(e->name, sizeof e->name, "%s", sqlite3_column_text(st, 0));
        e->st = s;
        e->lease_expiry = sqlite3_column_int64(st, 2);
        e->price = (uint64_t)sqlite3_column_int64(st, 3);
        e->offer_expiry = sqlite3_column_int64(st, 4);
        e->reserve_expiry = sqlite3_column_int64(st, 5);
        memcpy(e->buyer, h160, 20);
    }
    sqlite3_finalize(st);
    return n;
}

int engine_listings(EngineName *out, int max) {
    sqlite3 *db = read_db();
    if (!db) return 0;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT name,st,lease_expiry,price,offer_expiry,reserve_expiry,buyer,owner"
            " FROM names WHERE st IN (?,?) ORDER BY price DESC, name", -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int(st, 1, SM_LISTED);
    sqlite3_bind_int(st, 2, SM_RESERVED);
    int n = 0;
    while (n < max && sqlite3_step(st) == SQLITE_ROW) {
        EngineName *e = &out[n++];
        memset(e, 0, sizeof *e);
        snprintf(e->name, sizeof e->name, "%s", sqlite3_column_text(st, 0));
        e->st = sqlite3_column_int(st, 1);
        e->lease_expiry = sqlite3_column_int64(st, 2);
        e->price = (uint64_t)sqlite3_column_int64(st, 3);
        e->offer_expiry = sqlite3_column_int64(st, 4);
        e->reserve_expiry = sqlite3_column_int64(st, 5);
        const void *by = sqlite3_column_blob(st, 6);
        const void *ow = sqlite3_column_blob(st, 7);
        if (by && sqlite3_column_bytes(st, 6) == 20) memcpy(e->buyer, by, 20);
        if (ow && sqlite3_column_bytes(st, 7) == 20) memcpy(e->owner, ow, 20);
    }
    sqlite3_finalize(st);
    return n;
}

int engine_name_lookup(const char *name, uint8_t owner160[20], int *st) {
    sqlite3 *db = read_db();
    if (!db) return 0;
    IdxNameRow r;
    if (!idx_db_name_row(db, name, &r)) return 0;
    if (owner160) {
        if (r.owner_type != 0) return -1;   // exists, but not a P2PKH owner
        memcpy(owner160, r.owner, 20);
    }
    if (st) *st = r.st;
    return 1;
}

// ── known peers (Peers page) ─────────────────────────────────────────────────
// Raw read of the indexer's peers table (schema: db.c) on the UI connection —
// same pattern as engine_listings' names read. Rows are the MESH bucket only
// (confirmed IDX_DNET_MARK agents first, then dnaddr-vouched hints, freshest
// first) — the plain chain harvest is thousands of addrs nobody needs to
// scroll; it surfaces as the total count alone.
int engine_peers(EnginePeer *out, int max, int *total, int *pepenet) {
    if (total) *total = 0;
    if (pepenet) *pepenet = 0;
    sqlite3 *db = read_db();
    if (!db) return 0;
    sqlite3_stmt *st = NULL;
    if (total || pepenet) {
        if (sqlite3_prepare_v2(db,
                "SELECT count(*), sum(agent LIKE '" IDX_DNET_MARK "%')"
                " FROM peers", -1, &st, NULL) == SQLITE_OK) {
            if (sqlite3_step(st) == SQLITE_ROW) {
                if (total)   *total   = sqlite3_column_int(st, 0);
                if (pepenet) *pepenet = sqlite3_column_int(st, 1);
            }
            sqlite3_finalize(st);
        }
        st = NULL;
    }
    if (sqlite3_prepare_v2(db,
            "SELECT addr, ifnull(agent,''), last_seen, ifnull(last_good,0),"
            "       ifnull(dnet,0)"
            " FROM peers"
            " WHERE agent LIKE '" IDX_DNET_MARK "%' OR ifnull(dnet,0) = 1"
            " ORDER BY (agent LIKE '" IDX_DNET_MARK "%') DESC,"
            "          max(ifnull(last_good,0), last_seen) DESC"
            " LIMIT ?", -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_int(st, 1, max);
    int n = 0;
    while (n < max && sqlite3_step(st) == SQLITE_ROW) {
        EnginePeer *p = &out[n++];
        memset(p, 0, sizeof *p);
        snprintf(p->addr, sizeof p->addr, "%s", sqlite3_column_text(st, 0));
        snprintf(p->agent, sizeof p->agent, "%s", sqlite3_column_text(st, 1));
        p->last_seen = sqlite3_column_int64(st, 2);
        p->last_good = sqlite3_column_int64(st, 3);
        p->dnet      = sqlite3_column_int(st, 4);
    }
    sqlite3_finalize(st);
    return n;
}

typedef struct { const uint8_t *txid; uint32_t vout; int found; } OutpCtx;
static void outp_cb(void *u, const uint8_t txid[32], uint32_t vout,
                    int64_t value, int64_t height) {
    (void)value; (void)height;
    OutpCtx *c = u;
    if (!c->found && vout == c->vout && !memcmp(txid, c->txid, 32)) c->found = 1;
}

int engine_outpoint_unspent(const uint8_t h160[20], const uint8_t txid[32],
                            uint32_t vout) {
    sqlite3 *db = read_db();
    if (!db) return 0;
    OutpCtx c = { txid, vout, 0 };
    idx_db_utxos(db, h160, outp_cb, &c);
    return c.found;
}

typedef struct { EngineUtxoCb cb; void *ud; int n; } UxCtx;
static void ux_cb(void *u, const uint8_t txid[32], uint32_t vout,
                  int64_t value, int64_t height) {
    (void)height;
    UxCtx *c = u;
    c->cb(c->ud, txid, vout, value);
    c->n++;
}

int engine_utxos(const uint8_t h160[20], EngineUtxoCb cb, void *ud) {
    sqlite3 *db = read_db();
    if (!db) return 0;
    UxCtx c = { cb, ud, 0 };
    idx_db_utxos(db, h160, ux_cb, &c);
    return c.n;
}

void engine_status(EngineStatus *out) {
    memset(out, 0, sizeof *out);
    pthread_mutex_lock(&g.mu);
    out->running = g.running; out->pass_active = g.pass_active;
    out->last_rc = g.last_rc;  out->passes = g.passes;
    pthread_mutex_unlock(&g.mu);
    out->peer_height = idx_sync_peer_height;   // indexer.h seam (volatile, sync thread writes)
    sqlite3 *db = read_db(); if (!db) return;
    static int64_t g_act;             // immutable per-db — read once, then cached
    if (!g_act) g_act = idx_db_get_activation(db, 0);
    out->activation = g_act;
    int64_t h = 0; uint8_t tip[32];
    if (!idx_db_load_sync(db, &h, tip)) return;
    out->height = h;
    if (h != g_rate_h) {         // rate + fee: recompute only when the tip moved
        OracleFeed *o = oracle_new();
        idx_db_oracle_warm(db, o);
        int64_t mtp; uint64_t rate;
        oracle_for_height(o, h + 1, &mtp, &rate);
        oracle_free(o);
        g_rate = rate;
        g_fee = fee_quote_at(db, h);
        g_rate_h = h;
    }
    out->rate = g_rate;
    out->year_cost = 13 * (int64_t)g_rate;
    out->fee = g_fee;
}
