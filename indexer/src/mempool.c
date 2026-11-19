// mempool.c — see mempool.h. Two chained hash tables (by txid, by prevout) over
// a shared set of entries, one mutex, static zero-initialized state.
#include "mempool.h"
#include "txcheck.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#define MP_BUCKETS    8192            // power of two
#define MP_MASK       (MP_BUCKETS - 1)
#define MP_SEEN_RING  4096

typedef struct MpEntry {
    uint8_t  txid[32];
    uint8_t *raw; size_t len;
    int64_t  added;
    uint8_t (*prev)[36]; int nprev;
    struct MpEntry *hnext;            // txid bucket chain
} MpEntry;

typedef struct MpPrev {
    uint8_t  prevout[36];
    MpEntry *e;
    struct MpPrev *hnext;             // prevout bucket chain
} MpPrev;

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static MpEntry *g_tbucket[MP_BUCKETS];
static MpPrev  *g_pbucket[MP_BUCKETS];
static volatile int g_count;          // read racily as an empty-pool fast path
static size_t   g_bytes;
static uint8_t  g_seen[MP_SEEN_RING][32];
static int      g_seen_head, g_seen_n;

// ── hashing ──────────────────────────────────────────────────────────────────
// txid is already a uniform sha256d — take two bytes. prevout mixes via FNV-1a.
static unsigned tx_h(const uint8_t txid[32]) { return ((unsigned)txid[0] | (unsigned)txid[1] << 8) & MP_MASK; }
static unsigned pv_h(const uint8_t p[36]) {
    unsigned h = 2166136261u;
    for (int i = 0; i < 36; i++) { h ^= p[i]; h *= 16777619u; }
    return h & MP_MASK;
}

static MpEntry *find_entry(const uint8_t txid[32]) {
    for (MpEntry *e = g_tbucket[tx_h(txid)]; e; e = e->hnext)
        if (!memcmp(e->txid, txid, 32)) return e;
    return NULL;
}
static MpEntry *prevout_owner(const uint8_t prevout[36]) {
    for (MpPrev *p = g_pbucket[pv_h(prevout)]; p; p = p->hnext)
        if (!memcmp(p->prevout, prevout, 36)) return p->e;
    return NULL;
}

// caller holds g_mu. Unlink from both tables, free.
static void remove_entry(MpEntry *e) {
    unsigned b = tx_h(e->txid);
    for (MpEntry **pp = &g_tbucket[b]; *pp; pp = &(*pp)->hnext)
        if (*pp == e) { *pp = e->hnext; break; }
    for (int i = 0; i < e->nprev; i++) {
        unsigned pb = pv_h(e->prev[i]);
        for (MpPrev **pp = &g_pbucket[pb]; *pp; pp = &(*pp)->hnext)
            if ((*pp)->e == e && !memcmp((*pp)->prevout, e->prev[i], 36)) {
                MpPrev *dead = *pp; *pp = dead->hnext; free(dead); break;
            }
    }
    g_count--; g_bytes -= e->len;
    free(e->prev); free(e->raw); free(e);
}

// caller holds g_mu, and the pool is non-empty. Evict the oldest entry.
static void evict_oldest(void) {
    MpEntry *old = NULL;
    for (int b = 0; b < MP_BUCKETS; b++)
        for (MpEntry *e = g_tbucket[b]; e; e = e->hnext)
            if (!old || e->added < old->added) old = e;
    if (old) remove_entry(old);
}

// ── seen ring ────────────────────────────────────────────────────────────────
static int seen_locked(const uint8_t txid[32]) {
    for (int i = 0; i < g_seen_n; i++) if (!memcmp(g_seen[i], txid, 32)) return 1;
    return 0;
}
static void note_seen_locked(const uint8_t txid[32]) {
    if (seen_locked(txid)) return;
    memcpy(g_seen[g_seen_head], txid, 32);
    g_seen_head = (g_seen_head + 1) % MP_SEEN_RING;
    if (g_seen_n < MP_SEEN_RING) g_seen_n++;
}

// ── public API ───────────────────────────────────────────────────────────────
int mempool_accept(const uint8_t *raw, size_t len, uint8_t txid_out[32],
                   char *reason, size_t rc) {
    if (txid_out) memset(txid_out, 0, 32);
    if (!txcheck_stateless(raw, len, reason, rc)) {
        // mempool.h: the seen ring covers "(accepted OR rejected) — suppresses
        // re-requesting a tx we already processed and dropped", and sync.c's
        // inv handler is the consumer (`if (mempool_has(h) || mempool_seen(h))
        // continue;`). Without this, a peer re-announcing the same nonstandard
        // tx makes us getdata + re-validate identical bytes on every cycle.
        // Only bytes that PARSE carry a txid we can trust: a blob that fails to
        // parse has no txid at all (whatever we hashed would not be the id the
        // peer invs), so it must never be written into the ring — recording a
        // bogus 32 bytes would both miss the intended suppression and burn a
        // ring slot that a real txid needs.
        IdxTx bad;
        if (idx_tx_parse(raw, len, &bad)) {
            pthread_mutex_lock(&g_mu);
            note_seen_locked(bad.txid);
            pthread_mutex_unlock(&g_mu);
            idx_tx_free(&bad);
        }
        return 0;                       // txid_out stays zeroed on a txcheck reject
    }

    IdxTx tx;
    if (!idx_tx_parse(raw, len, &tx)) { if (reason && rc) snprintf(reason, rc, "malformed tx"); return 0; }
    if (txid_out) memcpy(txid_out, tx.txid, 32);

    pthread_mutex_lock(&g_mu);
    note_seen_locked(tx.txid);
    if (find_entry(tx.txid)) { pthread_mutex_unlock(&g_mu); idx_tx_free(&tx);
        if (reason && rc) snprintf(reason, rc, "already in pool"); return 0; }
    for (int i = 0; i < tx.n_in; i++)
        if (prevout_owner(tx.ins[i].prevout)) { pthread_mutex_unlock(&g_mu); idx_tx_free(&tx);
            if (reason && rc) snprintf(reason, rc, "conflicting input (double-spend)"); return 0; }

    while (g_count >= MEMPOOL_MAX_TXS || g_bytes + len > MEMPOOL_MAX_BYTES) {
        if (!g_count) break;                    // len alone exceeds the byte cap — shouldn't happen (≤100KB)
        evict_oldest();
    }

    MpEntry *e = calloc(1, sizeof *e);
    uint8_t *rawcopy = malloc(len);
    uint8_t (*prev)[36] = tx.n_in ? malloc((size_t)tx.n_in * 36) : NULL;
    if (!e || !rawcopy || (tx.n_in && !prev)) {
        pthread_mutex_unlock(&g_mu); free(e); free(rawcopy); free(prev); idx_tx_free(&tx);
        if (reason && rc) snprintf(reason, rc, "out of memory"); return 0;
    }
    memcpy(e->txid, tx.txid, 32);
    memcpy(rawcopy, raw, len); e->raw = rawcopy; e->len = len;
    e->added = (int64_t)time(NULL);
    e->nprev = tx.n_in; e->prev = prev;
    for (int i = 0; i < tx.n_in; i++) memcpy(e->prev[i], tx.ins[i].prevout, 36);
    // link into txid + prevout tables
    unsigned b = tx_h(e->txid); e->hnext = g_tbucket[b]; g_tbucket[b] = e;
    for (int i = 0; i < e->nprev; i++) {
        MpPrev *pn = malloc(sizeof *pn);
        if (!pn) continue;                       // conflict index best-effort; entry still valid
        memcpy(pn->prevout, e->prev[i], 36); pn->e = e;
        unsigned pb = pv_h(e->prev[i]); pn->hnext = g_pbucket[pb]; g_pbucket[pb] = pn;
    }
    g_count++; g_bytes += len;
    pthread_mutex_unlock(&g_mu);
    idx_tx_free(&tx);
    return 1;
}

int mempool_has(const uint8_t txid[32]) {
    pthread_mutex_lock(&g_mu);
    int r = find_entry(txid) != NULL;
    pthread_mutex_unlock(&g_mu);
    return r;
}

uint8_t *mempool_get_copy(const uint8_t txid[32], size_t *len_out) {
    pthread_mutex_lock(&g_mu);
    MpEntry *e = find_entry(txid);
    uint8_t *copy = NULL;
    if (e) { copy = malloc(e->len); if (copy) { memcpy(copy, e->raw, e->len); if (len_out) *len_out = e->len; } }
    pthread_mutex_unlock(&g_mu);
    return copy;
}

int mempool_seen(const uint8_t txid[32]) {
    pthread_mutex_lock(&g_mu);
    int r = find_entry(txid) != NULL || seen_locked(txid);
    pthread_mutex_unlock(&g_mu);
    return r;
}
void mempool_note_seen(const uint8_t txid[32]) {
    pthread_mutex_lock(&g_mu);
    note_seen_locked(txid);
    pthread_mutex_unlock(&g_mu);
}

void mempool_on_confirmed_tx(const uint8_t txid[32], const IdxTx *tx) {
    if (!g_count) return;                        // racy fast path — pool empty (initial sync)
    pthread_mutex_lock(&g_mu);
    MpEntry *e = find_entry(txid);
    if (e) remove_entry(e);
    if (tx) for (int i = 0; i < tx->n_in; i++) {
        MpEntry *o = prevout_owner(tx->ins[i].prevout);
        if (o) remove_entry(o);                  // a pool tx that double-spends the now-confirmed input
    }
    pthread_mutex_unlock(&g_mu);
}

void mempool_sweep(int64_t now) {
    if (!g_count) return;
    int64_t cutoff = now - MEMPOOL_EXPIRY_SEC;
    pthread_mutex_lock(&g_mu);
    for (int b = 0; b < MP_BUCKETS; b++) {
        MpEntry *e = g_tbucket[b];
        while (e) { MpEntry *next = e->hnext; if (e->added < cutoff) remove_entry(e); e = next; }
    }
    pthread_mutex_unlock(&g_mu);
}

int mempool_count(void) { return g_count; }

size_t mempool_txids(uint8_t (*out)[32], size_t max) {
    size_t n = 0;
    pthread_mutex_lock(&g_mu);
    for (int b = 0; b < MP_BUCKETS && n < max; b++)
        for (MpEntry *e = g_tbucket[b]; e && n < max; e = e->hnext)
            memcpy(out[n++], e->txid, 32);
    pthread_mutex_unlock(&g_mu);
    return n;
}

void mempool_scan(void (*cb)(void *, const uint8_t[32], const uint8_t *, size_t), void *ud) {
    pthread_mutex_lock(&g_mu);
    for (int b = 0; b < MP_BUCKETS; b++)
        for (MpEntry *e = g_tbucket[b]; e; e = e->hnext)
            cb(ud, e->txid, e->raw, e->len);
    pthread_mutex_unlock(&g_mu);
}

void mempool_reset(void) {
    pthread_mutex_lock(&g_mu);
    for (int b = 0; b < MP_BUCKETS; b++) {
        MpEntry *e = g_tbucket[b];
        while (e) { MpEntry *next = e->hnext; free(e->prev); free(e->raw); free(e); e = next; }
        g_tbucket[b] = NULL;
        MpPrev *p = g_pbucket[b];
        while (p) { MpPrev *next = p->hnext; free(p); p = next; }
        g_pbucket[b] = NULL;
    }
    g_count = 0; g_bytes = 0; g_seen_head = g_seen_n = 0;
    pthread_mutex_unlock(&g_mu);
}
