// dirscan.c — see dirscan.h. One thread, own read handles (an SpState on the
// dns record store + a raw sqlite3 on the chain projection, both WAL-safe
// alongside the engines' writers). Rebuilds on a ~10 s timer, a data_version
// change, or an explicit kick; publishes a double-buffered DirRow[].
#include "dirscan.h"

#include "dns_state.h"      // SpState + dns_state_zone (via pepenet/state.h)
#include "zone.h"           // zone / zone_rec
#include "dns_wire.h"       // DNS_A / DNS_TLSA type constants

#include <sqlite3.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static struct {
    char store_path[512], chain_db[512];
    pthread_t th;
    volatile int stop, kick;
    int started;

    pthread_mutex_t mu;
    DirRow  buf[DIR_MAX];       // published snapshot
    int     n;
    int64_t built_at;
    int     last_ms;
} g = { .mu = PTHREAD_MUTEX_INITIALIZER };

// collect names-with-zones into a growing list on the scan thread
struct namelist { char (*names)[40]; int n, cap; };
static int names_cb(void *u, const char *name) {
    struct namelist *nl = u;
    if (nl->n == nl->cap) {
        int cap = nl->cap ? nl->cap * 2 : 128;
        void *p = realloc(nl->names, (size_t)cap * sizeof nl->names[0]);
        if (!p) return 0;                       // stop iter on OOM
        nl->names = p; nl->cap = cap;
    }
    snprintf(nl->names[nl->n], sizeof nl->names[0], "%s", name);
    nl->n++;
    return 1;
}

// registry lease/owner for one name (empty → not registered)
static int registry_lease(sqlite3 *db, const char *name, int64_t *lease) {
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db, "SELECT lease_expiry FROM names WHERE name=?", -1, &st, NULL) != SQLITE_OK)
        return 0;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    int found = 0;
    if (sqlite3_step(st) == SQLITE_ROW) { *lease = sqlite3_column_int64(st, 0); found = 1; }
    sqlite3_finalize(st);
    return found;
}

static int cmp_rows(const void *a, const void *b) {
    const DirRow *x = a, *y = b;
    int sx = (x->has_a && x->has_tlsa) ? 2 : x->has_a ? 1 : 0;   // sites first
    int sy = (y->has_a && y->has_tlsa) ? 2 : y->has_a ? 1 : 0;
    if (sx != sy) return sy - sx;
    return strcmp(x->name, y->name);
}

static void rebuild(SpState *st, sqlite3 *chain) {
    struct namelist nl = { 0 };
    sp_state_names(st, names_cb, &nl);

    DirRow *rows = calloc(DIR_MAX, sizeof *rows);
    int n = 0;
    for (int i = 0; i < nl.n && n < DIR_MAX; i++) {
        zone z;
        int nr = dns_state_zone(st, nl.names[i], &z);
        if (nr <= 0) continue;
        DirRow *r = &rows[n];
        memset(r, 0, sizeof *r);
        snprintf(r->name, sizeof r->name, "%s", nl.names[i]);
        r->nrec = nr;
        int64_t lease = 0;
        r->registered = registry_lease(chain, nl.names[i], &lease);
        r->lease_expiry = lease;
        for (int k = 0; k < z.n; k++) {
            zone_rec *rec = &z.recs[k];
            if (rec->type == DNS_A && rec->label[0] == 0 && rec->rdlen == 4) {
                r->has_a = 1;
                snprintf(r->a_ip, sizeof r->a_ip, "%u.%u.%u.%u",
                         rec->rdata[0], rec->rdata[1], rec->rdata[2], rec->rdata[3]);
            }
            if (rec->type == DNS_TLSA && strncmp(rec->label, "_443._tcp", 9) == 0)
                r->has_tlsa = 1;
            if (rec->type == DNS_TXT && strcmp(rec->label, "_site") == 0 &&
                rec->rdlen > 0) {
                // TXT rdata is length-prefixed character-strings; skip the
                // first prefix byte when it matches (single-string case)
                int off = (rec->rdata[0] == rec->rdlen - 1) ? 1 : 0;
                int len = rec->rdlen - off;
                if (len > (int)sizeof r->site - 1) len = (int)sizeof r->site - 1;
                memcpy(r->site, rec->rdata + off, (size_t)len);
                r->site[len] = 0;
            }
        }
        n++;
    }
    free(nl.names);
    qsort(rows, (size_t)n, sizeof *rows, cmp_rows);

    pthread_mutex_lock(&g.mu);
    memcpy(g.buf, rows, (size_t)n * sizeof *rows);
    g.n = n;
    pthread_mutex_unlock(&g.mu);
    free(rows);
}

static void *scan_main(void *arg) {
    (void)arg;
    SpState *st = sp_state_open(g.store_path);
    sqlite3 *chain = NULL;
    sqlite3_open_v2(g.chain_db, &chain, SQLITE_OPEN_READONLY, NULL);
    if (!st || !chain) { if (st) sp_state_close(st); if (chain) sqlite3_close(chain); g.started = 0; return NULL; }

    int64_t last_dv_store = -1, last_dv_chain = -1;
    int idle = 0;                               // 100 ms ticks since last rebuild
    while (!g.stop) {
        // rebuild triggers: explicit kick, ~10 s timer, or a data_version bump
        int64_t dvs = 0, dvc = 0;
        sqlite3_stmt *q;
        // (the dns store's data_version rides its own connection — open a cheap
        //  probe on the same file each pass; sqlite caches the page anyway)
        if (sqlite3_prepare_v2(chain, "PRAGMA data_version", -1, &q, NULL) == SQLITE_OK) {
            if (sqlite3_step(q) == SQLITE_ROW) dvc = sqlite3_column_int64(q, 0);
            sqlite3_finalize(q);
        }
        // store data_version via a throwaway handle-free check: reuse store's db
        // by folding is heavy, so approximate store-change detection with the
        // kick + timer only; dvs stays 0 and the timer covers gossip arrivals.
        (void)dvs;

        int due = g.kick || idle >= 100 ||               // kicked or ~10 s
                  dvc != last_dv_chain;
        if (due) {
            g.kick = 0;
            struct timespec t0, t1;
            clock_gettime(CLOCK_MONOTONIC, &t0);
            rebuild(st, chain);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            int ms = (int)((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000);
            pthread_mutex_lock(&g.mu);
            g.built_at = (int64_t)time(NULL);
            g.last_ms = ms;
            pthread_mutex_unlock(&g.mu);
            last_dv_chain = dvc; last_dv_store = dvs;
            idle = 0;
        }
        struct timespec ts = { 0, 100 * 1000 * 1000 };  // 100 ms
        nanosleep(&ts, NULL);
        idle++;
    }
    sp_state_close(st);
    sqlite3_close(chain);
    g.started = 0;
    return NULL;
}

int dirscan_start(const char *store_path, const char *chain_db) {
    if (g.started) return 1;
    snprintf(g.store_path, sizeof g.store_path, "%s", store_path);
    snprintf(g.chain_db, sizeof g.chain_db, "%s", chain_db);
    g.stop = 0; g.kick = 1;                      // build once up front
    g.started = 1;
    if (pthread_create(&g.th, NULL, scan_main, NULL) != 0) { g.started = 0; return 0; }
    return 1;
}

void dirscan_stop(void) {
    if (!g.started) return;
    g.stop = 1;
    pthread_join(g.th, NULL);
}

void dirscan_kick(void) { g.kick = 1; }

int dirscan_snapshot(DirRow *out, int max, int64_t *built_at, int *last_ms) {
    pthread_mutex_lock(&g.mu);
    int n = g.n < max ? g.n : max;
    memcpy(out, g.buf, (size_t)n * sizeof *out);
    if (built_at) *built_at = g.built_at;
    if (last_ms)  *last_ms = g.last_ms;
    pthread_mutex_unlock(&g.mu);
    return n;
}
