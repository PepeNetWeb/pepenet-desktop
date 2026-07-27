/* t_dirscan.c — the Discover directory scan (src/dirscan.c).
 *
 * "dirscan" is not a filesystem walk: it is the .pepe WEBSITE directory. It
 * joins the DNS record store (pepenet-mesh sp_state, one row per label/type)
 * against the chain's names projection (sqlite) and publishes a sorted,
 * double-buffered DirRow[] the UI copies each frame. This suite builds a real
 * store with real owner-signed records and a real projection db under a
 * mkdtemp'd directory, drives the scanner's own rebuild, and proves:
 *
 *   · an EMPTY store yields zero rows (and does not touch the caller's buffer);
 *   · a zone with an apex A becomes a site: has_a, the dotted a_ip, nrec;
 *   · _443._tcp TLSA sets has_tlsa; a zone with records but no apex A is not
 *     a site; a non-apex A does not count;
 *   · the `_site` TXT blurb is un-length-prefixed and truncated to the row,
 *     never past it;
 *   · the chain join fills registered/lease_expiry, and a name the projection
 *     has never heard of reads registered=0, lease_expiry=0;
 *   · the sort is sites-with-TLSA, then sites, then the rest, alphabetical
 *     inside each tier;
 *   · MANY zones (past DIR_MAX) do not overrun the published buffer, and
 *     dirscan_snapshot honours the caller's `max` (canary-checked);
 *   · a store path that does not exist, and a path near PATH_MAX, are survived
 *     without a crash or a path-buffer overrun;
 *   · the thread lifecycle (start / kick / snapshot / stop) is safe and
 *     idempotent.
 *
 * dirscan.c is #included rather than linked so the suite can call its own
 * rebuild() deterministically instead of racing a 100 ms timer thread.
 */
#include "../src/dirscan.c"

#include "dns_state.h"
#include "zone.h"
#include "dns_wire.h"
#include "pepenet/crypto.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_fail;
#define CHECK(cond, name) do { \
    if (cond) printf("ok   %s\n", name); \
    else      { printf("FAIL %s\n", name); g_fail = 1; } \
} while (0)

/* ── SplitMix64 (never rand()) ────────────────────────────────────────────── */
static uint64_t g_rng = 0x123456789ABCDEFULL;
static uint64_t sm64(void) {
    uint64_t z = (g_rng += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* ── the fake chain the store's admission asks ────────────────────────────── */
static uint32_t  g_tip = 5000;
static uint8_t   g_owner160[20];
static int fk_owner(void *u, const char *name, uint8_t owner[20]) {
    (void)u; (void)name;
    memcpy(owner, g_owner160, 20);        /* we own every name in this fixture */
    return 1;
}
static int fk_header(void *u, uint32_t height, uint8_t out[32]) {
    (void)u;
    if (height > g_tip) return 0;
    uint8_t seed[8] = { 'h','d','r',2, (uint8_t)height, (uint8_t)(height >> 8),
                        (uint8_t)(height >> 16), (uint8_t)(height >> 24) };
    sp_sha256(seed, sizeof seed, out);
    return 1;
}
static uint32_t fk_tip(void *u) { (void)u; return g_tip; }
static SpChainOracle ORC = { NULL, fk_owner, fk_header, fk_tip };

static uint8_t OPRIV[32], OPUB[33];

/* publish one record into the store, owner-signed */
static int put(SpState *st, const char *name, const char *label,
               const char *type, uint32_t ttl, const char *value) {
    zone_rec r;
    if (zone_build_rec(label, type, ttl, value, &r) != 0) return -99;
    char err[160];
    return dns_state_put(st, &ORC, name, &r, OPRIV, OPUB,
                         SP_CERT_NONE, NULL, 0, err, sizeof err);
}
/* publish raw rdata (for the length-prefix cases zone_build_rec would escape) */
static int put_raw(SpState *st, const char *name, const char *label, uint16_t type,
                   const uint8_t *rdata, int rdlen) {
    zone_rec r;
    memset(&r, 0, sizeof r);
    snprintf(r.label, sizeof r.label, "%s", label);
    r.type = type; r.ttl = 300; r.rdlen = (uint16_t)rdlen;
    memcpy(r.rdata, rdata, (size_t)rdlen);
    char err[160];
    return dns_state_put(st, &ORC, name, &r, OPRIV, OPUB,
                         SP_CERT_NONE, NULL, 0, err, sizeof err);
}

/* ── the fake chain projection ────────────────────────────────────────────── */
static sqlite3 *open_chain(const char *path) {
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) return NULL;
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS names("
                     "name TEXT PRIMARY KEY, lease_expiry INTEGER)", NULL, NULL, NULL);
    return db;
}
static void reg_name(sqlite3 *db, const char *name, int64_t lease) {
    sqlite3_stmt *s;
    sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO names(name,lease_expiry) VALUES(?,?)",
                       -1, &s, NULL);
    sqlite3_bind_text(s, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(s, 2, lease);
    sqlite3_step(s);
    sqlite3_finalize(s);
}

static const DirRow *find_row(const DirRow *rows, int n, const char *name) {
    for (int i = 0; i < n; i++) if (strcmp(rows[i].name, name) == 0) return &rows[i];
    return NULL;
}

int main(void) {
    char tmpl[] = "/tmp/t_dirscan_XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) { printf("FAIL mkdtemp\n"); return 1; }
    char storep[512], chainp[512];
    snprintf(storep, sizeof storep, "%s/dns.db", dir);
    snprintf(chainp, sizeof chainp, "%s/chain.db", dir);

    sp_sha256((const uint8_t *)"dirscan-owner", 13, OPRIV);
    while (!sp_pubkey(OPRIV, OPUB)) sp_sha256(OPRIV, 32, OPRIV);
    sp_hash160(OPUB, 33, g_owner160);

    DirRow rows[DIR_MAX + 8];
    int n;

    printf("-- an empty store --\n");
    {
        SpState *st = sp_state_open(storep);
        sqlite3 *ch = open_chain(chainp);
        CHECK(st != NULL && ch != NULL, "the fixture store and projection open");
        rebuild(st, ch);
        memset(rows, 0xAB, sizeof rows);
        n = dirscan_snapshot(rows, DIR_MAX, NULL, NULL);
        CHECK(n == 0, "an empty store publishes zero rows");
        int untouched = 1;
        for (unsigned i = 0; i < sizeof rows[0]; i++)
            if (((unsigned char *)&rows[0])[i] != 0xAB) untouched = 0;
        CHECK(untouched, "…and the caller's buffer is not written at all");
        int64_t built = -1; int ms = -1;
        dirscan_snapshot(rows, DIR_MAX, &built, &ms);
        CHECK(built == 0 && ms == 0, "built_at/last_ms are 0 before the thread ever timed a build");
        sp_state_close(st);
        sqlite3_close(ch);
    }

    printf("-- a zone becomes a site --\n");
    {
        SpState *st = sp_state_open(storep);
        sqlite3 *ch = open_chain(chainp);

        /* a full site: apex A + TLSA + a _site blurb */
        CHECK(put(st, "alpha", "@", "A", 300, "216.24.57.1") == 1, "alpha apex A publishes");
        CHECK(put(st, "alpha", "_443._tcp", "TLSA", 300,
                  "3 1 1 0000000000000000000000000000000000000000000000000000000000000000") == 1,
              "alpha _443._tcp TLSA publishes");
        CHECK(put(st, "alpha", "_site", "TXT", 300, "the alpha site") == 1, "alpha _site TXT publishes");
        /* a plain site: apex A only */
        CHECK(put(st, "bravo", "@", "A", 300, "10.0.0.7") == 1, "bravo apex A publishes");
        /* records but no apex A: not a site */
        CHECK(put(st, "charlie", "www", "A", 300, "10.0.0.8") == 1, "charlie has only a www A");
        CHECK(put(st, "delta", "@", "TXT", 300, "no website here") == 1, "delta has only a TXT");

        reg_name(ch, "alpha", 1900000000);
        reg_name(ch, "bravo", 1800000000);
        /* charlie/delta are deliberately NOT in the projection */

        rebuild(st, ch);
        n = dirscan_snapshot(rows, DIR_MAX, NULL, NULL);
        CHECK(n == 4, "all four zones produce a row");

        const DirRow *a = find_row(rows, n, "alpha");
        CHECK(a && a->has_a == 1, "alpha is a site (apex A)");
        CHECK(a && strcmp(a->a_ip, "216.24.57.1") == 0, "…the apex A is rendered dotted-quad");
        CHECK(a && a->has_tlsa == 1, "…and _443._tcp TLSA marks it visitable with a green lock");
        CHECK(a && a->nrec == 3, "…nrec counts every live record in the zone");
        CHECK(a && a->registered == 1 && a->lease_expiry == 1900000000,
              "…the chain join fills registered + lease_expiry");
        CHECK(a && strcmp(a->site, "the alpha site") == 0,
              "…the _site TXT blurb is un-length-prefixed for the Discover card");

        const DirRow *b = find_row(rows, n, "bravo");
        CHECK(b && b->has_a == 1 && b->has_tlsa == 0, "bravo is a site without TLSA");
        CHECK(b && strcmp(b->a_ip, "10.0.0.7") == 0, "…with its own apex A");
        CHECK(b && b->site[0] == 0, "…and no blurb");

        const DirRow *c = find_row(rows, n, "charlie");
        CHECK(c && c->has_a == 0, "a NON-apex A does not make a site");
        CHECK(c && c->a_ip[0] == 0, "…and leaves a_ip empty");
        CHECK(c && c->registered == 0 && c->lease_expiry == 0,
              "a name the projection never heard of reads registered=0, lease 0");

        const DirRow *d = find_row(rows, n, "delta");
        CHECK(d && d->has_a == 0 && d->nrec == 1, "a TXT-only zone is listed but is not a site");

        printf("-- the sort: sites-with-TLSA, then sites, then the rest --\n");
        CHECK(n == 4 && strcmp(rows[0].name, "alpha") == 0, "the TLSA site sorts first");
        CHECK(n >= 2 && strcmp(rows[1].name, "bravo") == 0, "the plain site sorts second");
        CHECK(n == 4 && strcmp(rows[2].name, "charlie") == 0 && strcmp(rows[3].name, "delta") == 0,
              "the non-sites sort last, alphabetically");
        /* add a second TLSA site that sorts before alpha alphabetically */
        CHECK(put(st, "aardvark", "@", "A", 300, "10.0.0.9") == 1, "aardvark apex A publishes");
        CHECK(put(st, "aardvark", "_443._tcp", "TLSA", 300,
                  "3 1 1 1111111111111111111111111111111111111111111111111111111111111111") == 1,
              "aardvark TLSA publishes");
        rebuild(st, ch);
        n = dirscan_snapshot(rows, DIR_MAX, NULL, NULL);
        CHECK(n == 5 && strcmp(rows[0].name, "aardvark") == 0 && strcmp(rows[1].name, "alpha") == 0,
              "inside the TLSA tier the sort is alphabetical");

        sp_state_close(st);
        sqlite3_close(ch);
    }

    printf("-- the _site blurb: prefixes, truncation, non-ASCII --\n");
    {
        SpState *st = sp_state_open(storep);
        sqlite3 *ch = open_chain(chainp);

        /* a DNS character-string carries its own length prefix; the scanner
         * strips it only when it matches the rdata length exactly */
        uint8_t pfx[8] = { 5, 'h','e','l','l','o' };
        CHECK(put_raw(st, "echo", "_site", DNS_TXT, pfx, 6) == 1, "a length-prefixed TXT publishes");
        /* a blurb longer than DirRow.site: must truncate, never overrun */
        uint8_t big[300];
        big[0] = 255;
        for (int i = 1; i < 256; i++) big[i] = (uint8_t)('a' + (i % 26));
        CHECK(put_raw(st, "foxtrot", "_site", DNS_TXT, big, 256) == 1, "a 256-byte TXT publishes");
        /* UTF-8 */
        const char *utf = "caf\xC3\xA9 \xE2\x98\x95 \xF0\x9F\x90\xB6";
        uint8_t u[64];
        u[0] = (uint8_t)strlen(utf);
        memcpy(u + 1, utf, strlen(utf));
        CHECK(put_raw(st, "golf", "_site", DNS_TXT, u, (int)strlen(utf) + 1) == 1,
              "a UTF-8 TXT publishes");

        rebuild(st, ch);
        n = dirscan_snapshot(rows, DIR_MAX, NULL, NULL);
        const DirRow *e = find_row(rows, n, "echo");
        CHECK(e && strcmp(e->site, "hello") == 0, "the character-string length prefix is stripped");
        const DirRow *f = find_row(rows, n, "foxtrot");
        CHECK(f && strlen(f->site) == sizeof f->site - 1,
              "an oversize blurb is truncated to sizeof(site)-1");
        CHECK(f && f->site[sizeof f->site - 1] == 0, "…and stays NUL-terminated");
        const DirRow *gg = find_row(rows, n, "golf");
        CHECK(gg && strcmp(gg->site, utf) == 0, "a UTF-8 blurb survives byte-exactly");

        sp_state_close(st);
        sqlite3_close(ch);
    }

    printf("-- awkward names --\n");
    {
        SpState *st = sp_state_open(storep);
        sqlite3 *ch = open_chain(chainp);
        char n32[33]; memset(n32, 'z', 32); n32[32] = 0;      /* the §3.1 maximum */
        CHECK(put(st, n32, "@", "A", 300, "10.1.1.1") == 1, "a 32-byte apex publishes");
        /* a deep label chain under the apex */
        CHECK(put(st, "hotel", "a.very.deep.label.chain.under.the.apex", "A", 300, "10.1.1.2") == 1,
              "a deep sublabel chain publishes");
        rebuild(st, ch);
        n = dirscan_snapshot(rows, DIR_MAX, NULL, NULL);
        const DirRow *z = find_row(rows, n, n32);
        CHECK(z != NULL, "the 32-byte apex has a row");
        CHECK(z && strlen(z->name) == 32 && z->has_a == 1, "…its name fits DirRow.name[40] intact");
        const DirRow *h = find_row(rows, n, "hotel");
        CHECK(h && h->has_a == 0 && h->nrec == 1, "the deep-label zone is listed but is not a site");
        sp_state_close(st);
        sqlite3_close(ch);
    }

    printf("-- many zones: DIR_MAX and the caller's max --\n");
    {
        /* a fresh store so the count is exactly what this block publishes */
        char bigp[512];
        snprintf(bigp, sizeof bigp, "%s/big.db", dir);
        SpState *st = sp_state_open(bigp);
        sqlite3 *ch = open_chain(chainp);
        int made = 0;
        for (int i = 0; i < DIR_MAX + 20; i++) {
            char nm[24];
            snprintf(nm, sizeof nm, "site%04d", i);
            char ip[24];
            snprintf(ip, sizeof ip, "10.%d.%d.%d", (i >> 16) & 255, (i >> 8) & 255, i & 255);
            if (put(st, nm, "@", "A", 300, ip) == 1) made++;
        }
        CHECK(made == DIR_MAX + 20, "532 zones published into the store");

        rebuild(st, ch);
        n = dirscan_snapshot(rows, DIR_MAX, NULL, NULL);
        CHECK(n == DIR_MAX, "the published snapshot is capped at DIR_MAX rows");

        /* the caller's max is honoured — canary past the requested rows */
        struct { DirRow r[8]; unsigned char canary[64]; } box;
        memset(&box, 0x5A, sizeof box);
        int got = dirscan_snapshot(box.r, 8, NULL, NULL);
        CHECK(got == 8, "dirscan_snapshot returns at most the caller's max");
        int intact = 1;
        for (unsigned i = 0; i < sizeof box.canary; i++) if (box.canary[i] != 0x5A) intact = 0;
        CHECK(intact, "…and writes nothing past it");
        int named = 1;
        for (int i = 0; i < got; i++) if (box.r[i].name[0] == 0) named = 0;
        CHECK(named, "…the rows it did copy are real");
        got = dirscan_snapshot(box.r, 0, NULL, NULL);
        CHECK(got == 0, "a max of 0 copies nothing");

        sp_state_close(st);
        sqlite3_close(ch);
        unlink(bigp);
    }

    printf("-- paths that cannot work --\n");
    {
        /* the published snapshot is process-global: a failed scan must leave
         * the last good one exactly as it was, not half-overwrite it */
        int64_t base_built = 0;
        int base_n = dirscan_snapshot(rows, DIR_MAX, &base_built, NULL);

        char missing[512];
        snprintf(missing, sizeof missing, "%s/nope/deeper/store.db", dir);
        CHECK(dirscan_start(missing, "/nonexistent/chain.db") == 1,
              "dirscan_start on a path that does not exist still returns 1");
        for (int i = 0; i < 50 && g.started; i++) {
            struct timespec ts = { 0, 20 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
        int64_t b2 = 0;
        CHECK(dirscan_snapshot(rows, DIR_MAX, &b2, NULL) == base_n && b2 == base_built,
              "…and publishes nothing (the scan thread bails, the old snapshot stands)");
        dirscan_stop();

        /* a path near PATH_MAX: store_path is char[512], so this must truncate
         * rather than run off the end (ASan catches the difference) */
        char huge[PATH_MAX + 64];
        memset(huge, 'x', sizeof huge - 1);
        huge[0] = '/';
        huge[sizeof huge - 1] = 0;
        CHECK(dirscan_start(huge, huge) == 1, "a PATH_MAX-sized path is accepted");
        CHECK(strlen(g.store_path) == sizeof g.store_path - 1,
              "…and truncated to fill store_path[512] exactly, no further");
        CHECK(strlen(g.chain_db) == sizeof g.chain_db - 1, "…same for chain_db[512]");
        for (int i = 0; i < 50 && g.started; i++) {
            struct timespec ts = { 0, 20 * 1000 * 1000 };
            nanosleep(&ts, NULL);
        }
        dirscan_stop();
        int64_t b3 = 0;
        CHECK(dirscan_snapshot(rows, DIR_MAX, &b3, NULL) == base_n && b3 == base_built,
              "nothing was published from the truncated path either");
    }

    printf("-- the thread lifecycle --\n");
    {
        CHECK(dirscan_start(storep, chainp) == 1, "the scan thread starts on the real fixture");
        CHECK(dirscan_start(storep, chainp) == 1, "a second start is idempotent");
        int64_t built = 0; int ms = -1;
        n = 0;
        for (int i = 0; i < 200; i++) {                 /* the first build is kicked up front */
            struct timespec ts = { 0, 20 * 1000 * 1000 };
            nanosleep(&ts, NULL);
            n = dirscan_snapshot(rows, DIR_MAX, &built, &ms);
            if (n > 0) break;
        }
        CHECK(n > 0, "the thread published a snapshot without being asked twice");
        CHECK(built > 0, "…stamped with a wall-clock build time");
        CHECK(ms >= 0, "…and a build duration");
        const DirRow *a = find_row(rows, n, "alpha");
        CHECK(a && a->has_a && a->has_tlsa, "the threaded build agrees with the direct rebuild");

        dirscan_kick();
        struct timespec ts = { 0, 300 * 1000 * 1000 };
        nanosleep(&ts, NULL);
        int64_t built2 = 0;
        int n2 = dirscan_snapshot(rows, DIR_MAX, &built2, NULL);
        CHECK(n2 == n, "a kick rebuilds to the same row count");
        CHECK(built2 >= built, "…and refreshes the build stamp");

        dirscan_stop();
        dirscan_stop();
        CHECK(1, "dirscan_stop is safe to call twice");
    }

    /* random-order stability: the sort must be a total order, not a coin flip */
    printf("-- the sort is a total order --\n");
    {
        DirRow probe[64];
        memset(probe, 0, sizeof probe);
        for (int i = 0; i < 64; i++) {
            snprintf(probe[i].name, sizeof probe[i].name, "n%03d", (int)(sm64() % 1000));
            probe[i].has_a    = (int)(sm64() & 1);
            probe[i].has_tlsa = (int)(sm64() & 1);
        }
        qsort(probe, 64, sizeof probe[0], cmp_rows);
        int ordered = 1;
        for (int i = 1; i < 64; i++) if (cmp_rows(&probe[i - 1], &probe[i]) > 0) ordered = 0;
        CHECK(ordered, "cmp_rows leaves 64 shuffled rows non-decreasing");
        int tiers = 1, last = 3;
        for (int i = 0; i < 64; i++) {
            int t = (probe[i].has_a && probe[i].has_tlsa) ? 2 : probe[i].has_a ? 1 : 0;
            if (t > last) tiers = 0;
            last = t;
        }
        CHECK(tiers, "…with the site tiers strictly descending");
    }

    unlink(storep); unlink(chainp);
    { char p[600]; snprintf(p, sizeof p, "%s/dns.db-wal", dir); unlink(p);
      snprintf(p, sizeof p, "%s/dns.db-shm", dir); unlink(p);
      snprintf(p, sizeof p, "%s/big.db-wal", dir); unlink(p);
      snprintf(p, sizeof p, "%s/big.db-shm", dir); unlink(p); }
    rmdir(dir);

    printf("%s\n", g_fail ? "t_dirscan: FAIL" : "t_dirscan: all ok");
    return g_fail;
}
