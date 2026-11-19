/* resolve_test.c — the first tests for resolve.c (the live resolver).
 *
 * resolve.c is the gate between an SNI arriving from a browser and the proxy
 * dialling an origin: it decides whether a name resolves at all, and hands the
 * proxy the TLSA that DANE will then enforce. A false "yes" here is not
 * immediately fatal (dane.c still has to match the pin), but a resolver that
 * mixes up names, ignores the ownership lease, or hands back a pin belonging to
 * a different name would turn the pin check into theatre.
 *
 * Hermetic end to end: this test builds a throwaway indexer sqlite db (the
 * `names`/`blocks`/`meta` tables dns_chain.c queries) and a throwaway record
 * store, publishes owner-signed A/TLSA records into it with a key it generates,
 * then drives resolver_resolve. No real chain, no network, no daemon; every
 * file lands in one mkdtemp'd dir that is removed at the end.
 *
 * PROVEN here:
 *   - resolver_open guards every argument and never half-opens;
 *   - resolver_resolve guards NULL sni/out/ud;
 *   - the apex and a subdomain both resolve, with the A record's address, port
 *     443, and the EXACT TLSA bytes that were published (not another name's);
 *   - FAIL-CLOSED: an owned name with an A but NO TLSA does not resolve — the
 *     proxy is never handed an origin it cannot authenticate;
 *   - the OWNERSHIP LEASE gate: once lease_expiry lapses, a name with perfectly
 *     good records stops resolving;
 *   - names that do not exist, empty zones, wrong TLD, malformed and oversize
 *     names all return 0;
 *   - case-insensitivity of the SNI (DNS names are case-insensitive);
 *   - the PEPENET_ORIGIN_PORT test override, including that junk values are
 *     ignored rather than applied.
 */
#include "resolve.h"
#include "origin.h"

#include "dns_state.h"
#include "dns_chain.h"
#include "zone.h"
#include "pepenet/crypto.h"

#include <sqlite3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

static int g_fail;
#define CHECK(cond, name) do { \
    if (cond) printf("ok   %s\n", name); \
    else      { printf("FAIL %s\n", name); g_fail = 1; } \
} while (0)

static char g_dir[256], g_store[512], g_idx[512];

/* The pins we publish, so the test can assert the resolver returns THESE bytes. */
static uint8_t PIN_APEX[32], PIN_WWW[32];

/* ── the fake indexer db ──────────────────────────────────────────────────── */

static int sql(sqlite3 *db, const char *s) {
    char *e = NULL;
    if (sqlite3_exec(db, s, NULL, NULL, &e) != SQLITE_OK) {
        fprintf(stderr, "sql: %s (%s)\n", e ? e : "?", s);
        sqlite3_free(e);
        return 0;
    }
    return 1;
}

/* Lay the three tables dns_chain.c reads, put `owner` on the two names, and
 * fill 101 block headers so an anchor at tip-6 verifies. */
static int build_indexer(const uint8_t owner[20], int64_t lease_expiry) {
    sqlite3 *db = NULL;
    if (sqlite3_open(g_idx, &db) != SQLITE_OK) return 0;
    int ok = sql(db, "CREATE TABLE IF NOT EXISTS names(name TEXT PRIMARY KEY, owner BLOB, lease_expiry INTEGER);")
          && sql(db, "CREATE TABLE IF NOT EXISTS blocks(height INTEGER PRIMARY KEY, hash BLOB);")
          && sql(db, "CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);")
          && sql(db, "DELETE FROM names;")
          && sql(db, "INSERT OR REPLACE INTO meta(k,v) VALUES('height','100');");
    if (ok) {                                   /* deterministic block hashes */
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO blocks(height,hash) VALUES(?1,?2)", -1, &st, NULL);
        for (int h = 0; h <= 100 && st; h++) {
            uint8_t hash[32];
            memset(hash, 0, 32);
            hash[0] = (uint8_t)h; hash[31] = 0xAB;
            sqlite3_reset(st);
            sqlite3_bind_int64(st, 1, h);
            sqlite3_bind_blob(st, 2, hash, 32, SQLITE_STATIC);
            if (sqlite3_step(st) != SQLITE_DONE) ok = 0;
        }
        if (st) sqlite3_finalize(st);
    }
    if (ok) {                                   /* `pepenet` is owned; `empty` too */
        const char *names[] = { "pepenet", "empty" };
        sqlite3_stmt *st = NULL;
        sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO names(name,owner,lease_expiry) VALUES(?1,?2,?3)", -1, &st, NULL);
        for (size_t i = 0; i < sizeof names / sizeof names[0] && st; i++) {
            sqlite3_reset(st);
            sqlite3_bind_text(st, 1, names[i], -1, SQLITE_STATIC);
            sqlite3_bind_blob(st, 2, owner, 20, SQLITE_STATIC);
            sqlite3_bind_int64(st, 3, lease_expiry);
            if (sqlite3_step(st) != SQLITE_DONE) ok = 0;
        }
        if (st) sqlite3_finalize(st);
    }
    sqlite3_close(db);
    return ok;
}

/* Rewrite just the lease, to prove the gate. */
static int set_lease(const char *name, int64_t expiry) {
    sqlite3 *db = NULL;
    if (sqlite3_open(g_idx, &db) != SQLITE_OK) return 0;
    char buf[256];
    snprintf(buf, sizeof buf, "UPDATE names SET lease_expiry=%lld WHERE name='%s';",
             (long long)expiry, name);
    int ok = sql(db, buf);
    sqlite3_close(db);
    return ok;
}

/* ── publishing owner-signed records into the store ───────────────────────── */

static int publish(SpState *st, const SpChainOracle *orc,
                   const uint8_t priv[32], const uint8_t pub[33],
                   const char *apex, const char *label,
                   const char *type, const char *rdata) {
    zone_rec r;
    if (zone_build_rec(label, type, 300, rdata, &r) != 0) {
        fprintf(stderr, "build_rec %s %s failed\n", label, type);
        return 0;
    }
    char err[160] = "";
    int rc = dns_state_put(st, orc, apex, &r, priv, pub, SP_CERT_NONE, NULL, 0,
                           err, sizeof err);
    if (rc != 1) fprintf(stderr, "put %s/%s rc=%d (%s)\n", label, type, rc, err);
    return rc == 1;
}

static void hexstr(const uint8_t *p, int n, char *out) {
    for (int i = 0; i < n; i++) sprintf(out + i * 2, "%02x", p[i]);
}

int main(void) {
    setbuf(stdout, NULL);

    char tmpl[] = "/tmp/pepenet-resolvetest.XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) { perror("mkdtemp"); return 1; }
    snprintf(g_dir, sizeof g_dir, "%s", dir);
    snprintf(g_store, sizeof g_store, "%s/store.db", g_dir);
    snprintf(g_idx,   sizeof g_idx,   "%s/indexer.db", g_dir);

    /* an owner key, and the hash160 the indexer will record for it */
    uint8_t priv[32], pub[33], owner[20];
    for (int i = 0; i < 32; i++) priv[i] = (uint8_t)(i + 1);
    if (!sp_pubkey(priv, pub)) { fprintf(stderr, "pubkey\n"); return 1; }
    sp_hash160(pub, 33, owner);

    if (!build_indexer(owner, (int64_t)time(NULL) + 3600)) { fprintf(stderr, "indexer\n"); return 1; }

    /* two distinct pins, so a resolver that returns the WRONG name's pin is caught */
    for (int i = 0; i < 32; i++) { PIN_APEX[i] = (uint8_t)(0x10 + i); PIN_WWW[i] = (uint8_t)(0xA0 + i); }
    char apex_hex[80], www_hex[80];
    hexstr(PIN_APEX, 32, apex_hex);
    hexstr(PIN_WWW, 32, www_hex);

    /* publish into the store with our own handles, then close them */
    {
        DnsChain *ch = dns_chain_open(g_idx);
        SpState  *st = sp_state_open(g_store);
        if (!ch || !st) { fprintf(stderr, "open store/chain\n"); return 1; }
        SpChainOracle orc = dns_chain_oracle(ch);

        char tlsa[200];
        int ok = 1;
        ok &= publish(st, &orc, priv, pub, "pepenet", "@", "A", "192.0.2.9");
        snprintf(tlsa, sizeof tlsa, "3 1 1 %s", apex_hex);
        ok &= publish(st, &orc, priv, pub, "pepenet", "_443._tcp", "TLSA", tlsa);

        ok &= publish(st, &orc, priv, pub, "pepenet", "www", "A", "192.0.2.10");
        snprintf(tlsa, sizeof tlsa, "3 1 1 %s", www_hex);
        ok &= publish(st, &orc, priv, pub, "pepenet", "_443._tcp.www", "TLSA", tlsa);

        /* `naked` has an A but deliberately NO TLSA — the fail-closed case */
        ok &= publish(st, &orc, priv, pub, "pepenet", "naked", "A", "192.0.2.11");
        /* `pinonly` has a TLSA but no A */
        snprintf(tlsa, sizeof tlsa, "3 1 1 %s", apex_hex);
        ok &= publish(st, &orc, priv, pub, "pepenet", "_443._tcp.pinonly", "TLSA", tlsa);

        sp_state_close(st);
        dns_chain_close(ch);
        if (!ok) { fprintf(stderr, "publish failed\n"); return 1; }
    }

    /* ── open guards ─────────────────────────────────────────────────────── */
    printf("-- resolver_open argument guards --\n");
    {
        CHECK(resolver_open(NULL, g_store, g_idx) == NULL, "NULL suffix -> NULL");
        CHECK(resolver_open("", g_store, g_idx) == NULL, "empty suffix -> NULL");
        CHECK(resolver_open("pepe", NULL, g_idx) == NULL, "NULL store path -> NULL");
        CHECK(resolver_open("pepe", g_store, NULL) == NULL, "NULL indexer path -> NULL");
        resolver_close(NULL);
        CHECK(1, "resolver_close(NULL) does not crash");
    }

    Resolver *r = resolver_open("pepe", g_store, g_idx);
    CHECK(r != NULL, "resolver_open succeeds on the fixture");
    if (!r) return 1;

    /* ── resolve guards ──────────────────────────────────────────────────── */
    printf("-- resolver_resolve argument guards --\n");
    {
        OriginInfo oi;
        CHECK(resolver_resolve(NULL, &oi, r) == 0, "NULL sni -> 0");
        CHECK(resolver_resolve("pepenet.pepe", NULL, r) == 0, "NULL out -> 0");
        CHECK(resolver_resolve("pepenet.pepe", &oi, NULL) == 0, "NULL resolver -> 0");
    }

    /* ── the happy paths ─────────────────────────────────────────────────── */
    printf("-- apex and subdomain resolve with their own pins --\n");
    {
        OriginInfo oi;
        memset(&oi, 0, sizeof oi);
        int got = resolver_resolve("pepenet.pepe", &oi, r);
        CHECK(got == 1, "apex 'pepenet.pepe' resolves");
        CHECK(got && !strcmp(oi.host, "192.0.2.9"), "apex host is its A record");
        CHECK(got && oi.port == 443, "apex port is 443");
        CHECK(got && oi.usage == 3 && oi.selector == 1 && oi.mtype == 1,
              "apex TLSA is 3 1 1");
        CHECK(got && oi.assoc_len == 32 && memcmp(oi.assoc, PIN_APEX, 32) == 0,
              "apex association is EXACTLY the published pin");

        memset(&oi, 0, sizeof oi);
        got = resolver_resolve("www.pepenet.pepe", &oi, r);
        CHECK(got == 1, "subdomain 'www.pepenet.pepe' resolves");
        CHECK(got && !strcmp(oi.host, "192.0.2.10"), "subdomain host is its own A record");
        CHECK(got && oi.assoc_len == 32 && memcmp(oi.assoc, PIN_WWW, 32) == 0,
              "subdomain gets ITS OWN pin, not the apex's");
    }

    /* ── fail-closed ─────────────────────────────────────────────────────── */
    printf("-- fail-closed: no pin, no service --\n");
    {
        OriginInfo oi;
        CHECK(resolver_resolve("naked.pepenet.pepe", &oi, r) == 0,
              "A record but NO TLSA -> 0 (never dial an unauthenticatable origin)");
        CHECK(resolver_resolve("pinonly.pepenet.pepe", &oi, r) == 0,
              "TLSA but no A record -> 0");
    }

    /* ── names that do not resolve ───────────────────────────────────────── */
    printf("-- non-resolving names --\n");
    {
        OriginInfo oi;
        struct { const char *sni; const char *what; } no[] = {
            { "nosuchname.pepe",        "unowned apex -> 0" },
            { "empty.pepe",             "owned name with an EMPTY zone -> 0" },
            { "www.nosuchname.pepe",    "subdomain of an unowned apex -> 0" },
            { "pepenet.doge",           "right name, WRONG tld -> 0" },
            { "pepenet.com",            "ICANN name -> 0" },
            { "pepe",                   "the bare suffix -> 0" },
            { ".pepe",                  "empty apex '.pepe' -> 0" },
            { "pepenet.",               "trailing dot only -> 0" },
            { "",                       "empty string -> 0" },
            { "..pepe",                 "double dot -> 0" },
            { "pepenet..pepe",          "empty label before the tld -> 0" },
            { "nope.pepenet.pepe",      "unknown subdomain of an owned apex -> 0" },
            { "192.0.2.9",              "a bare IP as SNI -> 0" },
            { "pepenet.pepe.evil.com",  "our name as a PREFIX of an ICANN name -> 0" },
        };
        for (size_t i = 0; i < sizeof no / sizeof no[0]; i++)
            CHECK(resolver_resolve(no[i].sni, &oi, r) == 0, no[i].what);
    }

    /* ── oversize / adversarial names ────────────────────────────────────── */
    printf("-- oversize and adversarial names --\n");
    {
        OriginInfo oi;
        char big[600];

        memset(big, 'a', 300); big[300] = 0;
        CHECK(resolver_resolve(big, &oi, r) == 0, "300-byte name with no tld -> 0");

        memset(big, 'a', 300); strcpy(big + 300, ".pepe");
        CHECK(resolver_resolve(big, &oi, r) == 0, "300-byte apex under .pepe -> 0 (apex cap is 64)");

        memset(big, 'a', 500); strcpy(big + 500, ".pepenet.pepe");
        CHECK(resolver_resolve(big, &oi, r) == 0, "500-byte subdomain -> 0 (sub cap is 128)");

        /* deep label nesting under a real apex */
        strcpy(big, "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.pepenet.pepe");
        CHECK(resolver_resolve(big, &oi, r) == 0, "deeply nested unknown subdomain -> 0");

        /* control characters embedded in the name */
        CHECK(resolver_resolve("pep\renet.pepe", &oi, r) == 0, "CR in the name -> 0");
        CHECK(resolver_resolve("pep\nenet.pepe", &oi, r) == 0, "LF in the name -> 0");
        CHECK(resolver_resolve("pepenet.pepe\r\n", &oi, r) == 0, "trailing CRLF -> 0");
        CHECK(resolver_resolve("pepenet\t.pepe", &oi, r) == 0, "tab in the name -> 0");
        CHECK(resolver_resolve("../../etc/passwd.pepe", &oi, r) == 0, "path traversal shape -> 0");
        CHECK(resolver_resolve("pepenet.pepe'; DROP TABLE names;--", &oi, r) == 0,
              "SQL injection shape -> 0");
        /* the apex is bound as a parameter, so this must be a plain miss, and
         * the table must still be there afterwards */
        CHECK(resolver_resolve("pepenet.pepe", &oi, r) == 1,
              "the store still answers after the injection attempt");
    }

    /* ── case-insensitivity ──────────────────────────────────────────────── */
    printf("-- SNI case-insensitivity (DNS names are case-insensitive) --\n");
    {
        OriginInfo oi;
        /* FAILS: the APEX reaches the ownership oracle with its original case.
         * origin.c:17 matches the suffix with strcasecmp and origin.c:49
         * matches every LABEL with strcasecmp, but origin.c:31 copies the apex
         * through verbatim, and resolve.c:63 then hands it to
         *   dns_chain.c:59  SELECT owner, lease_expiry FROM names WHERE name=?1
         * which is an exact, case-SENSITIVE SQL comparison against the
         * lowercase name the indexer stored. "PEPENET" misses, owner_now
         * returns 0, and resolve.c:65 gives up — an existing site serves the
         * fail-closed 404.
         *
         * That this is a bug and not a convention is settled by the rest of the
         * family: dns_wire.c:47 lowercases every name as it comes OFF THE WIRE
         * ("dotted, lowercased"), and dns_state.c:23 lowercases label bytes
         * with the comment "DNS labels: case-blind". dnsd therefore never hands
         * owner_now anything but lowercase. resolve.c is the one path that
         * takes a name from the TLS SNI instead of the DNS wire decoder, so it
         * is the one path that never gets that lowercasing.
         *
         * Fail-closed, so not a security hole — an availability bug. Fix is one
         * line: lowercase `apex` before owner_now, mirroring dns_wire.c:47. */
        memset(&oi, 0, sizeof oi);
        int up = resolver_resolve("PEPENET.PEPE", &oi, r);
        CHECK(up == 1 && !strcmp(oi.host, "192.0.2.9"),
              "all-uppercase 'PEPENET.PEPE' resolves like the lowercase form");
        memset(&oi, 0, sizeof oi);
        CHECK(resolver_resolve("PePeNeT.pEpE", &oi, r) == 1, "mixed-case apex resolves");
        memset(&oi, 0, sizeof oi);
        CHECK(resolver_resolve("WWW.pepenet.pepe", &oi, r) == 1, "uppercase subdomain resolves");
        memset(&oi, 0, sizeof oi);
        CHECK(resolver_resolve("pepenet.PEPE", &oi, r) == 1, "uppercase TLD alone resolves");
    }

    /* ── the origin-port override ────────────────────────────────────────── */
    printf("-- PEPENET_ORIGIN_PORT override --\n");
    {
        OriginInfo oi;
        setenv("PEPENET_ORIGIN_PORT", "5001", 1);
        memset(&oi, 0, sizeof oi);
        CHECK(resolver_resolve("pepenet.pepe", &oi, r) == 1 && oi.port == 5001,
              "a valid override is applied");
        setenv("PEPENET_ORIGIN_PORT", "0", 1);
        memset(&oi, 0, sizeof oi);
        CHECK(resolver_resolve("pepenet.pepe", &oi, r) == 1 && oi.port == 443,
              "override of 0 is ignored (stays 443)");
        setenv("PEPENET_ORIGIN_PORT", "70000", 1);
        memset(&oi, 0, sizeof oi);
        CHECK(resolver_resolve("pepenet.pepe", &oi, r) == 1 && oi.port == 443,
              "out-of-range override is ignored");
        setenv("PEPENET_ORIGIN_PORT", "notanumber", 1);
        memset(&oi, 0, sizeof oi);
        CHECK(resolver_resolve("pepenet.pepe", &oi, r) == 1 && oi.port == 443,
              "non-numeric override is ignored");
        setenv("PEPENET_ORIGIN_PORT", "", 1);
        memset(&oi, 0, sizeof oi);
        CHECK(resolver_resolve("pepenet.pepe", &oi, r) == 1 && oi.port == 443,
              "empty override is ignored");
        unsetenv("PEPENET_ORIGIN_PORT");
    }

    /* ── the ownership lease gate ────────────────────────────────────────── */
    printf("-- the ownership lease gate --\n");
    {
        OriginInfo oi;
        CHECK(resolver_resolve("pepenet.pepe", &oi, r) == 1, "resolves while the lease is live");
        /* Lapse the lease. The records are untouched and still owner-signed;
         * only the chain's answer changes. resolve.c must stop serving. */
        CHECK(set_lease("pepenet", (int64_t)time(NULL) - 1), "lease moved into the past");
        CHECK(resolver_resolve("pepenet.pepe", &oi, r) == 0,
              "a LAPSED lease stops the name resolving (records alone are not enough)");
        CHECK(resolver_resolve("www.pepenet.pepe", &oi, r) == 0,
              "subdomains of a lapsed name stop resolving too");
        CHECK(set_lease("pepenet", (int64_t)time(NULL) + 3600), "lease restored");
        CHECK(resolver_resolve("pepenet.pepe", &oi, r) == 1, "renewing the lease restores service");
    }

    resolver_close(r);

    /* clean up the fixture dir */
    unlink(g_store);
    unlink(g_idx);
    {
        char pat[600];
        snprintf(pat, sizeof pat, "%s/store.db-wal", g_dir); unlink(pat);
        snprintf(pat, sizeof pat, "%s/store.db-shm", g_dir); unlink(pat);
        snprintf(pat, sizeof pat, "%s/indexer.db-wal", g_dir); unlink(pat);
        snprintf(pat, sizeof pat, "%s/indexer.db-shm", g_dir); unlink(pat);
    }
    rmdir(g_dir);

    printf(g_fail ? "\nresolve_test: FAIL\n" : "\nresolve_test: all ok\n");
    return g_fail;
}
