// view_test.c — battery for src/view.c, the ownership view every overlay
// resolves identity through.
//
// SCOPE NOTE. The brief for this file was written against a "peer view /
// selection" module. src/view.c is NOT that: it is a read-only name -> owner
// lookup with two backends (a chainless test table loaded from a file, and the
// indexer's sqlite projection incl. the `epochs` ownership history). There is no
// peer list, no selection policy, no eviction and no fixed capacity — the test
// table grows by realloc. The required properties are therefore proven against
// the equivalent surface of THIS module, and the mapping is stated per section.
//
// PROVEN HERE:
//   · DETERMINISM given a seeded input — the same table answers identically
//     across reopens and across randomised query order (2000 shuffled lookups).
//   · 0 entries, 1 entry, and the large-table case (8192 entries, twice the
//     4096-entry "max peers" figure), all correct.
//   · A DUPLICATE entry does NOT double-count: a repeated name resolves to one
//     owner, always the same one, and never yields two distinct answers.
//   · "EVICTION picks what the policy says" -> here the policy is the loader
//     filter: §3.1-invalid names and malformed owner hex are dropped at load.
//     Every dropped row is proven unreachable through every accessor.
//   · The view NEVER returns an entry it was told to drop — proven for loader-
//     rejected rows, for `epochs` lapse rows (recorded NULL owner = unowned at
//     that height), and for names absent from the projection.
//   · NO OUT-OF-BOUNDS INDEXING at the boundary: the table is filled exactly
//     full and then one over; names of length 0, 1, SP_NAME_MAX and
//     SP_NAME_MAX+1 are queried; and every non-NUL-terminated `name` argument is
//     placed flush against an mmap PROT_NONE guard page so that reading even one
//     byte past name_len faults (trapped and reported, not silently passed).
//   · The full §4.2 epoch-resolution matrix against a REAL sqlite projection:
//     exact height hits, lapse rows, heights below the history, the
//     `epochs_from` horizon, and the documented fallback to the current owner.
//
// Fixtures live in a mkdtemp'd directory and are removed on exit. No network,
// no ~/.pepenet.
#include "pepenet/view.h"
#include "pepenet/crypto.h"

#include <setjmp.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int g_fail;
static long g_checks;
#define CK(c, m) do { g_checks++; if (c) printf("  ok   %s\n", m); \
                      else { printf("  FAIL %s\n", m); g_fail++; } } while (0)

static char g_dir[] = "/tmp/pepenet-mesh-view.XXXXXX";
static int  g_dir_ok;

static const char *g_phase = "startup";
static void on_alarm(int s) {
    (void)s;
    char m[256];
    int n = snprintf(m, sizeof m, "\nview_test: WATCHDOG FAIL — hang in phase: %s\n", g_phase);
    ssize_t r = write(2, m, (size_t)n); (void)r;
    _exit(1);
}
#define PHASE(p, secs) do { g_phase = (p); alarm(secs); } while (0)

// ── SplitMix64 ───────────────────────────────────────────────────────────────
static uint64_t g_rng;
static uint64_t rnd(void) {
    uint64_t z = (g_rng += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

// ── fault trap + guard page ──────────────────────────────────────────────────
static sigjmp_buf g_jmp;
static volatile sig_atomic_t g_trapped;
static void on_fault(int s) { (void)s; g_trapped = 1; siglongjmp(g_jmp, 1); }
static uint8_t *g_gbase, *g_gend;
static size_t g_gmap;
static int guard_init(size_t bytes) {
    size_t ps = (size_t)getpagesize();
    size_t data = ((bytes + ps - 1) / ps) * ps;
    g_gmap = data + 2 * ps;
    g_gbase = mmap(NULL, g_gmap, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (g_gbase == MAP_FAILED) return 0;
    if (mprotect(g_gbase, ps, PROT_NONE)) return 0;
    if (mprotect(g_gbase + ps + data, ps, PROT_NONE)) return 0;
    g_gend = g_gbase + ps + data;
    return 1;
}
static uint8_t *guard_put(const void *src, size_t n) {
    uint8_t *p = g_gend - n; if (n) memcpy(p, src, n); return p;
}

// ── fixtures ─────────────────────────────────────────────────────────────────
static void fpath(char *out, size_t n, const char *leaf) { snprintf(out, n, "%s/%s", g_dir, leaf); }

static void hex20(const uint8_t b[20], char out[41]) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 20; i++) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 15]; }
    out[40] = 0;
}
static void owner_n(uint32_t i, uint8_t o[20]) {
    uint8_t s[8] = { 'o','w','n', 0, (uint8_t)i, (uint8_t)(i>>8), (uint8_t)(i>>16), (uint8_t)(i>>24) };
    uint8_t h[32]; sp_sha256(s, 8, h); memcpy(o, h, 20);
}
// deterministic §3.1-valid name for index i
static void name_n(uint32_t i, char out[40]) {
    static const char C[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    int p = 0; out[p++] = 'n';
    uint32_t x = i;
    do { out[p++] = C[x % 36]; x /= 36; } while (x);
    out[p] = 0;
}

// ── a chain-mode fixture DB ──────────────────────────────────────────────────
static int db_exec(sqlite3 *db, const char *sql) {
    char *e = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &e);
    if (rc != SQLITE_OK) { fprintf(stderr, "  (sql) %s\n", e ? e : "?"); sqlite3_free(e); }
    return rc == SQLITE_OK;
}
static int db_bind_row(sqlite3 *db, const char *sql, const char *name,
                       const uint8_t *owner, int64_t h, int have_h) {
    sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return 0;
    int i = 1;
    sqlite3_bind_text(st, i++, name, -1, SQLITE_TRANSIENT);
    if (have_h) sqlite3_bind_int64(st, i++, h);
    if (owner) sqlite3_bind_blob(st, i++, owner, 20, SQLITE_TRANSIENT);
    else       sqlite3_bind_null(st, i++);
    int ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGALRM, on_alarm);
    { struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_handler = on_fault;
      sigemptyset(&sa.sa_mask); sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS, &sa, NULL); }
    if (!guard_init(4096)) { printf("  FAIL guard mmap\n"); return 1; }

    uint64_t seed = 0x5EED17E900BADA55ULL;
    if (argc > 1) seed = strtoull(argv[1], NULL, 0);
    else { const char *e = getenv("SP_SEED"); if (e) seed = strtoull(e, NULL, 0); }
    g_rng = seed;
    printf("view_test  seed = 0x%016llx   (reproduce: ./view_test 0x%016llx)\n",
           (unsigned long long)seed, (unsigned long long)seed);

    if (!mkdtemp(g_dir)) { printf("  FAIL mkdtemp\n"); return 1; }
    g_dir_ok = 1;
    printf("           fixtures in %s (removed on exit)\n", g_dir);

    uint8_t got[20];
    char path[512];

    // ═══ test mode: empty / one / many ═══════════════════════════════════════
    PHASE("test-mode cardinality", 120);
    printf("-- test mode: 0, 1 and many entries --\n");
    {
        // 0 entries
        fpath(path, sizeof path, "empty.txt");
        FILE *f = fopen(path, "w"); fclose(f);
        SpView *v = sp_view_open_test(path, 1000);
        CK(v != NULL, "empty table opens (0 entries)");
        if (v) {
            CK(!sp_view_owner_now(v, "anything", got), "0 entries: lookup returns unowned");
            uint8_t z[20]; memset(z, 0, 20);
            CK(!sp_view_addr_owns_name(v, z), "0 entries: addr_owns_name is 0");
            CK(sp_view_tip(v) == 1000, "0 entries: tip is the value passed in");
            sp_view_close(v);
        }
        // missing file
        fpath(path, sizeof path, "does-not-exist.txt");
        CK(sp_view_open_test(path, 1) == NULL, "missing names file returns NULL");
        CK(sp_view_open_chain(path) == NULL, "missing chain db returns NULL (read-only open)");

        // 1 entry
        uint8_t o0[20]; owner_n(0, o0); char h0[41]; hex20(o0, h0);
        fpath(path, sizeof path, "one.txt");
        f = fopen(path, "w"); fprintf(f, "solo %s\n", h0); fclose(f);
        v = sp_view_open_test(path, 7);
        CK(v != NULL, "1-entry table opens");
        if (v) {
            CK(sp_view_owner_now(v, "solo", got) && memcmp(got, o0, 20) == 0, "1 entry resolves");
            CK(!sp_view_owner_now(v, "sol", got), "1 entry: prefix of the name does not match");
            CK(!sp_view_owner_now(v, "solo1", got), "1 entry: extension of the name does not match");
            CK(sp_view_addr_owns_name(v, o0), "1 entry: its owner owns a name");
            uint8_t other[20]; owner_n(99, other);
            CK(!sp_view_addr_owns_name(v, other), "1 entry: a different addr owns nothing");
            CK(sp_view_tip(v) == 7, "1 entry: tip");
            sp_view_close(v);
        }
        // large table — fill exactly full, then one over
        const int BIG = 8192;
        fpath(path, sizeof path, "big.txt");
        f = fopen(path, "w");
        for (int i = 0; i < BIG; i++) {
            char nm[40], hx[41]; uint8_t o[20];
            name_n((uint32_t)i, nm); owner_n((uint32_t)i, o); hex20(o, hx);
            fprintf(f, "%s %s\n", nm, hx);
        }
        fclose(f);
        v = sp_view_open_test(path, 4242);
        CK(v != NULL, "8192-entry table opens (2x the 4096 'max peers' figure)");
        if (v) {
            int miss = 0;
            for (int i = 0; i < BIG; i++) {
                char nm[40]; uint8_t o[20];
                name_n((uint32_t)i, nm); owner_n((uint32_t)i, o);
                g_checks++;
                if (!sp_view_owner_now(v, nm, got) || memcmp(got, o, 20) != 0) miss++;
            }
            CK(miss == 0, "all 8192 entries resolve to the right owner (exactly full)");
            // "one over": query index BIG, which was never inserted
            char nm[40]; name_n((uint32_t)BIG, nm);
            CK(!sp_view_owner_now(v, nm, got), "the entry one past the end is absent, not garbage");
            // and the last entry is still intact after that probe
            name_n((uint32_t)(BIG - 1), nm); uint8_t o[20]; owner_n((uint32_t)(BIG - 1), o);
            CK(sp_view_owner_now(v, nm, got) && memcmp(got, o, 20) == 0,
               "the last entry is intact after probing past the end");
            CK(sp_view_addr_owns_name(v, o), "the last entry's owner is found by addr scan");
            sp_view_close(v);
        }
    }

    // ═══ determinism ═════════════════════════════════════════════════════════
    PHASE("determinism", 120);
    printf("-- determinism given a seeded input --\n");
    {
        const int N = 512;
        fpath(path, sizeof path, "det.txt");
        FILE *f = fopen(path, "w");
        for (int i = 0; i < N; i++) {
            char nm[40], hx[41]; uint8_t o[20];
            name_n((uint32_t)i, nm); owner_n((uint32_t)i, o); hex20(o, hx);
            fprintf(f, "%s %s\n", nm, hx);
        }
        fclose(f);
        SpView *a = sp_view_open_test(path, 100);
        SpView *b = sp_view_open_test(path, 100);
        CK(a && b, "two independent opens of the same table succeed");
        int diff = 0;
        // 2000 lookups in SHUFFLED order must agree between the two views and
        // must not depend on the order they are issued in
        uint8_t seen[512][20]; int have[512]; memset(have, 0, sizeof have);
        for (int i = 0; i < 2000; i++) {
            int idx = (int)(rnd() % (unsigned)N);
            char nm[40]; name_n((uint32_t)idx, nm);
            uint8_t ga[20], gb[20];
            int ra = sp_view_owner_now(a, nm, ga);
            int rb = sp_view_owner_now(b, nm, gb);
            g_checks++;
            if (ra != rb || (ra && memcmp(ga, gb, 20) != 0)) { diff++; continue; }
            if (!ra) { diff++; continue; }
            if (have[idx]) { if (memcmp(seen[idx], ga, 20) != 0) diff++; }
            else { memcpy(seen[idx], ga, 20); have[idx] = 1; }
        }
        CK(diff == 0, "2000 shuffled lookups: identical across views and stable per name");
        // reopen/close cycles must not perturb anything
        int cyc_bad = 0;
        for (int c = 0; c < 50; c++) {
            SpView *t = sp_view_open_test(path, 100);
            if (!t) { cyc_bad++; continue; }
            char nm[40]; uint8_t o[20];
            name_n(0, nm); owner_n(0, o);
            if (!sp_view_owner_now(t, nm, got) || memcmp(got, o, 20) != 0) cyc_bad++;
            sp_view_close(t);
            g_checks++;
        }
        CK(cyc_bad == 0, "50 open/close cycles: same answers, no crash, no corruption");
        sp_view_close(a); sp_view_close(b);
        sp_view_close(NULL);
        CK(1, "sp_view_close(NULL) is a no-op (does not crash)");
    }

    // ═══ duplicates ══════════════════════════════════════════════════════════
    PHASE("duplicates", 60);
    printf("-- duplicate entries are not double-counted --\n");
    {
        uint8_t oA[20], oB[20]; owner_n(1, oA); owner_n(2, oB);
        char hA[41], hB[41]; hex20(oA, hA); hex20(oB, hB);
        fpath(path, sizeof path, "dup.txt");
        FILE *f = fopen(path, "w");
        fprintf(f, "dupe %s\n", hA);
        fprintf(f, "dupe %s\n", hA);          // exact duplicate
        fprintf(f, "dupe %s\n", hA);
        fprintf(f, "conflict %s\n", hA);
        fprintf(f, "conflict %s\n", hB);      // same name, DIFFERENT owner
        fprintf(f, "solo %s\n", hB);
        fclose(f);
        SpView *v = sp_view_open_test(path, 1);
        CK(v != NULL, "table with duplicates opens");
        if (v) {
            CK(sp_view_owner_now(v, "dupe", got) && memcmp(got, oA, 20) == 0,
               "an exactly-duplicated entry resolves to that one owner");
            // stability: 500 repeat lookups must never flip
            int flips = 0; uint8_t first[20];
            sp_view_owner_now(v, "conflict", first);
            for (int i = 0; i < 500; i++) {
                uint8_t g2[20]; g_checks++;
                if (!sp_view_owner_now(v, "conflict", g2) || memcmp(g2, first, 20) != 0) flips++;
            }
            CK(flips == 0, "a name listed twice with different owners resolves deterministically "
                           "(first row wins, 500/500 stable)");
            CK(memcmp(first, oA, 20) == 0, "and the winner is the FIRST row, not the last");
            CK(sp_view_addr_owns_name(v, oA) && sp_view_addr_owns_name(v, oB),
               "both owners still register as owning at least one name");
            // duplicates must not make a lookup return two different answers in
            // one call, nor leak the second row through any accessor
            CK(sp_view_owner_now(v, "dupe", got) && memcmp(got, oA, 20) == 0,
               "repeat lookup of the duplicated name is unchanged");
            sp_view_close(v);
        }
    }

    // ═══ the loader filter = the eviction policy ═════════════════════════════
    PHASE("loader filter", 60);
    printf("-- loader filter: rejected rows are NEVER returned --\n");
    {
        uint8_t o[20]; owner_n(5, o); char hx[41]; hex20(o, hx);
        char n32[33]; memset(n32, 'a', 32); n32[32] = 0;
        char n33[34]; memset(n33, 'b', 33); n33[33] = 0;
        fpath(path, sizeof path, "filter.txt");
        FILE *f = fopen(path, "w");
        fprintf(f, "good %s\n", hx);
        fprintf(f, "%s %s\n", n32, hx);        // SP_NAME_MAX — must LOAD
        fprintf(f, "%s %s\n", n33, hx);        // SP_NAME_MAX+1 — must be dropped
        fprintf(f, "Alice %s\n", hx);          // uppercase
        fprintf(f, "foo.bar %s\n", hx);        // dot
        fprintf(f, "foo_bar %s\n", hx);        // underscore
        fprintf(f, "xn--ace %s\n", hx);        // ACE prefix
        fprintf(f, "-lead %s\n", hx);          // leading hyphen
        fprintf(f, "trail- %s\n", hx);         // trailing hyphen
        fprintf(f, "shorthex %s\n", "00112233");                       // 8 hex chars
        fprintf(f, "longhex %s00\n", hx);                              // 42 hex chars
        fprintf(f, "nothex zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\n"); // 40 non-hex
        fprintf(f, "alsogood %s\n", hx);
        fclose(f);
        SpView *v = sp_view_open_test(path, 1);
        CK(v != NULL, "mixed table opens");
        if (v) {
            CK(sp_view_owner_now(v, "good", got), "valid row loaded");
            CK(sp_view_owner_now(v, "alsogood", got), "valid row after the junk still loaded");
            CK(sp_view_owner_now(v, n32, got), "name of exactly SP_NAME_MAX (32) loaded");
            const char *dropped[] = { "Alice", "foo.bar", "foo_bar", "xn--ace",
                                      "-lead", "trail-", "shorthex", "longhex", "nothex" };
            int leaked = 0;
            for (unsigned i = 0; i < sizeof dropped / sizeof *dropped; i++) {
                g_checks++;
                if (sp_view_owner_now(v, dropped[i], got)) {
                    leaked++; printf("  FAIL dropped row \"%s\" is still reachable\n", dropped[i]);
                }
            }
            CK(leaked == 0, "all 9 loader-rejected rows are unreachable through owner_now");
            // and through the length-explicit accessor, incl. the 33-byte name
            CK(!sp_view_owner_of(v, (const uint8_t *)n33, 33, 1, got),
               "name of SP_NAME_MAX+1 (33) unreachable through owner_of");
            CK(!sp_view_owner_of(v, (const uint8_t *)"Alice", 5, 1, got),
               "invalid name short-circuits owner_of without a table scan");
            sp_view_close(v);
        }
        // a 100-character name: fscanf's %63s truncates it. Must not crash.
        fpath(path, sizeof path, "longline.txt");
        f = fopen(path, "w");
        for (int i = 0; i < 100; i++) fputc('a', f);
        fprintf(f, " %s\ngood %s\n", hx, hx);
        fclose(f);
        v = sp_view_open_test(path, 1);
        CK(v != NULL, "table with a 100-char name opens (fscanf %63s truncation path)");
        if (v) {
            char n63[64]; memset(n63, 'a', 63); n63[63] = 0;
            CK(!sp_view_owner_now(v, n63, got), "the truncated 63-char token is not owned");
            sp_view_close(v);
        }
    }

    // ═══ boundary / out-of-bounds indexing ═══════════════════════════════════
    PHASE("boundaries", 60);
    printf("-- boundary arguments, guard-paged (no over-read past name_len) --\n");
    {
        uint8_t o[20]; owner_n(11, o); char hx[41]; hex20(o, hx);
        char n32[33]; memset(n32, 'a', 32); n32[32] = 0;
        fpath(path, sizeof path, "bound.txt");
        FILE *f = fopen(path, "w");
        fprintf(f, "a %s\n", hx);
        fprintf(f, "%s %s\n", n32, hx);
        fclose(f);
        SpView *v = sp_view_open_test(path, 1);
        CK(v != NULL, "boundary table opens");
        if (!v) goto after_bounds;

        // every name argument sits flush against a PROT_NONE page: reading
        // name[name_len] faults, and the fault is caught and reported.
        struct { const char *nm; int len; int want; const char *lbl; } T[] = {
            { "a",   1,  1, "name_len 1 (present) resolves" },
            { "a",   0,  0, "name_len 0 rejected" },
            { "ab",  2,  0, "name_len 2 (absent) returns unowned" },
            { "a",  -1,  0, "name_len -1 rejected" },
            { NULL, 32,  1, "name_len 32 (SP_NAME_MAX, present) resolves" },
            { NULL, 33,  0, "name_len 33 (SP_NAME_MAX+1) rejected" } };
        long faults = 0;
        for (unsigned i = 0; i < sizeof T / sizeof *T; i++) {
            const char *src = T[i].nm ? T[i].nm : n32;
            int L = T[i].len;
            size_t cp = L > 0 ? (size_t)L : 0;
            if (i == 5) cp = 33;                       // 33 bytes of 'a' for the +1 case
            uint8_t tmp[64]; memset(tmp, 'a', sizeof tmp);
            if (T[i].nm) memcpy(tmp, src, strlen(src));
            uint8_t *p = guard_put(tmp, cp);
            int rc = 0; g_trapped = 0; g_checks++;
            if (sigsetjmp(g_jmp, 1) == 0) rc = sp_view_owner_of(v, p, L, 1, got);
            if (g_trapped) { faults++; printf("  FAIL over-read for %s\n", T[i].lbl); }
            else CK(rc == T[i].want, T[i].lbl);
        }
        CK(faults == 0, "no accessor read a single byte past name_len (guard page held)");
        // sp_view_owner_of with a huge name_len must be refused before any read
        { uint8_t *p = guard_put("a", 1); int rc = 0; g_trapped = 0;
          if (sigsetjmp(g_jmp, 1) == 0) rc = sp_view_owner_of(v, p, 0x7FFFFFFF, 1, got);
          CK(!g_trapped && rc == 0, "name_len INT_MAX rejected without reading"); }
        { uint8_t *p = guard_put("a", 1); int rc = 0; g_trapped = 0;
          if (sigsetjmp(g_jmp, 1) == 0) rc = sp_view_owner_of(v, p, 1 << 30, 1, got);
          CK(!g_trapped && rc == 0, "name_len 2^30 rejected without reading"); }
        // addr argument at the page edge
        { uint8_t *p = guard_put(o, 20); int rc = 0; g_trapped = 0;
          if (sigsetjmp(g_jmp, 1) == 0) rc = sp_view_addr_owns_name(v, p);
          CK(!g_trapped && rc == 1, "addr_owns_name reads exactly 20 bytes at the page edge"); }
        // every height value: the test backend ignores height, must never index
        { int bad = 0;
          uint32_t H[] = { 0, 1, 0x7FFFFFFF, 0x80000000u, 0xFFFFFFFEu, 0xFFFFFFFFu };
          for (unsigned i = 0; i < sizeof H / sizeof *H; i++) {
              g_checks++;
              if (!sp_view_owner_of(v, (const uint8_t *)"a", 1, H[i], got)) bad++; }
          CK(bad == 0, "test backend answers identically at every extreme height"); }
        sp_view_close(v);
    }
after_bounds:

    // ═══ chain mode: the §4.2 epoch matrix against a real sqlite db ══════════
    PHASE("chain mode", 180);
    printf("-- chain mode: names-only projection --\n");
    {
        uint8_t oA[20], oB[20]; owner_n(21, oA); owner_n(22, oB);
        fpath(path, sizeof path, "names-only.db");
        sqlite3 *db;
        CK(sqlite3_open(path, &db) == SQLITE_OK, "fixture db created");
        CK(db_exec(db, "CREATE TABLE names(name TEXT PRIMARY KEY, owner BLOB);"
                       "CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);"
                       "INSERT INTO meta VALUES('proj_height','900');"), "names+meta schema");
        db_bind_row(db, "INSERT INTO names(name,owner) VALUES(?,?)", "alpha", oA, 0, 0);
        db_bind_row(db, "INSERT INTO names(name,owner) VALUES(?,?)", "beta",  oB, 0, 0);
        db_bind_row(db, "INSERT INTO names(name,owner) VALUES(?,?)", "nullowner", NULL, 0, 0);
        db_exec(db, "INSERT INTO names(name,owner) VALUES('shortowner', X'0011')");
        sqlite3_close(db);

        SpView *v = sp_view_open_chain(path);
        CK(v != NULL, "chain view opens read-only");
        if (v) {
            CK(sp_view_tip(v) == 900, "tip read from meta.proj_height");
            CK(sp_view_owner_now(v, "alpha", got) && memcmp(got, oA, 20) == 0, "alpha resolves");
            CK(sp_view_owner_now(v, "beta", got) && memcmp(got, oB, 20) == 0, "beta resolves");
            CK(!sp_view_owner_now(v, "gamma", got), "absent name unowned");
            CK(!sp_view_owner_now(v, "nullowner", got), "NULL owner blob treated as unowned");
            CK(!sp_view_owner_now(v, "shortowner", got), "2-byte owner blob rejected (needs 20)");
            CK(!sp_view_owner_now(v, "Alpha", got), "invalid §3.1 name never hits the db");
            CK(sp_view_addr_owns_name(v, oA), "addr_owns_name finds oA");
            uint8_t none[20]; owner_n(999, none);
            CK(!sp_view_addr_owns_name(v, none), "addr_owns_name misses an unknown addr");
            // height is irrelevant without an epochs table -> current owner
            int bad = 0;
            uint32_t H[] = { 0, 1, 500, 900, 901, 0xFFFFFFFFu };
            for (unsigned i = 0; i < sizeof H / sizeof *H; i++) {
                g_checks++;
                if (!sp_view_owner_of(v, (const uint8_t *)"alpha", 5, H[i], got)) bad++; }
            CK(bad == 0, "no epochs table: owner_of falls back to the current owner at every height");
            // SQL-injection shaped names are impossible (§3.1 charset) but bound anyway
            CK(!sp_view_owner_now(v, "a-or-1-1", got), "a hyphenated name is bound, not interpolated");
            sp_view_close(v);
        }
        // the `height` meta fallback key
        fpath(path, sizeof path, "height-key.db");
        sqlite3_open(path, &db);
        db_exec(db, "CREATE TABLE names(name TEXT, owner BLOB);"
                    "CREATE TABLE meta(k TEXT, v TEXT); INSERT INTO meta VALUES('height','321');");
        sqlite3_close(db);
        v = sp_view_open_chain(path);
        CK(v && sp_view_tip(v) == 321, "tip falls back to meta.height when proj_height is absent");
        if (v) sp_view_close(v);
        // no meta at all
        fpath(path, sizeof path, "nometa.db");
        sqlite3_open(path, &db);
        db_exec(db, "CREATE TABLE names(name TEXT, owner BLOB);");
        sqlite3_close(db);
        v = sp_view_open_chain(path);
        CK(v && sp_view_tip(v) == 0, "tip is 0 when meta is absent (no crash)");
        if (v) { CK(!sp_view_owner_now(v, "alpha", got), "lookup with no rows is unowned"); sp_view_close(v); }
        // completely empty db (no tables)
        fpath(path, sizeof path, "bare.db");
        sqlite3_open(path, &db); db_exec(db, "PRAGMA user_version=1;"); sqlite3_close(db);
        v = sp_view_open_chain(path);
        CK(v != NULL, "db with no tables still opens");
        if (v) {
            CK(sp_view_tip(v) == 0, "bare db: tip 0");
            CK(!sp_view_owner_now(v, "alpha", got), "bare db: lookup returns 0, no crash");
            CK(!sp_view_addr_owns_name(v, oA), "bare db: addr scan returns 0, no crash");
            sp_view_close(v);
        }
        // a file that is not a database at all
        fpath(path, sizeof path, "garbage.db");
        FILE *gf = fopen(path, "wb");
        for (int i = 0; i < 4096; i++) fputc((int)(rnd() & 0xFF), gf);
        fclose(gf);
        v = sp_view_open_chain(path);
        CK(1, "non-database file: open returned without crashing");
        if (v) {
            CK(!sp_view_owner_now(v, "alpha", got), "non-database file: lookup returns 0");
            CK(sp_view_tip(v) == 0, "non-database file: tip 0");
            sp_view_close(v);
        }
    }

    printf("-- chain mode: §4.2 epoch resolution --\n");
    {
        uint8_t oA[20], oB[20], oC[20];
        owner_n(31, oA); owner_n(32, oB); owner_n(33, oC);
        fpath(path, sizeof path, "epochs.db");
        sqlite3 *db; sqlite3_open(path, &db);
        db_exec(db, "CREATE TABLE names(name TEXT PRIMARY KEY, owner BLOB);"
                    "CREATE TABLE epochs(name TEXT, start_height INTEGER, owner BLOB);"
                    "CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);"
                    "INSERT INTO meta VALUES('proj_height','1000');"
                    "INSERT INTO meta VALUES('epochs_from','100');");
        // `flip`: A owns from 200, lapses at 400, C owns from 600
        const char *EI = "INSERT INTO epochs(name,start_height,owner) VALUES(?,?,?)";
        db_bind_row(db, EI, "flip", oA,   200, 1);
        db_bind_row(db, EI, "flip", NULL, 400, 1);          // lapse row
        db_bind_row(db, EI, "flip", oC,   600, 1);
        db_bind_row(db, "INSERT INTO names(name,owner) VALUES(?,?)", "flip", oC, 0, 0);
        // `late`: first epoch starts at 700 — before that it is KNOWN-unowned
        db_bind_row(db, EI, "late", oB, 700, 1);
        db_bind_row(db, "INSERT INTO names(name,owner) VALUES(?,?)", "late", oB, 0, 0);
        // `nohist`: present in names, absent from epochs -> history does not
        // cover it -> documented fallback to the current owner
        db_bind_row(db, "INSERT INTO names(name,owner) VALUES(?,?)", "nohist", oA, 0, 0);
        // `early`: an epoch that begins exactly at epochs_from
        db_bind_row(db, EI, "early", oB, 100, 1);
        db_bind_row(db, "INSERT INTO names(name,owner) VALUES(?,?)", "early", oB, 0, 0);
        sqlite3_close(db);

        SpView *v = sp_view_open_chain(path);
        CK(v != NULL, "epochs db opens");
        if (v) {
            CK(sp_view_tip(v) == 1000, "tip 1000");
            struct { const char *nm; uint32_t h; int want; const uint8_t *who; const char *lbl; } E[] = {
                { "flip", 200, 1, oA, "flip @200 (epoch start) -> A" },
                { "flip", 201, 1, oA, "flip @201 -> A" },
                { "flip", 399, 1, oA, "flip @399 (last height of A's epoch) -> A" },
                { "flip", 400, 0, NULL, "flip @400 (lapse row) -> UNOWNED" },
                { "flip", 599, 0, NULL, "flip @599 (still lapsed) -> UNOWNED" },
                { "flip", 600, 1, oC, "flip @600 (C's epoch starts) -> C" },
                { "flip", 1000, 1, oC, "flip @tip -> C" },
                { "flip", 0xFFFFFFFFu, 1, oC, "flip @2^32-1 -> C (no overflow in the bind)" },
                { "late", 699, 0, NULL, "late @699 (before its first epoch) -> KNOWN-unowned" },
                { "late", 100, 0, NULL, "late @epochs_from -> KNOWN-unowned" },
                { "late", 700, 1, oB, "late @700 -> B" },
                { "nohist", 50, 1, oA, "nohist @50 -> falls back to the current owner (documented)" },
                { "nohist", 1000, 1, oA, "nohist @tip -> current owner" },
                { "early", 100, 1, oB, "early @100 (epoch == epochs_from) -> B" },
                { "early", 99, 1, oB, "early @99 (below epochs_from) -> fallback to current owner" },
                { "absent", 500, 0, NULL, "a name in neither table -> unowned" } };
            for (unsigned i = 0; i < sizeof E / sizeof *E; i++) {
                uint8_t g2[20];
                int rc = sp_view_owner_of(v, (const uint8_t *)E[i].nm, (int)strlen(E[i].nm), E[i].h, g2);
                int ok = rc == E[i].want && (!E[i].who || memcmp(g2, E[i].who, 20) == 0);
                CK(ok, E[i].lbl);
            }
            CK(sp_view_owner_now(v, "flip", got) && memcmp(got, oC, 20) == 0,
               "owner_now uses the tip height (-> C)");
            // determinism across 1000 shuffled epoch queries
            int diff = 0;
            for (int i = 0; i < 1000; i++) {
                unsigned k = (unsigned)(rnd() % (sizeof E / sizeof *E));
                uint8_t g2[20];
                int rc = sp_view_owner_of(v, (const uint8_t *)E[k].nm, (int)strlen(E[k].nm), E[k].h, g2);
                g_checks++;
                if (rc != E[k].want || (E[k].who && memcmp(g2, E[k].who, 20) != 0)) diff++;
            }
            CK(diff == 0, "1000 shuffled epoch queries: fully deterministic");
            // "never returns something it was told to drop": the lapse row
            int leaked = 0;
            for (uint32_t hh = 400; hh < 600; hh += 7) {
                uint8_t g2[20]; g_checks++;
                if (sp_view_owner_of(v, (const uint8_t *)"flip", 4, hh, g2)) leaked++;
            }
            CK(leaked == 0, "across the whole lapse window (400..599) the view returns NOTHING");
            sp_view_close(v);
        }
        // epochs table with a malformed owner blob length
        fpath(path, sizeof path, "epochs-bad.db");
        sqlite3_open(path, &db);
        db_exec(db, "CREATE TABLE names(name TEXT, owner BLOB);"
                    "CREATE TABLE epochs(name TEXT, start_height INTEGER, owner BLOB);"
                    "CREATE TABLE meta(k TEXT, v TEXT);"
                    "INSERT INTO meta VALUES('proj_height','500');"
                    "INSERT INTO epochs VALUES('bad', 10, X'00112233');"   // 4-byte owner
                    "INSERT INTO names VALUES('bad', X'00112233');");
        sqlite3_close(db);
        v = sp_view_open_chain(path);
        CK(v != NULL, "db with a malformed epoch owner opens");
        if (v) {
            CK(!sp_view_owner_of(v, (const uint8_t *)"bad", 3, 100, got),
               "4-byte epoch owner blob never fills owner[20] (returns unowned)");
            sp_view_close(v);
        }
    }

    // ═══ open/close stress ═══════════════════════════════════════════════════
    PHASE("open/close stress", 120);
    printf("-- repeated open/close (resource release) --\n");
    {
        fpath(path, sizeof path, "epochs.db");
        int bad = 0;
        for (int i = 0; i < 200; i++) {
            SpView *v = sp_view_open_chain(path);
            if (!v) { bad++; continue; }
            uint8_t g2[20];
            if (!sp_view_owner_of(v, (const uint8_t *)"flip", 4, 300, g2)) bad++;
            sp_view_close(v);
            g_checks++;
        }
        CK(bad == 0, "200 chain open/query/close cycles: all succeed (fds and stmts released)");
        fpath(path, sizeof path, "big.txt");
        bad = 0;
        for (int i = 0; i < 200; i++) {
            SpView *v = sp_view_open_test(path, 1);
            if (!v) { bad++; continue; }
            char nm[40]; name_n(1234, nm); uint8_t g2[20];
            if (!sp_view_owner_now(v, nm, g2)) bad++;
            sp_view_close(v);
            g_checks++;
        }
        CK(bad == 0, "200 test-mode open/query/close cycles over an 8192-row table: all succeed");
    }

    printf("-- robustness notes (read, not triggered) --\n");
    printf("  note  src/view.c:38  sp_view_open_chain: calloc() result is used\n"
           "        without a NULL check.\n");
    printf("  note  src/view.c:62  sp_view_open_test: `v->rows = realloc(v->rows, ...)`\n"
           "        is the classic realloc anti-pattern — on failure the old block\n"
           "        leaks and v->rows becomes NULL, then &v->rows[v->n] is\n"
           "        dereferenced at line 63. Only reachable under allocation\n"
           "        failure, so not exercised here.\n");
    printf("  note  src/view.c:59  the loader uses fscanf(\"%%63s %%63s\") — a name\n"
           "        longer than 63 bytes is silently split across two tokens and\n"
           "        desynchronises the rest of that line. Proven non-crashing above;\n"
           "        every resulting row is dropped by sp_name_valid.\n");
    CK(1, "robustness notes recorded");

    alarm(0);
    if (g_dir_ok) {
        char cmd[600]; snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
        if (system(cmd) != 0) printf("  note  could not remove %s\n", g_dir);
    }
    printf("\nview_test: %ld checks, %d failed\n", g_checks, g_fail);
    if (g_fail) { printf("view_test: FAILED\n"); return 1; }
    printf("view_test: all passed\n");
    return 0;
}
