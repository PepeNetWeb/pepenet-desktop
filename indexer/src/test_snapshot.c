// test_snapshot.c — idx-01: offline snapshot-export / snapshot-verify.
//
// 1. idx_snap_walk on synthetic direct-mined headers ground at a regtest-style
//    powLimit 0x207fffff (real scrypt, ~2 nonces each; 120 s spacing keeps
//    Digishield at the cap): a valid chain is accepted with work; broken linkage, a header
//    whose scrypt misses the target, a wrong nBits, and a truncated file are
//    each rejected at the right height.
// 2. End to end on the regtest fixture (mkblocks + index into a mkdtemp'd /tmp
//    db — never ~/.pepenet): export, verify OK; then a tampered names row in
//    state.db, a tampered MANIFEST digest, and an export over an existing
//    snapshot are each refused.
#include "snapshot.h"
#include "pow.h"
#include "chain.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include "indexer.h"
#include "db.h"
#include "oracle_feed.h"
#include <sys/wait.h>
#include <sys/stat.h>

int indexer_main(int argc, char **argv);
int chain_mkblocks(const char *dir);
int chain_mkblocks_mag(const char *dir, const uint8_t mag[2]);
int chain_mkblocks_expiry(const char *dir, const uint8_t mag[2]);

static int g_fail;
#define CHECK(c, n) do { if (c) printf("  ok   %s\n", n); else { printf("  FAIL %s\n", n); g_fail++; } } while (0)

#define PL 0x207fffffu   // regtest-style powLimit: ~1/2 of nonces meet it
static void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8*i)); }
// n headers on top of prev; returns buffer as one `headers` body
static size_t mkchain(uint8_t *out, const uint8_t prev0[32], uint32_t t0, int n) {
    size_t o = 0; out[o++] = (uint8_t)n;
    uint8_t prev[32]; memcpy(prev, prev0, 32);
    for (int i = 0; i < n; i++) {
        uint8_t *h = out + o; memset(h, 0, 80);
        put32(h, 1); memcpy(h + 4, prev, 32); memset(h + 36, 0x5a + i, 32);
        put32(h + 68, t0 + 120u * (i + 1)); put32(h + 72, PL);
        PowParams pp = { PL, 0 }; char why[96]; size_t sp_;
        for (uint32_t nonce = 0;; nonce++) { put32(h + 76, nonce); if (idx_pow_check2(h, 80, &pp, &sp_, why, sizeof why)) break; }
        idx_sha256d(h, 80, prev); o += 80; out[o++] = 0;
    }
    return o;
}
static void seed(IdxSnapWalk *w, const uint8_t g[32]) {
    memset(w, 0, sizeof *w); w->h = 100; memcpy(w->hash, g, 32);
    w->bits = PL; w->time = 1000; w->prev_time = 880; w->powlimit = PL; w->check_pow = 1;
}
static int run(int argc, ...) {
    char *argv[8]; setvbuf(stdout, NULL, _IOLBF, 0); va_list ap; va_start(ap, argc);
    for (int i = 0; i < argc; i++) argv[i] = va_arg(ap, char *);
    va_end(ap); fflush(stdout); int r = indexer_main(argc, argv); fflush(stdout); return r;
}

// idx-06: each build in its own process (fork), own data dir; optional crash.
static int child(const char *crash, int argc, ...) {
    char *argv[8]; va_list ap; va_start(ap, argc);
    for (int i = 0; i < argc; i++) argv[i] = va_arg(ap, char *);
    va_end(ap); fflush(stdout);
    pid_t p = fork(); if (p < 0) return -1;
    if (!p) {
        if (crash) setenv("IDX_TEST_CRASH_AT", crash, 1);
        int fd = open("/dev/null", O_WRONLY); dup2(fd, 1); dup2(fd, 2); close(fd);
        _exit(indexer_main(argc, argv));
    }
    int st; waitpid(p, &st, 0); return st;
}
// idx-09: like child(), but stdout+stderr go to logpath
static int childlog(const char *logpath, int argc, ...) {
    char *argv[8]; va_list ap; va_start(ap, argc);
    for (int i = 0; i < argc; i++) argv[i] = va_arg(ap, char *);
    va_end(ap); fflush(stdout);
    pid_t p = fork(); if (p < 0) return -1;
    if (!p) {
        int fd = open(logpath, O_WRONLY | O_CREAT | O_TRUNC, 0600); dup2(fd, 1); dup2(fd, 2); close(fd);
        _exit(indexer_main(argc, argv));
    }
    int st; waitpid(p, &st, 0); return st;
}
static int file_has(const char *path, const char *needle) {
    FILE *f = fopen(path, "r"); if (!f) return 0;
    char b[8192]; size_t n = fread(b, 1, sizeof b - 1, f); fclose(f); b[n] = 0;
    return strstr(b, needle) != NULL;
}
// value of "<key> <v>" in a MANIFEST ("" if absent); out holds 80 bytes
static void mf_field(const char *path, const char *key, char out[80]) {
    out[0] = 0; FILE *f = fopen(path, "r"); if (!f) return;
    char ln[256]; size_t kl = strlen(key);
    while (fgets(ln, sizeof ln, f))
        if (!strncmp(ln, key, kl) && ln[kl] == ' ') { snprintf(out, 80, "%s", ln + kl + 1); out[strcspn(out, "\n")] = 0; break; }
    fclose(f);
}
static int file_sha(const char *p, char out[65]) {
    uint8_t h[32]; int64_t n; if (!idx_snap_file_sha256(p, h, &n)) return 0;
    for (int i = 0; i < 32; i++) sprintf(out + 2*i, "%02x", h[i]); return 1;
}

// ---- idx-13 PROPOSAL: reorg rollback must equal a fresh sync of the winner ----
int chain_mkblocks_expiry_br(const char *dir, const uint8_t mag[2], char pfx, int fork, int64_t *times);
static int r13_index(const char *db, const char *dir, char pfx, int from, int to) {
    static char f[48][320]; const char *av[64]; int ac = 0;
    av[ac++] = "x"; av[ac++] = "index"; av[ac++] = db; av[ac++] = "0";
    for (int i = from; i <= to; i++) { snprintf(f[i], sizeof f[i], "%s/%c%02d.bin", dir, pfx, i); av[ac++] = f[i]; }
    av[ac++] = "--coin"; av[ac++] = "regtest"; av[ac] = NULL;
    char lg[400]; snprintf(lg, sizeof lg, "%s/r13.log", dir);
    fflush(stdout); pid_t pid = fork();
    if (pid == 0) { int fd = open(lg, O_WRONLY|O_CREAT|O_APPEND, 0600); if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); close(fd); }
                    _exit(indexer_main(ac, (char **)av)); }
    int st = 0; waitpid(pid, &st, 0); return WIFEXITED(st) ? WEXITSTATUS(st) : 99;
}
// what the live reorg path does: idx_sync_rollback to the fork point, then the sync tip = fork
static int r13_rollback(const char *dbp, int64_t fork_h) {
    sqlite3 *db = idx_db_open(dbp); if (!db) return 0;
    SmState *s = sm_new((uint64_t)idx_db_get_activation(db, 0));
    if (!idx_db_get_onchain_magic(db, s->onchain_magic)) idx_coin_onchain_magic("regtest", s->onchain_magic);
    idx_db_load_state(db, s);
    OracleFeed *o = oracle_new(); idx_db_oracle_warm(db, o);
    oracle_set_subsidy(o, idx_db_get_subsidy(db, 10000LL * SM_KOINU_PER_DOGE));
    int ok = idx_sync_rollback(&s, db, o, (int64_t)s->activation_height, fork_h) != 0;
    uint8_t h[32] = {0}; ok = ok && idx_db_block_get(db, fork_h, h);
    if (ok) idx_db_save_sync(db, fork_h, h);
    oracle_free(o); sm_free(s); sqlite3_close(db); return ok;
}
static void r13_q(const char *p, const char *sql, char *out, size_t n) {
    sqlite3 *x = NULL; sqlite3_stmt *q = NULL; out[0] = 0;
    if (sqlite3_open(p, &x) == SQLITE_OK && sqlite3_prepare_v2(x, sql, -1, &q, NULL) == SQLITE_OK &&
        sqlite3_step(q) == SQLITE_ROW && sqlite3_column_text(q, 0)) snprintf(out, n, "%s", (const char *)sqlite3_column_text(q, 0));
    sqlite3_finalize(q); sqlite3_close(x);
}
// node db vs fresh db: names, epochs, muts, commits, export sha, state_digest, state_ecmh
static void r13_same(const char *tag, const char *dir, const char *a, const char *b) {
    static const char *Q[] = {
        "SELECT group_concat(x,',') FROM (SELECT name||':'||hex(owner)||':'||lease_expiry AS x FROM names ORDER BY name)",
        "SELECT group_concat(name||':'||start_height||':'||coalesce(hex(owner),'-'),',') FROM (SELECT * FROM epochs ORDER BY name,start_height)",
        "SELECT group_concat(hex(owner)||':'||height,',') FROM (SELECT * FROM muts ORDER BY owner)",
        "SELECT count(*) FROM commits" };
    static const char *L[] = { "names", "epochs", "muts", "commits" };
    char m[200], x[4096], y[4096];
    for (int i = 0; i < 4; i++) { r13_q(a, Q[i], x, sizeof x); r13_q(b, Q[i], y, sizeof y);
        snprintf(m, sizeof m, "idx-13 %s: %s equal to a fresh sync of the winning branch", tag, L[i]); CHECK(!strcmp(x, y), m); }
    char ea[400], eb[400], c[1200], pa[420], pb[420], ha[65] = "", hb[65] = "?";
    snprintf(ea, sizeof ea, "%s/xa", dir); snprintf(eb, sizeof eb, "%s/xb", dir);
    snprintf(c, sizeof c, "rm -rf '%s' '%s'", ea, eb); if (system(c)) {}
    int ok = child(NULL, 5, "x", "snapshot-export", "regtest", a, ea) == 0 && child(NULL, 5, "x", "snapshot-export", "regtest", b, eb) == 0;
    snprintf(pa, sizeof pa, "%s/state.db", ea); snprintf(pb, sizeof pb, "%s/state.db", eb);
    snprintf(m, sizeof m, "idx-13 %s: export sha256 equal", tag);
    CHECK(ok && file_sha(pa, ha) && file_sha(pb, hb) && !strcmp(ha, hb), m);
    char da[80], db_[80], xa[80], xb[80];
    snprintf(pa, sizeof pa, "%s/MANIFEST", ea); snprintf(pb, sizeof pb, "%s/MANIFEST", eb);
    mf_field(pa, "state_digest", da); mf_field(pb, "state_digest", db_); mf_field(pa, "state_ecmh", xa); mf_field(pb, "state_ecmh", xb);
    snprintf(m, sizeof m, "idx-13 %s: state_digest equal", tag); CHECK(*da && !strcmp(da, db_), m);
    snprintf(m, sizeof m, "idx-13 %s: state_ecmh equal", tag);   CHECK(*xa && !strcmp(xa, xb), m);
}
static void r13_case(const char *dir, const uint8_t PN[2], const char *tag, char pfx, int fork_h, int check_at_fork) {
    char node[400], fresh[400], c[1000], m[200];
    snprintf(node, sizeof node, "%s/n_%c.db", dir, pfx); snprintf(fresh, sizeof fresh, "%s/f_%c.db", dir, pfx);
    snprintf(c, sizeof c, "rm -f '%s'* '%s'*", node, fresh); if (system(c)) {}
    chain_mkblocks_expiry_br(dir, PN, pfx, fork_h, NULL);
    snprintf(m, sizeof m, "idx-13 %s: node synced losing branch e00..e47, rolled back to %d", tag, fork_h);
    CHECK(r13_index(node, dir, 'e', 0, 47) == 0 && r13_rollback(node, fork_h), m);
    if (check_at_fork) {
        CHECK(r13_index(fresh, dir, pfx, 0, fork_h) == 0, "idx-13 fresh sync to the fork point");
        char t2[120]; snprintf(t2, sizeof t2, "%s (right after rollback)", tag); r13_same(t2, dir, node, fresh);
    }
    snprintf(m, sizeof m, "idx-13 %s: node connects winning branch %d..47", tag, fork_h + 1);
    CHECK(r13_index(node, dir, pfx, fork_h + 1, 47) == 0, m);
    snprintf(c, sizeof c, "rm -f '%s'*", fresh); if (system(c)) {}
    CHECK(r13_index(fresh, dir, pfx, 0, 47) == 0, "idx-13 fresh sync of the winning branch");
    r13_same(tag, dir, node, fresh);
}
static void r13_all(const char *dir, const uint8_t PN[2]) {
    int64_t t[48]; chain_mkblocks_expiry_br(dir, PN, 'e', 99, t);
    // carol commits at 21; spec expiry = first height whose MTP > commit MTP + 18000
    int64_t ct = sm_mtp(t + 10, 11); int hc = -1;
    for (int h = 22; h < 48 && hc < 0; h++) { int lo = h > 11 ? h - 11 : 0; if (sm_mtp(t + lo, h - lo) > ct + 18000) hc = h; }
    char lv[400], v[64]; snprintf(lv, sizeof lv, "%s/n_e.db", dir);
    snprintf(lv, sizeof lv, "%s/probe.db", dir); r13_index(lv, dir, 'e', 0, 47);
    r13_q(lv, "SELECT start_height FROM epochs WHERE name='alice' AND owner IS NULL", v, sizeof v);
    int lap = atoi(v);
    printf("  info idx-13: carol's commit expires at %d, alice lapses at %d (carriers 0,1,6,21)\n", hc, lap);
    CHECK(hc > 21 && hc < lap && lap > 21, "idx-13: fixture has a non-carrier expiry, then a non-carrier lapse, after the last carrier");
    r13_case(dir, PN, "crossing (fork 40, rollback range spans expiry+lapse)", 'a', 40, 1);
    r13_case(dir, PN, "exact expiry (fork at carol's expiry height)", 'c', hc, 1);
    r13_case(dir, PN, "exact lapse (fork at alice's lapse height)", 'l', lap, 1);
    r13_case(dir, PN, "deep (fork 3, 44 blocks replaced)", 'd', 3, 0);
}

int main(void) {
    printf("-- header walk (synthetic powLimit chain) --\n");
    uint8_t g[32]; memset(g, 0x42, 32);
    static uint8_t buf[8 * 81 + 4], bad[sizeof buf];
    size_t len = mkchain(buf, g, 1000, 8);
    IdxSnapWalk w; char why[200];
    seed(&w, g);
    int ok = idx_snap_walk(&w, buf, len, why, sizeof why);
    CHECK(ok && w.h == 108 && w.n == 8, "8 valid headers accepted, height 100→108");
    int nz = 0; for (int i = 0; i < 32; i++) nz |= w.work[i];
    CHECK(nz, "cumulative work is non-zero");
    uint8_t tip[32]; memcpy(tip, w.hash, 32);
    seed(&w, g); ok = idx_snap_walk(&w, buf, 1 + 81 * 3, why, sizeof why);
    CHECK(!ok && w.h == 103, "page cut after 3 of 8 headers rejected");
    memcpy(bad, buf, len); bad[1 + 81 * 3 + 4] ^= 1;                    // header 4 prev-hash
    seed(&w, g); ok = idx_snap_walk(&w, bad, len, why, sizeof why);
    CHECK(!ok && w.h == 103 && strstr(why, "link"), "broken linkage rejected at 104");
    memcpy(bad, buf, len);                                              // header 6: a nonce that misses
    { PowParams pp = { PL, 0 }; size_t sp_; uint8_t *h6 = bad + 1 + 81 * 5;
      for (uint32_t nn = 0;; nn++) { put32(h6 + 76, nn); if (!idx_pow_check2(h6, 80, &pp, &sp_, why, sizeof why)) break; } }
    seed(&w, g); ok = idx_snap_walk(&w, bad, len, why, sizeof why);
    CHECK(!ok && w.h == 105, "header missing its PoW target rejected at 106");
    memcpy(bad, buf, len); put32(bad + 1 + 72, 0x1d0fffff);             // header 1 nBits
    seed(&w, g); ok = idx_snap_walk(&w, bad, len, why, sizeof why);
    CHECK(!ok && w.h == 100, "wrong nBits rejected at 101");
    seed(&w, g); ok = idx_snap_walk(&w, buf, len - 5, why, sizeof why);
    CHECK(!ok && strstr(why, "truncated"), "truncated headers file rejected");
    { uint8_t g2[32]; memset(g2, 0x43, 32); seed(&w, g2); ok = idx_snap_walk(&w, buf, len, why, sizeof why);
      CHECK(!ok && w.h == 100, "chain off a different checkpoint rejected"); }
    (void)tip;

    printf("\n-- export / verify end to end (regtest fixture) --\n");
    char dir[] = "/tmp/idxsnapXXXXXX"; if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    char db[256], b0[256], b1[256], snap[256], snap2[256], cmd[2048];
    snprintf(db, sizeof db, "%s/f.db", dir); snprintf(b0, sizeof b0, "%s/blk0.bin", dir);
    snprintf(b1, sizeof b1, "%s/blk1.bin", dir); snprintf(snap, sizeof snap, "%s/snap", dir);
    snprintf(snap2, sizeof snap2, "%s/snap2", dir);
    CHECK(chain_mkblocks(dir) == 0, "fixture blocks written");
    CHECK(run(6, "x", "index", db, "0", b0, b1) == 0, "fixture folded");
    { char outp[300]; snprintf(outp, sizeof outp, "%s/export.out", dir);
      fflush(stdout); int sv = dup(1), fd = open(outp, O_WRONLY | O_CREAT | O_TRUNC, 0600); dup2(fd, 1); close(fd);
      int r = run(5, "x", "snapshot-export", "regtest", db, snap);
      fflush(stdout); dup2(sv, 1); close(sv);
      CHECK(r == 0, "snapshot-export ok");
      char sp[300]; snprintf(sp, sizeof sp, "%s/state.db", snap);
      uint8_t h[32]; char hx[65]; idx_snap_file_sha256(sp, h, NULL);
      for (int i = 0; i < 32; i++) sprintf(hx + 2*i, "%02x", h[i]);
      FILE *f = fopen(outp, "r"); char line[400]; int seen = 0;
      while (f && fgets(line, sizeof line, f)) if (!strncmp(line, "sha256 ", 7) && !strncmp(line + 7, hx, 64)) seen = 1;
      if (f) fclose(f);
      CHECK(seen, "idx-04: snapshot-export prints the state.db whole-file sha256"); }
    CHECK(run(5, "x", "snapshot-verify", "regtest", snap, "--allow-unpinned") == 0, "snapshot-verify --allow-unpinned ok on a fresh export");
    CHECK(run(4, "x", "snapshot-verify", "regtest", snap) == 1, "idx-05: snapshot-verify with no pin REFUSES (exit 1)");
    CHECK(run(5, "x", "snapshot-verify", "regtest", "--allow-unpinned", snap) == 0, "idx-05: --allow-unpinned accepted in any position");
    CHECK(run(5, "x", "snapshot-export", "regtest", db, snap) != 0, "export refuses to overwrite");
    CHECK(run(5, "x", "snapshot-verify", "doge", snap, "--allow-unpinned") != 0, "verify under the wrong coin fails");
    // tamper the state copy
    snprintf(cmd, sizeof cmd, "cp -r %s %s", snap, snap2); CHECK(system(cmd) == 0, "copied snapshot");
    { char sp[300]; snprintf(sp, sizeof sp, "%s/state.db", snap2); sqlite3 *d;
      int r = sqlite3_open(sp, &d) == SQLITE_OK &&
              sqlite3_exec(d, "UPDATE names SET owner=zeroblob(20)", 0, 0, 0) == SQLITE_OK &&
              sqlite3_changes(d) > 0;
      sqlite3_close(d); CHECK(r, "tampered an owner in state.db"); }
    CHECK(run(5, "x", "snapshot-verify", "regtest", snap2, "--allow-unpinned") != 0, "verify (unpinned) rejects a tampered state.db");
    // tamper the manifest digest
    snprintf(cmd, sizeof cmd, "rm -rf %s && cp -r %s %s && sed -i 's/^state_ecmh ./state_ecmh 0/;s/^state_ecmh 00/state_ecmh 11/' %s/MANIFEST", snap2, snap, snap2, snap2);
    CHECK(system(cmd) == 0, "tampered MANIFEST ecmh");
    CHECK(run(5, "x", "snapshot-verify", "regtest", snap2, "--allow-unpinned") != 0, "verify (unpinned) rejects a tampered MANIFEST");

    // ── idx-04: whole-file SHA-256 pin ─────────────────────────────────────
    printf("\n-- idx-04: whole-file sha256 pin (verify + import, fail closed) --\n");
    {
        char sp[300], pin[65], badpin[65], imp[300], snapf[300], snapt[300], why[400];
        snprintf(sp, sizeof sp, "%s/state.db", snap);
        uint8_t h[32]; idx_snap_file_sha256(sp, h, NULL);
        for (int i = 0; i < 32; i++) sprintf(pin + 2*i, "%02x", h[i]);
        memcpy(badpin, pin, 65); badpin[63] = badpin[63] == '0' ? '1' : '0';
        uint8_t tmp32[32];
        CHECK(idx_snap_parse_pin(pin, tmp32) && !memcmp(tmp32, h, 32), "pin parses (64 hex)");
        CHECK(!idx_snap_parse_pin("abc", tmp32) && !idx_snap_parse_pin(NULL, tmp32), "short/NULL pin rejected");
        { char up[65]; for (int i = 0; i < 65; i++) up[i] = (char)(pin[i] >= 'a' && pin[i] <= 'f' ? pin[i] - 32 : pin[i]);
          CHECK(idx_snap_parse_pin(up, tmp32) && !memcmp(tmp32, h, 32), "upper-case hex accepted"); }
        char zz[65]; memset(zz, 'g', 64); zz[64] = 0;
        CHECK(!idx_snap_parse_pin(zz, tmp32), "non-hex pin rejected");
        CHECK(idx_snap_default_pin("pep") == NULL && idx_snap_default_pin("doge") == NULL,
              "no compiled-in default pin for pep/doge (none published)");
        CHECK(idx_snap_effective_pin("pep", pin) == pin, "flag pin overrides the default");
        CHECK(idx_snap_effective_pin("pep", NULL) == idx_snap_default_pin("pep"), "no flag → compiled default");
        // verify
        CHECK(run(6, "x", "snapshot-verify", "regtest", snap, "--sha256", pin) == 0, "verify: matching pin → OK");
        CHECK(run(6, "x", "snapshot-verify", "regtest", snap, "--sha256", badpin) != 0, "verify: wrong pin → REFUSED");
        CHECK(run(6, "x", "snapshot-verify", "regtest", "--sha256", pin, snap) == 0, "verify: flag accepted in any position");
        CHECK(run(6, "x", "snapshot-verify", "regtest", snap, "--sha256", "zz") != 0, "verify: malformed pin → REFUSED");
        CHECK(run(5, "x", "snapshot-verify", "regtest", snap, "--sha256") == 2, "verify: --sha256 without a value → usage");
        // flipped byte / truncated copies (byte-level, deep in the file; sqlite
        // might still open these — the pin must refuse before it is asked to)
        snprintf(snapf, sizeof snapf, "%s/snapflip", dir); snprintf(snapt, sizeof snapt, "%s/snaptrunc", dir);
        snprintf(cmd, sizeof cmd, "cp -r %s %s && cp -r %s %s", snap, snapf, snap, snapt);
        CHECK(system(cmd) == 0, "copied snapshot twice");
        { char p2[400]; snprintf(p2, sizeof p2, "%s/state.db", snapf);
          FILE *f = fopen(p2, "r+b"); fseek(f, 0, SEEK_END); long sz = ftell(f);
          fseek(f, sz - 1, SEEK_SET); int c = fgetc(f); fseek(f, sz - 1, SEEK_SET); fputc(c ^ 0x01, f); fclose(f); }
        { char p2[400]; snprintf(p2, sizeof p2, "%s/state.db", snapt);
          FILE *f = fopen(p2, "r+b"); fseek(f, 0, SEEK_END); long sz = ftell(f); fclose(f);
          CHECK(truncate(p2, sz - 512) == 0, "truncated state.db by 512 bytes"); }
        CHECK(run(6, "x", "snapshot-verify", "regtest", snapf, "--sha256", pin) != 0, "verify: one flipped bit → REFUSED");
        CHECK(run(6, "x", "snapshot-verify", "regtest", snapt, "--sha256", pin) != 0, "verify: truncated file → REFUSED");
        CHECK(run(5, "x", "snapshot-verify", "regtest", snapf, "--allow-unpinned") == 0, "--allow-unpinned does not see a bit flip in a free page: why the pin is required");
        CHECK(run(7, "x", "snapshot-verify", "regtest", snapf, "--allow-unpinned", "--sha256", pin) != 0, "a given pin still wins over --allow-unpinned");
        // import
        snprintf(imp, sizeof imp, "%s/imp.db", dir);
        #define NOFILE(pth) (access(pth, F_OK) != 0)
        char impt[320]; snprintf(impt, sizeof impt, "%s.snap-tmp", imp);
        CHECK(!idx_snapshot_import("regtest", snapf, imp, pin, why, sizeof why) && strstr(why, "mismatch") && NOFILE(imp) && NOFILE(impt),
              "import: flipped byte → refused, nothing written");
        CHECK(!idx_snapshot_import("regtest", snapt, imp, pin, why, sizeof why) && strstr(why, "mismatch") && NOFILE(imp),
              "import: truncated file → refused, nothing written");
        CHECK(!idx_snapshot_import("regtest", snap, imp, NULL, why, sizeof why) && strstr(why, "no snapshot pin") && NOFILE(imp),
              "import: missing pin → refused, nothing written");
        CHECK(!idx_snapshot_import("regtest", snap, imp, "deadbeef", why, sizeof why) && strstr(why, "malformed") && NOFILE(imp),
              "import: malformed pin → refused");
        CHECK(!idx_snapshot_import("regtest", snap, imp, badpin, why, sizeof why) && NOFILE(imp),
              "import: wrong pin (correct file) → refused");
        CHECK(!idx_snapshot_import("doge", snap, imp, pin, why, sizeof why) && NOFILE(imp) && NOFILE(impt),
              "import: matching pin but MANIFEST coin mismatch → refused, temp removed");
        CHECK(run(7, "x", "snapshot-import", "regtest", snapf, imp, "--sha256", pin) == 1 && NOFILE(imp),
              "snapshot-import CLI: mismatch exits 1, nothing applied");
        // fallback: after a refusal the caller full-syncs; the result is the same state
        CHECK(run(6, "x", "index", imp, "0", b0, b1) == 0, "fallback: full fold from blocks after the refusal");
        CHECK(run(3, "x", "check", imp) == 0, "fallback db passes `check`");
        char fb[300]; snprintf(fb, sizeof fb, "%s/fb", dir);
        { char outp[300]; snprintf(outp, sizeof outp, "%s/fb.out", dir);
          fflush(stdout); int sv = dup(1), fd = open(outp, O_WRONLY | O_CREAT | O_TRUNC, 0600); dup2(fd, 1); close(fd);
          run(5, "x", "snapshot-export", "regtest", imp, fb); fflush(stdout); dup2(sv, 1); close(sv);
          snprintf(cmd, sizeof cmd, "grep -h '^state_' %s/MANIFEST | sort > %s/a && grep -h '^state_' %s/MANIFEST | sort > %s/b && cmp -s %s/a %s/b",
                   snap, dir, fb, dir, dir, dir);
          CHECK(system(cmd) == 0, "fallback full sync reaches the same state_digest/state_ecmh as the snapshot"); }
        // match: applied, and only once
        char imp2[300]; snprintf(imp2, sizeof imp2, "%s/imp2.db", dir);
        CHECK(idx_snapshot_import("regtest", snap, imp2, pin, why, sizeof why) == 1, "import: matching pin → applied");
        // idx-11: the applied db is the pinned file + this coin's meta onchain_magic, so
        // it is no longer byte-identical; its canonical re-export is.
        { char rx[340], rp[360], rh[65]; snprintf(rx, sizeof rx, "%s/reexp", dir); snprintf(rp, sizeof rp, "%s/state.db", rx);
          int sv = dup(1), dn = open("/dev/null", O_WRONLY); fflush(stdout); dup2(dn, 1); close(dn);
          int r = run(5, "x", "snapshot-export", "regtest", imp2, rx); fflush(stdout); dup2(sv, 1); close(sv);
          CHECK(r == 0 && file_sha(rp, rh) && !strcmp(rh, pin), "applied db re-exports byte-identical to the pinned file"); }
        CHECK(run(3, "x", "check", imp2) == 0, "applied db passes `check`");
        CHECK(!idx_snapshot_import("regtest", snap, imp2, pin, why, sizeof why) && strstr(why, "already exists"),
              "import never overwrites an existing db");
        CHECK(run(7, "x", "snapshot-import", "regtest", snap, imp, "--sha256", pin) == 1, "CLI import refuses over the fallback db");
        #undef NOFILE
    }
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir); if (system(cmd)) {}


    printf("\n-- idx-06: whole-file pin is reproducible across divergent builds --\n");
    {
        char rd[] = "/tmp/idxreproXXXXXX"; if (!mkdtemp(rd)) { perror("mkdtemp"); return 1; }
        char c0[300], c1[300], dbs[3][300], sns[3][300], sps[3][300], dd[300], hx[4][65];
        CHECK(chain_mkblocks(rd) == 0, "repro: fixture blocks written");
        snprintf(c0, sizeof c0, "%s/blk0.bin", rd); snprintf(c1, sizeof c1, "%s/blk1.bin", rd);
        for (int k = 0; k < 3; k++) {
            snprintf(dd, sizeof dd, "%s/node%d", rd, k); mkdir(dd, 0700);
            snprintf(dbs[k], sizeof dbs[k], "%s/i.db", dd); snprintf(sns[k], sizeof sns[k], "%s/snap", dd);
            snprintf(sps[k], sizeof sps[k], "%s/state.db", sns[k]);
        }
        // A: one process, both blocks in one batch
        CHECK(child(NULL, 6, "x", "index", dbs[0], "0", c0, c1) == 0, "repro A: one-shot fold");
        // B: two processes, one block each (different batching / run order)
        CHECK(child(NULL, 5, "x", "index", dbs[1], "0", c0) == 0 &&
              child(NULL, 5, "x", "index", dbs[1], "0", c1) == 0, "repro B: block-by-block fold in two processes");
        // C: SIGKILL at height 1 before the projection, then recover + resume
        int cst = child("1", 6, "x", "index", dbs[2], "0", c0, c1);
        CHECK(WIFSIGNALED(cst), "repro C: first run killed mid-fold");
        CHECK(child(NULL, 6, "x", "index", dbs[2], "0", c0, c1) == 0, "repro C: recovered and resumed");
        int eok = 1;
        for (int k = 0; k < 3; k++) eok &= child(NULL, 5, "x", "snapshot-export", "regtest", dbs[k], sns[k]) == 0;
        CHECK(eok, "repro: all three exports ok");
        int hok = 1; for (int k = 0; k < 3; k++) hok &= file_sha(sps[k], hx[k]);
        CHECK(hok && !strcmp(hx[0], hx[1]), "repro: A and B state.db sha256 identical");
        CHECK(hok && !strcmp(hx[0], hx[2]), "repro: A and crash/resumed C state.db sha256 identical");
        // pinning A's hash verifies B's and C's snapshots
        CHECK(run(6, "x", "snapshot-verify", "regtest", sns[1], "--sha256", hx[0]) == 0 &&
              run(6, "x", "snapshot-verify", "regtest", sns[2], "--sha256", hx[0]) == 0,
              "repro: one pin verifies every build's snapshot");
        // re-export of the same db (after another reader) is byte-identical too
        char s3[300], p3[300]; snprintf(s3, sizeof s3, "%s/again", rd); snprintf(p3, sizeof p3, "%s/state.db", s3);
        CHECK(child(NULL, 5, "x", "snapshot-export", "regtest", dbs[1], s3) == 0 && file_sha(p3, hx[3]) && !strcmp(hx[3], hx[0]),
              "repro: a second export is byte-identical");
        // the scratch file does not linger
        char tmpf[340]; snprintf(tmpf, sizeof tmpf, "%s/.state.db.canon", sns[0]);
        CHECK(access(tmpf, F_OK) != 0, "repro: canonicalisation scratch db removed");
        // idx-07: node-local tables (peers, watch, utxos) ship empty
        {
            char d4[300], db4[300], s4[300], p4[300], h4[65], imp[300];
            snprintf(d4, sizeof d4, "%s/node3", rd); mkdir(d4, 0700);
            snprintf(db4, sizeof db4, "%s/i.db", d4); snprintf(s4, sizeof s4, "%s/snap", d4);
            snprintf(p4, sizeof p4, "%s/state.db", s4); snprintf(imp, sizeof imp, "%s/imported.db", d4);
            CHECK(child(NULL, 6, "x", "index", db4, "0", c0, c1) == 0, "idx-07: fourth build folded");
            sqlite3 *x = NULL; int ok7 = sqlite3_open(db4, &x) == SQLITE_OK &&
                sqlite3_exec(x, "INSERT INTO peers(addr,services,last_seen,last_good,agent) VALUES('10.9.8.7:33874',1,1761500000,1761500000,'/x/');"
                                "INSERT INTO peers(addr,services,last_seen) VALUES('[2001:db8::1]:22556',5,1761400000);"
                                "INSERT INTO watch(h160) VALUES(x'00112233445566778899aabbccddeeff00112233');"
                                "INSERT INTO utxos VALUES(x'aa', 0, x'00112233445566778899aabbccddeeff00112233', 5000, 1, NULL);",
                             NULL, NULL, NULL) == SQLITE_OK;
            sqlite3_close(x);
            CHECK(ok7, "idx-07: node-local rows added (peers, watch, utxos)");
            CHECK(child(NULL, 5, "x", "snapshot-export", "regtest", db4, s4) == 0 && file_sha(p4, h4) && !strcmp(h4, hx[0]),
                  "idx-07: dbs differing only in peers/watch/utxos export the same sha256");
            sqlite3 *y = NULL; long long n = -1, nt = 0;
            if (sqlite3_open_v2(p4, &y, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                sqlite3_stmt *q = NULL;
                if (sqlite3_prepare_v2(y, "SELECT (SELECT count(*) FROM peers)+(SELECT count(*) FROM watch)+(SELECT count(*) FROM utxos),"
                                          " (SELECT count(*) FROM sqlite_master WHERE name IN ('peers','watch','utxos'))", -1, &q, NULL) == SQLITE_OK
                    && sqlite3_step(q) == SQLITE_ROW) { n = sqlite3_column_int64(q, 0); nt = sqlite3_column_int64(q, 1); }
                sqlite3_finalize(q); sqlite3_close(y);
            }
            CHECK(n == 0, "idx-07: peers/watch/utxos have zero rows in the snapshot");
            CHECK(nt == 3, "idx-07: ...and their schema is kept");
            CHECK(run(6, "x", "snapshot-verify", "regtest", s4, "--sha256", hx[0]) == 0, "idx-07: verify OK with empty node-local tables");
            CHECK(child(NULL, 7, "x", "snapshot-import", "regtest", s4, imp, "--sha256", hx[0]) == 0, "idx-07: import OK with empty node-local tables");
            CHECK(child(NULL, 3, "x", "check", imp) == 0, "idx-07: imported db passes check");
            CHECK(child(NULL, 4, "x", "watch", imp, "00112233445566778899aabbccddeeff00112233") == 0,
                  "idx-07: a wallet watch can be registered on the imported db");
            // idx-10: refold refuses when referenced heights are missing from raw_blocks
            {
                char rf[300], lg[300], c2[800];
                snprintf(rf, sizeof rf, "%s/rf.db", d4); snprintf(lg, sizeof lg, "%s/rflog", d4);
                #define RFQ(sql) ({ long long _v = -1; sqlite3 *_x = NULL; sqlite3_stmt *_q = NULL; \
                    if (sqlite3_open(rf, &_x) == SQLITE_OK && sqlite3_prepare_v2(_x, sql, -1, &_q, NULL) == SQLITE_OK && \
                        sqlite3_step(_q) == SQLITE_ROW) _v = sqlite3_column_int64(_q, 0); \
                    sqlite3_finalize(_q); sqlite3_close(_x); _v; })
                #define RFX(sql) ({ sqlite3 *_x = NULL; int _r = sqlite3_open(rf, &_x) == SQLITE_OK && \
                    sqlite3_exec(_x, sql, NULL, NULL, NULL) == SQLITE_OK; sqlite3_close(_x); _r; })
                snprintf(c2, sizeof c2, "rm -f '%s'* && cp '%s' '%s'", rf, db4, rf);
                CHECK(system(c2) == 0 && childlog(lg, 3, "x", "refold", rf) == 0 && !file_has(lg, "REFUSED"),
                      "idx-10: refold of a complete db succeeds");
                CHECK(RFX("INSERT INTO epochs(name,start_height,owner,owner_type) VALUES('zz-lapse',777,NULL,0)") &&
                      childlog(lg, 3, "x", "refold", rf) == 0, "idx-10: a lapse epoch at a non-carrier height does not trip the guard");
                CHECK(RFX("INSERT INTO commits(commitment,commit_height,tx_index,commit_time) VALUES(x'00',1227333,0,-30000)") &&
                      childlog(lg, 3, "x", "refold", rf) == 0 && !file_has(lg, "REFUSED"),
                      "idx-10: an expired commit at a missing height does not trip the guard");
                long long ep = RFQ("SELECT count(*) FROM epochs WHERE owner IS NOT NULL"), mu = RFQ("SELECT count(*) FROM muts");
                long long hgt = RFQ("SELECT height FROM raw_blocks ORDER BY height DESC LIMIT 1");
                CHECK(ep > 0 && hgt >= 0 && RFX("DELETE FROM raw_blocks WHERE height=(SELECT max(start_height) FROM epochs WHERE owner IS NOT NULL)"),
                      "idx-10: drop the raw block an owned epoch points at");
                CHECK(childlog(lg, 3, "x", "refold", rf) != 0 && file_has(lg, "REFUSED") && file_has(lg, "missing from raw_blocks"),
                      "idx-10: refold REFUSES (non-zero, clear message) on a missing referenced height");
                CHECK(RFQ("SELECT count(*) FROM epochs WHERE owner IS NOT NULL") == ep && RFQ("SELECT count(*) FROM muts") == mu,
                      "idx-10: ...and changes nothing");
                CHECK(childlog(lg, 4, "x", "refold", rf, "--force") == 0 && file_has(lg, "WARNING (--force)"),
                      "idx-10: refold --force proceeds with a warning");
                CHECK(RFQ("SELECT count(*) FROM epochs WHERE owner IS NOT NULL") < ep,
                      "idx-10: ...and the forced state is smaller (what the guard prevents by default)");
                snprintf(c2, sizeof c2, "rm -f '%s'* && cp '%s' '%s'", rf, db4, rf);
                CHECK(system(c2) == 0 && RFX("DELETE FROM raw_blocks WHERE height=(SELECT min(commit_height) FROM commits)") &&
                      childlog(lg, 3, "x", "refold", rf) != 0 && file_has(lg, "REFUSED"), "idx-10: a missing commit height is refused too");
                #undef RFQ
                #undef RFX
            }
            // idx-10: coin-less commands never guess pep (mainnet: an old doge db with no
            // onchain_magic was refolded under 'PN' and lost its DN names)
            {
                char dd[300], live[300], old[300], lg[300], c2[1200], b0[320], b1[320];
                static const uint8_t DN[2] = { 0x44, 0x4E };
                snprintf(dd, sizeof dd, "%s/dn", d4); mkdir(dd, 0700);
                snprintf(live, sizeof live, "%s/live.db", dd); snprintf(old, sizeof old, "%s/old.db", dd);
                snprintf(lg, sizeof lg, "%s/log", dd);
                snprintf(b0, sizeof b0, "%s/blk0.bin", dd); snprintf(b1, sizeof b1, "%s/blk1.bin", dd);
                #define MQ(path, sql) ({ long long _v = -1; sqlite3 *_x = NULL; sqlite3_stmt *_q = NULL; \
                    if (sqlite3_open(path, &_x) == SQLITE_OK && sqlite3_prepare_v2(_x, sql, -1, &_q, NULL) == SQLITE_OK && \
                        sqlite3_step(_q) == SQLITE_ROW) _v = sqlite3_column_int64(_q, 0); \
                    sqlite3_finalize(_q); sqlite3_close(_x); _v; })
                #define MX(path, sql) ({ sqlite3 *_x = NULL; int _r = sqlite3_open(path, &_x) == SQLITE_OK && \
                    sqlite3_exec(_x, sql, NULL, NULL, NULL) == SQLITE_OK; sqlite3_close(_x); _r; })
                #define FRESH_OLD() (snprintf(c2, sizeof c2, "rm -f '%s'* && cp '%s' '%s'", old, live, old), system(c2) == 0)
                // names as one comparable number: count + a hash over (name, owner)
                #define NAMESIG(path) MQ(path, "SELECT count(*)*1000003 + coalesce(sum(length(name)*7 + unicode(hex(owner))),0) FROM names WHERE st IS NOT NULL")
                CHECK(chain_mkblocks_mag(dd, DN) == 0 &&
                      childlog(lg, 7, "x", "index", live, "0", b0, b1, "--coin") != 0,
                      "idx-10: index --coin without a name is rejected");
                CHECK(childlog(lg, 8, "x", "index", live, "0", b0, b1, "--coin", "doge") == 0 &&
                      MQ(live, "SELECT count(*) FROM names WHERE name='alice'") == 1 &&
                      MQ(live, "SELECT count(*) FROM meta WHERE k='onchain_magic' AND v='444e'") == 1,
                      "idx-10: DN fixture indexed with --coin doge: alice registered, magic DN stored");
                long long sig = NAMESIG(live);
                CHECK(FRESH_OLD() && MX(old, "DELETE FROM meta WHERE k='onchain_magic'") &&
                      childlog(lg, 5, "x", "refold", old, "--coin", "doge") == 0 && NAMESIG(old) == sig &&
                      MQ(old, "SELECT count(*) FROM names WHERE name='alice'") == 1,
                      "idx-10: old-style doge db (no magic) refolds with --coin doge to the same names as live");
                CHECK(MQ(old, "SELECT count(*) FROM meta WHERE k='onchain_magic' AND v='444e'") == 1,
                      "idx-10: ...and an explicit coin is persisted");
                snprintf(c2, sizeof c2, "rm -rf '%s/ix' && mkdir '%s/ix'", dd, dd);
                { char ix[340]; snprintf(ix, sizeof ix, "%s/ix/i.db", dd);
                  CHECK(system(c2) == 0 && childlog(lg, 8, "x", "index", ix, "0", b0, b1, "--coin", "doge") == 0 && NAMESIG(ix) == sig,
                        "idx-10: a fresh offline index of the DN blocks gives the same names"); }
                // no magic, doge activation pin -> inferred DN, never persisted
                CHECK(FRESH_OLD() && MX(old, "DELETE FROM meta WHERE k='onchain_magic'; UPDATE meta SET v='6429500' WHERE k='activation'") &&
                      childlog(lg, 3, "x", "refold", old) == 0 && file_has(lg, "inferred from doge pins") &&
                      MQ(old, "SELECT count(*) FROM meta WHERE k='onchain_magic'") == 0,
                      "idx-10: no magic + doge activation: refold infers DN and does not write a guessed magic");
                CHECK(childlog(lg, 3, "x", "digest", old) == 0 && file_has(lg, "inferred from doge pins"),
                      "idx-10: digest infers DN the same way");
                // the poisoned mainnet db: doge activation but magic 'PN' written by the old refold
                CHECK(FRESH_OLD() && MX(old, "UPDATE meta SET v='504e' WHERE k='onchain_magic'; UPDATE meta SET v='6429500' WHERE k='activation'") &&
                      childlog(lg, 3, "x", "refold", old) != 0 && file_has(lg, "REFUSED") && file_has(lg, "contradicts") &&
                      MQ(old, "SELECT count(*) FROM meta WHERE k='onchain_magic' AND v='504e'") == 1,
                      "idx-10: doge-pinned db carrying 'PN' is refused without --coin, unchanged");
                CHECK(childlog(lg, 5, "x", "refold", old, "--coin", "doge") == 0 &&
                      MQ(old, "SELECT count(*) FROM meta WHERE k='onchain_magic' AND v='444e'") == 1,
                      "idx-10: ...and repaired by refold --coin doge");
                CHECK(FRESH_OLD() && MX(old, "UPDATE meta SET v='504e' WHERE k='onchain_magic'") &&
                      childlog(lg, 4, "x", "digest", old, "--coin") != 0 &&
                      childlog(lg, 5, "x", "digest", old, "--coin", "doge") != 0 && file_has(lg, "does not match coin doge"),
                      "idx-10: read-only commands refuse a coin/magic mismatch");
                // unknown pins, no magic -> refuse, nothing changed
                CHECK(FRESH_OLD() && MX(old, "DELETE FROM meta WHERE k='onchain_magic'; UPDATE meta SET v='12345' WHERE k='activation'") &&
                      childlog(lg, 3, "x", "refold", old) != 0 && file_has(lg, "REFUSED") && file_has(lg, "--coin") &&
                      MQ(old, "SELECT count(*) FROM names WHERE name='alice'") == 1,
                      "idx-10: no magic + unknown pins: refused with a clear error, nothing changed");
                CHECK(childlog(lg, 3, "x", "digest", old) != 0 && file_has(lg, "REFUSED"),
                      "idx-10: digest refuses too (never falls back to pep)");
                #undef MQ
                #undef MX
                #undef FRESH_OLD
                #undef NAMESIG
            }
            // idx-09: MANIFEST sqlite_version — logged, warned on, never refused on
            {
                char mf[400], want[100], lg[400], sd[300], im[300];
                snprintf(mf, sizeof mf, "%s/MANIFEST", s4); snprintf(lg, sizeof lg, "%s/log", d4);
                snprintf(want, sizeof want, "\nsqlite_version %s\n", sqlite3_libversion());
                CHECK(file_has(mf, want), "idx-09: MANIFEST carries sqlite_version = the exporter's runtime sqlite");
                CHECK(childlog(lg, 6, "x", "snapshot-verify", "regtest", s4, "--sha256", hx[0]) == 0 &&
                      file_has(lg, "matches this node") && !file_has(lg, "WARNING"), "idx-09: match: verify OK, logs the match, no warning");
                snprintf(im, sizeof im, "%s/imp-match.db", d4);
                CHECK(childlog(lg, 7, "x", "snapshot-import", "regtest", s4, im, "--sha256", hx[0]) == 0 &&
                      file_has(lg, "matches this node"), "idx-09: match: import applies and logs it");
                const char *cases[2][2] = { { "mism", "sed -i 's/^sqlite_version .*/sqlite_version 0.0.0-other/'" },
                                            { "miss", "sed -i '/^sqlite_version /d'" } };
                for (int k = 0; k < 2; k++) {
                    int mis = k == 0; char c2[1200], h5[65], m[160];
                    snprintf(sd, sizeof sd, "%s/snap-%s", d4, cases[k][0]);
                    snprintf(c2, sizeof c2, "cp -r '%s' '%s' && %s '%s/MANIFEST'", s4, sd, cases[k][1], sd);
                    int okc = system(c2) == 0; snprintf(mf, sizeof mf, "%s/state.db", sd);
                    snprintf(m, sizeof m, "idx-09: %s: state.db sha256 still = pin", mis ? "mismatch" : "missing key");
                    CHECK(okc && file_sha(mf, h5) && !strcmp(h5, hx[0]), m);
                    const char *needle = mis ? "WARNING: snapshot exported with sqlite 0.0.0-other" : "has no sqlite_version";
                    snprintf(m, sizeof m, "idx-09: %s: verify OK with the correct pin and logs it", mis ? "mismatch (warns)" : "missing key (accepted)");
                    CHECK(childlog(lg, 6, "x", "snapshot-verify", "regtest", sd, "--sha256", hx[0]) == 0 && file_has(lg, needle), m);
                    snprintf(im, sizeof im, "%s/imp-%s.db", d4, cases[k][0]);
                    snprintf(m, sizeof m, "idx-09: %s: import applies with the correct pin and logs it", mis ? "mismatch (warns)" : "missing key (accepted)");
                    CHECK(childlog(lg, 7, "x", "snapshot-import", "regtest", sd, im, "--sha256", hx[0]) == 0 && file_has(lg, needle) &&
                          access(im, F_OK) == 0, m);
                    snprintf(m, sizeof m, "idx-09: %s: a wrong pin is still refused", mis ? "mismatch" : "missing key");
                    snprintf(im, sizeof im, "%s/imp-%s-bad.db", d4, cases[k][0]);
                    CHECK(childlog(lg, 7, "x", "snapshot-import", "regtest", sd, im, "--sha256",
                                   "0000000000000000000000000000000000000000000000000000000000000000") != 0 && access(im, F_OK) != 0, m);
                }
            }
            // idx-11: onchain_magic is node-local: the export omits it, import re-stamps it
            {
                char d5[300], db5[300], s5[300], p5[300], h5[65], im5[300], c5[1200], lg5[300], m4[300], m5[300];
                snprintf(d5, sizeof d5, "%s/node5", rd); mkdir(d5, 0700);
                snprintf(db5, sizeof db5, "%s/i.db", d5); snprintf(s5, sizeof s5, "%s/snap", d5);
                snprintf(p5, sizeof p5, "%s/state.db", s5); snprintf(im5, sizeof im5, "%s/imp.db", d5);
                snprintf(lg5, sizeof lg5, "%s/log", d5);
                snprintf(m4, sizeof m4, "%s/MANIFEST", s4); snprintf(m5, sizeof m5, "%s/MANIFEST", s5);
                #define MQ5(path, sql) ({ long long _v = -1; sqlite3 *_x = NULL; sqlite3_stmt *_q = NULL; \
                    if (sqlite3_open(path, &_x) == SQLITE_OK && sqlite3_prepare_v2(_x, sql, -1, &_q, NULL) == SQLITE_OK && \
                        sqlite3_step(_q) == SQLITE_ROW) _v = sqlite3_column_int64(_q, 0); \
                    sqlite3_finalize(_q); sqlite3_close(_x); _v; })
                // db5 = dbs[1] (no stored magic) + meta onchain_magic='504e' (regtest's PN), nothing else
                snprintf(c5, sizeof c5, "cp '%s' '%s'", dbs[1], db5);
                sqlite3 *x5 = NULL;
                int ok5 = system(c5) == 0 && MQ5(db5, "SELECT count(*) FROM meta WHERE k='onchain_magic'") == 0 &&
                          sqlite3_open(db5, &x5) == SQLITE_OK &&
                          sqlite3_exec(x5, "INSERT INTO meta(k,v) VALUES('onchain_magic','504e')", NULL, NULL, NULL) == SQLITE_OK;
                sqlite3_close(x5);
                CHECK(ok5 && MQ5(db5, "SELECT count(*) FROM meta WHERE k='onchain_magic' AND v='504e'") == 1,
                      "idx-11: two dbs differing only in meta onchain_magic (absent vs 504e)");
                CHECK(child(NULL, 5, "x", "snapshot-export", "regtest", db5, s5) == 0 && file_sha(p5, h5) && !strcmp(h5, hx[0]),
                      "idx-11: ...export the same state.db sha256");
                char d4s[80] = "", d5s[80] = "", e4s[80] = "", e5s[80] = "";
                mf_field(m4, "state_digest", d4s); mf_field(m5, "state_digest", d5s);
                mf_field(m4, "state_ecmh", e4s);   mf_field(m5, "state_ecmh", e5s);
                CHECK(*d4s && !strcmp(d4s, d5s) && *e4s && !strcmp(e4s, e5s),
                      "idx-11: ...and the same state_digest/state_ecmh (magic was never digested)");
                CHECK(MQ5(p5, "SELECT count(*) FROM meta WHERE k='onchain_magic'") == 0,
                      "idx-11: the exported state.db carries no onchain_magic row");
                CHECK(childlog(lg5, 7, "x", "snapshot-import", "regtest", s5, im5, "--sha256", hx[0]) == 0 &&
                      MQ5(im5, "SELECT count(*) FROM meta WHERE k='onchain_magic' AND v='504e'") == 1,
                      "idx-11: import re-stamps the importing coin's magic (regtest -> 504e)");
                char im6[300]; snprintf(im6, sizeof im6, "%s/imp-from-unstamped.db", d5);
                CHECK(child(NULL, 7, "x", "snapshot-import", "regtest", s4, im6, "--sha256", hx[0]) == 0 &&
                      MQ5(im6, "SELECT count(*) FROM meta WHERE k='onchain_magic' AND v='504e'") == 1 &&
                      child(NULL, 3, "x", "check", im6) == 0,
                      "idx-11: import of a snapshot from an unstamped db is stamped too, and passes check");
                CHECK(run(6, "x", "snapshot-verify", "regtest", s5, "--sha256", hx[0]) == 0,
                      "idx-11: verify OK on the magic-less export");
                #undef MQ5
            }
            // idx-12: refold prunes expired commits and records lapses at the EXACT
            // live heights (every blocks row gets its preblock, not just carriers)
            {
                static const uint8_t PN[2] = { 0x50, 0x4E };
                char d6[300], lv[300], rf6[300], sl[300], sr[300], ml[300], mr[300], lg6[300], c6[1200];
                char hl[65] = "", hr[65] = "";
                snprintf(d6, sizeof d6, "%s/exp", rd); mkdir(d6, 0700);
                snprintf(lv, sizeof lv, "%s/live.db", d6); snprintf(rf6, sizeof rf6, "%s/refold.db", d6);
                snprintf(sl, sizeof sl, "%s/snapL", d6); snprintf(sr, sizeof sr, "%s/snapR", d6);
                snprintf(ml, sizeof ml, "%s/MANIFEST", sl); snprintf(mr, sizeof mr, "%s/MANIFEST", sr);
                snprintf(lg6, sizeof lg6, "%s/log", d6);
                #define MQ6(path, sql) ({ long long _v = -1; sqlite3 *_x = NULL; sqlite3_stmt *_q = NULL; \
                    if (sqlite3_open(path, &_x) == SQLITE_OK && sqlite3_prepare_v2(_x, sql, -1, &_q, NULL) == SQLITE_OK && \
                        sqlite3_step(_q) == SQLITE_ROW) _v = sqlite3_column_int64(_q, 0); \
                    sqlite3_finalize(_q); sqlite3_close(_x); _v; })
                #define MS6(path, sql, out) do { sqlite3 *_x = NULL; sqlite3_stmt *_q = NULL; (out)[0] = 0; \
                    if (sqlite3_open(path, &_x) == SQLITE_OK && sqlite3_prepare_v2(_x, sql, -1, &_q, NULL) == SQLITE_OK && \
                        sqlite3_step(_q) == SQLITE_ROW && sqlite3_column_text(_q, 0)) \
                        snprintf(out, sizeof(out), "%s", (const char *)sqlite3_column_text(_q, 0)); \
                    sqlite3_finalize(_q); sqlite3_close(_x); } while (0)
                const char *av[64]; int ac = 0;
                av[ac++] = "x"; av[ac++] = "index"; av[ac++] = lv; av[ac++] = "0";
                static char ef[48][320];
                for (int i = 0; i < 48; i++) { snprintf(ef[i], sizeof ef[i], "%s/e%02d.bin", d6, i); av[ac++] = ef[i]; }
                av[ac++] = "--coin"; av[ac++] = "regtest"; av[ac] = NULL;
                CHECK(chain_mkblocks_expiry(d6, PN) == 0, "idx-12: expiry/lapse fixture written (48 blocks, 4 carriers)");
                fflush(stdout); pid_t pid = fork();
                if (pid == 0) { int fd = open(lg6, O_WRONLY|O_CREAT|O_TRUNC, 0600); if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); close(fd); }
                                 _exit(indexer_main(ac, (char **)av)); }
                int stt = 0; waitpid(pid, &stt, 0);
                CHECK(WIFEXITED(stt) && WEXITSTATUS(stt) == 0, "idx-12: live fold (index, connect_block per block) succeeded");
                CHECK(MQ6(lv, "SELECT count(*) FROM raw_blocks") == 4 && MQ6(lv, "SELECT count(*) FROM blocks") == 48,
                      "idx-12: only the 4 carrier blocks keep raw bytes");
                CHECK(MQ6(lv, "SELECT count(*) FROM commits") == 0,
                      "idx-12: live: bob's and carol's commits expired (no carrier after carol's expiry)");
                long long lap = MQ6(lv, "SELECT start_height FROM epochs WHERE name='alice' AND owner IS NULL");
                CHECK(lap > 1 && MQ6(lv, "SELECT count(*) FROM raw_blocks WHERE height=(SELECT start_height FROM epochs WHERE name='alice' AND owner IS NULL)") == 0,
                      "idx-12: live: alice's lease lapsed on a NON-carrier block");
                snprintf(c6, sizeof c6, "cp '%s' '%s'", lv, rf6);
                CHECK(system(c6) == 0 && childlog(lg6, 3, "x", "refold", rf6) == 0, "idx-12: refold succeeds (lapse mut height does not trip the guard)");
                CHECK(MQ6(rf6, "SELECT count(*) FROM commits") == 0, "idx-12: refold prunes the expired commits too");
                CHECK(MQ6(rf6, "SELECT start_height FROM epochs WHERE name='alice' AND owner IS NULL") == lap,
                      "idx-12: refold records the lapse epoch at the exact live height");
                char el[4096], er[4096];
                MS6(lv, "SELECT group_concat(name||':'||start_height||':'||coalesce(hex(owner),'-'),',') FROM (SELECT * FROM epochs ORDER BY name,start_height)", el);
                MS6(rf6, "SELECT group_concat(name||':'||start_height||':'||coalesce(hex(owner),'-'),',') FROM (SELECT * FROM epochs ORDER BY name,start_height)", er);
                CHECK(*el && !strcmp(el, er), "idx-12: epochs table identical after refold");
                MS6(lv, "SELECT group_concat(hex(owner)||':'||height,',') FROM muts", el);
                MS6(rf6, "SELECT group_concat(hex(owner)||':'||height,',') FROM muts", er);
                CHECK(!strcmp(el, er), "idx-12: muts (lapse-stamped mutation heights) identical after refold");
                CHECK(child(NULL, 5, "x", "snapshot-export", "regtest", lv, sl) == 0 &&
                      child(NULL, 5, "x", "snapshot-export", "regtest", rf6, sr) == 0, "idx-12: both dbs export");
                { char p6l[340], p6r[340]; snprintf(p6l, sizeof p6l, "%s/state.db", sl); snprintf(p6r, sizeof p6r, "%s/state.db", sr);
                  CHECK(file_sha(p6l, hl) && file_sha(p6r, hr) && !strcmp(hl, hr), "idx-12: live and refold give the same canonical export sha256"); }
                char dl[80] = "", dr[80] = "", xl[80] = "", xr[80] = "";
                mf_field(ml, "state_digest", dl); mf_field(mr, "state_digest", dr);
                mf_field(ml, "state_ecmh", xl);   mf_field(mr, "state_ecmh", xr);
                CHECK(*dl && !strcmp(dl, dr), "idx-12: ...the same state_digest");
                CHECK(*xl && !strcmp(xl, xr), "idx-12: ...and the same state_ecmh");
                #undef MQ6
                #undef MS6
                r13_all(d6, PN);
            }
        }
        printf("  info pin %s\n", hx[0]);
        snprintf(cmd, sizeof cmd, "rm -rf '%s'", rd); if (system(cmd)) {}
    }
    printf(g_fail ? "\ntest_snapshot: %d FAILED\n" : "\ntest_snapshot: ALL PASSED\n", g_fail);
    return g_fail ? 1 : 0;
}
