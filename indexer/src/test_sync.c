// test_sync.c — rollback / refold at the seam that produced the ghost-UTXO bug.
//
// PROVES, on a synthetic but REAL-FORMAT chain (signed Dogecoin txs, real
// blocks) folded through the PRODUCTION path — `indexer_main("index", …)` →
// cmd_index → connect_block → tx_cb — into a sqlite db in a mkdtemp'd /tmp
// directory (removed at the end; never ~/.pepenet):
//
//   7. ROLLBACK/REFOLD AT THE SEAM. The chain is built so a wallet-touching
//      SPEND lands in a NON-CARRIER block while the FUNDING sits in a carrier
//      block — exactly the shape that inflated a live wallet to
//      167,591.40528856 PEP. Asserts (a) the replay substrate now stores the
//      wallet-touching block (raw_blocks == {carrier, wallet-spend}), and
//      (b) rolling back — to the tip, to between the funding and the spend, and
//      to below the funding — and refolding always converges on the TRUE
//      balance, never the inflated one. This is the acceptance test for the fix.
//   8. BOUNDARY ROLLBACKS: to the exact start height, to a height above the tip,
//      to 0, to -1, and to INT64_MIN/2 — each returns sanely, leaves the db
//      queryable and self-consistent, and never crashes or corrupts.
//   9. THE wallet_rewalk_v1 ONE-SHOT: runs once and only once. After a
//      successful re-walk the flag is set; when idx_sync_rollback FAILS the flag
//      stays UNSET so the next pass retries. The decision block below is a
//      verbatim mirror of cmd_sync's (src/sync.c:941-957) over the same public
//      helpers — cmd_sync itself is static and needs a socket.
//
// No floating point: all money is int64 koinu.
#include "sm.h"
#include "chain.h"
#include "db.h"
#include "indexer.h"
#include "oracle_feed.h"
#include "sha256.h"
#include "ripemd160.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include "dbcheck.h"

int secp_pubkey(const uint8_t priv[32], uint8_t pub33[33]);
int secp_ecdsa_sign(const uint8_t priv[32], const uint8_t h[32], uint8_t r32[32], uint8_t s32[32]);

static int g_fail;
#define CHECK(cond, name) do { \
    if (cond) printf("ok   %s\n", name); \
    else      { printf("FAIL %s\n", name); g_fail = 1; } \
} while (0)

// ── the incident's numbers, in koinu ─────────────────────────────────────────
#define FUND_VALUE   6872579102400LL      // 68,725.79102400 PEP — the resurrected output
#define ACTIVATION   2LL

// ── byte emitters (same shape as test_chain.c's) ─────────────────────────────
static void p(uint8_t *b, int *l, const uint8_t *d, int n) { memcpy(b + *l, d, (size_t)n); *l += n; }
static void p1(uint8_t *b, int *l, int v) { b[(*l)++] = (uint8_t)v; }
static void pu32(uint8_t *b, int *l, uint32_t v) { for (int i = 0; i < 4; i++) p1(b, l, (int)((v >> (8*i)) & 0xff)); }
static void pu64(uint8_t *b, int *l, uint64_t v) { for (int i = 0; i < 8; i++) p1(b, l, (int)((v >> (8*i)) & 0xff)); }
static void pvar(uint8_t *b, int *l, uint64_t v) {
    if (v < 0xFD) p1(b, l, (int)v);
    else if (v <= 0xFFFF) { p1(b, l, 0xFD); p1(b, l, (int)(v & 0xff)); p1(b, l, (int)((v >> 8) & 0xff)); }
    else { p1(b, l, 0xFE); pu32(b, l, (uint32_t)v); }
}
static void sha256_1(const uint8_t *d, size_t n, uint8_t o[32]) { SHA256_CTX c; sha256_init(&c); sha256_update(&c, d, (unsigned)n); sha256_final(&c, o); }
static void hash160(const uint8_t *d, size_t n, uint8_t o[20]) { uint8_t t[32]; sha256_1(d, n, t); ripemd160(t, 32, o); }
static void dsha(const uint8_t *d, size_t n, uint8_t o[32]) { uint8_t t[32]; sha256_1(d, n, t); sha256_1(t, 32, o); }
static int p2pkh(uint8_t *spk, const uint8_t h160[20]) {
    int l = 0; p1(spk, &l, 0x76); p1(spk, &l, 0xA9); p1(spk, &l, 0x14);
    p(spk, &l, h160, 20); p1(spk, &l, 0x88); p1(spk, &l, 0xAC); return l;
}

static int der_encode(const uint8_t r[32], const uint8_t s[32], uint8_t out[80]) {
    int ri = 0; while (ri < 31 && r[ri] == 0) ri++; int rl = 32 - ri; const uint8_t *R = r + ri;
    int si = 0; while (si < 31 && s[si] == 0) si++; int sl = 32 - si; const uint8_t *S = s + si;
    int rpad = (R[0] & 0x80) ? 1 : 0, spad = (S[0] & 0x80) ? 1 : 0;
    int o = 0; out[o++] = 0x30; out[o++] = (uint8_t)(2 + rl + rpad + 2 + sl + spad);
    out[o++] = 0x02; out[o++] = (uint8_t)(rl + rpad); if (rpad) out[o++] = 0x00; memcpy(out + o, R, (size_t)rl); o += rl;
    out[o++] = 0x02; out[o++] = (uint8_t)(sl + spad); if (spad) out[o++] = 0x00; memcpy(out + o, S, (size_t)sl); o += sl;
    out[o++] = 0x01;
    return o;
}

// A CARRIER tx: output 0 = OP_RETURN(action) [the §1 carrier the fold consumes],
// output 1 = a P2PKH payment of `pay_val` to `pay_h160`. Signed for real so §4
// attribution recovers the signer and the action actually folds.
static int build_carrier_tx(const uint8_t priv[32], const uint8_t pub33[33], const uint8_t h160[20],
                            const uint8_t *action, int alen,
                            const uint8_t *pay_h160, uint64_t pay_val,
                            const uint8_t prev_txid[32], uint32_t prev_vout,
                            uint8_t *out, int *out_len) {
    uint8_t spk0[100]; int spk0l = 0; p1(spk0, &spk0l, 0x6A);
    if (alen < 76) p1(spk0, &spk0l, alen); else { p1(spk0, &spk0l, 0x4C); p1(spk0, &spk0l, alen); }
    p(spk0, &spk0l, action, alen);
    uint8_t spk1[25]; int spk1l = p2pkh(spk1, pay_h160);
    uint8_t sc[25];   int scl   = p2pkh(sc, h160);

    uint8_t b[1024]; int l = 0;
    pu32(b, &l, 1); pvar(b, &l, 1);
    p(b, &l, prev_txid, 32); pu32(b, &l, prev_vout);
    pvar(b, &l, (uint64_t)scl); p(b, &l, sc, scl);
    pu32(b, &l, 0xFFFFFFFF);
    pvar(b, &l, 2);
    pu64(b, &l, 0); pvar(b, &l, (uint64_t)spk0l); p(b, &l, spk0, spk0l);
    pu64(b, &l, pay_val); pvar(b, &l, (uint64_t)spk1l); p(b, &l, spk1, spk1l);
    pu32(b, &l, 0); pu32(b, &l, 1);
    uint8_t sighash[32]; dsha(b, l, sighash);

    uint8_t r[32], s[32]; if (!secp_ecdsa_sign(priv, sighash, r, s)) return 0;
    uint8_t der[80]; int derl = der_encode(r, s, der);
    uint8_t ss[200]; int ssl = 0; p1(ss, &ssl, derl); p(ss, &ssl, der, derl); p1(ss, &ssl, 33); p(ss, &ssl, pub33, 33);

    int o = 0;
    pu32(out, &o, 1); pvar(out, &o, 1);
    p(out, &o, prev_txid, 32); pu32(out, &o, prev_vout);
    pvar(out, &o, (uint64_t)ssl); p(out, &o, ss, ssl);
    pu32(out, &o, 0xFFFFFFFF);
    pvar(out, &o, 2);
    pu64(out, &o, 0); pvar(out, &o, (uint64_t)spk0l); p(out, &o, spk0, spk0l);
    pu64(out, &o, pay_val); pvar(out, &o, (uint64_t)spk1l); p(out, &o, spk1, spk1l);
    pu32(out, &o, 0);
    *out_len = o;
    return 1;
}

// A PLAIN (non-carrier) tx: one input, one P2PKH output. No OP_RETURN, so the
// fold never counts it — the block carrying it reaches the replay substrate
// only via the WALLET rule.
static void build_plain_tx(const uint8_t prev_txid[32], uint32_t prev_vout,
                           const uint8_t pay_h160[20], uint64_t pay_val,
                           uint8_t tag, uint8_t *out, int *out_len) {
    uint8_t spk[25]; int spkl = p2pkh(spk, pay_h160);
    uint8_t ss[3] = { 0x02, tag, 0x5A };          // push 2 bytes: push-only, unique per tx
    int o = 0;
    pu32(out, &o, 1); pvar(out, &o, 1);
    p(out, &o, prev_txid, 32); pu32(out, &o, prev_vout);
    pvar(out, &o, 3); p(out, &o, ss, 3);
    pu32(out, &o, 0xFFFFFFFF);
    pvar(out, &o, 1);
    pu64(out, &o, pay_val); pvar(out, &o, (uint64_t)spkl); p(out, &o, spk, spkl);
    pu32(out, &o, 0);
    *out_len = o;
}

static void build_block(const uint8_t *tx, int txlen, uint32_t time, uint8_t *out, int *out_len) {
    int o = 0;
    pu32(out, &o, 1);                                  // version (no 0x100 → no AuxPoW)
    memset(out + o, 0, 32); o += 32;                   // prev
    memset(out + o, 0, 32); o += 32;                   // merkle
    pu32(out, &o, time);
    pu32(out, &o, 0x1e0ffff0);                         // bits
    pu32(out, &o, time);                               // nonce — keeps block hashes distinct
    pvar(out, &o, 1);
    p(out, &o, tx, txlen);
    *out_len = o;
}

static int write_file(const char *path, const uint8_t *b, int n) {
    FILE *f = fopen(path, "wb"); if (!f) return 0;
    size_t w = fwrite(b, 1, (size_t)n, f); fclose(f); return w == (size_t)n;
}

// ── the synthetic chain ──────────────────────────────────────────────────────
// h0 filler · h1 filler · h2 CARRIER + funds the wallet · h3 filler ·
// h4 NON-CARRIER spend of the wallet output · h5 filler
#define NBLK 6
#define H_FUND  2
#define H_SPEND 4
static char g_blk[NBLK][600];          // block file paths
static uint8_t g_wallet[20];           // watched hash160
static uint8_t g_fund_txid[32];

static void make_chain_files(const char *dir) {
    uint8_t priv[32]; for (int i = 0; i < 32; i++) priv[i] = (uint8_t)(i + 1);
    uint8_t pub[33]; if (!secp_pubkey(priv, pub)) { fprintf(stderr, "secp_pubkey failed\n"); exit(2); }
    uint8_t signer[20]; hash160(pub, 33, signer);
    memcpy(g_wallet, signer, 20);                        // the wallet we watch

    uint8_t stranger[20]; memset(stranger, 0x9C, 20);

    uint8_t tx[1024], blk[2048]; int txl, blkl;
    for (int i = 0; i < NBLK; i++) snprintf(g_blk[i], sizeof g_blk[0], "%s/blk%d.bin", dir, i);

    // h0, h1, h3, h5: fillers — plain txs to a stranger, nothing to fold, no
    // wallet touch. They must NEVER reach raw_blocks.
    for (int i = 0; i < NBLK; i++) {
        if (i == H_FUND || i == H_SPEND) continue;
        uint8_t prev[32]; memset(prev, (uint8_t)(0x40 + i), 32);
        build_plain_tx(prev, 0, stranger, 100000000ULL, (uint8_t)i, tx, &txl);
        build_block(tx, txl, (uint32_t)(1000 + 60 * i), blk, &blkl);
        if (!write_file(g_blk[i], blk, blkl)) { fprintf(stderr, "write %s failed\n", g_blk[i]); exit(2); }
    }

    // h2: a CARRIER block (a §1 COMMIT) that ALSO pays the wallet. Pre-fix this
    // is the only one of the two wallet blocks the substrate kept — which is
    // exactly why the replay could resurrect its output.
    uint8_t commit[36] = { 0xFF, 0x50, 0x4E, SM_OP_COMMIT };
    memset(commit + 4, 0x22, 32);
    uint8_t prevc[32]; memset(prevc, 0x11, 32);
    if (!build_carrier_tx(priv, pub, signer, commit, 36, g_wallet, (uint64_t)FUND_VALUE,
                          prevc, 0, tx, &txl)) { fprintf(stderr, "sign failed\n"); exit(2); }
    idx_sha256d(tx, (size_t)txl, g_fund_txid);
    build_block(tx, txl, (uint32_t)(1000 + 60 * H_FUND), blk, &blkl);
    if (!write_file(g_blk[H_FUND], blk, blkl)) exit(2);

    // h4: a NON-CARRIER block whose tx spends the wallet output (vout 1).
    build_plain_tx(g_fund_txid, 1, stranger, (uint64_t)FUND_VALUE - 100000, 0xE4, tx, &txl);
    build_block(tx, txl, (uint32_t)(1000 + 60 * H_SPEND), blk, &blkl);
    if (!write_file(g_blk[H_SPEND], blk, blkl)) exit(2);
}

// ── db helpers ───────────────────────────────────────────────────────────────
static void bal_cb(void *u, const uint8_t t[32], uint32_t v, int64_t value, int64_t h) {
    (void)t; (void)v; (void)h; *(int64_t *)u += value;
}
static int64_t balance(sqlite3 *db) { int64_t t = 0; idx_db_utxos(db, g_wallet, bal_cb, &t); return t; }
// bitmask of the heights present in raw_blocks (heights 0..62)
static uint64_t rawblock_mask(sqlite3 *db) {
    sqlite3_stmt *st; uint64_t m = 0;
    sqlite3_prepare_v2(db, "SELECT height FROM raw_blocks", -1, &st, NULL);
    while (sqlite3_step(st) == SQLITE_ROW) {
        int64_t h = sqlite3_column_int64(st, 0);
        if (h >= 0 && h < 63) m |= 1ULL << h;
    }
    sqlite3_finalize(st); return m;
}
#define WALLET_BLOCKS ((1ULL << H_FUND) | (1ULL << H_SPEND))
static int table_rows(sqlite3 *db, const char *tbl) {
    char sql[128]; snprintf(sql, sizeof sql, "SELECT COUNT(*) FROM %s", tbl);
    sqlite3_stmt *st; int n = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    if (sqlite3_step(st) == SQLITE_ROW) n = sqlite3_column_int(st, 0);
    sqlite3_finalize(st); return n;
}
static int db_intact(sqlite3 *db) {              // "no corruption" in sqlite's own terms
    sqlite3_stmt *st; int ok = 0;
    if (sqlite3_prepare_v2(db, "PRAGMA integrity_check", -1, &st, NULL) != SQLITE_OK) return 0;
    if (sqlite3_step(st) == SQLITE_ROW)
        ok = strcmp((const char *)sqlite3_column_text(st, 0), "ok") == 0;
    sqlite3_finalize(st); return ok;
}

// Run the real `index` command over blocks [from..to] of the synthetic chain.
// stdout is muted (cmd_index prints a digest banner); stderr is left alone.
static int run_index(const char *dbpath, int from, int to) {
    char act[32]; snprintf(act, sizeof act, "%lld", (long long)ACTIVATION);
    char *argv[8 + NBLK];
    int argc = 0;
    argv[argc++] = (char *)"indexerd"; argv[argc++] = (char *)"index";
    argv[argc++] = (char *)dbpath;     argv[argc++] = act;
    argv[argc++] = (char *)"--coin"; argv[argc++] = (char *)"regtest";   // idx-10: PN fixtures; never guessed
    for (int i = from; i <= to; i++) argv[argc++] = g_blk[i];
    fflush(stdout);
    int saved = dup(1), devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) { dup2(devnull, 1); close(devnull); }
    int rc = indexer_main(argc, argv);
    fflush(stdout);
    if (saved >= 0) { dup2(saved, 1); close(saved); }
    return rc;
}

static void rm_db(const char *path) {
    char b[700]; unlink(path);
    snprintf(b, sizeof b, "%s-wal", path); unlink(b);
    snprintf(b, sizeof b, "%s-shm", path); unlink(b);
    snprintf(b, sizeof b, "%s-journal", path); unlink(b);
}
// A fresh db with the wallet registered and blocks [0..to] folded through the
// production path. Returns 1 on success.
static int build_chain_db(const char *dbpath, int to) {
    rm_db(dbpath);
    sqlite3 *db = idx_db_open(dbpath); if (!db) return 0;
    idx_db_watch_add(db, g_wallet);                 // watch BEFORE funding, per db.h
    idx_db_close(db);
    return run_index(dbpath, 0, to) == 0;
}

// Open the fold state exactly as a sync pass does (projection + warm oracle).
typedef struct { sqlite3 *db; SmState *s; OracleFeed *o; int64_t activation; } Fold;
static int fold_open(Fold *f, const char *dbpath) {
    memset(f, 0, sizeof *f);
    f->db = idx_db_open(dbpath); if (!f->db) return 0;
    f->activation = idx_db_get_activation(f->db, ACTIVATION);
    f->s = sm_new((uint64_t)f->activation);
    if (!idx_db_get_onchain_magic(f->db, f->s->onchain_magic))
        idx_coin_onchain_magic("pep", f->s->onchain_magic);
    idx_db_load_state(f->db, f->s);
    f->o = oracle_new();
    idx_db_oracle_warm(f->db, f->o);
    return 1;
}
static void fold_close(Fold *f) {
    if (f->o) oracle_free(f->o);
    if (f->s) sm_free(f->s);
    if (f->db) idx_db_close(f->db);
    memset(f, 0, sizeof *f);
}

// ── 7. rollback / refold at the carrier↔non-carrier seam ─────────────────────
static void sec_seam(const char *dir) {
    printf("\n-- rollback/refold at the seam: a wallet spend in a NON-carrier block --\n");
    char dbp[600]; snprintf(dbp, sizeof dbp, "%s/seam.db", dir);

    if (!build_chain_db(dbp, NBLK - 1)) { CHECK(0, "fold the synthetic chain"); return; }
    sqlite3 *db = idx_db_open(dbp);
    if (!db) { CHECK(0, "reopen the folded db"); return; }

    int64_t h = 0; uint8_t tip[32];
    CHECK(idx_db_load_sync(db, &h, tip) && h == NBLK - 1, "chain folded to the tip (height 5)");
    CHECK(balance(db) == 0, "post-fold balance is 0 (the funding at h2 was spent at h4)");
    CHECK(idx_db_utxo_min_unspent(db) == -1, "no unspent wallet outputs remain");

    // THE PERSISTENCE RULE. Pre-fix the substrate held only {2} (carrier); the
    // spend at h4 was invisible to every future replay. It must now hold {2,4}.
    uint64_t mask = rawblock_mask(db);
    CHECK((mask & (1ULL << H_FUND)) != 0, "raw_blocks keeps the CARRIER block (h2)");
    CHECK((mask & (1ULL << H_SPEND)) != 0,
          "raw_blocks keeps the NON-CARRIER, WALLET-TOUCHING block (h4) — the fix");
    CHECK(mask == WALLET_BLOCKS, "raw_blocks holds exactly {h2, h4}: filler blocks are still skipped");
    idx_db_close(db);

    // (a) roll back TO THE TIP and replay. Pre-fix: the carrier block's re-put
    //     wiped spent_height and the wallet showed 68725.79102400 PEP again.
    {
        Fold f; if (!fold_open(&f, dbp)) { CHECK(0, "open fold state"); return; }
        CHECK(idx_sync_rollback(&f.s, f.db, f.o, f.activation, NBLK - 1) == 1, "rollback to the tip returns 1");
        CHECK(balance(f.db) == 0, "GHOST: balance stays 0 after a tip replay (not 68725.79102400 PEP)");
        CHECK(balance(f.db) != FUND_VALUE, "GHOST: the resurrected-output balance is unreachable");
        fold_close(&f);
    }

    // (b) roll back BETWEEN the funding and the spend, then refold forward. At
    //     h3 the wallet genuinely held the coin; after refolding h4/h5 it must
    //     converge back to 0 — the true value, not the inflated one.
    if (!build_chain_db(dbp, NBLK - 1)) { CHECK(0, "rebuild chain db"); return; }
    {
        Fold f; if (!fold_open(&f, dbp)) { CHECK(0, "open fold state"); return; }
        CHECK(idx_sync_rollback(&f.s, f.db, f.o, f.activation, H_SPEND - 1) == 1, "rollback to h3 returns 1");
        CHECK(balance(f.db) == FUND_VALUE, "at h3 the wallet correctly holds 68725.79102400 PEP again");
        CHECK(idx_db_utxo_min_unspent(f.db) == H_FUND, "min-unspent is the funding height");
        // stamp the cursor the way cmd_sync does after an accepted rollback
        uint8_t hh[32];
        if (idx_db_block_get(f.db, H_SPEND - 1, hh)) idx_db_save_sync(f.db, H_SPEND - 1, hh);
        fold_close(&f);
    }
    CHECK(run_index(dbp, H_SPEND, NBLK - 1) == 0, "refold h4..h5 through the production path");
    {
        sqlite3 *d2 = idx_db_open(dbp);
        CHECK(d2 && balance(d2) == 0,
              "ACCEPTANCE: refold converges on the TRUE balance (0), not the inflated one");
        CHECK(d2 && rawblock_mask(d2) == WALLET_BLOCKS, "the refold re-persists the wallet-touching block");
        if (d2) idx_db_close(d2);
    }

    // (c) roll back BELOW the funding, then refold the whole tail.
    if (!build_chain_db(dbp, NBLK - 1)) { CHECK(0, "rebuild chain db"); return; }
    {
        Fold f; if (!fold_open(&f, dbp)) { CHECK(0, "open fold state"); return; }
        CHECK(idx_sync_rollback(&f.s, f.db, f.o, f.activation, H_FUND - 1) == 1,
              "rollback to h1 (below the funding) returns 1");
        CHECK(balance(f.db) == 0, "the disconnected funding row is gone (balance 0)");
        CHECK(idx_db_utxo_min_unspent(f.db) == -1, "no unspent rows below the funding");
        uint8_t hh[32];
        if (idx_db_block_get(f.db, H_FUND - 1, hh)) idx_db_save_sync(f.db, H_FUND - 1, hh);
        fold_close(&f);
    }
    CHECK(run_index(dbp, H_FUND, NBLK - 1) == 0, "refold h2..h5 from below the funding");
    {
        sqlite3 *d2 = idx_db_open(dbp);
        CHECK(d2 && balance(d2) == 0, "ACCEPTANCE: a full re-walk of the wallet window still lands on 0");
        CHECK(d2 && idx_db_utxo_min_unspent(d2) == -1, "…with no unspent rows");
        if (d2) idx_db_close(d2);
    }

    // (d) the loop that mattered in production: rollback → replay, five times.
    //     Every round must be a fixed point.
    int loop_ok = 1;
    for (int round = 0; round < 5 && loop_ok; round++) {
        Fold f; if (!fold_open(&f, dbp)) { loop_ok = 0; break; }
        loop_ok = idx_sync_rollback(&f.s, f.db, f.o, f.activation, NBLK - 1) == 1 && balance(f.db) == 0;
        fold_close(&f);
    }
    CHECK(loop_ok, "five successive rollback+replay rounds all hold the balance at 0");
    rm_db(dbp);
}

// ── 8. boundary rollbacks ────────────────────────────────────────────────────
static void sec_bounds(const char *dir) {
    printf("\n-- boundary rollbacks (start height, above tip, 0, negative) --\n");
    char dbp[600]; snprintf(dbp, sizeof dbp, "%s/bounds.db", dir);

    // to_height == the chain's exact start height (0 here)
    if (!build_chain_db(dbp, NBLK - 1)) { CHECK(0, "build chain db"); return; }
    {
        Fold f; if (!fold_open(&f, dbp)) { CHECK(0, "open fold"); return; }
        CHECK(idx_sync_rollback(&f.s, f.db, f.o, f.activation, 0) == 1, "rollback to the exact start height returns 1");
        CHECK(db_intact(f.db), "…db integrity_check still ok");
        CHECK(rawblock_mask(f.db) == 0, "…the whole replay substrate above the start is gone");
        CHECK(balance(f.db) == 0 && idx_db_utxo_min_unspent(f.db) == -1, "…no wallet rows survive");
        CHECK(table_rows(f.db, "blocks") == 1, "…exactly the start block remains in blocks");
        fold_close(&f);
    }
    // the db is still usable afterwards: refolding the tail works
    { uint8_t hh[32]; sqlite3 *d = idx_db_open(dbp);
      if (d && idx_db_block_get(d, 0, hh)) idx_db_save_sync(d, 0, hh);
      if (d) idx_db_close(d); }
    CHECK(run_index(dbp, 1, NBLK - 1) == 0, "…and the tail refolds cleanly onto it");
    { sqlite3 *d = idx_db_open(dbp);
      CHECK(d && balance(d) == 0 && rawblock_mask(d) == WALLET_BLOCKS,
            "…reaching the same state as the original fold");
      if (d) idx_db_close(d); }

    // to_height far ABOVE the tip: nothing to prune, everything replays.
    if (!build_chain_db(dbp, NBLK - 1)) { CHECK(0, "build chain db"); return; }
    {
        Fold f; if (!fold_open(&f, dbp)) { CHECK(0, "open fold"); return; }
        int blocks_before = table_rows(f.db, "blocks");
        uint64_t mask_before = rawblock_mask(f.db);
        CHECK(idx_sync_rollback(&f.s, f.db, f.o, f.activation, 1000000) == 1, "rollback ABOVE the tip returns 1");
        CHECK(db_intact(f.db), "…db integrity_check still ok");
        CHECK(table_rows(f.db, "blocks") == blocks_before, "…prunes nothing");
        CHECK(rawblock_mask(f.db) == mask_before, "…the replay substrate is untouched");
        CHECK(balance(f.db) == 0, "…the balance is unchanged (still 0)");
        fold_close(&f);
    }

    // to_height == -1 and deeply negative heights: everything goes, sanely.
    const int64_t negs[] = { -1, -1000000, INT64_MIN / 2 };
    for (unsigned i = 0; i < sizeof negs / sizeof negs[0]; i++) {
        if (!build_chain_db(dbp, NBLK - 1)) { CHECK(0, "build chain db"); return; }
        Fold f; if (!fold_open(&f, dbp)) { CHECK(0, "open fold"); return; }
        char nm[160];
        int rc = idx_sync_rollback(&f.s, f.db, f.o, f.activation, negs[i]);
        snprintf(nm, sizeof nm, "rollback to %lld returns 1 (no crash)", (long long)negs[i]);
        CHECK(rc == 1, nm);
        snprintf(nm, sizeof nm, "rollback to %lld leaves the db intact", (long long)negs[i]);
        CHECK(db_intact(f.db), nm);
        snprintf(nm, sizeof nm, "rollback to %lld empties blocks/raw_blocks/utxos", (long long)negs[i]);
        CHECK(table_rows(f.db, "blocks") == 0 && table_rows(f.db, "raw_blocks") == 0 &&
              table_rows(f.db, "utxos") == 0, nm);
        snprintf(nm, sizeof nm, "rollback to %lld leaves the watch list alone", (long long)negs[i]);
        CHECK(table_rows(f.db, "watch") == 1, nm);
        // still writable: a put/spend round-trips after the wipe
        uint8_t t[32]; memset(t, 0x7E, 32);
        idx_db_utxo_put(f.db, t, 0, g_wallet, 12345, 9);
        snprintf(nm, sizeof nm, "rollback to %lld leaves the db writable", (long long)negs[i]);
        CHECK(balance(f.db) == 12345 && idx_db_utxo_spend(f.db, t, 0, 10) == 1, nm);
        fold_close(&f);
    }

    // a full re-index over the emptied db reproduces the same result (no latent corruption)
    { sqlite3 *d = idx_db_open(dbp);
      if (d) { sqlite3_exec(d, "DELETE FROM utxos;"
                               " DELETE FROM meta WHERE k IN ('height','tip','proj_height')",
                            NULL, NULL, NULL); idx_db_close(d); } }
    CHECK(run_index(dbp, 0, NBLK - 1) == 0, "a full re-index over the wiped db succeeds");
    { sqlite3 *d = idx_db_open(dbp);
      CHECK(d && balance(d) == 0 && rawblock_mask(d) == WALLET_BLOCKS,
            "…and reproduces the original state exactly");
      if (d) idx_db_close(d); }
    rm_db(dbp);
}

// ── 9. the wallet_rewalk_v1 one-shot ─────────────────────────────────────────
// A VERBATIM mirror of the decision block in cmd_sync (src/sync.c:941-957).
// cmd_sync is static and needs a peer socket; this reproduces its exact
// sequence over the same public helpers so the FLAG SEMANTICS are asserted as
// implemented, not as imagined.
enum { RW_SKIPPED = 0, RW_ROLLED_BACK = 1, RW_NOTHING_TO_DO = 2, RW_ROLLBACK_FAILED = 3 };
static int rewalk_pass(Fold *f, int64_t start, int64_t *height) {
    if (idx_db_flag_get(f->db, "wallet_rewalk_v1")) return RW_SKIPPED;
    int64_t mh = idx_db_utxo_min_unspent(f->db);
    int64_t to = mh > 0 ? mh - 1 : -1;
    if (to >= 0 && to < start) to = start;
    if (to >= 0 && to < *height) {
        if (idx_sync_rollback(&f->s, f->db, f->o, f->activation, to)) {
            *height = to;
            uint8_t tip[32];
            if (*height > start && idx_db_block_get(f->db, *height, tip)) idx_db_save_sync(f->db, *height, tip);
            idx_db_flag_set(f->db, "wallet_rewalk_v1");
            return RW_ROLLED_BACK;
        }
        return RW_ROLLBACK_FAILED;          // flag deliberately left UNSET → retry next pass
    }
    idx_db_flag_set(f->db, "wallet_rewalk_v1");
    return RW_NOTHING_TO_DO;
}

static void sec_rewalk(const char *dir) {
    printf("\n-- wallet_rewalk_v1: the one-shot runs once, and retries only on failure --\n");
    char dbp[600]; snprintf(dbp, sizeof dbp, "%s/rewalk.db", dir);

    // Case A: an unspent output at h2 with the tip at h3 → the re-walk rolls
    // back to h1 and sets the flag; every later pass is a no-op.
    if (!build_chain_db(dbp, H_SPEND - 1)) { CHECK(0, "build unspent chain db"); return; }
    {
        sqlite3 *d = idx_db_open(dbp);
        CHECK(d && balance(d) == FUND_VALUE, "pre-condition: the wallet holds an unspent output at h2");
        CHECK(d && idx_db_flag_get(d, "wallet_rewalk_v1") == 0, "a fresh db has NOT run the re-walk");
        if (d) idx_db_close(d);

        Fold f; if (!fold_open(&f, dbp)) { CHECK(0, "open fold"); return; }
        int64_t height = H_SPEND - 1;
        CHECK(rewalk_pass(&f, 0, &height) == RW_ROLLED_BACK, "pass 1 performs the re-walk");
        CHECK(height == H_FUND - 1, "…rolling the cursor back to just below the oldest unspent output");
        CHECK(idx_db_flag_get(f.db, "wallet_rewalk_v1") != 0, "…and setting wallet_rewalk_v1 on success");

        int64_t h2 = height;
        CHECK(rewalk_pass(&f, 0, &h2) == RW_SKIPPED, "pass 2 is skipped (the flag is set)");
        CHECK(h2 == height, "…and moves nothing");
        int64_t h3 = height;
        CHECK(rewalk_pass(&f, 0, &h3) == RW_SKIPPED && h3 == height,
              "pass 3 is skipped too — ONCE and only once");
        fold_close(&f);
    }

    // Case B: idx_sync_rollback FAILS → the flag must stay unset so the next
    // pass retries. A corrupt row in the replay substrate makes the replay
    // callback reject, which makes rawblock_iter return -1, which is the only
    // way idx_sync_rollback returns 0.
    if (!build_chain_db(dbp, H_SPEND - 1)) { CHECK(0, "build unspent chain db"); return; }
    {
        sqlite3 *d = idx_db_open(dbp);
        uint8_t garbage[64]; memset(garbage, 0xDD, sizeof garbage);
        idx_db_rawblock_put(d, 0, garbage, sizeof garbage);   // height 0 ≤ to, unparseable
        idx_db_close(d);

        Fold f; if (!fold_open(&f, dbp)) { CHECK(0, "open fold"); return; }
        int64_t height = H_SPEND - 1;
        CHECK(rewalk_pass(&f, 0, &height) == RW_ROLLBACK_FAILED, "a corrupt replay substrate makes the rollback FAIL");
        CHECK(idx_db_flag_get(f.db, "wallet_rewalk_v1") == 0,
              "…and the flag stays UNSET so the next pass retries");
        CHECK(height == H_SPEND - 1, "…the cursor is not advanced on failure");
        CHECK(db_intact(f.db), "…the db survives the failed rollback");

        // repair the substrate + re-seed an unspent output, then retry
        sqlite3_exec(f.db, "DELETE FROM raw_blocks WHERE height=0", NULL, NULL, NULL);
        idx_db_utxo_put(f.db, g_fund_txid, 1, g_wallet, FUND_VALUE, H_FUND);
        int64_t h2 = H_SPEND - 1;
        CHECK(rewalk_pass(&f, 0, &h2) == RW_ROLLED_BACK, "the RETRY pass performs the re-walk");
        CHECK(idx_db_flag_get(f.db, "wallet_rewalk_v1") != 0, "…and only now sets the flag");
        fold_close(&f);
    }

    // Case C: nothing to heal — no unspent rows at all. The flag is set anyway
    // (a no-wallet db must not re-walk on every future pass).
    if (!build_chain_db(dbp, NBLK - 1)) { CHECK(0, "build spent chain db"); return; }
    {
        Fold f; if (!fold_open(&f, dbp)) { CHECK(0, "open fold"); return; }
        CHECK(idx_db_utxo_min_unspent(f.db) == -1, "pre-condition: no unspent rows");
        int64_t height = NBLK - 1;
        CHECK(rewalk_pass(&f, 0, &height) == RW_NOTHING_TO_DO, "an all-spent db does no rollback");
        CHECK(height == NBLK - 1, "…and leaves the cursor at the tip");
        CHECK(idx_db_flag_get(f.db, "wallet_rewalk_v1") != 0, "…but still sets the flag (no re-walk every pass)");
        CHECK(rewalk_pass(&f, 0, &height) == RW_SKIPPED, "…and the following pass is a no-op");
        fold_close(&f);
    }

    // Case D: the `mh > 0` guard — an unspent output AT height 0 yields to = -1,
    // so no rollback is attempted and the flag is set. (Documents the implemented
    // behaviour: height 0 is below any real checkpoint, so there is nothing to
    // roll back to.)
    if (!build_chain_db(dbp, NBLK - 1)) { CHECK(0, "build chain db"); return; }
    {
        sqlite3 *d = idx_db_open(dbp);
        uint8_t t[32]; memset(t, 0x5B, 32);
        idx_db_utxo_put(d, t, 0, g_wallet, 1000, 0);          // unspent at height 0
        idx_db_close(d);
        Fold f; if (!fold_open(&f, dbp)) { CHECK(0, "open fold"); return; }
        CHECK(idx_db_utxo_min_unspent(f.db) == 0, "pre-condition: the oldest unspent output is at height 0");
        int64_t height = NBLK - 1;
        CHECK(rewalk_pass(&f, 0, &height) == RW_NOTHING_TO_DO, "min-unspent == 0 → no rollback (the mh>0 guard)");
        CHECK(idx_db_flag_get(f.db, "wallet_rewalk_v1") != 0, "…and the flag is set, so it never retries");
        fold_close(&f);
    }

    // Case E: the start-height clamp — an unspent output below the checkpoint
    // must not roll the fold below the checkpoint.
    if (!build_chain_db(dbp, NBLK - 1)) { CHECK(0, "build chain db"); return; }
    {
        sqlite3 *d = idx_db_open(dbp);
        sqlite3_exec(d, "DELETE FROM utxos", NULL, NULL, NULL);
        uint8_t t[32]; memset(t, 0x6C, 32);
        idx_db_utxo_put(d, t, 0, g_wallet, 1000, 2);          // unspent at h2; pretend start = 3
        idx_db_close(d);
        Fold f; if (!fold_open(&f, dbp)) { CHECK(0, "open fold"); return; }
        int64_t height = NBLK - 1, start = 3;
        CHECK(rewalk_pass(&f, start, &height) == RW_ROLLED_BACK,
              "an unspent output below the checkpoint still triggers a re-walk");
        CHECK(height == start, "…clamped to the start height, never below it");
        CHECK(idx_db_flag_get(f.db, "wallet_rewalk_v1") != 0, "…and the flag is set");
        fold_close(&f);
    }

    // Case F: to >= height (the cursor already sits below the oldest unspent
    // output) → no rollback, flag set.
    if (!build_chain_db(dbp, NBLK - 1)) { CHECK(0, "build chain db"); return; }
    {
        sqlite3 *d = idx_db_open(dbp);
        sqlite3_exec(d, "DELETE FROM utxos", NULL, NULL, NULL);
        uint8_t t[32]; memset(t, 0x7D, 32);
        idx_db_utxo_put(d, t, 0, g_wallet, 1000, 900);        // unspent far above the tip
        idx_db_close(d);
        Fold f; if (!fold_open(&f, dbp)) { CHECK(0, "open fold"); return; }
        int64_t height = NBLK - 1;
        CHECK(rewalk_pass(&f, 0, &height) == RW_NOTHING_TO_DO, "min-unspent above the cursor → no rollback");
        CHECK(height == NBLK - 1, "…the cursor never moves forward");
        CHECK(idx_db_flag_get(f.db, "wallet_rewalk_v1") != 0, "…and the flag is set");
        fold_close(&f);
    }
    rm_db(dbp);
}

// DN twin of the h2 COMMIT carrier. Same commitment bytes, same fold digest;
// each prefix is IGNORE under the other profile.
static void fold_commit(const SmAction *a, uint8_t dig[32]) {
    SmState *s = sm_new(0);
    sm_begin_block(s, 2, 1000, 1);
    SmTx t; memset(&t, 0, sizeof t);
    SmId *in = sm_tx_input(&t); memset(in->h160, 0x11, 20); in->type = SM_P2PKH;
    t.in_sighash_all[0] = 1;
    SmCarrier *c = sm_tx_carrier(&t);
    c->kind = SM_CAR_ACTION; c->act = *a; c->value = 0; c->vout = 0;
    sm_apply_tx(s, &t);
    sm_state_digest(s, dig);
    sm_tx_free(&t); sm_free(s);
}
static void sec_magic(void) {
    printf("\n-- on-chain magic: PN commit vector and its DN twin --\n");
    uint8_t pn[2] = { 0x50, 0x4E }, dn[2] = { 0x44, 0x4E };
    uint8_t commit[36] = { 0xFF, 0x50, 0x4E, SM_OP_COMMIT };
    memset(commit + 4, 0x22, 32);
    SmCarrier c;
    sm_decode_payload(commit, 36, 0, pn, &c);
    CHECK(c.kind == SM_CAR_ACTION && c.act.op == SM_OP_COMMIT, "PN commit decodes under the PN profile");
    SmAction pn_act = c.act;
    sm_decode_payload(commit, 36, 0, dn, &c);
    CHECK(c.kind == SM_CAR_IGNORE, "PN commit is ignored under the DN profile");
    uint8_t dnc[36]; memcpy(dnc, commit, 36); dnc[1] = dn[0]; dnc[2] = dn[1];
    sm_decode_payload(dnc, 36, 0, dn, &c);
    CHECK(c.kind == SM_CAR_ACTION && c.act.op == SM_OP_COMMIT, "DN twin commit decodes under the DN profile");
    SmAction dn_act = c.act;
    sm_decode_payload(dnc, 36, 0, pn, &c);
    CHECK(c.kind == SM_CAR_IGNORE, "DN commit is ignored under the PN profile");
    uint8_t dp[32], dd[32];
    fold_commit(&pn_act, dp); fold_commit(&dn_act, dd);
    CHECK(memcmp(dp, dd, 32) == 0, "DN commit fold digest equals the PN fold");
}


// ── 10–12 (idx-03): crash mid-write, reorg, and the read-only check ──────────
// alt branch for h3..h5: fillers with different seeds/times, NO wallet spend.
static char g_alt[NBLK][600];
static void make_alt_files(const char *dir) {
    uint8_t stranger[20]; memset(stranger, 0x7B, 20);
    uint8_t tx[1024], blk[2048]; int txl, blkl;
    for (int i = 3; i < NBLK; i++) {
        snprintf(g_alt[i], sizeof g_alt[0], "%s/alt%d.bin", dir, i);
        uint8_t prev[32]; memset(prev, (uint8_t)(0x90 + i), 32);
        build_plain_tx(prev, 0, stranger, 200000000ULL, (uint8_t)(0xA0 + i), tx, &txl);
        build_block(tx, txl, (uint32_t)(1000 + 61 * i), blk, &blkl);
        if (!write_file(g_alt[i], blk, blkl)) exit(2);
    }
}
static int run_files(const char *dbpath, char **files, int n) {
    char act[32]; snprintf(act, sizeof act, "%lld", (long long)ACTIVATION);
    char *argv[8 + NBLK]; int argc = 0;
    argv[argc++] = (char *)"indexerd"; argv[argc++] = (char *)"index";
    argv[argc++] = (char *)dbpath; argv[argc++] = act;
    argv[argc++] = (char *)"--coin"; argv[argc++] = (char *)"regtest";   // idx-10: PN fixtures; never guessed
    for (int i = 0; i < n; i++) argv[argc++] = files[i];
    fflush(stdout);
    int saved = dup(1), dn = open("/dev/null", O_WRONLY);
    if (dn >= 0) { dup2(dn, 1); close(dn); }
    int rc = indexer_main(argc, argv);
    fflush(stdout); if (saved >= 0) { dup2(saved, 1); close(saved); }
    return rc;
}
// Run `index` over files in a CHILD that SIGKILLs itself after block crash_at's
// rows autocommit (pre-projection). Returns 1 if the child died by SIGKILL.
static int run_files_killed(const char *dbpath, char **files, int n, int64_t crash_at) {
    fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) {
        char b[32]; snprintf(b, sizeof b, "%lld", (long long)crash_at);
        setenv("IDX_TEST_CRASH_AT", b, 1);
        int dn = open("/dev/null", O_WRONLY); if (dn >= 0) { dup2(dn, 2); close(dn); }
        run_files(dbpath, files, n); _exit(0);
    }
    int st = 0; waitpid(pid, &st, 0);
    return WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL;
}
static void state_digest(const char *dbpath, uint8_t d[32]) {
    Fold f; memset(d, 0, 32); if (!fold_open(&f, dbpath)) return;
    sm_state_digest(f.s, d); fold_close(&f);
}
static int64_t bal_of(const char *dbpath) {
    sqlite3 *db = idx_db_open(dbpath); int64_t b = db ? balance(db) : -1; idx_db_close(db); return b;
}
static int check_clean(const char *dbpath, int want_warn) {   // errors==0 (and warnings==0 if asked)
    IdxCheckReport r; FILE *nul = fopen("/dev/null", "w");
    int e = idx_db_check(dbpath, NULL, nul, &r); if (nul) fclose(nul);
    return e == 0 && (!want_warn || r.warnings == 0);
}
static int64_t cursor(const char *dbpath) {
    sqlite3 *db = idx_db_open(dbpath); int64_t h = -9; uint8_t t[32];
    if (db && !idx_db_load_sync(db, &h, t)) { h = -9; }
    idx_db_close(db); return h;
}
static int fresh_watch_db(const char *dbpath) {
    rm_db(dbpath); sqlite3 *db = idx_db_open(dbpath); if (!db) return 0;
    idx_db_watch_add(db, g_wallet); idx_db_close(db); return 1;
}

static void sec_crash(const char *dir) {
    printf("\n-- idx-03: SIGKILL mid-write → recovery resumes byte-identically --\n");
    char ref[600], dbp[600]; snprintf(ref, sizeof ref, "%s/ref.db", dir); snprintf(dbp, sizeof dbp, "%s/crash.db", dir);
    char *all[NBLK]; for (int i = 0; i < NBLK; i++) all[i] = g_blk[i];
    if (!fresh_watch_db(ref) || run_files(ref, all, NBLK)) { CHECK(0, "reference fold"); return; }
    uint8_t dref[32]; state_digest(ref, dref);
    CHECK(check_clean(ref, 1), "check: clean reference db has 0 errors, 0 warnings");
    int all_ok = 1, kills = 0, gaps_ok = 1;
    // (a) crash in the FIRST batch (no projection yet) at every height
    // (b) crash in a LATER batch (projection at h2) at h3/h4/h5
    for (int phase = 0; phase < 2; phase++)
      for (int k = phase ? 3 : 0; k < NBLK; k++) {
        if (!fresh_watch_db(dbp)) { all_ok = 0; continue; }
        int base = 0;
        if (phase) { if (run_files(dbp, all, 3)) { all_ok = 0; continue; } base = 3; }
        kills += run_files_killed(dbp, all + base, NBLK - base, k);
        if (cursor(dbp) != k) all_ok = 0;                       // the kill landed after h=k's rows
        if (!check_clean(dbp, 0)) gaps_ok = 0;                  // crash gap is a warning, never an error
        int64_t resume = phase ? 3 : 0;                         // = proj_height + 1
        if (run_files(dbp, all + resume, NBLK - (int)resume)) { all_ok = 0; continue; }
        uint8_t d[32]; state_digest(dbp, d);
        if (memcmp(d, dref, 32) || cursor(dbp) != NBLK - 1 || bal_of(dbp) != 0 || !check_clean(dbp, 1)) all_ok = 0;
      }
    CHECK(kills == NBLK + 3, "every injected crash was a real SIGKILL (9 kills)");
    CHECK(gaps_ok, "check: a crashed db reports the gap as a warning, 0 errors");
    CHECK(all_ok, "after each kill, resume → same digest, cursor 5, balance 0, check clean");

    // (c) recovery drops the dead rows: crash at h4 (spend recorded), then the
    //     chain reorgs to the alt branch — the stale spend must not survive.
    if (fresh_watch_db(dbp) && !run_files(dbp, all, 3)) {
        run_files_killed(dbp, all + 3, 3, 4);
        sqlite3 *db = idx_db_open(dbp);
        CHECK(db && balance(db) == 0, "pre-recovery: the h4 spend mark is on disk (autocommitted)");
        int64_t h = 0; uint8_t tip[32]; static const uint8_t z[32];
        idx_db_load_sync(db, &h, tip);
        CHECK(idx_sync_recover(db, -1, z, &h, tip) == 1 && h == 2, "idx_sync_recover rewinds the cursor to proj_height 2");
        CHECK(table_rows(db, "blocks") == 3 && balance(db) == FUND_VALUE,
              "recover pruned blocks/utxo marks above 2 (no stale spend from the dead write)");
        CHECK(idx_sync_recover(db, -1, z, &h, tip) == 0, "recover is a no-op on a consistent db");
        idx_db_close(db);
        char *alt[3] = { g_alt[3], g_alt[4], g_alt[5] };
        CHECK(run_files(dbp, alt, 3) == 0 && bal_of(dbp) == FUND_VALUE && check_clean(dbp, 1),
              "alt branch after the crash: output unspent, check clean");
    }
}

static void sec_reorg(const char *dir) {
    printf("\n-- idx-03: simulated reorg (h3..h5 replaced) resumes cleanly --\n");
    char dbp[600], ref[600]; snprintf(dbp, sizeof dbp, "%s/reorg.db", dir); snprintf(ref, sizeof ref, "%s/altref.db", dir);
    char *all[NBLK]; for (int i = 0; i < NBLK; i++) all[i] = g_blk[i];
    char *altc[NBLK] = { g_blk[0], g_blk[1], g_blk[2], g_alt[3], g_alt[4], g_alt[5] };
    if (!fresh_watch_db(ref) || run_files(ref, altc, NBLK)) { CHECK(0, "alt reference fold"); return; }
    uint8_t dalt[32]; state_digest(ref, dalt);
    if (!fresh_watch_db(dbp) || run_files(dbp, all, NBLK)) { CHECK(0, "main fold"); return; }
    CHECK(bal_of(dbp) == 0, "main branch: wallet output spent at h4");
    // the sync loop's reorg: rollback to the fork, stamp the cursor, connect
    Fold f; fold_open(&f, dbp);
    int ok = idx_sync_rollback(&f.s, f.db, f.o, f.activation, 2);
    uint8_t tip[32]; idx_db_block_get(f.db, 2, tip); idx_db_save_sync(f.db, 2, tip);
    fold_close(&f);
    CHECK(ok && check_clean(dbp, 1), "after rollback to the fork (h2): check clean, no orphans");
    CHECK(run_files(dbp, altc + 3, 3) == 0, "connect the alt branch h3'..h5'");
    uint8_t d[32]; state_digest(dbp, d);
    CHECK(memcmp(d, dalt, 32) == 0, "reorged state digest == a fresh fold of the alt chain");
    CHECK(bal_of(dbp) == FUND_VALUE, "spend disconnected: output unspent on the alt branch");
    CHECK(check_clean(dbp, 1), "check: reorged db clean");
    // crash DURING the post-reorg reconnect, then resume
    fold_open(&f, dbp); idx_sync_rollback(&f.s, f.db, f.o, f.activation, 2);
    idx_db_block_get(f.db, 2, tip); idx_db_save_sync(f.db, 2, tip); fold_close(&f);
    CHECK(run_files_killed(dbp, altc + 3, 3, 4), "SIGKILL mid-reconnect at h4'");
    CHECK(check_clean(dbp, 0), "check: crashed-mid-reorg db has 0 errors");
    CHECK(run_files(dbp, altc + 3, 3) == 0, "resume reconnect from the projection");
    state_digest(dbp, d);
    CHECK(memcmp(d, dalt, 32) == 0 && bal_of(dbp) == FUND_VALUE && check_clean(dbp, 1),
          "crash-in-reorg resume converges on the alt-chain digest, check clean");
}

static int exec_sql(const char *dbpath, const char *sql) {
    sqlite3 *db; if (sqlite3_open(dbpath, &db) != SQLITE_OK) return 0;
    int ok = sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK; sqlite3_close(db); return ok;
}
static void sec_check(const char *dir) {
    printf("\n-- idx-03: `check` flags each class of damage, and is read-only --\n");
    char dbp[600]; snprintf(dbp, sizeof dbp, "%s/chk.db", dir);
    char *all[NBLK]; for (int i = 0; i < NBLK; i++) all[i] = g_blk[i];
    struct { const char *sql, *what; } cases[] = {
        { "INSERT INTO blocks(height,hash,time,coinbase,bytes,bits) VALUES(9,zeroblob(32),1,0,0,1)", "orphan block above tip" },
        { "UPDATE meta SET v='00' || substr(v,3) WHERE k='tip'", "tip hash disagrees with stored block" },
        { "DELETE FROM blocks WHERE height=3", "gap in blocks below tip" },
        { "INSERT INTO epochs(name,start_height,owner,owner_type) VALUES('zz',8,NULL,0)", "orphan epoch above tip" },
        { "UPDATE utxos SET spent_height=9", "utxo spend above tip" },
        { "UPDATE meta SET v='7' WHERE k='proj_height'", "projection ahead of cursor" },
        { "INSERT INTO names(name,owner,owner_type,lease_expiry,st,seller,seller_type,price,offer_expiry,buyer,burn_leg,pay_leg,reserve_expiry)"
          " VALUES('bad',x'00',0,9,0,zeroblob(20),0,0,0,zeroblob(20),0,0,0)", "malformed name row" },
        { "INSERT INTO raw_blocks(height,raw) VALUES(1,x'00'); DELETE FROM blocks WHERE height=1", "raw block without a blocks row" },
    };
    int ncase = (int)(sizeof cases / sizeof cases[0]), caught = 0;
    for (int i = 0; i < ncase; i++) {
        if (!fresh_watch_db(dbp) || run_files(dbp, all, NBLK)) continue;
        exec_sql(dbp, cases[i].sql);
        IdxCheckReport r; FILE *nul = fopen("/dev/null", "w");
        int e = idx_db_check(dbp, NULL, nul, &r); if (nul) fclose(nul);
        if (e > 0) caught++; else printf("     missed: %s\n", cases[i].what);
    }
    CHECK(caught == ncase, "check reports an error for all 8 injected damage classes");
    // read-only: a check never changes the file
    fresh_watch_db(dbp); run_files(dbp, all, NBLK);
    { sqlite3 *db = idx_db_open(dbp); sqlite3_exec(db, "PRAGMA wal_checkpoint(TRUNCATE)", NULL, NULL, NULL); idx_db_close(db); }
    uint8_t before[32], after[32];
    { FILE *f = fopen(dbp, "rb"); uint8_t buf[4096]; size_t n; SHA256_CTX c; sha256_init(&c);
      while (f && (n = fread(buf, 1, sizeof buf, f)) > 0) { sha256_update(&c, buf, (unsigned)n); }
      if (f) fclose(f); sha256_final(&c, before); }
    IdxCheckReport r; FILE *nul = fopen("/dev/null", "w"); idx_db_check(dbp, NULL, nul, &r); if (nul) fclose(nul);
    { FILE *f = fopen(dbp, "rb"); uint8_t buf[4096]; size_t n; SHA256_CTX c; sha256_init(&c);
      while (f && (n = fread(buf, 1, sizeof buf, f)) > 0) { sha256_update(&c, buf, (unsigned)n); }
      if (f) fclose(f); sha256_final(&c, after); }
    CHECK(memcmp(before, after, 32) == 0 && r.errors == 0, "check is read-only: db bytes unchanged, clean db 0 errors");
    // corrupted file → integrity_check fails
    { FILE *f = fopen(dbp, "r+b"); if (f) { fseek(f, 0, SEEK_END); long sz = ftell(f); uint8_t junk[16]; memset(junk, 0xEE, sizeof junk);
        for (long pg = 1024; pg < sz; pg += 1024) { fseek(f, pg, SEEK_SET); fwrite(junk, 1, sizeof junk, f); } fclose(f); } }
    nul = fopen("/dev/null", "w"); int e = idx_db_check(dbp, NULL, nul, &r); if (nul) fclose(nul);
    CHECK(e != 0, "a byte-smashed db fails sqlite integrity_check");
}

// ── main ─────────────────────────────────────────────────────────────────────
// peer_height from announcements: monotonic in memory and on disk, the meta
// write rate-limited to one per IDX_PH_WRITE_MIN_S, force flushes, and a
// every write (handshake or announcement) is a monotonic max at the db.
static void sec_peer_height(const char *dir) {
    printf("\n-- peer_height follows announcements --\n");
    char p[700]; snprintf(p, sizeof p, "%s/ph.db", dir);
    sqlite3 *db = idx_db_open(p);
    if (!db) { CHECK(0, "open ph.db"); return; }
    idx_peer_height_reset();
    int64_t t = 1000000;
    CHECK(idx_peer_height_note(db, 100, t, 0) == 100 && idx_db_get_peer_height(db) == 100, "first announcement written at once");
    CHECK(idx_peer_height_note(db, 150, t + 1, 0) == 150 && idx_db_get_peer_height(db) == 100, "second within the window: memory only (rate-limited)");
    CHECK(idx_peer_height_note(db, 120, t + 2, 0) == 150, "a lower announcement never lowers the best");
    CHECK(idx_peer_height_note(db, 151, t + IDX_PH_WRITE_MIN_S - 1, 0) == 151 && idx_db_get_peer_height(db) == 100, "still inside the window: no write");
    idx_peer_height_note(db, 0, t + IDX_PH_WRITE_MIN_S, 0);
    CHECK(idx_db_get_peer_height(db) == 151, "window elapsed: best written");
    idx_peer_height_note(db, 160, t + IDX_PH_WRITE_MIN_S + 1, 1);
    CHECK(idx_db_get_peer_height(db) == 160, "force flushes inside the window");
    int writes = 0; int64_t last = idx_db_get_peer_height(db);
    for (int i = 0; i < 1000; i++) {           // a block every second for ~16 min
        idx_peer_height_note(db, 161 + i, t + 200 + i, 0);
        int64_t now = idx_db_get_peer_height(db); if (now != last) { writes++; last = now; }
    }
    CHECK(writes <= 1000 / IDX_PH_WRITE_MIN_S + 1 && writes >= 1000 / IDX_PH_WRITE_MIN_S - 1, "1000 announcements → ~1 write per window");
    idx_db_set_peer_height(db, 5000);
    idx_db_raise_peer_height(db, 4000);
    CHECK(idx_db_get_peer_height(db) == 5000, "raise never lowers the stored value");
    // restart: in-memory state wiped, then a lower handshake claim — stored stays
    idx_db_set_peer_height(db, 900);
    CHECK(idx_db_get_peer_height(db) == 5000, "set itself is monotonic (900 cannot replace 5000)");
    idx_peer_height_reset();                                 // process restart
    idx_db_set_peer_height(db, 500);                         // first handshake after restart
    CHECK(idx_db_get_peer_height(db) == 5000, "restart: handshake 500 cannot lower stored 5000");
    // also the exact scenario: preset 900, restart, handshake 500 → stay 900
    { char q[700]; snprintf(q, sizeof q, "%s/ph2.db", dir);
      sqlite3 *d2 = idx_db_open(q); idx_db_set_peer_height(d2, 900);
      CHECK(idx_db_get_peer_height(d2) == 900, "preset 900");
      idx_peer_height_reset();
      idx_db_set_peer_height(d2, 500);
      CHECK(idx_db_get_peer_height(d2) == 900, "restart: preset 900, handshake 500 → stays 900");
      idx_db_close(d2); unlink(q); }
    // load seeds g_ph_disk from DB: after reset+load, note(500) must keep memory+DB at 900
    { char q[256]; snprintf(q, sizeof q, "%s/ph_load.db", dir); unlink(q);
      sqlite3 *d2 = idx_db_open(q); idx_db_set_peer_height(d2, 900);
      CHECK(idx_db_get_peer_height(d2) == 900, "load-seed: preset 900");
      idx_peer_height_reset();
      idx_peer_height_load(d2);
      CHECK(idx_peer_height_note(d2, 500, 1000, 1) == 900, "load-seed: note 500 keeps in-memory best at 900");
      CHECK(idx_db_get_peer_height(d2) == 900, "load-seed: DB stays 900");
      idx_db_close(d2); unlink(q); }
    idx_db_close(db); idx_peer_height_reset();
    unlink(p);
}

int main(void) {
    char dir[] = "/tmp/idx_test_sync_XXXXXX";
    if (!mkdtemp(dir)) { fprintf(stderr, "mkdtemp failed\n"); return 1; }
    printf("temp chain dir: %s\n", dir);

    sec_magic();
    make_chain_files(dir);
    CHECK(1, "built a 6-block synthetic chain (carrier funding at h2, non-carrier spend at h4)");

    sec_seam(dir);
    sec_bounds(dir);
    sec_rewalk(dir);
    make_alt_files(dir);
    sec_crash(dir);
    sec_reorg(dir);
    sec_check(dir);
    sec_peer_height(dir);
    for (int i = 3; i < NBLK; i++) unlink(g_alt[i]);

    // teardown
    for (int i = 0; i < NBLK; i++) unlink(g_blk[i]);
    { const char *left[] = { "seam.db", "bounds.db", "rewalk.db", "ref.db", "crash.db", "reorg.db", "altref.db", "chk.db", "serve-pep.db", "serve-doge.db" };
      for (unsigned i = 0; i < sizeof left / sizeof left[0]; i++) {
          char pth[700]; snprintf(pth, sizeof pth, "%s/%s", dir, left[i]); rm_db(pth);
      } }
    if (rmdir(dir) != 0) fprintf(stderr, "warning: could not remove %s\n", dir);

    printf(g_fail ? "\ntest_sync: FAIL\n" : "\ntest_sync: all ok\n");
    return g_fail;
}
