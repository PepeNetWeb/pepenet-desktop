// test_db.c — the wallet-UTXO storage layer under adversarial replay.
//
// PROVES, against a REAL sqlite db in a mkdtemp'd /tmp directory (removed at the
// end — never ~/.pepenet):
//
//   1. THE GHOST-UTXO REGRESSION. An output that was funded, then spent, then
//      re-put by a rollback replay/refold STAYS SPENT. This is the exact shape of
//      the overcount that showed a wallet 167,591.40528856 PEP instead of
//      98,865.61426456 PEP: idx_db_utxo_put used INSERT OR REPLACE, which
//      rewrote spent_height=NULL on the conflicting row and resurrected an
//      already-spent 68,725.79102400 PEP output. With OR REPLACE restored this
//      section FAILS — that is the whole point of it.
//   2. idx_db_utxo_spend's RETURN VALUE: 1 when it hits a watched utxo, 0 when it
//      does not. sync.c's FoldCtx.wallet_touched is driven by exactly this; if it
//      lies, wallet-touching blocks stop being persisted to raw_blocks and the
//      ghost comes back.
//   3. idx_db_utxo_min_unspent: MIN(height) over unspent rows, -1 when none,
//      unaffected by spent rows, correct when the only unspent row is the lowest
//      or the highest. (It is the floor the wallet re-walk rolls back to.)
//   4. idx_db_flag_get / idx_db_flag_set: round-trip, durable across close/reopen,
//      and false for an unset flag — so the one-shot re-walk neither re-runs
//      forever nor is skipped on a fresh db.
//   5. BALANCE SUMMATION as a property: thousands of seeded-random put/spend
//      sequences (own SplitMix64 — never rand()) always sum, over unspent rows,
//      to an independently-kept running total. Values are pushed to the very edge
//      of INT64_MAX to prove no 64-bit overflow; the total never goes negative.
//   6. IDEMPOTENCE: applying the same block/tx twice changes nothing — a full
//      byte-fingerprint of the utxos table is identical after the replay.
//
// All money is int64 koinu. There is no floating point anywhere in this file.
#include "db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static int g_fail;
#define CHECK(cond, name) do { \
    if (cond) printf("ok   %s\n", name); \
    else      { printf("FAIL %s\n", name); g_fail = 1; } \
} while (0)

// ── seeded PRNG (SplitMix64 — deterministic, never rand()) ───────────────────
static uint64_t g_rng;
static uint64_t rnd64(void) {
    uint64_t z = (g_rng += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

// ── helpers ──────────────────────────────────────────────────────────────────
static void mk_txid(uint8_t out[32], uint32_t i) {
    memset(out, 0, 32);
    out[0] = (uint8_t)i; out[1] = (uint8_t)(i >> 8);
    out[2] = (uint8_t)(i >> 16); out[3] = (uint8_t)(i >> 24);
    out[31] = 0xA5;                    // keep it obviously not a null prevout
}
static void mk_h160(uint8_t out[20], uint8_t tag) { memset(out, tag, 20); }

static void bal_cb(void *u, const uint8_t txid[32], uint32_t vout, int64_t value, int64_t height) {
    (void)txid; (void)vout; (void)height;
    *(int64_t *)u += value;
}
static int64_t balance(sqlite3 *db, const uint8_t h160[20]) {
    int64_t t = 0; idx_db_utxos(db, h160, bal_cb, &t); return t;
}
static int utxo_count(sqlite3 *db, const uint8_t h160[20]) {
    return idx_db_utxos(db, h160, NULL, NULL);
}
// spent_height of one outpoint: -1 = unspent, -2 = no such row.
static int64_t spent_at(sqlite3 *db, const uint8_t txid[32], uint32_t vout) {
    sqlite3_stmt *st; int64_t r = -2;
    sqlite3_prepare_v2(db, "SELECT spent_height FROM utxos WHERE txid=? AND vout=?", -1, &st, NULL);
    sqlite3_bind_blob(st, 1, txid, 32, SQLITE_STATIC); sqlite3_bind_int(st, 2, (int)vout);
    if (sqlite3_step(st) == SQLITE_ROW)
        r = sqlite3_column_type(st, 0) == SQLITE_NULL ? -1 : sqlite3_column_int64(st, 0);
    sqlite3_finalize(st); return r;
}
// FNV-1a over the WHOLE utxos table in a deterministic order — "changed nothing"
// means every column of every row, not just the balance.
static uint64_t utxo_fingerprint(sqlite3 *db) {
    uint64_t h = 1469598103934665603ULL;
    #define MIX(p, n) do { const uint8_t *b_ = (const uint8_t *)(p); \
        for (int i_ = 0; i_ < (int)(n); i_++) { h ^= b_[i_]; h *= 1099511628211ULL; } } while (0)
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT txid,vout,h160,value,height,spent_height FROM utxos"
                           " ORDER BY txid,vout", -1, &st, NULL);
    while (sqlite3_step(st) == SQLITE_ROW) {
        MIX(sqlite3_column_blob(st, 0), sqlite3_column_bytes(st, 0));
        int64_t v = sqlite3_column_int64(st, 1); MIX(&v, sizeof v);
        MIX(sqlite3_column_blob(st, 2), sqlite3_column_bytes(st, 2));
        v = sqlite3_column_int64(st, 3); MIX(&v, sizeof v);
        v = sqlite3_column_int64(st, 4); MIX(&v, sizeof v);
        int isnull = sqlite3_column_type(st, 5) == SQLITE_NULL;
        MIX(&isnull, sizeof isnull);
        v = isnull ? 0 : sqlite3_column_int64(st, 5); MIX(&v, sizeof v);
    }
    sqlite3_finalize(st);
    #undef MIX
    return h;
}

// ── 1. the ghost-UTXO regression, as the incident actually happened ──────────
// Reconstructed from the real numbers: a 68,725.79102400 PEP output funded at
// height 1,133,161 (a CARRIER block — hence in the replay substrate), spent at
// height 1,135,986 (a NON-carrier block — hence NOT in it, pre-fix). A rollback
// replayed the funding block and, with INSERT OR REPLACE, brought the output
// back from the dead; the wallet then showed the two outputs' sum.
static void sec_ghost(sqlite3 *db) {
    printf("\n-- ghost utxo: a spent output must never be resurrected by a replay --\n");
    const int64_t GHOST_VALUE = 6872579102400LL;    // 68,725.79102400 PEP in koinu
    const int64_t OTHER_VALUE = 9886561426456LL;    // 98,865.61426456 PEP in koinu
    const int64_t INFLATED    = 16759140528856LL;   // 167,591.40528856 PEP — the bug's reading
    const int64_t FUND_H      = 1133161;
    const int64_t SPEND_H     = 1135986;

    uint8_t wallet[20]; mk_h160(wallet, 0x11);
    uint8_t ghost[32], other[32];
    mk_txid(ghost, 1133161); mk_txid(other, 1120005);

    idx_db_watch_add(db, wallet);

    idx_db_utxo_put(db, other, 0, wallet, OTHER_VALUE, 1120005);
    idx_db_utxo_put(db, ghost, 1, wallet, GHOST_VALUE, FUND_H);
    CHECK(balance(db, wallet) == INFLATED, "funded: balance == 167591.40528856 PEP (both outputs live)");

    CHECK(idx_db_utxo_spend(db, ghost, 1, SPEND_H) == 1, "spend of the 68725.79102400 output hits a watched row");
    CHECK(balance(db, wallet) == OTHER_VALUE, "after the spend: balance == 98865.61426456 PEP");
    CHECK(spent_at(db, ghost, 1) == SPEND_H, "spent_height recorded at 1135986");

    // The rollback replay / refold re-puts the SAME funding output. Pre-fix this
    // is where INSERT OR REPLACE wrote spent_height=NULL and the coin came back.
    idx_db_utxo_put(db, ghost, 1, wallet, GHOST_VALUE, FUND_H);
    CHECK(spent_at(db, ghost, 1) == SPEND_H, "re-put keeps spent_height (INSERT OR IGNORE, not REPLACE)");
    CHECK(balance(db, wallet) == OTHER_VALUE, "REGRESSION: balance stays 98865.61426456 PEP, not 167591.40528856");
    CHECK(balance(db, wallet) != INFLATED, "REGRESSION: the resurrected-output balance is NOT reachable");
    CHECK(utxo_count(db, wallet) == 1, "only one unspent output remains");

    // Ten more replays (a deep reorg refolds the same block many times).
    for (int i = 0; i < 10; i++) idx_db_utxo_put(db, ghost, 1, wallet, GHOST_VALUE, FUND_H);
    CHECK(balance(db, wallet) == OTHER_VALUE, "ten replays of the funding block change nothing");

    // A re-put must not silently rewrite value/height either.
    idx_db_utxo_put(db, other, 0, wallet, 1, 999);
    CHECK(balance(db, wallet) == OTHER_VALUE, "re-put of a LIVE output does not rewrite its value");

    // Only a reorg prune (the disconnect path) may take the funding row away —
    // that is precisely why OR IGNORE is safe: a conflicting insert is always the
    // SAME funding event, because a disconnected funding was DELETEd first.
    idx_db_block_prune_above(db, FUND_H - 1);
    CHECK(spent_at(db, ghost, 1) == -2, "prune above 1133160 DELETES the disconnected funding row");
    CHECK(utxo_count(db, wallet) == 1 && balance(db, wallet) == OTHER_VALUE,
          "…and leaves the older output (1120005) untouched");
    idx_db_utxo_put(db, ghost, 1, wallet, GHOST_VALUE, FUND_H);
    CHECK(spent_at(db, ghost, 1) == -1 && balance(db, wallet) == INFLATED,
          "after a GENUINE disconnect a re-fund is live again (the only route back to 167591.40528856)");
    CHECK(idx_db_utxo_spend(db, ghost, 1, SPEND_H) == 1 && balance(db, wallet) == OTHER_VALUE,
          "…and re-spending it returns to 98865.61426456 PEP");
}

// ── 2. idx_db_utxo_spend's return value (drives FoldCtx.wallet_touched) ──────
static void sec_spend_rc(sqlite3 *db) {
    printf("\n-- idx_db_utxo_spend return value (the wallet_touched signal) --\n");
    uint8_t w[20]; mk_h160(w, 0x22);
    uint8_t known[32], unknown[32];
    mk_txid(known, 7001); mk_txid(unknown, 7002);
    idx_db_watch_add(db, w);
    idx_db_utxo_put(db, known, 3, w, 500000000LL, 100);

    CHECK(idx_db_utxo_spend(db, unknown, 0, 101) == 0, "spend of an unknown outpoint returns 0");
    CHECK(idx_db_utxo_spend(db, known, 9, 101) == 0, "spend of a known txid at the WRONG vout returns 0");
    CHECK(idx_db_utxo_spend(db, known, 3, 101) == 1, "spend of a watched utxo returns 1");
    CHECK(spent_at(db, known, 3) == 101, "…and marks it spent");
    // Re-marking is what a replay does; it must still report "this block touched
    // the wallet", or the block stops being persisted on the next pass.
    CHECK(idx_db_utxo_spend(db, known, 3, 101) == 1, "re-spend of an already-spent row still returns 1 (replay-safe signal)");
    CHECK(spent_at(db, known, 3) == 101, "…and does not move the spend height");
    CHECK(balance(db, w) == 0, "spent output leaves no balance");

    // 0 must not be a side effect of an empty watch list or an empty table.
    uint8_t nobody[32]; mk_txid(nobody, 7003);
    CHECK(idx_db_utxo_spend(db, nobody, 0, 102) == 0, "spend against no matching row returns 0 (never a false 1)");
}

// ── 3. idx_db_utxo_min_unspent ───────────────────────────────────────────────
static void sec_min_unspent(const char *dir) {
    printf("\n-- idx_db_utxo_min_unspent (the wallet re-walk's floor) --\n");
    char path[512]; snprintf(path, sizeof path, "%s/minunspent.db", dir);
    sqlite3 *db = idx_db_open(path);
    if (!db) { CHECK(0, "open min-unspent db"); return; }
    uint8_t w[20]; mk_h160(w, 0x33);
    idx_db_watch_add(db, w);

    CHECK(idx_db_utxo_min_unspent(db) == -1, "empty table → -1");

    uint8_t t1[32], t2[32], t3[32];
    mk_txid(t1, 8001); mk_txid(t2, 8002); mk_txid(t3, 8003);
    idx_db_utxo_put(db, t2, 0, w, 10, 500);
    CHECK(idx_db_utxo_min_unspent(db) == 500, "single unspent row → its height");
    idx_db_utxo_put(db, t1, 0, w, 10, 100);
    idx_db_utxo_put(db, t3, 0, w, 10, 900);
    CHECK(idx_db_utxo_min_unspent(db) == 100, "minimum over three unspent rows");

    idx_db_utxo_spend(db, t1, 0, 1000);
    CHECK(idx_db_utxo_min_unspent(db) == 500, "a spent row is ignored (the lowest one)");
    CHECK(idx_db_utxo_min_unspent(db) != 100, "…the spent height is not what comes back");

    idx_db_utxo_spend(db, t2, 0, 1001);
    CHECK(idx_db_utxo_min_unspent(db) == 900, "only unspent row is the HIGHEST → that height");

    // Re-fund below everything: the only unspent row is now the lowest.
    idx_db_utxo_spend(db, t3, 0, 1002);
    CHECK(idx_db_utxo_min_unspent(db) == -1, "all rows spent → -1 (never 0, never a spent height)");
    uint8_t t0[32]; mk_txid(t0, 8000);
    idx_db_utxo_put(db, t0, 0, w, 10, 7);
    CHECK(idx_db_utxo_min_unspent(db) == 7, "only unspent row is the LOWEST → that height");

    // Rows for a DIFFERENT watched address count too — the re-walk floor spans
    // every watched address, so a second wallet's older coin must pull it down.
    uint8_t w2[20]; mk_h160(w2, 0x34);
    uint8_t t4[32]; mk_txid(t4, 8004);
    idx_db_watch_add(db, w2);
    idx_db_utxo_put(db, t4, 0, w2, 10, 3);
    CHECK(idx_db_utxo_min_unspent(db) == 3, "spans all watched addresses, not just one");

    // Height 0 is a legal (if unlikely) funding height and must not read as "none".
    uint8_t t5[32]; mk_txid(t5, 8005);
    idx_db_utxo_put(db, t5, 0, w, 10, 0);
    CHECK(idx_db_utxo_min_unspent(db) == 0, "a genuine height-0 unspent row returns 0, distinct from -1");

    idx_db_close(db);
    unlink(path);
}

// ── 4. one-shot meta flags ───────────────────────────────────────────────────
static void sec_flags(const char *dir) {
    printf("\n-- idx_db_flag_get / idx_db_flag_set (the one-shot re-walk marker) --\n");
    char path[512]; snprintf(path, sizeof path, "%s/flags.db", dir);
    sqlite3 *db = idx_db_open(path);
    if (!db) { CHECK(0, "open flags db"); return; }

    CHECK(idx_db_flag_get(db, "wallet_rewalk_v1") == 0, "fresh db: the flag reads FALSE (the re-walk must not be skipped)");
    CHECK(idx_db_flag_get(db, "some_other_flag") == 0, "an unset flag reads FALSE");

    idx_db_flag_set(db, "wallet_rewalk_v1");
    CHECK(idx_db_flag_get(db, "wallet_rewalk_v1") != 0, "set → get round-trips TRUE");
    CHECK(idx_db_flag_get(db, "some_other_flag") == 0, "setting one flag does not set another");

    idx_db_flag_set(db, "wallet_rewalk_v1");                 // idempotent set
    CHECK(idx_db_flag_get(db, "wallet_rewalk_v1") != 0, "re-setting an already-set flag keeps it TRUE");

    idx_db_close(db);
    sqlite3 *db2 = idx_db_open(path);
    if (!db2) { CHECK(0, "reopen flags db"); return; }
    CHECK(idx_db_flag_get(db2, "wallet_rewalk_v1") != 0,
          "DURABLE across close/reopen (the re-walk cannot re-run forever)");
    CHECK(idx_db_flag_get(db2, "some_other_flag") == 0, "an unset flag is still FALSE after reopen");
    idx_db_close(db2);

    // A brand-new db must NOT inherit the flag.
    char p2[512]; snprintf(p2, sizeof p2, "%s/flags2.db", dir);
    sqlite3 *db3 = idx_db_open(p2);
    CHECK(db3 && idx_db_flag_get(db3, "wallet_rewalk_v1") == 0, "a different db starts unflagged");
    idx_db_close(db3);
    unlink(path); unlink(p2);
}

// ── 5. balance summation as a property over seeded-random sequences ──────────
#define POOL 512
static void sec_property(const char *dir) {
    printf("\n-- balance summation property (seeded random put/spend sequences) --\n");
    char path[512]; snprintf(path, sizeof path, "%s/prop.db", dir);
    sqlite3 *db = idx_db_open(path);
    if (!db) { CHECK(0, "open property db"); return; }
    uint8_t w[20]; mk_h160(w, 0x44);
    idx_db_watch_add(db, w);

    // The independent model: what the test believes the wallet holds.
    static int64_t val[POOL];
    static int8_t  live[POOL];     // 0 = never put, 1 = unspent, 2 = spent
    int64_t total = 0;

    int mismatches = 0, neg = 0, rc_bad = 0, edge_hits = 0;
    const int OPS = 6000;
    g_rng = 0x5EEDF00DCAFEBABEULL;

    for (int op = 0; op < OPS; op++) {
        uint64_t r = rnd64();
        int i = (int)(r % POOL);
        int action = (int)((r >> 20) % 3);          // 0,1 = put · 2 = spend

        if (action != 2) {
            int64_t v;
            if ((r >> 40) % 64 == 0) {
                // near-2^63 draw: push the running total right up to INT64_MAX
                // so a 64-bit overflow anywhere in the sum path would show.
                int64_t head = INT64_MAX - total;
                v = (int64_t)(rnd64() >> 2);        // [0, 2^62)
                v += (int64_t)1 << 62;              // → [2^62, 2^63-1] — fits exactly
                if (v > head) v = head;             // clamp: the model must stay exact
                if (v > 0) edge_hits++;
            } else {
                v = (int64_t)(rnd64() % 1000000000000ULL);
                if (v > INT64_MAX - total) v = INT64_MAX - total;
            }
            if (v < 0) v = 0;
            uint8_t txid[32]; mk_txid(txid, (uint32_t)i);
            idx_db_utxo_put(db, txid, 0, w, v, 1000 + i);
            if (live[i] == 0) { val[i] = v; live[i] = 1; total += v; }
            // live[i] != 0 → INSERT OR IGNORE keeps the standing row: model unchanged.
        } else {
            uint8_t txid[32]; mk_txid(txid, (uint32_t)i);
            int hit = idx_db_utxo_spend(db, txid, 0, 900000 + op);
            int want = live[i] != 0;                // a row exists ⇒ UPDATE matched it
            if (hit != want) rc_bad++;
            if (live[i] == 1) { total -= val[i]; live[i] = 2; }
        }

        if (total < 0) neg++;
        if (balance(db, w) != total) mismatches++;
    }

    CHECK(mismatches == 0, "the db's unspent sum equals the independently-kept total at EVERY step");
    CHECK(rc_bad == 0, "idx_db_utxo_spend's return value matches the model at every step");
    CHECK(neg == 0, "the running total never goes negative");
    CHECK(edge_hits > 0, "the sequence actually exercised values near 2^63");
    CHECK(balance(db, w) == total, "final balance matches the model");

    // A hard overflow probe, independent of the random walk: two rows that
    // together sit exactly at INT64_MAX.
    sqlite3 *db2 = idx_db_open(":memory:");
    uint8_t w2[20]; mk_h160(w2, 0x45);
    uint8_t a[32], b[32]; mk_txid(a, 90001); mk_txid(b, 90002);
    idx_db_watch_add(db2, w2);
    idx_db_utxo_put(db2, a, 0, w2, INT64_MAX - 1, 1);
    idx_db_utxo_put(db2, b, 0, w2, 1, 2);
    CHECK(balance(db2, w2) == INT64_MAX, "a wallet summing to exactly INT64_MAX reads back exactly");
    idx_db_utxo_spend(db2, a, 0, 3);
    CHECK(balance(db2, w2) == 1, "…and drops to 1 when the huge output is spent");
    idx_db_close(db2);

    idx_db_close(db);
    unlink(path);
}

// ── 6. idempotence: applying the same block twice changes nothing ────────────
// A "block" here is the wallet-relevant effect of a block's txs: some outputs
// paying the wallet, some inputs spending earlier ones — exactly what
// sync.c's tx_cb does. A refold/replay reapplies it verbatim.
static void apply_block(sqlite3 *db, const uint8_t w[20], int64_t height,
                        const uint32_t *fund_ix, const int64_t *fund_v, int n_fund,
                        const uint32_t *spend_ix, int n_spend) {
    for (int i = 0; i < n_fund; i++) {
        uint8_t t[32]; mk_txid(t, fund_ix[i]);
        idx_db_utxo_put(db, t, 0, w, fund_v[i], height);
    }
    for (int i = 0; i < n_spend; i++) {
        uint8_t t[32]; mk_txid(t, spend_ix[i]);
        idx_db_utxo_spend(db, t, 0, height);
    }
}
static void sec_idempotence(const char *dir) {
    printf("\n-- idempotence: replaying the same block/tx changes nothing --\n");
    char path[512]; snprintf(path, sizeof path, "%s/idem.db", dir);
    sqlite3 *db = idx_db_open(path);
    if (!db) { CHECK(0, "open idempotence db"); return; }
    uint8_t w[20]; mk_h160(w, 0x55);
    idx_db_watch_add(db, w);

    const uint32_t f1[] = { 100, 101, 102 };
    const int64_t  v1[] = { 500000000LL, 1234567890LL, 999999999999LL };
    const uint32_t f2[] = { 103 };
    const int64_t  v2[] = { 42LL };
    const uint32_t s2[] = { 101 };

    apply_block(db, w, 200, f1, v1, 3, NULL, 0);
    apply_block(db, w, 201, f2, v2, 1, s2, 1);

    uint64_t fp = utxo_fingerprint(db);
    int64_t  bal = balance(db, w);
    int64_t  mh  = idx_db_utxo_min_unspent(db);
    int      cnt = utxo_count(db, w);
    CHECK(bal == 500000000LL + 999999999999LL + 42LL, "two blocks folded: balance is the sum of unspent outputs");

    apply_block(db, w, 200, f1, v1, 3, NULL, 0);          // replay block 200
    CHECK(utxo_fingerprint(db) == fp, "replaying block 200 leaves the utxos table byte-identical");
    apply_block(db, w, 201, f2, v2, 1, s2, 1);            // replay block 201
    CHECK(utxo_fingerprint(db) == fp, "replaying block 201 leaves the utxos table byte-identical");

    for (int i = 0; i < 5; i++) {                          // replay both, five times
        apply_block(db, w, 200, f1, v1, 3, NULL, 0);
        apply_block(db, w, 201, f2, v2, 1, s2, 1);
    }
    CHECK(utxo_fingerprint(db) == fp, "five full replays leave the utxos table byte-identical");
    CHECK(balance(db, w) == bal, "…balance unchanged");
    CHECK(idx_db_utxo_min_unspent(db) == mh, "…min-unspent unchanged");
    CHECK(utxo_count(db, w) == cnt, "…unspent row count unchanged");

    // Out-of-order replay (the substrate iterates ascending, but prove the
    // effect does not depend on it) must also converge to the same table.
    apply_block(db, w, 201, f2, v2, 1, s2, 1);
    apply_block(db, w, 200, f1, v1, 3, NULL, 0);
    CHECK(utxo_fingerprint(db) == fp, "replaying the two blocks in reverse order converges identically");

    idx_db_close(db);
    unlink(path);
}

// ── main ─────────────────────────────────────────────────────────────────────
static void rm_db(const char *path) {
    char b[600];
    unlink(path);
    snprintf(b, sizeof b, "%s-wal", path); unlink(b);
    snprintf(b, sizeof b, "%s-shm", path); unlink(b);
    snprintf(b, sizeof b, "%s-journal", path); unlink(b);
}

// A marked peer known only from inbound (last_good=0) whose dial failed must
// sit out the retry window, not re-seat every serve tick.
static void sec_mesh_nat_backoff(const char *dir) {
    char p[600]; snprintf(p, sizeof p, "%s/meshbk.db", dir);
    sqlite3 *db = idx_db_open(p);
    CHECK(db != NULL, "mesh backoff: open db");
    if (!db) return;
    char pool[8][80]; int64_t now = 1800000000;
    idx_db_peer_touch_agent(db, "74.179.67.173", 33874, "/pepenet-dnsd:0.1/", now - 100);
    int n = idx_db_peers_dnet_confirmed(db, pool, 8, now - 600);
    CHECK(n == 1, "mesh backoff: inbound-marked peer is a candidate before any dial");
    idx_db_peer_tried(db, "74.179.67.173:33874", now);
    n = idx_db_peers_dnet_confirmed(db, pool, 8, now - 600);
    CHECK(n == 0, "mesh backoff: failed dial of last_good=0 marked peer sits out DIAL_RETRY_S");
    n = idx_db_peers_dnet_confirmed(db, pool, 8, now + 1);
    CHECK(n == 1, "mesh backoff: candidate again after the window");
    idx_db_close(db); rm_db(p);
}

int main(void) {
    char dir[] = "/tmp/idx_test_db_XXXXXX";
    if (!mkdtemp(dir)) { fprintf(stderr, "mkdtemp failed\n"); return 1; }
    printf("temp db dir: %s\n", dir);

    char main_db[512]; snprintf(main_db, sizeof main_db, "%s/wallet.db", dir);
    sqlite3 *db = idx_db_open(main_db);
    CHECK(db != NULL, "open a temporary wallet db");
    if (db) {
        sec_ghost(db);
        sec_spend_rc(db);
        idx_db_close(db);
    }
    sec_min_unspent(dir);
    sec_flags(dir);
    sec_property(dir);
    sec_idempotence(dir);
    sec_mesh_nat_backoff(dir);

    // teardown: the temp tree goes away entirely.
    rm_db(main_db);
    { const char *leftovers[] = { "minunspent.db", "flags.db", "flags2.db", "prop.db", "idem.db" };
      for (unsigned i = 0; i < sizeof leftovers / sizeof leftovers[0]; i++) {
          char p[600]; snprintf(p, sizeof p, "%s/%s", dir, leftovers[i]); rm_db(p);
      } }
    if (rmdir(dir) != 0) fprintf(stderr, "warning: could not remove %s\n", dir);

    printf(g_fail ? "\ntest_db: FAIL\n" : "\ntest_db: all ok\n");
    return g_fail;
}
