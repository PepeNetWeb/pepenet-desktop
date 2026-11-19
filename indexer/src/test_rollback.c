// test_rollback.c — #4: the reorg rollback is ONE transaction, and replays from
// the newest rollback checkpoint instead of from activation.
//
// Real signed carrier blocks (commit/claim/TRANSFER_NAME, test_chain.c
// chain_mkblocks_rb) folded through the production `index` path into sqlite
// dbs in a mkdtemp'd /tmp dir (removed at the end). Every post-reorg state is
// compared — names/commits/muts/epochs rows AND sm_state_digest — with a FRESH
// fold of the winning branch, so a checkpoint can never change state_digest.
//   A. a reorg that REMOVES claims/transfers, and one that CHANGES a transfer
//   B. repeated reorgs (a→b→a→c→a) on one db, checkpoints bounded
//   C. a crash (SIGKILL) inside the rollback transaction, before COMMIT: the db
//      is exactly the pre-reorg db; recovery + retry converges
//   D. a reorg across checkpoints: the replay starts at the checkpoint (proved by
//      deleting the raw blocks under it), a corrupt checkpoint falls back, and
//      with checkpoints on or off the result is identical
#include "sm.h"
#include "db.h"
#include "indexer.h"
#include "oracle_feed.h"
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include "dbcheck.h"

int chain_mkblocks_rb(const char *dir, char pfx, int fork, int kind, int nblk);
extern void (*idx_sync_rollback_test_hook)(sqlite3 *db, int64_t to_height);

static int g_fail;
#define CHECK(cond, name) do { \
    if (cond) printf("ok   %s\n", name); \
    else      { printf("FAIL %s\n", name); g_fail = 1; } \
} while (0)

#define NB 40
static char g_dir[512];

static void rm_db(const char *path) {
    char b[700]; unlink(path);
    snprintf(b, sizeof b, "%s-wal", path); unlink(b);
    snprintf(b, sizeof b, "%s-shm", path); unlink(b);
    snprintf(b, sizeof b, "%s-journal", path); unlink(b);
}
// index heights [from..to] of branch pfx into dbpath
static int run_br(const char *dbpath, char pfx, int from, int to) {
    char *argv[8 + NB]; char paths[NB][600]; int argc = 0;
    argv[argc++] = (char *)"indexerd"; argv[argc++] = (char *)"index";
    argv[argc++] = (char *)dbpath; argv[argc++] = (char *)"0";
    argv[argc++] = (char *)"--coin"; argv[argc++] = (char *)"regtest";
    for (int h = from; h <= to; h++) { snprintf(paths[h], sizeof paths[0], "%s/%c%02d.bin", g_dir, pfx, h); argv[argc++] = paths[h]; }
    fflush(stdout);
    int saved = dup(1), dn = open("/dev/null", O_WRONLY);
    if (dn >= 0) { dup2(dn, 1); close(dn); }
    int rc = indexer_main(argc, argv);
    fflush(stdout); if (saved >= 0) { dup2(saved, 1); close(saved); }
    return rc;
}
static int fresh(const char *dbpath, int64_t every) {
    rm_db(dbpath); sqlite3 *db = idx_db_open(dbpath); if (!db) return 0;
    idx_db_ckpt_set_every(db, every); idx_db_close(db); return 1;
}
// fold branch pfx 0..to in chunks of 10 (each chunk ends in a projection)
static int sync_br(const char *dbpath, char pfx, int from, int to) {
    for (int a = from; a <= to; a = (a / 10 + 1) * 10) {
        int b = (a / 10) * 10 + 9; if (b > to) b = to;
        if (run_br(dbpath, pfx, a, b)) return 0;
    }
    return 1;
}

typedef struct { sqlite3 *db; SmState *s; OracleFeed *o; } Fold;
static int fold_open(Fold *f, const char *dbpath) {
    memset(f, 0, sizeof *f);
    f->db = idx_db_open(dbpath); if (!f->db) return 0;
    f->s = sm_new((uint64_t)idx_db_get_activation(f->db, 0));
    if (!idx_db_get_onchain_magic(f->db, f->s->onchain_magic)) idx_coin_onchain_magic("pep", f->s->onchain_magic);
    idx_db_load_state(f->db, f->s);
    f->s->cur_height = idx_db_projected_height(f->db);
    f->o = oracle_new(); idx_db_oracle_warm(f->db, f->o);
    return 1;
}
static void fold_close(Fold *f) { oracle_free(f->o); sm_free(f->s); idx_db_close(f->db); memset(f, 0, sizeof *f); }

// what the sync loop does on a reorg: rollback, then stamp the cursor
static int reorg_to(const char *dbpath, int64_t fork) {
    Fold f; if (!fold_open(&f, dbpath)) return 0;
    int ok = idx_sync_rollback(&f.s, f.db, f.o, (int64_t)f.s->activation_height, fork);
    if (ok) { uint8_t tip[32]; memset(tip, 0, 32); idx_db_block_get(f.db, fork, tip); idx_db_save_sync(f.db, fork, tip); }
    fold_close(&f); return ok;
}

// sha256 over the ordered rows of one query (stable fingerprint of a table)
static void q_hash(sqlite3 *db, const char *sql, uint8_t out[32]) {
    SHA256_CTX c; sha256_init(&c); sqlite3_stmt *st;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW)
            for (int i = 0; i < sqlite3_column_count(st); i++) {
                int n = sqlite3_column_bytes(st, i); const void *b = sqlite3_column_blob(st, i);
                uint8_t tag = (uint8_t)sqlite3_column_type(st, i);
                sha256_update(&c, &tag, 1); sha256_update(&c, (const uint8_t *)&n, sizeof n);
                if (b && n) sha256_update(&c, b, (unsigned)n);
            }
        sqlite3_finalize(st);
    }
    sha256_final(&c, out);
}
typedef struct { uint8_t dig[32], names[32], commits[32], muts[32], epochs[32], blocks[32]; int64_t proj, cur; } Snap;
static int snap(const char *dbpath, Snap *z) {
    memset(z, 0, sizeof *z); Fold f; if (!fold_open(&f, dbpath)) return 0;
    sm_state_digest(f.s, z->dig);
    q_hash(f.db, "SELECT * FROM names ORDER BY name", z->names);
    q_hash(f.db, "SELECT * FROM commits ORDER BY commitment", z->commits);
    q_hash(f.db, "SELECT * FROM muts ORDER BY owner", z->muts);
    q_hash(f.db, "SELECT * FROM epochs ORDER BY name,start_height", z->epochs);
    q_hash(f.db, "SELECT height,hash,time FROM blocks ORDER BY height", z->blocks);
    z->proj = idx_db_projected_height(f.db);
    uint8_t t[32]; if (!idx_db_load_sync(f.db, &z->cur, t)) z->cur = -9;
    fold_close(&f); return 1;
}
static int same_state(const Snap *a, const Snap *b) {
    return !memcmp(a->dig, b->dig, 32) && !memcmp(a->names, b->names, 32) && !memcmp(a->commits, b->commits, 32)
        && !memcmp(a->muts, b->muts, 32) && !memcmp(a->epochs, b->epochs, 32);
}
static int owner_byte(const char *dbpath, const char *name) {     // first owner byte, -1 if absent
    sqlite3 *db = idx_db_open(dbpath); IdxNameRow r; int v = -1;
    if (db && idx_db_name_row(db, name, &r)) v = r.owner[0];
    idx_db_close(db); return v;
}
static int check_clean(const char *dbpath) {
    IdxCheckReport r; FILE *nul = fopen("/dev/null", "w");
    int e = idx_db_check(dbpath, NULL, nul, &r); if (nul) fclose(nul);
    return e == 0 && r.warnings == 0;
}
static int ckpts(const char *dbpath) { sqlite3 *db = idx_db_open(dbpath); int n = db ? idx_db_ckpt_count(db) : -1; idx_db_close(db); return n; }
static int exec_sql(const char *dbpath, const char *sql) {
    sqlite3 *db = idx_db_open(dbpath); if (!db) return 0;
    int ok = sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK; idx_db_close(db); return ok;
}

// branches: a = main (kind 2, fork NB), b = fork 3 remove, c = fork 15 remove,
// d = fork 15 change transfers, e = fork 25 remove (bob's transfer at 22 stays)
typedef struct { char pfx; int fork; int kind; } Br;
static const Br BR[] = { { 'a', NB, 2 }, { 'b', 3, 0 }, { 'c', 15, 0 }, { 'd', 15, 1 }, { 'e', 25, 0 }, { 'f', 9, 2 } };
#define NBR ((int)(sizeof BR / sizeof BR[0]))
static Snap g_ref[128];
static const Snap *ref(char pfx) { return &g_ref[(int)pfx]; }

static int reorg_and_connect(const char *dbp, const Br *b) {
    return reorg_to(dbp, b->fork) && sync_br(dbp, b->pfx, b->fork + 1, NB - 1);
}

static void sec_claims(void) {
    printf("\n-- A: a reorg that removes / changes claims and transfers --\n");
    char dbp[600]; snprintf(dbp, sizeof dbp, "%s/A.db", g_dir);
    int ok_all = 1;
    for (int i = 1; i < NBR - 1; i++) {
        const Br *b = &BR[i];
        if (!fresh(dbp, 5) || !sync_br(dbp, 'a', 0, NB - 1)) { ok_all = 0; continue; }
        if (!reorg_to(dbp, b->fork)) { ok_all = 0; continue; }
        if (!sync_br(dbp, b->pfx, b->fork + 1, NB - 1)) { ok_all = 0; continue; }
        Snap z; snap(dbp, &z);
        char nm[200]; snprintf(nm, sizeof nm, "reorg a→%c (fork %d, %s): state + digest == fresh sync of %c, cursor %d",
                               b->pfx, b->fork, b->kind == 1 ? "transfer above fork changed" : b->fork < 22 ? "claims/transfers above fork removed" : "blocks replaced, no action above fork", b->pfx, NB - 1);
        int ok = same_state(&z, ref(b->pfx)) && z.cur == NB - 1 && z.proj == NB - 1 && check_clean(dbp);
        CHECK(ok, nm); ok_all &= ok;
    }
    // spot-check what the user would see
    if (fresh(dbp, 5) && sync_br(dbp, 'a', 0, NB - 1)) {
        CHECK(owner_byte(dbp, "bob") == 0x5A && owner_byte(dbp, "alice") == 0x5A, "main branch: alice and bob transferred to T");
        reorg_and_connect(dbp, &BR[1]);
        CHECK(owner_byte(dbp, "bob") == -1 && owner_byte(dbp, "alice") != 0x5A && owner_byte(dbp, "alice") >= 0,
              "after the fork-3 reorg: bob's claim is gone, alice's transfer is undone");
        Br bd = BR[3]; bd.fork = 3;           // b and d share only heights <= 3
        reorg_and_connect(dbp, &bd);
        CHECK(owner_byte(dbp, "bob") == 0x6B && owner_byte(dbp, "alice") == 0x5A, "after the fork-15 change reorg: bob's transfer (h22) now goes to T', alice's (h12, below the fork) stays at T");
    }
    (void)ok_all;
}

static void sec_repeat(void) {
    printf("\n-- B: repeated reorgs on one db --\n");
    char dbp[600]; snprintf(dbp, sizeof dbp, "%s/B.db", g_dir);
    if (!fresh(dbp, 5) || !sync_br(dbp, 'a', 0, NB - 1)) { CHECK(0, "main fold"); return; }
    const Br *seq[] = { &BR[2], &BR[0], &BR[4], &BR[1], &BR[3], &BR[0], &BR[5], &BR[4], &BR[0] };
    // a fork from branch X back to a: the fork point is min(forks) on the path
    int ok = 1, bounded = 1, nseq = (int)(sizeof seq / sizeof seq[0]); char cur = 'a'; int curfork = NB;
    for (int i = 0; i < nseq; i++) {
        const Br *b = seq[i];
        int fork = b->fork < curfork ? b->fork : curfork;
        if (b->pfx == 'a') fork = curfork;
        if (!reorg_to(dbp, fork) || !sync_br(dbp, b->pfx, fork + 1, NB - 1)) { ok = 0; break; }
        Snap z; snap(dbp, &z);
        if (!same_state(&z, ref(b->pfx)) || z.cur != NB - 1 || !check_clean(dbp)) { ok = 0; printf("     diverged at step %d (%c→%c)\n", i, cur, b->pfx); }
        if (ckpts(dbp) > 4) bounded = 0;
        cur = b->pfx; curfork = b->pfx == 'a' ? NB : b->fork;
    }
    CHECK(ok, "9 consecutive reorgs (a→c→a→e→b→d→a→f→e→a): every step == fresh sync of the winner");
    CHECK(bounded, "checkpoint rows never exceed 4");
    // same fork twice in a row (rollback onto a state that was itself rolled back)
    ok = reorg_to(dbp, 15) && reorg_to(dbp, 15) && reorg_to(dbp, 9) && sync_br(dbp, 'a', 10, NB - 1);
    Snap z; snap(dbp, &z);
    CHECK(ok && same_state(&z, ref('a')), "back-to-back rollbacks (15, 15, 9) then reconnect == fresh sync");
}

static void crash_hook(sqlite3 *db, int64_t h) { (void)db; (void)h; raise(SIGKILL); }
static int rollback_killed(const char *dbpath, int64_t fork_h) {
    fflush(stdout); fflush(stderr);
    pid_t pid = fork();
    if (pid == 0) {
        idx_sync_rollback_test_hook = crash_hook;
        reorg_to(dbpath, fork_h); _exit(0);
    }
    int st = 0; waitpid(pid, &st, 0);
    return WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL;
}
static void sec_crash(void) {
    printf("\n-- C: crash inside the rollback transaction --\n");
    char dbp[600]; snprintf(dbp, sizeof dbp, "%s/C.db", g_dir);
    int64_t forks[] = { 3, 15, 25, 29, 38 };
    int all = 1, kills = 0, pre_ok = 1;
    for (int i = 0; i < 5; i++) {
        if (!fresh(dbp, 5) || !sync_br(dbp, 'a', 0, NB - 1)) { all = 0; continue; }
        Snap before; snap(dbp, &before); int nck = ckpts(dbp);
        kills += rollback_killed(dbp, forks[i]);
        Snap after; snap(dbp, &after);
        // nothing the rollback did may be visible: blocks, projection, cursor, checkpoints
        if (!same_state(&before, &after) || memcmp(before.blocks, after.blocks, 32) || after.proj != NB - 1
            || after.cur != NB - 1 || ckpts(dbp) != nck || !check_clean(dbp)) pre_ok = 0;
        // the node restarts and the reorg is retried (recover is a no-op: db consistent)
        sqlite3 *db = idx_db_open(dbp); int64_t h = 0; uint8_t tip[32]; static const uint8_t z0[32];
        idx_db_load_sync(db, &h, tip); int rec = idx_sync_recover(db, 0, z0, &h, tip); idx_db_close(db);
        const Br *b = forks[i] == 3 ? &BR[1] : forks[i] == 15 ? &BR[3] : forks[i] == 25 ? &BR[4] : NULL;
        char px = b ? b->pfx : 'a';
        if (rec != 0 || !reorg_to(dbp, forks[i]) || !sync_br(dbp, px, (int)forks[i] + 1, NB - 1)) { all = 0; continue; }
        Snap z; snap(dbp, &z);
        if (!same_state(&z, ref(px)) || !check_clean(dbp)) all = 0;
    }
    CHECK(kills == 5, "5 rollbacks SIGKILLed after replay+projection, before COMMIT");
    CHECK(pre_ok, "after each kill the db is the pre-reorg db (blocks, projection, digest, cursor, checkpoints), check clean");
    CHECK(all, "restart: recover is a no-op, the retried reorg converges on the winner's fresh-sync state");
    // in-process failure: COMMIT can't happen if the replay substrate is broken → RAM restored
    if (fresh(dbp, 5) && sync_br(dbp, 'a', 0, NB - 1)) {
        exec_sql(dbp, "DELETE FROM rb_ckpt; UPDATE raw_blocks SET raw=x'00' WHERE height=1");
        Snap before; snap(dbp, &before);
        Fold f; fold_open(&f, dbp);
        uint8_t d0[32]; sm_state_digest(f.s, d0);
        int rc = idx_sync_rollback(&f.s, f.db, f.o, 0, 20);
        uint8_t d1[32]; sm_state_digest(f.s, d1);
        int ram_ok = !memcmp(d0, d1, 32) && f.s->cur_height == NB - 1;
        fold_close(&f);
        Snap after; snap(dbp, &after);
        CHECK(rc == 0 && ram_ok && same_state(&before, &after) && !memcmp(before.blocks, after.blocks, 32),
              "a failing replay returns 0, rolls the db back, and reloads the pre-rollback state into RAM");
    }
}

static void sec_ckpt(void) {
    printf("\n-- D: reorg across checkpoints --\n");
    char dbp[600], dbn[600]; snprintf(dbp, sizeof dbp, "%s/D.db", g_dir); snprintf(dbn, sizeof dbn, "%s/Dn.db", g_dir);
    if (!fresh(dbp, 5) || !sync_br(dbp, 'a', 0, NB - 1)) { CHECK(0, "main fold"); return; }
    CHECK(ckpts(dbp) == 4, "checkpoints taken at the chunk projections (9,19,29,39)");
    // with checkpoints off, the same rollback is the old full replay
    if (!fresh(dbn, 0) || !sync_br(dbn, 'a', 0, NB - 1)) { CHECK(0, "no-ckpt fold"); return; }
    CHECK(ckpts(dbn) == 0, "rb_ckpt_every=0 takes no checkpoints");
    int eq = 1;
    for (int64_t to = 0; to < NB; to += 3) {
        char a[700], b[700]; snprintf(a, sizeof a, "%s.%lld", dbp, (long long)to); snprintf(b, sizeof b, "%s.%lld", dbn, (long long)to);
        char cmd[3000]; snprintf(cmd, sizeof cmd, "cp %s %s && cp %s %s", dbp, a, dbn, b);
        if (system(cmd) != 0) { eq = 0; continue; }
        reorg_to(a, to); reorg_to(b, to);
        Snap x, y; snap(a, &x); snap(b, &y);
        if (!same_state(&x, &y) || x.proj != to) { eq = 0; printf("     differ at rollback to %lld\n", (long long)to); }
        rm_db(a); rm_db(b);
    }
    CHECK(eq, "rollback to every 3rd height: checkpoint replay == full replay (digest + all rows)");
    // proof the checkpoint is USED: drop the raw blocks under checkpoint 19 —
    // a full replay would lose alice/bob (claims at 1/5), a checkpoint replay can't.
    {
        char a[700]; snprintf(a, sizeof a, "%s.used", dbp); char cmd[1400]; snprintf(cmd, sizeof cmd, "cp %s %s", dbp, a);
        Snap pre; snap(dbp, &pre);
        int ok = system(cmd) == 0 && exec_sql(a, "DELETE FROM raw_blocks WHERE height<=19") && reorg_to(a, 25);
        ok = ok && sync_br(a, 'e', 26, NB - 1);
        Snap z; snap(a, &z);
        CHECK(ok && same_state(&z, ref('e')), "rollback to 25 replays from checkpoint 19 (raw blocks <=19 not needed), == fresh sync of e");
        CHECK(ckpts(a) <= 4, "checkpoints above the fork pruned, bounded");
        rm_db(a);
        // the same with no checkpoints must NOT match: the claims are gone
        snprintf(a, sizeof a, "%s.nock", dbp); snprintf(cmd, sizeof cmd, "cp %s %s", dbp, a);
        ok = system(cmd) == 0 && exec_sql(a, "DELETE FROM raw_blocks WHERE height<=19; DELETE FROM rb_ckpt") && reorg_to(a, 25);
        snap(a, &z);
        CHECK(ok && memcmp(z.dig, ref('e')->dig, 32) != 0, "control: same rollback without checkpoints diverges (the shortcut is real)");
        rm_db(a);
        (void)pre;
    }
    // a corrupt / tampered checkpoint is rejected (digest mismatch) → next older one
    {
        char a[700]; snprintf(a, sizeof a, "%s.bad", dbp); char cmd[1400]; snprintf(cmd, sizeof cmd, "cp %s %s", dbp, a);
        int ok = system(cmd) == 0
              && exec_sql(a, "UPDATE rb_ckpt SET state=substr(state,1,length(state)-1)||x'01' WHERE height=19;"
                             "UPDATE rb_ckpt SET digest=zeroblob(32) WHERE height=29")
              && reorg_to(a, 33) && sync_br(a, 'a', 34, NB - 1);
        Snap z; snap(a, &z);
        CHECK(ok && same_state(&z, ref('a')), "tampered checkpoints 19/29 rejected; replay from 9 still == fresh sync");
        rm_db(a);
    }
    // checkpoint exactly AT the fork height, and fork below the oldest checkpoint
    {
        int ok = reorg_to(dbp, 19) && sync_br(dbp, 'a', 20, NB - 1);
        Snap z; snap(dbp, &z); ok = ok && same_state(&z, ref('a'));
        ok = ok && reorg_to(dbp, 3) && sync_br(dbp, 'b', 4, NB - 1);
        snap(dbp, &z); ok = ok && same_state(&z, ref('b'));
        CHECK(ok, "fork AT a checkpoint (19) and below every checkpoint (3) both == fresh sync");
    }
    // refold voids checkpoints (rules may have changed)
    {
        char *argv[] = { (char *)"indexerd", (char *)"refold", dbp, (char *)"--coin", (char *)"regtest", NULL };
        fflush(stdout); int saved = dup(1), dn = open("/dev/null", O_WRONLY); if (dn >= 0) { dup2(dn, 1); close(dn); }
        int rc = indexer_main(5, argv);
        fflush(stdout); if (saved >= 0) { dup2(saved, 1); close(saved); }
        Snap z; snap(dbp, &z);
        CHECK(rc == 0 && ckpts(dbp) <= 1 && same_state(&z, ref('b')), "refold wipes old checkpoints, state unchanged");
    }
}

// run fn with stderr captured to path; returns fn's result
static int capture_err(const char *path, int (*fn)(void *), void *arg) {
    fflush(stderr); int saved = dup(2), fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) { dup2(fd, 2); close(fd); }
    int rc = fn(arg);
    fflush(stderr); if (saved >= 0) { dup2(saved, 2); close(saved); }
    return rc;
}
static int file_has(const char *path, const char *needle) {
    FILE *f = fopen(path, "r"); if (!f) return 0;
    char buf[8192]; size_t n = fread(buf, 1, sizeof buf - 1, f); fclose(f); buf[n] = 0;
    return strstr(buf, needle) != NULL;
}
typedef struct { const char *db; int64_t fork; } ReorgArg;
static int reorg_cb(void *a) { ReorgArg *r = a; return reorg_to(r->db, r->fork); }
static int64_t q_i64(const char *dbpath, const char *sql) {
    sqlite3 *db = idx_db_open(dbpath); int64_t v = -999; sqlite3_stmt *st;
    if (db && sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    idx_db_close(db); return v;
}

static void sec_polish(void) {
    printf("\n-- E: checkpoint format / cap / wipe / prune / seed / reject log --\n");
    char dbp[600], a[700], cmd[1600], log[700];
    snprintf(dbp, sizeof dbp, "%s/E.db", g_dir); snprintf(log, sizeof log, "%s/E.log", g_dir);
    if (!fresh(dbp, 5) || !sync_br(dbp, 'a', 0, NB - 1)) { CHECK(0, "E main fold"); return; }
    // 1. format version
    CHECK(q_i64(dbp, "SELECT COUNT(*) FROM rb_ckpt WHERE substr(state,1,4)=x'01000000'") == 4,
          "every checkpoint blob starts with u32 LE format_ver=1");
    snprintf(a, sizeof a, "%s.ver", dbp); snprintf(cmd, sizeof cmd, "cp %s %s", dbp, a);
    {
        int ok = system(cmd) == 0 && exec_sql(a, "UPDATE rb_ckpt SET state=x'02000000'||substr(state,5) WHERE height=29;"
                                                 "UPDATE rb_ckpt SET state=substr(state,5) WHERE height=19");
        ReorgArg r = { a, 33 };
        ok = ok && capture_err(log, reorg_cb, &r) && sync_br(a, 'a', 34, NB - 1);
        Snap z; snap(a, &z);
        CHECK(ok && same_state(&z, ref('a')), "unknown format_ver (29) and pre-version blob (19) rejected; replay from 9 == fresh sync");
        CHECK(file_has(log, "rejected checkpoint at height 29: unknown format version 2"),
              "reject log names height 29 and reason 'unknown format version 2'");
        CHECK(file_has(log, "rejected checkpoint at height 19: unknown format version"),
              "reject log names the legacy (unversioned) row at 19");
        rm_db(a);
    }
    // 2. reject log for digest mismatch
    snprintf(a, sizeof a, "%s.dig", dbp); snprintf(cmd, sizeof cmd, "cp %s %s", dbp, a);
    {
        int ok = system(cmd) == 0 && exec_sql(a, "UPDATE rb_ckpt SET digest=zeroblob(32) WHERE height=29");
        ReorgArg r = { a, 33 }; ok = ok && capture_err(log, reorg_cb, &r);
        CHECK(ok && file_has(log, "rejected checkpoint at height 29: digest mismatch"), "reject log: height 29, digest mismatch");
        rm_db(a);
    }
    // 3. size cap: save side (skip, projection still succeeds) and load side (reject + log)
    {
        char b[700]; snprintf(b, sizeof b, "%s.cap", dbp);
        size_t old = idx_ckpt_max_bytes; idx_ckpt_max_bytes = 16;
        int ok = fresh(b, 5) && sync_br(b, 'a', 0, NB - 1);
        Snap z; snap(b, &z);
        CHECK(ok && ckpts(b) == 0 && same_state(&z, ref('a')), "state over the size cap is not checkpointed; projection unaffected");
        snprintf(cmd, sizeof cmd, "cp %s %s.cap2", dbp, dbp); snprintf(a, sizeof a, "%s.cap2", dbp);
        ok = system(cmd) == 0;
        ReorgArg r = { a, 33 }; ok = ok && capture_err(log, reorg_cb, &r);
        idx_ckpt_max_bytes = old;
        ok = ok && sync_br(a, 'a', 34, NB - 1); snap(a, &z);
        CHECK(ok && file_has(log, "rejected checkpoint at height 29: state blob over size cap") && same_state(&z, ref('a')),
              "oversize stored blob rejected on load with log; full replay == fresh sync");
        rm_db(a); rm_db(b);
    }
    // 4. wipe is a plain DELETE
    snprintf(a, sizeof a, "%s.wipe", dbp); snprintf(cmd, sizeof cmd, "cp %s %s", dbp, a);
    {
        int ok = system(cmd) == 0; sqlite3 *db = idx_db_open(a);
        ok = ok && db && idx_db_ckpt_count(db) == 4 && idx_db_ckpt_wipe(db) && idx_db_ckpt_count(db) == 0;
        idx_db_close(db);
        CHECK(ok, "ckpt_wipe deletes every row");
        rm_db(a);
    }
    // 5. keep-4 prune: highest 4 heights survive, whatever else is in the table
    snprintf(a, sizeof a, "%s.prune", dbp); snprintf(cmd, sizeof cmd, "cp %s %s", dbp, a);
    {
        int ok = system(cmd) == 0 && exec_sql(a, "INSERT INTO rb_ckpt VALUES(1,0,zeroblob(32),x'00');"
                                                 "INSERT INTO rb_ckpt VALUES(2,0,zeroblob(32),x'00');"
                                                 "INSERT INTO rb_ckpt VALUES(3,0,NULL,NULL)");
        Fold f; ok = ok && fold_open(&f, a);
        if (ok) { ok = idx_db_ckpt_save(f.db, f.s); fold_close(&f); }
        ok = ok && q_i64(a, "SELECT COUNT(*) FROM rb_ckpt") == 4
                && q_i64(a, "SELECT MIN(height) FROM rb_ckpt") == 9 && q_i64(a, "SELECT MAX(height) FROM rb_ckpt") == 39;
        CHECK(ok, "keep-4 prune: 7 rows -> exactly heights 9,19,29,39 kept");
        ok = exec_sql(a, "DELETE FROM rb_ckpt WHERE height<39") && fold_open(&f, a);
        if (ok) { ok = idx_db_ckpt_save(f.db, f.s); fold_close(&f); }
        CHECK(ok && ckpts(a) == 1, "keep-4 prune with fewer than 4 rows deletes nothing");
        rm_db(a);
    }
    // 6. seed on open
    {
        char b[700]; snprintf(b, sizeof b, "%s.seed", dbp);
        int ok = fresh(b, 1000) && sync_br(b, 'a', 0, NB - 1) && ckpts(b) == 0;
        Fold f;
        ok = ok && fold_open(&f, b); int r1 = ok ? idx_db_ckpt_seed(f.db, f.s) : -9; if (ok) fold_close(&f);
        CHECK(ok && r1 == 0 && ckpts(b) == 0, "seed: tip (39) not past activation+every (1000) -> no checkpoint");
        { sqlite3 *d = idx_db_open(b); if (d) idx_db_ckpt_set_every(d, 5); idx_db_close(d); }
        fold_open(&f, b); f.s->cur_height = 30; int rm = idx_db_ckpt_seed(f.db, f.s); fold_close(&f);
        CHECK(rm == 0 && ckpts(b) == 0, "seed: loaded state not the projection (cursor != proj_height) -> skipped");
        fold_open(&f, b); int r2 = idx_db_ckpt_seed(f.db, f.s); int r3 = idx_db_ckpt_seed(f.db, f.s); fold_close(&f);
        CHECK(r2 == 1 && r3 == 0 && ckpts(b) == 1 && q_i64(b, "SELECT height FROM rb_ckpt") == 39,
              "seed: empty table + tip far past activation -> one checkpoint at 39; second call no-op");
        fold_open(&f, b); SmState *t = sm_new(f.s->activation_height);
        int64_t got = idx_db_ckpt_load(f.db, 39, t); uint8_t d1[32], d2[32]; sm_state_digest(t, d1); sm_state_digest(f.s, d2);
        sm_free(t); fold_close(&f);
        CHECK(got == 39 && !memcmp(d1, d2, 32), "seeded checkpoint loads back with the projection's digest");
        ok = reorg_to(b, 39);
        Snap z; snap(b, &z);
        CHECK(ok && same_state(&z, ref('a')), "rollback to the seeded height == fresh sync");
        rm_db(b);
    }
}


typedef struct { const char *db; char pfx; int from, to; } SyncArg;
static int sync_cb(void *a) { SyncArg *r = a; return sync_br(r->db, r->pfx, r->from, r->to); }
static void sec_ckpt_fail(void) {
    printf("\n-- F: checkpoint save failure is logged and skipped, projection commits --\n");
    char dbp[600], log[700];
    snprintf(dbp, sizeof dbp, "%s/F.db", g_dir); snprintf(log, sizeof log, "%s/F.log", g_dir);
    int ok = fresh(dbp, 5) && exec_sql(dbp, "CREATE TRIGGER f_ckpt_fail BEFORE INSERT ON rb_ckpt "
                                            "BEGIN SELECT RAISE(ABORT, 'forced ckpt failure'); END;");
    SyncArg r = { dbp, 'a', 0, NB - 1 };
    ok = ok && capture_err(log, sync_cb, &r);
    Snap z; snap(dbp, &z);
    CHECK(ok, "sync completes although every checkpoint save fails");
    CHECK(z.proj == NB - 1, "proj_height advances to the tip (projection committed)");
    CHECK(same_state(&z, ref('a')), "projected state == fresh sync of a (digest + all rows)");
    CHECK(ckpts(dbp) == 0, "no checkpoint rows written");
    CHECK(file_has(log, "rb_ckpt: warning: checkpoint save failed at height 9"), "warning logged naming height 9");
    CHECK(file_has(log, "forced ckpt failure"), "warning carries the sqlite error");
    // removing the fault: the next projection checkpoints normally again
    ok = exec_sql(dbp, "DROP TRIGGER f_ckpt_fail") && fresh(dbp, 5) && sync_br(dbp, 'a', 0, NB - 1);
    CHECK(ok && ckpts(dbp) == 4, "without the fault checkpoints are taken again");
    rm_db(dbp);
}
int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/rbtxn.XXXXXX");
    if (!mkdtemp(g_dir)) { perror("mkdtemp"); return 2; }
    for (int i = 0; i < NBR; i++)
        if (chain_mkblocks_rb(g_dir, BR[i].pfx, BR[i].fork, BR[i].kind, NB)) { fprintf(stderr, "fixture failed\n"); return 2; }
    // references: a fresh fold of each branch, no reorg, checkpoints off
    char rp[600];
    for (int i = 0; i < NBR; i++) {
        snprintf(rp, sizeof rp, "%s/ref_%c.db", g_dir, BR[i].pfx);
        if (!fresh(rp, 0) || !sync_br(rp, BR[i].pfx, 0, NB - 1) || !snap(rp, &g_ref[(int)BR[i].pfx])) { fprintf(stderr, "ref %c failed\n", BR[i].pfx); return 2; }
    }
    CHECK(owner_byte(rp, "alice") >= 0, "fixture: claims fold (alice exists on the f branch)");
    int distinct = 1;
    for (int i = 1; i <= 3; i++) if (!memcmp(g_ref['a'].dig, g_ref[(int)BR[i].pfx].dig, 32)) distinct = 0;
    for (int i = 1; i <= 3; i++) for (int j = i + 1; j <= 3; j++) if (!memcmp(g_ref[(int)BR[i].pfx].dig, g_ref[(int)BR[j].pfx].dig, 32)) distinct = 0;
    CHECK(distinct, "fixture: branches a, b, c, d end in four different state_digests (e/f: same actions, different blocks)");
    sec_claims();
    sec_repeat();
    sec_crash();
    sec_ckpt();
    sec_polish();
    sec_ckpt_fail();
    char cmd[700]; snprintf(cmd, sizeof cmd, "rm -rf %s", g_dir); if (system(cmd) != 0) {}
    printf("\ntest_rollback: %s\n", g_fail ? "FAILED" : "ALL PASSED");
    return g_fail;
}
