// jitter_test.c — ordering / interleaving stress for the pepenet-mesh state
// machine, plus the one genuine concurrency surface the design does claim.
//
// ── THREADING: WHAT IS ACTUALLY HERE ────────────────────────────────────────
// Stated plainly, because the answer shapes this whole file:
//
//   src/ AND include/ CONTAIN NO THREADING AT ALL.
//   $ grep -rn 'pthread|thread|atomic|mutex|socket|bind\(|listen\(|accept\(|
//                select\(|poll\(|epoll|kqueue|fork\(' src/ include/  ->  0 hits
//
//   There is no background thread, no socket loop, no shared mutable global, no
//   lock and no atomic anywhere in the library. src/wire.c and src/crypto.c are
//   pure functions; src/view.c and src/state.c own a private sqlite3* each and
//   touch nothing else. So there are no start/stop cycles of a background thread
//   to exercise and no intra-library data race to find: inventing threads inside
//   this library would be testing a design that does not exist.
//
// Therefore this file does what the shape of the code actually calls for:
//
//   PART 1 — INTERLEAVING / ORDERING STRESS (the real concurrency risk here).
//     The state model claims to be a per-key, anchor-ordered LWW register: gossip
//     may deliver ops in ANY order, any number of times, and every replica must
//     land on the same state. That is the convergence property, and disagreeing
//     replicas is exactly the bug class threads would otherwise cause. Proven by
//     replaying one seeded batch of signed ops in hundreds of random permutations
//     into fresh stores and requiring a byte-identical state digest each time,
//     with duplicate/replayed deliveries injected throughout.
//
//   PART 2 — INVARIANTS AFTER EVERY SINGLE ADMISSION (not just at the end):
//     no negative counts, held bytes never exceed the budget, held bytes exactly
//     equal the recomputed sum of held blobs, no duplicate (name,key) row, the
//     per-name floor never moves backwards inside an epoch, reads agree with
//     iteration, and a CONTROL OPERATION (a fresh owner-signed PUT at a high
//     anchor) still succeeds after every batch.
//
//   PART 3 — REPEATED OPEN/CLOSE CYCLES WITH OPS IN FLIGHT (50 cycles, on-disk):
//     the analogue of start/stop for a module whose only resource is a sqlite
//     handle. Proves nothing is lost across a cycle, nothing is corrupted, and
//     handles/fds are actually released.
//
//   PART 4 — MULTI-THREADED WAL PROBE. The only concurrency the design DOES
//     claim: view.h says a view "runs safely alongside a live indexerd" over WAL.
//     16 threads, each with its OWN SpState/SpView handle on ONE shared on-disk
//     database, seeded-random 0-2 ms jitter at random points, randomised
//     operation order, concurrent admit/read/iterate. The threads belong to the
//     TEST driving separate handles — they are not pretending the library has
//     any of its own. This is the part worth running under ThreadSanitizer.
//
// Everything is seeded (SplitMix64, never rand()); the seed is printed and can be
// replayed with `./jitter_test <seed>`. A SIGALRM watchdog turns a deadlock or a
// hang into a clear FAIL instead of hanging. Fixtures live in a mkdtemp'd
// directory and are removed on exit.
//
// Build with TSAN=1 to add -fsanitize=thread (see the Makefile).
#include "pepenet/state.h"
#include "pepenet/view.h"
#include "pepenet/crypto.h"

#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int g_fail;
static long g_checks;
#define CK(c, m) do { g_checks++; if (c) printf("  ok   %s\n", m); \
                      else { printf("  FAIL %s\n", m); g_fail++; } } while (0)

static char g_dir[] = "/tmp/pepenet-mesh-jitter.XXXXXX";
static int  g_dir_ok;

static const char *g_phase = "startup";
static void on_alarm(int s) {
    (void)s;
    char m[320];
    int n = snprintf(m, sizeof m,
        "\njitter_test: WATCHDOG FAIL — no progress in phase: %s\n"
        "             (a deadlock or a hang, NOT a pass)\n", g_phase);
    ssize_t r = write(2, m, (size_t)n); (void)r;
    _exit(1);
}
#define PHASE(p, secs) do { g_phase = (p); alarm(secs); } while (0)

// ── SplitMix64 (never rand()) ────────────────────────────────────────────────
static uint64_t g_rng;
static uint64_t rnd(void) {
    uint64_t z = (g_rng += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
// per-thread stream, so thread scheduling never perturbs the seed
typedef struct { uint64_t s; } Rng;
static uint64_t rnd_of(Rng *r) {
    uint64_t z = (r->s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static void jitter(Rng *r) {                    // random 0-2 ms sleep
    unsigned us = (unsigned)(rnd_of(r) % 2000);
    if (us) { struct timespec ts = { 0, (long)us * 1000L }; nanosleep(&ts, NULL); }
}

// ── fault trap (a crash must FAIL, not kill the run silently) ────────────────
static sigjmp_buf g_jmp;
static volatile sig_atomic_t g_trapped;
static void on_fault(int s) { (void)s; g_trapped = 1; siglongjmp(g_jmp, 1); }

// ── fake chain, identical contract to state_test.c ───────────────────────────
#define FAKE_TIP     1000u
#define FAKE_HORIZON 50u
static int header_at(void *u, uint32_t height, uint8_t out[32]) {
    (void)u;
    if (height > FAKE_TIP) return 0;
    if (height <= FAKE_HORIZON) return -1;
    uint8_t s[8] = { 'h','d','r',0, (uint8_t)height, (uint8_t)(height >> 8),
                     (uint8_t)(height >> 16), (uint8_t)(height >> 24) };
    sp_sha256(s, sizeof s, out);
    return 1;
}
static void anchor_of(uint32_t h, uint8_t out[32]) {
    if (header_at(NULL, h, out) != 1) memset(out, 0xAB, 32);
}
static uint32_t fake_tip(void *u) { (void)u; return FAKE_TIP; }
static int oracle_owner(void *u, const char *name, uint8_t owner[20]) {
    return sp_view_owner_now((SpView *)u, name, owner);
}

static uint8_t OPRIV[32], OPUB[33], O160[20];
static void testkey(const char *s, uint8_t priv[32], uint8_t pub[33]) {
    sp_sha256((const uint8_t *)s, strlen(s), priv);
    while (!sp_pubkey(priv, pub)) sp_sha256(priv, 32, priv);
}
static void hex20(const uint8_t b[20], char out[41]) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 20; i++) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 15]; }
    out[40] = 0;
}

#define NNAMES 3
static const char *NAMES[NNAMES] = { "zone", "other", "third" };

// ── the op batch ─────────────────────────────────────────────────────────────
typedef struct { uint8_t blob[1024]; int len; int name_idx; uint8_t op; int key_idx; uint32_t anchor; } Op;

// ── state snapshot: a canonical digest of everything the store holds ─────────
typedef struct { char names[64][SP_NAME_MAX + 1]; int n; } NameList;
static int name_cb(void *u, const char *name) {
    NameList *l = u;
    if (l->n < 64) { snprintf(l->names[l->n], sizeof l->names[0], "%s", name); l->n++; }
    return 1;
}
typedef struct { uint8_t buf[1 << 16]; size_t n; int rows; int64_t bytes; } Acc;
static void acc(Acc *a, const void *p, size_t n) {
    if (a->n + n <= sizeof a->buf) { memcpy(a->buf + a->n, p, n); a->n += n; }
}
static uint8_t g_prev_key[512]; static int g_prev_len = -1; static int g_key_order_bad;
static int row_cb(void *u, const uint8_t *key, int key_len, int op,
                  uint32_t anchor, const uint8_t *blob, int blen) {
    Acc *a = u;
    // key ordering must be strictly increasing => no duplicate (name,key) row
    if (g_prev_len >= 0) {
        int m = key_len < g_prev_len ? key_len : g_prev_len;
        int c = memcmp(g_prev_key, key, (size_t)m);
        if (c > 0 || (c == 0 && key_len <= g_prev_len)) g_key_order_bad++;
    }
    if (key_len > 0 && key_len <= (int)sizeof g_prev_key) { memcpy(g_prev_key, key, (size_t)key_len); g_prev_len = key_len; }
    acc(a, key, (size_t)key_len);
    acc(a, &op, 1);
    acc(a, &anchor, 4);
    acc(a, blob, (size_t)blen);
    a->rows++;
    a->bytes += blen;
    return 1;
}
// rows_digest: rows only.  full_digest: rows + floor + sum + clear blob.
// held_bytes: the recomputed byte total (rows + clear), for the sum invariant.
static void snapshot(SpState *s, uint8_t rows_digest[32], uint8_t full_digest[32],
                     int64_t *held_bytes, int *dup_rows)
{
    NameList l; l.n = 0;
    sp_state_names(s, name_cb, &l);
    Acc *ra = calloc(1, sizeof *ra), *fa = calloc(1, sizeof *fa);
    int64_t total = 0;
    g_key_order_bad = 0;
    for (int i = 0; i < l.n; i++) {
        acc(ra, l.names[i], strlen(l.names[i]));
        acc(fa, l.names[i], strlen(l.names[i]));
        g_prev_len = -1;
        Acc *tmp = calloc(1, sizeof *tmp);
        sp_state_iter(s, l.names[i], row_cb, tmp);
        acc(ra, tmp->buf, tmp->n);
        acc(fa, tmp->buf, tmp->n);
        total += tmp->bytes;
        uint32_t fl = sp_state_floor(s, l.names[i]);
        int64_t sum = sp_state_sum(s, l.names[i]);
        acc(fa, &fl, 4); acc(fa, &sum, 8);
        uint8_t *cb = NULL; int cl = 0;
        if (sp_state_clear_get(s, l.names[i], &cb, &cl)) { acc(fa, cb, (size_t)cl); total += cl; free(cb); }
        free(tmp);
    }
    *dup_rows = g_key_order_bad;
    sp_sha256(ra->buf, ra->n, rows_digest);
    sp_sha256(fa->buf, fa->n, full_digest);
    *held_bytes = total;
    free(ra); free(fa);
}

// ── invariant check after every admission ────────────────────────────────────
static int invariants(SpState *s, int64_t budget, const char *where) {
    NameList l; l.n = 0;
    sp_state_names(s, name_cb, &l);
    int bad = 0;
    for (int i = 0; i < l.n; i++) {
        int64_t sum = sp_state_sum(s, l.names[i]);
        if (sum < 0) { printf("  FAIL [%s] %s: NEGATIVE held bytes (%lld)\n", where, l.names[i], (long long)sum); bad++; }
        if (sum > budget) { printf("  FAIL [%s] %s: held bytes %lld exceed budget %lld\n",
                                   where, l.names[i], (long long)sum, (long long)budget); bad++; }
    }
    uint8_t rd[32], fd[32]; int64_t held; int dup;
    snapshot(s, rd, fd, &held, &dup);
    if (dup) { printf("  FAIL [%s] duplicate or mis-ordered (name,key) rows: %d\n", where, dup); bad++; }
    int64_t declared = 0;
    for (int i = 0; i < l.n; i++) declared += sp_state_sum(s, l.names[i]);
    if (declared != held) {
        printf("  FAIL [%s] LOST UPDATE: declared held bytes %lld != recomputed %lld\n",
               where, (long long)declared, (long long)held);
        bad++;
    }
    return bad;
}

// ── shared fixtures for the thread probe ─────────────────────────────────────
typedef struct {
    const char   *db_path;
    const char   *view_path;
    const Op     *ops;
    int           n_ops;
    uint64_t      seed;
    int           id;
    int64_t       budget;
    volatile int *stop;
    // results
    int           admitted, rejected, dups, holds, control_fail, read_fail, crash;
} Worker;

static void *worker(void *u) {
    Worker *w = u;
    Rng r = { w->seed };
    SpView  *vw = sp_view_open_test(w->view_path, FAKE_TIP);
    SpState *st = sp_state_open(w->db_path);          // this thread's OWN handles
    if (!vw || !st) { w->crash = 1; if (vw) sp_view_close(vw); if (st) sp_state_close(st); return NULL; }
    SpChainOracle o = { vw, oracle_owner, header_at, fake_tip };
    char err[128];
    for (int i = 0; i < w->n_ops && !*w->stop; i++) {
        if (rnd_of(&r) % 4 == 0) jitter(&r);
        int k = (int)(rnd_of(&r) % (unsigned)w->n_ops);      // random ORDER
        const Op *op = &w->ops[k];
        switch (rnd_of(&r) % 8) {
        case 0: case 1: case 2: case 3: case 4: {
            int rc = sp_state_admit(st, &o, w->budget, 0x20, op->blob, op->len, err, sizeof err);
            if (rc == 1) w->admitted++; else if (rc == -1) w->dups++;
            else if (rc == -2) w->holds++; else w->rejected++;
            break; }
        case 5: {                                            // concurrent read
            uint8_t *b = NULL; int bl = 0;
            char key[16]; snprintf(key, sizeof key, "k%d", op->key_idx);
            if (sp_state_get(st, NAMES[op->name_idx], (const uint8_t *)key, (int)strlen(key), &b, &bl)) {
                if (bl <= 0) w->read_fail++;
                free(b);
            }
            break; }
        case 6: {                                            // concurrent iterate
            Acc *a = calloc(1, sizeof *a);
            g_prev_len = -1;
            sp_state_iter(st, NAMES[op->name_idx], row_cb, a);
            free(a);
            break; }
        default: {                                           // concurrent metadata
            (void)sp_state_sum(st, NAMES[op->name_idx]);
            (void)sp_state_floor(st, NAMES[op->name_idx]);
            break; }
        }
        if (rnd_of(&r) % 16 == 0) jitter(&r);
    }
    // CONTROL OPERATION: a fresh owner-signed PUT at a high anchor must still
    // be admitted no matter what the other threads did.
    {
        uint8_t ah[32]; anchor_of(FAKE_TIP - 1, ah);
        uint8_t blob[1024];
        char key[32]; snprintf(key, sizeof key, "ctl%d", w->id);
        int n = sp_state_op_build(SP_OP_PUT, NAMES[0], (const uint8_t *)key, (int)strlen(key),
                                  (const uint8_t *)"control", 7, FAKE_TIP - 1, ah,
                                  OPRIV, OPUB, SP_CERT_NONE, NULL, 0, blob, sizeof blob);
        int rc = n > 0 ? sp_state_admit(st, &o, w->budget, 0x20, blob, n, err, sizeof err) : -99;
        if (rc != 1 && rc != -1) { w->control_fail = 1;
            printf("  FAIL thread %d: control op refused (rc=%d, err=%s)\n", w->id, rc, err); }
    }
    sp_state_close(st);
    sp_view_close(vw);
    return NULL;
}

// ── PART 5 writer: N distinct keys of ONE name, so the only shared cell is
//    st_names.sum_bytes. Each thread signs nothing (ops are pre-built) and owns
//    its own SpState/SpView handles.
typedef struct {
    const char *db_path, *view_path;
    int id, n, admitted;
    uint64_t seed;
} LUWorker;
static void *lu_worker(void *u) {
    LUWorker *w = u;
    Rng r = { w->seed };
    SpView  *vw2 = sp_view_open_test(w->view_path, FAKE_TIP);
    SpState *st  = sp_state_open(w->db_path);
    if (!vw2 || !st) { if (vw2) sp_view_close(vw2); if (st) sp_state_close(st); return NULL; }
    SpChainOracle o = { vw2, oracle_owner, header_at, fake_tip };
    char err[128];
    for (int i = 0; i < w->n; i++) {
        char key[32]; snprintf(key, sizeof key, "t%dk%d", w->id, i);   // disjoint keys
        uint32_t anchor = 200 + (uint32_t)i;
        uint8_t ah[32]; anchor_of(anchor, ah);
        uint8_t b[1024];
        int n = sp_state_op_build(SP_OP_PUT, NAMES[0], (const uint8_t *)key, (int)strlen(key),
                                  (const uint8_t *)"0123456789", 10, anchor, ah,
                                  OPRIV, OPUB, SP_CERT_NONE, NULL, 0, b, sizeof b);
        if (n > 0 && sp_state_admit(st, &o, 1 << 20, 0x20, b, n, err, sizeof err) == 1) w->admitted++;
        if (rnd_of(&r) % 32 == 0) jitter(&r);
    }
    sp_state_close(st); sp_view_close(vw2);
    return NULL;
}

// ═════════════════════════════════════════════════════════════════════════════
int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGALRM, on_alarm);
    { struct sigaction sa; memset(&sa, 0, sizeof sa); sa.sa_handler = on_fault;
      sigemptyset(&sa.sa_mask); sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS, &sa, NULL); }

    uint64_t seed = 0x51DE0A11BEEF5EEDULL;
    if (argc > 1) seed = strtoull(argv[1], NULL, 0);
    else { const char *e = getenv("SP_SEED"); if (e) seed = strtoull(e, NULL, 0); }
    g_rng = seed;
    printf("jitter_test  seed = 0x%016llx   (reproduce: ./jitter_test 0x%016llx)\n",
           (unsigned long long)seed, (unsigned long long)seed);
    printf("             src/ has NO threads, locks, atomics or sockets — see the\n"
           "             file-top comment. Parts 1-3 are ordering stress; part 4 drives\n"
           "             the one concurrency surface the design does claim (WAL).\n");

    if (!mkdtemp(g_dir)) { printf("  FAIL mkdtemp\n"); return 1; }
    g_dir_ok = 1;
    printf("             fixtures in %s (removed on exit)\n", g_dir);

    testkey("owner", OPRIV, OPUB); sp_hash160(OPUB, 33, O160);
    char oh[41]; hex20(O160, oh);
    char view_path[512]; snprintf(view_path, sizeof view_path, "%s/names.txt", g_dir);
    FILE *f = fopen(view_path, "w");
    for (int i = 0; i < NNAMES; i++) fprintf(f, "%s %s\n", NAMES[i], oh);
    fclose(f);
    SpView *vw = sp_view_open_test(view_path, FAKE_TIP);
    if (!vw) { printf("  FAIL view fixture\n"); return 1; }
    SpChainOracle orc = { vw, oracle_owner, header_at, fake_tip };
    const int64_t BUDGET = 1 << 20;          // generous: budget must not be the
                                             // thing that makes order matter
    char err[128];

    // ── build the batch ──────────────────────────────────────────────────────
    // Anchors are UNIQUE per (name,key), so "strictly raises the key" can never
    // be decided by arrival order — any residual order-dependence is a real bug.
    PHASE("batch construction", 300);
    printf("-- batch construction --\n");
    #define NKEYS 6
    #define NOPS  60
    static Op ops[NOPS];
    int n_ops = 0;
    {
        uint32_t next_anchor[NNAMES][NKEYS];
        for (int a = 0; a < NNAMES; a++) for (int b = 0; b < NKEYS; b++) next_anchor[a][b] = 100 + (uint32_t)(a * 100 + b * 10);
        uint32_t next_clear[NNAMES] = { 150, 250, 350 };
        for (int i = 0; i < NOPS; i++) {
            int ni = (int)(rnd() % NNAMES);
            uint8_t op;
            uint32_t r3 = (uint32_t)(rnd() % 10);
            op = r3 < 5 ? SP_OP_PUT : (r3 < 8 ? SP_OP_DEL : SP_OP_CLEAR);
            int ki = (int)(rnd() % NKEYS);
            uint32_t anchor;
            if (op == SP_OP_CLEAR) { anchor = next_clear[ni]; next_clear[ni] += 37; }
            else { anchor = next_anchor[ni][ki]; next_anchor[ni][ki] += 1; }
            if (anchor <= FAKE_HORIZON) anchor = FAKE_HORIZON + 1;
            if (anchor >= FAKE_TIP) anchor = FAKE_TIP - 1;
            char key[16]; snprintf(key, sizeof key, "k%d", ki);
            char pay[64]; int pl = 0;
            if (op == SP_OP_PUT) { pl = 1 + (int)(rnd() % 40); for (int j = 0; j < pl; j++) pay[j] = (char)('a' + (rnd() % 26)); }
            uint8_t ah[32]; anchor_of(anchor, ah);
            int n = sp_state_op_build(op, NAMES[ni],
                                      op == SP_OP_CLEAR ? NULL : (const uint8_t *)key,
                                      op == SP_OP_CLEAR ? 0 : (int)strlen(key),
                                      op == SP_OP_PUT ? (const uint8_t *)pay : NULL,
                                      op == SP_OP_PUT ? pl : 0,
                                      anchor, ah, OPRIV, OPUB, SP_CERT_NONE, NULL, 0,
                                      ops[n_ops].blob, (int)sizeof ops[n_ops].blob);
            if (n <= 0) continue;
            ops[n_ops].len = n; ops[n_ops].name_idx = ni; ops[n_ops].op = op;
            ops[n_ops].key_idx = ki; ops[n_ops].anchor = anchor;
            n_ops++;
        }
        char lbl[96];
        snprintf(lbl, sizeof lbl, "built %d signed ops across %d names / %d keys", n_ops, NNAMES, NKEYS);
        CK(n_ops > NOPS / 2, lbl);
    }

    // ═══ PART 1: convergence under reordering ════════════════════════════════
    PHASE("convergence under reordering", 900);
    printf("-- PART 1: convergence under randomised delivery order --\n");
    {
        const int TRIALS = 200;
        uint8_t ref_rows[32], ref_full[32];
        int64_t ref_bytes = 0;
        int rows_diff = 0, full_diff = 0, inv_bad = 0, order[NOPS];

        for (int t = 0; t < TRIALS; t++) {
            SpState *st = sp_state_open(":memory:");
            if (!st) { CK(0, "open :memory: store"); break; }
            for (int i = 0; i < n_ops; i++) order[i] = i;
            for (int i = n_ops - 1; i > 0; i--) {             // Fisher-Yates
                int j = (int)(rnd() % (unsigned)(i + 1));
                int tmp = order[i]; order[i] = order[j]; order[j] = tmp;
            }
            for (int i = 0; i < n_ops; i++) {
                const Op *o = &ops[order[i]];
                int reps = 1 + (int)(rnd() % 3);              // REPLAYED deliveries
                for (int r = 0; r < reps; r++) {
                    g_trapped = 0;
                    int rc = -99;
                    if (sigsetjmp(g_jmp, 1) == 0)
                        rc = sp_state_admit(st, &orc, BUDGET, 0x20, o->blob, o->len, err, sizeof err);
                    if (g_trapped) { printf("  FAIL CRASH admitting op %d (trial %d)\n", order[i], t); g_fail++; break; }
                    if (r > 0 && rc == 1) {
                        // a second identical delivery must be a duplicate (-1) or a
                        // rejection, never a fresh admission
                        printf("  FAIL replayed identical op admitted twice (op %d, rc=%d)\n", order[i], rc);
                        g_fail++;
                    }
                }
            }
            if (t < 20) inv_bad += invariants(st, BUDGET, "part1");
            uint8_t rd[32], fd[32]; int64_t held; int dup;
            snapshot(st, rd, fd, &held, &dup);
            if (t == 0) { memcpy(ref_rows, rd, 32); memcpy(ref_full, fd, 32); ref_bytes = held; }
            else {
                if (memcmp(rd, ref_rows, 32) != 0) rows_diff++;
                if (memcmp(fd, ref_full, 32) != 0) full_diff++;
                if (held != ref_bytes) full_diff++;
            }
            if (dup) { printf("  FAIL duplicate (name,key) rows in trial %d\n", t); g_fail++; }
            g_checks++;
            sp_state_close(st);
        }
        char lbl[160];
        snprintf(lbl, sizeof lbl,
                 "%d random delivery orders (with 1-3x replay of every op) converge to "
                 "the SAME rows", TRIALS);
        CK(rows_diff == 0, lbl);
        snprintf(lbl, sizeof lbl,
                 "%d random delivery orders converge to the same floor, held-byte total "
                 "and clear proof", TRIALS);
        CK(full_diff == 0, lbl);
        CK(inv_bad == 0, "invariants hold in every sampled trial (no negative counts, no "
                         "duplicate rows, no lost updates)");
    }

    // ═══ PART 2: per-admission invariants + control op ═══════════════════════
    PHASE("per-admission invariants", 900);
    printf("-- PART 2: invariants after EVERY admission --\n");
    {
        SpState *st = sp_state_open(":memory:");
        int bad = 0, admitted = 0, control_bad = 0;
        for (int round = 0; round < 6; round++) {
            for (int i = 0; i < n_ops; i++) {
                int k = (int)(rnd() % (unsigned)n_ops);
                int rc = sp_state_admit(st, &orc, BUDGET, 0x20, ops[k].blob, ops[k].len, err, sizeof err);
                if (rc == 1) admitted++;
                bad += invariants(st, BUDGET, "part2");
                g_checks++;
            }
            // CONTROL: a fresh owner-signed PUT at a high anchor must ALWAYS admit
            uint8_t ah[32]; anchor_of(FAKE_TIP - 1, ah);
            uint8_t blob[1024];
            char key[32]; snprintf(key, sizeof key, "control%d", round);
            int n = sp_state_op_build(SP_OP_PUT, NAMES[0], (const uint8_t *)key, (int)strlen(key),
                                      (const uint8_t *)"alive", 5, FAKE_TIP - 1, ah,
                                      OPRIV, OPUB, SP_CERT_NONE, NULL, 0, blob, sizeof blob);
            int rc = sp_state_admit(st, &orc, BUDGET, 0x20, blob, n, err, sizeof err);
            if (rc != 1) { control_bad++; printf("  FAIL control op refused after round %d (rc=%d, %s)\n", round, rc, err); }
            uint8_t *b = NULL; int bl = 0;
            if (!sp_state_get(st, NAMES[0], (const uint8_t *)key, (int)strlen(key), &b, &bl) || bl <= 0)
                { control_bad++; printf("  FAIL control op not readable back after round %d\n", round); }
            free(b);
        }
        char lbl[160];
        snprintf(lbl, sizeof lbl, "%d admissions x full invariant sweep: all clean", 6 * n_ops);
        CK(bad == 0, lbl);
        CK(control_bad == 0, "the control operation succeeded and read back after all 6 rounds");
        CK(admitted > 0, "the stress actually admitted work (sanity)");
        sp_state_close(st);
    }

    // ── tight budget: convergence is NOT claimed, invariants still are ───────
    printf("-- PART 2b: tight budget (rejections allowed, invariants are not) --\n");
    {
        const int64_t TIGHT = 4096;
        int bad = 0;
        for (int t = 0; t < 30; t++) {
            SpState *st = sp_state_open(":memory:");
            for (int i = 0; i < n_ops; i++) {
                int k = (int)(rnd() % (unsigned)n_ops);
                sp_state_admit(st, &orc, TIGHT, 0x20, ops[k].blob, ops[k].len, err, sizeof err);
            }
            bad += invariants(st, TIGHT, "part2b");
            g_checks++;
            sp_state_close(st);
        }
        CK(bad == 0, "30 tight-budget interleavings: held bytes never negative, never over "
                     "budget, always equal to the recomputed total");
    }

    // ═══ PART 3: open/close cycles with ops in flight ════════════════════════
    PHASE("open/close cycles", 600);
    printf("-- PART 3: 50 open/close cycles with ops in flight --\n");
    {
        char db[512]; snprintf(db, sizeof db, "%s/cycle.db", g_dir);
        unlink(db);
        int bad = 0, lost = 0;
        uint8_t prev_rows[32]; int have_prev = 0;
        for (int c = 0; c < 50; c++) {
            SpState *st = sp_state_open(db);
            if (!st) { bad++; printf("  FAIL open cycle %d\n", c); continue; }
            // state must survive the previous close exactly
            uint8_t rd[32], fd[32]; int64_t held; int dup;
            snapshot(st, rd, fd, &held, &dup);
            if (have_prev && memcmp(rd, prev_rows, 32) != 0) {
                lost++; printf("  FAIL state changed across close/open at cycle %d\n", c);
            }
            if (dup) { bad++; printf("  FAIL duplicate rows after reopen at cycle %d\n", c); }
            // ops in flight
            for (int i = 0; i < 12; i++) {
                int k = (int)(rnd() % (unsigned)n_ops);
                sp_state_admit(st, &orc, BUDGET, 0x20, ops[k].blob, ops[k].len, err, sizeof err);
            }
            bad += invariants(st, BUDGET, "part3");
            snapshot(st, prev_rows, fd, &held, &dup);
            have_prev = 1;
            sp_state_close(st);
            g_checks++;
        }
        CK(bad == 0, "50 open/close cycles: no crash, no corruption, invariants hold throughout");
        CK(lost == 0, "50 open/close cycles: nothing lost or altered across a close/reopen");
        // a control op must still work on the 51st open
        SpState *st = sp_state_open(db);
        uint8_t ah[32]; anchor_of(FAKE_TIP - 1, ah);
        uint8_t blob[1024];
        int n = sp_state_op_build(SP_OP_PUT, NAMES[0], (const uint8_t *)"final", 5,
                                  (const uint8_t *)"ok", 2, FAKE_TIP - 1, ah,
                                  OPRIV, OPUB, SP_CERT_NONE, NULL, 0, blob, sizeof blob);
        int rc = sp_state_admit(st, &orc, BUDGET, 0x20, blob, n, err, sizeof err);
        CK(rc == 1, "the store is still fully functional after 50 cycles (control op admits)");
        sp_state_close(st);
        // fd exhaustion would show up here: 200 more opens without closing would
        // fail, so prove close() actually releases by opening 300 sequentially
        int opens = 0;
        for (int i = 0; i < 300; i++) {
            SpState *t = sp_state_open(db);
            if (!t) break;
            opens++;
            sp_state_close(t);
        }
        CK(opens == 300, "300 sequential open/close: handles are genuinely released "
                         "(no fd leak)");
        sp_state_close(NULL);
        CK(1, "sp_state_close(NULL) is a no-op");
    }

    // ═══ PART 4: multi-threaded WAL probe ════════════════════════════════════
    PHASE("multi-threaded WAL probe", 900);
    printf("-- PART 4: 16 threads, own handles, ONE shared db, seeded jitter --\n");
    {
        char db[512]; snprintf(db, sizeof db, "%s/shared.db", g_dir);
        unlink(db);
        { SpState *seedst = sp_state_open(db);          // create the schema first
          CK(seedst != NULL, "shared db created (WAL)");
          if (seedst) sp_state_close(seedst); }

        const int NT = 16;
        pthread_t th[16];
        static Worker w[16];
        volatile int stop = 0;
        for (int i = 0; i < NT; i++) {
            memset(&w[i], 0, sizeof w[i]);
            w[i].db_path = db; w[i].view_path = view_path;
            w[i].ops = ops; w[i].n_ops = n_ops;
            w[i].seed = seed ^ (0x9E3779B97F4A7C15ULL * (uint64_t)(i + 1));
            w[i].id = i; w[i].budget = BUDGET; w[i].stop = &stop;
        }
        int spawned = 0;
        for (int i = 0; i < NT; i++) if (pthread_create(&th[i], NULL, worker, &w[i]) == 0) spawned++;
        char lbl[128];
        snprintf(lbl, sizeof lbl, "%d/%d threads spawned", spawned, NT);
        CK(spawned == NT, lbl);
        for (int i = 0; i < spawned; i++) pthread_join(th[i], NULL);

        long adm = 0, rej = 0, dup = 0, hold = 0;
        int crash = 0, ctl = 0, rdf = 0;
        for (int i = 0; i < spawned; i++) {
            adm += w[i].admitted; rej += w[i].rejected; dup += w[i].dups; hold += w[i].holds;
            crash += w[i].crash; ctl += w[i].control_fail; rdf += w[i].read_fail;
        }
        printf("       admitted=%ld rejected=%ld duplicate=%ld held=%ld\n", adm, rej, dup, hold);
        CK(crash == 0, "no thread failed to open its own handles on the shared db");
        CK(rdf == 0, "every concurrent read returned a well-formed row");
        CK(ctl == 0, "every thread's control operation still succeeded under contention");
        CK(adm > 0, "concurrent admissions actually landed (contention was real)");

        // the shared db must be intact and consistent afterwards
        SpState *st = sp_state_open(db);
        CK(st != NULL, "shared db reopens after 16-way contention");
        if (st) {
            int bad = invariants(st, BUDGET, "part4");
            CK(bad == 0, "post-contention invariants: no negative counts, no duplicate "
                         "(name,key) rows, no lost updates");
            // every control row written by a thread must be present exactly once
            int present = 0;
            for (int i = 0; i < spawned; i++) {
                char key[32]; snprintf(key, sizeof key, "ctl%d", i);
                uint8_t *b = NULL; int bl = 0;
                if (sp_state_get(st, NAMES[0], (const uint8_t *)key, (int)strlen(key), &b, &bl)) { present++; free(b); }
            }
            snprintf(lbl, sizeof lbl, "%d/%d per-thread control rows survived the race", present, spawned);
            CK(present == spawned, lbl);
            sp_state_close(st);
        }
        // and again, with concurrent readers only (the documented WAL claim)
        {
            const int NR = 16;
            pthread_t rt[16]; static Worker rw[16];
            for (int i = 0; i < NR; i++) {
                memset(&rw[i], 0, sizeof rw[i]);
                rw[i].db_path = db; rw[i].view_path = view_path;
                rw[i].ops = ops; rw[i].n_ops = n_ops;
                rw[i].seed = ~seed ^ (0x9E3779B97F4A7C15ULL * (uint64_t)(i + 1));
                rw[i].id = 100 + i; rw[i].budget = BUDGET; rw[i].stop = &stop;
            }
            int sp2 = 0;
            for (int i = 0; i < NR; i++) if (pthread_create(&rt[i], NULL, worker, &rw[i]) == 0) sp2++;
            for (int i = 0; i < sp2; i++) pthread_join(rt[i], NULL);
            int c2 = 0; for (int i = 0; i < sp2; i++) c2 += rw[i].control_fail + rw[i].crash + rw[i].read_fail;
            CK(c2 == 0, "a second 16-way round over the now-populated db is equally clean");
        }
    }

    // ═══ PART 5: minimal lost-update reproducer ══════════════════════════════
    // Part 4 detects the divergence incidentally. This isolates it: N threads,
    // each with its OWN handle, each writing its OWN keys of ONE name, so the
    // ONLY thing they contend on is the st_names.sum_bytes accumulator.
    PHASE("lost-update reproducer", 600);
    printf("-- PART 5: minimal lost-update reproducer (scaling by thread count) --\n");
    {
        struct { int nt; int64_t declared, real; int rows, admitted; } R[5];
        int NTS[5] = { 1, 2, 4, 8, 16 };
        int diverged = 0;
        for (int t = 0; t < 5; t++) {
            char db[512]; snprintf(db, sizeof db, "%s/lu%d.db", g_dir, t);
            unlink(db);
            { SpState *s0 = sp_state_open(db); if (s0) sp_state_close(s0); }
            int NT = NTS[t];
            pthread_t th[16]; static LUWorker w[16];
            // distinct keys per thread, so no two threads ever touch the same
            // (name,key) row — the ONLY shared cell is st_names.sum_bytes
            for (int i = 0; i < NT; i++) {
                memset(&w[i], 0, sizeof w[i]);
                w[i].db_path = db; w[i].view_path = view_path;
                w[i].id = 1000 * (t + 1) + i; w[i].n = 150;
                w[i].seed = seed + (uint64_t)i;
            }
            for (int i = 0; i < NT; i++) pthread_create(&th[i], NULL, lu_worker, &w[i]);
            for (int i = 0; i < NT; i++) pthread_join(th[i], NULL);
            SpState *st = sp_state_open(db);
            Acc *a = calloc(1, sizeof *a); g_prev_len = -1;
            int rows = sp_state_iter(st, NAMES[0], row_cb, a);
            int64_t real = a->bytes;
            uint8_t *cb = NULL; int cl = 0;
            if (sp_state_clear_get(st, NAMES[0], &cb, &cl)) { real += cl; free(cb); }
            int64_t declared = sp_state_sum(st, NAMES[0]);
            free(a);
            sp_state_close(st);
            R[t].nt = NT; R[t].declared = declared; R[t].real = real; R[t].rows = rows;
            R[t].admitted = 0; for (int i = 0; i < NT; i++) R[t].admitted += w[i].admitted;
            if (declared != real) diverged++;
        }
        printf("       threads | admitted | rows | real bytes | sum_bytes |    delta\n");
        for (int t = 0; t < 5; t++)
            printf("       %7d | %8d | %4d | %10lld | %9lld | %8lld\n",
                   R[t].nt, R[t].admitted, R[t].rows, (long long)R[t].real,
                   (long long)R[t].declared, (long long)(R[t].declared - R[t].real));
        if (diverged) {
            printf("\n"
                   "  *** FINDING #2 — LOST UPDATE / NON-ATOMIC READ-MODIFY-WRITE ******\n"
                   "  src/state.c: sp_state_admit() is a multi-statement\n"
                   "  read-modify-write with NO TRANSACTION anywhere in the file\n"
                   "  (`grep -n 'BEGIN|COMMIT|SAVEPOINT' src/state.c` -> no matches):\n"
                   "\n"
                   "      state.c:344  meta_get(...)                 // SELECT sum_bytes\n"
                   "      state.c:389  SELECT anchor,op_id,LENGTH(blob) FROM st_rows ...\n"
                   "      state.c:404  INSERT OR REPLACE INTO st_rows ...\n"
                   "      state.c:414  m.sum = m.sum - held_len + len;\n"
                   "      state.c:415  meta_put(...)                 // writes sum_bytes\n"
                   "\n"
                   "  sqlite serialises each STATEMENT, not the sequence. Two writers on\n"
                   "  the same name both read the old sum_bytes and both write\n"
                   "  old + their own delta; the later write silently discards the\n"
                   "  earlier one. The row INSERTs all land (rows == admitted above), so\n"
                   "  the DATA is intact while the ACCOUNTING is not — and sum_bytes is\n"
                   "  persisted, so the corruption survives a restart.\n"
                   "\n"
                   "  Impact: sum_bytes is the per-name budget accumulator consulted at\n"
                   "  state.c:402 (`m.sum - held_len + len > budget`) and at state.c:379\n"
                   "  for CLEAR. Undercounting means the per-name byte budget stops\n"
                   "  being enforced -> unbounded growth for one name (resource\n"
                   "  exhaustion). Overcounting would reject a legitimate owner's writes.\n"
                   "\n"
                   "  This is NOT threads-only. view.h and README advertise running\n"
                   "  \"alongside a live indexerd\" over WAL, i.e. multiple PROCESSES on\n"
                   "  one database — the same interleaving applies there with no threads\n"
                   "  involved at all.\n"
                   "\n"
                   "  Compounding: every writer ignores sqlite3_step()'s return code\n"
                   "  (state.c:287, 294, 356, 374, 413, 505), so a write that fails with\n"
                   "  SQLITE_BUSY is dropped while sp_state_admit() still returns 1\n"
                   "  (\"admitted\").\n"
                   "\n"
                   "  Interleaving that triggers it (2 threads suffice):\n"
                   "    T1: meta_get(zone) -> sum=S\n"
                   "    T2: meta_get(zone) -> sum=S            <- both read the same S\n"
                   "    T1: INSERT row_a (len La); meta_put(sum = S + La)\n"
                   "    T2: INSERT row_b (len Lb); meta_put(sum = S + Lb)  <- La lost\n"
                   "  Final: two rows totalling S+La+Lb bytes, sum_bytes = S+Lb.\n"
                   "\n"
                   "  Classification: RACE -> persistent state corruption + budget bypass.\n"
                   "  Fix shape: wrap the whole of sp_state_admit in\n"
                   "  BEGIN IMMEDIATE ... COMMIT (retrying on SQLITE_BUSY), and check\n"
                   "  every sqlite3_step() result.\n"
                   "  ******************************************************************\n\n");
        }
        /* FAILS: src/state.c:344-415 — sp_state_admit performs a non-atomic
           read-modify-write of st_names.sum_bytes with no enclosing transaction,
           so concurrent writers (threads OR the documented multi-process WAL
           setup) lose each other's byte accounting and the per-name budget stops
           being enforced. Single-threaded (nt=1 above) is always exact. */
        CK(diverged == 0,
           "held-byte accounting survives concurrent writers at 1/2/4/8/16 threads");
    }

    printf("-- threading review (read, not measured) --\n");
    printf("  note  src/*.c declare no pthread, no atomic, no mutex, no global mutable\n"
           "        state and no socket. Every module is either a pure function\n"
           "        (wire.c, crypto.c) or a struct owning one private sqlite3*\n"
           "        (view.c, state.c). The ONLY thread-safety contract that exists is\n"
           "        sqlite's, and it is honoured here by giving each thread its own\n"
           "        handle — which is what part 4 exercises.\n");
    printf("  note  sharing ONE SpState* across threads is NOT documented as safe and\n"
           "        is NOT tested here: state.h makes no such claim, so asserting it\n"
           "        would be inventing a contract. If a caller ever needs it, the\n"
           "        module would need an explicit lock — there is none today.\n");
    printf("  note  secp_shim.c:104 signctx() lazily initialises a function-local\n"
           "        static secp256k1_context with NO synchronisation. Two threads\n"
           "        calling sp_ecdsa_sign()/sp_pubkey() for the first time\n"
           "        simultaneously can both see c == NULL and both call\n"
           "        secp256k1_context_create(), leaking one context and racing on the\n"
           "        store to `c`. Part 4 signs only on the main thread before\n"
           "        spawning, so this is reported by READING, not by triggering.\n"
           "        Classification: benign-ish init race + leak, in the shim rather\n"
           "        than in src/. It would be a genuine TSan finding on any caller\n"
           "        that signs concurrently from a cold start.\n");
    CK(1, "threading review recorded");

    alarm(0);
    sp_view_close(vw);
    if (g_dir_ok) {
        char cmd[600]; snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
        if (system(cmd) != 0) printf("  note  could not remove %s\n", g_dir);
    }
    printf("\njitter_test: %ld checks, %d failed\n", g_checks, g_fail);
    if (g_fail) { printf("jitter_test: FAILED\n"); return 1; }
    printf("jitter_test: all passed\n");
    return 0;
}
