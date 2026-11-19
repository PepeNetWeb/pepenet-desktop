// test_serve.c — the NODE_NETWORK_LIMITED serving cache (src/serve_store.c),
// which until now had NO suite of its own: `indexerd selftest`, test_db,
// test_sync and test_codec never name it. It is the whole read surface a
// remote peer can reach (getheaders / getblocks / getdata) plus the blockstage
// mailbox that folds blocks arriving over the mesh connection, so every
// answer below is one an untrusted peer can ask for.
//
// PROVES, against a REAL sqlite aux db in a mkdtemp'd /tmp directory (removed
// at the end — never ~/.pepenet):
//
//  13a. THE EMPTY STORE answers every reader with the documented "nothing"
//       value rather than a lie or a crash: tip -1, win_floor -1, locate -1,
//       headers_from 0 bytes / 0 count, hashes_from 0, block 0, have 0,
//       stage_next 0, stage_pending 0. And every entry point tolerates a NULL
//       ServeStore — the serve loop calls them with ss unset when the aux db
//       failed to open.
//  13b. PUT → READ round-trips byte-for-byte: tip tracks MAX(height),
//       hash_at is exact, headers_from returns headers STRICTLY above the
//       given height in ascending order concatenated at 80 bytes each,
//       hashes_from agrees with it hash-for-hash, and getdata returns the
//       exact raw bytes that were put.
//  13c. THE ROLLING WINDOW. After 400 sequential puts the raw window holds
//       exactly heights tip-288..tip and the HEADER chain is untrimmed below
//       it — so a block below the floor still resolves a hash but serves no
//       body (returns 0 rather than a short/empty block). win_floor reports
//       that floor exactly. Note recorded: the window is 289 wide, not 288
//       (`height < tip - 288` keeps tip-288); over-delivery, never under.
//  13d. LOCATE walks the locator newest→oldest and returns the FIRST height it
//       recognises — the fork point. Unknown locators, a zero-length locator,
//       and a locator whose only known entry sits last all behave.
//  13e. OUTPUT BOUNDS. headers_from never writes past outcap and never past
//       `max`, proven with a canary byte past the end of the buffer over every
//       cap from 0 to 40*80, and the reported count always matches the bytes
//       returned (bytes == 80*count).
//  13f. REORG. prune_above drops both tables strictly above the height and
//       keeps the height itself; pruning to -1 empties the store; pruning
//       above the tip is a no-op. A re-put at an occupied height REPLACES it,
//       and the displaced hash stops being served — no ghost header survives a
//       reorg to answer getdata for a block that is no longer ours.
//  13g. THE BLOCKSTAGE mailbox: stage_put reports 1 only on a genuinely new
//       hash and 0 on a duplicate; `have` covers stage rows as well as
//       headers (the inv-fetch dedup); stage_next chains by prev and hands
//       back malloc'd bytes; stage_del removes; rows age out at exactly
//       at < now-3600; the table is hard-capped to the freshest 32 rows; and
//       stage_pending counts only rows whose hash is NOT already a known
//       header.
//  13h. INVARIANTS under a seeded-random put/prune sequence (own SplitMix64 —
//       never rand()): tip == MAX(height) put and not pruned, win_floor is
//       never below tip-288 nor above tip, every hash inside the window
//       serves a body, and every hash outside it does not.
//
// Two robustness notes are recorded (read, not triggered) at the end of 13e
// for the unguarded `max` on headers_from. Both are unreachable from the
// shipped call sites, which pass hardcoded positive constants.
#include "serve_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

static void rm_db(const char *path) {
    char b[600];
    unlink(path);
    snprintf(b, sizeof b, "%s-wal", path);     unlink(b);
    snprintf(b, sizeof b, "%s-shm", path);     unlink(b);
    snprintf(b, sizeof b, "%s-journal", path); unlink(b);
}

static char g_dir[512];
static char g_paths[16][600];
static int  g_npaths;

// open a fresh, uniquely-named store inside the temp dir (tracked for teardown)
static ServeStore *fresh_store(const char *tag) {
    char *p = g_paths[g_npaths++];
    snprintf(p, 600, "%s/%s.db", g_dir, tag);
    rm_db(p);
    return serve_store_open(p);
}

// ── deterministic synthetic blocks ───────────────────────────────────────────
// A block at `height` in chain `variant`: an 80-byte header whose first bytes
// encode (height,variant), a 32-byte hash derived from the same pair, and a
// raw body that BEGINS with the header (exactly as sync.c passes it, where hdr
// and raw are the same pointer).
#define RAWLEN 200
typedef struct { uint8_t hash[32], hdr[80], raw[RAWLEN]; } Blk;

// The mixing must be INJECTIVE in (height,variant): an earlier draft used
// `height * 31 + i * 7` truncated to 8 bits, which made heights h and h+256
// share a hash — and a "block below the window" then resolved to a header 256
// higher that was still inside it. Below, bytes 0..11 carry height and variant
// verbatim, so two distinct blocks can never collide however the tail mixes.
static uint64_t mix64(uint64_t z) {
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void mkblk(Blk *b, int64_t height, uint32_t variant) {
    memset(b, 0, sizeof *b);
    uint64_t h = (uint64_t)height, v = variant;
    for (int i = 0; i < 8; i++)  b->hash[i]     = (uint8_t)(h >> (8 * i));
    for (int i = 0; i < 4; i++)  b->hash[8 + i] = (uint8_t)(v >> (8 * i));
    for (int i = 12; i < 32; i++)
        b->hash[i] = (uint8_t)(mix64(h * 0x100000001B3ULL + v + (uint64_t)i) >> 24);

    for (int i = 0; i < 8; i++)  b->hdr[i]     = (uint8_t)(h >> (8 * i));
    for (int i = 0; i < 4; i++)  b->hdr[8 + i] = (uint8_t)(v >> (8 * i));
    for (int i = 12; i < 80; i++)
        b->hdr[i] = (uint8_t)(mix64(h * 0x9E3779B1ULL + v * 131 + (uint64_t)i) >> 16);

    memcpy(b->raw, b->hdr, 80);
    for (int i = 80; i < RAWLEN; i++)
        b->raw[i] = (uint8_t)(mix64(h * 0xD6E8FEB86659FD93ULL + v * 43 + (uint64_t)i) >> 8);
}

// put a synthetic block, declaring `height` as the tip (what sync.c does)
static void put_blk(ServeStore *ss, Blk *b, int64_t height, uint32_t variant) {
    mkblk(b, height, variant);
    serve_store_put(ss, height, b->hash, b->hdr, b->raw, RAWLEN, height);
}

// ── 13.0 the test vectors themselves ─────────────────────────────────────────
// Every assertion below distinguishes blocks BY HASH, so a collision in the
// synthetic vectors would silently turn a real check into a vacuous one (an
// earlier draft collided at a 256-height period and made 13c pass a block that
// should have been out of window). Prove injectivity before relying on it.
static void sec_vectors(void) {
    printf("\n-- 13.0 the synthetic vectors are collision-free --\n");
    enum { H = 1200, NV = 3 };
    static uint8_t seen[H * NV][32];
    int k = 0, dup = 0, hdr_dup = 0;
    static uint8_t hdrs[H * NV][80];

    for (uint32_t v = 0; v < NV; v++)
        for (int64_t h = 0; h < H; h++) {
            Blk b; mkblk(&b, h, v);
            memcpy(seen[k], b.hash, 32);
            memcpy(hdrs[k], b.hdr, 80);
            k++;
        }
    for (int i = 0; i < k && !dup; i++)
        for (int j = i + 1; j < k; j++)
            if (memcmp(seen[i], seen[j], 32) == 0) { dup = 1; break; }
    for (int i = 0; i < k && !hdr_dup; i++)
        for (int j = i + 1; j < k; j++)
            if (memcmp(hdrs[i], hdrs[j], 80) == 0) { hdr_dup = 1; break; }

    CHECK(!dup,     "3600 (height,variant) pairs yield 3600 distinct hashes");
    CHECK(!hdr_dup, "... and 3600 distinct 80-byte headers");

    { Blk a, c; mkblk(&a, 7, 0); mkblk(&c, 7, 0);
      CHECK(memcmp(a.hash, c.hash, 32) == 0 && memcmp(a.raw, c.raw, RAWLEN) == 0,
            "mkblk is deterministic: the same (height,variant) rebuilds identical bytes"); }
    { Blk a, c; mkblk(&a, 7, 0); mkblk(&c, 7, 1);
      CHECK(memcmp(a.hash, c.hash, 32) != 0,
            "... and the variant alone changes the hash (forks are distinguishable)"); }
    { Blk a; mkblk(&a, 42, 0);
      CHECK(memcmp(a.raw, a.hdr, 80) == 0,
            "a raw block BEGINS with its header, as sync.c passes it"); }
}

// ── 13a. the empty store, and NULL tolerance ─────────────────────────────────
static void sec_empty(void) {
    printf("\n-- 13a. the empty store answers 'nothing', and NULL is tolerated --\n");
    ServeStore *ss = fresh_store("empty");
    CHECK(ss != NULL, "serve_store_open creates a fresh aux db");
    if (!ss) return;

    uint8_t h32[32], out[80 * 4], (*hs)[32] = malloc(4 * 32), *raw = NULL;
    size_t len = 0;
    int n = -1;

    CHECK(serve_store_tip(ss) == -1,                       "tip of an empty store is -1");
    CHECK(serve_store_win_floor(ss) == -1,                 "win_floor of an empty store is -1");
    CHECK(serve_store_locate(ss, (uint8_t *)"", 0) == -1,  "locate over a 0-length locator is -1");
    CHECK(serve_store_headers_from(ss, -1, out, sizeof out, 10, &n) == 0 && n == 0,
                                                           "headers_from returns 0 bytes / 0 count");
    CHECK(serve_store_hashes_from(ss, -1, hs, 4) == 0,     "hashes_from returns 0");
    memset(h32, 0x11, 32);
    CHECK(serve_store_hash_at(ss, 0, h32) == 0,            "hash_at on an empty store returns 0");
    CHECK(serve_store_block(ss, h32, &raw, &len) == 0,     "getdata on an empty store returns 0");
    CHECK(serve_store_have(ss, h32) == 0,                  "have() is 0 for an unknown hash");
    CHECK(serve_store_stage_next(ss, h32, h32, &raw, &len) == 0, "stage_next finds nothing");
    CHECK(serve_store_stage_pending(ss) == 0,              "stage_pending is 0");

    // the serve loop runs with ss == NULL whenever the aux db failed to open
    n = -1;
    CHECK(serve_store_tip(NULL) == -1,                     "NULL store: tip is -1");
    CHECK(serve_store_win_floor(NULL) == -1,               "NULL store: win_floor is -1");
    CHECK(serve_store_locate(NULL, h32, 1) == -1,          "NULL store: locate is -1");
    CHECK(serve_store_headers_from(NULL, -1, out, sizeof out, 10, &n) == 0 && n == 0,
                                                           "NULL store: headers_from is 0/0");
    CHECK(serve_store_hashes_from(NULL, -1, hs, 4) == 0,   "NULL store: hashes_from is 0");
    CHECK(serve_store_hash_at(NULL, 0, h32) == 0,          "NULL store: hash_at is 0");
    CHECK(serve_store_block(NULL, h32, &raw, &len) == 0,   "NULL store: getdata is 0");
    CHECK(serve_store_have(NULL, h32) == 0,                "NULL store: have is 0");
    CHECK(serve_store_stage_put(NULL, h32, h32, out, 4, 0) == 0, "NULL store: stage_put is 0");
    CHECK(serve_store_stage_next(NULL, h32, h32, &raw, &len) == 0, "NULL store: stage_next is 0");
    CHECK(serve_store_stage_pending(NULL) == 0,            "NULL store: stage_pending is 0");
    serve_store_prune_above(NULL, 0);                      // must not crash
    serve_store_stage_del(NULL, h32);                      // must not crash
    serve_store_close(NULL);                               // must not crash
    CHECK(1, "NULL store: prune_above / stage_del / close are no-ops, no crash");

    // a store with a header but an EMPTY body still refuses to serve a body:
    // 0 is "not held", never a zero-length block.
    Blk b; mkblk(&b, 5, 0);
    serve_store_put(ss, 5, b.hash, b.hdr, NULL, 0, 5);
    CHECK(serve_store_hash_at(ss, 5, h32) == 1 && memcmp(h32, b.hash, 32) == 0,
                                                           "a header-only put is still located by height");
    raw = NULL; len = 12345;
    CHECK(serve_store_block(ss, b.hash, &raw, &len) == 0,  "... but getdata for it returns 0, not an empty block");
    CHECK(raw == NULL,                                     "... and leaves the caller's raw pointer untouched");

    free(hs);
    serve_store_close(ss);
}

// ── 13b. put → read round-trip ───────────────────────────────────────────────
static void sec_put_read(void) {
    printf("\n-- 13b. put → read round-trips byte-for-byte --\n");
    ServeStore *ss = fresh_store("putread");
    if (!ss) { CHECK(0, "open putread store"); return; }

    Blk b[10];
    for (int64_t h = 0; h < 10; h++) put_blk(ss, &b[h], h, 0);

    CHECK(serve_store_tip(ss) == 9, "tip == MAX(height) after 10 sequential puts");

    int exact = 1;
    for (int64_t h = 0; h < 10; h++) {
        uint8_t got[32];
        if (!serve_store_hash_at(ss, h, got) || memcmp(got, b[h].hash, 32) != 0) exact = 0;
    }
    CHECK(exact, "hash_at returns the exact hash put at every height");
    { uint8_t got[32];
      CHECK(serve_store_hash_at(ss, 10, got) == 0, "hash_at above the tip returns 0"); }

    // headers_from is STRICTLY above the given height, ascending, 80B each
    uint8_t out[80 * 16]; int n = -1;
    size_t bytes = serve_store_headers_from(ss, 3, out, sizeof out, 16, &n);
    CHECK(n == 6 && bytes == 6 * 80, "headers_from(after=3) yields heights 4..9 (6 headers, 480 bytes)");
    int ord = 1;
    for (int i = 0; i < n; i++)
        if (memcmp(out + i * 80, b[4 + i].hdr, 80) != 0) ord = 0;
    CHECK(ord, "... in ascending height order, each header byte-exact");

    n = -1;
    bytes = serve_store_headers_from(ss, -1, out, sizeof out, 16, &n);
    CHECK(n == 10 && bytes == 800, "headers_from(after=-1) yields the whole chain from height 0");
    n = -1;
    bytes = serve_store_headers_from(ss, 9, out, sizeof out, 16, &n);
    CHECK(n == 0 && bytes == 0, "headers_from(after=tip) yields nothing (strictly above)");

    // hashes_from agrees with headers_from, hash for hash
    uint8_t (*hs)[32] = malloc(16 * 32);
    int nh = serve_store_hashes_from(ss, 3, hs, 16);
    int agree = (nh == 6);
    for (int i = 0; i < nh && agree; i++)
        if (memcmp(hs[i], b[4 + i].hash, 32) != 0) agree = 0;
    CHECK(agree, "hashes_from(after=3) returns the same six blocks, ascending");
    CHECK(serve_store_hashes_from(ss, 9, hs, 16) == 0, "hashes_from(after=tip) returns 0");
    CHECK(serve_store_hashes_from(ss, 3, hs, 2) == 2,  "hashes_from honours max");

    // getdata returns the exact bytes
    int bodies = 1;
    for (int64_t h = 0; h < 10; h++) {
        uint8_t *raw = NULL; size_t len = 0;
        if (!serve_store_block(ss, b[h].hash, &raw, &len) ||
            len != RAWLEN || memcmp(raw, b[h].raw, RAWLEN) != 0) bodies = 0;
        free(raw);
    }
    CHECK(bodies, "getdata returns the exact raw bytes put, at every height");

    { uint8_t bogus[32]; memset(bogus, 0x5C, 32);
      uint8_t *raw = NULL; size_t len = 0;
      CHECK(serve_store_block(ss, bogus, &raw, &len) == 0, "getdata for an unknown hash returns 0");
      CHECK(serve_store_have(ss, bogus) == 0,              "have() is 0 for an unknown hash");
      CHECK(serve_store_have(ss, b[7].hash) == 1,          "have() is 1 for a stored header"); }

    CHECK(serve_store_win_floor(ss) == 0, "win_floor is 0 while the chain is shorter than the window");

    free(hs);
    serve_store_close(ss);
}

// ── 13c. the rolling raw-block window ────────────────────────────────────────
static void sec_window(void) {
    printf("\n-- 13c. the rolling %d-block raw window --\n", SERVE_BLOCK_WINDOW);
    ServeStore *ss = fresh_store("window");
    if (!ss) { CHECK(0, "open window store"); return; }

    const int64_t TIP = 399;
    Blk b;
    for (int64_t h = 0; h <= TIP; h++) put_blk(ss, &b, h, 0);

    CHECK(serve_store_tip(ss) == TIP, "tip == 399 after 400 sequential puts");

    int64_t floor_h = serve_store_win_floor(ss);
    CHECK(floor_h == TIP - SERVE_BLOCK_WINDOW, "win_floor == tip - 288 exactly");

    // bodies: held from the floor up, gone below it
    int in_win = 1, below = 1;
    for (int64_t h = floor_h; h <= TIP; h++) {
        Blk e; mkblk(&e, h, 0);
        uint8_t *raw = NULL; size_t len = 0;
        if (!serve_store_block(ss, e.hash, &raw, &len) || len != RAWLEN) in_win = 0;
        free(raw);
    }
    for (int64_t h = 0; h < floor_h; h++) {
        Blk e; mkblk(&e, h, 0);
        uint8_t *raw = NULL; size_t len = 0;
        if (serve_store_block(ss, e.hash, &raw, &len) != 0) below = 0;
        free(raw);
    }
    CHECK(in_win, "every block from win_floor to the tip still serves its body");
    CHECK(below,  "every block BELOW win_floor serves no body (getdata returns 0)");

    // ... while the HEADER chain is never trimmed
    int hdrs = 1;
    for (int64_t h = 0; h <= TIP; h++) {
        Blk e; mkblk(&e, h, 0);
        uint8_t got[32];
        if (!serve_store_hash_at(ss, h, got) || memcmp(got, e.hash, 32) != 0) hdrs = 0;
        if (!serve_store_have(ss, e.hash)) hdrs = 0;
    }
    CHECK(hdrs, "the header chain is untrimmed: all 400 headers still resolve and are have()n");

    { int n = -1; static uint8_t out[2000 * 80];
      size_t bytes = serve_store_headers_from(ss, -1, out, sizeof out, 2000, &n);
      CHECK(n == 400 && bytes == 400 * 80, "getheaders can still walk the full 400-header chain"); }

    printf("note  the window is %d blocks wide, not %d: serve_store.c:55 deletes\n"
           "      `height < tip - %d`, which KEEPS height tip-%d. A limited node\n"
           "      therefore over-delivers by one block and never under-delivers\n"
           "      against the BIP159 promise — recorded, not a failure.\n",
           SERVE_BLOCK_WINDOW + 1, SERVE_BLOCK_WINDOW, SERVE_BLOCK_WINDOW, SERVE_BLOCK_WINDOW);
    { int64_t held = TIP - floor_h + 1;
      CHECK(held == SERVE_BLOCK_WINDOW + 1, "... and that width is exactly 289, as recorded above"); }

    serve_store_close(ss);
}

// ── 13d. locator resolution (the fork point) ─────────────────────────────────
static void sec_locate(void) {
    printf("\n-- 13d. locate walks the locator newest→oldest --\n");
    ServeStore *ss = fresh_store("locate");
    if (!ss) { CHECK(0, "open locate store"); return; }

    Blk b[20];
    for (int64_t h = 0; h < 20; h++) put_blk(ss, &b[h], h, 0);

    uint8_t loc[8 * 32];
    // a well-formed locator: newest→oldest, all known. First entry wins.
    for (int i = 0; i < 4; i++) memcpy(loc + i * 32, b[19 - i].hash, 32);
    CHECK(serve_store_locate(ss, loc, 4) == 19, "an all-known locator resolves to its FIRST (newest) entry");

    // the realistic shape: the peer's newest few are on a fork we don't know,
    // and the first hash we recognise is the fork point.
    Blk fork;
    for (int i = 0; i < 3; i++) { mkblk(&fork, 30 + i, 9); memcpy(loc + i * 32, fork.hash, 32); }
    memcpy(loc + 3 * 32, b[12].hash, 32);
    memcpy(loc + 4 * 32, b[6].hash, 32);
    CHECK(serve_store_locate(ss, loc, 5) == 12,
          "unknown entries are skipped; the first recognised one (height 12) is the fork point");

    // nothing in common → -1 ("send from my earliest" for getheaders; silence for getblocks)
    for (int i = 0; i < 5; i++) { mkblk(&fork, 50 + i, 9); memcpy(loc + i * 32, fork.hash, 32); }
    CHECK(serve_store_locate(ss, loc, 5) == -1, "a locator with no common block resolves to -1");

    CHECK(serve_store_locate(ss, loc, 0) == -1, "a zero-length locator resolves to -1");

    // only the LAST entry is known — the loop must run to the end
    for (int i = 0; i < 7; i++) { mkblk(&fork, 60 + i, 9); memcpy(loc + i * 32, fork.hash, 32); }
    memcpy(loc + 7 * 32, b[0].hash, 32);
    CHECK(serve_store_locate(ss, loc, 8) == 0, "a locator whose ONLY known entry is last still resolves (height 0)");

    serve_store_close(ss);
}

// ── 13e. output bounds on headers_from ───────────────────────────────────────
static void sec_bounds(void) {
    printf("\n-- 13e. headers_from never writes past outcap or max --\n");
    ServeStore *ss = fresh_store("bounds");
    if (!ss) { CHECK(0, "open bounds store"); return; }

    Blk b[40];
    for (int64_t h = 0; h < 40; h++) put_blk(ss, &b[h], h, 0);

    // canary-guarded buffer: one byte past every cap must survive
    enum { BUFCAP = 40 * 80 };
    static uint8_t buf[BUFCAP + 1];
    int cap_ok = 1, count_ok = 1, prefix_ok = 1;

    for (size_t cap = 0; cap <= BUFCAP; cap++) {
        memset(buf, 0, sizeof buf);
        buf[cap] = 0xDD;                                   // canary immediately past the cap
        int n = -1;
        size_t bytes = serve_store_headers_from(ss, -1, buf, cap, 40, &n);

        if (buf[cap] != 0xDD)                cap_ok   = 0; // wrote past outcap
        if (bytes > cap)                     cap_ok   = 0;
        if (n < 0 || bytes != (size_t)n * 80) count_ok = 0; // bytes and count must agree
        if ((size_t)n != cap / 80)            count_ok = 0; // exactly as many as fit
        for (int i = 0; i < n; i++)
            if (memcmp(buf + i * 80, b[i].hdr, 80) != 0) prefix_ok = 0;
    }
    CHECK(cap_ok,    "over every cap 0..3200: the canary survives and bytes <= cap");
    CHECK(count_ok,  "... the reported count is exactly cap/80 and bytes == 80*count");
    CHECK(prefix_ok, "... and what IS written is the correct ascending prefix");

    // `max` bounds the count independently of the buffer
    int max_ok = 1;
    for (int max = 0; max <= 40; max++) {
        int n = -1;
        size_t bytes = serve_store_headers_from(ss, -1, buf, BUFCAP, max, &n);
        if (n != max || bytes != (size_t)max * 80) max_ok = 0;
    }
    CHECK(max_ok, "max bounds the count exactly, for every max 0..40");

    { int n = -1;
      CHECK(serve_store_headers_from(ss, -1, buf, BUFCAP, 0, &n) == 0 && n == 0,
            "max == 0 returns nothing"); }

    // the same for hashes_from
    uint8_t (*hs)[32] = malloc(64 * 32);
    int hf_ok = 1;
    for (int max = 1; max <= 40; max++)
        if (serve_store_hashes_from(ss, -1, hs, max) != max) hf_ok = 0;
    CHECK(hf_ok, "hashes_from honours max for every max 1..40");
    CHECK(serve_store_hashes_from(ss, -1, hs, 0) == 0,  "hashes_from(max=0) returns 0");
    CHECK(serve_store_hashes_from(ss, -1, hs, -1) == 0, "hashes_from(max=-1) is GUARDED and returns 0");

    // robustness notes — read, and demonstrated here, but not reachable from
    // any shipped call site (sync.c passes the constants 2000, 500 and 32).
    printf("-- robustness notes (demonstrated, not reachable in production) --\n");
    { int n = -1;
      size_t bytes = serve_store_headers_from(ss, -1, buf, BUFCAP, -1, &n);
      printf("note  src/serve_store.c:106  headers_from binds `max` straight into\n"
             "      LIMIT ?, and SQLite treats a NEGATIVE limit as UNLIMITED — so\n"
             "      max=-1 returned %d headers (%zu bytes) instead of none, where\n"
             "      hashes_from's explicit `max <= 0` guard returns 0. The outcap\n"
             "      bound still holds, so this is a count asymmetry, not an\n"
             "      overrun. Both shipped callers pass positive constants.\n",
             n, bytes);
      CHECK(bytes <= BUFCAP, "... even under the unlimited LIMIT, outcap is still respected"); }

    free(hs);
    serve_store_close(ss);
}

// ── 13f. reorg: prune_above and replace-at-height ────────────────────────────
static void sec_reorg(void) {
    printf("\n-- 13f. reorg: prune_above and replace-at-height --\n");
    ServeStore *ss = fresh_store("reorg");
    if (!ss) { CHECK(0, "open reorg store"); return; }

    Blk b[30];
    for (int64_t h = 0; h < 30; h++) put_blk(ss, &b[h], h, 0);

    serve_store_prune_above(ss, 20);
    CHECK(serve_store_tip(ss) == 20, "prune_above(20) leaves the tip at 20");

    { uint8_t got[32];
      CHECK(serve_store_hash_at(ss, 20, got) == 1, "height 20 itself is KEPT (strictly above is dropped)");
      CHECK(serve_store_hash_at(ss, 21, got) == 0, "height 21 is gone"); }

    int gone = 1;
    for (int64_t h = 21; h < 30; h++) {
        uint8_t *raw = NULL; size_t len = 0; uint8_t got[32];
        if (serve_store_hash_at(ss, h, got)) gone = 0;
        if (serve_store_have(ss, b[h].hash)) gone = 0;
        if (serve_store_block(ss, b[h].hash, &raw, &len)) gone = 0;
        free(raw);
    }
    CHECK(gone, "every pruned height is gone from BOTH tables (no header, no body)");

    int kept = 1;
    for (int64_t h = 0; h <= 20; h++) {
        uint8_t *raw = NULL; size_t len = 0;
        if (!serve_store_have(ss, b[h].hash)) kept = 0;
        if (!serve_store_block(ss, b[h].hash, &raw, &len)) kept = 0;
        free(raw);
    }
    CHECK(kept, "everything at or below 20 survives with its body");

    serve_store_prune_above(ss, 999);
    CHECK(serve_store_tip(ss) == 20, "prune_above above the tip is a no-op");

    // the reorg that matters: a DIFFERENT block arrives at an occupied height
    Blk alt;
    put_blk(ss, &alt, 20, 7);                              // variant 7 = the winning fork
    CHECK(serve_store_tip(ss) == 20, "re-put at height 20 keeps the tip at 20");
    { uint8_t got[32];
      CHECK(serve_store_hash_at(ss, 20, got) == 1 && memcmp(got, alt.hash, 32) == 0,
            "height 20 now resolves to the NEW hash"); }
    CHECK(serve_store_have(ss, alt.hash) == 1,  "the new block is have()n");
    CHECK(serve_store_have(ss, b[20].hash) == 0, "the DISPLACED hash is no longer have()n (no ghost header)");
    { uint8_t *raw = NULL; size_t len = 0;
      CHECK(serve_store_block(ss, b[20].hash, &raw, &len) == 0,
            "... and getdata for the displaced hash returns 0");
      free(raw); raw = NULL;
      CHECK(serve_store_block(ss, alt.hash, &raw, &len) == 1 && len == RAWLEN &&
            memcmp(raw, alt.raw, RAWLEN) == 0, "... while the new block serves its own body");
      free(raw); }

    serve_store_prune_above(ss, -1);
    CHECK(serve_store_tip(ss) == -1,       "prune_above(-1) empties the store");
    CHECK(serve_store_win_floor(ss) == -1, "... including the raw window");

    serve_store_close(ss);
}

// ── 13g. the blockstage mailbox ──────────────────────────────────────────────
static void sec_stage(void) {
    printf("\n-- 13g. the blockstage mailbox --\n");
    ServeStore *ss = fresh_store("stage");
    if (!ss) { CHECK(0, "open stage store"); return; }

    Blk p, c1, c2;
    mkblk(&p,  100, 0);                                    // the parent (a known header)
    mkblk(&c1, 101, 0);                                    // a child chaining onto it
    mkblk(&c2, 102, 0);

    CHECK(serve_store_stage_put(ss, c1.hash, p.hash, c1.raw, RAWLEN, 1000) == 1,
          "stage_put reports 1 for a newly staged hash");
    CHECK(serve_store_stage_put(ss, c1.hash, p.hash, c1.raw, RAWLEN, 1000) == 0,
          "... and 0 for a duplicate (INSERT OR IGNORE — the inv-fetch dedup)");
    CHECK(serve_store_stage_put(ss, c1.hash, p.hash, NULL, 0, 1000) == 0,
          "a body-less stage_put is refused outright");

    CHECK(serve_store_have(ss, c1.hash) == 1,
          "have() covers stage rows as well as headers");

    // stage_next chains by prev
    { uint8_t hout[32], *raw = NULL; size_t len = 0;
      int got = serve_store_stage_next(ss, p.hash, hout, &raw, &len);
      CHECK(got == 1 && memcmp(hout, c1.hash, 32) == 0 && len == RAWLEN &&
            memcmp(raw, c1.raw, RAWLEN) == 0,
            "stage_next(prev) hands back the child's hash and exact bytes");
      free(raw); }

    { uint8_t hout[32], *raw = NULL; size_t len = 0;
      CHECK(serve_store_stage_next(ss, c2.hash, hout, &raw, &len) == 0,
            "stage_next for a prev nothing chains to returns 0");
      free(raw); }

    CHECK(serve_store_stage_pending(ss) == 1,
          "stage_pending counts the staged block (its hash is no known header)");

    // once the same block is a known HEADER, it stops being 'pending'
    serve_store_put(ss, 101, c1.hash, c1.hdr, c1.raw, RAWLEN, 101);
    CHECK(serve_store_stage_pending(ss) == 0,
          "... and stops counting once that hash is a known header (it just ages out)");

    serve_store_stage_del(ss, c1.hash);
    { uint8_t hout[32], *raw = NULL; size_t len = 0;
      CHECK(serve_store_stage_next(ss, p.hash, hout, &raw, &len) == 0, "stage_del removes the row");
      free(raw); }

    serve_store_close(ss);

    // ── aging: rows die at exactly at < now-3600 ──
    ss = fresh_store("stage_age");
    if (!ss) { CHECK(0, "open stage_age store"); return; }
    Blk old, mid, new_;
    mkblk(&old, 200, 1); mkblk(&mid, 201, 1); mkblk(&new_, 202, 1);

    serve_store_stage_put(ss, old.hash, p.hash, old.raw, RAWLEN, 1000);
    CHECK(serve_store_stage_pending(ss) == 1, "aging: one row staged at t=1000");

    // now = 4600 → delete at < 1000 → 1000 is NOT less than 1000 → survives
    serve_store_stage_put(ss, mid.hash, p.hash, mid.raw, RAWLEN, 4600);
    CHECK(serve_store_stage_pending(ss) == 2,
          "at t=now-3600 exactly, the old row SURVIVES (the bound is `at < now-3600`)");

    // now = 4601 → delete at < 1001 → the t=1000 row goes
    serve_store_stage_put(ss, new_.hash, p.hash, new_.raw, RAWLEN, 4601);
    CHECK(serve_store_stage_pending(ss) == 2,
          "one second later it is aged out (2 rows: the two fresh ones)");
    CHECK(serve_store_have(ss, old.hash) == 0, "... and the aged-out hash is no longer have()n");
    CHECK(serve_store_have(ss, mid.hash) == 1 && serve_store_have(ss, new_.hash) == 1,
          "... while both fresh rows remain");

    serve_store_close(ss);

    // ── the hard cap: the freshest 32 rows, no matter how much junk arrives ──
    ss = fresh_store("stage_cap");
    if (!ss) { CHECK(0, "open stage_cap store"); return; }
    Blk junk[64];
    for (int i = 0; i < 64; i++) {
        mkblk(&junk[i], 300 + i, 2);
        serve_store_stage_put(ss, junk[i].hash, p.hash, junk[i].raw, RAWLEN, 10000 + i);
    }
    CHECK(serve_store_stage_pending(ss) == 32,
          "64 staged junk blocks are hard-capped to 32 rows");

    int freshest = 1, oldest_gone = 1;
    for (int i = 32; i < 64; i++) if (!serve_store_have(ss, junk[i].hash)) freshest = 0;
    for (int i = 0;  i < 32; i++) if ( serve_store_have(ss, junk[i].hash)) oldest_gone = 0;
    CHECK(freshest,    "... and the 32 kept are the FRESHEST by `at`");
    CHECK(oldest_gone, "... the 32 oldest were evicted");

    serve_store_close(ss);
}

// ── 13h. invariants under a seeded-random put/prune sequence ─────────────────
static void sec_property(void) {
    printf("\n-- 13h. invariants under seeded-random put/prune --\n");
    ServeStore *ss = fresh_store("property");
    if (!ss) { CHECK(0, "open property store"); return; }

    g_rng = 0x5E4E570E1234ULL;
    int64_t model_tip = -1;                                // the height we believe is the tip
    int64_t max_tip = -1;                                  // deepest the walk ever got
    int tip_ok = 1, floor_ok = 1, body_ok = 1, prunes = 0, puts = 0;
    int trimmed_seen = 0;                                  // did we ever observe a trimmed window?

    for (int step = 0; step < 1200; step++) {
        // Reorgs are shallow relative to the extend rate ON PURPOSE: at ~8%
        // with depths up to 40 the walk drifts backwards (-0.68 height/step)
        // and the chain never reaches 288, so the window logic below is never
        // exercised. These figures net out to roughly +0.7/step.
        if (model_tip >= 0 && (rnd64() % 100) < 8) {       // ~8% of steps: a reorg
            int64_t depth = (int64_t)(rnd64() % 6);
            int64_t to = model_tip - depth; if (to < -1) to = -1;
            serve_store_prune_above(ss, to);
            model_tip = to;
            prunes++;
        } else {                                            // otherwise extend by one
            Blk b;
            put_blk(ss, &b, model_tip + 1, 0);
            model_tip++;
            puts++;
        }
        if (model_tip > max_tip) max_tip = model_tip;

        if (serve_store_tip(ss) != model_tip) tip_ok = 0;

        int64_t fl = serve_store_win_floor(ss);
        if (fl > 0) trimmed_seen = 1;
        if (model_tip < 0) {
            if (fl != -1) floor_ok = 0;
        } else {
            if (fl < 0 || fl > model_tip) floor_ok = 0;
            if (fl < model_tip - SERVE_BLOCK_WINDOW) floor_ok = 0;
        }

        // spot-check the body invariant: inside the window a body is served,
        // outside it (but still a known header) it is not.
        if (model_tip >= 0) {
            int64_t h = (int64_t)(rnd64() % (uint64_t)(model_tip + 1));
            Blk e; mkblk(&e, h, 0);
            uint8_t *raw = NULL; size_t len = 0;
            int served = serve_store_block(ss, e.hash, &raw, &len);
            free(raw);
            int expect = (fl >= 0 && h >= fl);
            if (served != expect) body_ok = 0;
            if (served && len != RAWLEN) body_ok = 0;
        }
    }

    printf("     (%d puts, %d prunes, final tip %lld, deepest tip %lld)\n",
           puts, prunes, (long long)model_tip, (long long)max_tip);
    // Guard the guard: if the walk never outgrows the window, the floor and
    // body invariants below are vacuous. Assert the run actually got there.
    CHECK(max_tip > SERVE_BLOCK_WINDOW,
          "the walk grew past the 288-block window (so the trim path was exercised)");
    CHECK(trimmed_seen, "... and a trimmed (non-zero) win_floor was actually observed");
    CHECK(tip_ok,   "tip always equals the highest un-pruned height put");
    CHECK(floor_ok, "win_floor is always within [tip-288, tip], or -1 when empty");
    CHECK(body_ok,  "a body is served exactly when its height is at or above win_floor");

    serve_store_close(ss);
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/idx_test_serve_XXXXXX");
    if (!mkdtemp(g_dir)) { fprintf(stderr, "mkdtemp failed\n"); return 1; }
    printf("temp serve-store dir: %s\n", g_dir);

    sec_vectors();
    sec_empty();
    sec_put_read();
    sec_window();
    sec_locate();
    sec_bounds();
    sec_reorg();
    sec_stage();
    sec_property();

    for (int i = 0; i < g_npaths; i++) rm_db(g_paths[i]);
    if (rmdir(g_dir) != 0) fprintf(stderr, "warning: could not remove %s\n", g_dir);

    printf(g_fail ? "\ntest_serve: FAIL\n" : "\ntest_serve: all ok\n");
    return g_fail;
}
