/* t_ops.c — the on-chain action layer: the §2 opcode registry, the exact
 * carrier bytes the desktop puts in an OP_RETURN, and the queue in src/ops.c
 * that decides WHEN those bytes get built.
 *
 * This is consensus-critical: a wrong byte burns real coin, and the wire
 * layout is the one thing a GUI test can pin without a chain. So the suite
 * proves, in this order:
 *
 *   1. the registry itself — VOTE_UP=0x01 … TRADE=0x0F — pinned against the
 *      canonical source (indexer/protocol/impls/c/src/sm.h) as literal bytes;
 *   2. the EXACT payload bytes of every action the desktop can build, as
 *      hardcoded hexdumps derived by reading src/wallet.c's carrier builders,
 *      cross-checked three ways: the hardcoded array == the protocol's own
 *      canonical encoder (sm_encode_action) == a byte-for-byte MIRROR of
 *      wallet.c's builder, and all three decode back through the real
 *      consensus decoder (sm_decode_payload);
 *   3. field widths, endianness and length prefixes — 5-byte LE anchors,
 *      8-byte LE prices, 4-byte LE windows, LSB-first bitmaps;
 *   4. the length bounds: names 1..32 of [a-z0-9-], flag bitmaps 1..71 (51 for
 *      TRANSFER), and that EVERY op's maximum payload still fits the 80-byte
 *      OP_RETURN relay ceiling — plus a canary proof that a max-length input
 *      does not run off the end of the carrier buffer;
 *   5. a seeded-random ROUND-TRIP property test (SplitMix64, never rand()):
 *      8000 valid actions across all 15 opcodes must encode → decode back to
 *      exactly the fields they went in with;
 *   6. src/ops.c itself — the FIFO, the §3.5 clash/serialization rules, the
 *      relay-cap hold, queue admission limits, and the balance projection —
 *      driven through its real public API with a stub signer/wallet/engine.
 *
 * MIRROR NOTE: swl_dispatch's carrier builders (src/wallet.c:1017-1316) are
 * static inside a translation unit that opens sqlite, sockets and secp, so the
 * `wc_*` functions below are hand-copied from it. They are the thing under
 * test in section 2 — if wallet.c's layout changes, these must change with it
 * and the hardcoded hexdumps must be re-derived from the spec.
 */
#include "ops.h"
#include "wallet.h"
#include "signer.h"
#include "engine.h"
#include "model.h"
#include "sm.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int g_fail;
#define CHECK(cond, name) do { \
    if (cond) printf("ok   %s\n", name); \
    else      { printf("FAIL %s\n", name); g_fail = 1; } \
} while (0)

static void hexdump(const char *tag, const uint8_t *b, size_t n) {
    printf("     %s (%zu):", tag, n);
    for (size_t i = 0; i < n; i++) printf(" %02x", b[i]);
    printf("\n");
}
static int bytes_eq(const char *what, const uint8_t *got, size_t gn,
                    const uint8_t *want, size_t wn) {
    if (gn == wn && memcmp(got, want, wn) == 0) return 1;
    printf("     %s MISMATCH\n", what);
    hexdump("want", want, wn);
    hexdump("got ", got, gn);
    return 0;
}

/* ── SplitMix64 — the suite's only randomness ─────────────────────────────── */
static uint64_t g_rng = 0xDEADBEEFCAFEF00DULL;
static uint64_t sm64(void) {
    uint64_t z = (g_rng += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static uint32_t rnd(uint32_t n) { return (uint32_t)(sm64() % n); }

/* ══ MIRROR of src/wallet.c's carrier builders — KEEP IN SYNC ═════════════════
 * Each returns the payload length. The 0xFF 'P' 'N' + opcode header and every
 * field offset below are copied verbatim from swl_dispatch/swl_do_commit.
 *
 * WC_*_CAP is the size wallet.c DECLARES for that op's `uint8_t payload[...]`
 * local. wallet.c itself performs the memcpy with no length check against it;
 * the mirrors refuse instead of reproducing the overrun, and the bounds
 * section below asserts on WC_*_CAP directly so the shortfall is visible as a
 * failing assertion rather than as a crashed test binary. */
#define WC_CLAIM_CAP      (4 + 32 + SM_NAME_MAX)   /* wallet.c:1130 */
#define WC_SELL_CAP       (4 + 8 + 4 + SM_NAME_MAX)/* wallet.c:1199 */
#define WC_NAME_ONLY_CAP  (4 + SM_NAME_MAX)        /* wallet.c:1237 / :1262 / :1284 */
#define WC_SELL_TO_CAP    (4 + 8 + 20 + SM_NAME_MAX) /* wallet.c:1311 */

static size_t wc_commit(uint8_t out[80], const uint8_t commitment[32]) {
    uint8_t payload[36] = { 0xFF, 0x50, 0x4E, SM_OP_COMMIT };
    memcpy(payload + 4, commitment, 32);
    memcpy(out, payload, 36); return 36;
}
static size_t wc_claim(uint8_t out[80], const uint8_t salt[32], const char *name) {
    size_t nlen = strlen(name);
    if (36 + nlen > WC_CLAIM_CAP) return 0;          /* wallet.c has NO such guard */
    uint8_t payload[WC_CLAIM_CAP] = { 0xFF, 0x50, 0x4E, SM_OP_CLAIM };
    memcpy(payload + 4, salt, 32);
    memcpy(payload + 36, name, nlen);
    memcpy(out, payload, 36 + nlen); return 36 + nlen;
}
static size_t wc_renew_all(uint8_t out[80]) {
    uint8_t payload[4] = { 0xFF, 0x50, 0x4E, SM_OP_RENEW };
    memcpy(out, payload, 4); return 4;
}
static size_t wc_renew_sel(uint8_t out[80], int64_t anchor, const uint8_t *flags, int nflags) {
    uint8_t payload[4 + 5 + 71] = { 0xFF, 0x50, 0x4E, SM_OP_RENEW };
    for (int i = 0; i < 5; i++) payload[4 + i] = (uint8_t)((uint64_t)anchor >> (8 * i));
    memcpy(payload + 9, flags, (size_t)nflags);
    memcpy(out, payload, 9 + (size_t)nflags); return 9 + (size_t)nflags;
}
static size_t wc_transfer_all(uint8_t out[80], const uint8_t to160[20]) {
    uint8_t payload[24] = { 0xFF, 0x50, 0x4E, SM_OP_TRANSFER };
    memcpy(payload + 4, to160, 20);
    memcpy(out, payload, 24); return 24;
}
static size_t wc_transfer_sel(uint8_t out[80], const uint8_t to160[20], int64_t anchor,
                              const uint8_t *flags, int nflags) {
    uint8_t payload[4 + 20 + 5 + 51] = { 0xFF, 0x50, 0x4E, SM_OP_TRANSFER };
    memcpy(payload + 4, to160, 20);
    for (int i = 0; i < 5; i++) payload[24 + i] = (uint8_t)((uint64_t)anchor >> (8 * i));
    memcpy(payload + 29, flags, (size_t)nflags);
    memcpy(out, payload, 29 + (size_t)nflags); return 29 + (size_t)nflags;
}
static size_t wc_sell(uint8_t out[80], uint64_t price, uint32_t window_s, const char *name) {
    size_t nlen = strlen(name);
    if (16 + nlen > WC_SELL_CAP) return 0;           /* wallet.c has NO such guard */
    uint8_t payload[WC_SELL_CAP] = { 0xFF, 0x50, 0x4E, SM_OP_SELL };
    for (int i = 0; i < 8; i++) payload[4 + i]  = (uint8_t)(price   >> (8 * i));
    for (int i = 0; i < 4; i++) payload[12 + i] = (uint8_t)(window_s >> (8 * i));
    memcpy(payload + 16, name, nlen);
    memcpy(out, payload, 16 + nlen); return 16 + nlen;
}
static size_t wc_release(uint8_t out[80], int64_t anchor, const uint8_t *flags, int nflags) {
    uint8_t payload[4 + 5 + 71] = { 0xFF, 0x50, 0x4E, SM_OP_RELEASE };
    for (int i = 0; i < 5; i++) payload[4 + i] = (uint8_t)((uint64_t)anchor >> (8 * i));
    memcpy(payload + 9, flags, (size_t)nflags);
    memcpy(out, payload, 9 + (size_t)nflags); return 9 + (size_t)nflags;
}
static size_t wc_name_only(uint8_t out[80], uint8_t op, const char *name) {
    size_t nlen = strlen(name);
    if (4 + nlen > WC_NAME_ONLY_CAP) return 0;       /* wallet.c has NO such guard */
    uint8_t payload[WC_NAME_ONLY_CAP] = { 0xFF, 0x50, 0x4E, 0 };
    payload[3] = op;
    memcpy(payload + 4, name, nlen);
    memcpy(out, payload, 4 + nlen); return 4 + nlen;
}
static size_t wc_sell_to(uint8_t out[80], uint64_t price, const uint8_t to160[20], const char *name) {
    size_t nlen = strlen(name);
    if (32 + nlen > WC_SELL_TO_CAP) return 0;        /* wallet.c has NO such guard */
    uint8_t payload[WC_SELL_TO_CAP] = { 0xFF, 0x50, 0x4E, SM_OP_SELL_TO };
    for (int i = 0; i < 8; i++) payload[4 + i] = (uint8_t)(price >> (8 * i));
    memcpy(payload + 12, to160, 20);
    memcpy(payload + 32, name, nlen);
    memcpy(out, payload, 32 + nlen); return 32 + nlen;
}
/* ══ end mirror ═══════════════════════════════════════════════════════════ */

/* fixed, printable test material so the hexdumps below are readable */
static const uint8_t SALT32[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08, 0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18, 0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,
};
static const uint8_t H160A[20] = {
    0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,
    0xaa,0xab,0xac,0xad,0xae,0xaf,0xb0,0xb1,0xb2,0xb3,
};

/* decode a payload through the REAL consensus decoder */
static int dec(const uint8_t *p, size_t n, SmAction *a) {
    SmCarrier car;
    memset(&car, 0, sizeof car);
    sm_decode_payload(p, n, 0, &car);
    if (car.kind != SM_CAR_ACTION) return 0;
    *a = car.act;
    return 1;
}

/* ══ section 6: the stub world src/ops.c is linked against ═══════════════════ */
Model M;                                  /* model.h's global, for the §activation gate */

/* relay-policy budgets (wallet.c owns the real ones): default datacarriersize
 * 83 → 80-byte payload → 71/51 flag bytes — the historical numbers. */
int swl_flags_budget_renew(void) { return 71; }
int swl_flags_budget_xfer(void)  { return 51; }

static pthread_mutex_t st_mu = PTHREAD_MUTEX_INITIALIZER;
static int  st_calls;                     /* swl_run invocations that completed */
static volatile int st_entered;           /* swl_run invocations that STARTED */
static SwlReq st_seen[128]; static int st_nseen;
/* SwlReq carries the coin view behind POINTERS into the worker's stack frame,
 * so the copy above dangles the moment swl_run returns — snapshot the values. */
static struct { int nvirt, nlocked; int64_t virt_value; uint32_t virt_vout; } st_view[128];
static int  st_force_code = SWL_R_OK;
static volatile int st_gate;              /* 1 = swl_run blocks until released */
static pthread_mutex_t gate_mu = PTHREAD_MUTEX_INITIALIZER;

int signer_ready(void) { return 1; }
int signer_acquire(SignerKey *out) { memset(out, 0, sizeof *out); return 1; }
void signer_release(SignerKey *k) { (void)k; }
const char *signer_backend(void) { return "test"; }
int64_t model_fee_k(void) { return 100000; }

/* The db's verdict on the chain, as the sweep reads it. Two worlds:
 *   mode 0 — nothing confirmed: each link's INPUTS are still unspent (0x77…,
 *            stamped by the stub builder) and no link's change outpoint exists;
 *   mode 1 — everything confirmed exactly as built: every outpoint we ask
 *            about is in the utxo set, so the youngest link's as-built change
 *            proves itself and every ancestor. */
static volatile int st_utxo_mode;
int engine_outpoint_unspent(const uint8_t h160[20], const uint8_t txid[32], uint32_t vout) {
    (void)h160; (void)vout;
    if (st_utxo_mode) return 1;
    return txid[0] == 0x77;
}
int engine_utxos(const uint8_t h160[20], EngineUtxoCb cb, void *ud) {
    (void)h160; (void)cb; (void)ud; return 0;
}
int engine_market_mine(const uint8_t h160[20], EngineName *out, int max) {
    (void)h160; (void)out; (void)max; return 0;
}
int engine_name_lookup(const char *name, uint8_t owner160[20], int *st) {
    (void)name; (void)owner160; (void)st; return 0;
}
int swl_rebroadcast(const char *coin, const char *ip, const char *dbpath,
                    const uint8_t *raw, size_t rawlen, const uint8_t txid[32]) {
    (void)coin; (void)ip; (void)dbpath; (void)raw; (void)rawlen; (void)txid; return 1;
}

/* the stub builder: records the request, hands back a plausible link */
int swl_run(const SwlReq *req, SwlRes *res) {
    st_entered++;
    if (st_gate) { pthread_mutex_lock(&gate_mu); pthread_mutex_unlock(&gate_mu); }
    memset(res, 0, sizeof *res);
    pthread_mutex_lock(&st_mu);
    int seq = st_calls++;
    if (st_nseen < 128) {
        st_view[st_nseen].nvirt      = req->nvirt;
        st_view[st_nseen].nlocked    = req->nlocked;
        st_view[st_nseen].virt_value = req->nvirt ? req->virt[0].value : -1;
        st_view[st_nseen].virt_vout  = req->nvirt ? req->virt[0].vout  : 0xFFFFFFFFu;
        st_seen[st_nseen++] = *req;
    }
    int code = st_force_code;
    pthread_mutex_unlock(&st_mu);
    res->code = (SwlCode)code;
    if (code == SWL_R_ERR) { snprintf(res->err, sizeof res->err, "stub refusal"); return 0; }
    if (code == SWL_R_WAIT_COMMIT) return 1;
    memset(res->txid32, 0, 32);
    res->txid32[0] = (uint8_t)(seq + 1);
    snprintf(res->txid, sizeof res->txid, "%064x", seq + 1);
    res->nins = 1;
    memset(res->ins[0].txid, 0x77, 32);
    res->ins[0].txid[31] = (uint8_t)seq;
    res->ins[0].vout = 0;
    res->has_change = 1;
    res->change_vout = 1;
    res->change_value = 5000000;
    res->spent_inputs = 10000000;
    res->change = 5000000;
    res->rawlen = 4;
    memset(res->raw, 0xAB, 4);
    return 1;
}

static void snooze(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000 * 1000 };
    nanosleep(&ts, NULL);
}
/* wait until swl_run has been entered at least `n` times */
static void wait_entered(int n) {
    for (int i = 0; i < 5000 && st_entered < n; i++) snooze(1);
}
/* wait until the worker has stopped making progress */
static void settle(void) {
    int last = -1;
    for (int i = 0; i < 400; i++) {
        snooze(5);
        OpsStatus s;
        ops_status(&s);
        int now = s.queued * 1000 + s.inflight;
        if (now == last && s.phase != OPS_BUSY) return;
        last = now;
    }
}

int main(void) {
    static uint8_t got[SM_CARRIER_MAX], want[SM_CARRIER_MAX];
    size_t gn;
    SmAction a;

    /* ── 1. the §2 opcode registry ─────────────────────────────────────────── */
    printf("-- §2 opcode registry (canonical: indexer/protocol/impls/c/src/sm.h) --\n");
    CHECK(SM_OP_RENEW_NAME    == 0x01, "RENEW_NAME    == 0x01");
    CHECK(SM_OP_TRANSFER_NAME == 0x02, "TRANSFER_NAME == 0x02");
    CHECK(SM_OP_COMMIT    == 0x03, "COMMIT    == 0x03");
    CHECK(SM_OP_CLAIM     == 0x04, "CLAIM     == 0x04");
    CHECK(SM_OP_RENEW     == 0x05, "RENEW     == 0x05");
    CHECK(SM_OP_TRANSFER  == 0x06, "TRANSFER  == 0x06");
    CHECK(SM_OP_SELL      == 0x07, "SELL      == 0x07");
    CHECK(SM_OP_RESERVE   == 0x08, "RESERVE   == 0x08");
    CHECK(SM_OP_SETTLE    == 0x09, "SETTLE    == 0x09");
    CHECK(SM_OP_RELEASE   == 0x0A, "RELEASE   == 0x0A");
    CHECK(SM_OP_RELEASE_NAME == 0x0B, "RELEASE_NAME == 0x0B");
    CHECK(SM_OP_SELL_TO   == 0x0C, "SELL_TO   == 0x0C");
    CHECK(SM_OP_PAY       == 0x0D, "PAY       == 0x0D");
    CHECK(SM_OP_AS        == 0x0E, "AS        == 0x0E");
    CHECK(SM_OP_TRADE     == 0x0F, "TRADE     == 0x0F");
    CHECK(SM_OP_MIN == SM_OP_RENEW_NAME && SM_OP_MAX == SM_OP_TRADE,
          "registry is contiguous 0x01..0x0F (uniform activation gate)");
    CHECK(SM_NAME_MAX == 32, "SM_NAME_MAX == 32");

    /* ── 2. exact wire bytes, hexdump-pinned ───────────────────────────────── */
    printf("-- exact carrier bytes: the 0xFF 'P' 'N' header --\n");
    {
        gn = wc_renew_all(got);
        static const uint8_t w[] = { 0xFF, 0x50, 0x4E, 0x05 };
        CHECK(bytes_eq("RENEW-all", got, gn, w, sizeof w),
              "bare RENEW == FF 50 4E 05 (4 bytes, no anchor, no bitmap)");
        CHECK(got[0] == 0xFF && got[1] == 'P' && got[2] == 'N',
              "every action carries the 0xFF 'P' 'N' magic");
        memset(&a, 0, sizeof a);
        a.op = SM_OP_RENEW;
        CHECK(sm_encode_action(&a, want) == gn && memcmp(want, got, gn) == 0,
              "canonical encoder agrees on bare RENEW");
        CHECK(dec(got, gn, &a) && a.op == SM_OP_RENEW && !a.has_anchor && a.flags_len == 0,
              "consensus decoder reads it back as renew-ALL");
    }

    printf("-- COMMIT (0x03) --\n");
    {
        uint8_t cm[32];
        for (int i = 0; i < 32; i++) cm[i] = (uint8_t)(0xC0 + i);
        gn = wc_commit(got, cm);
        static const uint8_t w[36] = {
            0xFF,0x50,0x4E,0x03,
            0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf,
            0xd0,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xd8,0xd9,0xda,0xdb,0xdc,0xdd,0xde,0xdf,
        };
        CHECK(bytes_eq("COMMIT", got, gn, w, sizeof w), "COMMIT == header + commitment[32], 36 bytes");
        memset(&a, 0, sizeof a); a.op = SM_OP_COMMIT; memcpy(a.commitment, cm, 32);
        CHECK(sm_encode_action(&a, want) == 36 && memcmp(want, got, 36) == 0, "canonical encoder agrees on COMMIT");
        CHECK(dec(got, gn, &a) && a.op == SM_OP_COMMIT && memcmp(a.commitment, cm, 32) == 0,
              "decoder recovers the commitment");
    }

    printf("-- CLAIM (0x04): salt(32) then the name, no length prefix --\n");
    {
        gn = wc_claim(got, SALT32, "pepe");
        static const uint8_t w[40] = {
            0xFF,0x50,0x4E,0x04,
            0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
            0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,
            'p','e','p','e',
        };
        CHECK(bytes_eq("CLAIM", got, gn, w, sizeof w), "CLAIM 'pepe' == header + salt[32] + name, 40 bytes");
        memset(&a, 0, sizeof a);
        a.op = SM_OP_CLAIM; memcpy(a.salt, SALT32, 32);
        memcpy(a.name, "pepe", 4); a.name_len = 4;
        CHECK(sm_encode_action(&a, want) == 40 && memcmp(want, got, 40) == 0, "canonical encoder agrees on CLAIM");
        CHECK(dec(got, gn, &a) && a.op == SM_OP_CLAIM && a.name_len == 4 &&
              strcmp(a.name, "pepe") == 0 && memcmp(a.salt, SALT32, 32) == 0,
              "decoder recovers salt + name (name length is implied by the payload length)");
    }

    printf("-- RENEW (0x05) selective: 5-byte LITTLE-ENDIAN anchor + LSB-first bitmap --\n");
    {
        uint8_t flags[71] = { 0 };
        flags[0] = 0x05;                     /* names at lex positions 0 and 2 */
        gn = wc_renew_sel(got, 0x0102030405LL, flags, 1);
        static const uint8_t w[10] = { 0xFF,0x50,0x4E,0x05, 0x05,0x04,0x03,0x02,0x01, 0x05 };
        CHECK(bytes_eq("RENEW-sel", got, gn, w, sizeof w),
              "selective RENEW == header + anchor LE5 + flags, 10 bytes");
        memset(&a, 0, sizeof a);
        a.op = SM_OP_RENEW; a.has_anchor = 1; a.anchor = 0x0102030405ULL;
        a.flags[0] = 0x05; a.flags_len = 1;
        CHECK(sm_encode_action(&a, want) == 10 && memcmp(want, got, 10) == 0, "canonical encoder agrees");
        CHECK(dec(got, gn, &a) && a.has_anchor && a.anchor == 0x0102030405ULL &&
              a.flags_len == 1 && a.flags[0] == 0x05,
              "decoder recovers the anchor little-endian and the bitmap byte");
        /* the 5-byte anchor field is the whole height range the chain can reach */
        gn = wc_renew_sel(got, 0xFFFFFFFFFFLL, flags, 1);
        CHECK(got[4] == 0xFF && got[5] == 0xFF && got[6] == 0xFF && got[7] == 0xFF && got[8] == 0xFF,
              "anchor 2^40-1 fills all five bytes");
        CHECK(dec(got, gn, &a) && a.anchor == 0xFFFFFFFFFFULL, "decoder reads the max anchor");
    }

    printf("-- TRANSFER (0x06): bare all-form and selective --\n");
    {
        gn = wc_transfer_all(got, H160A);
        static const uint8_t w[24] = {
            0xFF,0x50,0x4E,0x06,
            0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,
            0xaa,0xab,0xac,0xad,0xae,0xaf,0xb0,0xb1,0xb2,0xb3,
        };
        CHECK(bytes_eq("TRANSFER-all", got, gn, w, sizeof w),
              "bare TRANSFER == header + target hash160, 24 bytes");
        memset(&a, 0, sizeof a); a.op = SM_OP_TRANSFER; memcpy(a.addr, H160A, 20);
        CHECK(sm_encode_action(&a, want) == 24 && memcmp(want, got, 24) == 0, "canonical encoder agrees");
        CHECK(dec(got, gn, &a) && !a.has_anchor && memcmp(a.addr, H160A, 20) == 0,
              "decoder reads it as transfer-ALL (no anchor)");

        uint8_t flags[51] = { 0x80, 0x01 };
        gn = wc_transfer_sel(got, H160A, 0x0000000042LL, flags, 2);
        static const uint8_t w2[31] = {
            0xFF,0x50,0x4E,0x06,
            0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,
            0xaa,0xab,0xac,0xad,0xae,0xaf,0xb0,0xb1,0xb2,0xb3,
            0x42,0x00,0x00,0x00,0x00, 0x80,0x01,
        };
        CHECK(bytes_eq("TRANSFER-sel", got, gn, w2, sizeof w2),
              "selective TRANSFER == header + hash160 + anchor LE5 + flags, 31 bytes");
        memset(&a, 0, sizeof a);
        a.op = SM_OP_TRANSFER; memcpy(a.addr, H160A, 20);
        a.has_anchor = 1; a.anchor = 0x42; a.flags[0] = 0x80; a.flags[1] = 0x01; a.flags_len = 2;
        CHECK(sm_encode_action(&a, want) == 31 && memcmp(want, got, 31) == 0, "canonical encoder agrees");
        CHECK(dec(got, gn, &a) && a.has_anchor && a.anchor == 0x42 && a.flags_len == 2 &&
              a.flags[0] == 0x80 && a.flags[1] == 0x01 && memcmp(a.addr, H160A, 20) == 0,
              "decoder recovers target, anchor and bitmap");
    }

    printf("-- SELL (0x07): price LE8, window LE4, then the name --\n");
    {
        gn = wc_sell(got, 200000000ULL, 18000U, "shibe");
        static const uint8_t w[21] = {
            0xFF,0x50,0x4E,0x07,
            0x00,0xc2,0xeb,0x0b,0x00,0x00,0x00,0x00,      /* 200000000 LE */
            0x50,0x46,0x00,0x00,                          /* 18000 LE */
            's','h','i','b','e',
        };
        CHECK(bytes_eq("SELL", got, gn, w, sizeof w), "SELL == header + price LE8 + window LE4 + name");
        memset(&a, 0, sizeof a);
        a.op = SM_OP_SELL; a.price = 200000000ULL; a.window = 18000U;
        memcpy(a.name, "shibe", 5); a.name_len = 5;
        CHECK(sm_encode_action(&a, want) == 21 && memcmp(want, got, 21) == 0, "canonical encoder agrees");
        CHECK(dec(got, gn, &a) && a.price == 200000000ULL && a.window == 18000U &&
              strcmp(a.name, "shibe") == 0, "decoder recovers price, window and name");
        /* window 0 means "the default 5 h RESERVE_WINDOW" — it is a real zero */
        gn = wc_sell(got, 3ULL, 0U, "a");
        CHECK(got[12] == 0 && got[13] == 0 && got[14] == 0 && got[15] == 0 && gn == 17,
              "window 0 is encoded as four zero bytes, not omitted");
        CHECK(dec(got, gn, &a) && a.window == 0 && a.price == 3, "decoder reads window 0 / the SELL price floor");
        /* full 64-bit price */
        gn = wc_sell(got, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFU, "z");
        CHECK(dec(got, gn, &a) && a.price == 0xFFFFFFFFFFFFFFFFULL && a.window == 0xFFFFFFFFU,
              "a full-width price and window survive the round trip");
    }

    printf("-- RESERVE (0x08) / SETTLE (0x09) / PAY (0x0D): header + name --\n");
    {
        struct { uint8_t op; const char *label; } t[] = {
            { SM_OP_RESERVE, "RESERVE" }, { SM_OP_SETTLE, "SETTLE" }, { SM_OP_PAY, "PAY" },
        };
        for (unsigned i = 0; i < 3; i++) {
            gn = wc_name_only(got, t[i].op, "doge");
            uint8_t w[8] = { 0xFF, 0x50, 0x4E, 0, 'd','o','g','e' };
            w[3] = t[i].op;
            char nm[64];
            snprintf(nm, sizeof nm, "%s 'doge' == FF 50 4E %02X 'd' 'o' 'g' 'e' (8 bytes)", t[i].label, t[i].op);
            CHECK(bytes_eq(t[i].label, got, gn, w, sizeof w), nm);
            memset(&a, 0, sizeof a);
            a.op = t[i].op; memcpy(a.name, "doge", 4); a.name_len = 4;
            CHECK(sm_encode_action(&a, want) == 8 && memcmp(want, got, 8) == 0,
                  "canonical encoder agrees");
            CHECK(dec(got, gn, &a) && a.op == t[i].op && strcmp(a.name, "doge") == 0,
                  "decoder recovers the name");
        }
    }

    printf("-- RELEASE (0x0A): anchor LE5 + bitmap, always anchored --\n");
    {
        uint8_t flags[71] = { 0x01 };
        gn = wc_release(got, 900000LL, flags, 1);
        static const uint8_t w[10] = { 0xFF,0x50,0x4E,0x0A, 0xa0,0xbb,0x0d,0x00,0x00, 0x01 };
        CHECK(bytes_eq("RELEASE", got, gn, w, sizeof w), "RELEASE == header + anchor LE5 + flags, 10 bytes");
        memset(&a, 0, sizeof a);
        a.op = SM_OP_RELEASE; a.has_anchor = 1; a.anchor = 900000; a.flags[0] = 1; a.flags_len = 1;
        CHECK(sm_encode_action(&a, want) == 10 && memcmp(want, got, 10) == 0, "canonical encoder agrees");
        CHECK(dec(got, gn, &a) && a.has_anchor && a.anchor == 900000 && a.flags_len == 1,
              "decoder recovers the release bitmap");
        CHECK(dec((const uint8_t[]){0xFF,0x50,0x4E,0x0A, 0,0,0,0,0}, 9, &a) == 0,
              "a RELEASE with an EMPTY bitmap is refused (it must name something)");
    }

    printf("-- SELL_TO (0x0C): price LE8 + buyer hash160 + name --\n");
    {
        gn = wc_sell_to(got, 500000000ULL, H160A, "pepe");
        static const uint8_t w[36] = {
            0xFF,0x50,0x4E,0x0C,
            0x00,0x65,0xcd,0x1d,0x00,0x00,0x00,0x00,     /* 500000000 LE */
            0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,
            0xaa,0xab,0xac,0xad,0xae,0xaf,0xb0,0xb1,0xb2,0xb3,
            'p','e','p','e',
        };
        CHECK(bytes_eq("SELL_TO", got, gn, w, sizeof w), "SELL_TO == header + price LE8 + buyer + name");
        memset(&a, 0, sizeof a);
        a.op = SM_OP_SELL_TO; a.price = 500000000ULL; memcpy(a.addr, H160A, 20);
        memcpy(a.name, "pepe", 4); a.name_len = 4;
        CHECK(sm_encode_action(&a, want) == 36 && memcmp(want, got, 36) == 0, "canonical encoder agrees");
        CHECK(dec(got, gn, &a) && a.price == 500000000ULL && memcmp(a.addr, H160A, 20) == 0 &&
              strcmp(a.name, "pepe") == 0, "decoder recovers price, buyer and name");
    }

    printf("-- ops the desktop never builds, pinned anyway (the registry is shared) --\n");
    {
        memset(&a, 0, sizeof a);
        a.op = SM_OP_RENEW_NAME; memcpy(a.name, "pepe", 4); a.name_len = 4;
        gn = sm_encode_action(&a, got);
        CHECK(gn == 8 && got[3] == 0x01 && memcmp(got + 4, "pepe", 4) == 0,
              "RENEW_NAME == header + bare name bytes");
        memset(&a, 0, sizeof a);
        a.op = SM_OP_TRANSFER_NAME; memcpy(a.addr, H160A, 20);
        memcpy(a.name, "pepe", 4); a.name_len = 4;
        gn = sm_encode_action(&a, got);
        CHECK(gn == 28 && got[3] == 0x02 && memcmp(got + 4, H160A, 20) == 0 &&
              memcmp(got + 24, "pepe", 4) == 0,
              "TRANSFER_NAME == header + target(20) + name");
        memset(&a, 0, sizeof a);
        a.op = SM_OP_RELEASE_NAME; memcpy(a.name, "pepe", 4); a.name_len = 4;
        gn = sm_encode_action(&a, got);
        CHECK(gn == 8 && got[3] == 0x0B, "RELEASE_NAME == header + bare name bytes");
        memset(&a, 0, sizeof a);
        a.op = SM_OP_AS; a.as_index = 3;
        gn = sm_encode_action(&a, got);
        CHECK(gn == 5 && got[3] == 0x0E && got[4] == 3, "AS == header + one index byte");
        memset(&a, 0, sizeof a);
        a.op = SM_OP_TRADE; a.idx_a = 0; a.idx_b = 1;
        memcpy(a.name, "aa", 2); a.name_len = 2; memcpy(a.name_b, "bb", 2); a.name_b_len = 2;
        gn = sm_encode_action(&a, got);
        static const uint8_t wt[11] = { 0xFF,0x50,0x4E,0x0F, 0x00,0x01, 'a','a', 0x2C, 'b','b' };
        CHECK(bytes_eq("TRADE", got, gn, wt, sizeof wt), "TRADE == header + idxA + idxB + 'a,b'");
    }

    /* ── 4. bounds ─────────────────────────────────────────────────────────── */
    printf("-- name bounds (§3.1: [a-z0-9-], 1..32) --\n");
    {
        CHECK(sm_name_valid("a", 1) == 1, "a 1-byte name is valid");
        char n32[33]; memset(n32, 'a', 32); n32[32] = 0;
        CHECK(sm_name_valid(n32, 32) == 1, "a 32-byte name is valid");
        char n33[34]; memset(n33, 'a', 33); n33[33] = 0;
        CHECK(sm_name_valid(n33, 33) == 0, "a 33-byte name is REFUSED");
        CHECK(sm_name_valid("", 0) == 0, "the empty name is REFUSED");
        CHECK(sm_name_valid("Pepe", 4) == 0, "uppercase is REFUSED");
        CHECK(sm_name_valid("pe_pe", 5) == 0, "underscore is REFUSED (charset re-pin 2026-07-07)");
        CHECK(sm_name_valid("pe.pe", 5) == 0, "dot is REFUSED");
        CHECK(sm_name_valid("pe-pe", 5) == 1, "hyphen is ACCEPTED");
        CHECK(sm_name_valid("-a", 2) == 0 && sm_name_valid("a-", 2) == 0,
              "leading/trailing hyphens are REFUSED (structural re-pin 2026-07-07)");

        /* the decoder enforces the same bounds through the payload length
         * (built with the canonical encoder — wallet.c's mirror cannot express
         * a name this long; see the buffer section below) */
        memset(&a, 0, sizeof a);
        a.op = SM_OP_RESERVE; memcpy(a.name, n32, 32); a.name_len = 32;
        gn = sm_encode_action(&a, got);
        CHECK(gn == 36 && dec(got, gn, &a) && a.name_len == 32, "a 32-byte RESERVE name decodes");
        uint8_t over[80];
        memcpy(over, got, gn); over[gn] = 'a';
        CHECK(dec(over, gn + 1, &a) == 0, "a 33-byte RESERVE name is REFUSED by the decoder");
        CHECK(dec((const uint8_t[]){0xFF,0x50,0x4E,0x08}, 4, &a) == 0,
              "a RESERVE with an EMPTY name is REFUSED");
        CHECK(dec((const uint8_t[]){0xFF,0x50,0x4E,0x08,'A'}, 5, &a) == 0,
              "a RESERVE name outside the charset is REFUSED");

        /* the encoder refuses out-of-range name lengths rather than truncating */
        memset(&a, 0, sizeof a); a.op = SM_OP_RESERVE; a.name_len = 0;
        CHECK(sm_encode_action(&a, got) == 0, "canonical encoder refuses a zero-length name");
        a.name_len = 33;
        CHECK(sm_encode_action(&a, got) == 0, "canonical encoder refuses a 33-byte name");
    }

    printf("-- the desktop's carrier buffers vs. the 32-byte consensus bound --\n");
    {
        /* §3.1's charset/length was re-pinned to [a-z0-9-] 1..32 on 2026-07-07
         * (sm.h SM_NAME_MAX, state.c sm_name_valid). wallet.c's carrier locals
         * were sized for the OLD 20-byte bound and still are — its own refusal
         * text at :1104 still reads "at most 20 bytes" — and NOTHING between
         * the name field and the memcpy clamps the length:
         *
         *   claim dialog UI.claim_name[64], gated only by sm_name_valid (<=32)
         *     -> ops_claim() -> SwlReq.name[24]      (snprintf: <=23 bytes)
         *     -> swl_dispatch memcpy(payload+36, req->name, nlen)
         *        into uint8_t payload[4+32+20] = 56 bytes.  36+23 = 59.
         *
         * RESERVE/SETTLE/PAY never call sm_name_valid at all — their names come
         * from the projection via EngineName.name[24]. */
        SwlReq r; EngineName en;
        CHECK(sizeof r.name == (size_t)SM_NAME_MAX + 1,
              "SwlReq.name holds a full 32-byte consensus name + NUL");
        CHECK(sizeof en.name == (size_t)SM_NAME_MAX + 1,
              "EngineName.name holds a full 32-byte name (projection rows are not truncated)");
        size_t worst = sizeof r.name - 1;                /* 32 */
        CHECK(36 + worst <= WC_CLAIM_CAP,
              "CLAIM carrier holds a max-length name (36+32)");
        CHECK(16 + worst <= WC_SELL_CAP,
              "SELL carrier holds a max-length name (16+32)");
        CHECK(4 + worst <= WC_NAME_ONLY_CAP,
              "RESERVE/SETTLE/PAY carriers hold a max-length name (4+32)");
        CHECK(32 + worst <= WC_SELL_TO_CAP,
              "SELL_TO carrier holds a max-length name (32+32)");
        /* the FIRST buffer a long claim reaches: the commit's sha256 preimage,
         * salt(32) ‖ name ‖ h160(20), built in `uint8_t pre[32 + 20 + 20]` */
        CHECK(32 + worst + 20 <= (size_t)(32 + SM_NAME_MAX + 20),
              "commitment preimage holds salt+max-name+h160 (32+32+20)");
        CHECK((size_t)SM_NAME_MAX < sizeof r.name,
              "SwlReq.name is wide enough for the full consensus name");
        /* Boundary: a full-length consensus name now FITS every carrier, and
         * anything past SM_NAME_MAX is refused rather than copied. */
        char nmax[SM_NAME_MAX + 1]; memset(nmax, 'a', SM_NAME_MAX); nmax[SM_NAME_MAX] = 0;
        CHECK(wc_claim(got, SALT32, nmax) > 0, "a full 32-byte CLAIM name is carried, not refused");
        CHECK(wc_name_only(got, SM_OP_RESERVE, nmax) > 0,
              "a full 32-byte RESERVE name is carried, not refused");
        char nover[SM_NAME_MAX + 2]; memset(nover, 'a', SM_NAME_MAX + 1); nover[SM_NAME_MAX + 1] = 0;
        CHECK(wc_claim(got, SALT32, nover) == 0, "a name past SM_NAME_MAX is refused, never copied");
        CHECK(wc_name_only(got, SM_OP_RESERVE, nover) == 0,
              "an over-long RESERVE name is refused, never copied");
    }

    printf("-- bitmap bounds and the 80-byte OP_RETURN ceiling --\n");
    {
        uint8_t flags[71];
        memset(flags, 0xFF, sizeof flags);
        gn = wc_renew_sel(got, 1, flags, 71);
        CHECK(gn == 80, "selective RENEW with a full 71-byte bitmap is exactly 80 bytes");
        CHECK(dec(got, gn, &a) && a.flags_len == 71, "the decoder accepts a 71-byte renew bitmap");
        gn = wc_release(got, 1, flags, 71);
        CHECK(gn == 80 && dec(got, gn, &a) && a.flags_len == 71, "RELEASE tops out at 80 bytes / 71 flag bytes");
        gn = wc_transfer_sel(got, H160A, 1, flags, 51);
        CHECK(gn == 80, "selective TRANSFER with a full 51-byte bitmap is exactly 80 bytes");
        CHECK(dec(got, gn, &a) && a.flags_len == 51, "the decoder accepts a 51-byte transfer bitmap");
        /* one byte more crosses the RELAY budget (wallet.c refuses to build it)
         * but is CONSENSUS-valid out to the §6 ceiling — the decoder accepts it */
        uint8_t big[96];
        memcpy(big, got, gn); big[gn] = 0xFF;
        CHECK(dec(big, gn + 1, &a) == 1 && a.flags_len == 52,
              "a 52-byte transfer bitmap is consensus-VALID (§6; relay is the gate)");
        memset(&a, 0, sizeof a);
        a.op = SM_OP_TRANSFER; a.has_anchor = 1; a.flags_len = SM_FLAGS_XFER_MAX + 1;
        CHECK(sm_encode_action(&a, got) == 0, "canonical encoder refuses flags past the §6 transfer cap");
        a.op = SM_OP_RELEASE; a.flags_len = SM_FLAGS_MAX + 1;
        CHECK(sm_encode_action(&a, got) == 0, "canonical encoder refuses flags past the §6 release cap");
        a.flags_len = 0;
        CHECK(sm_encode_action(&a, got) == 0, "canonical encoder refuses an empty release bitmap");

        /* every op's worst case still relays (built canonically: a 32-byte
         * name overflows wallet.c's own carrier locals, see above) */
        char n32[33]; memset(n32, 'z', 32); n32[32] = 0;
        size_t worst[7];
        memset(&a, 0, sizeof a);
        a.op = SM_OP_CLAIM; memcpy(a.name, n32, 32); a.name_len = 32;
        worst[0] = sm_encode_action(&a, got);
        a.op = SM_OP_SELL; a.price = ~0ULL; a.window = ~0U;
        worst[1] = sm_encode_action(&a, got);
        a.op = SM_OP_SELL_TO; memcpy(a.addr, H160A, 20);
        worst[2] = sm_encode_action(&a, got);
        worst[3] = wc_renew_sel(got, ~0LL, flags, 71);
        worst[4] = wc_release(got, ~0LL, flags, 71);
        worst[5] = wc_transfer_sel(got, H160A, ~0LL, flags, 51);
        worst[6] = 36;                                   /* COMMIT is fixed */
        int all_fit = 1;
        for (int i = 0; i < 7; i++) if (worst[i] == 0 || worst[i] > 80) all_fit = 0;
        CHECK(all_fit, "every op's maximum payload fits the 80-byte OP_RETURN relay ceiling");
        CHECK(worst[0] == 68 && worst[1] == 48 && worst[2] == 64,
              "max CLAIM=68, max SELL=48, max SELL_TO=64 bytes");
    }

    printf("-- no overrun building a max-length carrier --\n");
    {
        struct { uint8_t buf[80]; uint8_t canary[32]; } box;
        memset(&box, 0x5A, sizeof box);
        char n20[21]; memset(n20, 'q', 20); n20[20] = 0;   /* the length wallet.c sized for */
        char n32[33]; memset(n32, 'q', 32); n32[32] = 0;
        uint8_t flags[71]; memset(flags, 0xFF, sizeof flags);
        wc_claim(box.buf, SALT32, n20);
        wc_renew_sel(box.buf, ~0LL, flags, 71);
        wc_release(box.buf, ~0LL, flags, 71);
        wc_transfer_sel(box.buf, H160A, ~0LL, flags, 51);
        wc_sell(box.buf, ~0ULL, ~0U, n20);
        wc_sell_to(box.buf, ~0ULL, H160A, n20);
        wc_name_only(box.buf, SM_OP_PAY, n20);
        memset(&a, 0, sizeof a);
        a.op = SM_OP_CLAIM; memcpy(a.name, n32, 32); a.name_len = 32;
        sm_encode_action(&a, box.buf);                     /* the 68-byte worst case */
        a.op = SM_OP_RELEASE; a.has_anchor = 1; a.anchor = ~0ULL >> 24;
        memcpy(a.flags, flags, 71); a.flags_len = 71;
        sm_encode_action(&a, box.buf);                     /* the 80-byte worst case */
        int intact = 1;
        for (unsigned i = 0; i < sizeof box.canary; i++) if (box.canary[i] != 0x5A) intact = 0;
        CHECK(intact, "the 32-byte canary past an 80-byte carrier is untouched by every builder");
    }

    printf("-- malformed payloads are refused, never guessed --\n");
    {
        CHECK(dec((const uint8_t[]){0xFE,0x50,0x4E,0x04}, 4, &a) == 0, "wrong magic byte 0 -> not an action");
        CHECK(dec((const uint8_t[]){0xFF,0x51,0x4E,0x04}, 4, &a) == 0, "wrong magic byte 1 -> not an action");
        CHECK(dec((const uint8_t[]){0xFF,0x50,0x4F,0x04}, 4, &a) == 0, "wrong magic byte 2 -> not an action");
        CHECK(dec((const uint8_t[]){0xFF,0x50,0x4E,0x00}, 4, &a) == 0, "opcode 0x00 is not in the registry");
        CHECK(dec((const uint8_t[]){0xFF,0x50,0x4E,0x10}, 4, &a) == 0, "opcode 0x10 is past the registry");
        CHECK(dec((const uint8_t[]){0xFF,0x50,0x4E,0xFF}, 4, &a) == 0, "opcode 0xFF is past the registry");
        uint8_t trunc[80];
        gn = wc_claim(trunc, SALT32, "pepe");
        CHECK(dec(trunc, gn - 1, &a) == 1, "CLAIM truncated by one byte decodes as a SHORTER name");
        CHECK(dec(trunc, 36, &a) == 0, "CLAIM with a zero-length name is REFUSED");
        CHECK(dec(trunc, 20, &a) == 0, "CLAIM truncated inside the salt is REFUSED");
        gn = wc_commit(trunc, SALT32);
        CHECK(dec(trunc, gn - 1, &a) == 0, "COMMIT is fixed-width: 31 commitment bytes is REFUSED");
        CHECK(dec(trunc, gn + 1, &a) == 0, "COMMIT with a trailing byte is REFUSED");
        gn = wc_transfer_all(trunc, H160A);
        CHECK(dec(trunc, gn + 1, &a) == 0, "TRANSFER with 21 target bytes is REFUSED (20 or >=26 only)");
        CHECK(dec(trunc, gn + 5, &a) == 0, "TRANSFER with an anchor but no bitmap is REFUSED");
    }

    /* ── 5. the round-trip property test ───────────────────────────────────── */
    printf("-- round-trip property: 8000 seeded-random actions --\n");
    {
        static const uint8_t OPS[] = {
            SM_OP_RENEW_NAME, SM_OP_TRANSFER_NAME, SM_OP_COMMIT, SM_OP_CLAIM, SM_OP_RENEW,
            SM_OP_TRANSFER, SM_OP_SELL, SM_OP_RESERVE, SM_OP_SETTLE, SM_OP_RELEASE,
            SM_OP_RELEASE_NAME, SM_OP_SELL_TO, SM_OP_PAY, SM_OP_AS, SM_OP_TRADE,
        };
        int seen[16] = { 0 };
        int enc_fail = 0, dec_fail = 0, field_fail = 0, over80 = 0;
        for (int it = 0; it < 8000; it++) {
            SmAction in;
            memset(&in, 0, sizeof in);
            uint8_t op = OPS[rnd(sizeof OPS)];
            in.op = op;
            switch (op) {
            case SM_OP_COMMIT:
                for (int i = 0; i < 32; i++) in.commitment[i] = (uint8_t)sm64();
                break;
            case SM_OP_CLAIM:
                for (int i = 0; i < 32; i++) in.salt[i] = (uint8_t)sm64();
                /* FALLTHROUGH to a name */
                /* fall through */
            case SM_OP_RESERVE: case SM_OP_SETTLE: case SM_OP_PAY:
            case SM_OP_RENEW_NAME: case SM_OP_RELEASE_NAME: case SM_OP_TRANSFER_NAME:
            case SM_OP_SELL: case SM_OP_SELL_TO: {
                in.name_len = (uint8_t)(1 + rnd(SM_NAME_MAX));
                for (int i = 0; i < in.name_len; i++) {
                    static const char AL[] = "abcdefghijklmnopqrstuvwxyz0123456789";  /* alnum only: the fuzz must not trip the §3.1 structural hyphen rules */
                    in.name[i] = AL[rnd(sizeof AL - 1)];
                }
                in.name[in.name_len] = 0;
                if (op == SM_OP_SELL)    { in.price = sm64(); in.window = (uint32_t)sm64(); }
                if (op == SM_OP_SELL_TO) { in.price = sm64();
                    for (int i = 0; i < 20; i++) in.addr[i] = (uint8_t)sm64(); }
                if (op == SM_OP_TRANSFER_NAME)
                    for (int i = 0; i < 20; i++) in.addr[i] = (uint8_t)sm64();
                break;
            }
            case SM_OP_RENEW: {
                int form = (int)rnd(3);
                if (form == 1) { in.has_anchor = 1; in.anchor = sm64() & 0xFFFFFFFFFFULL; }
                if (form == 2) {
                    in.has_anchor = 1; in.anchor = sm64() & 0xFFFFFFFFFFULL;
                    in.flags_len = (uint16_t)(1 + rnd(SM_FLAGS_MAX));
                    for (int i = 0; i < in.flags_len; i++) in.flags[i] = (uint8_t)sm64();
                }
                break;
            }
            case SM_OP_TRANSFER:
                for (int i = 0; i < 20; i++) in.addr[i] = (uint8_t)sm64();
                if (rnd(2)) {
                    in.has_anchor = 1; in.anchor = sm64() & 0xFFFFFFFFFFULL;
                    in.flags_len = (uint16_t)(1 + rnd(SM_FLAGS_XFER_MAX));
                    for (int i = 0; i < in.flags_len; i++) in.flags[i] = (uint8_t)sm64();
                }
                break;
            case SM_OP_RELEASE:
                in.has_anchor = 1; in.anchor = sm64() & 0xFFFFFFFFFFULL;
                in.flags_len = (uint16_t)(1 + rnd(SM_FLAGS_MAX));
                for (int i = 0; i < in.flags_len; i++) in.flags[i] = (uint8_t)sm64();
                break;
            case SM_OP_AS:
                in.as_index = (uint8_t)sm64();
                break;
            case SM_OP_TRADE: {
                static const char AL[] = "abcdefghijklmnopqrstuvwxyz0123456789";  /* alnum only: the fuzz must not trip the §3.1 structural hyphen rules */
                in.idx_a = (uint8_t)sm64(); in.idx_b = (uint8_t)sm64();
                in.name_len   = (uint8_t)(1 + rnd(32));
                in.name_b_len = (uint8_t)(1 + rnd(32));
                for (int i = 0; i < in.name_len; i++)   in.name[i]   = AL[rnd(sizeof AL - 1)];
                for (int i = 0; i < in.name_b_len; i++) in.name_b[i] = AL[rnd(sizeof AL - 1)];
                in.name[in.name_len] = 0; in.name_b[in.name_b_len] = 0;
                break;
            }
            default: break;
            }

            static uint8_t buf[SM_CARRIER_MAX];
            size_t n = sm_encode_action(&in, buf);
            if (n == 0) { enc_fail++; continue; }
            if (n > SM_CARRIER_MAX) { over80++; continue; }
            SmAction out;
            if (!dec(buf, n, &out)) { dec_fail++; continue; }

            int ok = out.op == in.op;
            switch (op) {
            case SM_OP_COMMIT:
                ok &= memcmp(out.commitment, in.commitment, 32) == 0; break;
            case SM_OP_CLAIM:
                ok &= memcmp(out.salt, in.salt, 32) == 0;
                /* fall through */
            case SM_OP_RESERVE: case SM_OP_SETTLE: case SM_OP_PAY:
            case SM_OP_RENEW_NAME: case SM_OP_RELEASE_NAME:
                ok &= out.name_len == in.name_len && strcmp(out.name, in.name) == 0; break;
            case SM_OP_TRANSFER_NAME:
                ok &= memcmp(out.addr, in.addr, 20) == 0 &&
                      out.name_len == in.name_len && strcmp(out.name, in.name) == 0; break;
            case SM_OP_SELL:
                ok &= out.price == in.price && out.window == in.window &&
                      out.name_len == in.name_len && strcmp(out.name, in.name) == 0; break;
            case SM_OP_SELL_TO:
                ok &= out.price == in.price && memcmp(out.addr, in.addr, 20) == 0 &&
                      out.name_len == in.name_len && strcmp(out.name, in.name) == 0; break;
            case SM_OP_RENEW:
                ok &= out.has_anchor == in.has_anchor && out.flags_len == in.flags_len &&
                      (!in.has_anchor || out.anchor == in.anchor) &&
                      memcmp(out.flags, in.flags, in.flags_len) == 0; break;
            case SM_OP_TRANSFER:
                ok &= memcmp(out.addr, in.addr, 20) == 0 &&
                      out.has_anchor == in.has_anchor && out.flags_len == in.flags_len &&
                      (!in.has_anchor || out.anchor == in.anchor) &&
                      memcmp(out.flags, in.flags, in.flags_len) == 0; break;
            case SM_OP_RELEASE:
                ok &= out.anchor == in.anchor && out.flags_len == in.flags_len &&
                      memcmp(out.flags, in.flags, in.flags_len) == 0; break;
            case SM_OP_AS:
                ok &= out.as_index == in.as_index; break;
            case SM_OP_TRADE:
                ok &= out.idx_a == in.idx_a && out.idx_b == in.idx_b &&
                      strcmp(out.name, in.name) == 0 && strcmp(out.name_b, in.name_b) == 0; break;
            default: break;
            }
            if (!ok) { field_fail++; if (field_fail == 1) hexdump("first mismatch", buf, n); }
            seen[op] = 1;
        }
        CHECK(enc_fail == 0, "every generated action encoded");
        CHECK(over80 == 0, "no action encoded past the SM_CARRIER_MAX ceiling (§6)");
        CHECK(dec_fail == 0, "every encoded action decoded back as an ACTION carrier");
        CHECK(field_fail == 0, "every decoded action matched its input fields exactly");
        int all_ops = 1;
        for (int i = 1; i <= 15; i++) if (!seen[i]) all_ops = 0;
        CHECK(all_ops, "the corpus covered all 15 opcodes");

        /* the §6 pinned ceiling, held from the emitter side too: a RENEW
         * at the full consensus flag budget is exactly the 9,996-byte carrier. */
        memset(&a, 0, sizeof a);
        a.op = SM_OP_RENEW; a.has_anchor = 1; a.flags_len = SM_FLAGS_MAX;
        CHECK(sm_encode_action(&a, got) == SM_CARRIER_MAX,
              "RENEW at SM_FLAGS_MAX encodes to exactly SM_CARRIER_MAX (9,996) bytes");
        a.flags_len = SM_FLAGS_MAX + 1;
        CHECK(sm_encode_action(&a, got) == 0, "flags past the consensus cap refuse to encode");
    }

    printf("-- bare UTF-8 is never an action (names-only demux) --\n");
    {
        SmCarrier car;
        const uint8_t hi[] = { 'h','e','l','l','o' };
        sm_decode_payload(hi, 5, 100, &car);
        CHECK(car.kind == SM_CAR_IGNORE, "burn-bearing UTF-8 is IGNORED (posts are gone)");
        sm_decode_payload(hi, 5, 0, &car);
        CHECK(car.kind == SM_CAR_IGNORE, "the same bytes with no burn are IGNORED");
        const uint8_t bad[] = { 0xFF, 0x50, 0x4E, 0x04, 'x' };
        sm_decode_payload(bad, 5, 100, &car);
        CHECK(car.kind == SM_CAR_IGNORE, "a MALFORMED action is IGNORED, never half-parsed");
    }

    /* ── 6. src/ops.c: the queue that decides when bytes get built ──────────── */
    char dir[256], db[512], parks[512];
    snprintf(dir, sizeof dir, "/tmp/t_ops_%d", (int)getpid());
    snprintf(db, sizeof db, "%s/chain.db", dir);
    snprintf(parks, sizeof parks, "%s/ops-pending-doge.txt", dir);

    printf("-- src/ops.c: submitter guards --\n");
    {
        uint8_t h160[20]; memset(h160, 0x22, 20);
        CHECK(ops_available() == 0, "ops_available() is 0 before ops_init");
        CHECK(ops_sell("x", 200000000ULL, 18000) == 0, "a submit before ops_init is refused");
        mkdir(dir, 0700);
        ops_init("doge", db, "127.0.0.1", h160);
        CHECK(ops_available() == 1, "ops_available() is 1 once inited and the signer is ready");
        CHECK(ops_gate() == NULL, "the submit gate is open on an empty queue");

        /* the §3.5 bitmap batch is 1..PEP_NAMES_MAX names — checked before anything is queued */
        CHECK(ops_release_multi(NULL, 0) == 0, "release of 0 names is refused");
        CHECK(ops_release_multi(NULL, PEP_NAMES_MAX + 1) == 0,
              "release past the batch cap is refused (bitmap batch is 1..PEP_NAMES_MAX)");
        CHECK(ops_renew_sel(NULL, 0, 1) == 0, "selective renew of 0 names is refused");
        CHECK(ops_renew_sel(NULL, PEP_NAMES_MAX + 1, 1) == 0, "selective renew past the batch cap is refused");
        CHECK(ops_transfer_sel(NULL, 0, H160A) == 0, "selective transfer of 0 names is refused");
        CHECK(ops_transfer_sel(NULL, PEP_NAMES_MAX + 1, H160A) == 0, "selective transfer past the batch cap is refused");

        /* §activation: a commit mined below the activation height can never fold */
        M.demo = 0; M.height = 100; M.activation = 500;
        CHECK(ops_claim("early", 1000) == 0, "a claim below the activation height is refused");
        M.height = 0; M.activation = 0;
        st_force_code = SWL_R_ERR;           /* refuse it so no link/park survives */
        CHECK(ops_claim("unknown", 1000) == 1, "…and once activation is 0 the guard opens");
        settle();
        st_force_code = SWL_R_OK;
        M.demo = 1;                          /* the rest of the suite runs demo-gated off */
        OpsStatus s;
        ops_status(&s);
        CHECK(s.inflight == 0 && s.queued == 0 && s.claim_wait == 0,
              "a refused build leaves no link, no queue entry and no park");
    }

    printf("-- src/ops.c: the durable commit->claim park --\n");
    {
        st_force_code = SWL_R_WAIT_COMMIT;   /* the commit is not indexed yet */
        st_calls = 0; st_nseen = 0; st_entered = 0;
        CHECK(ops_claim("parkme", 1234567) == 1, "a claim is accepted");
        settle();
        OpsStatus s;
        ops_status(&s);
        CHECK(s.inflight == 0, "SWL_R_WAIT_COMMIT creates no chain link");
        CHECK(s.claim_wait == 1, "…it parks: status reports claim_wait");
        CHECK(ops_name_pending("parkme") == OPS_PEND_CLAIM, "the parked name reads as a pending CLAIM");
        CHECK((ops_pending_buckets("parkme") & 8) != 0, "…and it is reported from the park bucket");
        char names[8][PEP_NAME_CAP];
        int n = ops_claiming(names, 8);
        CHECK(n == 1 && strcmp(names[0], "parkme") == 0, "ops_claiming() lists exactly the parked name");
        CHECK(ops_balance_delta() == -1234567,
              "the parked rent is already debited from the balance projection");

        /* the journal is what survives an app close between the two txs */
        FILE *f = fopen(parks, "r");
        char line[128] = { 0 };
        if (f) { if (!fgets(line, sizeof line, f)) line[0] = 0; fclose(f); }
        CHECK(f != NULL, "the two-phase park journal was written next to the db");
        CHECK(strcmp(line, "c 1234567 parkme\n") == 0,
              "the journal records 'c <rent> <name>' so a restart resumes the claim");

        /* a hard refusal unparks — it must not auto-retry forever */
        st_force_code = SWL_R_ERR;
        CHECK(ops_claim("parkme", 1234567) == 1, "re-submitting a parked claim is idempotent");
        settle();
        CHECK(ops_name_pending("parkme") == OPS_PEND_CLAIM,
              "an already-parked claim keeps waiting rather than rebuilding");
        st_force_code = SWL_R_OK;
    }

    printf("-- src/ops.c: FIFO, admission cap, and the chained coin view --\n");
    {
        st_calls = 0; st_nseen = 0; st_entered = 0;
        st_gate = 1;
        pthread_mutex_lock(&gate_mu);        /* freeze the worker inside swl_run */

        CHECK(ops_sell("name00", 200000000ULL, 18000) == 1, "the first op is accepted");
        wait_entered(1);
        CHECK(st_entered == 1, "the worker picked the head up and is inside the builder");

        int accepted = 0, refused = 0;
        for (int i = 1; i <= 17; i++) {
            char nm[24];
            snprintf(nm, sizeof nm, "name%02d", i);
            if (ops_sell(nm, 200000000ULL, 18000)) accepted++; else refused++;
        }
        CHECK(accepted == 16 && refused == 1,
              "the user queue admits exactly 16 waiting intents (Q_USER_MAX)");
        CHECK(ops_gate() != NULL, "the submit gate closes once the queue is full");
        OpsStatus s;
        ops_status(&s);
        CHECK(s.queued == 16, "status reports all 16 queued intents");
        CHECK(ops_name_pending("name05") == OPS_PEND_SELL, "a queued SELL reads as pending");
        CHECK(ops_name_pending("name99") == OPS_PEND_NONE, "an untouched name reads as not pending");
        CHECK((ops_pending_buckets("name05") & 4) != 0, "…from the queue bucket");
        CHECK((ops_pending_buckets("name00") & 1) != 0, "the op being built right now is in the cur bucket");
        CHECK(ops_balance_delta() <= -1234567 - 16 * model_fee_k(),
              "ops_balance_delta() debits the fee of every queued intent");

        pthread_mutex_unlock(&gate_mu);      /* let the worker drain */
        st_gate = 0;
        settle();

        ops_status(&s);
        CHECK(st_calls == 17, "the worker built all 17 intents");
        CHECK(s.queued == 0, "the queue drained");
        int fifo = 1;
        for (int i = 0; i < 17 && i < st_nseen; i++) {
            char nm[24];
            snprintf(nm, sizeof nm, "name%02d", i);
            if (strcmp(st_seen[i].name, nm) != 0) fifo = 0;
        }
        CHECK(fifo, "intents were built in FIFO order");
        CHECK(st_seen[0].op == SWL_SELL && st_seen[0].price == 200000000ULL &&
              st_seen[0].window_s == 18000, "the op args survived the queue verbatim");
        CHECK(st_seen[0].fee == model_fee_k(), "the fee stamped on the intent is the one the dialog showed");
        CHECK(st_seen[0].want_change == 1, "builds force a >= dust change output so the sweep can prove them");
        CHECK(strcmp(st_seen[0].dbpath, db) == 0 && strcmp(st_seen[0].ip, "127.0.0.1") == 0,
              "the build is stamped with the db path and peer ops_init was given");

        /* the chained coin view: link N+1 spends link N's change */
        CHECK(st_view[0].nvirt == 0 && st_view[0].nlocked == 0,
              "the first build sees a plain confirmed-only coin view");
        CHECK(st_view[1].nvirt == 1, "the second build sees the first link's change as a VIRTUAL utxo");
        CHECK(st_view[1].virt_value == 5000000 && st_view[1].virt_vout == 1,
              "…with the previous link's change value and vout");
        CHECK(st_view[1].nlocked == 1, "the second build has the first link's input LOCKED out");
        CHECK(st_view[16].nlocked == 16, "by link 17 every earlier link's inputs are locked");
        CHECK(st_view[16].nvirt == 1, "the newest change always rides the next build");

        ops_status(&s);
        CHECK(s.inflight == 17 && s.pending == 1, "17 links are in flight (nothing confirms in this stub)");
        CHECK(ops_balance_delta() == -17 * 5000000 - 1234567,
              "the projected delta is the links' net spend plus the parked rent");
    }

    printf("-- src/ops.c: the relay-cap hold (one under the 25-ancestor limit) --\n");
    {
        int before = st_calls;
        int accepted = 0;
        for (int i = 0; i < 16; i++) {
            char nm[24];
            snprintf(nm, sizeof nm, "cap%02d", i);
            if (ops_sell(nm, 200000000ULL, 18000)) accepted++;
        }
        CHECK(accepted == 16, "16 more ops are accepted into the queue");
        settle();
        OpsStatus s;
        ops_status(&s);
        CHECK(s.inflight == 24, "the chain stops at 24 links — one under the 25-ancestor relay cap");
        CHECK(s.queued == 9, "the remaining 9 intents wait in the queue");
        CHECK(st_calls == before + 7, "only the 7 intents that fit under the cap were built");
        CHECK(s.hold[0] != 0, "the hold reason is reported to the UI");
        CHECK(ops_name_pending("cap15") == OPS_PEND_SELL, "a held intent still reads as pending");
        CHECK((ops_pending_buckets("cap15") & 4) != 0, "…from the queue bucket");
        CHECK(ops_name_pending("name00") == OPS_PEND_SELL, "an in-flight SELL reads as pending");
        CHECK((ops_pending_buckets("name00") & 2) != 0, "…from the links bucket");

        /* a new tip at which the db shows NOTHING confirmed must pop nothing:
         * the sweep only retires links the db proves folded */
        ops_poll(1000, 100);
        settle();
        ops_status(&s);
        CHECK(s.inflight == 24, "a new tip with nothing confirmed pops no link");
        CHECK(s.queued == 10,
              "…and the parked claim re-fires exactly one attempt, at the queue FRONT");
        CHECK(s.claim_wait == 1, "the park survives a tip at which the commit has not indexed");

        /* now the db shows every link's as-built change — the youngest proven
         * link retires itself and every ancestor, and the held queue resumes */
        st_utxo_mode = 1;
        ops_poll(1001, 200);
        settle();
        ops_status(&s);
        CHECK(s.inflight == 10, "the proven chain retires and the 10 held intents build");
        CHECK(s.queued == 0, "the hold lifted once the chain drained");
        CHECK(s.claim_wait == 0, "the resumed claim completed and the park dissolved");
        CHECK(ops_name_pending("parkme") == OPS_PEND_CLAIM,
              "…the claim is now pending as an in-flight link instead");

        ops_poll(1002, 300);
        settle();
        ops_status(&s);
        CHECK(s.inflight == 0 && s.pending == 0, "the last links retire too");
        CHECK(ops_balance_delta() == 0, "an empty queue and chain project no balance delta");
        CHECK(ops_name_pending("parkme") == OPS_PEND_NONE, "…and nothing reads as pending any more");

        int sells = 0;
        for (int i = 0; i < st_nseen; i++) if (st_seen[i].op == SWL_SELL) sells++;
        CHECK(sells == 33, "all 33 submitted SELL intents were built exactly once");

        unlink(parks); unlink(db); rmdir(dir);
        (void)before;
    }

    printf("%s\n", g_fail ? "t_ops: FAIL" : "t_ops: all ok");
    return g_fail;
}
