// Differential-fuzz, property, and reorg test harnesses (SPEC-conformance.md §8–§10).
//
// Three modes beyond the `random` soak and the directed `scenario` vectors:
//
//   sm fuzz <seed> <count>        differential fuzzer: dumb-random + grammar-aware
//                                 perturbed OP_RETURN payloads → sm_decode_payload →
//                                 fold → digest. Pins the byte-level parse/drop path
//                                 (§0 "indexers MUST agree byte-for-byte on validity").
//   sm properties <seed> <count>  the `random` stream, with hard invariant assertions
//                                 (conservation, no-double-ownership, boundary nesting)
//                                 and a per-block property_digest cross-checked across
//                                 languages — invariants proven, not just asserted.
//   sm reorg <seed> <count>       fold-purity confluence: replay, checkpoint-resume,
//                                 clear-rebuild, and a fork-and-return down a divergent
//                                 branch — the reorg story (§5) made executable.
//
// Everything is a pure function of (seed, count): no fold-state reads in the fuzzer
// (so its byte stream is identical across languages), no floating point, fixed-width
// integer math. All draw orders are pinned in SPEC-conformance.md.
#include "sm.h"
#include "prng.h"
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ── small SHA-256 streaming helpers (LE ints; i128 16 bytes LE) ──────────────
static void h8  (SHA256_CTX *h, uint8_t v)  { sha256_update(h, &v, 1); }
static void h32 (SHA256_CTX *h, uint32_t v) { uint8_t t[4];  for (int i=0;i<4;i++)  t[i]=(uint8_t)(v>>(8*i)); sha256_update(h,t,4); }
static void h64 (SHA256_CTX *h, uint64_t v) { uint8_t t[8];  for (int i=0;i<8;i++)  t[i]=(uint8_t)(v>>(8*i)); sha256_update(h,t,8); }
static void h128(SHA256_CTX *h, unsigned __int128 v) { uint8_t t[16]; for (int i=0;i<16;i++) t[i]=(uint8_t)(v>>(8*i)); sha256_update(h,t,16); }
static void hexout(const uint8_t *d, int n, char *out) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[2*i]=H[d[i]>>4]; out[2*i+1]=H[d[i]&15]; } out[2*n]='\0';
}

// ═══════════════════════ property fingerprint (§8) ═══════════════════════════
static uint64_t dep_leg(uint64_t price, unsigned bps) {
    unsigned __int128 v = (unsigned __int128)price * bps / 10000u;
    uint64_t leg = (uint64_t)v;
    return leg < (uint64_t)SM_DUST_FLOOR ? (uint64_t)SM_DUST_FLOOR : leg;
}
static int cmp_name_s(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

int sm_block_fingerprint(SmState *s, int64_t mtp, SHA256_CTX *h) {
    int viol = 0;
    uint32_t n_owned=0, n_listed=0, n_offered=0, n_reserved=0;
    unsigned __int128 sum_lease=0, sum_price=0, sum_legs=0;

    for (int i = 0; i < s->n_names; i++) {
        SmNameRow *r = &s->names[i];
        sum_lease += (unsigned __int128)(uint64_t)r->lease_expiry;
        switch (r->st) {
        case SM_OWNED:    n_owned++; break;
        case SM_LISTED:   n_listed++;  sum_price += r->price; break;
        case SM_OFFERED:  n_offered++; sum_price += r->price; break;
        case SM_RESERVED: n_reserved++; sum_price += r->price;
                          sum_legs += (unsigned __int128)r->burn_leg + r->pay_leg; break;
        }
        // ── hard invariants (the cross-language property assertions) ──
        if (!(mtp < r->lease_expiry)) viol++;                          // lapsed row survived preblock
        if (r->lease_expiry > mtp + SM_MAX_LEASE) viol++;              // lease beyond MAX_LEASE ceiling
        if (r->st == SM_LISTED || r->st == SM_OFFERED || r->st == SM_RESERVED) {
            if (r->offer_expiry + SM_REORG_BUFFER > r->lease_expiry) viol++;          // nest vs lease (§5)
            if (r->st == SM_LISTED && r->price < (uint64_t)SM_SELL_PRICE_FLOOR) viol++; // SELL floor
            if (r->st == SM_RESERVED) {
                if (r->reserve_expiry > r->offer_expiry) viol++;                       // reserve nests in offer
                if (r->price < r->burn_leg + r->pay_leg) viol++;                       // settle underflow guard
                if (r->burn_leg != dep_leg(r->price, SM_RESERVE_BURN_BPS)) viol++;     // conservation: bps math
                if (r->pay_leg  != dep_leg(r->price, SM_RESERVE_PAY_BPS))  viol++;
                if (r->price - r->burn_leg - r->pay_leg < (uint64_t)SM_DUST_FLOOR) viol++; // remainder ≥ DUST
            }
        } else if (r->st != SM_OWNED) viol++;                          // unknown state
    }
    // no-double-ownership (the headline market/transfer/trade invariant)
    if (s->n_names > 1) {
        char (*nm)[SM_NAME_MAX + 1] = malloc((size_t)s->n_names * sizeof(*nm));
        for (int i = 0; i < s->n_names; i++) memcpy(nm[i], s->names[i].name, SM_NAME_MAX + 1);
        qsort(nm, (size_t)s->n_names, sizeof(*nm), cmp_name_s);
        for (int i = 1; i < s->n_names; i++) if (strcmp(nm[i-1], nm[i]) == 0) { viol++; break; }
        free(nm);
    }
    // mutation heights never exceed the height just folded
    for (int i = 0; i < s->n_muts; i++) if (s->muts[i].height > s->cur_height) viol++;

    // ── fingerprint (pinned field order; order-independent aggregates) ──
    h32(h, (uint32_t)s->n_names); h32(h, n_owned); h32(h, n_listed); h32(h, n_offered); h32(h, n_reserved);
    h32(h, (uint32_t)s->n_commits); h32(h, (uint32_t)s->n_muts);
    h128(h, sum_lease); h128(h, sum_price); h128(h, sum_legs);
    return viol;
}

// ═══════════════════════ differential fuzzer (§9) ════════════════════════════
#define FZ_NIDS      16
#define FZ_NAMEPOOL  400
#define FZ_BASE_TS   1700000000LL

typedef struct {
    SmRng rng;
    int64_t ts_ring[16]; int64_t last_ts; int64_t height; uint64_t rate;
    SHA256_CTX ih;                          // input_digest (raw fuzz stream)
    int64_t cov[18];                        // decode coverage: [0]=ignore [1+op]=action(op 1..15 → 2..16)
    int boundary;                           // bfuzz: snap numeric fields to the §-constant boundary table
} FzGen;

// Boundary table for `bfuzz` (§9 boundary-cluster fuzzer) — the protocol constants
// and their ±1 neighbours plus the 2^k word edges, where the fold's comparisons live.
static const uint64_t VAL_BND[] = {
    0, 1, 2, 3, 4, 5,
    17999, 18000, 18001,                                  // RESERVE_WINDOW / COMMIT_EXPIRY ±1
    7199, 7200, 7201,                                     // DIRECT_WINDOW / REORG_BUFFER ±1
    86399, 86400, 86401,                                  // BILLING_UNIT ±1
    31535999ULL, 31536000ULL, 31536001ULL,               // MAX_LEASE ±1
    0x7FFFFFFFULL, 0x80000000ULL, 0xFFFFFFFFULL, 0x100000000ULL,   // u32 edges
    0x1FFFFFFFFFFFFFULL, 0x20000000000000ULL,             // JS Number cliff: 2^53-1 (MAX_SAFE_INTEGER), 2^53
    0x20000000000001ULL, 0x40000000000001ULL,             // 2^53+1, 2^54+1 (both unrepresentable in IEEE-754 double)
    0x7FFFFFFFFFFFFFFFULL, 0x8000000000000000ULL,         // i64 edge
    0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL,          // u64 max
};
#define NVAL_BND ((int)(sizeof(VAL_BND) / sizeof(VAL_BND[0])))
static const int64_t MTP_BND[] = { 1, 2, 300, 7200, 18000, 86400, 604800LL, 31536000LL, 31536001LL };
#define NMTP_BND ((int)(sizeof(MTP_BND) / sizeof(MTP_BND[0])))

static uint64_t fbnd (FzGen *g, uint64_t n) { return sm_rng_bounded(&g->rng, n); }
static uint8_t  fbyte(FzGen *g)             { return (uint8_t)fbnd(g, 256); }

static void fz_id(int idx, SmId *out) {
    memset(out, 0, sizeof *out);
    out->h160[0] = (uint8_t)idx; out->h160[19] = (uint8_t)idx;
    out->type = (idx % 4 == 3) ? SM_P2SH : SM_P2PKH;
}
static void fz_name(int i, char *out, uint8_t *len) {   // 'n' + base36(i), as in gen.c
    static const char *D = "0123456789abcdefghijklmnopqrstuvwxyz";
    char buf[8]; int n = 0, v = i;
    if (v == 0) buf[n++] = '0'; else while (v > 0) { buf[n++] = D[v % 36]; v /= 36; }
    out[0] = 'n'; for (int k = 0; k < n; k++) out[1 + k] = buf[n - 1 - k];
    out[1 + n] = '\0'; *len = (uint8_t)(1 + n);
}
static uint64_t fz_price(FzGen *g) {
    if (g->boundary && fbnd(g, 2) == 0) return VAL_BND[fbnd(g, NVAL_BND)];  // boundary-snap (bfuzz)
    if (fbnd(g, 20) == 0) return UINT64_MAX - fbnd(g, 1000);          // near-2^64 deposit-overflow edge
    return (uint64_t)SM_SELL_PRICE_FLOOR + fbnd(g, 1000000);
}
static void fz_fill(FzGen *g, uint8_t *p, int n) { for (int i = 0; i < n; i++) p[i] = fbyte(g); }

// Build a plausible action for `op` with random-but-valid fields (so the encoder
// succeeds); the grammar-aware twist below then perturbs the bytes. PINNED draws.

// Flags-length draw: mostly tiny (1..3), ~1/8 past the old 80-byte carrier
// boundary, ~1/32 anywhere in the full consensus range up to `cap` (§6).
static uint16_t fz_flags_len(FzGen *g, int cap) {
    uint64_t m = fbnd(g, 32);
    if (m == 0) return (uint16_t)(1 + fbnd(g, (uint64_t)cap));
    if (m < 4)  return (uint16_t)(1 + fbnd(g, 200));
    return (uint16_t)(1 + fbnd(g, 3));
}

static void fz_build_action(FzGen *g, uint8_t op, SmAction *a) {
    memset(a, 0, sizeof *a); a->op = op;
    char nm[SM_NAME_MAX + 1]; uint8_t nl;
    switch (op) {
    case SM_OP_COMMIT:
        fz_fill(g, a->commitment, 32); break;
    case SM_OP_CLAIM:
        fz_fill(g, a->salt, 32); fz_name((int)fbnd(g, FZ_NAMEPOOL), nm, &nl);
        memcpy(a->name, nm, nl + 1); a->name_len = nl; break;
    case SM_OP_RENEW: {
        uint64_t m = fbnd(g, 3);
        if (m == 0) { a->has_anchor = 0; a->flags_len = 0; }
        else if (m == 1) { a->has_anchor = 1; a->anchor = fbnd(g, 1u << 20); a->flags_len = 0; }
        else { a->has_anchor = 1; a->anchor = fbnd(g, 1u << 20);
               a->flags_len = fz_flags_len(g, SM_FLAGS_MAX); fz_fill(g, a->flags, a->flags_len); }
        break; }
    case SM_OP_TRANSFER: {
        SmId t; fz_id((int)fbnd(g, FZ_NIDS), &t); memcpy(a->addr, t.h160, 20);
        if (fbnd(g, 2) == 0) { a->has_anchor = 0; }
        else { a->has_anchor = 1; a->anchor = fbnd(g, 1u << 20);
               a->flags_len = fz_flags_len(g, SM_FLAGS_XFER_MAX); fz_fill(g, a->flags, a->flags_len); }
        break; }
    case SM_OP_SELL:
        a->price = fz_price(g);
        if (g->boundary && fbnd(g, 2) == 0) a->window = (uint32_t)VAL_BND[fbnd(g, NVAL_BND)];   // boundary-snap (bfuzz)
        else a->window = (fbnd(g, 2) == 0) ? 0 : (uint32_t)(SM_RESERVE_WINDOW + fbnd(g, 100000));
        fz_name((int)fbnd(g, FZ_NAMEPOOL), nm, &nl); memcpy(a->name, nm, nl + 1); a->name_len = nl; break;
    case SM_OP_RENEW_NAME: case SM_OP_RELEASE_NAME:
    case SM_OP_RESERVE: case SM_OP_SETTLE: case SM_OP_PAY:
        fz_name((int)fbnd(g, FZ_NAMEPOOL), nm, &nl); memcpy(a->name, nm, nl + 1); a->name_len = nl; break;
    case SM_OP_TRANSFER_NAME: {
        SmId t; fz_id((int)fbnd(g, FZ_NIDS), &t); memcpy(a->addr, t.h160, 20);
        fz_name((int)fbnd(g, FZ_NAMEPOOL), nm, &nl); memcpy(a->name, nm, nl + 1); a->name_len = nl; break; }
    case SM_OP_RELEASE:
        a->has_anchor = 1; a->anchor = fbnd(g, 1u << 20);
        a->flags_len = fz_flags_len(g, SM_FLAGS_MAX); fz_fill(g, a->flags, a->flags_len); break;
    case SM_OP_SELL_TO: {
        a->price = fz_price(g); SmId b; fz_id((int)fbnd(g, FZ_NIDS), &b); memcpy(a->addr, b.h160, 20);
        fz_name((int)fbnd(g, FZ_NAMEPOOL), nm, &nl); memcpy(a->name, nm, nl + 1); a->name_len = nl; break; }
    case SM_OP_AS:
        a->as_index = (uint8_t)fbnd(g, 20); break;                    // sometimes OOB → segment drops
    case SM_OP_TRADE: {
        a->idx_a = (uint8_t)fbnd(g, 6); a->idx_b = (uint8_t)fbnd(g, 6);
        char nb[SM_NAME_MAX + 1]; uint8_t lb;
        fz_name((int)fbnd(g, FZ_NAMEPOOL), nm, &nl); fz_name((int)fbnd(g, FZ_NAMEPOOL), nb, &lb);
        memcpy(a->name, nm, nl + 1); a->name_len = nl;
        memcpy(a->name_b, nb, lb + 1); a->name_b_len = lb; break; }
    default: break;
    }
}

// Produce one carrier's raw payload bytes (dumb-random or grammar-aware+twist).
// Returns the length; *out holds ≤ SM_CARRIER_MAX bytes. PINNED draw order.
// FZ_CARS bounds the per-tx raw-copy arrays (the fuzz draws 1..4 carriers);
// it is a harness constant, decoupled from the SM_INLINE_CARRIERS memory hint.
#define FZ_CARS 8
/* Fuzz stays on the PepeNet prefix so pinned input digests do not move.
   DN coverage is a separate selftest, not a retarget of this draw. */
static const uint8_t FZ_PN[2] = { 0x50, 0x4E };
static int fz_carrier_bytes(FzGen *g, uint8_t out[SM_CARRIER_MAX]) {
    uint64_t mode = fbnd(g, 10);
    if (mode < 4) {                                                   // ── dumb random (40%) ──
        uint64_t pf = fbnd(g, 3);
        int len = (fbnd(g, 8) == 0)                                   // 1/8 wide: 0..SM_CARRIER_MAX
                ? (int)fbnd(g, SM_CARRIER_MAX + 1)
                : (int)fbnd(g, 81);                                   // else the dense 0..80 band
        for (int i = 0; i < len; i++) out[i] = fbyte(g);
        uint8_t pop = (uint8_t)fbnd(g, 21);                           // candidate opcode 0..20
        if (pf == 0 && len >= 4) { out[0]=0xFF; out[1]=0x50; out[2]=0x4E; out[3]=pop; }  // force action prefix
        return len;
    }
    // ── grammar-aware (60%): build → encode → perturb ──
    uint8_t op = (uint8_t)(1 + fbnd(g, 15));                          // 0x01..0x0F
    SmAction a; fz_build_action(g, op, &a);
    size_t enc = sm_encode_action(&a, FZ_PN, out);
    if (enc == 0) { out[0] = 0xFF; return 1; }                        // unreachable (fields valid); degenerate → ignore
    int len = (int)enc;
    switch (fbnd(g, 6)) {                                             // the twist
    case 0: case 1: break;                                            // leave valid
    case 2: len = (int)fbnd(g, (uint64_t)len + 1); break;            // truncate to 0..len
    case 3: if (len > 0) { int pos = (int)fbnd(g, (uint64_t)len); out[pos] = fbyte(g); } break; // flip a byte
    case 4: { int add = (int)fbnd(g, 4); for (int k = 0; k < add; k++) { uint8_t bv = fbyte(g); if (len < SM_CARRIER_MAX) out[len++] = bv; } } break; // extend
    case 5: if (len > 0) { static const uint8_t T[4] = {0x2C, 0x2E, 0x41, 0xFF};   // comma/dot/upper/non-utf8
                           int pos = (int)fbnd(g, (uint64_t)len); out[pos] = T[fbnd(g, 4)]; } break;
    }
    return len;
}
static uint64_t fz_value(FzGen *g) {
    if (g->boundary && fbnd(g, 2) == 0) return VAL_BND[fbnd(g, NVAL_BND)];  // boundary-snap (bfuzz)
    uint64_t sel = fbnd(g, 12);
    if (sel == 0) return 0;                                           // ~1/12 zero (drops votes/posts)
    if (sel == 1) return UINT64_MAX - fbnd(g, 1000);                  // huge
    return 1 + fbnd(g, 1000);                                         // small (can match a deposit leg)
}

// Hash the raw fuzz tx (the bytes + injected fields) into input_digest. PINNED.
static void fz_hash_tx(FzGen *g, const SmTx *t, const uint8_t (*raw)[SM_CARRIER_MAX], const int *rlen) {
    SHA256_CTX *h = &g->ih;
    h32(h, t->txindex); h8(h, (uint8_t)t->n_inputs);
    for (int i = 0; i < t->n_inputs; i++) { sha256_update(h, t->inputs[i].h160, 20); h8(h, t->inputs[i].type); h8(h, t->in_sighash_all[i]); }
    h8(h, (uint8_t)t->n_carriers);
    for (int c = 0; c < t->n_carriers; c++) {
        h32(h, (uint32_t)rlen[c]); sha256_update(h, raw[c], (unsigned)rlen[c]);
        h64(h, t->carriers[c].value); h32(h, t->carriers[c].vout);
    }
    h8(h, (uint8_t)t->n_outs);
    for (int o = 0; o < t->n_outs; o++) { sha256_update(h, t->outs[o].h160, 20); h8(h, t->outs[o].type); h64(h, t->outs[o].value); h32(h, t->outs[o].vout); }
}

// Build + decode one fuzz tx (txindex j). Records decode coverage.
static void fz_build_tx(FzGen *g, uint32_t j, SmTx *t) {
    sm_tx_free(t); memset(t, 0, sizeof *t); t->txindex = j;
    int n_in = 1 + (int)fbnd(g, 4);                                   // 1..4
    for (int i = 0; i < n_in; i++) {
        SmId *in = sm_tx_input(t);
        fz_id((int)fbnd(g, FZ_NIDS), in);
        t->in_sighash_all[i] = (fbnd(g, 8) != 0);                     // 7/8 sign SIGHASH_ALL
    }

    static uint8_t raw[FZ_CARS][SM_CARRIER_MAX]; int rlen[FZ_CARS];   // static: 80 KB, single-threaded fuzz
    int n_car = 1 + (int)fbnd(g, 4);                                  // 1..4
    for (int c = 0; c < n_car; c++) {
        rlen[c] = fz_carrier_bytes(g, raw[c]);
        uint64_t val = fz_value(g);
        SmCarrier *cr = sm_tx_carrier(t);
        sm_decode_payload(raw[c], (size_t)rlen[c], val, FZ_PN, cr);
        cr->value = val; cr->vout = (uint32_t)c;
        if (cr->kind == SM_CAR_IGNORE) g->cov[0]++;
        else                           g->cov[1 + cr->act.op]++;       // op 1..15 → 2..16
    }

    int n_out = (int)fbnd(g, 4);                                      // 0..3
    for (int o = 0; o < n_out; o++) {
        SmId d; fz_id((int)fbnd(g, FZ_NIDS), &d);
        SmOut *ot = sm_tx_out(t);
        memcpy(ot->h160, d.h160, 20);
        ot->type = (fbnd(g, 4) == 3) ? SM_P2SH : SM_P2PKH;
        ot->value = fz_value(g);
        ot->vout = (uint32_t)(SM_SYNTH_VOUT_BASE + o);
    }

    fz_hash_tx(g, t, raw, rlen);
}

static uint64_t fz_run(uint64_t seed, uint64_t count, int boundary, uint8_t idig[32], uint8_t sdig[32], int64_t cov[18]) {
    FzGen g; memset(&g, 0, sizeof g);
    sm_rng_seed(&g.rng, seed); g.boundary = boundary;
    for (int i = 0; i < 16; i++) g.ts_ring[i] = FZ_BASE_TS;
    g.last_ts = FZ_BASE_TS; g.height = 0;
    sha256_init(&g.ih);
    SmState *st = sm_new(0);

    uint64_t emitted = 0;
    while (emitted < count) {
        g.height += 1;
        int64_t mtp = sm_mtp(g.ts_ring, 11);
        if (boundary && fbnd(&g, 2) == 0) g.last_ts += MTP_BND[fbnd(&g, NMTP_BND)];   // boundary MTP jumps (bfuzz)
        else g.last_ts += 300 + (int64_t)fbnd(&g, 600);
        for (int i = 0; i < 10; i++) g.ts_ring[i] = g.ts_ring[i + 1];
        g.ts_ring[10] = g.last_ts;
        g.rate = 28u * (1u + fbnd(&g, 4));
        sm_begin_block(st, g.height, mtp, g.rate);
        int ntx = 1 + (int)fbnd(&g, 8);
        SmTx t = {0};
        for (int j = 0; j < ntx && emitted < count; j++) {
            fz_build_tx(&g, (uint32_t)j, &t);
            sm_apply_tx(st, &t);
            emitted++;
        }
        sm_tx_free(&t);
    }
    sha256_final(&g.ih, idig);
    sm_state_digest(st, sdig);
    if (cov) for (int i = 0; i < 18; i++) cov[i] = g.cov[i];
    sm_free(st);
    return emitted;
}

static int fuzz_cli(int argc, char **argv, int boundary, const char *name) {
    if (argc < 4) { fprintf(stderr, "usage: %s %s <seed> <count> [--cov]\n", argv[0], name); return 2; }
    uint64_t seed = strtoull(argv[2], NULL, 0), count = strtoull(argv[3], NULL, 0);
    int cov = (argc > 4 && strcmp(argv[4], "--cov") == 0);
    uint8_t idig[32], sdig[32]; int64_t c[18];
    uint64_t n = fz_run(seed, count, boundary, idig, sdig, c);
    char ih[65], sh[65]; hexout(idig, 32, ih); hexout(sdig, 32, sh);
    printf("txs=%llu\ninput_digest=%s\nstate_digest=%s\n", (unsigned long long)n, ih, sh);
    if (cov) {
        static const char *OPN[16] = { "?", "renewname","transfername","commit","claim","renew","transfer","sell",
                                       "reserve","settle","release","releasename","sellto","pay","as","trade" };
        printf("decode_cov: ignore=%lld", (long long)c[0]);
        for (int op = 1; op <= 15; op++) printf(" %s=%lld", OPN[op], (long long)c[1 + op]);
        printf("\n");
    }
    return 0;
}
int sm_cmd_fuzz (int argc, char **argv) { return fuzz_cli(argc, argv, 0, "fuzz"); }
int sm_cmd_bfuzz(int argc, char **argv) { return fuzz_cli(argc, argv, 1, "bfuzz"); }

// ═══════════════════════ property mode (§8) ══════════════════════════════════
int sm_cmd_properties(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s properties <seed> <count>\n", argv[0]); return 2; }
    uint64_t seed = strtoull(argv[2], NULL, 0), count = strtoull(argv[3], NULL, 0);
    uint8_t idig[32], sdig[32], pdig[32]; int64_t viol = 0;
    sm_generate(seed, count, 0, idig, sdig, NULL, &viol, pdig);
    char sh[65], ph[65]; hexout(sdig, 32, sh); hexout(pdig, 32, ph);
    printf("violations=%lld\nproperty_digest=%s\nstate_digest=%s\n", (long long)viol, ph, sh);
    return viol == 0 ? 0 : 1;
}

// ═══════════════════════ reorg mode (§10) ════════════════════════════════════
// Fold blocks [lo, hi) of the recorded chain into `s` (each block's txs in order).
static void fold_range(SmState *s, const SmRecBlk *blk, const SmTx *txs, int lo, int hi) {
    for (int b = lo; b < hi; b++) {
        sm_begin_block(s, blk[b].height, blk[b].mtp, blk[b].rate);
        for (int t = blk[b].tx_lo; t < blk[b].tx_hi; t++) sm_apply_tx(s, &txs[t]);
    }
}
// A divergent alternate tail: blocks [lo, hi) with each block's txs applied in
// REVERSE order (a different, mostly-invalid history that dirties state).
static void fold_range_rev(SmState *s, const SmRecBlk *blk, const SmTx *txs, int lo, int hi) {
    for (int b = lo; b < hi; b++) {
        sm_begin_block(s, blk[b].height, blk[b].mtp, blk[b].rate);
        for (int t = blk[b].tx_hi - 1; t >= blk[b].tx_lo; t--) sm_apply_tx(s, &txs[t]);
    }
}
static int dig_eq(SmState *s, const uint8_t want[32]) { uint8_t d[32]; sm_state_digest(s, d); return memcmp(d, want, 32) == 0; }

int sm_cmd_reorg(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s reorg <seed> <count>\n", argv[0]); return 2; }
    uint64_t seed = strtoull(argv[2], NULL, 0), count = strtoull(argv[3], NULL, 0);
    if (count > 20000) count = 20000;                                 // reorg keeps the realized chain in RAM

    int max_blk = (int)count + 1, max_tx = (int)count + 1;
    SmRecBlk *blk = malloc((size_t)max_blk * sizeof(SmRecBlk));
    SmTx     *txs = calloc((size_t)max_tx, sizeof(SmTx));
    int nblk = 0;
    sm_record_chain(seed, count, blk, &nblk, max_blk, txs, max_tx);
    int J = nblk / 2;                                                 // fork point (block index)

    SmState *s = sm_new(0);
    int checks = 0, fails = 0;
    #define EXPECT(c) do { checks++; if (!(c)) fails++; } while (0)

    // canonical full fold → D_full
    fold_range(s, blk, txs, 0, nblk);
    uint8_t D_full[32]; sm_state_digest(s, D_full);

    // 1. replay determinism: a fresh full fold reproduces D_full.
    sm_clear(s); fold_range(s, blk, txs, 0, nblk); EXPECT(dig_eq(s, D_full));

    // capture S_J (fold-purity reference for the fork point)
    sm_clear(s); fold_range(s, blk, txs, 0, J);
    uint8_t S_J[32]; sm_state_digest(s, S_J);

    // 2. checkpoint resume: prefix then suffix on the same state == full fold.
    fold_range(s, blk, txs, J, nblk); EXPECT(dig_eq(s, D_full));

    // 3. clear-rebuild: clearing a full state and re-folding the prefix == S_J
    //    (proves sm_clear leaves NO residue — the reorg rebuild primitive).
    sm_clear(s); fold_range(s, blk, txs, 0, nblk); sm_clear(s); fold_range(s, blk, txs, 0, J);
    EXPECT(dig_eq(s, S_J));

    // 4. fork-and-return: down a divergent branch, back to the fork, replay canonical.
    sm_clear(s); fold_range(s, blk, txs, 0, J); EXPECT(dig_eq(s, S_J));   // re-derive the fork state
    fold_range_rev(s, blk, txs, J, nblk);                                // wrong branch (reversed tail)
    uint8_t D_alt[32]; sm_state_digest(s, D_alt);
    sm_clear(s); fold_range(s, blk, txs, 0, J); EXPECT(dig_eq(s, S_J));   // roll back to the fork
    fold_range(s, blk, txs, J, nblk); EXPECT(dig_eq(s, D_full));         // replay the canonical tail

    sm_free(s); free(blk); free(txs);

    // reorg_digest binds the three states the confluence checks pivot on.
    SHA256_CTX h; sha256_init(&h);
    sha256_update(&h, D_full, 32); sha256_update(&h, S_J, 32); sha256_update(&h, D_alt, 32);
    uint8_t rd[32]; sha256_final(&h, rd);
    char fh[65], jh[65], ah[65], rh[65];
    hexout(D_full, 32, fh); hexout(S_J, 32, jh); hexout(D_alt, 32, ah); hexout(rd, 32, rh);
    printf("blocks=%d fork=%d checks=%d failures=%d\n", nblk, J, checks, fails);
    printf("D_full=%s\nS_fork=%s\nD_alt=%s\nreorg_digest=%s\n", fh, jh, ah, rh);
    return fails == 0 ? 0 : 1;
}

// Fold blocks [lo,hi) skipping every other one (a divergent "missing blocks" branch).
static void fold_range_skip(SmState *s, const SmRecBlk *blk, const SmTx *txs, int lo, int hi) {
    for (int b = lo; b < hi; b += 2) {
        sm_begin_block(s, blk[b].height, blk[b].mtp, blk[b].rate);
        for (int t = blk[b].tx_lo; t < blk[b].tx_hi; t++) sm_apply_tx(s, &txs[t]);
    }
}

// ── reorg-DEPTH fuzzer: many trials, PRNG-chosen fork point + divergence kind ──
// Each trial forks at a random block, walks a divergent branch (reversed tail /
// dropped-every-other / tail-replayed-twice), then proves clear-rebuild to the fork
// reproduces S_fork and replaying the canonical tail reproduces D_full. Stresses the
// reorg machinery far harder than the single fixed fork of `reorg`.
int sm_cmd_reorgfuzz(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s reorgfuzz <seed> <count>\n", argv[0]); return 2; }
    uint64_t seed = strtoull(argv[2], NULL, 0), count = strtoull(argv[3], NULL, 0);
    if (count > 20000) count = 20000;
    int max_blk = (int)count + 1, max_tx = (int)count + 1;
    SmRecBlk *blk = malloc((size_t)max_blk * sizeof(SmRecBlk));
    SmTx     *txs = calloc((size_t)max_tx, sizeof(SmTx));
    int nblk = 0;
    sm_record_chain(seed, count, blk, &nblk, max_blk, txs, max_tx);

    SmState *s = sm_new(0);
    fold_range(s, blk, txs, 0, nblk);
    uint8_t D_full[32]; sm_state_digest(s, D_full);

    SmRng tr; sm_rng_seed(&tr, seed ^ 0x5245464B5A475F31ULL);   // independent trial PRNG ("REFKZG_1")
    SHA256_CTX acc; sha256_init(&acc);
    const int K = 64;
    int checks = 0, fails = 0;
    for (int k = 0; k < K; k++) {
        int J = (int)sm_rng_bounded(&tr, (uint64_t)nblk + 1);
        int kind = (int)sm_rng_bounded(&tr, 3);
        sm_clear(s); fold_range(s, blk, txs, 0, J);
        uint8_t S_J[32]; sm_state_digest(s, S_J);
        if      (kind == 0) fold_range_rev (s, blk, txs, J, nblk);          // reversed tail
        else if (kind == 1) fold_range_skip(s, blk, txs, J, nblk);          // dropped every other
        else { fold_range(s, blk, txs, J, nblk); fold_range(s, blk, txs, J, nblk); }  // tail replayed twice
        uint8_t D_alt[32]; sm_state_digest(s, D_alt); sha256_update(&acc, D_alt, 32);
        sm_clear(s); fold_range(s, blk, txs, 0, J); checks++; if (!dig_eq(s, S_J))   fails++;  // clear-rebuild → S_fork
        fold_range(s, blk, txs, J, nblk);          checks++; if (!dig_eq(s, D_full)) fails++;  // canonical replay → D_full
    }
    sm_free(s); free(blk); free(txs);
    sha256_update(&acc, D_full, 32);
    uint8_t rd[32]; sha256_final(&acc, rd);
    char rh[65]; hexout(rd, 32, rh);
    printf("blocks=%d trials=%d checks=%d failures=%d\nreorgfuzz_digest=%s\n", nblk, K, checks, fails, rh);
    return fails == 0 ? 0 : 1;
}

// ── metamorphic drop-closed at scale ─────────────────────────────────────────
// Property: an action the protocol IGNORES is provably inert. After each block of
// the `random` chain, inject a fixed all-inert tx (malformed CLAIM, unknown opcode,
// bare UTF-8 noise, overlay-band carrier) and assert the state digest is
// byte-unchanged. A decoder/fold bug that lets any "should-be-inert" carrier
// mutate state lights up as failures>0 (and a divergent state_digest).
static void build_inert_tx(SmTx *t) {
    sm_tx_free(t); memset(t, 0, sizeof *t);
    t->txindex = 0x7FFFFFFF;
    SmId *in = sm_tx_input(t); in->h160[0] = 0xEE; in->h160[19] = 0xEE;
    in->type = SM_P2PKH; t->in_sighash_all[0] = 1;
    // 0: truncated CLAIM → IGNORE
    uint8_t bad[8] = { 0xFF, 0x50, 0x4E, SM_OP_CLAIM, 0, 0, 0, 0 };
    SmCarrier *c0 = sm_tx_carrier(t);
    sm_decode_payload(bad, 8, 0, FZ_PN, c0); c0->value = 0; c0->vout = 0;
    // 1: unknown opcode in gap (0x20) → IGNORE
    uint8_t unk[4] = { 0xFF, 0x50, 0x4E, 0x20 };
    SmCarrier *c1 = sm_tx_carrier(t);
    sm_decode_payload(unk, 4, 0, FZ_PN, c1); c1->value = 0; c1->vout = 1;
    // 2: bare UTF-8 noise (no prefix) → IGNORE
    SmCarrier *c2 = sm_tx_carrier(t);
    sm_decode_payload((const uint8_t *)"hello", 5, 1, FZ_PN, c2); c2->value = 1; c2->vout = 2;
    // 3: overlay-band opcode 0xD6 → IGNORE
    uint8_t ov[5] = { 0xFF, 0x50, 0x4E, 0xD6, 0x00 };
    SmCarrier *c3 = sm_tx_carrier(t);
    sm_decode_payload(ov, 5, 0, FZ_PN, c3); c3->value = 0; c3->vout = 3;
}

int sm_cmd_meta(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s meta <seed> <count>\n", argv[0]); return 2; }
    uint64_t seed = strtoull(argv[2], NULL, 0), count = strtoull(argv[3], NULL, 0);
    if (count > 20000) count = 20000;
    int max_blk = (int)count + 1, max_tx = (int)count + 1;
    SmRecBlk *blk = malloc((size_t)max_blk * sizeof(SmRecBlk));
    SmTx     *txs = calloc((size_t)max_tx, sizeof(SmTx));
    int nblk = 0;
    sm_record_chain(seed, count, blk, &nblk, max_blk, txs, max_tx);

    SmTx inert = {0}; build_inert_tx(&inert);
    SmState *s = sm_new(0);
    int checks = 0, fails = 0;
    for (int b = 0; b < nblk; b++) {
        sm_begin_block(s, blk[b].height, blk[b].mtp, blk[b].rate);
        for (int t = blk[b].tx_lo; t < blk[b].tx_hi; t++) sm_apply_tx(s, &txs[t]);
        uint8_t before[32]; sm_state_digest(s, before);
        sm_apply_tx(s, &inert);                         // inert ⇒ must not change state
        uint8_t after[32]; sm_state_digest(s, after);
        checks++; if (memcmp(before, after, 32) != 0) fails++;
    }
    uint8_t sd[32]; sm_state_digest(s, sd);
    sm_free(s); free(blk); free(txs);
    char sh[65]; hexout(sd, 32, sh);
    printf("blocks=%d checks=%d failures=%d\nstate_digest=%s\n", nblk, checks, fails, sh);
    return fails == 0 ? 0 : 1;
}

// ── coverage assertion (meta-test of the generators) ─────────────────────────
// Every fold branch the random soak is meant to exercise, and every decode branch
// the fuzzer is meant to reach, MUST fire — else a generator silently went blind to
// a path. Asserts all generator/decode branches fire.
int sm_cmd_coverage(int argc, char **argv) {
    uint64_t seed  = argc > 2 ? strtoull(argv[2], NULL, 0) : 42;
    uint64_t count = argc > 3 ? strtoull(argv[3], NULL, 0) : 300000;
    static const char *EVN[SM_EV_COUNT] = {
        "claim_mint","claim_displace","waterfill_cap","waterfill_forfeit","reserve_win","reserve_clamp",
        "settle_ok","pay_ok","trade_ok","lapse","release_name","as_drop","sell_ok","sellto_ok" };
    static const char *OPN[16] = { "?","renewname","transfername","commit","claim","renew","transfer","sell",
                                   "reserve","settle","release","releasename","sellto","pay","as","trade" };
    int missing = 0;
    uint8_t id[32], sd[32]; int64_t ev[SM_EV_COUNT];
    sm_generate(seed, count, 0, id, sd, ev, NULL, NULL);
    for (int i = 0; i < SM_EV_COUNT; i++) {
        if (ev[i] == 0) { printf("UNCOVERED generator branch: %s\n", EVN[i]); missing++; }
    }
    uint8_t fi[32], fs[32]; int64_t cov[18];
    fz_run(seed, count, 0, fi, fs, cov);
    if (cov[0] == 0) { printf("UNCOVERED decode: ignore\n"); missing++; }
    for (int op = 1; op <= 15; op++) if (cov[1 + op] == 0) { printf("UNCOVERED decode op: %s\n", OPN[op]); missing++; }
    printf("coverage: %d uncovered branch(es) at seed=%llu count=%llu\n",
           missing, (unsigned long long)seed, (unsigned long long)count);
    return missing ? 1 : 0;
}
