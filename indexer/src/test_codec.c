// test_codec.c — the pure codecs: base58check, tx standardness, compact targets.
//
// PROVES:
//  10. BASE58 / BASE58CHECK (src/base58.c). Official known-answer vectors
//      (Bitcoin genesis address, the 20-zero-byte burn address, the BIP16 P2SH
//      test address, the Bitcoin-wiki WIF vector, plus Dogecoin/Pepecoin
//      version bytes — every one cross-checked against an independent
//      implementation before being hardcoded here). Encode→decode round-trips
//      over thousands of seeded-random byte strings; rejection of bad
//      checksums, of the excluded alphabet characters (0 O I l), and of empty
//      input; leading zero bytes becoming leading '1's (the classic off-by-one);
//      and oversize input / undersized output buffers rejected with no overrun
//      (canary-guarded buffers).
//  11. TX STANDARDNESS (src/txcheck.c) + POOL SEMANTICS (src/mempool.c) against
//      adversarial transactions, each rejected for the RIGHT reason. Every case
//      in this file is one the shipped `indexerd selftest` does NOT cover —
//      it already asserts dust / oversize-scriptSig / non-push scriptSig /
//      duplicate input / value-out-of-range / coinbase / nonstandard-spk /
//      pool conflict + eviction, so what follows is the complement: size
//      bounds, the empty-input and empty-output shapes, running-total overflow,
//      negative values, the exact dust and scriptSig BOUNDARIES, every
//      push-opcode edge (PUSHDATA1/2/4 truncation and overrun, OP_1NEGATE,
//      OP_16, the first non-push opcode), P2SH standardness, malformed
//      OP_RETURN carriers, same-txid-different-vout inputs, and the seen-ring /
//      get_copy / sweep / txid_out behaviour of the pool.
//  12. COMPACT TARGETS (src/pow.c). bits→target→bits round-trips over thousands
//      of seeded-random canonical values (driven through the exported
//      idx_pow_next_bits, whose unit-modulation path is exactly
//      target_to_bits(bits_to_target(bits))); non-canonical mantissas
//      normalising to the same target; and every invalid encoding — the
//      negative flag, a zero mantissa, an exponent past 32 — REJECTED rather
//      than accepted, checked exhaustively against an independently written
//      validity predicate over 200k random words.
//
// KNOWN FAILURE (product defect, deliberately NOT weakened — see the /* FAILS */
// comment in sec_mempool): a tx rejected by txcheck_stateless never enters the
// "accepted OR rejected" seen ring that mempool.h documents and sync.c:1772
// relies on, so a peer can make us re-download and re-validate the same
// nonstandard tx on every announcement. This file therefore exits non-zero
// until mempool.c notes the txid on a post-validation reject.
#include "base58.h"
#include "chain.h"
#include "txcheck.h"
#include "mempool.h"
#include "pow.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

static int hexbytes(const char *hex, uint8_t *out) {
    int n = 0;
    for (const char *p = hex; p[0] && p[1]; p += 2) { unsigned v; sscanf(p, "%2x", &v); out[n++] = (uint8_t)v; }
    return n;
}

// ── 10a. known-answer vectors ────────────────────────────────────────────────
// Every pair below was verified against an independent base58check
// implementation before being written here; the first four are published,
// widely-attested vectors.
struct KAV { uint8_t version; const char *payload_hex; const char *addr; const char *what; };
static const struct KAV KAVS[] = {
    { 0x00, "62e907b15cbf27d5425399ebf6f0fb50ebb88f18", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
      "bitcoin genesis address (v0x00)" },
    { 0x00, "0000000000000000000000000000000000000000", "1111111111111111111114oLvT2",
      "20 zero bytes → 21 leading '1's (v0x00)" },
    { 0x05, "74f209f6ea907e2ea48f74fae05782ae8a665257", "3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou",
      "bitcoin P2SH test address (v0x05)" },
    { 0x80, "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d",
      "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
      "bitcoin-wiki WIF vector — a 32-byte payload (v0x80)" },
    { 0x1e, "62e907b15cbf27d5425399ebf6f0fb50ebb88f18", "DEA5vGb2NpAwCiCp5yTE16F3DueQUVivQp",
      "dogecoin address version (v0x1e)" },
    { 0x38, "62e907b15cbf27d5425399ebf6f0fb50ebb88f18", "PgwmX6LWqWDiTyq4it7WcMKVb2Lw1dq7jU",
      "pepecoin address version (v0x38)" },
    { 0x00, "ffffffffffffffffffffffffffffffffffffffff", "1QLbz7JHiBTspS962RLKV8GndWFwi5j6Qr",
      "all-ones hash160 (v0x00)" },
};

static void sec_b58_kav(void) {
    printf("\n-- base58check known-answer vectors --\n");
    for (unsigned i = 0; i < sizeof KAVS / sizeof KAVS[0]; i++) {
        uint8_t pay[64]; int n = hexbytes(KAVS[i].payload_hex, pay);
        char out[128], nm[200];
        memset(out, 0, sizeof out);
        int ok = idx_b58check_encode(KAVS[i].version, pay, (size_t)n, out, sizeof out);
        snprintf(nm, sizeof nm, "encode: %s", KAVS[i].what);
        CHECK(ok && strcmp(out, KAVS[i].addr) == 0, nm);

        uint8_t back[64]; size_t blen = 0; uint8_t ver = 0xAB;
        int dok = idx_b58check_decode(KAVS[i].addr, &ver, back, sizeof back, &blen);
        snprintf(nm, sizeof nm, "decode: %s", KAVS[i].what);
        CHECK(dok && ver == KAVS[i].version && blen == (size_t)n && memcmp(back, pay, (size_t)n) == 0, nm);
    }
}

// ── 10b. round-trip over seeded-random byte strings ──────────────────────────
static void sec_b58_roundtrip(void) {
    printf("\n-- base58check encode→decode round-trip (seeded random) --\n");
    g_rng = 0xB58C4EC70FFEEULL;
    int trials = 0, bad_enc = 0, bad_dec = 0, bad_ver = 0, bad_len = 0, bad_bytes = 0;
    int zero_lead_trials = 0, bad_zero_lead = 0;

    for (int t = 0; t < 20000; t++) {
        uint64_t r = rnd64();
        size_t n = 1 + (size_t)(r % 59);              // encode caps payload at 59 (n+5 ≤ 64)
        uint8_t version = (uint8_t)(r >> 32);
        uint8_t pay[64];
        for (size_t i = 0; i < n; i++) pay[i] = (uint8_t)(rnd64() >> 24);
        // every ~4th trial: force leading zero bytes (and sometimes a zero version)
        size_t leading = 0;
        if (t % 4 == 0) {
            leading = 1 + (size_t)(rnd64() % (n < 6 ? n : 6));
            for (size_t i = 0; i < leading; i++) pay[i] = 0;
            if (rnd64() & 1) version = 0;
        }

        char enc[128];
        if (!idx_b58check_encode(version, pay, n, enc, sizeof enc)) { bad_enc++; continue; }
        trials++;

        // Leading zero BYTES must become leading '1' CHARS, one for one. Build the
        // checked buffer (version || payload || sha256d[0:4]) independently and
        // count its leading zero bytes — the payload's own tail and the checksum
        // can start with zeros too, so the count has to be measured, not assumed.
        if (leading) {
            uint8_t full[80]; full[0] = version; memcpy(full + 1, pay, n);
            uint8_t ck[32]; idx_sha256d(full, n + 1, ck); memcpy(full + 1 + n, ck, 4);
            size_t want = 0; while (want < n + 5 && full[want] == 0) want++;
            size_t got = 0; while (enc[got] == '1') got++;
            zero_lead_trials++;
            if (got != want) bad_zero_lead++;
        }

        uint8_t back[64]; size_t blen = 0; uint8_t ver = 0;
        if (!idx_b58check_decode(enc, &ver, back, sizeof back, &blen)) { bad_dec++; continue; }
        if (ver != version) bad_ver++;
        if (blen != n) bad_len++;
        else if (memcmp(back, pay, n) != 0) bad_bytes++;
    }
    CHECK(bad_enc == 0, "every random payload (1..59 bytes) encodes");
    CHECK(trials > 19000, "the round-trip actually ran (≈20000 trials)");
    CHECK(bad_dec == 0, "every encoded string decodes");
    CHECK(bad_ver == 0, "the version byte survives the round-trip");
    CHECK(bad_len == 0, "the payload length survives the round-trip");
    CHECK(bad_bytes == 0, "the payload bytes survive the round-trip");
    CHECK(zero_lead_trials > 1000, "leading-zero payloads were actually exercised");
    CHECK(bad_zero_lead == 0, "leading zero bytes map one-for-one onto leading '1's");
}

// ── 10c. rejection + buffer safety ───────────────────────────────────────────
static void sec_b58_reject(void) {
    printf("\n-- base58check rejection + buffer safety --\n");
    uint8_t h160[20]; hexbytes("62e907b15cbf27d5425399ebf6f0fb50ebb88f18", h160);
    struct { uint8_t payload[64]; uint8_t canary[32]; } g;
    memset(&g, 0, sizeof g);
    memset(g.canary, 0x5A, sizeof g.canary);
    size_t plen = 0; uint8_t ver = 0;

    CHECK(idx_b58check_decode("", &ver, g.payload, sizeof g.payload, &plen) == 0, "empty input is rejected");
    CHECK(idx_b58check_decode("1", &ver, g.payload, sizeof g.payload, &plen) == 0, "a lone '1' is rejected (< 5 bytes)");
    CHECK(idx_b58check_decode("11111", &ver, g.payload, sizeof g.payload, &plen) == 0,
          "five '1's decode to five zero bytes with a bad checksum → rejected");

    // bad checksum: mutate the last character of a valid address
    char bad[64]; snprintf(bad, sizeof bad, "%s", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    bad[strlen(bad) - 1] = (bad[strlen(bad) - 1] == 'a') ? 'b' : 'a';
    CHECK(idx_b58check_decode(bad, &ver, g.payload, sizeof g.payload, &plen) == 0, "a mutated final character fails the checksum");
    snprintf(bad, sizeof bad, "%s", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    bad[5] = (bad[5] == 'e') ? 'f' : 'e';
    CHECK(idx_b58check_decode(bad, &ver, g.payload, sizeof g.payload, &plen) == 0, "a mutated middle character fails the checksum");

    // every character excluded from the base58 alphabet
    const char *excluded = "0OIl";
    for (const char *c = excluded; *c; c++) {
        char s[64]; snprintf(s, sizeof s, "%s", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        s[10] = *c;
        char nm[96]; snprintf(nm, sizeof nm, "the excluded character '%c' is rejected", *c);
        CHECK(idx_b58check_decode(s, &ver, g.payload, sizeof g.payload, &plen) == 0, nm);
    }
    CHECK(idx_b58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7Div NA", &ver, g.payload, sizeof g.payload, &plen) == 0,
          "a space is rejected");
    CHECK(idx_b58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7Div\xffNA", &ver, g.payload, sizeof g.payload, &plen) == 0,
          "a high-bit byte is rejected");

    // oversize input: neither shape may overrun the 64-byte internal buffers
    { char big[4097]; memset(big, '1', 4096); big[4096] = 0;
      CHECK(idx_b58check_decode(big, &ver, g.payload, sizeof g.payload, &plen) == 0, "4096 leading '1's are rejected");
      memset(big, 'z', 4096); big[4096] = 0;
      CHECK(idx_b58check_decode(big, &ver, g.payload, sizeof g.payload, &plen) == 0, "4096 high digits are rejected");
      memset(big, '1', 2048); memset(big + 2048, 'z', 2048); big[4096] = 0;
      CHECK(idx_b58check_decode(big, &ver, g.payload, sizeof g.payload, &plen) == 0, "a 4096-char mixed string is rejected"); }
    CHECK(memcmp(g.canary, "\x5a\x5a\x5a\x5a", 4) == 0, "decode never wrote past the payload buffer (canary intact)");
    { int intact = 1; for (unsigned i = 0; i < sizeof g.canary; i++) if (g.canary[i] != 0x5A) intact = 0;
      CHECK(intact, "…the whole canary is intact"); }

    // a payload too small for the caller's buffer must be refused, not truncated
    uint8_t tiny[4]; size_t tl = 0;
    CHECK(idx_b58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", &ver, tiny, sizeof tiny, &tl) == 0,
          "decode refuses a payload_max smaller than the payload");

    // encode: payload past the internal 59-byte cap, and a too-small output buffer
    struct { char out[128]; uint8_t canary[32]; } e;
    memset(&e, 0, sizeof e); memset(e.canary, 0x5A, sizeof e.canary);
    uint8_t big_pay[128]; memset(big_pay, 0x77, sizeof big_pay);
    CHECK(idx_b58check_encode(0, big_pay, 60, e.out, sizeof e.out) == 0, "encode refuses a 60-byte payload (n+5 > 64)");
    CHECK(idx_b58check_encode(0, big_pay, 128, e.out, sizeof e.out) == 0, "encode refuses a 128-byte payload");
    CHECK(idx_b58check_encode(0, h160, 20, e.out, 8) == 0, "encode refuses a too-small output buffer");
    { int intact = 1; for (unsigned i = 0; i < sizeof e.canary; i++) if (e.canary[i] != 0x5A) intact = 0;
      CHECK(intact, "encode never wrote past the output buffer (canary intact)"); }

    // and it still succeeds at the exact boundary sizes
    char ok59[128];
    CHECK(idx_b58check_encode(0x1e, big_pay, 59, ok59, sizeof ok59) == 1, "encode accepts the largest legal payload (59 bytes)");
    uint8_t back[64]; size_t bl = 0;
    CHECK(idx_b58check_decode(ok59, &ver, back, sizeof back, &bl) == 1 && bl == 59 && ver == 0x1e,
          "…and it decodes back exactly");
    char ok1[128];
    CHECK(idx_b58check_encode(0x00, big_pay, 1, ok1, sizeof ok1) == 1 &&
          idx_b58check_decode(ok1, &ver, back, sizeof back, &bl) == 1 && bl == 1,
          "a 1-byte payload round-trips");
}

// ── 11. tx standardness + pool semantics ─────────────────────────────────────
static void p(uint8_t *b, int *l, const uint8_t *d, int n) { memcpy(b + *l, d, (size_t)n); *l += n; }
static void p1(uint8_t *b, int *l, int v) { b[(*l)++] = (uint8_t)v; }
static void pu32(uint8_t *b, int *l, uint32_t v) { for (int i = 0; i < 4; i++) p1(b, l, (int)((v >> (8*i)) & 0xff)); }
static void pu64(uint8_t *b, int *l, uint64_t v) { for (int i = 0; i < 8; i++) p1(b, l, (int)((v >> (8*i)) & 0xff)); }
static void pvar(uint8_t *b, int *l, uint64_t v) {
    if (v < 0xFD) p1(b, l, (int)v);
    else if (v <= 0xFFFF) { p1(b, l, 0xFD); p1(b, l, (int)(v & 0xff)); p1(b, l, (int)((v >> 8) & 0xff)); }
    else { p1(b, l, 0xFE); pu32(b, l, (uint32_t)v); }
}
static int raw_tx(uint8_t *out, int nin, const uint8_t (*prev)[36],
                  const uint8_t **ss, const int *ssn,
                  int nout, const uint64_t *val, const uint8_t **spk, const int *spkn) {
    int o = 0; pu32(out, &o, 1); pvar(out, &o, (uint64_t)nin);
    for (int i = 0; i < nin; i++) {
        p(out, &o, prev[i], 36); pvar(out, &o, (uint64_t)ssn[i]);
        if (ssn[i]) p(out, &o, ss[i], (int)ssn[i]);
        pu32(out, &o, 0xFFFFFFFF);
    }
    pvar(out, &o, (uint64_t)nout);
    for (int i = 0; i < nout; i++) { pu64(out, &o, val[i]); pvar(out, &o, (uint64_t)spkn[i]); p(out, &o, spk[i], spkn[i]); }
    pu32(out, &o, 0);
    return o;
}

static uint8_t  g_p2pkh[25], g_p2sh[23], g_opret[38];
static uint8_t  g_prev1[36], g_prev2[36];
static uint8_t  g_push[2] = { 0x01, 0xAB };
static const uint8_t *g_ss1[4]; static int g_ssn1[4];

static void codec_scripts_init(void) {
    uint8_t h[20]; memset(h, 0x5C, 20);
    int l = 0; p1(g_p2pkh, &l, 0x76); p1(g_p2pkh, &l, 0xA9); p1(g_p2pkh, &l, 0x14); p(g_p2pkh, &l, h, 20); p1(g_p2pkh, &l, 0x88); p1(g_p2pkh, &l, 0xAC);
    l = 0; p1(g_p2sh, &l, 0xA9); p1(g_p2sh, &l, 0x14); p(g_p2sh, &l, h, 20); p1(g_p2sh, &l, 0x87);
    l = 0; p1(g_opret, &l, 0x6A); p1(g_opret, &l, 36);
    { uint8_t a[36] = { 0xFF, 0x50, 0x4E, 0x01 }; memset(a + 4, 0x22, 32); p(g_opret, &l, a, 36); }
    memset(g_prev1, 0xD1, 36); g_prev1[35] = 0x00;
    memset(g_prev2, 0xD2, 36); g_prev2[35] = 0x00;
    for (int i = 0; i < 4; i++) { g_ss1[i] = g_push; g_ssn1[i] = 2; }
}

// helper: run txcheck and compare the reason string
static int reject_because(const uint8_t *raw, int len, const char *why_want) {
    char why[128] = "";
    int ok = txcheck_stateless(raw, (size_t)len, why, sizeof why);
    return ok == 0 && strcmp(why, why_want) == 0;
}
static int accepted(const uint8_t *raw, int len) {
    char why[128] = "";
    if (txcheck_stateless(raw, (size_t)len, why, sizeof why)) return 1;
    fprintf(stderr, "    (unexpected reject: %s)\n", why);
    return 0;
}

static void sec_txcheck(void) {
    printf("\n-- tx standardness: the cases the shipped selftest does NOT cover --\n");
    codec_scripts_init();
    uint8_t raw[4096];
    const uint8_t *spk1[2] = { g_p2pkh, g_p2pkh }; int spkn1[2] = { 25, 25 };
    const uint8_t (*prev1)[36] = (const uint8_t (*)[36])g_prev1;
    uint64_t okval[2] = { 100000000ULL, 100000000ULL };

    // size bounds (never exercised by the selftest)
    { uint8_t tiny[64]; int o = 0;
      pu32(tiny, &o, 1); pvar(tiny, &o, 1); p(tiny, &o, g_prev1, 36); pvar(tiny, &o, 0);
      pu32(tiny, &o, 0xFFFFFFFF); pvar(tiny, &o, 0); pu32(tiny, &o, 0);
      CHECK(o < TX_MIN_SIZE && reject_because(tiny, o, "tx too small"), "reject a tx below TX_MIN_SIZE (61)"); }
    { uint8_t *huge = calloc(1, TX_MAX_SIZE + 8);
      CHECK(huge && reject_because(huge, TX_MAX_SIZE + 1, "tx exceeds 100KB"), "reject a tx above TX_MAX_SIZE (100000)");
      free(huge); }

    // degenerate input/output counts
    { uint8_t big_ss[24]; big_ss[0] = 22; memset(big_ss + 1, 0xAA, 22);
      const uint8_t *ss[1] = { big_ss }; int ssn[1] = { 23 };
      int n = raw_tx(raw, 1, prev1, ss, ssn, 0, okval, spk1, spkn1);
      CHECK(n >= TX_MIN_SIZE && reject_because(raw, n, "no outputs"), "reject a tx with zero outputs"); }
    { // a 0-input tx starts with the segwit marker byte, so the parser refuses it first
      int o = 0; pu32(raw, &o, 1); pvar(raw, &o, 0);
      pvar(raw, &o, 1); pu64(raw, &o, okval[0]); pvar(raw, &o, 25); p(raw, &o, g_p2pkh, 25);
      pu32(raw, &o, 0);
      while (o < TX_MIN_SIZE) p1(raw, &o, 0);
      CHECK(reject_because(raw, o, "malformed/segwit tx"), "reject a tx with zero inputs (segwit-marker shaped)"); }

    // value arithmetic: the running total, and a negative value
    { uint64_t v2[2] = { 900000000000000000ULL, 900000000000000000ULL };   // each ≤ MAX_MONEY, sum > it
      int n = raw_tx(raw, 1, prev1, g_ss1, g_ssn1, 2, v2, spk1, spkn1);
      CHECK(reject_because(raw, n, "output total out of range"), "reject a running output TOTAL past MAX_MONEY"); }
    { uint64_t vneg[1] = { 0xFFFFFFFFFFFFFFFFULL };                        // = -1 as int64
      int n = raw_tx(raw, 1, prev1, g_ss1, g_ssn1, 1, vneg, spk1, spkn1);
      CHECK(reject_because(raw, n, "output value out of range"), "reject a NEGATIVE output value"); }
    { uint64_t vmax[1] = { (uint64_t)TX_MAX_MONEY };
      int n = raw_tx(raw, 1, prev1, g_ss1, g_ssn1, 1, vmax, spk1, spkn1);
      CHECK(accepted(raw, n), "accept an output of exactly MAX_MONEY (the boundary is inclusive)"); }

    // the dust BOUNDARY (the selftest only tests 1 koinu)
    { uint64_t vd[1] = { (uint64_t)TX_DUST_LIMIT };
      int n = raw_tx(raw, 1, prev1, g_ss1, g_ssn1, 1, vd, spk1, spkn1);
      CHECK(accepted(raw, n), "accept an output of exactly TX_DUST_LIMIT"); }
    { uint64_t vd[1] = { (uint64_t)TX_DUST_LIMIT - 1 };
      int n = raw_tx(raw, 1, prev1, g_ss1, g_ssn1, 1, vd, spk1, spkn1);
      CHECK(reject_because(raw, n, "dust output"), "reject an output one koinu below TX_DUST_LIMIT"); }
    { const uint8_t *sp[1] = { g_p2sh }; int sn[1] = { 23 };
      uint64_t vd[1] = { (uint64_t)TX_DUST_LIMIT - 1 };
      int n = raw_tx(raw, 1, prev1, g_ss1, g_ssn1, 1, vd, sp, sn);
      CHECK(reject_because(raw, n, "dust output"), "the dust rule covers P2SH outputs too"); }
    { const uint8_t *sp[1] = { g_p2sh }; int sn[1] = { 23 };
      int n = raw_tx(raw, 1, prev1, g_ss1, g_ssn1, 1, okval, sp, sn);
      CHECK(accepted(raw, n), "a funded P2SH output is standard"); }

    // carrier outputs are dust-exempt; malformed OP_RETURNs are not carriers
    { const uint8_t *sp[2] = { g_opret, g_p2pkh }; int sn[2] = { 38, 25 };
      uint64_t v[2] = { 0, 100000000ULL };
      int n = raw_tx(raw, 1, prev1, g_ss1, g_ssn1, 2, v, sp, sn);
      CHECK(accepted(raw, n), "an OP_RETURN carrier at value 0 is exempt from dust"); }
    { uint8_t dn[38]; memcpy(dn, g_opret, 38); dn[3] = 0x44;   // same push, DN magic
      const uint8_t *sp[2] = { dn, g_p2pkh }; int sn[2] = { 38, 25 };
      uint64_t v[2] = { 0, 100000000ULL };
      int n = raw_tx(raw, 1, prev1, g_ss1, g_ssn1, 2, v, sp, sn);
      CHECK(accepted(raw, n), "DN twin: an OP_RETURN carrier at value 0 is exempt from dust"); }
    { uint8_t multi[8]; int l = 0; p1(multi, &l, 0x6A); p1(multi, &l, 0x01); p1(multi, &l, 0xAA);
      p1(multi, &l, 0x01); p1(multi, &l, 0xBB);
      const uint8_t *sp[1] = { multi }; int sn[1] = { l };
      uint64_t v[1] = { 0 };
      int n = raw_tx(raw, 1, prev1, g_ss1, g_ssn1, 1, v, sp, sn);
      CHECK(reject_because(raw, n, "nonstandard scriptPubKey"), "a MULTI-push OP_RETURN is not a carrier (§1) → nonstandard"); }
    { uint8_t nonmin[80]; int l = 0; p1(nonmin, &l, 0x6A); p1(nonmin, &l, 0x4C); p1(nonmin, &l, 0x05);
      for (int i = 0; i < 5; i++) p1(nonmin, &l, 0xCC);
      const uint8_t *sp[1] = { nonmin }; int sn[1] = { l };
      uint64_t v[1] = { 0 };
      int n = raw_tx(raw, 1, prev1, g_ss1, g_ssn1, 1, v, sp, sn);
      CHECK(reject_because(raw, n, "nonstandard scriptPubKey"), "a NON-MINIMAL PUSHDATA1 OP_RETURN is not a carrier → nonstandard"); }

    // scriptSig: the exact cap boundary, and every push-opcode edge
    { static uint8_t ss1650[1650]; ss1650[0] = 0x4D; ss1650[1] = 0x6F; ss1650[2] = 0x06;  // PUSHDATA2 1647
      const uint8_t *ss[1] = { ss1650 }; int ssn[1] = { 1650 };
      int n = raw_tx(raw, 1, prev1, ss, ssn, 1, okval, spk1, spkn1);
      CHECK(accepted(raw, n), "accept a scriptSig of exactly TX_MAX_SCRIPTSIG (1650)"); }
    struct { const uint8_t bytes[12]; int len; int push_only; const char *what; } edges[] = {
        { { 0x4F }, 1, 1, "OP_1NEGATE (0x4f) counts as a push" },
        { { 0x50 }, 1, 1, "the reserved 0x50 counts as a push" },
        { { 0x60 }, 1, 1, "OP_16 (0x60) counts as a push" },
        { { 0x61 }, 1, 0, "OP_NOP (0x61) is the first non-push opcode" },
        { { 0xAC }, 1, 0, "OP_CHECKSIG (0xac) is not a push" },
        { { 0x4C }, 1, 0, "a truncated PUSHDATA1 (no length byte)" },
        { { 0x4C, 0x10 }, 2, 0, "a PUSHDATA1 whose data runs off the end" },
        { { 0x4D, 0x00 }, 2, 0, "a truncated PUSHDATA2 (one length byte)" },
        { { 0x4D, 0xFF, 0xFF }, 3, 0, "a PUSHDATA2 claiming 65535 bytes" },
        { { 0x4E, 0x00, 0x00, 0x00 }, 4, 0, "a truncated PUSHDATA4" },
        { { 0x4E, 0xFF, 0xFF, 0xFF, 0x7F }, 5, 0, "a PUSHDATA4 claiming 2^31-1 bytes (overrun probe)" },
        { { 0x4E, 0xFF, 0xFF, 0xFF, 0xFF }, 5, 0, "a PUSHDATA4 claiming 2^32-1 bytes (overrun probe)" },
        { { 0x4B }, 1, 0, "a direct push of 75 with no data" },
        { { 0x01, 0xAA, 0x02, 0xBB, 0xCC, 0x60 }, 6, 1, "a chain of pushes ending in OP_16" },
    };
    for (unsigned i = 0; i < sizeof edges / sizeof edges[0]; i++) {
        const uint8_t *ss[1] = { edges[i].bytes }; int ssn[1] = { edges[i].len };
        int n = raw_tx(raw, 1, prev1, ss, ssn, 1, okval, spk1, spkn1);
        char nm[160];
        if (edges[i].push_only) {
            snprintf(nm, sizeof nm, "scriptSig accepted: %s", edges[i].what);
            CHECK(accepted(raw, n), nm);
        } else {
            snprintf(nm, sizeof nm, "scriptSig rejected as not push-only: %s", edges[i].what);
            CHECK(reject_because(raw, n, "scriptSig not push-only"), nm);
        }
    }

    // inputs: same txid at DIFFERENT vouts is NOT an in-tx double spend
    { uint8_t two[2][36]; memset(two[0], 0xE1, 36); memcpy(two[1], two[0], 36);
      two[0][32] = 0; two[1][32] = 1;                       // same txid, vout 0 and 1
      int n = raw_tx(raw, 2, (const uint8_t (*)[36])two, g_ss1, g_ssn1, 1, okval, spk1, spkn1);
      CHECK(accepted(raw, n), "two inputs sharing a txid at different vouts are legal"); }
    { uint8_t two[2][36]; memset(two[0], 0xE1, 36); memcpy(two[1], two[0], 36);
      int n = raw_tx(raw, 2, (const uint8_t (*)[36])two, g_ss1, g_ssn1, 1, okval, spk1, spkn1);
      CHECK(reject_because(raw, n, "duplicate input"), "…while identical outpoints are still a duplicate input"); }
    // the coinbase rule fires only for a SINGLE-input tx (Core's shape) — a null
    // prevout alongside a second input is NOT treated as a coinbase.
    { uint8_t two[2][36]; memset(two[0], 0, 36); memset(two[0] + 32, 0xFF, 4);
      memset(two[1], 0xE7, 36);
      int n = raw_tx(raw, 2, (const uint8_t (*)[36])two, g_ss1, g_ssn1, 1, okval, spk1, spkn1);
      CHECK(accepted(raw, n), "a null prevout in a MULTI-input tx is not caught by the coinbase rule"); }
    // a null txid with a non-max vout is an ordinary (if unspendable) outpoint
    { uint8_t one[1][36]; memset(one[0], 0, 36);
      int n = raw_tx(raw, 1, (const uint8_t (*)[36])one, g_ss1, g_ssn1, 1, okval, spk1, spkn1);
      CHECK(accepted(raw, n), "a null txid with vout 0 is not a coinbase"); }

    // trailing bytes: a framed `tx` payload must be consumed exactly
    { int n = raw_tx(raw, 1, prev1, g_ss1, g_ssn1, 1, okval, spk1, spkn1);
      raw[n] = 0x00;
      CHECK(reject_because(raw, n + 1, "malformed/segwit tx"), "reject a tx with trailing bytes"); }
    { int n = raw_tx(raw, 1, prev1, g_ss1, g_ssn1, 1, okval, spk1, spkn1);
      CHECK(reject_because(raw, n - 1, "malformed/segwit tx"), "reject a truncated tx"); }

    // a NULL reason pointer must not crash
    { int n = raw_tx(raw, 1, prev1, g_ss1, g_ssn1, 1, okval, spk1, spkn1);
      raw[4] = 0xFF;                                   // corrupt the input count varint
      CHECK(txcheck_stateless(raw, (size_t)n, NULL, 0) == 0, "a NULL reason buffer is safe"); }
}

static void scan_cb(void *ud, const uint8_t txid[32], const uint8_t *r, size_t n) {
    (void)txid; (void)r; (void)n; (*(int *)ud)++;
}
static void sec_mempool(void) {
    printf("\n-- relay pool semantics the shipped selftest does NOT cover --\n");
    mempool_reset();
    uint8_t raw[4096];
    const uint8_t *spk1[1] = { g_p2pkh }; int spkn1[1] = { 25 };
    uint64_t okval[1] = { 100000000ULL };
    uint8_t prevA[36]; memset(prevA, 0xF1, 36);
    char why[128];

    int n = raw_tx(raw, 1, (const uint8_t (*)[36])prevA, g_ss1, g_ssn1, 1, okval, spk1, spkn1);
    uint8_t txid[32], zero[32] = { 0 };
    CHECK(mempool_accept(raw, (size_t)n, txid, why, sizeof why) == 1, "accept a hand-built standard tx");
    CHECK(memcmp(txid, zero, 32) != 0, "txid_out is filled on accept");
    CHECK(mempool_seen(txid), "an accepted tx reads as seen");

    uint8_t txid2[32];
    CHECK(mempool_accept(raw, (size_t)n, txid2, why, sizeof why) == 0 && !strcmp(why, "already in pool"),
          "a duplicate is rejected as 'already in pool'");
    CHECK(memcmp(txid2, txid, 32) == 0, "…with txid_out still filled (post-parse reject)");

    size_t glen = 0;
    uint8_t bogus[32]; memset(bogus, 0x99, 32);
    CHECK(mempool_get_copy(bogus, &glen) == NULL, "get_copy of an unknown txid returns NULL");
    CHECK(!mempool_has(bogus) && !mempool_seen(bogus), "an unknown txid is neither pooled nor seen");
    mempool_note_seen(bogus);
    CHECK(mempool_seen(bogus) && !mempool_has(bogus), "note_seen marks it seen WITHOUT pooling it");

    uint8_t ids[8][32];
    CHECK(mempool_txids(ids, 8) == 1 && memcmp(ids[0], txid, 32) == 0, "txids enumerates the pool");
    CHECK(mempool_txids(ids, 0) == 0, "txids with max 0 copies nothing");
    { int seen = 0; mempool_scan(scan_cb, &seen); CHECK(seen == 1, "scan visits every pooled tx"); }
    CHECK(mempool_count() == 1, "count == 1");

    // malformed bytes: txid_out is ZEROED (nothing parsed)
    { uint8_t junk[80]; memset(junk, 0x5A, sizeof junk);
      uint8_t out[32]; memset(out, 0xAA, 32);
      CHECK(mempool_accept(junk, sizeof junk, out, why, sizeof why) == 0, "malformed bytes are rejected");
      CHECK(memcmp(out, zero, 32) == 0, "…and txid_out is zeroed when nothing parses"); }

    // sweep: entries older than MEMPOOL_EXPIRY_SEC are dropped
    CHECK(mempool_count() == 1, "the pool still holds the accepted tx");
    mempool_sweep((int64_t)time(NULL));
    CHECK(mempool_count() == 1, "a fresh sweep drops nothing");
    mempool_sweep((int64_t)time(NULL) + MEMPOOL_EXPIRY_SEC + 10);
    CHECK(mempool_count() == 0 && !mempool_has(txid), "a sweep past the expiry drops the entry");
    CHECK(mempool_seen(txid), "…but the seen ring still remembers it (no re-request storm)");

    // reset clears both the pool AND the seen ring
    mempool_reset();
    CHECK(mempool_count() == 0 && !mempool_seen(txid), "reset clears the pool and the seen ring");

    // a tx rejected by txcheck never enters the pool
    { uint64_t dust[1] = { 1 };
      int m = raw_tx(raw, 1, (const uint8_t (*)[36])prevA, g_ss1, g_ssn1, 1, dust, spk1, spkn1);
      uint8_t out[32], dust_txid[32];
      idx_sha256d(raw, (size_t)m, dust_txid);          // the txid the peer announced
      CHECK(mempool_accept(raw, (size_t)m, out, why, sizeof why) == 0 && !strcmp(why, "dust output"),
            "a dust tx is rejected with txcheck's reason");
      CHECK(mempool_count() == 0, "…and never enters the pool");

      // mempool.h: the seen ring is "(accepted OR rejected) — suppresses
      // re-requesting a tx we already processed and dropped", and sync.c:1772
      // is the consumer: `if (mempool_has(h) || mempool_seen(h)) continue;`
      // guards the inv→getdata pull. A tx dropped by txcheck_stateless never
      // reaches note_seen_locked (mempool.c:98 returns before it), so every
      // re-announcement of the same junk tx is re-pulled and re-validated.
      /* FAILS: mempool.c:98 — mempool_accept returns on the txcheck_stateless
         failure BEFORE note_seen_locked (mempool.c:105), so a rejected-but-
         well-formed tx is never recorded in the "accepted OR rejected" seen
         ring that mempool.h documents. Scenario: a peer invs a dust tx; we
         getdata it, download it, reject it, record nothing; the peer invs it
         again on the next announcement cycle and we download and re-validate
         it again, indefinitely. The fix is to note_seen the parsed txid on a
         post-validation reject as well. */
      CHECK(mempool_seen(dust_txid),
            "a txcheck-rejected tx enters the seen ring (mempool.h: 'accepted OR rejected')");

      // txid_out on a parse-OK / txcheck-rejected tx: pinned as IMPLEMENTED.
      // mempool.h's "filled whenever the bytes parse" reads either way — the
      // only parse mempool_accept itself performs happens after txcheck — so
      // this records the behaviour rather than asserting an intent.
      uint8_t zero2[32] = { 0 };
      CHECK(memcmp(out, zero2, 32) == 0,
            "…txid_out is left zeroed on a pre-parse (txcheck) reject [behaviour pinned]"); }
    mempool_reset();
}

// ── 12. compact targets ──────────────────────────────────────────────────────
// A powLimit far above anything we generate, so idx_pow_next_bits never clamps.
#define POWLIM 0x1f7fffffu
// Unit modulation: actual solve time == 60 s ⇒ modulated == 60 ⇒ the new target
// is prev * 60 / 60 == prev exactly. So the call below is, precisely,
// target_to_bits(bits_to_target(bits)) — the compact round-trip, through the
// only exported door onto pow.c's static pair.
static uint32_t compact_roundtrip(uint32_t bits) { return idx_pow_next_bits(bits, 1000060, 1000000, POWLIM); }

// An INDEPENDENT re-derivation of "is this compact word a valid positive
// target", written from the arith_uint256/SetCompact rules rather than from
// pow.c, so agreement is evidence and not a tautology.
static int compact_is_valid(uint32_t bits) {
    if (bits & 0x00800000u) return 0;                       // the sign bit: negative
    uint32_t exp = bits >> 24, mant = bits & 0x007fffffu;
    if (mant == 0) return 0;
    if (exp <= 3) return (mant >> (8 * (3 - exp))) != 0;     // shifted away to nothing?
    return exp <= 32;                                        // past 32 bytes = past 256 bits
}
static int work_is_zero(uint32_t bits) {
    uint8_t w[32]; idx_pow_work(bits, w);
    for (int i = 0; i < 32; i++) if (w[i]) return 0;
    return 1;
}

static void sec_pow(void) {
    printf("\n-- compact targets: round-trip, normalisation, and rejection --\n");

    // real chain values first
    const uint32_t real[] = { 0x1e0fffff, 0x1e0ffff0, 0x1a009a69, 0x196ac0dc, 0x1d00ffff, 0x1b0404cb };
    for (unsigned i = 0; i < sizeof real / sizeof real[0]; i++) {
        char nm[96]; snprintf(nm, sizeof nm, "round-trip a real chain nBits 0x%08x", real[i]);
        CHECK(compact_roundtrip(real[i]) == real[i], nm);
    }

    // seeded-random canonical values (exp 3..30, mantissa's top byte set)
    g_rng = 0xC0FFEE1234567890ULL;
    int rt_bad = 0, rt_n = 0;
    for (int t = 0; t < 20000; t++) {
        uint64_t r = rnd64();
        uint32_t exp = 3 + (uint32_t)(r % 28);                       // 3..30
        uint32_t mant = 0x010000u + (uint32_t)((r >> 16) % 0x7F0000u); // 0x010000..0x7fffff
        uint32_t bits = (exp << 24) | mant;
        if (!compact_is_valid(bits)) continue;
        rt_n++;
        if (compact_roundtrip(bits) != bits) rt_bad++;
    }
    CHECK(rt_n > 19000, "the canonical round-trip actually ran (≈20000 values)");
    CHECK(rt_bad == 0, "every canonical compact value round-trips bits→target→bits exactly");

    // NON-canonical mantissas normalise onto the canonical form of the SAME target
    struct { uint32_t in, want; const char *what; } norm[] = {
        { 0x05000012u, 0x03120000u, "0x05000012 normalises to 0x03120000" },
        { 0x0500ffffu, 0x0500ffffu, "0x0500ffff is already canonical after the sign shift" },
        { 0x02008000u, 0x02008000u, "a two-byte mantissa keeps its exponent" },
        // exp ≤ 3 shifts the mantissa right by 8*(3-exp) (Core's SetCompact), so
        // 0x01123456 keeps only 0x12 and re-encodes at size 1.
        { 0x01123456u, 0x01120000u, "an exp-1 word keeps only its top mantissa byte" },
        { 0x03123456u, 0x03123456u, "exp 3 is the identity case" },
    };
    for (unsigned i = 0; i < sizeof norm / sizeof norm[0]; i++) {
        uint32_t got = compact_roundtrip(norm[i].in);
        char nm[160]; snprintf(nm, sizeof nm, "%s (got 0x%08x)", norm[i].what, got);
        CHECK(got == norm[i].want, nm);
        // whatever the encoding, equal targets must imply equal (and nonzero) work
        uint8_t wa[32], wb[32]; idx_pow_work(norm[i].in, wa); idx_pow_work(got, wb);
        snprintf(nm, sizeof nm, "…and 0x%08x / 0x%08x carry identical nonzero work", norm[i].in, got);
        CHECK(memcmp(wa, wb, 32) == 0 && !work_is_zero(norm[i].in), nm);
    }

    // invalid encodings must be REJECTED, not silently accepted
    struct { uint32_t bits; const char *what; } bad[] = {
        { 0x00000000u, "zero" },
        { 0x1d800000u, "the NEGATIVE flag (0x00800000) set" },
        { 0x1e800001u, "the negative flag with a nonzero mantissa" },
        { 0xFFFFFFFFu, "all ones (negative + exp 255)" },
        { 0x1d000000u, "a ZERO mantissa" },
        { 0x20000000u, "exp 32 with a zero mantissa" },
        { 0x21010000u, "exp 33 — OVERFLOWS 256 bits" },
        { 0xFF010000u, "exp 255 — far past 256 bits" },
        { 0x01000012u, "exp 1 whose mantissa shifts away to zero" },
        { 0x00123456u, "exp 0 whose mantissa shifts away to zero" },
    };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char nm[160];
        snprintf(nm, sizeof nm, "reject 0x%08x — %s (zero work)", bad[i].bits, bad[i].what);
        CHECK(work_is_zero(bad[i].bits), nm);
        snprintf(nm, sizeof nm, "reject 0x%08x — %s (no next-bits)", bad[i].bits, bad[i].what);
        CHECK(idx_pow_next_bits(bad[i].bits, 1000060, 1000000, POWLIM) == 0, nm);
    }

    // exhaustive-ish fuzz: accept/reject must agree with the independent predicate
    g_rng = 0x1234ABCD5678EF01ULL;
    int disagree = 0, valid_seen = 0, invalid_seen = 0;
    for (int t = 0; t < 200000; t++) {
        uint32_t bits = (uint32_t)rnd64();
        int want = compact_is_valid(bits);
        int got = !work_is_zero(bits);
        if (want) valid_seen++; else invalid_seen++;
        if (want != got) { if (!disagree) fprintf(stderr, "    first disagreement at 0x%08x\n", bits); disagree++; }
    }
    CHECK(valid_seen > 1000 && invalid_seen > 1000, "the fuzz saw both valid and invalid compact words");
    CHECK(disagree == 0, "over 200k random words, valid/invalid agrees with an independent predicate");

    // a valid target always has NONZERO work, and a bigger target means LESS work
    { uint8_t easy[32], hard[32];
      idx_pow_work(0x1e0fffff, easy); idx_pow_work(0x1b0404cb, hard);
      CHECK(idx_pow_work_cmp(hard, easy) > 0, "a smaller target carries more work");
      uint8_t sum[32]; memcpy(sum, easy, 32); idx_pow_work_add(sum, hard);
      CHECK(idx_pow_work_cmp(sum, hard) > 0 && idx_pow_work_cmp(sum, easy) > 0, "work accumulates"); }

    // and the block-level gate rejects junk rather than reading past it
    { PowParams pp = { 0x1e0fffff, 0x62 };
      char why[128]; uint8_t junk[16]; memset(junk, 0xAB, sizeof junk);
      CHECK(idx_pow_check(junk, sizeof junk, &pp, why, sizeof why) == 0, "idx_pow_check rejects a 16-byte 'block'");
      CHECK(idx_pow_check(junk, 0, &pp, why, sizeof why) == 0, "idx_pow_check rejects a zero-length buffer"); }
}

// ── main ─────────────────────────────────────────────────────────────────────
int main(void) {
    sec_b58_kav();
    sec_b58_roundtrip();
    sec_b58_reject();
    sec_txcheck();
    sec_mempool();
    sec_pow();
    printf(g_fail ? "\ntest_codec: FAIL\n" : "\ntest_codec: all ok\n");
    return g_fail;
}
