/* t_hdwallet.c — BIP32/BIP44 derivation. The seed is the wallet; if this walks
 * the wrong tree the money is at an address the user's backup phrase can never
 * reproduce on any other client.
 *
 * The problem: hdwallet.h exposes exactly ONE path, m/44'/3'/0'/0/<index>, and
 * no published vector set covers it. So the suite builds its own general BIP-32
 * CKD-priv walker (OpenSSL HMAC-SHA512 + libsecp scalar tweak-add) and first
 * PINS THAT WALKER to the official BIP-32 Test Vector 1 — master and all five
 * children of m/0'/1/2'/2/1000000000, private key AND chain code, covering
 * hardened and non-hardened steps and the 1000000000 index encoding. Only then
 * is it used as the oracle for the product's fixed path.
 *
 * Proves, on top of that anchor:
 *   · hd_privkey_from_seed(seed, i) is exactly CKD(m/44'/3'/0'/0/i) — the
 *     BIP-44 purpose, coin type 3, account 0, EXTERNAL chain 0, and the
 *     hardening pattern ' ' ' - -, verified against a vector-pinned walker over
 *     thousands of random seeds and indices;
 *   · it is NOT any of the plausible near-miss paths (wrong coin type, wrong
 *     change branch, wrong account, all-hardened, all-unhardened) — the classic
 *     way a wallet silently strands funds;
 *   · derivation is deterministic (same seed+index → identical 32 bytes),
 *     distinct paths give distinct keys with no collisions over 4000 draws,
 *     hardened and non-hardened children of the same parent differ, and every
 *     derived scalar is a valid secp256k1 secret key;
 *   · a single flipped seed bit changes the key (no truncated-seed bug);
 *   · edge indices 0 / 1 / 2^31-1 / 2^31 / 2^32-1 all return success, and the
 *     unchecked top bit at index ≥ 2^31 silently HARDENS the last step — the
 *     one thing here that does not match the header's stated path.
 *
 * No key or seed is printed or written anywhere: the seeds are public test
 * vectors and synthetic PRNG output, and only pass/fail is reported.
 */
#include "hdwallet.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <secp256k1.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail, g_ok, g_nfail;
#define CHECK(cond, name) do { \
    if (cond) { printf("ok   %s\n", name); g_ok++; } \
    else      { printf("FAIL %s\n", name); g_fail = 1; g_nfail++; } \
} while (0)

/* deterministic PRNG — a failing seed must be reproducible, so never rand() */
static uint64_t g_rng = 0xC0FFEE123456789ULL;
static uint64_t sm64(void) {
    uint64_t z = (g_rng += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static void rand_bytes(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(sm64() >> 24);
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}
static void unhex(const char *h, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(hexval(h[2*i]) * 16 + hexval(h[2*i+1]));
}

/* ── the reference walker: general BIP-32 CKD-priv, any seed length, any path.
 *    Pinned to the official vectors below BEFORE it is trusted as an oracle. */
static secp256k1_context *CX;
static void hmac512(const uint8_t *k, int kl, const uint8_t *d, int dl, uint8_t o[64]) {
    unsigned int ol = 64;
    HMAC(EVP_sha512(), k, kl, d, (size_t)dl, o, &ol);
}
static int ckd(const uint8_t *seed, int seedlen, const uint32_t *path, int n,
               uint8_t priv[32], uint8_t cc[32]) {
    uint8_t I[64], data[37], pub[33];
    hmac512((const uint8_t *)"Bitcoin seed", 12, seed, seedlen, I);
    memcpy(priv, I, 32);
    memcpy(cc, I + 32, 32);
    if (!secp256k1_ec_seckey_verify(CX, priv)) return 0;
    for (int L = 0; L < n; L++) {
        if (path[L] & 0x80000000u) {
            data[0] = 0x00;
            memcpy(data + 1, priv, 32);
        } else {
            secp256k1_pubkey pk;
            if (!secp256k1_ec_pubkey_create(CX, &pk, priv)) return 0;
            size_t pl = sizeof pub;
            secp256k1_ec_pubkey_serialize(CX, pub, &pl, &pk, SECP256K1_EC_COMPRESSED);
            memcpy(data, pub, 33);
        }
        data[33] = (uint8_t)(path[L] >> 24); data[34] = (uint8_t)(path[L] >> 16);
        data[35] = (uint8_t)(path[L] >> 8);  data[36] = (uint8_t)(path[L]);
        hmac512(cc, 32, data, 37, I);
        if (!secp256k1_ec_seckey_tweak_add(CX, priv, I)) return 0;
        memcpy(cc, I + 32, 32);
    }
    return 1;
}

/* the product's one path */
#define P44 0x8000002Cu
#define C3  0x80000003u
#define A0  0x80000000u
static void path44(uint32_t p[5], uint32_t index) {
    p[0] = P44; p[1] = C3; p[2] = A0; p[3] = 0; p[4] = index;
}

/* ── official BIP-32 Test Vector 1 (seed 000102030405060708090a0b0c0d0e0f) ── */
typedef struct { int depth; const char *label, *priv, *cc; } B32;
static const B32 V1[] = {
 { 0, "m",
   "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
   "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508" },
 { 1, "m/0'",
   "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
   "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141" },
 { 2, "m/0'/1",
   "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
   "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19" },
 { 3, "m/0'/1/2'",
   "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
   "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f" },
 { 4, "m/0'/1/2'/2",
   "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
   "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd" },
 { 5, "m/0'/1/2'/2/1000000000",
   "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
   "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e" },
};

int main(void) {
    CX = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    uint8_t priv[32], cc[32], wp[32], wc[32], seed[64];
    char name[128];

    /* ═══ 1. pin the reference walker to the official BIP-32 vectors ════ */
    printf("-- official BIP-32 Test Vector 1 (pins the reference walker) --\n");
    {
        uint8_t v1seed[16];
        unhex("000102030405060708090a0b0c0d0e0f", v1seed, 16);
        const uint32_t full[5] = { 0x80000000u, 1u, 0x80000002u, 2u, 1000000000u };
        for (int i = 0; i < (int)(sizeof V1 / sizeof V1[0]); i++) {
            unhex(V1[i].priv, wp, 32);
            unhex(V1[i].cc, wc, 32);
            int ok = ckd(v1seed, 16, full, V1[i].depth, priv, cc);
            snprintf(name, sizeof name, "BIP-32 vector 1 %s → private key", V1[i].label);
            CHECK(ok && !memcmp(priv, wp, 32), name);
            snprintf(name, sizeof name, "BIP-32 vector 1 %s → chain code", V1[i].label);
            CHECK(ok && !memcmp(cc, wc, 32), name);
        }
    }

    /* ═══ 2. the product's path IS m/44'/3'/0'/0/<index> ════════════════ */
    printf("-- hd_privkey_from_seed == CKD(m/44'/3'/0'/0/i) --\n");
    {
        /* the canonical all-zero-entropy BIP-39 seed — a public test vector */
        unhex("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
              "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4", seed, 64);
        uint32_t p[5];
        path44(p, 0);
        CHECK(ckd(seed, 64, p, 5, wp, wc) && hd_privkey_from_seed(seed, 0, priv) == 1 &&
              !memcmp(priv, wp, 32),
              "canonical BIP-39 seed, index 0 → the m/44'/3'/0'/0/0 key");

        int mismatch = 0, failed = 0;
        for (int t = 0; t < 1200; t++) {
            rand_bytes(seed, 64);
            uint32_t idx = (uint32_t)(sm64() & 0x7FFFFFFFu);
            path44(p, idx);
            if (!hd_privkey_from_seed(seed, idx, priv)) { failed++; continue; }
            if (!ckd(seed, 64, p, 5, wp, wc) || memcmp(priv, wp, 32)) mismatch++;
        }
        CHECK(failed == 0,   "1200 random seeds × random indices all derive successfully");
        CHECK(mismatch == 0, "all 1200 match the vector-pinned walker exactly");

        /* sequential indices too — index encoding is big-endian, off-by-one free */
        int seq_bad = 0;
        rand_bytes(seed, 64);
        for (uint32_t i = 0; i < 256; i++) {
            path44(p, i);
            if (!hd_privkey_from_seed(seed, i, priv)) { seq_bad++; continue; }
            if (!ckd(seed, 64, p, 5, wp, wc) || memcmp(priv, wp, 32)) seq_bad++;
        }
        CHECK(seq_bad == 0, "indices 0..255 match the walker (big-endian index encoding)");
    }

    /* ═══ 3. it is not a NEAR-MISS path ═════════════════════════════════ */
    printf("-- the near-miss paths that would strand funds --\n");
    {
        rand_bytes(seed, 64);
        hd_privkey_from_seed(seed, 7, priv);
        struct { const char *label; uint32_t p[5]; } near[] = {
            { "m/44'/0'/0'/0/7   (bitcoin coin type)",  { P44, 0x80000000u, A0, 0, 7 } },
            { "m/44'/3'/1'/0/7   (account 1)",          { P44, C3, 0x80000001u, 0, 7 } },
            { "m/44'/3'/0'/1/7   (internal/change)",    { P44, C3, A0, 1, 7 } },
            { "m/44'/3'/0'/0'/7  (hardened change)",    { P44, C3, A0, A0, 7 } },
            { "m/44'/3'/0'/0/7'  (hardened leaf)",      { P44, C3, A0, 0, 0x80000007u } },
            { "m/44/3/0/0/7     (nothing hardened)",    { 44u, 3u, 0u, 0u, 7 } },
            { "m/3'/44'/0'/0/7  (purpose/coin swapped)",{ C3, P44, A0, 0, 7 } },
        };
        for (int i = 0; i < (int)(sizeof near / sizeof near[0]); i++) {
            int ok = ckd(seed, 64, near[i].p, 5, wp, wc);
            snprintf(name, sizeof name, "differs from %s", near[i].label);
            CHECK(ok && memcmp(priv, wp, 32) != 0, name);
        }
        /* and a truncated path is not it either */
        uint32_t p4[5]; path44(p4, 7);
        CHECK(ckd(seed, 64, p4, 4, wp, wc) && memcmp(priv, wp, 32) != 0,
              "differs from the 4-level prefix m/44'/3'/0'/0");
    }

    /* ═══ 4. determinism, distinctness, hardening ═══════════════════════ */
    printf("-- determinism and distinctness --\n");
    {
        int nondet = 0;
        rand_bytes(seed, 64);
        hd_privkey_from_seed(seed, 3, wp);
        for (int t = 0; t < 2000; t++) {
            if (!hd_privkey_from_seed(seed, 3, priv) || memcmp(priv, wp, 32)) nondet++;
        }
        CHECK(nondet == 0, "same seed + same index → identical key, 2000/2000");

        /* 4000 distinct (seed,index) pairs must give 4000 distinct keys */
        enum { N = 4000 };
        static uint8_t keys[N][32];
        int derive_fail = 0;
        uint8_t fixed_seed[64];
        rand_bytes(fixed_seed, 64);          /* one seed, 2000 indices */
        for (int t = 0; t < N; t++) {
            /* half: 2000 seeds at index 0. half: one seed at indices 1..2000 —
             * index 0 of `fixed_seed` is deliberately skipped so the two halves
             * cannot legitimately name the same (seed, index) pair. */
            if (t < N / 2) { rand_bytes(seed, 64); hd_privkey_from_seed(seed, 0, keys[t]); }
            else           { hd_privkey_from_seed(fixed_seed, (uint32_t)(t - N / 2 + 1), keys[t]); }
            if (!secp256k1_ec_seckey_verify(CX, keys[t])) derive_fail++;
        }
        CHECK(derive_fail == 0, "every derived scalar is a valid secp256k1 secret key");
        int collisions = 0;
        for (int i = 0; i < N; i++)
            for (int j = i + 1; j < N; j++)
                if (!memcmp(keys[i], keys[j], 32)) collisions++;
        CHECK(collisions == 0, "4000 distinct seeds/indices → 4000 distinct keys");

        /* zero key never escapes */
        uint8_t zero[32] = { 0 };
        int zeros = 0;
        for (int t = 0; t < N; t++) if (!memcmp(keys[t], zero, 32)) zeros++;
        CHECK(zeros == 0, "no derived key is the zero scalar");

        /* hardened vs non-hardened child of the same parent */
        uint32_t hp[5], np[5];
        path44(np, 11); path44(hp, 11); hp[4] = 0x8000000Bu;   /* 11' */
        rand_bytes(seed, 64);
        uint8_t a[32], b[32], acc[32], bcc[32];
        CHECK(ckd(seed, 64, np, 5, a, acc) && ckd(seed, 64, hp, 5, b, bcc) &&
              memcmp(a, b, 32) != 0 && memcmp(acc, bcc, 32) != 0,
              "hardened child 11' differs from non-hardened child 11 (key and chain code)");
    }

    /* ═══ 5. seed sensitivity ═══════════════════════════════════════════ */
    printf("-- seed sensitivity (no truncated-seed bug) --\n");
    {
        uint8_t base[64];
        rand_bytes(base, 64);
        hd_privkey_from_seed(base, 0, wp);
        int same = 0, failed = 0;
        for (int bit = 0; bit < 512; bit++) {
            memcpy(seed, base, 64);
            seed[bit >> 3] ^= (uint8_t)(0x80 >> (bit & 7));
            if (!hd_privkey_from_seed(seed, 0, priv)) { failed++; continue; }
            if (!memcmp(priv, wp, 32)) same++;
        }
        CHECK(failed == 0, "all 512 single-bit seed variants derive successfully");
        CHECK(same == 0,   "every one of the 512 seed bits changes the derived key");

        /* degenerate seeds still derive */
        memset(seed, 0x00, 64);
        CHECK(hd_privkey_from_seed(seed, 0, priv) == 1 && secp256k1_ec_seckey_verify(CX, priv),
              "all-zero seed derives a valid key");
        memset(seed, 0xFF, 64);
        CHECK(hd_privkey_from_seed(seed, 0, priv) == 1 && secp256k1_ec_seckey_verify(CX, priv),
              "all-0xFF seed derives a valid key");
    }

    /* ═══ 6. index edge values ══════════════════════════════════════════ */
    printf("-- index edge values --\n");
    {
        rand_bytes(seed, 64);
        const uint32_t edges[] = { 0u, 1u, 2u, 0x7FFFFFFEu, 0x7FFFFFFFu,
                                   0x80000000u, 0x80000001u, 0xFFFFFFFFu };
        int allok = 1, allvalid = 1;
        for (int i = 0; i < (int)(sizeof edges / sizeof edges[0]); i++) {
            if (!hd_privkey_from_seed(seed, edges[i], priv)) allok = 0;
            else if (!secp256k1_ec_seckey_verify(CX, priv)) allvalid = 0;
        }
        CHECK(allok,    "indices 0, 1, 2, 2^31-2, 2^31-1, 2^31, 2^31+1, 2^32-1 all succeed");
        CHECK(allvalid, "every edge index yields a valid secret key");

        /* the last BIP-44 level is meant to be a NORMAL child, but the index is
         * spliced into the path verbatim, so its top bit selects hardening. */
        uint32_t p[5];
        path44(p, 0x80000000u);                 /* what the code actually walks */
        CHECK(hd_privkey_from_seed(seed, 0x80000000u, priv) && ckd(seed, 64, p, 5, wp, wc) &&
              !memcmp(priv, wp, 32),
              "index 2^31 silently derives the HARDENED child (no range check on index)");
        /* …and it is NOT the normal child of index 0, i.e. the two namespaces
         * overlap in the API's flat uint32 index space */
        path44(p, 0u);
        CHECK(ckd(seed, 64, p, 5, wp, wc) && memcmp(priv, wp, 32) != 0,
              "index 2^31 and index 0 are different keys (hardened namespace aliases in)");
    }

    secp256k1_context_destroy(CX);
    printf("\nt_hdwallet: %d ok, %d failed\n", g_ok, g_nfail);
    return g_fail;
}
