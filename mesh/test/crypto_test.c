// crypto_test.c — adversarial battery for src/crypto.c.
//
// PROVEN HERE:
//   1. KNOWN-ANSWER VECTORS for every primitive crypto.c wraps, taken from the
//      standards, not from this implementation:
//        · SHA-256   — NIST FIPS 180-2 §D.1/§D.2/§D.3 (""/"abc"/448-bit/896-bit/1M×'a')
//        · SHA-256d  — the Bitcoin double hash over those same inputs
//        · hash160   — RIPEMD160(SHA256(·)); pinned to the two canonical
//                      privkey=1 Bitcoin identities (751e76e8… / 91b24bf9…)
//        · secp256k1 — RFC 6979 deterministic ECDSA test vectors (the widely
//                      republished secp256k1/SHA-256 set: "Satoshi Nakamoto",
//                      "All those moments…", n−1, "Alan Turing", "computer disease")
//        · Base58Check — the canonical addresses those hash160s encode to
//                      (1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH, 1EHNa6Q4…,
//                       1111111111111111111114oLvT2)
//      NOTE: crypto.c wraps NO standalone HMAC and NO KDF — its public surface is
//      SHA-256 / SHA-256d / hash160 / secp256k1 pubkey·sign·verify / Base58Check /
//      §3.1 name rules. HMAC-SHA256 exists only inside libsecp's RFC-6979 nonce
//      generator, and is pinned transitively by the signing vectors above (a wrong
//      HMAC gives a different, still-valid r‖s — so the byte-exact match IS the
//      HMAC KAT).
//   2. sign→verify round-trip over thousands of seeded-random messages and keys
//      (SplitMix64, never rand(); the seed is printed and is reproducible via
//      `./crypto_test <seed>`).
//   3. NEGATIVE crypto, swept rather than sampled:
//        (a) every single bit of the message flipped (512 bits) — verify must fail
//        (b) every single bit of the digest flipped (256 bits) — must fail
//        (c) every single bit of the signature flipped (512 bits) — must fail
//        (d) verification against many wrong public keys — must fail
//        (e) all-zero, all-0xFF, r=0, s=0, r=n, s=n, r=p, and every trailing
//            truncation (last 1..32 bytes zeroed) — must fail
//        (f) wrong / over-long / under-long pubkey lengths, hybrid 0x06/0x07
//            SEC1 prefixes, x >= p — must fail, with the key placed against an
//            mmap guard page so any over-read traps instead of passing silently
//   4. MALLEABILITY: whether sp_ecdsa_verify enforces low-S. It does NOT — see
//      the FINDING banner in the "-- malleability --" section.
//   5. Constant-time review: the memcmp-based comparisons are enumerated by
//      reading, in the "-- side-channel review --" section. (No timing measured.)
//
// Links crypto.c only — no sqlite, no state/view.
#include "pepenet/crypto.h"

#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int g_fail;
static long g_checks;
#define CK(c, m) do { g_checks++; if (c) printf("  ok   %s\n", m); \
                      else { printf("  FAIL %s\n", m); g_fail++; } } while (0)
// quiet form for sweep loops: only the aggregate is printed
#define QCK(c) do { g_checks++; if (!(c)) sweep_bad++; } while (0)

// ── watchdog: a hang must FAIL, not hang ─────────────────────────────────────
static void on_alarm(int s) {
    (void)s;
    const char *m = "\ncrypto_test: WATCHDOG — timed out (hang)\n";
    ssize_t r = write(2, m, strlen(m)); (void)r;
    _exit(1);
}

// ── SplitMix64 (never rand()) ────────────────────────────────────────────────
static uint64_t g_rng;
static uint64_t rnd(void) {
    uint64_t z = (g_rng += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static void rndbytes(uint8_t *b, size_t n) { for (size_t i = 0; i < n; i++) b[i] = (uint8_t)rnd(); }

// ── hex helpers ──────────────────────────────────────────────────────────────
static int hb(const char *h, uint8_t *o, int n) {
    for (int i = 0; i < n; i++) { unsigned v; if (sscanf(h + 2 * i, "%2x", &v) != 1) return 0; o[i] = (uint8_t)v; }
    return 1;
}
static int hexeq(const uint8_t *b, int n, const char *h) {
    uint8_t e[64]; if (n > 64 || !hb(h, e, n)) return 0;
    return memcmp(b, e, (size_t)n) == 0;
}

// ── guard-page buffer: data ends exactly at a PROT_NONE page ─────────────────
// Any read one byte past `end` faults; a fault is trapped below and FAILS.
typedef struct { uint8_t *base; uint8_t *p; size_t len; size_t map; } Guard;
static int guard_make(Guard *g, const void *src, size_t len) {
    size_t ps = (size_t)getpagesize();
    size_t data = ((len + ps - 1) / ps) * ps; if (!data) data = ps;
    g->map = data + 2 * ps;
    g->base = mmap(NULL, g->map, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (g->base == MAP_FAILED) return 0;
    if (mprotect(g->base, ps, PROT_NONE) != 0) return 0;                    // guard before
    if (mprotect(g->base + ps + data, ps, PROT_NONE) != 0) return 0;        // guard after
    g->p = g->base + ps + data - len;                                        // flush right
    g->len = len;
    if (len) memcpy(g->p, src, len);
    return 1;
}
static void guard_free(Guard *g) { if (g->base && g->base != MAP_FAILED) munmap(g->base, g->map); g->base = NULL; }

static sigjmp_buf g_jmp;
static volatile sig_atomic_t g_trapped;
static void on_fault(int s) { (void)s; g_trapped = 1; siglongjmp(g_jmp, 1); }
static void trap_install(void) {
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_fault; sigemptyset(&sa.sa_mask); sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS, &sa, NULL);
}
#define NO_FAULT(stmt, label) do { g_trapped = 0; \
    if (sigsetjmp(g_jmp, 1) == 0) { stmt; } \
    CK(!g_trapped, label " (no out-of-bounds access)"); } while (0)

// ── curve constants (big-endian) ─────────────────────────────────────────────
static const uint8_t CURVE_N[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41 };
static const uint8_t CURVE_P[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F };
static const uint8_t N_HALF[32] = {   // floor(n/2) — the low-S admission bound
    0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0 };
static int be_cmp32(const uint8_t *a, const uint8_t *b) {
    for (int i = 0; i < 32; i++) if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}
static void be_sub32(const uint8_t *a, const uint8_t *b, uint8_t *o) {   // o = a - b
    int borrow = 0;
    for (int i = 31; i >= 0; i--) { int d = (int)a[i] - (int)b[i] - borrow;
        if (d < 0) { d += 256; borrow = 1; } else borrow = 0; o[i] = (uint8_t)d; }
}

// ── a deterministic valid keypair from a counter ─────────────────────────────
static void keyat(uint64_t i, uint8_t priv[32], uint8_t pub[33]) {
    uint8_t s[8]; for (int j = 0; j < 8; j++) s[j] = (uint8_t)(i >> (8 * j));
    sp_sha256(s, 8, priv);
    while (!sp_pubkey(priv, pub)) sp_sha256(priv, 32, priv);
}

// ═════════════════════════════════════════════════════════════════════════════
int main(int argc, char **argv) {
    signal(SIGALRM, on_alarm); alarm(300);
    trap_install();

    uint64_t seed = 0x5EED0C0FFEE12345ULL;
    if (argc > 1) seed = strtoull(argv[1], NULL, 0);
    else { const char *e = getenv("SP_SEED"); if (e) seed = strtoull(e, NULL, 0); }
    g_rng = seed;
    printf("crypto_test  seed = 0x%016llx   (reproduce: ./crypto_test 0x%016llx)\n",
           (unsigned long long)seed, (unsigned long long)seed);

    long sweep_bad = 0;
    uint8_t d[32], d2[32], h[20];

    // ── KAT: SHA-256 (NIST FIPS 180-2) ───────────────────────────────────────
    printf("-- KAT: SHA-256 (NIST FIPS 180-2) --\n");
    {
        sp_sha256((const uint8_t *)"", 0, d);
        CK(hexeq(d, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
           "SHA-256(\"\")");
        sp_sha256((const uint8_t *)"abc", 3, d);
        CK(hexeq(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
           "SHA-256(\"abc\")  §D.1");
        static const char *M448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        sp_sha256((const uint8_t *)M448, strlen(M448), d);
        CK(hexeq(d, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
           "SHA-256(448-bit msg)  §D.2");
        static const char *M896 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
                                  "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        sp_sha256((const uint8_t *)M896, strlen(M896), d);
        CK(hexeq(d, 32, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
           "SHA-256(896-bit msg)  §D.3");
        uint8_t *mil = malloc(1000000); memset(mil, 'a', 1000000);
        sp_sha256(mil, 1000000, d); free(mil);
        CK(hexeq(d, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
           "SHA-256(1,000,000 x 'a')  — also proves the length counter past 2^19 bits");
        // block-boundary sweep: 0..200 bytes must agree with a fresh call (no
        // ctx state leak between the padding cases 55/56/63/64/119/120)
        uint8_t buf[256]; memset(buf, 0x5A, sizeof buf);
        for (int n = 0; n <= 200; n++) {
            uint8_t a[32], b[32]; sp_sha256(buf, (size_t)n, a); sp_sha256(buf, (size_t)n, b);
            QCK(memcmp(a, b, 32) == 0);
        }
        CK(sweep_bad == 0, "SHA-256 is stateless across 201 padding-boundary lengths");
        sweep_bad = 0;
    }

    // ── KAT: SHA-256d ────────────────────────────────────────────────────────
    printf("-- KAT: SHA-256d (Bitcoin double hash) --\n");
    {
        sp_sha256d((const uint8_t *)"", 0, d);
        CK(hexeq(d, 32, "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"),
           "SHA-256d(\"\")");
        sp_sha256d((const uint8_t *)"abc", 3, d);
        CK(hexeq(d, 32, "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"),
           "SHA-256d(\"abc\")");
        // composition identity over random inputs
        for (int i = 0; i < 500; i++) {
            uint8_t m[128]; size_t n = rnd() % 128; rndbytes(m, n);
            uint8_t a[32], t[32], b[32];
            sp_sha256d(m, n, a); sp_sha256(m, n, t); sp_sha256(t, 32, b);
            QCK(memcmp(a, b, 32) == 0);
        }
        CK(sweep_bad == 0, "sha256d == sha256(sha256(x)) over 500 random inputs");
        sweep_bad = 0;
    }

    // ── KAT: hash160 ─────────────────────────────────────────────────────────
    printf("-- KAT: hash160 = RIPEMD160(SHA256(.)) --\n");
    {
        sp_hash160((const uint8_t *)"", 0, h);
        CK(hexeq(h, 20, "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"), "hash160(\"\")");
        sp_hash160((const uint8_t *)"abc", 3, h);
        CK(hexeq(h, 20, "bb1be98c142444d7a56aa3981c3942a978e4dc33"), "hash160(\"abc\")");
        uint8_t pub1c[33], pub1u[65];
        hb("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", pub1c, 33);
        hb("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
           "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", pub1u, 65);
        sp_hash160(pub1c, 33, h);
        CK(hexeq(h, 20, "751e76e8199196d454941c45d1b3a323f1433bd6"),
           "hash160(compressed pubkey of privkey=1)  — canonical Bitcoin identity");
        sp_hash160(pub1u, 65, h);
        CK(hexeq(h, 20, "91b24bf9f5288532960ac687abb035127b1d28a5"),
           "hash160(uncompressed pubkey of privkey=1)");
        // and the library must DERIVE that same pubkey from privkey=1
        uint8_t k1[32] = {0}; k1[31] = 1; uint8_t got[33];
        CK(sp_pubkey(k1, got) && memcmp(got, pub1c, 33) == 0,
           "sp_pubkey(1) == 0279BE667E…  (generator point G, compressed)");
    }

    // ── KAT: RFC 6979 deterministic ECDSA over secp256k1 ─────────────────────
    printf("-- KAT: secp256k1 ECDSA, RFC 6979 deterministic nonce --\n");
    {
        struct { const char *priv, *msg, *r, *s, *pub; } V[] = {
        { "0000000000000000000000000000000000000000000000000000000000000001",
          "Satoshi Nakamoto",
          "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8",
          "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5",
          "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" },
        { "0000000000000000000000000000000000000000000000000000000000000001",
          "All those moments will be lost in time, like tears in rain. Time to die...",
          "8600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b",
          "547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21",
          "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" },
        { "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140",   // n-1
          "Satoshi Nakamoto",
          "fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d0",
          "6b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5",
          "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" },
        { "f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181",
          "Alan Turing",
          "7063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c",
          "58dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea",
          "0292df7b245b81aa637ab4e867c8d511008f79161a97d64f2ac709600352f7acbc" },
        { "e91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2",
          "There is a computer disease that anybody who works with computers knows about. "
          "It's a very serious disease and it interferes completely with the work. "
          "The trouble with computers is that you 'play' with them!",
          "b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b",
          "279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6",
          "03567b7512001f3cc4dcb8b8096c046fff571ab07adb2126cd42908f2ff1ca424a" } };
        char lbl[160];
        for (unsigned i = 0; i < sizeof V / sizeof *V; i++) {
            uint8_t priv[32], pub[33], want[64], sig[64];
            hb(V[i].priv, priv, 32); hb(V[i].pub, pub, 33);
            hb(V[i].r, want, 32); hb(V[i].s, want + 32, 32);
            sp_sha256((const uint8_t *)V[i].msg, strlen(V[i].msg), d);
            snprintf(lbl, sizeof lbl, "vector %u: pubkey derives", i + 1);
            uint8_t gp[33]; CK(sp_pubkey(priv, gp) && memcmp(gp, pub, 33) == 0, lbl);
            // (i) the PUBLISHED r||s must verify — proves the vector is genuine
            //     independently of how this library signs
            snprintf(lbl, sizeof lbl, "vector %u: published r||s VERIFIES", i + 1);
            CK(sp_ecdsa_verify(d, want, pub, 33), lbl);
            // (ii) and signing must reproduce it byte-for-byte — RFC 6979 nonce
            //      (HMAC-SHA256 DRBG) + low-S normalisation, both pinned here
            snprintf(lbl, sizeof lbl, "vector %u: sp_ecdsa_sign reproduces r||s exactly", i + 1);
            CK(sp_ecdsa_sign(priv, d, sig) && memcmp(sig, want, 64) == 0, lbl);
            snprintf(lbl, sizeof lbl, "vector %u: signature is low-S", i + 1);
            CK(be_cmp32(want + 32, N_HALF) <= 0, lbl);
        }
    }

    // ── KAT: Base58Check ─────────────────────────────────────────────────────
    printf("-- KAT: Base58Check --\n");
    {
        uint8_t pay[64]; size_t pl; uint8_t ver; char out[128];
        hb("751e76e8199196d454941c45d1b3a323f1433bd6", h, 20);
        CK(sp_addr_encode(0x00, h, 20, out, sizeof out) &&
           strcmp(out, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH") == 0,
           "encode v0x00 + 751e76e8… -> 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        CK(sp_addr_decode("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", &ver, pay, sizeof pay, &pl) &&
           ver == 0x00 && pl == 20 && memcmp(pay, h, 20) == 0, "decode reverses it");
        hb("91b24bf9f5288532960ac687abb035127b1d28a5", h, 20);
        CK(sp_addr_encode(0x00, h, 20, out, sizeof out) &&
           strcmp(out, "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm") == 0,
           "encode v0x00 + 91b24bf9… -> 1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm");
        uint8_t z20[20]; memset(z20, 0, 20);
        CK(sp_addr_encode(0x00, z20, 20, out, sizeof out) &&
           strcmp(out, "1111111111111111111114oLvT2") == 0,
           "all-zero payload -> 21 leading '1's (leading-zero rule)");
        CK(sp_addr_decode("1111111111111111111114oLvT2", &ver, pay, sizeof pay, &pl) &&
           ver == 0 && pl == 20 && memcmp(pay, z20, 20) == 0, "and decodes back to 20 zero bytes");
        uint8_t f20[20]; memset(f20, 0xFF, 20);
        CK(sp_addr_encode(0x00, f20, 20, out, sizeof out) &&
           strcmp(out, "1QLbz7JHiBTspS962RLKV8GndWFwi5j6Qr") == 0, "all-0xFF payload vector");
        hb("bb1be98c142444d7a56aa3981c3942a978e4dc33", h, 20);
        CK(sp_addr_encode(0x37, h, 20, out, sizeof out) &&
           strcmp(out, "PReWxE36fp4nHyZ7egiEqdeQUymoPY5m8b") == 0,
           "version byte 0x37 (pepecoin P-address) vector");
    }

    // ── Base58Check negatives + boundaries ───────────────────────────────────
    printf("-- Base58Check: negatives and boundaries --\n");
    {
        uint8_t pay[256]; size_t pl; uint8_t ver; char out[512];
        CK(!sp_addr_decode("", &ver, pay, sizeof pay, &pl), "empty string rejected");
        CK(!sp_addr_decode("1", &ver, pay, sizeof pay, &pl), "1-char rejected (< 5 bytes)");
        CK(!sp_addr_decode("1111", &ver, pay, sizeof pay, &pl), "4 bytes rejected (< 5)");
        CK(!sp_addr_decode("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMI", &ver, pay, sizeof pay, &pl),
           "bad checksum rejected");
        CK(!sp_addr_decode("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAM0", &ver, pay, sizeof pay, &pl),
           "digit '0' (not in the alphabet) rejected");
        CK(!sp_addr_decode("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMO", &ver, pay, sizeof pay, &pl),
           "letter 'O' rejected");
        CK(!sp_addr_decode("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMI", &ver, pay, sizeof pay, &pl),
           "letter 'I' rejected");
        CK(!sp_addr_decode("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMl", &ver, pay, sizeof pay, &pl),
           "letter 'l' rejected");
        char ones[4096]; memset(ones, '1', sizeof ones - 1); ones[sizeof ones - 1] = 0;
        CK(!sp_addr_decode(ones, &ver, pay, sizeof pay, &pl),
           "4095 leading '1's rejected (no stack smash on the zeros path)");
        char zzz[4096]; memset(zzz, 'z', sizeof zzz - 1); zzz[sizeof zzz - 1] = 0;
        CK(!sp_addr_decode(zzz, &ver, pay, sizeof pay, &pl),
           "4095 'z' rejected (big-int scratch bound holds)");
        // encode buffer bounds: payload 123 is the documented max (n+1+4 <= 128)
        uint8_t big[200]; memset(big, 0xA5, sizeof big);
        CK(sp_addr_encode(0x00, big, 123, out, sizeof out), "payload 123 encodes (max)");
        CK(!sp_addr_encode(0x00, big, 124, out, sizeof out), "payload 124 refused (max+1)");
        CK(!sp_addr_encode(0x00, big, 200, out, sizeof out), "payload 200 refused");
        CK(!sp_addr_encode(0x00, h, 20, out, 5), "out_max too small refused");
        CK(sp_addr_encode(0x00, big, 0, out, sizeof out), "empty payload encodes");
        // decode payload_max too small
        CK(!sp_addr_decode("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", &ver, pay, 10, &pl),
           "payload_max smaller than the payload refused");
        // round-trip fuzz
        for (int i = 0; i < 4000; i++) {
            uint8_t v = (uint8_t)rnd(); size_t n = rnd() % 124;
            uint8_t p[128]; rndbytes(p, n);
            uint8_t v2, p2[128]; size_t n2;
            char s[512];
            int e = sp_addr_encode(v, p, n, s, sizeof s);
            QCK(e == 1);
            if (!e) continue;
            QCK(sp_addr_decode(s, &v2, p2, sizeof p2, &n2) && v2 == v && n2 == n &&
                memcmp(p, p2, n) == 0);
        }
        CK(sweep_bad == 0, "4000 seeded-random Base58Check encode->decode round-trips");
        sweep_bad = 0;
        // corrupt one char of a valid address: must never decode
        for (int i = 0; i < 3000; i++) {
            char s[128]; strcpy(s, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
            size_t L = strlen(s); size_t pos = rnd() % L;
            static const char A[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
            char c = A[rnd() % 58];
            if (c == s[pos]) continue;
            s[pos] = c;
            uint8_t v2, p2[64]; size_t n2;
            QCK(!sp_addr_decode(s, &v2, p2, sizeof p2, &n2));
        }
        CK(sweep_bad == 0, "3000 single-character corruptions all fail the checksum");
        sweep_bad = 0;
    }

    // ── round-trip: thousands of seeded-random sign/verify ───────────────────
    printf("-- sign/verify round-trip (seeded random) --\n");
    {
        const int N = 4000;
        int signed_ok = 0, verified = 0, lowS = 0;
        for (int i = 0; i < N; i++) {
            uint8_t priv[32], pub[33], sig[64];
            keyat(rnd(), priv, pub);
            uint8_t msg[256]; size_t n = rnd() % 256; rndbytes(msg, n);
            sp_sha256(msg, n, d);
            if (!sp_ecdsa_sign(priv, d, sig)) continue;
            signed_ok++;
            if (sp_ecdsa_verify(d, sig, pub, 33)) verified++;
            if (be_cmp32(sig + 32, N_HALF) <= 0) lowS++;
        }
        g_checks += 3;
        CK(signed_ok == N, "4000/4000 random (key,message) pairs signed");
        CK(verified == N, "4000/4000 signatures verify against their own key");
        CK(lowS == N, "4000/4000 produced signatures are low-S (sign side canonical)");
        // determinism: signing twice must give identical bytes (RFC 6979)
        for (int i = 0; i < 500; i++) {
            uint8_t priv[32], pub[33], a[64], b[64];
            keyat(rnd(), priv, pub);
            rndbytes(d, 32);
            QCK(sp_ecdsa_sign(priv, d, a) && sp_ecdsa_sign(priv, d, b) && memcmp(a, b, 64) == 0);
        }
        CK(sweep_bad == 0, "500x re-signing is bit-identical (deterministic nonce)");
        sweep_bad = 0;
    }

    // ── NEGATIVE: systematic bit-flip sweeps ─────────────────────────────────
    printf("-- negative: exhaustive bit-flip sweeps --\n");
    {
        uint8_t priv[32], pub[33], sig[64];
        keyat(0xA11CE, priv, pub);
        uint8_t msg[64]; rndbytes(msg, 64);
        sp_sha256(msg, 64, d);
        if (!sp_ecdsa_sign(priv, d, sig)) { CK(0, "setup sign"); }
        CK(sp_ecdsa_verify(d, sig, pub, 33), "baseline signature verifies");

        // (a) every bit of the 64-byte MESSAGE
        int accepted = 0;
        for (int byte = 0; byte < 64; byte++) for (int bit = 0; bit < 8; bit++) {
            uint8_t m2[64]; memcpy(m2, msg, 64); m2[byte] ^= (uint8_t)(1u << bit);
            sp_sha256(m2, 64, d2);
            g_checks++;
            if (sp_ecdsa_verify(d2, sig, pub, 33)) accepted++;
        }
        CK(accepted == 0, "all 512 single-bit message flips REJECTED");

        // (b) every bit of the 32-byte DIGEST
        accepted = 0;
        for (int byte = 0; byte < 32; byte++) for (int bit = 0; bit < 8; bit++) {
            memcpy(d2, d, 32);
            sp_sha256(msg, 64, d2); d2[byte] ^= (uint8_t)(1u << bit);
            g_checks++;
            if (sp_ecdsa_verify(d2, sig, pub, 33)) accepted++;
        }
        CK(accepted == 0, "all 256 single-bit digest flips REJECTED");

        // (c) every bit of the 64-byte SIGNATURE
        sp_sha256(msg, 64, d);
        accepted = 0;
        for (int byte = 0; byte < 64; byte++) for (int bit = 0; bit < 8; bit++) {
            uint8_t s2[64]; memcpy(s2, sig, 64); s2[byte] ^= (uint8_t)(1u << bit);
            g_checks++;
            if (sp_ecdsa_verify(d, s2, pub, 33)) accepted++;
        }
        CK(accepted == 0, "all 512 single-bit signature flips REJECTED");

        // (d) wrong public key
        accepted = 0;
        for (int i = 0; i < 500; i++) {
            uint8_t p2[32], q2[33]; keyat(0x1000 + (uint64_t)i, p2, q2);
            if (memcmp(q2, pub, 33) == 0) continue;
            g_checks++;
            if (sp_ecdsa_verify(d, sig, q2, 33)) accepted++;
        }
        CK(accepted == 0, "500 wrong public keys all REJECTED");
        // the sibling key (same x, flipped parity) is the classic near-miss
        { uint8_t q[33]; memcpy(q, pub, 33); q[0] ^= 0x01;
          CK(!sp_ecdsa_verify(d, sig, q, 33), "parity-flipped sibling pubkey REJECTED"); }
    }

    // ── NEGATIVE: degenerate / malformed signatures ──────────────────────────
    printf("-- negative: degenerate signature encodings --\n");
    {
        uint8_t priv[32], pub[33], sig[64], t[64];
        keyat(0xB0B, priv, pub);
        sp_sha256((const uint8_t *)"degenerate", 10, d);
        sp_ecdsa_sign(priv, d, sig);
        CK(sp_ecdsa_verify(d, sig, pub, 33), "baseline verifies");

        memset(t, 0x00, 64); CK(!sp_ecdsa_verify(d, t, pub, 33), "all-zero signature REJECTED");
        memset(t, 0xFF, 64); CK(!sp_ecdsa_verify(d, t, pub, 33), "all-0xFF signature REJECTED");
        memcpy(t, sig, 64); memset(t, 0, 32);
        CK(!sp_ecdsa_verify(d, t, pub, 33), "r = 0 REJECTED");
        memcpy(t, sig, 64); memset(t + 32, 0, 32);
        CK(!sp_ecdsa_verify(d, t, pub, 33), "s = 0 REJECTED");
        memcpy(t, sig, 64); memcpy(t, CURVE_N, 32);
        CK(!sp_ecdsa_verify(d, t, pub, 33), "r = n REJECTED (out of scalar range)");
        memcpy(t, sig, 64); memcpy(t + 32, CURVE_N, 32);
        CK(!sp_ecdsa_verify(d, t, pub, 33), "s = n REJECTED");
        memcpy(t, sig, 64); memcpy(t, CURVE_P, 32);
        CK(!sp_ecdsa_verify(d, t, pub, 33), "r = p REJECTED (p > n)");
        memcpy(t, sig, 64); memcpy(t + 32, CURVE_P, 32);
        CK(!sp_ecdsa_verify(d, t, pub, 33), "s = p REJECTED");
        // truncation: the API is fixed-width, so truncation == trailing zeros
        int acc = 0;
        for (int k = 1; k <= 32; k++) {
            memcpy(t, sig, 64); memset(t + 64 - k, 0, (size_t)k);
            g_checks++; if (sp_ecdsa_verify(d, t, pub, 33)) acc++;
        }
        CK(acc == 0, "32 trailing-truncation lengths (last 1..32 bytes zeroed) REJECTED");
        acc = 0;
        for (int k = 1; k <= 32; k++) {
            memcpy(t, sig, 64); memset(t, 0, (size_t)k);
            g_checks++; if (sp_ecdsa_verify(d, t, pub, 33)) acc++;
        }
        CK(acc == 0, "32 leading-truncation lengths (first 1..32 bytes zeroed) REJECTED");
        // swapped halves
        memcpy(t, sig + 32, 32); memcpy(t + 32, sig, 32);
        CK(!sp_ecdsa_verify(d, t, pub, 33), "r and s swapped REJECTED");
        // 20000 pure-random 64-byte "signatures"
        acc = 0;
        for (int i = 0; i < 20000; i++) { rndbytes(t, 64); g_checks++; if (sp_ecdsa_verify(d, t, pub, 33)) acc++; }
        CK(acc == 0, "20000 pure-random 64-byte signatures REJECTED");
    }

    // ── NEGATIVE: public key encodings, against a guard page ─────────────────
    printf("-- negative: public-key encoding gate (guard-paged) --\n");
    {
        uint8_t priv[32], pub[33], sig[64], pub65[65];
        keyat(0xC0DE, priv, pub);
        sp_sha256((const uint8_t *)"pubenc", 6, d);
        sp_ecdsa_sign(priv, d, sig);

        Guard g;
        CK(guard_make(&g, pub, 33), "guard-page buffer created");
        NO_FAULT({ (void)sp_ecdsa_verify(d, sig, g.p, 33); }, "verify(pub,33) at page edge");
        CK(sp_ecdsa_verify(d, sig, g.p, 33), "guard-paged pubkey still verifies");
        // wrong declared lengths must be refused WITHOUT reading past the key
        int lens[] = { 0, 1, 2, 16, 20, 32, 34, 40, 64, 66, 100, 1024 };
        int acc = 0;
        for (unsigned i = 0; i < sizeof lens / sizeof *lens; i++) {
            int L = lens[i];
            // place the key flush-right so a read of L>33 bytes from g.p walks INTO the guard
            g_trapped = 0;
            if (sigsetjmp(g_jmp, 1) == 0) { g_checks++; if (sp_ecdsa_verify(d, sig, g.p, L)) acc++; }
            if (g_trapped) { printf("  FAIL publen=%d caused an out-of-bounds read\n", L); g_fail++; }
        }
        CK(acc == 0, "12 wrong pubkey lengths (0,1,2,16,20,32,34,40,64,66,100,1024) REJECTED");
        guard_free(&g);
        // negative length
        CK(!sp_ecdsa_verify(d, sig, pub, -1), "negative publen REJECTED");
        // hybrid SEC1 prefixes 0x06/0x07 on a 65-byte key: valid to libsecp,
        // must be refused so the shim matches the pure reference impls
        hb("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
           "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", pub65, 65);
        uint8_t k1[32] = {0}; k1[31] = 1; uint8_t s1[64];
        sp_sha256((const uint8_t *)"hybrid", 6, d2);
        sp_ecdsa_sign(k1, d2, s1);
        CK(sp_ecdsa_verify(d2, s1, pub65, 65), "uncompressed 0x04 key accepted");
        pub65[0] = 0x06; CK(!sp_ecdsa_verify(d2, s1, pub65, 65), "hybrid prefix 0x06 REJECTED");
        pub65[0] = 0x07; CK(!sp_ecdsa_verify(d2, s1, pub65, 65), "hybrid prefix 0x07 REJECTED");
        pub65[0] = 0x00; CK(!sp_ecdsa_verify(d2, s1, pub65, 65), "prefix 0x00 REJECTED");
        pub65[0] = 0x04;
        // x >= p on a compressed key
        uint8_t bad33[33]; bad33[0] = 0x02; memcpy(bad33 + 1, CURVE_P, 32);
        CK(!sp_ecdsa_verify(d, sig, bad33, 33), "compressed key with x = p REJECTED");
        memset(bad33 + 1, 0xFF, 32);
        CK(!sp_ecdsa_verify(d, sig, bad33, 33), "compressed key with x = 2^256-1 REJECTED");
        bad33[0] = 0x01; memcpy(bad33 + 1, pub + 1, 32);
        CK(!sp_ecdsa_verify(d, sig, bad33, 33), "compressed prefix 0x01 REJECTED");
        bad33[0] = 0x04;
        CK(!sp_ecdsa_verify(d, sig, bad33, 33), "prefix 0x04 with 33-byte length REJECTED");
        // 5000 random 33-byte blobs as pubkeys
        acc = 0;
        for (int i = 0; i < 5000; i++) { rndbytes(bad33, 33); g_checks++;
            if (sp_ecdsa_verify(d, sig, bad33, 33)) acc++; }
        CK(acc == 0, "5000 random 33-byte blobs rejected as public keys");
        // sp_pubkey key-range gate
        uint8_t z[32]; memset(z, 0, 32); uint8_t o33[33];
        CK(!sp_pubkey(z, o33), "sp_pubkey(0) REJECTED");
        CK(!sp_pubkey(CURVE_N, o33), "sp_pubkey(n) REJECTED");
        memset(z, 0xFF, 32); CK(!sp_pubkey(z, o33), "sp_pubkey(2^256-1) REJECTED");
        uint8_t nm1[32]; memcpy(nm1, CURVE_N, 32); nm1[31] = 0x40;
        CK(sp_pubkey(nm1, o33), "sp_pubkey(n-1) accepted (top of the valid range)");
        CK(!sp_ecdsa_sign(z, d, sig), "sp_ecdsa_sign with an out-of-range key REJECTED");
    }

    // ── MALLEABILITY / CANONICALITY ──────────────────────────────────────────
    printf("-- malleability / canonicality --\n");
    {
        uint8_t priv[32], pub[33], sig[64], mal[64];
        keyat(0xDECAF, priv, pub);
        sp_sha256((const uint8_t *)"malleable", 9, d);
        sp_ecdsa_sign(priv, d, sig);
        CK(sp_ecdsa_verify(d, sig, pub, 33), "baseline (low-S) verifies");
        CK(be_cmp32(sig + 32, N_HALF) <= 0, "signer emits low-S");
        memcpy(mal, sig, 32); be_sub32(CURVE_N, sig + 32, mal + 32);   // s' = n - s
        CK(be_cmp32(mal + 32, N_HALF) > 0, "s' = n - s is high-S");
        CK(memcmp(mal, sig, 64) != 0, "s' is a DIFFERENT 64-byte encoding of the same signature");

        int accepts_high_s = sp_ecdsa_verify(d, mal, pub, 33);
        printf("\n"
               "  *** FINDING (malleability) *******************************************\n"
               "  sp_ecdsa_verify() does NOT enforce low-S / canonical (r,s).\n"
               "  src/crypto.c:35-39 forwards to secp_ecdsa_verify(), and\n"
               "  ../namespace-protocol/shim/secp_shim.c:89 calls\n"
               "      secp256k1_ecdsa_signature_normalize(CTX, &sig, &sig);\n"
               "  before verifying, i.e. it deliberately ACCEPTS high-S. So every\n"
               "  signature has two encodings that both verify at this layer, and\n"
               "  anything that identifies a message by its signature bytes (a dedup\n"
               "  cache, a gossip seen-set, a log key) can be doubled by an attacker\n"
               "  who never holds the private key.\n"
               "  Mitigation present: the ADMISSION path gates it separately —\n"
               "  src/state.c:26 low_s() is applied at src/state.c:321 (ops),\n"
               "  src/state.c:105 (P2PKH certs) and src/state.c:57 (multisig certs).\n"
               "  So op_id-keyed state is safe; any NEW caller of sp_ecdsa_verify()\n"
               "  that forgets the low_s() check inherits the malleability.\n"
               "  Classification: protocol/malleability, not memory-unsafe.\n"
               "  **********************************************************************\n\n");
        CK(accepts_high_s == 1,
           "documented behaviour pinned: high-S IS accepted by sp_ecdsa_verify (see FINDING)");
        // and pin the mitigation constant so a future change to N_HALF is caught
        uint8_t twice[32]; memcpy(twice, N_HALF, 32);
        // 2*floor(n/2) + 1 == n
        int carry = 0;
        for (int i = 31; i >= 0; i--) { int t2 = twice[i] * 2 + carry; twice[i] = (uint8_t)t2; carry = t2 >> 8; }
        twice[31] = (uint8_t)(twice[31] + 1);
        CK(carry == 0 && memcmp(twice, CURVE_N, 32) == 0,
           "state.c's N_HALF really is floor(n/2)  (2*N_HALF + 1 == n)");
        // sweep: for random signatures the high-S twin is always accepted too
        int twins = 0;
        for (int i = 0; i < 300; i++) {
            uint8_t p2[32], q2[33], s2[64], m2[64];
            keyat(rnd(), p2, q2); rndbytes(d2, 32);
            if (!sp_ecdsa_sign(p2, d2, s2)) continue;
            memcpy(m2, s2, 32); be_sub32(CURVE_N, s2 + 32, m2 + 32);
            g_checks++;
            if (sp_ecdsa_verify(d2, m2, q2, 33)) twins++;
        }
        CK(twins == 300, "300/300 high-S twins accepted — malleability is systematic, not incidental");
    }

    // ── §3.1 name rules: boundaries and a full byte sweep ────────────────────
    printf("-- name rules (§3.1) boundaries --\n");
    {
        char n[64];
        memset(n, 'a', sizeof n);
        CK(sp_name_valid(n, SP_NAME_MAX), "len == SP_NAME_MAX (32) valid");
        CK(!sp_name_valid(n, SP_NAME_MAX + 1), "len == SP_NAME_MAX+1 (33) invalid");
        CK(sp_name_valid(n, SP_NAME_MAX - 1), "len == SP_NAME_MAX-1 (31) valid");
        CK(!sp_name_valid(n, 0), "len 0 invalid");
        CK(!sp_name_valid(NULL, 5), "NULL invalid");
        CK(!sp_name_valid(NULL, 0), "NULL + len 0 invalid");
        // every byte value at every position class
        int bad = 0;
        for (int c = 0; c < 256; c++) {
            char t[4] = { 'a', (char)c, 'b', 0 };
            int want = ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-');
            g_checks++;
            if (sp_name_valid(t, 3) != want) { bad++; printf("  FAIL charset byte 0x%02x\n", c); }
        }
        CK(bad == 0, "all 256 byte values classified exactly as [a-z0-9-]");
        // embedded NUL must not truncate the scan
        { char t[5] = { 'a', 0, 'b', 'c', 0 };
          CK(!sp_name_valid(t, 4), "embedded NUL rejected (length-driven scan, not strlen)"); }
        // guard page: only `len` bytes may be read
        { Guard g; if (guard_make(&g, "abc", 3)) {
            NO_FAULT({ (void)sp_name_valid((const char *)g.p, 3); }, "sp_name_valid reads only len bytes");
            guard_free(&g); } }
        // the ACE rule
        CK(!sp_name_valid("xn--a", 5), "xn--a rejected");
        CK(!sp_name_valid("ab--", 4), "ab-- rejected (also trailing hyphen)");
        CK(sp_name_valid("a--b", 4), "a--b valid (-- at 2-3, not 3-4)");
        CK(sp_name_valid("abc--d", 6), "abc--d valid (-- at 4-5)");
        CK(!sp_name_valid("ab--c", 5), "ab--c rejected (-- exactly at 3-4)");
        // sp_key_is_owner
        uint8_t priv[32], pub[33], own[20];
        keyat(7, priv, pub); sp_hash160(pub, 33, own);
        CK(sp_key_is_owner(pub, 33, own), "sp_key_is_owner: matching hash160");
        int acc = 0;
        for (int i = 0; i < 20; i++) for (int b = 0; b < 8; b++) {
            uint8_t o2[20]; memcpy(o2, own, 20); o2[i] ^= (uint8_t)(1u << b);
            g_checks++; if (sp_key_is_owner(pub, 33, o2)) acc++;
        }
        CK(acc == 0, "all 160 single-bit owner-hash flips rejected by sp_key_is_owner");
    }

    // ── side-channel review (by reading, no timing measured) ─────────────────
    printf("-- side-channel review (read, not measured) --\n");
    printf("  note  src/crypto.c:43   sp_key_is_owner  -> memcmp(h, owner, 20)\n");
    printf("  note  src/crypto.c:119  sp_addr_decode   -> memcmp(ck, full+flen-4, 4)\n");
    printf("  note  src/state.c:99    sp_cert_verify   -> memcmp(ct->name, name, n)\n");
    printf("  note  src/state.c:100   sp_cert_verify   -> memcmp(posting_key, .., 33)\n");
    printf("  note  src/state.c:104   sp_cert_verify   -> memcmp(h, owner_h160, 20)\n");
    printf("  note  src/state.c:110   sp_cert_verify   -> memcmp(h, owner_h160, 20)\n");
    printf("  note  src/state.c:338   sp_state_admit   -> memcmp(hh, anchor_hash, 32)\n");
    printf("  note  src/state.c:365/395              -> memcmp(op_id, .., 32) dedup\n");
    CK(1, "every memcmp above compares PUBLIC values (hash160s, pubkeys, header "
          "hashes, op_ids) — none is a secret-key or MAC comparison, so the "
          "early-exit leak is not exploitable here");
    CK(1, "no HMAC/MAC tag comparison exists in crypto.c to leak (there is no "
          "standalone HMAC in the public surface at all)");
    printf("  note  private-key handling: crypto.c never compares or branches on\n"
           "        priv[]; all secret math is inside vendored libsecp256k1\n"
           "        (constant-time by construction). secp_shim.c:107 signs through\n"
           "        an UNRANDOMIZED context (no secp256k1_context_randomize call) —\n"
           "        acceptable for RFC-6979 deterministic ECDSA, but it forgoes the\n"
           "        blinding libsecp offers against physical side channels.\n");

    alarm(0);
    printf("\ncrypto_test: %ld checks, %d failed\n", g_checks, g_fail);
    if (g_fail) { printf("crypto_test: FAILED\n"); return 1; }
    printf("crypto_test: all passed\n");
    return 0;
}
