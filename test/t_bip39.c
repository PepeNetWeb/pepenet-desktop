/* t_bip39.c — the recovery phrase. This is the LAST line of defence on a lost
 * machine, so what it proves is exactness, not "it runs".
 *
 * Proves: src/bip39.c reproduces the official BIP-39 English test vectors
 * bit-for-bit (entropy → mnemonic, mnemonic → entropy, mnemonic → seed) — the
 * seed leg is anchored two ways, against the published TREZOR-passphrase
 * vectors recomputed here through OpenSSL's PBKDF2 (proving the KDF stack in
 * THIS build is BIP-39-conformant: salt "mnemonic"+passphrase, 2048 rounds,
 * HMAC-SHA512, 64 bytes) and against the independently-published empty-
 * passphrase seed for the canonical all-zero phrase (proving bip39.c passes
 * the EMPTY passphrase, which is what it actually promises).
 *
 * Proves: the checksum is a real 4-bit gate and not decoration — for every one
 * of the 132 bit positions of a phrase's word-index stream, acceptance matches
 * an INDEPENDENT oracle (OpenSSL SHA-256, not the engine's sha256.c) exactly;
 * corrupting any of the 4 checksum bits is rejected 100% of the time, and
 * corrupting an entropy bit is rejected at the ~15/16 rate the 4-bit checksum
 * mathematically allows. Same for every one of the 2047 wrong final words.
 *
 * Proves: the wordlist itself satisfies BIP-39's structural requirements —
 * exactly 2048 entries, strictly ascending, no duplicates, unique in the first
 * four characters (the property the standard grants users so a phrase can be
 * typed four letters at a time), pure lowercase ASCII.
 *
 * Proves: encode never writes outside `cap` for ANY cap from 0 to 200 (canary-
 * guarded), and decode fails cleanly — never crashes, never reads out of
 * bounds — on NULL, "", 1/11/13/15/24-word phrases, 100 KB of garbage,
 * embedded NULs, UTF-8, tabs/CRLF, and words that share a 4-char prefix with a
 * real one.
 *
 * SCOPE NOTE: bip39.h fixes this API at 128-bit entropy / 12 words. The other
 * BIP-39 entropy sizes (160/192/224/256) are therefore not reachable through
 * any function here; the closest reachable assertion — that phrases of those
 * word counts are REJECTED rather than half-parsed — is made below.
 */
#include "bip39.h"

#include <openssl/evp.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail, g_ok, g_nfail;
#define CHECK(cond, name) do { \
    if (cond) { printf("ok   %s\n", name); g_ok++; } \
    else      { printf("FAIL %s\n", name); g_fail = 1; g_nfail++; } \
} while (0)

/* ── deterministic PRNG (SplitMix64) — never rand(): a failing seed must be
 *    reproducible on the next run and on someone else's machine. ─────────── */
static uint64_t g_rng = 0xDEECE66D1BADF00DULL;
static uint64_t sm64(void) {
    uint64_t z = (g_rng += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static void rand_bytes(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(sm64() >> 24);
}

/* ── independent primitives: OpenSSL, deliberately NOT the engine's sha256.c
 *    that bip39.c itself uses, so a shared bug cannot cancel out. ────────── */
static void osha256(const uint8_t *d, size_t n, uint8_t out[32]) {
    unsigned int ol = 32;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c, EVP_sha256(), NULL);
    EVP_DigestUpdate(c, d, n);
    EVP_DigestFinal_ex(c, out, &ol);
    EVP_MD_CTX_free(c);
}
static void pbkdf2_seed(const char *mnemonic, const char *passphrase, uint8_t out[64]) {
    char salt[256];
    snprintf(salt, sizeof salt, "mnemonic%s", passphrase);
    PKCS5_PBKDF2_HMAC(mnemonic, (int)strlen(mnemonic),
                      (const unsigned char *)salt, (int)strlen(salt),
                      2048, EVP_sha512(), 64, out);
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static void unhex(const char *h, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(hexval(h[2*i]) * 16 + hexval(h[2*i+1]));
}

/* 132-bit stream (16 entropy bytes + 4 checksum bits in the top nibble of
 * bits[16]) → the 12 words it encodes. Lets the test build phrases bip39.c's
 * own encoder would never emit (wrong checksums, single-bit corruptions). */
static void words_from_bits(const uint8_t bits[17], char *out, size_t cap) {
    size_t n = 0;
    for (int w = 0; w < 12; w++) {
        uint32_t idx = 0;
        for (int b = 0; b < 11; b++) {
            int pos = w * 11 + b;
            idx = (idx << 1) | ((bits[pos >> 3] >> (7 - (pos & 7))) & 1);
        }
        int r = snprintf(out + n, cap - n, "%s%s", w ? " " : "", BIP39_WORDS[idx]);
        if (r < 0 || (size_t)r >= cap - n) { out[cap-1] = 0; return; }
        n += (size_t)r;
    }
}
/* the oracle: is this 132-bit stream a checksum-valid BIP-39 phrase? */
static int bits_valid(const uint8_t bits[17]) {
    uint8_t h[32];
    osha256(bits, 16, h);
    return (bits[16] & 0xF0) == (h[0] & 0xF0);
}

/* ── the official BIP-39 English vectors (128-bit half of the Trezor set) ── */
typedef struct { const char *entropy, *mnemonic, *seed_trezor; } Vec;
static const Vec VECS[] = {
 { "00000000000000000000000000000000",
   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
   "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04" },
 { "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
   "legal winner thank year wave sausage worth useful legal winner thank yellow",
   "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607" },
 { "80808080808080808080808080808080",
   "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
   "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8" },
 { "ffffffffffffffffffffffffffffffff",
   "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
   "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069" },
 { "9e885d952ad362caeb4efe34a8e91bd2",
   "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
   "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028" },
 { "77c2b00716cec7213839159e404db50d",
   "jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge",
   "b5b6d0127db1a9d2226af0c3346031d77af31e918dba64287a1b44b8ebf63cdd52676f672a290aae502472cf2d602c051f3e6f18055e84e4c43897fc4e51a6ff" },
 { "0c1e24e5917779d297e14d45f14e1a1a",
   "army van defense carry jealous true garbage claim echo media make crunch",
   "3338a6d2ee71c7f28eb5b882159634cd46a898463e9d2d0980f8e80dfbba5b0fa0291e5fb888a599b44b93187be6ee3ab5fd3ead7dd646341b2cdb8d08d13bf7" },
};
#define NVECS ((int)(sizeof VECS / sizeof VECS[0]))

/* The empty-passphrase seed for the canonical all-zero-entropy phrase — this
 * is the value published everywhere as the root of the m/44'/…/0 tutorial
 * chain, and it is the ONLY passphrase bip39_seed_from_mnemonic offers. */
static const char *ZERO_SEED_EMPTY_PW =
 "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
 "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

int main(void) {
    char mn[256], name[160];
    uint8_t ent[16], back[16], seed[64], want[64];

    /* ═══ 1. known-answer vectors ═══════════════════════════════════════ */
    printf("-- official BIP-39 English vectors (128-bit) --\n");
    for (int i = 0; i < NVECS; i++) {
        unhex(VECS[i].entropy, ent, 16);

        bip39_mnemonic_from_entropy(ent, mn, sizeof mn);
        snprintf(name, sizeof name, "vector %d: entropy %.8s… → mnemonic", i, VECS[i].entropy);
        CHECK(!strcmp(mn, VECS[i].mnemonic), name);

        memset(back, 0xAA, sizeof back);
        int ok = bip39_entropy_from_mnemonic(VECS[i].mnemonic, back);
        snprintf(name, sizeof name, "vector %d: mnemonic → entropy (checksum accepts)", i);
        CHECK(ok == 1 && !memcmp(back, ent, 16), name);

        /* the KDF stack in THIS build is BIP-39-conformant: recomputing the
         * published TREZOR-passphrase seed must land on the published bytes */
        unhex(VECS[i].seed_trezor, want, 64);
        pbkdf2_seed(VECS[i].mnemonic, "TREZOR", seed);
        snprintf(name, sizeof name, "vector %d: PBKDF2 stack reproduces the published TREZOR seed", i);
        CHECK(!memcmp(seed, want, 64), name);

        /* and bip39.c's seed is that same KDF with the EMPTY passphrase */
        pbkdf2_seed(VECS[i].mnemonic, "", want);
        bip39_seed_from_mnemonic(VECS[i].mnemonic, seed);
        snprintf(name, sizeof name, "vector %d: seed == PBKDF2(mnemonic,\"mnemonic\",2048,SHA512,64)", i);
        CHECK(!memcmp(seed, want, 64), name);
    }
    unhex(ZERO_SEED_EMPTY_PW, want, 64);
    bip39_seed_from_mnemonic(VECS[0].mnemonic, seed);
    CHECK(!memcmp(seed, want, 64),
          "all-zero phrase → the published empty-passphrase 64-byte seed");

    /* the seed must depend on the phrase, and only on the phrase */
    bip39_seed_from_mnemonic(VECS[1].mnemonic, want);
    CHECK(memcmp(seed, want, 64) != 0, "distinct phrases → distinct seeds");
    bip39_seed_from_mnemonic(VECS[0].mnemonic, want);
    CHECK(!memcmp(seed, want, 64), "seed derivation is deterministic");

    /* ═══ 2. wordlist invariants (BIP-39 §wordlist) ═════════════════════ */
    printf("-- wordlist structure --\n");
    {
        int nonnull = 1, sorted = 1, unique = 1, pfx4 = 1, ascii = 1, len_ok = 1;
        for (int i = 0; i < 2048; i++) {
            const char *w = BIP39_WORDS[i];
            if (!w) { nonnull = 0; break; }
            size_t l = strlen(w);
            if (l < 3 || l > 8) len_ok = 0;
            for (size_t k = 0; k < l; k++) if (w[k] < 'a' || w[k] > 'z') ascii = 0;
            if (i) {
                int c = strcmp(BIP39_WORDS[i-1], w);
                if (c >= 0) { sorted = 0; if (c == 0) unique = 0; }
                /* strictly sorted ⇒ a 4-char collision can only be adjacent */
                if (!strncmp(BIP39_WORDS[i-1], w, 4)) pfx4 = 0;
            }
        }
        CHECK(nonnull, "wordlist has 2048 non-NULL entries");
        CHECK(sorted,  "wordlist is strictly ascending (bsearch lookup is sound)");
        CHECK(unique,  "wordlist has no duplicate words");
        CHECK(pfx4,    "wordlist is unique in the first 4 characters");
        CHECK(ascii,   "wordlist is pure lowercase ASCII a-z (no NFKD needed)");
        CHECK(len_ok,  "every word is 3..8 characters");

        /* index ⇄ word is a bijection over the whole 11-bit space */
        int roundtrip = 1;
        for (int i = 0; i < 2048 && roundtrip; i++) {
            uint8_t bits[17];
            memset(bits, 0, sizeof bits);
            for (int b = 0; b < 11; b++) if ((i >> (10 - b)) & 1) bits[b >> 3] |= (uint8_t)(0x80 >> (b & 7));
            uint8_t h[32];
            osha256(bits, 16, h);
            bits[16] = h[0];
            char m[256];
            words_from_bits(bits, m, sizeof m);
            if (strncmp(m, BIP39_WORDS[i], strlen(BIP39_WORDS[i]))) roundtrip = 0;
            if (m[strlen(BIP39_WORDS[i])] != ' ') roundtrip = 0;
            uint8_t e[16];
            if (!bip39_entropy_from_mnemonic(m, e) || memcmp(e, bits, 16)) roundtrip = 0;
        }
        CHECK(roundtrip, "all 2048 word indices encode and decode as themselves");
    }

    /* ═══ 3. property: encode → decode round-trip ═══════════════════════ */
    printf("-- property: entropy round-trip (8000 random 128-bit entropies) --\n");
    {
        int bad_rt = 0, bad_words = 0, bad_len = 0;
        for (int t = 0; t < 8000; t++) {
            rand_bytes(ent, 16);
            memset(mn, 0x7F, sizeof mn);
            bip39_mnemonic_from_entropy(ent, mn, sizeof mn);

            /* exactly 12 space-separated words, every one in the list */
            int nw = 0;
            char copy[256]; snprintf(copy, sizeof copy, "%s", mn);
            for (char *tok = strtok(copy, " "); tok; tok = strtok(NULL, " ")) {
                int found = 0;
                for (int lo = 0, hi = 2047; lo <= hi; ) {
                    int mid = (lo + hi) / 2, c = strcmp(tok, BIP39_WORDS[mid]);
                    if (!c) { found = 1; break; }
                    if (c < 0) hi = mid - 1; else lo = mid + 1;
                }
                if (!found) bad_words++;
                nw++;
            }
            if (nw != 12) bad_len++;

            memset(back, 0, sizeof back);
            if (bip39_entropy_from_mnemonic(mn, back) != 1 || memcmp(back, ent, 16)) bad_rt++;
        }
        CHECK(bad_len == 0,   "every encode produces exactly 12 words");
        CHECK(bad_words == 0, "every emitted word is in the 2048-word list");
        CHECK(bad_rt == 0,    "entropy → mnemonic → entropy is the identity, 8000/8000");
    }

    /* the encoder's checksum nibble agrees with the independent SHA-256 */
    {
        int mismatch = 0;
        for (int t = 0; t < 4000; t++) {
            uint8_t bits[17], h[32];
            rand_bytes(ent, 16);
            osha256(ent, 16, h);
            memcpy(bits, ent, 16);
            bits[16] = h[0];
            char expect[256];
            words_from_bits(bits, expect, sizeof expect);
            bip39_mnemonic_from_entropy(ent, mn, sizeof mn);
            if (strcmp(mn, expect)) mismatch++;
        }
        CHECK(mismatch == 0, "encoder's checksum nibble == OpenSSL SHA-256(entropy)[0] top nibble");
    }

    /* ═══ 4. property: single-bit corruption of the 132-bit stream ══════ */
    printf("-- property: single-bit corruption vs an independent checksum oracle --\n");
    {
        int disagree = 0, cksum_flips = 0, cksum_accepted = 0;
        int ent_flips = 0, ent_accepted = 0, wrong_entropy = 0;
        for (int t = 0; t < 400; t++) {
            uint8_t base[17], h[32];
            rand_bytes(ent, 16);
            osha256(ent, 16, h);
            memcpy(base, ent, 16);
            base[16] = (uint8_t)(h[0] & 0xF0);

            for (int bit = 0; bit < 132; bit++) {
                uint8_t bits[17];
                memcpy(bits, base, 17);
                bits[bit >> 3] ^= (uint8_t)(0x80 >> (bit & 7));

                char m[256];
                words_from_bits(bits, m, sizeof m);
                uint8_t got[16];
                int accepted = bip39_entropy_from_mnemonic(m, got);
                int expect   = bits_valid(bits);
                if (accepted != expect) disagree++;
                if (accepted && memcmp(got, bits, 16)) wrong_entropy++;

                if (bit >= 128) { cksum_flips++; if (accepted) cksum_accepted++; }
                else            { ent_flips++;   if (accepted) ent_accepted++; }
            }
        }
        CHECK(disagree == 0,
              "acceptance matches the independent oracle on all 52800 corruptions");
        CHECK(wrong_entropy == 0,
              "an accepted corruption still decodes to the bits that were sent");
        CHECK(cksum_flips == 1600 && cksum_accepted == 0,
              "every one of the 1600 checksum-bit flips is REJECTED");
        /* 4-bit checksum ⇒ a corrupted entropy bit slips through 1 time in 16.
         * 51200 trials, p=1/16: mean 3200, sd ≈ 54.8 — this band is ±9 sd. */
        CHECK(ent_flips == 51200 && ent_accepted > 2700 && ent_accepted < 3700,
              "entropy-bit flips are caught at the 15/16 rate the checksum allows");
    }

    /* every wrong FINAL word (the word carrying all 4 checksum bits) */
    printf("-- property: all 2047 wrong final words --\n");
    {
        int disagree = 0, accepted = 0;
        uint8_t base[17], h[32];
        unhex(VECS[4].entropy, ent, 16);
        osha256(ent, 16, h);
        memcpy(base, ent, 16);
        base[16] = (uint8_t)(h[0] & 0xF0);
        /* the true index of word 12 = low 7 bits of entropy[15] << 4 | cksum */
        uint32_t true_idx = (uint32_t)((base[15] & 0x7F) << 4) | (uint32_t)(base[16] >> 4);
        for (uint32_t idx = 0; idx < 2048; idx++) {
            if (idx == true_idx) continue;
            uint8_t bits[17];
            memcpy(bits, base, 17);
            bits[15] = (uint8_t)((bits[15] & 0x80) | ((idx >> 4) & 0x7F));
            bits[16] = (uint8_t)((idx & 0x0F) << 4);
            char m[256];
            words_from_bits(bits, m, sizeof m);
            uint8_t got[16];
            int got_ok = bip39_entropy_from_mnemonic(m, got);
            if (got_ok != bits_valid(bits)) disagree++;
            if (got_ok) accepted++;
        }
        CHECK(disagree == 0, "all 2047 alternative final words match the oracle exactly");
        CHECK(accepted > 0 && accepted < 200,
              "only the checksum-consistent minority of wrong final words pass");
        /* and the true one is still accepted */
        char m[256];
        words_from_bits(base, m, sizeof m);
        CHECK(bip39_entropy_from_mnemonic(m, back) == 1, "the correct final word still validates");
    }

    /* ═══ 5. adversarial / edge input ═══════════════════════════════════ */
    printf("-- adversarial decode input --\n");
    {
        uint8_t e[16];
        CHECK(bip39_entropy_from_mnemonic(NULL, e) == 0, "NULL mnemonic rejected");
        CHECK(bip39_entropy_from_mnemonic("", e) == 0, "empty string rejected");
        CHECK(bip39_entropy_from_mnemonic("   \t\r\n  ", e) == 0, "whitespace-only rejected");
        CHECK(bip39_entropy_from_mnemonic("abandon", e) == 0, "1 word rejected");
        CHECK(bip39_entropy_from_mnemonic(
              "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", e) == 0,
              "11 words rejected");
        CHECK(bip39_entropy_from_mnemonic(
              "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", e) == 0,
              "13 words rejected");
        /* the other BIP-39 entropy sizes are out of this API's scope: they must
         * be refused outright, never truncated to their first 12 words */
        CHECK(bip39_entropy_from_mnemonic(
              "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
              "abandon abandon abandon abandon abandon abandon", e) == 0, "15 words (160-bit) rejected");
        CHECK(bip39_entropy_from_mnemonic(
              "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
              "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art", e) == 0,
              "24 words (256-bit) rejected");

        /* wrong checksum, right words */
        CHECK(bip39_entropy_from_mnemonic(
              "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", e) == 0,
              "12 valid words with a bad checksum rejected");
        /* unknown word, and a word sharing a 4-char prefix with a real one */
        CHECK(bip39_entropy_from_mnemonic(
              "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abanxxx", e) == 0,
              "unknown word sharing a 4-char prefix rejected");
        CHECK(bip39_entropy_from_mnemonic(
              "zzzzzz abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", e) == 0,
              "word past the end of the list rejected");
        CHECK(bip39_entropy_from_mnemonic(
              "aaaaaa abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", e) == 0,
              "word before the start of the list rejected");

        /* case folding and separator tolerance are documented behaviour */
        CHECK(bip39_entropy_from_mnemonic(
              "ABANDON Abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ABOUT", e) == 1,
              "uppercase folds to lowercase and validates");
        CHECK(bip39_entropy_from_mnemonic(
              "abandon\tabandon\r\nabandon abandon  abandon   abandon abandon abandon abandon abandon abandon about", e) == 1,
              "tabs / CRLF / runs of spaces collapse");
        CHECK(bip39_entropy_from_mnemonic(
              "  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about  ", e) == 1,
              "leading / trailing whitespace tolerated");

        /* embedded NUL: everything past it is invisible to strlen-based code,
         * so this must read as a 1-word phrase, not as a 12-word one */
        static const char nulled[] =
            "abandon\0abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        CHECK(bip39_entropy_from_mnemonic(nulled, e) == 0, "embedded NUL truncates to 1 word, rejected");

        /* non-ASCII: high bytes are not letters, must not be case-folded into
         * a valid word and must not index out of bounds */
        CHECK(bip39_entropy_from_mnemonic(
              "ábandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", e) == 0,
              "UTF-8 accented word rejected");
        CHECK(bip39_entropy_from_mnemonic(
              "\xff\xfe\xfd\xfc abandon abandon abandon abandon abandon abandon abandon abandon abandon about", e) == 0,
              "raw high bytes rejected");

        /* oversize: 100 KB must fail cleanly, not smash bip39.c's 512-byte buf */
        char *big = malloc(100001);
        memset(big, 'a', 100000); big[100000] = 0;
        CHECK(bip39_entropy_from_mnemonic(big, e) == 0, "100 KB of 'a' rejected without crashing");
        for (int i = 0; i < 100000; i++) big[i] = (i % 8 == 7) ? ' ' : 'a';
        CHECK(bip39_entropy_from_mnemonic(big, e) == 0, "100 KB of unknown words rejected");
        free(big);

        /* a 13-word phrase whose 13th word sits past bip39.c's 512-byte input
         * window: truncation must NOT turn it into an accepted 12-word phrase */
        {
            char pad[1024];
            int n = snprintf(pad, sizeof pad, "%s", VECS[0].mnemonic);
            while (n < 900) pad[n++] = ' ';
            snprintf(pad + n, sizeof pad - (size_t)n, "zoo");
            /* FAILS (see report): bip39.c:53 truncates the input at 511 bytes
             * BEFORE tokenising, so the 13th word falls off and the phrase is
             * accepted as a valid 12-word one. Correct behaviour is rejection. */
            CHECK(bip39_entropy_from_mnemonic(pad, e) == 0,
                  "13th word beyond the 512-byte input window still rejected");
        }

        /* The sharper form of the same truncation. 49 words in the list are
         * proper prefixes of a longer word (act/action, art/artefact, …). If
         * the 512-byte cut lands right after such a prefix, a phrase ending in
         * the LONG word is accepted as the phrase ending in the SHORT one —
         * i.e. a different entropy, a different wallet, no error shown. */
        {
            char head[256], padded[1024], longw[16];
            uint8_t ent2[16];
            int built = 0;
            for (int t = 0; t < 20000 && !built; t++) {
                rand_bytes(ent2, 16);
                bip39_mnemonic_from_entropy(ent2, mn, sizeof mn);
                char *sp = strrchr(mn, ' ');
                if (!sp) continue;
                const char *last = sp + 1;
                size_t ll = strlen(last);
                /* is `last` a proper prefix of the word that follows it? */
                for (int i = 0; i < 2047; i++) {
                    if (strcmp(BIP39_WORDS[i], last)) continue;
                    if (!strncmp(BIP39_WORDS[i+1], last, ll) && strlen(BIP39_WORDS[i+1]) > ll) {
                        snprintf(longw, sizeof longw, "%s", BIP39_WORDS[i+1]);
                        size_t hl = (size_t)(sp - mn) + 1;          /* "w1 … w11 " */
                        snprintf(head, sizeof head, "%.*s", (int)hl, mn);
                        int n = (int)hl;
                        int padlen = 511 - n - (int)ll;             /* cut lands after `last` */
                        if (padlen < 1) break;
                        snprintf(padded, sizeof padded, "%s", head);
                        for (int k = 0; k < padlen; k++) padded[n++] = ' ';
                        snprintf(padded + n, sizeof padded - (size_t)n, "%s", longw);
                        built = 1;
                    }
                    break;
                }
            }
            /* FAILS (see report): same root cause, bip39.c:53 — the phrase the
             * user actually typed ends in `longw`, but only its prefix survives
             * the 512-byte window, so a DIFFERENT wallet is restored silently. */
            CHECK(built && bip39_entropy_from_mnemonic(padded, e) == 0,
                  "a final word split by the 512-byte window is not accepted as its prefix");
        }
    }

    /* ═══ 6. encoder buffer safety ══════════════════════════════════════ */
    printf("-- encode never writes outside cap --\n");
    {
        int overrun = 0, unterminated = 0;
        for (int t = 0; t < 200; t++) {
            rand_bytes(ent, 16);
            for (size_t cap = 0; cap <= 200; cap++) {
                uint8_t arena[320];
                memset(arena, 0x5A, sizeof arena);          /* canary */
                char *out = (char *)arena + 32;
                bip39_mnemonic_from_entropy(ent, out, cap);
                for (int i = 0; i < 32; i++) if (arena[i] != 0x5A) overrun = 1;
                for (size_t i = 32 + cap; i < sizeof arena; i++) if (arena[i] != 0x5A) overrun = 1;
                if (cap > 0 && memchr(out, 0, cap) == NULL) unterminated = 1;
            }
        }
        CHECK(overrun == 0,      "no write outside [out, out+cap) for any cap 0..200");
        CHECK(unterminated == 0, "output is NUL-terminated for every cap > 0");

        /* the documented cap (≥128) always holds a full 12-word phrase */
        int short_out = 0;
        for (int t = 0; t < 2000; t++) {
            rand_bytes(ent, 16);
            char o[128];
            bip39_mnemonic_from_entropy(ent, o, sizeof o);
            uint8_t e2[16];
            if (bip39_entropy_from_mnemonic(o, e2) != 1 || memcmp(e2, ent, 16)) short_out++;
        }
        CHECK(short_out == 0, "the documented 128-byte buffer never truncates a phrase");
    }

    printf("\nt_bip39: %d ok, %d failed\n", g_ok, g_nfail);
    return g_fail;
}
