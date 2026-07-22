// bip39.c — see bip39.h. Checksum uses the engine's SHA-256; the seed stretch
// uses OpenSSL's PBKDF2-HMAC-SHA512 (libcrypto is already linked for the TLS
// proxy). English wordlist only (ASCII, no NFKD normalization needed).
#include "bip39.h"
#include "sha256.h"

#include <openssl/evp.h>

#include <stdlib.h>
#include <string.h>

// ── entropy → mnemonic (128-bit entropy + 4-bit checksum = 12×11 bits) ────────
void bip39_mnemonic_from_entropy(const uint8_t entropy[16], char *out, size_t cap) {
    SHA256_CTX ctx; uint8_t hash[32];
    sha256_init(&ctx); sha256_update(&ctx, entropy, 16); sha256_final(&ctx, hash);

    uint8_t bits[17];
    memcpy(bits, entropy, 16);
    bits[16] = hash[0];                         // only the top 4 bits are used

    char *p = out;
    char *end = out + cap;
    for (int w = 0; w < 12; w++) {
        uint32_t idx = 0;
        for (int b = 0; b < 11; b++) {
            int pos = w * 11 + b;
            idx = (idx << 1) | ((bits[pos >> 3] >> (7 - (pos & 7))) & 1);
        }
        const char *word = BIP39_WORDS[idx];
        size_t wl = strlen(word);
        if (p != out && p < end) *p++ = ' ';
        if (p + wl >= end) break;
        memcpy(p, word, wl); p += wl;
    }
    if (p < end) *p = '\0'; else if (cap) out[cap - 1] = '\0';
}

// ── mnemonic → entropy (reverse lookup + checksum verify) ─────────────────────
static int cmp_word(const void *key, const void *elem) {
    return strcmp((const char *)key, *(const char *const *)elem);
}
static int word_index(const char *w) {
    const char *const *hit = bsearch(w, BIP39_WORDS, 2048,
                                     sizeof BIP39_WORDS[0], cmp_word);
    return hit ? (int)(hit - BIP39_WORDS) : -1;
}

int bip39_entropy_from_mnemonic(const char *mnemonic, uint8_t entropy[16]) {
    if (!mnemonic) return 0;

    char buf[512];
    size_t bl = 0;
    for (const char *p = mnemonic; *p && bl < sizeof buf - 1; p++) {
        char c = *p;
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');   // fold case
        buf[bl++] = c;
    }
    buf[bl] = 0;

    const char *words[13]; int nw = 0;
    char *save = NULL;
    for (char *tok = strtok_r(buf, " \t\r\n", &save); tok; tok = strtok_r(NULL, " \t\r\n", &save)) {
        if (nw >= 13) { nw++; break; }
        words[nw++] = tok;
    }
    if (nw != 12) return 0;

    uint8_t bits[17];
    memset(bits, 0, sizeof bits);
    for (int w = 0; w < 12; w++) {
        int idx = word_index(words[w]);
        if (idx < 0) return 0;                                 // word not in list
        for (int b = 0; b < 11; b++) {
            if ((idx >> (10 - b)) & 1) {
                int pos = w * 11 + b;
                bits[pos >> 3] |= (uint8_t)(0x80 >> (pos & 7));
            }
        }
    }

    memcpy(entropy, bits, 16);
    SHA256_CTX ctx; uint8_t hash[32];
    sha256_init(&ctx); sha256_update(&ctx, entropy, 16); sha256_final(&ctx, hash);
    return (uint8_t)(bits[16] & 0xF0) == (uint8_t)(hash[0] & 0xF0);   // 4-bit checksum
}

// ── mnemonic → 64-byte BIP32 seed ─────────────────────────────────────────────
void bip39_seed_from_mnemonic(const char *mnemonic, uint8_t seed_out[64]) {
    PKCS5_PBKDF2_HMAC(mnemonic, (int)strlen(mnemonic),
                      (const unsigned char *)"mnemonic", 8, 2048,
                      EVP_sha512(), 64, seed_out);
}
