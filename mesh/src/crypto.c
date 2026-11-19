// crypto.c — facade over the audited primitives. Hashes = protocol-sm's byte-
// locked SHA-256/RIPEMD-160; curve ops = vendored libsecp256k1 via secp_shim.c.
// Base58Check is self-contained here (over the linked SHA-256) so the network lib
// carries no indexer dependency.
#include "pepenet/crypto.h"

#include <string.h>

#include "sha256.h"        // protocol-sm (quoted include; -I .../protocol/impls/c/src)
#include "ripemd160.h"
#include "secp256k1.h"     // protocol-sm's secp_* interface (NOT the vendored header)

// ── hashes ───────────────────────────────────────────────────────────────────
void sp_sha256(const uint8_t *d, size_t n, uint8_t out[32]) {
    SHA256_CTX c; sha256_init(&c); sha256_update(&c, d, (unsigned)n); sha256_final(&c, out);
}

void sp_sha256d(const uint8_t *d, size_t n, uint8_t out[32]) {
    uint8_t t[32]; sp_sha256(d, n, t); sp_sha256(t, 32, out);
}

void sp_hash160(const uint8_t *d, size_t n, uint8_t out[20]) {
    uint8_t t[32]; sp_sha256(d, n, t); ripemd160(t, 32, out);
}

// ── secp256k1 ────────────────────────────────────────────────────────────────
int sp_pubkey(const uint8_t priv[32], uint8_t pub33[33]) {
    return secp_pubkey(priv, pub33);
}

int sp_ecdsa_sign(const uint8_t priv[32], const uint8_t digest[32], uint8_t sig64[64]) {
    return secp_ecdsa_sign(priv, digest, sig64, sig64 + 32);
}

int sp_ecdsa_verify(const uint8_t digest[32], const uint8_t sig64[64],
                    const uint8_t *pub, int publen) {
    if (!secp_on_curve(pub, publen)) return 0;
    return secp_ecdsa_verify(digest, sig64, sig64 + 32, pub, publen);
}

int sp_key_is_owner(const uint8_t *pub, int publen, const uint8_t owner[20]) {
    uint8_t h[20]; sp_hash160(pub, (size_t)publen, h);
    return memcmp(h, owner, 20) == 0;
}

// ── §3.1 name validation (mirrors protocol-sm sm_name_valid) ─────────────────
int sp_name_valid(const char *name, size_t len) {
    if (!name || len < 1 || len > SP_NAME_MAX) return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)name[i];
        // charset: [a-z0-9-] — a DNS label, lowercased. reject, never fold.
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return 0;
    }
    // structural (RFC-1123 / IDNA): no leading/trailing hyphen; no `--` at 3–4
    // (kills xn-- and every ACE prefix).
    if (name[0] == '-' || name[len - 1] == '-') return 0;
    if (len >= 4 && name[2] == '-' && name[3] == '-') return 0;
    return 1;
}

// ── Base58Check ──────────────────────────────────────────────────────────────
static const char B58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int sp_addr_encode(uint8_t version, const uint8_t *payload, size_t n,
                   char *out, size_t out_max) {
    uint8_t buf[128];
    if (n + 1 + 4 > sizeof buf) return 0;
    buf[0] = version;
    memcpy(buf + 1, payload, n);
    uint8_t ck[32]; sp_sha256d(buf, n + 1, ck);
    memcpy(buf + 1 + n, ck, 4);
    size_t blen = n + 1 + 4;

    // count leading zero bytes → leading '1's
    size_t zeros = 0;
    while (zeros < blen && buf[zeros] == 0) zeros++;

    uint8_t tmp[256]; size_t tlen = 0;
    for (size_t i = zeros; i < blen; i++) {
        int carry = buf[i];
        for (size_t j = 0; j < tlen; j++) { carry += tmp[j] << 8; tmp[j] = (uint8_t)(carry % 58); carry /= 58; }
        while (carry) { if (tlen >= sizeof tmp) return 0; tmp[tlen++] = (uint8_t)(carry % 58); carry /= 58; }
    }
    if (zeros + tlen + 1 > out_max) return 0;
    size_t o = 0;
    for (size_t i = 0; i < zeros; i++) out[o++] = '1';
    for (size_t i = 0; i < tlen; i++) out[o++] = B58[tmp[tlen - 1 - i]];
    out[o] = '\0';
    return 1;
}

static int b58val(char c) {
    for (int i = 0; i < 58; i++) if (B58[i] == c) return i;
    return -1;
}

int sp_addr_decode(const char *s, uint8_t *version,
                   uint8_t *payload, size_t payload_max, size_t *payload_len) {
    size_t slen = strlen(s);
    size_t zeros = 0;
    while (zeros < slen && s[zeros] == '1') zeros++;

    uint8_t tmp[256]; size_t tlen = 0;
    for (size_t i = zeros; i < slen; i++) {
        int v = b58val(s[i]);
        if (v < 0) return 0;
        int carry = v;
        for (size_t j = 0; j < tlen; j++) { carry += tmp[j] * 58; tmp[j] = (uint8_t)(carry & 0xFF); carry >>= 8; }
        while (carry) { if (tlen >= sizeof tmp) return 0; tmp[tlen++] = (uint8_t)(carry & 0xFF); carry >>= 8; }
    }
    size_t flen = zeros + tlen;                 // full = version+payload+checksum
    if (flen < 5) return 0;
    uint8_t full[256];
    if (flen > sizeof full) return 0;
    for (size_t i = 0; i < zeros; i++) full[i] = 0;
    for (size_t i = 0; i < tlen; i++) full[zeros + i] = tmp[tlen - 1 - i];

    uint8_t ck[32]; sp_sha256d(full, flen - 4, ck);
    if (memcmp(ck, full + flen - 4, 4) != 0) return 0;

    size_t plen = flen - 5;                     // minus version(1) + checksum(4)
    if (plen > payload_max) return 0;
    *version = full[0];
    memcpy(payload, full + 1, plen);
    *payload_len = plen;
    return 1;
}
