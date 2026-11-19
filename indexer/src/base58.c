// base58.c — see base58.h. Classic big-endian base-256 ↔ base-58 long division.
#include "base58.h"
#include "chain.h"       // idx_sha256d
#include <string.h>

static const char *ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int idx_b58check_encode(uint8_t version, const uint8_t *payload, size_t n,
                        char *out, size_t out_max) {
    uint8_t buf[64];
    if (n + 5 > sizeof buf) return 0;
    buf[0] = version;
    memcpy(buf + 1, payload, n);
    uint8_t ck[32]; idx_sha256d(buf, n + 1, ck);
    memcpy(buf + 1 + n, ck, 4);
    size_t blen = n + 5;

    char tmp[96]; size_t tn = 0;
    size_t zeros = 0; while (zeros < blen && buf[zeros] == 0) zeros++;
    uint8_t num[64]; memcpy(num, buf, blen);
    size_t start = zeros;
    while (start < blen) {                       // repeated ÷58, remainders = digits
        unsigned rem = 0;
        for (size_t i = start; i < blen; i++) {
            unsigned v = rem * 256 + num[i];
            num[i] = (uint8_t)(v / 58);
            rem = v % 58;
        }
        if (tn >= sizeof tmp) return 0;
        tmp[tn++] = ALPHA[rem];
        while (start < blen && num[start] == 0) start++;
    }
    if (zeros + tn + 1 > out_max) return 0;
    size_t o = 0;
    for (size_t i = 0; i < zeros; i++) out[o++] = '1';
    while (tn) out[o++] = tmp[--tn];
    out[o] = 0;
    return 1;
}

static int b58val(char c) {
    const char *p = strchr(ALPHA, c);
    return (c && p) ? (int)(p - ALPHA) : -1;
}

int idx_b58check_decode(const char *s, uint8_t *version,
                        uint8_t *payload, size_t payload_max, size_t *payload_len) {
    uint8_t num[64]; size_t blen = 0;
    size_t zeros = 0; while (s[zeros] == '1') zeros++;
    for (const char *p = s; *p; p++) {           // ×58 + digit accumulate
        int d = b58val(*p); if (d < 0) return 0;
        unsigned carry = (unsigned)d;
        for (size_t i = 0; i < blen; i++) {
            unsigned v = num[blen - 1 - i] * 58u + carry;
            num[blen - 1 - i] = (uint8_t)(v & 0xff);
            carry = v >> 8;
        }
        while (carry) {
            if (blen >= sizeof num) return 0;
            memmove(num + 1, num, blen++);
            num[0] = (uint8_t)(carry & 0xff);
            carry >>= 8;
        }
    }
    // leading '1's = leading zero bytes (beyond what the arithmetic produced)
    uint8_t full[64]; size_t flen = zeros + blen;
    if (flen > sizeof full || flen < 5) return 0;
    memset(full, 0, zeros); memcpy(full + zeros, num, blen);
    uint8_t ck[32]; idx_sha256d(full, flen - 4, ck);
    if (memcmp(ck, full + flen - 4, 4) != 0) return 0;
    size_t plen = flen - 5;
    if (plen > payload_max) return 0;
    *version = full[0];
    memcpy(payload, full + 1, plen);
    *payload_len = plen;
    return 1;
}
