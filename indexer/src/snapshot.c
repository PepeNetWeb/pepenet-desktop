// snapshot.c — see snapshot.h.
#include "snapshot.h"
#include "pow.h"
#include "chain.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sha256.h"

static int rd_varint(const uint8_t *b, size_t len, size_t *o, uint64_t *v) {
    if (*o >= len) return 0;
    uint8_t c = b[(*o)++];
    int n = c == 0xFD ? 2 : c == 0xFE ? 4 : c == 0xFF ? 8 : 0;
    if (!n) { *v = c; return 1; }
    if (*o + (size_t)n > len) return 0;
    uint64_t x = 0; for (int i = 0; i < n; i++) x |= (uint64_t)b[*o + i] << (8 * i);
    *o += (size_t)n; *v = x; return 1;
}
static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

int idx_snap_walk(IdxSnapWalk *w, const uint8_t *buf, size_t len, char *why, size_t cap) {
    PowParams pp = { w->powlimit, w->aux_chain_id };
    size_t o = 0;
    while (o < len) {
        uint64_t cnt;
        if (!rd_varint(buf, len, &o, &cnt)) { snprintf(why, cap, "truncated headers count"); return 0; }
        for (uint64_t i = 0; i < cnt; i++) {
            if (o + 80 > len) { snprintf(why, cap, "header %lld truncated", (long long)(w->h + 1)); return 0; }
            const uint8_t *hdr = buf + o;
            if (memcmp(hdr + 4, w->hash, 32) != 0) {
                snprintf(why, cap, "header %lld does not link to %lld", (long long)(w->h + 1), (long long)w->h); return 0; }
            size_t span = 80;
            if (w->check_pow) {
                if (!idx_pow_check2(hdr, len - o, &pp, &span, why, cap)) return 0;
                uint32_t bits = le32(hdr + 72);
                if (w->bits && w->time && w->prev_time) {
                    uint32_t want = idx_pow_next_bits(w->bits, w->time, w->prev_time, w->powlimit);
                    if (bits != want) {
                        snprintf(why, cap, "nBits 0x%08x != Digishield 0x%08x at %lld", bits, want, (long long)(w->h + 1));
                        return 0; }
                }
                uint8_t wk[32]; idx_pow_work(bits, wk); idx_pow_work_add(w->work, wk);
            }
            idx_sha256d(hdr, 80, w->hash);
            w->prev_time = w->time; w->time = le32(hdr + 68); w->bits = le32(hdr + 72);
            w->h++; w->n++;
            o += span;
            uint64_t tc;
            if (!rd_varint(buf, len, &o, &tc)) { snprintf(why, cap, "truncated tx count"); return 0; }
            if (tc != 0) { snprintf(why, cap, "non-zero tx count in headers"); return 0; }
        }
        if (cnt == 0) { snprintf(why, cap, "empty headers page"); return 0; }
    }
    return 1;
}

// ── idx-04 pin ───────────────────────────────────────────────────────────────
const char *idx_snap_default_pin(const char *coin) {
    const char *p = NULL;
    if (coin && (!strcmp(coin, "pep") || !strcmp(coin, "pepe"))) p = IDX_SNAPSHOT_PIN_PEP;
    else if (coin && !strcmp(coin, "doge")) p = IDX_SNAPSHOT_PIN_DOGE;
    return p && *p ? p : NULL;
}
const char *idx_snap_effective_pin(const char *coin, const char *flag_hex) {
    return flag_hex ? flag_hex : idx_snap_default_pin(coin);
}
static int hexv(char c) {
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 :
           c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}
int idx_snap_parse_pin(const char *hex, uint8_t out[32]) {
    if (!hex || strlen(hex) != 64) return 0;
    for (int i = 0; i < 32; i++) {
        int a = hexv(hex[2*i]), b = hexv(hex[2*i+1]);
        if (a < 0 || b < 0) return 0;
        out[i] = (uint8_t)(a << 4 | b);
    }
    return 1;
}
int idx_snap_file_sha256(const char *path, uint8_t out[32], int64_t *size) {
    FILE *f = fopen(path, "rb"); if (!f) return 0;
    SHA256_CTX c; sha256_init(&c);
    uint8_t buf[65536]; size_t n; int64_t tot = 0;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) { sha256_update(&c, buf, n); tot += (int64_t)n; }
    int err = ferror(f); fclose(f);
    if (err) return 0;
    sha256_final(&c, out); if (size) *size = tot; return 1;
}
int idx_snap_pin_check(const char *path, const char *pin_hex, char *why, size_t cap) {
    uint8_t want[32], got[32]; int64_t sz = 0;
    if (!pin_hex) { snprintf(why, cap, "no snapshot pin (no --snapshot-sha256 and no compiled default)"); return 0; }
    if (!idx_snap_parse_pin(pin_hex, want)) { snprintf(why, cap, "malformed snapshot pin (need 64 hex digits)"); return 0; }
    if (!idx_snap_file_sha256(path, got, &sz)) { snprintf(why, cap, "cannot read %s", path); return 0; }
    if (memcmp(want, got, 32)) {
        static const char *H = "0123456789abcdef"; char gh[65];
        for (int i = 0; i < 32; i++) { gh[2*i] = H[got[i] >> 4]; gh[2*i+1] = H[got[i] & 15]; }
        gh[64] = 0;
        snprintf(why, cap, "sha256 mismatch: file %s (%lld bytes) has %s", path, (long long)sz, gh);
        return 0;
    }
    snprintf(why, cap, "sha256 pin matches");
    return 1;
}
