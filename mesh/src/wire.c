// wire.c — CompactSize + LE codec. Byte-compatible with the namespace protocol's
// vp_wvar/vp_rvar (impls/c/src/vpost_core.c) and Dogecoin's CompactSize, so an
// overlay frame and its on-chain form are the same bytes.
#include "pepenet/wire.h"

int sp_wvar(uint8_t *o, uint64_t v) {
    if (v < 0xFD)            { o[0] = (uint8_t)v; return 1; }
    if (v <= 0xFFFF)         { o[0] = 0xFD; o[1] = (uint8_t)v; o[2] = (uint8_t)(v >> 8); return 3; }
    if (v <= 0xFFFFFFFFULL)  { o[0] = 0xFE; for (int i = 0; i < 4; i++) o[1 + i] = (uint8_t)(v >> (8 * i)); return 5; }
    o[0] = 0xFF; for (int i = 0; i < 8; i++) o[1 + i] = (uint8_t)(v >> (8 * i));
    return 9;
}

int sp_rvar(const uint8_t *c, int len, int *off, uint64_t *v) {
    if (*off < 0 || *off >= len) return 0;
    // remaining is >= 1 here; compare by subtraction so `*off + n` can never
    // overflow int for a caller that hands us a large offset.
    int remaining = len - *off;
    uint8_t b = c[*off];
    if (b < 0xFD)  { *v = b; *off += 1; return 1; }
    if (b == 0xFD) {
        if (remaining < 3) return 0;
        uint64_t y = (uint64_t)c[*off + 1] | ((uint64_t)c[*off + 2] << 8);
        if (y < 0xFD) return 0;          /* non-minimal: must have used 1 byte */
        *v = y; *off += 3; return 1;
    }
    if (b == 0xFE) {
        if (remaining < 5) return 0;
        uint64_t x = 0; for (int i = 0; i < 4; i++) x |= (uint64_t)c[*off + 1 + i] << (8 * i);
        if (x <= 0xFFFF) return 0;       /* non-minimal: must have used the 3-byte form */
        *v = x; *off += 5; return 1;
    }
    if (remaining < 9) return 0;
    uint64_t x = 0; for (int i = 0; i < 8; i++) x |= (uint64_t)c[*off + 1 + i] << (8 * i);
    if (x <= 0xFFFFFFFFULL) return 0;    /* non-minimal: must have used the 5-byte form */
    *v = x; *off += 9; return 1;
}

int sp_wle32(uint8_t *o, uint32_t v) {
    for (int i = 0; i < 4; i++) o[i] = (uint8_t)(v >> (8 * i));
    return 4;
}

uint32_t sp_rle32(const uint8_t *c) {
    return (uint32_t)c[0] | ((uint32_t)c[1] << 8) | ((uint32_t)c[2] << 16) | ((uint32_t)c[3] << 24);
}
