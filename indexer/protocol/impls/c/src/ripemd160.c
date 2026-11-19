// RIPEMD-160 (Dobbertin–Bosselaers–Preneel), compact public-domain-style impl.
#include "ripemd160.h"
#include <string.h>

static uint32_t rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

#define F1(x, y, z) ((x) ^ (y) ^ (z))
#define F2(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define F3(x, y, z) (((x) | ~(y)) ^ (z))
#define F4(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define F5(x, y, z) ((x) ^ ((y) | ~(z)))

static void compress(uint32_t h[5], const uint8_t block[64]) {
    uint32_t X[16];
    for (int i = 0; i < 16; i++)
        X[i] = (uint32_t)block[4*i] | ((uint32_t)block[4*i+1] << 8) |
               ((uint32_t)block[4*i+2] << 16) | ((uint32_t)block[4*i+3] << 24);

    // message word selection (left line / right line)
    static const int rl[80] = {
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
        7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
        3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
        1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
        4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13 };
    static const int rr[80] = {
        5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
        6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
        15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
        8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
        12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11 };
    static const int sl[80] = {
        11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
        7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
        11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
        11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
        9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6 };
    static const int sr[80] = {
        8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
        9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
        9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
        15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
        8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11 };
    static const uint32_t KL[5] = {0x00000000,0x5A827999,0x6ED9EBA1,0x8F1BBCDC,0xA953FD4E};
    static const uint32_t KR[5] = {0x50A28BE6,0x5C4DD124,0x6D703EF3,0x7A6D76E9,0x00000000};

    uint32_t al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
    uint32_t ar = h[0], br = h[1], cr = h[2], dr = h[3], er = h[4];
    for (int j = 0; j < 80; j++) {
        int rnd = j / 16;
        uint32_t t;
        uint32_t fl, fr;
        switch (rnd) {
            case 0: fl = F1(bl,cl,dl); fr = F5(br,cr,dr); break;
            case 1: fl = F2(bl,cl,dl); fr = F4(br,cr,dr); break;
            case 2: fl = F3(bl,cl,dl); fr = F3(br,cr,dr); break;
            case 3: fl = F4(bl,cl,dl); fr = F2(br,cr,dr); break;
            default: fl = F5(bl,cl,dl); fr = F1(br,cr,dr); break;
        }
        t = rol(al + fl + X[rl[j]] + KL[rnd], sl[j]) + el;
        al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = t;
        t = rol(ar + fr + X[rr[j]] + KR[rnd], sr[j]) + er;
        ar = er; er = dr; dr = rol(cr, 10); cr = br; br = t;
    }
    uint32_t tmp = h[1] + cl + dr;
    h[1] = h[2] + dl + er;
    h[2] = h[3] + el + ar;
    h[3] = h[4] + al + br;
    h[4] = h[0] + bl + cr;
    h[0] = tmp;
}

void ripemd160(const uint8_t *msg, size_t len, uint8_t out[20]) {
    uint32_t h[5] = {0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0};
    size_t i = 0;
    uint8_t block[64];
    while (len - i >= 64) { compress(h, msg + i); i += 64; }

    size_t rem = len - i;
    memset(block, 0, 64);
    memcpy(block, msg + i, rem);
    block[rem] = 0x80;
    if (rem >= 56) { compress(h, block); memset(block, 0, 64); }
    uint64_t bits = (uint64_t)len * 8;
    for (int k = 0; k < 8; k++) block[56 + k] = (uint8_t)(bits >> (8 * k));
    compress(h, block);

    for (int k = 0; k < 5; k++) {
        out[4*k]   = (uint8_t)(h[k]);
        out[4*k+1] = (uint8_t)(h[k] >> 8);
        out[4*k+2] = (uint8_t)(h[k] >> 16);
        out[4*k+3] = (uint8_t)(h[k] >> 24);
    }
}
