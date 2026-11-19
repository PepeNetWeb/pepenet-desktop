// §4 Strategy B — real secp256k1 (self-rolled; see secp256k1.h).
//
// Layout:
//   • field arithmetic mod p (4×64-bit limbs, fast fold-reduction)
//   • Jacobian point ops + double-and-add scalar multiply
//   • pubkey decode / on-curve / decompress
//   • scalar arithmetic mod n (binary-egcd inverse; schoolbook mulmod)
//   • HMAC-SHA256 + RFC-6979 nonce + ECDSA sign/verify
//   • constants KAT (secp_selftest)
//
// Correctness, not speed, is the goal; nothing here is constant time.
#include "secp256k1.h"
#include "sha256.h"

#include <string.h>
#include <stdio.h>

typedef unsigned __int128 u128;

// ── field element: value = v[0] + v[1]·2^64 + v[2]·2^128 + v[3]·2^192, in [0,p) ──
typedef struct { uint64_t v[4]; } fe;

// p = 2^256 − 2^32 − 977 ; little-endian limbs.
static const fe FE_P = {{ 0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
                          0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL }};
static const uint64_t FE_C = 0x1000003D1ULL;   // 2^256 mod p = 2^32 + 977

// n (group order) and G, as big-endian byte constants (KAT-pinned in selftest).
static const uint8_t SECP_N_BE[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41 };
static const uint8_t SECP_N_HALF_BE[32] = {
    0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0 };
static const uint8_t SECP_GX_BE[32] = {
    0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,0x07,
    0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98 };
static const uint8_t SECP_GY_BE[32] = {
    0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,0x08,0xA8,
    0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,0xD4,0xB8 };

// ── 256-bit helpers (limb arrays, little-endian) ──────────────────────────────
static void be32_to_limbs(const uint8_t b[32], uint64_t out[4]) {
    for (int i = 0; i < 4; i++) {
        uint64_t w = 0;
        for (int j = 0; j < 8; j++) w = (w << 8) | b[i * 8 + j];
        out[3 - i] = w;                                   // b[0..7] = most significant
    }
}
static void limbs_to_be32(const uint64_t in[4], uint8_t b[32]) {
    for (int i = 0; i < 4; i++) {
        uint64_t w = in[3 - i];
        for (int j = 0; j < 8; j++) b[i * 8 + j] = (uint8_t)(w >> (56 - 8 * j));
    }
}
static int limb_cmp(const uint64_t a[4], const uint64_t b[4]) {  // -1/0/1
    for (int i = 3; i >= 0; i--) if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}
static int limb_is_zero(const uint64_t a[4]) { return (a[0]|a[1]|a[2]|a[3]) == 0; }

// ── field arithmetic mod p ────────────────────────────────────────────────────
static int fe_is_zero(const fe *a) { return limb_is_zero(a->v); }
static int fe_eq(const fe *a, const fe *b) { return limb_cmp(a->v, b->v) == 0; }
static int fe_is_odd(const fe *a) { return (int)(a->v[0] & 1); }

static void fe_cond_sub_p(fe *a) {                        // while a>=p: a-=p
    while (limb_cmp(a->v, FE_P.v) >= 0) {
        u128 borrow = 0;
        for (int i = 0; i < 4; i++) {
            u128 x = (u128)a->v[i] - FE_P.v[i] - borrow;
            a->v[i] = (uint64_t)x; borrow = (x >> 64) & 1;
        }
    }
}
static void fe_add(fe *r, const fe *a, const fe *b) {
    u128 carry = 0;
    for (int i = 0; i < 4; i++) { u128 x = (u128)a->v[i] + b->v[i] + carry; r->v[i] = (uint64_t)x; carry = x >> 64; }
    if (carry) {                                          // overflow past 2^256: fold C
        u128 c = (u128)FE_C * (uint64_t)carry;
        u128 x = (u128)r->v[0] + (uint64_t)c; r->v[0] = (uint64_t)x; uint64_t cc = (uint64_t)(x >> 64);
        x = (u128)r->v[1] + (uint64_t)(c >> 64) + cc; r->v[1] = (uint64_t)x; cc = (uint64_t)(x >> 64);
        x = (u128)r->v[2] + cc; r->v[2] = (uint64_t)x; cc = (uint64_t)(x >> 64);
        x = (u128)r->v[3] + cc; r->v[3] = (uint64_t)x;
    }
    fe_cond_sub_p(r);
}
static void fe_sub(fe *r, const fe *a, const fe *b) {     // a-b mod p
    u128 borrow = 0;
    for (int i = 0; i < 4; i++) { u128 x = (u128)a->v[i] - b->v[i] - borrow; r->v[i] = (uint64_t)x; borrow = (x >> 64) & 1; }
    if (borrow) {                                         // add p back
        u128 carry = 0;
        for (int i = 0; i < 4; i++) { u128 x = (u128)r->v[i] + FE_P.v[i] + carry; r->v[i] = (uint64_t)x; carry = x >> 64; }
    }
}
// reduce an 8-limb (512-bit) product mod p.
static void fe_reduce(uint64_t t[8], fe *r) {
    uint64_t low[5] = { t[0], t[1], t[2], t[3], 0 };
    u128 carry = 0;
    for (int i = 0; i < 4; i++) {                         // low += high·C
        u128 x = (u128)t[4 + i] * FE_C + low[i] + carry;
        low[i] = (uint64_t)x; carry = x >> 64;
    }
    low[4] += (uint64_t)carry;
    while (low[4]) {                                      // fold the 5th limb back
        uint64_t h = low[4]; low[4] = 0;
        u128 c = (u128)h * FE_C;
        u128 x = (u128)low[0] + (uint64_t)c; low[0] = (uint64_t)x; uint64_t cc = (uint64_t)(x >> 64);
        x = (u128)low[1] + (uint64_t)(c >> 64) + cc; low[1] = (uint64_t)x; cc = (uint64_t)(x >> 64);
        x = (u128)low[2] + cc; low[2] = (uint64_t)x; cc = (uint64_t)(x >> 64);
        x = (u128)low[3] + cc; low[3] = (uint64_t)x; cc = (uint64_t)(x >> 64);
        low[4] = cc;
    }
    r->v[0] = low[0]; r->v[1] = low[1]; r->v[2] = low[2]; r->v[3] = low[3];
    fe_cond_sub_p(r);
}
static void fe_mul(fe *r, const fe *a, const fe *b) {
    uint64_t t[8] = {0,0,0,0,0,0,0,0};
    for (int i = 0; i < 4; i++) {
        u128 carry = 0;
        for (int j = 0; j < 4; j++) {
            u128 x = (u128)a->v[i] * b->v[j] + t[i + j] + carry;
            t[i + j] = (uint64_t)x; carry = x >> 64;
        }
        t[i + 4] += (uint64_t)carry;
    }
    fe_reduce(t, r);
}
static void fe_sqr(fe *r, const fe *a) { fe_mul(r, a, a); }
static void fe_set_u64(fe *r, uint64_t x) { r->v[0] = x; r->v[1] = r->v[2] = r->v[3] = 0; }

// r = a^exp mod p, exp as 32 big-endian bytes.
static void fe_pow(fe *r, const fe *a, const uint8_t exp_be[32]) {
    fe acc; fe_set_u64(&acc, 1);
    for (int byte = 0; byte < 32; byte++) {
        for (int bit = 7; bit >= 0; bit--) {
            fe_sqr(&acc, &acc);
            if ((exp_be[byte] >> bit) & 1) fe_mul(&acc, &acc, a);
        }
    }
    *r = acc;
}
static void fe_inv(fe *r, const fe *a) {                  // a^(p-2)
    static const uint8_t P_MINUS_2[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2D };
    fe_pow(r, a, P_MINUS_2);
}
static void fe_sqrt(fe *r, const fe *a) {                 // a^((p+1)/4); p≡3 mod 4
    static const uint8_t P_PLUS_1_DIV4[32] = {
        0x3F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xBF,0xFF,0xFF,0x0C };
    fe_pow(r, a, P_PLUS_1_DIV4);
}

// ── points (Jacobian: affine = (X/Z^2, Y/Z^3); Z==0 ⇒ infinity) ──────────────
typedef struct { fe X, Y, Z; int inf; } jac;

static void jac_set_inf(jac *p) { p->inf = 1; fe_set_u64(&p->X, 1); fe_set_u64(&p->Y, 1); fe_set_u64(&p->Z, 0); }

static void jac_double(jac *r, const jac *p) {
    if (p->inf || fe_is_zero(&p->Y)) { jac_set_inf(r); return; }
    fe A, B, C, D, E, F, t, t2, X3, Y3, Z3;
    fe_sqr(&A, &p->X);                                    // A = X^2
    fe_sqr(&B, &p->Y);                                    // B = Y^2
    fe_sqr(&C, &B);                                       // C = B^2
    fe_add(&t, &p->X, &B); fe_sqr(&t, &t);                // (X+B)^2
    fe_sub(&t, &t, &A); fe_sub(&t, &t, &C);              // (X+B)^2 - A - C
    fe_add(&D, &t, &t);                                   // D = 2·(...)
    fe_add(&E, &A, &A); fe_add(&E, &E, &A);              // E = 3A
    fe_sqr(&F, &E);                                       // F = E^2
    fe_sub(&X3, &F, &D); fe_sub(&X3, &X3, &D);           // X3 = F - 2D
    fe_sub(&t, &D, &X3); fe_mul(&t, &E, &t);            // E·(D - X3)
    fe_add(&t2, &C, &C); fe_add(&t2, &t2, &t2); fe_add(&t2, &t2, &t2); // 8C
    fe_sub(&Y3, &t, &t2);                                 // Y3 = E·(D-X3) - 8C
    fe_mul(&Z3, &p->Y, &p->Z); fe_add(&Z3, &Z3, &Z3);   // Z3 = 2·Y·Z   (read p->Y/Z before write)
    r->X = X3; r->Y = Y3; r->Z = Z3; r->inf = 0;
}
static void jac_add(jac *r, const jac *p, const jac *q) {
    if (p->inf) { *r = *q; return; }
    if (q->inf) { *r = *p; return; }
    fe Z1Z1, Z2Z2, U1, U2, S1, S2, H, R, t, t2, X3, Y3, Z3;
    fe_sqr(&Z1Z1, &p->Z); fe_sqr(&Z2Z2, &q->Z);
    fe_mul(&U1, &p->X, &Z2Z2); fe_mul(&U2, &q->X, &Z1Z1);
    fe_mul(&S1, &p->Y, &q->Z); fe_mul(&S1, &S1, &Z2Z2);  // S1 = Y1·Z2^3
    fe_mul(&S2, &q->Y, &p->Z); fe_mul(&S2, &S2, &Z1Z1);  // S2 = Y2·Z1^3
    if (fe_eq(&U1, &U2)) {
        if (!fe_eq(&S1, &S2)) { jac_set_inf(r); return; } // P + (−P)
        jac_double(r, p); return;                         // P == Q
    }
    fe_sub(&H, &U2, &U1); fe_sub(&R, &S2, &S1);
    fe HH, HHH, V;
    fe_sqr(&HH, &H); fe_mul(&HHH, &H, &HH); fe_mul(&V, &U1, &HH);
    fe_sqr(&t, &R); fe_sub(&t, &t, &HHH);
    fe_add(&t2, &V, &V); fe_sub(&X3, &t, &t2);          // X3 = R^2 - HHH - 2V
    fe_sub(&t, &V, &X3); fe_mul(&t, &R, &t);
    fe_mul(&t2, &S1, &HHH); fe_sub(&Y3, &t, &t2);       // Y3 = R·(V-X3) - S1·HHH
    fe_mul(&t, &p->Z, &q->Z); fe_mul(&Z3, &t, &H);      // Z3 = Z1·Z2·H
    r->X = X3; r->Y = Y3; r->Z = Z3; r->inf = 0;
}
// R = scalar·P, scalar as 32 big-endian bytes (double-and-add, MSB first).
static void jac_mul(jac *r, const jac *p, const uint8_t k_be[32]) {
    jac acc; jac_set_inf(&acc);
    for (int byte = 0; byte < 32; byte++) {
        for (int bit = 7; bit >= 0; bit--) {
            jac_double(&acc, &acc);
            if ((k_be[byte] >> bit) & 1) jac_add(&acc, &acc, p);
        }
    }
    *r = acc;
}
// affine X,Y from a non-infinity Jacobian point.
static int jac_affine(const jac *p, fe *x, fe *y) {
    if (p->inf || fe_is_zero(&p->Z)) return 0;
    fe zinv, zinv2, zinv3;
    fe_inv(&zinv, &p->Z); fe_sqr(&zinv2, &zinv); fe_mul(&zinv3, &zinv2, &zinv);
    fe_mul(x, &p->X, &zinv2); fe_mul(y, &p->Y, &zinv3);
    return 1;
}
static void jac_from_affine(jac *p, const fe *x, const fe *y) {
    p->X = *x; p->Y = *y; fe_set_u64(&p->Z, 1); p->inf = 0;
}
static void secp_G(jac *g) {
    fe gx, gy;
    be32_to_limbs(SECP_GX_BE, gx.v); be32_to_limbs(SECP_GY_BE, gy.v);
    jac_from_affine(g, &gx, &gy);
}

// ── pubkey decode + on-curve ──────────────────────────────────────────────────
static int fe_from_be_lt_p(const uint8_t b[32], fe *r) {  // load, require < p
    be32_to_limbs(b, r->v);
    return limb_cmp(r->v, FE_P.v) < 0;
}
static void rhs_curve(fe *out, const fe *x) {             // x^3 + 7
    fe x2, x3, seven;
    fe_sqr(&x2, x); fe_mul(&x3, &x2, x);
    fe_set_u64(&seven, 7); fe_add(out, &x3, &seven);
}
// decode to affine point; returns 1 iff on curve (and parity-consistent for 03/02).
static int pub_decode(const uint8_t *pub, int plen, fe *x, fe *y) {
    if (plen == 33 && (pub[0] == 0x02 || pub[0] == 0x03)) {
        if (!fe_from_be_lt_p(pub + 1, x)) return 0;
        fe rhs, beta, beta2;
        rhs_curve(&rhs, x);
        fe_sqrt(&beta, &rhs);
        fe_sqr(&beta2, &beta);
        if (!fe_eq(&beta2, &rhs)) return 0;               // not a quadratic residue ⇒ off curve
        int want_odd = (pub[0] == 0x03);
        if (fe_is_odd(&beta) != want_odd) fe_sub(&beta, &FE_P, &beta);
        *y = beta; return 1;
    }
    if (plen == 65 && pub[0] == 0x04) {
        if (!fe_from_be_lt_p(pub + 1, x)) return 0;
        if (!fe_from_be_lt_p(pub + 33, y)) return 0;
        fe rhs, y2;
        rhs_curve(&rhs, x); fe_sqr(&y2, y);
        return fe_eq(&y2, &rhs);
    }
    return 0;
}
int secp_on_curve(const uint8_t *pub, int plen) {
    fe x, y; return pub_decode(pub, plen, &x, &y);
}

// ── scalar arithmetic mod n ───────────────────────────────────────────────────
static void sc_n(uint64_t n[4]) { be32_to_limbs(SECP_N_BE, n); }
// reduce a 256-bit value mod n (value < 2^256 < 2n ⇒ ≤1 subtract, but loop to be safe).
static void sc_reduce(uint64_t a[4]) {
    uint64_t n[4]; sc_n(n);
    while (limb_cmp(a, n) >= 0) {
        u128 borrow = 0;
        for (int i = 0; i < 4; i++) { u128 x = (u128)a[i] - n[i] - borrow; a[i] = (uint64_t)x; borrow = (x >> 64) & 1; }
    }
}
// r = (a·b) mod n  (schoolbook to 512 bits, bitwise reduce — called O(1)/op).
static void sc_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t t[8] = {0,0,0,0,0,0,0,0};
    for (int i = 0; i < 4; i++) {
        u128 carry = 0;
        for (int j = 0; j < 4; j++) { u128 x = (u128)a[i] * b[j] + t[i + j] + carry; t[i + j] = (uint64_t)x; carry = x >> 64; }
        t[i + 4] += (uint64_t)carry;
    }
    uint64_t n[4]; sc_n(n);
    uint64_t rem[4] = {0,0,0,0};
    for (int bit = 511; bit >= 0; bit--) {                // rem = (rem<<1 | t[bit]) ; if rem>=n rem-=n
        uint64_t top = rem[3] >> 63;
        rem[3] = (rem[3] << 1) | (rem[2] >> 63);
        rem[2] = (rem[2] << 1) | (rem[1] >> 63);
        rem[1] = (rem[1] << 1) | (rem[0] >> 63);
        rem[0] = (rem[0] << 1) | ((t[bit >> 6] >> (bit & 63)) & 1);
        if (top || limb_cmp(rem, n) >= 0) {               // top bit set ⇒ rem ≥ 2^256 > n
            u128 borrow = 0;
            for (int i = 0; i < 4; i++) { u128 x = (u128)rem[i] - n[i] - borrow; rem[i] = (uint64_t)x; borrow = (x >> 64) & 1; }
        }
    }
    memcpy(r, rem, sizeof rem);
}
// binary extended-gcd inverse mod n (n odd). r = a^{-1} mod n; a in [1,n).
static int sc_add_mod(uint64_t r[4], const uint64_t a[4], const uint64_t b[4], const uint64_t m[4]) {
    u128 carry = 0; uint64_t s[4];
    for (int i = 0; i < 4; i++) { u128 x = (u128)a[i] + b[i] + carry; s[i] = (uint64_t)x; carry = x >> 64; }
    int over = (int)carry;
    if (over || limb_cmp(s, m) >= 0) {
        u128 borrow = 0;
        for (int i = 0; i < 4; i++) { u128 x = (u128)s[i] - m[i] - borrow; s[i] = (uint64_t)x; borrow = (x >> 64) & 1; }
    }
    memcpy(r, s, sizeof s); return 0;
}
static void sc_sub_mod(uint64_t r[4], const uint64_t a[4], const uint64_t b[4], const uint64_t m[4]) {
    if (limb_cmp(a, b) >= 0) {
        u128 borrow = 0;
        for (int i = 0; i < 4; i++) { u128 x = (u128)a[i] - b[i] - borrow; r[i] = (uint64_t)x; borrow = (x >> 64) & 1; }
    } else {                                              // a - b + m
        uint64_t t[4]; u128 borrow = 0;
        for (int i = 0; i < 4; i++) { u128 x = (u128)a[i] - b[i] - borrow; t[i] = (uint64_t)x; borrow = (x >> 64) & 1; }
        u128 carry = 0;
        for (int i = 0; i < 4; i++) { u128 x = (u128)t[i] + m[i] + carry; r[i] = (uint64_t)x; carry = x >> 64; }
    }
}
static void halve_mod(uint64_t x[4], const uint64_t m[4]) {  // x ← x/2 mod m (m odd)
    int odd = (int)(x[0] & 1);
    uint64_t carry = 0;
    if (odd) {                                            // x += m (may carry to bit 256)
        u128 c = 0;
        for (int i = 0; i < 4; i++) { u128 t = (u128)x[i] + m[i] + c; x[i] = (uint64_t)t; c = t >> 64; }
        carry = (uint64_t)c;
    }
    x[0] = (x[0] >> 1) | (x[1] << 63);
    x[1] = (x[1] >> 1) | (x[2] << 63);
    x[2] = (x[2] >> 1) | (x[3] << 63);
    x[3] = (x[3] >> 1) | (carry << 63);
}
static int sc_inv(uint64_t r[4], const uint64_t a_in[4]) {
    uint64_t n[4]; sc_n(n);
    uint64_t u[4], v[4], x1[4] = {1,0,0,0}, x2[4] = {0,0,0,0};
    memcpy(u, a_in, sizeof u); memcpy(v, n, sizeof v);
    uint64_t one[4] = {1,0,0,0};
    if (limb_is_zero(u)) return 0;
    while (limb_cmp(u, one) != 0 && limb_cmp(v, one) != 0) {
        while ((u[0] & 1) == 0) { u[0]=(u[0]>>1)|(u[1]<<63); u[1]=(u[1]>>1)|(u[2]<<63); u[2]=(u[2]>>1)|(u[3]<<63); u[3]>>=1; halve_mod(x1, n); }
        while ((v[0] & 1) == 0) { v[0]=(v[0]>>1)|(v[1]<<63); v[1]=(v[1]>>1)|(v[2]<<63); v[2]=(v[2]>>1)|(v[3]<<63); v[3]>>=1; halve_mod(x2, n); }
        if (limb_cmp(u, v) >= 0) {
            u128 borrow = 0;
            for (int i = 0; i < 4; i++) { u128 t = (u128)u[i] - v[i] - borrow; u[i] = (uint64_t)t; borrow = (t >> 64) & 1; }
            sc_sub_mod(x1, x1, x2, n);
        } else {
            u128 borrow = 0;
            for (int i = 0; i < 4; i++) { u128 t = (u128)v[i] - u[i] - borrow; v[i] = (uint64_t)t; borrow = (t >> 64) & 1; }
            sc_sub_mod(x2, x2, x1, n);
        }
    }
    memcpy(r, (limb_cmp(u, one) == 0) ? x1 : x2, 4 * sizeof(uint64_t));
    return 1;
}

// ── ECDSA verify ──────────────────────────────────────────────────────────────
int secp_ecdsa_verify(const uint8_t hash32[32], const uint8_t r32[32],
                      const uint8_t s32[32], const uint8_t *pub, int plen) {
    fe qx, qy;
    if (!pub_decode(pub, plen, &qx, &qy)) return 0;
    uint64_t n[4]; sc_n(n);
    uint64_t r[4], s[4], z[4];
    be32_to_limbs(r32, r); be32_to_limbs(s32, s); be32_to_limbs(hash32, z);
    if (limb_is_zero(r) || limb_cmp(r, n) >= 0) return 0; // 1 ≤ r < n
    if (limb_is_zero(s) || limb_cmp(s, n) >= 0) return 0; // 1 ≤ s < n
    sc_reduce(z);                                          // z mod n
    uint64_t w[4]; if (!sc_inv(w, s)) return 0;           // w = s^{-1}
    uint64_t u1[4], u2[4]; sc_mul(u1, z, w); sc_mul(u2, r, w);
    uint8_t u1b[32], u2b[32]; limbs_to_be32(u1, u1b); limbs_to_be32(u2, u2b);
    jac G, Q, A, B, Rj;
    secp_G(&G); jac_from_affine(&Q, &qx, &qy);
    jac_mul(&A, &G, u1b); jac_mul(&B, &Q, u2b); jac_add(&Rj, &A, &B);
    fe rx, ry; if (!jac_affine(&Rj, &rx, &ry)) return 0;  // R == ∞ ⇒ invalid
    uint64_t xr[4]; memcpy(xr, rx.v, sizeof xr); sc_reduce(xr);
    return limb_cmp(xr, r) == 0;
}

// ── HMAC-SHA256 ───────────────────────────────────────────────────────────────
static void sha256_buf(const uint8_t *d, int n, uint8_t out[32]) {
    SHA256_CTX c; sha256_init(&c); sha256_update(&c, d, (unsigned)n); sha256_final(&c, out);
}
static void hmac_sha256(const uint8_t *key, int klen, const uint8_t *msg, int mlen, uint8_t out[32]) {
    uint8_t k[64], ki[64], ko[64];
    if (klen > 64) { sha256_buf(key, klen, k); memset(k + 32, 0, 32); }
    else { memcpy(k, key, (size_t)klen); memset(k + klen, 0, (size_t)(64 - klen)); }
    for (int i = 0; i < 64; i++) { ki[i] = k[i] ^ 0x36; ko[i] = k[i] ^ 0x5c; }
    SHA256_CTX c; uint8_t inner[32];
    sha256_init(&c); sha256_update(&c, ki, 64); sha256_update(&c, msg, (unsigned)mlen); sha256_final(&c, inner);
    sha256_init(&c); sha256_update(&c, ko, 64); sha256_update(&c, inner, 32); sha256_final(&c, out);
}

// ── RFC-6979 nonce + ECDSA sign ───────────────────────────────────────────────
// k_out = first valid candidate in [1,n) from the HMAC_DRBG stream keyed by (x, h1).
static void rfc6979_k(const uint8_t priv32[32], const uint8_t hash32[32], uint8_t k_out[32]) {
    uint64_t n[4]; sc_n(n);
    uint8_t h1[32]; memcpy(h1, hash32, 32);               // bits2octets(h1) = (h1 mod n) BE
    uint64_t hz[4]; be32_to_limbs(h1, hz); sc_reduce(hz);
    uint8_t h1o[32]; limbs_to_be32(hz, h1o);
    uint8_t V[32], K[32];
    memset(V, 0x01, 32); memset(K, 0x00, 32);
    uint8_t buf[32 + 1 + 32 + 32]; int bl;
    // K = HMAC_K(V ‖ 0x00 ‖ x ‖ h1o)
    bl = 0; memcpy(buf, V, 32); bl = 32; buf[bl++] = 0x00; memcpy(buf + bl, priv32, 32); bl += 32; memcpy(buf + bl, h1o, 32); bl += 32;
    hmac_sha256(K, 32, buf, bl, K);
    hmac_sha256(K, 32, V, 32, V);                         // V = HMAC_K(V)
    bl = 0; memcpy(buf, V, 32); bl = 32; buf[bl++] = 0x01; memcpy(buf + bl, priv32, 32); bl += 32; memcpy(buf + bl, h1o, 32); bl += 32;
    hmac_sha256(K, 32, buf, bl, K);
    hmac_sha256(K, 32, V, 32, V);
    for (;;) {
        hmac_sha256(K, 32, V, 32, V);                     // T = V (qlen == 256 ⇒ one block)
        uint64_t kz[4]; be32_to_limbs(V, kz);
        if (!limb_is_zero(kz) && limb_cmp(kz, n) < 0) { memcpy(k_out, V, 32); return; }
        uint8_t z = 0x00;                                 // K = HMAC_K(V ‖ 0x00) ; V = HMAC_K(V)
        uint8_t b2[33]; memcpy(b2, V, 32); b2[32] = z;
        hmac_sha256(K, 32, b2, 33, K);
        hmac_sha256(K, 32, V, 32, V);
    }
}
int secp_ecdsa_sign(const uint8_t priv32[32], const uint8_t hash32[32],
                    uint8_t r32[32], uint8_t s32[32]) {
    uint64_t n[4]; sc_n(n);
    uint64_t d[4]; be32_to_limbs(priv32, d);
    if (limb_is_zero(d) || limb_cmp(d, n) >= 0) return 0;
    uint64_t z[4]; be32_to_limbs(hash32, z); sc_reduce(z);
    uint8_t kb[32]; uint8_t feed[32]; memcpy(feed, hash32, 32);
    for (int attempt = 0; attempt < 64; attempt++) {
        rfc6979_k(priv32, feed, kb);
        jac G, R; secp_G(&G); jac_mul(&R, &G, kb);
        fe rx, ry; if (!jac_affine(&R, &rx, &ry)) { sha256_buf(kb, 32, feed); continue; }
        uint64_t r[4]; memcpy(r, rx.v, sizeof r); sc_reduce(r);
        if (limb_is_zero(r)) { sha256_buf(kb, 32, feed); continue; }
        uint64_t kk[4]; be32_to_limbs(kb, kk);
        uint64_t kinv[4]; if (!sc_inv(kinv, kk)) { sha256_buf(kb, 32, feed); continue; }
        uint64_t rd[4]; sc_mul(rd, r, d);
        uint64_t zrd[4]; sc_add_mod(zrd, z, rd, n);
        uint64_t s[4]; sc_mul(s, kinv, zrd);
        if (limb_is_zero(s)) { sha256_buf(kb, 32, feed); continue; }
        uint64_t nh[4]; be32_to_limbs(SECP_N_HALF_BE, nh);
        if (limb_cmp(s, nh) > 0) {                        // low-S: s = n - s
            u128 borrow = 0; uint64_t ns[4];
            for (int i = 0; i < 4; i++) { u128 x = (u128)n[i] - s[i] - borrow; ns[i] = (uint64_t)x; borrow = (x >> 64) & 1; }
            memcpy(s, ns, sizeof s);
        }
        limbs_to_be32(r, r32); limbs_to_be32(s, s32);
        return 1;
    }
    return 0;
}
int secp_pubkey(const uint8_t priv32[32], uint8_t pub33[33]) {
    uint64_t n[4]; sc_n(n);
    uint64_t d[4]; be32_to_limbs(priv32, d);
    if (limb_is_zero(d) || limb_cmp(d, n) >= 0) return 0;
    jac G, P; secp_G(&G); jac_mul(&P, &G, priv32);
    fe x, y; if (!jac_affine(&P, &x, &y)) return 0;
    pub33[0] = fe_is_odd(&y) ? 0x03 : 0x02;
    limbs_to_be32(x.v, pub33 + 1);
    return 1;
}

// ── ECMH (Elliptic Curve Multiset Hash) ───────────────────────────────────────
// An accumulator is a 33-byte compressed point (0x02/0x03 ‖ X-be); the all-zero
// sentinel (prefix 0x00) is the identity ∞. See secp256k1.h.
static const uint8_t ECMH_H2C_TAG[8] = { 'E','C','M','H','h','2','c','1' };

void secp_ecmh_identity(uint8_t acc33[33]) { memset(acc33, 0, 33); }

static void ecmh_ser(const jac *p, uint8_t out33[33]) {   // point → 33 bytes (∞ → zeros)
    fe x, y;
    if (p->inf || !jac_affine(p, &x, &y)) { memset(out33, 0, 33); return; }
    out33[0] = fe_is_odd(&y) ? 0x03 : 0x02;
    limbs_to_be32(x.v, out33 + 1);
}
static void ecmh_load(const uint8_t in33[33], jac *p) {   // 33 bytes → point
    if (in33[0] == 0) { jac_set_inf(p); return; }
    fe x, y;
    if (!pub_decode(in33, 33, &x, &y)) { jac_set_inf(p); return; }  // non-decodable X → ∞ (no uninit read; matches Go/Py/TS)
    jac_from_affine(p, &x, &y);
}

int secp_ecmh_hash(const uint8_t *pre, int len, uint8_t pt33[33]) {
    for (int ctr = 0; ; ctr++) {
        SHA256_CTX c; sha256_init(&c);
        sha256_update(&c, ECMH_H2C_TAG, 8);
        if (len > 0) sha256_update(&c, pre, (unsigned)len);
        uint8_t cb[4] = { (uint8_t)ctr, (uint8_t)(ctr >> 8), (uint8_t)(ctr >> 16), (uint8_t)(ctr >> 24) };
        sha256_update(&c, cb, 4);
        uint8_t h[32]; sha256_final(&c, h);
        fe x; be32_to_limbs(h, x.v); fe_cond_sub_p(&x);    // x = SHA256(...) mod p
        fe rhs; rhs_curve(&rhs, &x);
        fe beta, b2; fe_sqrt(&beta, &rhs); fe_sqr(&b2, &beta);
        if (!fe_eq(&b2, &rhs)) continue;                   // x³+7 not a QR ⇒ bump ctr
        pt33[0] = 0x02; limbs_to_be32(x.v, pt33 + 1);      // canonical even-Y
        return ctr;
    }
}

void secp_ecmh_negate(uint8_t pt33[33]) { if (pt33[0]) pt33[0] ^= 1; }

void secp_ecmh_add(uint8_t acc33[33], const uint8_t pt33[33]) {
    jac a, p, r; ecmh_load(acc33, &a); ecmh_load(pt33, &p);
    jac_add(&r, &a, &p); ecmh_ser(&r, acc33);
}

int secp_ecmh_selftest(void) {
    int fail = 0;
    uint8_t pa[33], pb[33], acc1[33], acc2[33], id[33];
    secp_ecmh_identity(id);
    secp_ecmh_hash((const uint8_t *)"alpha", 5, pa);
    secp_ecmh_hash((const uint8_t *)"beta",  4, pb);
    secp_ecmh_identity(acc1); secp_ecmh_add(acc1, pa); secp_ecmh_add(acc1, pb);
    secp_ecmh_identity(acc2); secp_ecmh_add(acc2, pb); secp_ecmh_add(acc2, pa);
    if (memcmp(acc1, acc2, 33)) fail++;                    // commutativity
    secp_ecmh_identity(acc1); secp_ecmh_add(acc1, pa);
    if (memcmp(acc1, pa, 33)) fail++;                      // identity: ∞ + P == P
    uint8_t npa[33]; memcpy(npa, pa, 33); secp_ecmh_negate(npa);
    secp_ecmh_identity(acc1); secp_ecmh_add(acc1, pa); secp_ecmh_add(acc1, npa);
    if (memcmp(acc1, id, 33)) fail++;                      // inverse: P + (−P) == ∞
    secp_ecmh_identity(acc1); secp_ecmh_add(acc1, pa);
    memcpy(acc2, acc1, 33); secp_ecmh_add(acc2, pb);
    uint8_t npb[33]; memcpy(npb, pb, 33); secp_ecmh_negate(npb); secp_ecmh_add(acc2, npb);
    if (memcmp(acc1, acc2, 33)) fail++;                    // add-then-remove round-trip
    return fail;
}

// ── self-check ────────────────────────────────────────────────────────────────
static int secp_kat_fail(const char *what) {
#ifdef SECP_KAT_VERBOSE
    fprintf(stderr, "secp KAT FAIL: %s\n", what);
#endif
    return (void)what, 1;
}
int secp_selftest(void) {
    int fail = 0;
    // constants: N_HALF = N>>1, and G on curve.
    { uint64_t n[4], nh[4]; sc_n(n); be32_to_limbs(SECP_N_HALF_BE, nh);
      uint64_t h[4]; memcpy(h, n, sizeof h);
      h[0]=(h[0]>>1)|(h[1]<<63); h[1]=(h[1]>>1)|(h[2]<<63); h[2]=(h[2]>>1)|(h[3]<<63); h[3]>>=1;
      if (limb_cmp(h, nh) != 0) fail += secp_kat_fail("N_HALF"); }
    // G on curve via the uncompressed encoding.
    { uint8_t g[65]; g[0]=0x04; memcpy(g+1, SECP_GX_BE, 32); memcpy(g+33, SECP_GY_BE, 32);
      if (!secp_on_curve(g, 65)) fail += secp_kat_fail("G on curve"); }
    // 2G known-answer (well-known constant).
    { static const uint8_t two[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2};
      static const uint8_t G2X[32] = {0xC6,0x04,0x7F,0x94,0x41,0xED,0x7D,0x6D,0x30,0x45,0x40,0x6E,0x95,0xC0,0x7C,0xD8,
                                       0x5C,0x77,0x8E,0x4B,0x8C,0xEF,0x3C,0xA7,0xAB,0xAC,0x09,0xB9,0x5C,0x70,0x9E,0xE5};
      static const uint8_t G2Y[32] = {0x1A,0xE1,0x68,0xFE,0xA6,0x3D,0xC3,0x39,0xA3,0xC5,0x84,0x19,0x46,0x6C,0xEA,0xEE,
                                       0xF7,0xF6,0x32,0x65,0x32,0x66,0xD0,0xE1,0x23,0x64,0x31,0xA9,0x50,0xCF,0xE5,0x2A};
      jac G, P; secp_G(&G); jac_mul(&P, &G, two);
      fe x, y; uint8_t xb[32], yb[32];
      if (!jac_affine(&P, &x, &y)) fail += secp_kat_fail("2G affine");
      else { limbs_to_be32(x.v, xb); limbs_to_be32(y.v, yb);
             if (memcmp(xb, G2X, 32) || memcmp(yb, G2Y, 32)) fail += secp_kat_fail("2G value"); } }
    // n·G == ∞.
    { jac G, P; secp_G(&G); jac_mul(&P, &G, SECP_N_BE);
      fe x, y; if (jac_affine(&P, &x, &y)) fail += secp_kat_fail("n·G != inf"); }
    // decompress round-trip: compress G, decode, compare.
    { uint8_t gc[33]; gc[0] = 0x02;                       // Gy is even (ends 0xB8)
      memcpy(gc+1, SECP_GX_BE, 32);
      fe x, y; if (!pub_decode(gc, 33, &x, &y)) fail += secp_kat_fail("decompress G");
      else { uint8_t yb[32]; limbs_to_be32(y.v, yb); if (memcmp(yb, SECP_GY_BE, 32)) fail += secp_kat_fail("decompress Gy"); } }
    // sign / verify round-trip over a few deterministic keys + a tamper check.
    for (int t = 1; t <= 4; t++) {
        uint8_t priv[32]; memset(priv, 0, 32); priv[31] = (uint8_t)(t * 7 + 1);
        uint8_t pub[33]; if (!secp_pubkey(priv, pub)) { fail += secp_kat_fail("pubkey"); continue; }
        uint8_t msg[32]; for (int i = 0; i < 32; i++) msg[i] = (uint8_t)(i * 13 + t);
        uint8_t mh[32]; sha256_buf(msg, 32, mh);
        uint8_t r[32], s[32];
        if (!secp_ecdsa_sign(priv, mh, r, s)) { fail += secp_kat_fail("sign"); continue; }
        if (!secp_ecdsa_verify(mh, r, s, pub, 33)) fail += secp_kat_fail("verify");
        uint8_t mh2[32]; memcpy(mh2, mh, 32); mh2[0] ^= 0x01;
        if (secp_ecdsa_verify(mh2, r, s, pub, 33)) fail += secp_kat_fail("tamper verify");
    }
    return fail;
}
