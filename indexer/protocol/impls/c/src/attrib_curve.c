// §4 Strategy B — the pinned ECDSA curve-vector set (`sm attrib-curve`).
//
// The irreducible, hand-pinned core that makes "the curve is real" a CHECKABLE
// claim rather than a trust-me. Every reference impl runs this exact vector script
// against its OWN secp256k1 and must print byte-identical output (prose/vector-
// pinned, Tier-2 style — all 7 impls agree). Covers: pinned P/N/N_HALF constants,
// on-curve membership at the edges, ECDSA verify accept/reject at the scalar
// boundaries (r/s = 0, n, >n; tampered hash; wrong key; high-S still verifies),
// and RFC-6979 deterministic (r,s) + canonical-DER known-answers. See
// SPEC-conformance.md §13 + SPEC-RATIONALE.md §11.
#include "attrib.h"
#include "secp256k1.h"
#include "sha256.h"

#include <stdio.h>
#include <string.h>

static const char *HEXD = "0123456789abcdef";
static void puthex(const uint8_t *d, int n) { for (int i = 0; i < n; i++) { putchar(HEXD[d[i] >> 4]); putchar(HEXD[d[i] & 15]); } }
static void sha(const uint8_t *d, int n, uint8_t out[32]) { SHA256_CTX c; sha256_init(&c); sha256_update(&c, d, (unsigned)n); sha256_final(&c, out); }

// secp256k1 n, n/2, and p as big-endian constants (mirrors secp256k1.c; pinned here
// so the vector script self-contains its expected scalars cross-language).
static const uint8_t CV_P[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F };
static const uint8_t CV_N[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41 };
static const uint8_t CV_NHALF[32] = {
    0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0 };
static const uint8_t CV_GX[32] = {
    0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,0x07,
    0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98 };
static const uint8_t CV_GY[32] = {
    0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,0x08,0xA8,
    0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,0xD4,0xB8 };

// canonical strict-DER encoding of (r,s) ‖ SIGHASH_ALL — the byte form the §4 shell
// parses. Pads each integer to a minimal positive DER INTEGER (leading 0x00 only to
// clear a high bit). Cross-language KAT: this output must be byte-identical.
static int der_int(uint8_t *out, const uint8_t v[32]) {
    int i = 0; while (i < 31 && v[i] == 0) i++;           // strip leading zeros
    int len = 32 - i; int pad = (v[i] & 0x80) ? 1 : 0;
    out[0] = 0x02; out[1] = (uint8_t)(len + pad); int n = 2;
    if (pad) out[n++] = 0x00;
    memcpy(out + n, v + i, (size_t)len); n += len;
    return n;
}
static int der_sig(uint8_t *out, const uint8_t r[32], const uint8_t s[32]) {
    uint8_t body[80]; int bl = 0;
    bl += der_int(body + bl, r); bl += der_int(body + bl, s);
    out[0] = 0x30; out[1] = (uint8_t)bl;
    memcpy(out + 2, body, (size_t)bl);
    out[2 + bl] = 0x01;                                   // SIGHASH_ALL
    return 2 + bl + 1;
}

int attrib_cmd_curve(void) {
    SHA256_CTX comb; sha256_init(&comb);
    #define FEED(p,n) sha256_update(&comb, (const uint8_t*)(p), (unsigned)(n))

    // ── 1. pinned constants ────────────────────────────────────────────────────
    printf("p ");     puthex(CV_P, 32);     printf("\n"); FEED(CV_P, 32);
    printf("n ");     puthex(CV_N, 32);     printf("\n"); FEED(CV_N, 32);
    printf("nhalf "); puthex(CV_NHALF, 32); printf("\n"); FEED(CV_NHALF, 32);

    // ── 2. on-curve membership at the edges ────────────────────────────────────
    // helper-local builders
    uint8_t buf[80];
    struct { const char *name; int len; uint8_t key[80]; } oc[16]; int noc = 0;
    // G uncompressed (on)
    buf[0]=0x04; memcpy(buf+1,CV_GX,32); memcpy(buf+33,CV_GY,32);
    oc[noc].len=65; memcpy(oc[noc].key,buf,65); oc[noc].name="oc_G_uncomp"; noc++;
    // G compressed even (on) — Gy is even ⇒ 0x02
    buf[0]=0x02; memcpy(buf+1,CV_GX,32);
    oc[noc].len=33; memcpy(oc[noc].key,buf,33); oc[noc].name="oc_G_comp02"; noc++;
    // G compressed odd-prefix (still on curve: yields p−Gy, the odd root)
    buf[0]=0x03; memcpy(buf+1,CV_GX,32);
    oc[noc].len=33; memcpy(oc[noc].key,buf,33); oc[noc].name="oc_G_comp03"; noc++;
    // (Gx, Gy^lsb) uncompressed (off curve: Y altered)
    buf[0]=0x04; memcpy(buf+1,CV_GX,32); memcpy(buf+33,CV_GY,32); buf[64]^=0x01;
    oc[noc].len=65; memcpy(oc[noc].key,buf,65); oc[noc].name="oc_G_badY"; noc++;
    // compressed X=0 (rhs=7; verdict = is 7 a QR mod p — pinned by the digest)
    buf[0]=0x02; memset(buf+1,0,32);
    oc[noc].len=33; memcpy(oc[noc].key,buf,33); oc[noc].name="oc_X0"; noc++;
    // compressed X=1
    buf[0]=0x02; memset(buf+1,0,32); buf[32]=1;
    oc[noc].len=33; memcpy(oc[noc].key,buf,33); oc[noc].name="oc_X1"; noc++;
    // uncompressed X>=p (X = p) ⇒ decode-reject
    buf[0]=0x04; memcpy(buf+1,CV_P,32); memcpy(buf+33,CV_GY,32);
    oc[noc].len=65; memcpy(oc[noc].key,buf,65); oc[noc].name="oc_Xeqp"; noc++;
    // compressed X>=p ⇒ decode-reject
    buf[0]=0x02; memcpy(buf+1,CV_P,32);
    oc[noc].len=33; memcpy(oc[noc].key,buf,33); oc[noc].name="oc_comp_Xeqp"; noc++;
    // bad prefix 0x05 ⇒ reject
    buf[0]=0x05; memcpy(buf+1,CV_GX,32);
    oc[noc].len=33; memcpy(oc[noc].key,buf,33); oc[noc].name="oc_badprefix"; noc++;
    for (int i = 0; i < noc; i++) {
        int v = secp_on_curve(oc[i].key, oc[i].len);
        printf("%s %d\n", oc[i].name, v);
        uint8_t b = (uint8_t)v; FEED(&b, 1); FEED(oc[i].key, oc[i].len);
    }

    // ── 3 & 4. RFC-6979 deterministic sign + ECDSA verify at the boundaries ─────
    // Four deterministic signers; message hash = SHA256("strategy-b curve vector <i>").
    for (int i = 0; i < 4; i++) {
        uint8_t priv[32]; memset(priv, 0, 32);
        priv[28]=0xC0; priv[29]=0xFF; priv[30]=0xEE; priv[31]=(uint8_t)(0x10 + i);
        uint8_t pub[33]; if (!secp_pubkey(priv, pub)) { printf("sig%d PUBFAIL\n", i); continue; }
        char m[40]; int ml = sprintf(m, "strategy-b curve vector %d", i);
        uint8_t h[32]; sha((const uint8_t*)m, ml, h);
        uint8_t r[32], s[32];
        if (!secp_ecdsa_sign(priv, h, r, s)) { printf("sig%d SIGNFAIL\n", i); continue; }
        // RFC-6979 known-answer: print pub, r, s, and canonical DER (all byte-pinned).
        uint8_t der[80]; int dl = der_sig(der, r, s);
        printf("sig%d pub=", i); puthex(pub, 33);
        printf(" r=");   puthex(r, 32);
        printf(" s=");   puthex(s, 32);
        printf(" der="); puthex(der, dl);
        printf("\n");
        FEED(pub, 33); FEED(r, 32); FEED(s, 32); FEED(der, dl);

        // verify boundary battery (accept/reject bit each, all pinned).
        uint8_t zero[32]; memset(zero, 0, 32);
        uint8_t hbad[32]; memcpy(hbad, h, 32); hbad[0]^=0x01;
        uint8_t hiS[32]; { // high-S = n - s ; verify must still accept (low-S is a DER rule)
            // compute n - s via byte subtraction
            int borrow = 0;
            for (int k = 31; k >= 0; k--) { int d = CV_N[k] - s[k] - borrow; if (d < 0) { d += 256; borrow = 1; } else borrow = 0; hiS[k] = (uint8_t)d; }
        }
        uint8_t wrongpub[33]; memcpy(wrongpub, pub, 33); wrongpub[0] ^= 0x01; // flip parity ⇒ other point (valid key, wrong one)
        struct { const char *nm; const uint8_t *hh; const uint8_t *rr; const uint8_t *ss; const uint8_t *pk; } vt[] = {
            { "valid",   h,    r,    s,    pub      },
            { "tamper",  hbad, r,    s,    pub      },
            { "r0",      h,    zero, s,    pub      },
            { "s0",      h,    r,    zero, pub      },
            { "rN",      h,    CV_N, s,    pub      },
            { "sN",      h,    r,    CV_N, pub      },
            { "highS",   h,    r,    hiS,  pub      },
            { "wrongpk", h,    r,    s,    wrongpub },
        };
        printf("ver%d", i);
        for (unsigned t = 0; t < sizeof vt / sizeof vt[0]; t++) {
            int v = secp_ecdsa_verify(vt[t].hh, vt[t].rr, vt[t].ss, vt[t].pk, 33);
            printf(" %s=%d", vt[t].nm, v);
            uint8_t b = (uint8_t)v; FEED(&b, 1);
        }
        printf("\n");
    }

    // ── 5. tiny-key KAT: priv=1 ⇒ pub=G ; priv=2 ⇒ pub=2G (decompressed) ────────
    { uint8_t p1[32]; memset(p1,0,32); p1[31]=1; uint8_t pk1[33];
      secp_pubkey(p1, pk1); printf("priv1_pub="); puthex(pk1, 33); printf("\n"); FEED(pk1, 33);
      uint8_t p2[32]; memset(p2,0,32); p2[31]=2; uint8_t pk2[33];
      secp_pubkey(p2, pk2); printf("priv2_pub="); puthex(pk2, 33); printf("\n"); FEED(pk2, 33); }

    // PRIMARY cross-language digest: the pure curve layer (sections 1–5). All 7 impls
    // must reproduce this exactly (RFC-6979 + DER + field math are deterministic).
    uint8_t cd[32]; sha256_final(&comb, cd);
    printf("combined "); puthex(cd, 32); printf("\n");

    // ── 6. end-to-end: sign the actual legacy sighash, attribute() with real curve ──
    // Separate digest (depends on each impl's §4 attribution byte-logic + the sighash
    // linkage). Also cross-language; kept separable so the curve layer can be certified
    // independently of the attribution shell.
    SHA256_CTX e2e; sha256_init(&e2e);
    attrib_real_endtoend(&e2e);
    uint8_t ed[32]; sha256_final(&e2e, ed);
    printf("combined_e2e "); puthex(ed, 32); printf("\n");
    #undef FEED
    return 0;
}
