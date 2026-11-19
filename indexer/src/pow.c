// pow.c — see pow.h. Scrypt + compact-target arithmetic + Digishield + AuxPoW.
#include "pow.h"
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ── HMAC-SHA256 / PBKDF2 (only what scrypt needs: c=1) ───────────────────────
typedef struct { SHA256_CTX inner; SHA256_CTX outer; } Hmac;
static void hmac_init(Hmac *h, const uint8_t *key, size_t keylen) {
    uint8_t k[64], pad[64];
    memset(k, 0, 64);
    if (keylen > 64) { SHA256_CTX c; sha256_init(&c); sha256_update(&c, key, (unsigned)keylen); sha256_final(&c, k); }
    else memcpy(k, key, keylen);
    sha256_init(&h->inner);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    sha256_update(&h->inner, pad, 64);
    sha256_init(&h->outer);
    for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
    sha256_update(&h->outer, pad, 64);
}
static void hmac_final(Hmac *h, uint8_t out[32]) {
    uint8_t ih[32];
    sha256_final(&h->inner, ih);
    sha256_update(&h->outer, ih, 32);
    sha256_final(&h->outer, out);
}
// PBKDF2-HMAC-SHA256 with c=1: out = Σ blocks HMAC(pass, salt || be32(i))
static void pbkdf2_c1(const uint8_t *pass, size_t plen, const uint8_t *salt, size_t slen,
                      uint8_t *out, size_t dklen) {
    for (uint32_t i = 1; dklen; i++) {
        Hmac h; hmac_init(&h, pass, plen);
        sha256_update(&h.inner, salt, (unsigned)slen);
        uint8_t be[4] = { (uint8_t)(i >> 24), (uint8_t)(i >> 16), (uint8_t)(i >> 8), (uint8_t)i };
        sha256_update(&h.inner, be, 4);
        uint8_t t[32]; hmac_final(&h, t);
        size_t n = dklen < 32 ? dklen : 32;
        memcpy(out, t, n); out += n; dklen -= n;
    }
}

// ── salsa20/8 core + scrypt (r=1, p=1, N parameterized for the RFC vector) ───
#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
static void salsa8(uint32_t B[16]) {
    uint32_t x[16];
    memcpy(x, B, 64);
    for (int i = 0; i < 8; i += 2) {
        x[ 4] ^= R(x[ 0]+x[12], 7); x[ 8] ^= R(x[ 4]+x[ 0], 9);
        x[12] ^= R(x[ 8]+x[ 4],13); x[ 0] ^= R(x[12]+x[ 8],18);
        x[ 9] ^= R(x[ 5]+x[ 1], 7); x[13] ^= R(x[ 9]+x[ 5], 9);
        x[ 1] ^= R(x[13]+x[ 9],13); x[ 5] ^= R(x[ 1]+x[13],18);
        x[14] ^= R(x[10]+x[ 6], 7); x[ 2] ^= R(x[14]+x[10], 9);
        x[ 6] ^= R(x[ 2]+x[14],13); x[10] ^= R(x[ 6]+x[ 2],18);
        x[ 3] ^= R(x[15]+x[11], 7); x[ 7] ^= R(x[ 3]+x[15], 9);
        x[11] ^= R(x[ 7]+x[ 3],13); x[15] ^= R(x[11]+x[ 7],18);
        x[ 1] ^= R(x[ 0]+x[ 3], 7); x[ 2] ^= R(x[ 1]+x[ 0], 9);
        x[ 3] ^= R(x[ 2]+x[ 1],13); x[ 0] ^= R(x[ 3]+x[ 2],18);
        x[ 6] ^= R(x[ 5]+x[ 4], 7); x[ 7] ^= R(x[ 6]+x[ 5], 9);
        x[ 4] ^= R(x[ 7]+x[ 6],13); x[ 5] ^= R(x[ 4]+x[ 7],18);
        x[11] ^= R(x[10]+x[ 9], 7); x[ 8] ^= R(x[11]+x[10], 9);
        x[ 9] ^= R(x[ 8]+x[11],13); x[10] ^= R(x[ 9]+x[ 8],18);
        x[12] ^= R(x[15]+x[14], 7); x[13] ^= R(x[12]+x[15], 9);
        x[14] ^= R(x[13]+x[12],13); x[15] ^= R(x[14]+x[13],18);
    }
    for (int i = 0; i < 16; i++) B[i] += x[i];
}
#undef R
// BlockMix for r=1: X = (B0,B1) of 16 u32 each; B0' = salsa8(B0^B1),
// B1' = salsa8(B1^B0'); integerify = first word of B1'.
static void blockmix_r1(uint32_t X[32]) {
    for (int i = 0; i < 16; i++) X[i] ^= X[16 + i];
    salsa8(X);
    for (int i = 0; i < 16; i++) X[16 + i] ^= X[i];
    salsa8(X + 16);
}
// scrypt with r=1, p=1. N must be a power of two. dk up to 64 bytes.
static void scrypt_r1p1(const uint8_t *pass, size_t plen, uint32_t N,
                        uint8_t *dk, size_t dklen) {
    uint8_t Bb[128];
    pbkdf2_c1(pass, plen, pass, plen, Bb, 128);
    uint32_t X[32];
    for (int i = 0; i < 32; i++)
        X[i] = (uint32_t)Bb[4*i] | (uint32_t)Bb[4*i+1] << 8 |
               (uint32_t)Bb[4*i+2] << 16 | (uint32_t)Bb[4*i+3] << 24;
    uint32_t *V = malloc((size_t)N * 128);
    if (!V) { memset(dk, 0xFF, dklen); return; }       // fail CLOSED: max hash > any target
    for (uint32_t i = 0; i < N; i++) {
        memcpy(V + (size_t)i * 32, X, 128);
        blockmix_r1(X);
    }
    for (uint32_t i = 0; i < N; i++) {
        uint32_t j = X[16] & (N - 1);                  // integerify: B1'[0]
        for (int k = 0; k < 32; k++) X[k] ^= V[(size_t)j * 32 + k];
        blockmix_r1(X);
    }
    free(V);
    for (int i = 0; i < 32; i++) {
        Bb[4*i] = (uint8_t)X[i]; Bb[4*i+1] = (uint8_t)(X[i] >> 8);
        Bb[4*i+2] = (uint8_t)(X[i] >> 16); Bb[4*i+3] = (uint8_t)(X[i] >> 24);
    }
    pbkdf2_c1(pass, plen, Bb, 128, dk, dklen);
}

void idx_pow_hash(const uint8_t hdr[80], uint8_t out32[32]) {
    scrypt_r1p1(hdr, 80, 1024, out32, 32);
}

// ── compact targets (arith_uint256 semantics, positive values only) ──────────
// Targets are 32-byte little-endian; [31] is the most significant byte.
static int bits_to_target(uint32_t bits, uint8_t t[32]) {
    memset(t, 0, 32);
    uint32_t exp = bits >> 24, mant = bits & 0x007fffff;
    if (bits & 0x00800000) return 0;                   // negative: invalid
    if (mant == 0) return 0;
    if (exp <= 3) { mant >>= 8 * (3 - exp); if (!mant) return 0; exp = 3; }
    if (exp > 32) return 0;                            // overflows 256 bits
    if (exp >= 1) t[exp - 1] = (uint8_t)(mant >> 16);
    if (exp >= 2) t[exp - 2] = (uint8_t)(mant >> 8);
    t[exp - 3] = (uint8_t)mant;
    return 1;
}
static uint32_t target_to_bits(const uint8_t t[32]) {  // GetCompact, fNegative=0
    int size = 32;
    while (size > 0 && t[size - 1] == 0) size--;
    if (size == 0) return 0;
    uint32_t mant;
    if (size >= 3) mant = (uint32_t)t[size - 1] << 16 | (uint32_t)t[size - 2] << 8 | t[size - 3];
    else if (size == 2) mant = (uint32_t)t[1] << 16 | (uint32_t)t[0] << 8;
    else mant = (uint32_t)t[0] << 16;
    if (mant & 0x00800000) { mant >>= 8; size++; }     // keep the sign bit clear
    return ((uint32_t)size << 24) | mant;
}
static int cmp256(const uint8_t a[32], const uint8_t b[32]) {
    for (int i = 31; i >= 0; i--) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

// ── 256-bit LE arithmetic for cumulative work (arith_uint256 semantics) ───────
static void u256_add(uint8_t a[32], const uint8_t b[32]) {   // a += b (mod 2^256)
    uint32_t carry = 0;
    for (int i = 0; i < 32; i++) { uint32_t s = (uint32_t)a[i] + b[i] + carry; a[i] = (uint8_t)s; carry = s >> 8; }
}
static void u256_sub(uint8_t a[32], const uint8_t b[32]) {   // a -= b (a >= b)
    int32_t borrow = 0;
    for (int i = 0; i < 32; i++) { int32_t d = (int32_t)a[i] - b[i] - borrow; borrow = d < 0; if (borrow) d += 256; a[i] = (uint8_t)d; }
}
static void u256_shl1(uint8_t a[32]) {                       // a <<= 1
    uint8_t carry = 0;
    for (int i = 0; i < 32; i++) { uint8_t nc = a[i] >> 7; a[i] = (uint8_t)((a[i] << 1) | carry); carry = nc; }
}

void idx_pow_work(uint32_t bits, uint8_t work[32]) {
    memset(work, 0, 32);
    uint8_t target[32];
    if (!bits_to_target(bits, target)) return;               // invalid / zero → 0 work
    // GetBlockProof: floor(2^256 / (target+1)) = (~target)/(target+1) + 1.
    // ~target avoids ever forming 2^256; target ≤ powLimit ≪ 2^256 so target+1
    // never overflows 256 bits.
    uint8_t nt[32], den[32];
    for (int i = 0; i < 32; i++) nt[i] = (uint8_t)~target[i];
    memcpy(den, target, 32);
    uint8_t one[32] = { 1 }; u256_add(den, one);             // den = target + 1
    uint8_t q[32], rem[32]; memset(q, 0, 32); memset(rem, 0, 32);
    for (int bit = 255; bit >= 0; bit--) {                   // rem:q = nt / den, MSB first
        u256_shl1(rem);
        rem[0] |= (nt[bit >> 3] >> (bit & 7)) & 1;
        if (cmp256(rem, den) >= 0) { u256_sub(rem, den); q[bit >> 3] |= (uint8_t)(1 << (bit & 7)); }
    }
    memcpy(work, q, 32); u256_add(work, one);                // + 1
}
void idx_pow_work_add(uint8_t acc[32], const uint8_t add[32]) { u256_add(acc, add); }
int  idx_pow_work_cmp(const uint8_t a[32], const uint8_t b[32]) { return cmp256(a, b); }

uint32_t idx_pow_next_bits(uint32_t prev_bits, int64_t prev_time,
                           int64_t prevprev_time, uint32_t powlimit) {
    // Digishield (per-block): modulate the actual solve time toward the 60 s
    // target by 1/8, clamp to [45,90], scale the previous target by it.
    // Integer semantics mirror Core: C's truncating division == C++'s.
    int64_t actual = prev_time - prevprev_time;
    int64_t modulated = 60 + (actual - 60) / 8;
    if (modulated < 45) modulated = 45;
    if (modulated > 90) modulated = 90;
    uint8_t prev[32], lim[32];
    if (!bits_to_target(prev_bits, prev) || !bits_to_target(powlimit, lim))
        return 0;
    // wide = prev * modulated / 60 in a 40-byte buffer (powLimit·90 < 2^244,
    // so 320 bits never overflows), then cap at powLimit
    uint8_t wide[40];
    memset(wide, 0, sizeof wide);
    uint64_t carry = 0;
    for (int i = 0; i < 32; i++) {
        carry += (uint64_t)prev[i] * (uint64_t)modulated;
        wide[i] = (uint8_t)carry; carry >>= 8;
    }
    for (int i = 32; i < 40 && carry; i++) { wide[i] = (uint8_t)carry; carry >>= 8; }
    uint32_t rem = 0;
    for (int i = 39; i >= 0; i--) {
        uint32_t cur = (rem << 8) | wide[i];
        wide[i] = (uint8_t)(cur / 60);
        rem = cur % 60;
    }
    uint8_t t[32];
    int over = 0;
    for (int i = 32; i < 40; i++) if (wide[i]) over = 1;
    memcpy(t, wide, 32);
    if (over || cmp256(t, lim) > 0) memcpy(t, lim, 32);
    return target_to_bits(t);
}

// ── AuxPoW verification ───────────────────────────────────────────────────────
static void sha256d(const uint8_t *p, size_t n, uint8_t out[32]) {
    SHA256_CTX c; uint8_t h[32];
    sha256_init(&c); sha256_update(&c, p, (unsigned)n); sha256_final(&c, h);
    sha256_init(&c); sha256_update(&c, h, 32); sha256_final(&c, out);
}
typedef struct { const uint8_t *p; size_t len, off; int err; } Pc;
static const uint8_t *pc_take(Pc *c, size_t n) {
    if (c->err || c->off + n > c->len) { c->err = 1; return NULL; }
    const uint8_t *r = c->p + c->off; c->off += n; return r;
}
static uint64_t pc_varint(Pc *c) {
    const uint8_t *b = pc_take(c, 1); if (!b) return 0;
    if (*b < 0xFD) return *b;
    if (*b == 0xFD) { const uint8_t *v = pc_take(c, 2); return v ? (uint64_t)v[0] | (uint64_t)v[1] << 8 : 0; }
    if (*b == 0xFE) { const uint8_t *v = pc_take(c, 4); return v ? (uint64_t)v[0] | (uint64_t)v[1] << 8 | (uint64_t)v[2] << 16 | (uint64_t)v[3] << 24 : 0; }
    c->err = 1; return 0;                              // 8-byte counts: no real block
}
static uint32_t pc_u32(Pc *c) {
    const uint8_t *v = pc_take(c, 4);
    return v ? (uint32_t)v[0] | (uint32_t)v[1] << 8 | (uint32_t)v[2] << 16 | (uint32_t)v[3] << 24 : 0;
}
// apply a merkle branch: index bit 0 = we're the left node at that level
static void branch_apply(uint8_t h[32], const uint8_t *branch, int n, uint32_t index) {
    uint8_t buf[64];
    for (int i = 0; i < n; i++) {
        if (index & 1) { memcpy(buf, branch + 32 * i, 32); memcpy(buf + 32, h, 32); }
        else           { memcpy(buf, h, 32); memcpy(buf + 32, branch + 32 * i, 32); }
        sha256d(buf, 64, h);
        index >>= 1;
    }
}
static int fail(char *why, size_t cap, const char *msg) {
    if (why) snprintf(why, cap, "%s", msg);
    return 0;
}

int idx_pow_check(const uint8_t *raw, size_t len, const PowParams *pp,
                  char *why, size_t whycap) {
    return idx_pow_check2(raw, len, pp, NULL, why, whycap);
}

int idx_pow_check2(const uint8_t *raw, size_t len, const PowParams *pp,
                   size_t *consumed, char *why, size_t whycap) {
    if (len < 80) return fail(why, whycap, "short header");
    uint32_t version = (uint32_t)raw[0] | (uint32_t)raw[1] << 8 | (uint32_t)raw[2] << 16 | (uint32_t)raw[3] << 24;
    uint32_t bits = (uint32_t)raw[72] | (uint32_t)raw[73] << 8 | (uint32_t)raw[74] << 16 | (uint32_t)raw[75] << 24;
    uint8_t target[32], limit[32];
    if (!bits_to_target(bits, target)) return fail(why, whycap, "bad nBits");
    if (!bits_to_target(pp->powlimit, limit)) return fail(why, whycap, "bad powlimit");
    if (cmp256(target, limit) > 0) return fail(why, whycap, "target above powLimit");
    // strict chain id on every post-legacy block (both profiles checkpoint far
    // past the legacy era)
    if ((version >> 16) != pp->aux_chain_id) return fail(why, whycap, "wrong chain id");
    uint8_t pow[32];
    if (!(version & 0x100)) {                          // direct-mined: own header
        idx_pow_hash(raw, pow);
        if (cmp256(pow, target) > 0) return fail(why, whycap, "insufficient work");
        if (consumed) *consumed = 80;
        return 1;
    }
    // merged-mined: verify the AuxPoW that sits between header and tx count.
    Pc c = { raw, len, 80, 0 };
    // Parent coinbase tx. The parent chain (e.g. Litecoin) may be SegWit, so the
    // coinbase can carry a BIP144 marker/flag + witness — Core deserializes it
    // with its witness-aware CTransaction reader (a getdata block arrives witness-
    // stripped, but a `headers` message keeps the witness). The txid that the
    // merkle branch commits to is over the NON-witness serialization, so we hash
    // version ‖ (vin..vout) ‖ locktime, skipping marker/flag and the witness.
    size_t cb_start = c.off;
    pc_u32(&c);                                        // tx version
    size_t body_start = c.off;                         // vin count varint (non-witness)
    uint64_t vin = pc_varint(&c);
    int segwit = 0;
    if (vin == 0 && !c.err) {                          // 0x00 marker → SegWit
        pc_take(&c, 1);                                // flag byte (0x01)
        segwit = 1;
        body_start = c.off;                            // real vin count starts here
        vin = pc_varint(&c);
    }
    if (c.err || vin == 0 || vin > 1000) return fail(why, whycap, "auxpow: bad coinbase vin");
    const uint8_t *script = NULL; uint64_t script_len = 0;
    for (uint64_t i = 0; i < vin && !c.err; i++) {
        pc_take(&c, 36);
        uint64_t sl = pc_varint(&c);
        if (sl > 100000) { c.err = 1; break; }
        const uint8_t *s = pc_take(&c, sl);
        if (i == 0) { script = s; script_len = sl; }
        pc_u32(&c);                                    // sequence
    }
    uint64_t vout = pc_varint(&c);
    if (c.err || vout > 10000) return fail(why, whycap, "auxpow: bad coinbase vout");
    for (uint64_t i = 0; i < vout && !c.err; i++) {
        pc_take(&c, 8);
        uint64_t sl = pc_varint(&c);
        if (sl > 100000) { c.err = 1; break; }
        pc_take(&c, sl);
    }
    size_t body_end = c.off;                           // end of outputs (before witness)
    if (segwit) {                                      // skip one witness stack per input
        for (uint64_t i = 0; i < vin && !c.err; i++) {
            uint64_t items = pc_varint(&c);
            if (items > 100000) { c.err = 1; break; }
            for (uint64_t j = 0; j < items && !c.err; j++) {
                uint64_t wl = pc_varint(&c);
                if (wl > 100000) { c.err = 1; break; }
                pc_take(&c, wl);
            }
        }
    }
    pc_u32(&c);                                        // locktime
    if (c.err || !script) return fail(why, whycap, "auxpow: coinbase parse");
    size_t cb_end = c.off;
    uint8_t cb_hash[32];
    if (segwit) {                                      // txid over non-witness bytes
        SHA256_CTX hc; uint8_t t[32];
        sha256_init(&hc);
        sha256_update(&hc, raw + cb_start, 4);                     // version
        sha256_update(&hc, raw + body_start, body_end - body_start); // vin..vout
        sha256_update(&hc, raw + cb_end - 4, 4);                   // locktime
        sha256_final(&hc, t);
        sha256_init(&hc); sha256_update(&hc, t, 32); sha256_final(&hc, cb_hash);
    } else {
        sha256d(raw + cb_start, cb_end - cb_start, cb_hash);
    }
    pc_take(&c, 32);                                   // hashBlock (informational)
    uint64_t nmb = pc_varint(&c);                      // coinbase merkle branch
    if (c.err || nmb > 64) return fail(why, whycap, "auxpow: coinbase branch");
    const uint8_t *mb = pc_take(&c, nmb * 32);
    uint32_t mb_index = pc_u32(&c);
    uint64_t ncb = pc_varint(&c);                      // chain merkle branch
    if (c.err || ncb > 30) return fail(why, whycap, "auxpow: chain branch too long");
    const uint8_t *chb = pc_take(&c, ncb * 32);
    uint32_t ch_index = pc_u32(&c);
    const uint8_t *parent = pc_take(&c, 80);
    if (c.err) return fail(why, whycap, "auxpow: truncated");
    if (mb_index != 0) return fail(why, whycap, "auxpow: coinbase branch index != 0");
    uint32_t parent_ver = (uint32_t)parent[0] | (uint32_t)parent[1] << 8 | (uint32_t)parent[2] << 16 | (uint32_t)parent[3] << 24;
    if ((parent_ver >> 16) == pp->aux_chain_id)
        return fail(why, whycap, "auxpow: parent has our chain id");
    // coinbase really is the parent's first tx
    uint8_t root[32];
    memcpy(root, cb_hash, 32);
    branch_apply(root, mb, (int)nmb, 0);
    if (memcmp(root, parent + 36, 32) != 0)
        return fail(why, whycap, "auxpow: coinbase not in parent");
    // our block hash climbs the chain branch to the committed aux root
    uint8_t aux[32];
    sha256d(raw, 80, aux);
    branch_apply(aux, chb, (int)ncb, ch_index);
    uint8_t aux_be[32];                                // committed in reversed order
    for (int i = 0; i < 32; i++) aux_be[i] = aux[31 - i];
    // find the commitment in the parent coinbase scriptSig
    static const uint8_t mm[4] = { 0xfa, 0xbe, 'm', 'm' };
    const uint8_t *head = NULL, *rootp = NULL;
    for (size_t i = 0; script_len >= 4 && i + 4 <= script_len; i++)
        if (!memcmp(script + i, mm, 4)) { head = script + i; break; }
    for (size_t i = 0; script_len >= 32 && i + 32 <= script_len; i++)
        if (!memcmp(script + i, aux_be, 32)) { rootp = script + i; break; }
    if (!rootp) return fail(why, whycap, "auxpow: aux root not committed");
    if (head) {
        for (size_t i = (size_t)(head - script) + 1; i + 4 <= script_len; i++)
            if (!memcmp(script + i, mm, 4))
                return fail(why, whycap, "auxpow: multiple mm headers");
        if (head + 4 != rootp)
            return fail(why, whycap, "auxpow: root not after mm header");
    } else if ((size_t)(rootp - script) > 20)
        return fail(why, whycap, "auxpow: root too deep in coinbase");
    // size + nonce trail the root: size = 2^branch, nonce derives our slot
    if ((size_t)(rootp - script) + 32 + 8 > script_len)
        return fail(why, whycap, "auxpow: no size/nonce after root");
    const uint8_t *tail = rootp + 32;
    uint32_t nsize = (uint32_t)tail[0] | (uint32_t)tail[1] << 8 | (uint32_t)tail[2] << 16 | (uint32_t)tail[3] << 24;
    uint32_t nonce = (uint32_t)tail[4] | (uint32_t)tail[5] << 8 | (uint32_t)tail[6] << 16 | (uint32_t)tail[7] << 24;
    if (nsize != (1u << ncb)) return fail(why, whycap, "auxpow: size != 2^branch");
    uint32_t rand = nonce;                             // Core's expected-index PRNG
    rand = rand * 1103515245u + 12345u;
    rand += pp->aux_chain_id;
    rand = rand * 1103515245u + 12345u;
    if (ch_index != rand % nsize) return fail(why, whycap, "auxpow: wrong chain slot");
    // finally: the parent header carries the work
    idx_pow_hash(parent, pow);
    if (cmp256(pow, target) > 0) return fail(why, whycap, "auxpow: insufficient work");
    if (consumed) *consumed = c.off;                   // header + full AuxPoW span
    return 1;
}

// ── selftest ──────────────────────────────────────────────────────────────────
int idx_pow_selftest(void) {
    int bad = 0;
    // RFC 7914 §12: scrypt(P="", S="", N=16, r=1, p=1, dkLen=64)
    static const uint8_t rfc[64] = {
        0x77,0xd6,0x57,0x62,0x38,0x65,0x7b,0x20,0x3b,0x19,0xca,0x42,0xc1,0x8a,0x04,0x97,
        0xf1,0x6b,0x48,0x44,0xe3,0x07,0x4a,0xe8,0xdf,0xdf,0xfa,0x3f,0xed,0xe2,0x14,0x42,
        0xfc,0xd0,0x06,0x9d,0xed,0x09,0x48,0xf8,0x32,0x6a,0x75,0x3a,0x0f,0xc8,0x1f,0x17,
        0xe8,0xd3,0xe0,0xfb,0x2e,0x0d,0x36,0x28,0xcf,0x35,0xe2,0x0c,0x38,0xd1,0x89,0x06 };
    uint8_t dk[64];
    scrypt_r1p1((const uint8_t *)"", 0, 16, dk, 64);
    if (memcmp(dk, rfc, 64) != 0) { fprintf(stderr, "  FAIL pow: RFC 7914 scrypt vector\n"); bad++; }
    // compact round-trips (values off the real chains)
    static const uint32_t cases[] = { 0x1e0fffff, 0x1a009a69, 0x1a00969d, 0x1b101234 };
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        uint8_t t[32];
        if (!bits_to_target(cases[i], t) || target_to_bits(t) != cases[i]) {
            fprintf(stderr, "  FAIL pow: compact round-trip 0x%08x\n", cases[i]); bad++;
        }
    }
    // Digishield fixpoint: solve time exactly 60 s keeps the target
    if (idx_pow_next_bits(0x1a009a69, 1000060, 1000000, 0x1e0fffff) != 0x1a009a69) {
        fprintf(stderr, "  FAIL pow: digishield 60s fixpoint\n"); bad++;
    }
    // clamps: instant blocks harden by 45/60, a stall softens by at most 90/60
    { uint8_t a[32], b[32];
      bits_to_target(idx_pow_next_bits(0x1a009a69, 1000000, 1000000, 0x1e0fffff), a);
      bits_to_target(0x1a009a69, b);
      if (cmp256(a, b) >= 0) { fprintf(stderr, "  FAIL pow: digishield min clamp\n"); bad++; }
      bits_to_target(idx_pow_next_bits(0x1a009a69, 1009999, 1000000, 0x1e0fffff), a);
      if (cmp256(a, b) <= 0) { fprintf(stderr, "  FAIL pow: digishield max clamp\n"); bad++; } }
    // ── cumulative work (GetBlockProof) ──────────────────────────────────────
    // helper: read a work value's low 64 bits (LE) as a uint64
    #define WLO(w) ((uint64_t)(w)[0] | (uint64_t)(w)[1]<<8 | (uint64_t)(w)[2]<<16 | \
                    (uint64_t)(w)[3]<<24 | (uint64_t)(w)[4]<<32 | (uint64_t)(w)[5]<<40 | \
                    (uint64_t)(w)[6]<<48 | (uint64_t)(w)[7]<<56)
    { uint8_t w[32];
      // Bitcoin difficulty-1 (0x1d00ffff): chainwork per block == 0x100010001.
      idx_pow_work(0x1d00ffff, w);
      int hi = 0; for (int i = 8; i < 32; i++) if (w[i]) hi = 1;
      if (hi || WLO(w) != 0x100010001ULL) { fprintf(stderr, "  FAIL pow: work(0x1d00ffff) != 0x100010001\n"); bad++; }
      // powLimit 0x1e0fffff: floor(2^256/(target+1)) == 1048577.
      idx_pow_work(0x1e0fffff, w);
      hi = 0; for (int i = 8; i < 32; i++) if (w[i]) hi = 1;
      if (hi || WLO(w) != 1048577ULL) { fprintf(stderr, "  FAIL pow: work(0x1e0fffff) != 1048577\n"); bad++; }
      // invalid nBits → zero work
      idx_pow_work(0, w);
      hi = 0; for (int i = 0; i < 32; i++) if (w[i]) hi = 1;
      if (hi) { fprintf(stderr, "  FAIL pow: work(0) != 0\n"); bad++; }
      // harder target ⇒ strictly more work; add is exact; cmp is ordered
      uint8_t easy[32], hard[32], sum[32];
      idx_pow_work(0x1e0fffff, easy); idx_pow_work(0x1d00ffff, hard);
      if (idx_pow_work_cmp(hard, easy) <= 0) { fprintf(stderr, "  FAIL pow: work cmp order\n"); bad++; }
      memcpy(sum, easy, 32); idx_pow_work_add(sum, easy);    // 2*work(easy)
      if (WLO(sum) != 2 * 1048577ULL) { fprintf(stderr, "  FAIL pow: work add\n"); bad++; }
      if (idx_pow_work_cmp(sum, easy) <= 0 || idx_pow_work_cmp(easy, easy) != 0) { fprintf(stderr, "  FAIL pow: work cmp\n"); bad++; } }
    #undef WLO
    return bad;
}
