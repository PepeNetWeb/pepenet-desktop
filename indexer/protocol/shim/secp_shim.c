// secp_shim.c — protocol-sm's secp256k1.h, re-implemented on the audited
// vendored libsecp256k1 (Bitcoin Core).
//
// WHY: the headless indexer must NOT ship the self-rolled, non-constant-time
// field/scalar/point arithmetic from protocol-sm's secp256k1.c — if copied into a
// wallet it would leak secret-key bits. This binary needs only PUBLIC-key ops:
// ECDSA *verify* (§4 attribution) and ECMH point algebra (§13.2 state digest).
// Every secret-key path here (sign / pubkey-derive) exists solely so the linked
// engine's optional self-checks resolve; the indexer never calls them with a real
// key. The math is delegated to libsecp; this file is pure glue.
//
// Byte-for-byte compatibility with the self-rolled reference is REQUIRED so the
// ECMH digest reproduces the pinned goldens (SPEC-conformance §13.2): same H2C
// tag "ECMHh2c1", same x = SHA256(tag‖pre‖ctr_le32) mod p, same even-Y root, same
// ∞=33-zero sentinel, same compressed encoding. Verified against `sm ecmh`.
// We DEFINE the secp_* functions protocol-sm's secp256k1.h declares; the linker
// matches by symbol, so we don't include that (name-colliding) header here. The
// signatures are mirrored from it by hand.
#include <secp256k1.h>        // the vendored library (angle: resolves to vendor/.../include)
#include "sha256.h"           // protocol-sm's SHA-256 (same bytes as the reference)
#include <stdint.h>
#include <string.h>

// mirrored prototypes (from protocol-sm/impls/c/src/secp256k1.h)
int  secp_on_curve(const uint8_t *pub, int plen);
int  secp_ecdsa_verify(const uint8_t h[32], const uint8_t r[32], const uint8_t s[32], const uint8_t *pub, int plen);
int  secp_ecdsa_sign(const uint8_t priv[32], const uint8_t h[32], uint8_t r[32], uint8_t s[32]);
int  secp_pubkey(const uint8_t priv[32], uint8_t pub33[33]);
int  secp_selftest(void);
void secp_ecmh_identity(uint8_t acc33[33]);
int  secp_ecmh_hash(const uint8_t *pre, int len, uint8_t pt33[33]);
void secp_ecmh_negate(uint8_t pt33[33]);
void secp_ecmh_add(uint8_t acc33[33], const uint8_t pt33[33]);
int  secp_ecmh_selftest(void);

// One global verify/sign context. The static context handles verify + ECMH point
// ops; signing through it is unrandomized but only the (never-in-production) self
// checks use it. No per-call allocation.
#define CTX secp256k1_context_static

// p = 2^256 − 2^32 − 977, big-endian.
static const uint8_t P_BE[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F };

// x ← x mod p, for a 32-byte BE x < 2^256 (so x < 2p ⇒ at most one subtract).
static void mod_p_once(uint8_t x[32]) {
    int ge = 0;                                   // x >= p ?
    for (int i = 0; i < 32; i++) { if (x[i] != P_BE[i]) { ge = x[i] > P_BE[i]; break; } if (i == 31) ge = 1; }
    if (!ge) return;
    int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int d = (int)x[i] - (int)P_BE[i] - borrow;
        if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
        x[i] = (uint8_t)d;
    }
}

// Canonical SEC1 prefix gate — the self-rolled reference accepts ONLY 0x02/0x03 for
// 33-byte and 0x04 for 65-byte keys. libsecp's ec_pubkey_parse ALSO accepts the
// 65-byte HYBRID forms (0x06/0x07); admitting those here would make the shim accept
// a key the pure impls reject → a consensus split for any direct caller. Reject them
// before delegating so the shim and the reference accept exactly the same set.
static int sec1_prefix_ok(const uint8_t *pub, int plen) {
    if (plen == 33) return pub[0] == 0x02 || pub[0] == 0x03;
    if (plen == 65) return pub[0] == 0x04;
    return 0;
}

// ── on-curve (canonical-ENCODING is the caller's job, per §4) ─────────────────
int secp_on_curve(const uint8_t *pub, int plen) {
    if (!sec1_prefix_ok(pub, plen)) return 0;
    secp256k1_pubkey pk;
    return secp256k1_ec_pubkey_parse(CTX, &pk, pub, (size_t)plen) ? 1 : 0;
}

// ── ECDSA verify. r32/s32 are raw 32-byte BE scalar VALUES (low-S is enforced
// upstream at the DER layer per §4; we normalize so high-S still verifies, exactly
// like the self-rolled reference which left low-S to the caller). ───────────────
int secp_ecdsa_verify(const uint8_t hash32[32], const uint8_t r32[32],
                      const uint8_t s32[32], const uint8_t *pub, int plen) {
    if (!sec1_prefix_ok(pub, plen)) return 0;               // reject hybrid (0x06/0x07), match pure impls
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_parse(CTX, &pk, pub, (size_t)plen)) return 0;
    uint8_t compact[64];
    memcpy(compact, r32, 32); memcpy(compact + 32, s32, 32);
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_compact(CTX, &sig, compact)) return 0;
    secp256k1_ecdsa_signature_normalize(CTX, &sig, &sig);   // accept high-S
    return secp256k1_ecdsa_verify(CTX, &sig, hash32, &pk) ? 1 : 0;
}

// ── secret-key paths (NOT used by indexing; only the offline test signs). These
// need a gen-table context the static one lacks; created lazily so the default
// indexing path still allocates no signing infrastructure. ───────────────────
static const secp256k1_context *signctx(void) {
    static secp256k1_context *c = NULL;
    if (!c) c = secp256k1_context_create(SECP256K1_CONTEXT_NONE);  // modern libsecp: can sign+verify
    return c;
}

int secp_ecdsa_sign(const uint8_t priv32[32], const uint8_t hash32[32],
                    uint8_t r32[32], uint8_t s32[32]) {
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(signctx(), &sig, hash32, priv32, NULL, NULL)) return 0;
    uint8_t compact[64];
    secp256k1_ecdsa_signature_serialize_compact(CTX, compact, &sig);  // low-S
    memcpy(r32, compact, 32); memcpy(s32, compact + 32, 32);
    return 1;
}

int secp_pubkey(const uint8_t priv32[32], uint8_t pub33[33]) {
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(signctx(), &pk, priv32)) return 0;
    size_t n = 33;
    return secp256k1_ec_pubkey_serialize(CTX, pub33, &n, &pk, SECP256K1_EC_COMPRESSED) ? 1 : 0;
}

int secp_selftest(void) { return 0; }   // curve constants are libsecp's concern

// ── ECMH (incremental multiset hash) — §13.2 ─────────────────────────────────
// Accumulator/point = 33 bytes: compressed point (0x02/0x03 ‖ X-be) or 33 zeros
// for the identity (point at ∞, which libsecp has no pubkey for — handled here).

void secp_ecmh_identity(uint8_t acc33[33]) { memset(acc33, 0, 33); }

// pt ← hash_to_curve("ECMHh2c1" ‖ pre[len] ‖ ctr_le32): first ctr whose candidate
// x = SHA256(...) mod p is a valid even-Y point. Identical to the self-rolled
// reference (same tag, reduction, even-Y root) — so the ECMH goldens hold.
int secp_ecmh_hash(const uint8_t *pre, int len, uint8_t pt33[33]) {
    static const uint8_t TAG[8] = { 'E','C','M','H','h','2','c','1' };
    for (int ctr = 0; ; ctr++) {
        SHA256_CTX c; sha256_init(&c);
        sha256_update(&c, TAG, 8);
        if (len > 0) sha256_update(&c, pre, (unsigned)len);
        uint8_t cb[4] = { (uint8_t)ctr, (uint8_t)(ctr >> 8), (uint8_t)(ctr >> 16), (uint8_t)(ctr >> 24) };
        sha256_update(&c, cb, 4);
        uint8_t h[32]; sha256_final(&c, h);
        mod_p_once(h);                                     // x = SHA256(...) mod p
        uint8_t cand[33]; cand[0] = 0x02; memcpy(cand + 1, h, 32);
        secp256k1_pubkey pk;                               // parse 0x02‖x: succeeds iff x³+7 is a QR
        if (secp256k1_ec_pubkey_parse(CTX, &pk, cand, 33)) { memcpy(pt33, cand, 33); return ctr; }
        // else x is not the X of a curve point → bump ctr (matches reference)
    }
}

void secp_ecmh_negate(uint8_t pt33[33]) { if (pt33[0]) pt33[0] ^= 1; }  // even↔odd Y; ∞ is its own inverse

void secp_ecmh_add(uint8_t acc33[33], const uint8_t pt33[33]) {
    int acc_inf = (acc33[0] == 0), pt_inf = (pt33[0] == 0);
    if (pt_inf) return;                       // acc + ∞ = acc
    if (acc_inf) { memcpy(acc33, pt33, 33); return; }   // ∞ + pt = pt
    secp256k1_pubkey a, b;
    if (!secp256k1_ec_pubkey_parse(CTX, &a, acc33, 33) ||
        !secp256k1_ec_pubkey_parse(CTX, &b, pt33, 33)) { return; }   // shouldn't happen on valid accs
    const secp256k1_pubkey *ins[2] = { &a, &b };
    secp256k1_pubkey r;
    if (!secp256k1_ec_pubkey_combine(CTX, &r, ins, 2)) { memset(acc33, 0, 33); return; }  // sum = ∞
    size_t n = 33;
    secp256k1_ec_pubkey_serialize(CTX, acc33, &n, &r, SECP256K1_EC_COMPRESSED);
}

int secp_ecmh_selftest(void) { return 0; }
