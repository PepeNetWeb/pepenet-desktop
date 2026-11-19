// §4 Strategy B — real secp256k1 (self-rolled, zero external deps).
//
// Replaces the injected curve oracle in the §4 attribution shell with genuine
// elliptic-curve math: field arithmetic mod p = 2^256 − 2^32 − 977, point ops in
// Jacobian coordinates, ECDSA verify, and RFC-6979 deterministic signing (so the
// accept path is cross-language reproducible without randomness). NOT constant
// time — this is a verifier/test oracle, never touches secret keys in production.
// Pinned in SPEC-conformance.md §13 (curve-vector set) + SPEC-RATIONALE.md §11.
#ifndef SM_SECP256K1_H
#define SM_SECP256K1_H

#include <stdint.h>

// on-curve test on a canonically-ENCODED pubkey: 33-byte compressed (0x02/0x03)
// or 65-byte uncompressed (0x04). Returns 1 iff the decoded point lies on the
// curve (and, for compressed keys, the X coordinate has a square root). Anything
// else (bad length/prefix, X≥p, non-residue) → 0. Encoding canonicality is the
// caller's job (§4 pub_enc_ok); this is purely the curve membership test.
int secp_on_curve(const uint8_t *pub, int plen);

// ECDSA verify. r32/s32 are the 32-byte big-endian scalar VALUES (low-S is the
// DER layer's concern, not enforced here). Returns 1 iff the signature is valid
// for the given message hash and pubkey.
int secp_ecdsa_verify(const uint8_t hash32[32], const uint8_t r32[32],
                      const uint8_t s32[32], const uint8_t *pub, int plen);

// RFC-6979 deterministic ECDSA sign (HMAC-SHA256 nonce), low-S normalized.
// Writes 32-byte big-endian r,s. Returns 1 on success, 0 if priv is 0 or ≥ n.
int secp_ecdsa_sign(const uint8_t priv32[32], const uint8_t hash32[32],
                    uint8_t r32[32], uint8_t s32[32]);

// derive the 33-byte compressed pubkey from a private scalar. 1 on success.
int secp_pubkey(const uint8_t priv32[32], uint8_t pub33[33]);

// self-check: pinned P/N/N_HALF/G constants + 2G KAT + n·G=∞ + decompress and
// sign/verify round-trips. Returns 0 on success, nonzero (count) on any failure.
int secp_selftest(void);

// ── ECMH (Elliptic Curve Multiset Hash) — incremental state digest primitive ────
// A running accumulator is an opaque 33-byte value: a compressed curve point
// (0x02/0x03 ‖ X-be), or the all-zero sentinel for the identity (point at ∞).
// hash-to-curve is try-and-increment over SHA-256; H2C always yields the EVEN-Y
// root (prefix 0x02), so a point's negation is a one-bit prefix flip. The combine
// is commutative + invertible: add/remove a record's point in O(1) without
// re-reading the rest of the state. Pinned in SPEC-conformance.md §13.2.

// acc ← identity (∞): 33 zero bytes.
void secp_ecmh_identity(uint8_t acc33[33]);

// pt ← hash_to_curve("ECMHh2c1" ‖ pre[len] ‖ ctr_le32), first ctr whose candidate
// x = SHA256(...) mod p has x³+7 a quadratic residue; y forced even. Returns ctr.
int secp_ecmh_hash(const uint8_t *pre, int len, uint8_t pt33[33]);

// pt ← −pt (negate): flip the compressed parity bit; ∞ is its own inverse (no-op).
void secp_ecmh_negate(uint8_t pt33[33]);

// acc ← acc + pt (curve point addition; either operand may be ∞).
void secp_ecmh_add(uint8_t acc33[33], const uint8_t pt33[33]);

// ECMH algebra self-check (identity / commutativity / inverse / KAT). 0 on success.
int secp_ecmh_selftest(void);

#endif
