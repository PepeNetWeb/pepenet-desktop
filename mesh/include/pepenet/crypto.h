// crypto.h — the shared crypto facade for pepenet overlays.
//
// One small surface over the AUDITED primitives the rest of the family already
// pins: protocol-sm's byte-locked SHA-256 / RIPEMD-160, and ALL curve math on the
// vendored constant-time libsecp256k1 (via secp_shim.c). Nothing here rolls its
// own field arithmetic — an overlay daemon that verifies zone signatures or signs
// with a hot key gets the same crypto the indexer and carrier do.
//
// Identity model (unchanged across the family): an owner is a 20-byte hash160 of
// a 33-byte compressed secp256k1 pubkey. The on-chain `names.owner` blob IS that
// hash160. So "does this key own this name?" is hash160(pub) == owner, and an
// overlay authenticates a blob by (1) checking the signer's key hashes to the
// on-chain owner and (2) verifying the signature over the blob.
//
// Names are pure decoration on that identity. Consensus name rules (§3.1) live
// here so every overlay (DNS apex, overlay handles, …) refuses the same labels the
// fold refuses — reject, never case-fold.
#ifndef PEPENET_CRYPTO_H
#define PEPENET_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// §3.1: a DNS host label, lowercased — [a-z0-9-], 1..32.
#define SP_NAME_MAX  32

// ── hashes ───────────────────────────────────────────────────────────────────
void sp_sha256 (const uint8_t *d, size_t n, uint8_t out[32]);
void sp_sha256d(const uint8_t *d, size_t n, uint8_t out[32]);   // SHA256(SHA256(d))
void sp_hash160(const uint8_t *d, size_t n, uint8_t out[20]);   // RIPEMD160(SHA256(d))

// ── secp256k1 (compressed 33-byte pubkeys, 32-byte r‖s signatures) ───────────
// Derive the compressed pubkey for a private key. 1 ok · 0 invalid key.
int  sp_pubkey(const uint8_t priv[32], uint8_t pub33[33]);
// Sign a 32-byte digest (low-S, deterministic). 1 ok · 0 fail. Writes r‖s.
int  sp_ecdsa_sign(const uint8_t priv[32], const uint8_t digest[32], uint8_t sig64[64]);
// Verify r‖s over a digest against a compressed/uncompressed pubkey. 1 ok · 0 no.
int  sp_ecdsa_verify(const uint8_t digest[32], const uint8_t sig64[64],
                     const uint8_t *pub, int publen);

// Convenience: does `pub` hash160 to `owner`? (the ownership gate). 1/0.
int  sp_key_is_owner(const uint8_t *pub, int publen, const uint8_t owner[20]);

// §3.1 name validation — byte-identical to protocol-sm's sm_name_valid:
//   charset [a-z0-9-] (no case-folding: 'A' is invalid, not lower-cased),
//   length 1..SP_NAME_MAX,
//   no leading/trailing hyphen,
//   no '--' at positions 3–4 (kills xn-- and every ACE prefix).
// 1 valid · 0 invalid. name may be non-NUL-terminated; only the first `len` bytes count.
int  sp_name_valid(const char *name, size_t len);

// ── Base58Check addresses (display layer; state keys on the naked hash160) ───
// version+payload with a 4-byte sha256d checksum. 1 ok · 0 buffer too small.
int  sp_addr_encode(uint8_t version, const uint8_t *payload, size_t n,
                    char *out, size_t out_max);
// decode+verify checksum. 1 ok (fills *version, payload, *payload_len) · 0 bad.
int  sp_addr_decode(const char *s, uint8_t *version,
                    uint8_t *payload, size_t payload_max, size_t *payload_len);

#ifdef __cplusplus
}
#endif

#endif
