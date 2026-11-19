// pow.h — proof-of-work validation for the Doge-family host chains (SPV-grade).
//
// Three layers, matching Core's CheckAuxPowProofOfWork:
//   • target sanity: nBits decodes to 0 < target ≤ powLimit;
//   • the work itself: scrypt(own header) ≤ target for direct-mined blocks, or
//     the full AuxPoW check for merged-mined ones — coinbase merkle branch to
//     the parent's root, the aux-root commitment in the parent coinbase
//     (0xfa 0xbe 'm' 'm' rules, size = 2^branch, nonce→expected-index), strict
//     chain-id rules, then scrypt(parent header) ≤ our target;
//   • context: per-block Digishield retarget (the expected nBits for a block
//     given its parent's bits + solve time) — computed by the caller from the
//     blocks table, compared compact-to-compact exactly like Core.
//
// Everything an attacker controls is bounds-checked; everything consensus-
// critical mirrors Core's integer semantics (truncating division, uint32
// wrap in the expected-index PRNG, compact round-trip through GetCompact).
#ifndef IDX_POW_H
#define IDX_POW_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t powlimit;      // compact form (doge family: 0x1e0fffff)
    uint32_t aux_chain_id;  // consensus nAuxpowChainId; strict rules assumed
                            // (both host profiles checkpoint far past legacy)
} PowParams;

// Stateless work check on a raw block (header + optional AuxPoW + txs).
// Returns 1 ok; 0 invalid with a short reason in why.
int idx_pow_check(const uint8_t *raw, size_t len, const PowParams *pp,
                  char *why, size_t whycap);

// As idx_pow_check, but also reports how many bytes the header + AuxPoW occupy
// (80 for a direct-mined block, 80 + the AuxPoW for a merged-mined one) in
// *consumed — the span before the tx count. Lets a caller walk a `headers`
// message (each element = header[+auxpow] + a 0 tx-count varint) or a block's
// tx section. *consumed is set only on success (return 1).
int idx_pow_check2(const uint8_t *raw, size_t len, const PowParams *pp,
                   size_t *consumed, char *why, size_t whycap);

// ── cumulative work (most-work chain selection) ──────────────────────────────
// Per-block proof = floor(2^256 / (target+1)), the arith_uint256 GetBlockProof:
// how many hashing attempts the target implies. work[32] is 256-bit little-
// endian. bits that don't decode to a positive target yield 0 work.
void idx_pow_work(uint32_t bits, uint8_t work[32]);
// acc += add, 256-bit little-endian (wraps mod 2^256 — chainwork never nears it).
void idx_pow_work_add(uint8_t acc[32], const uint8_t add[32]);
// -1 / 0 / 1 for a < b / == / > (256-bit little-endian).
int  idx_pow_work_cmp(const uint8_t a[32], const uint8_t b[32]);

// Per-block Digishield: the expected compact nBits for the block AFTER the one
// described by (prev_bits, prev_time), where prevprev_time is its parent's
// timestamp. 60 s target, ±modulation clamped to [45,90], capped at powLimit.
uint32_t idx_pow_next_bits(uint32_t prev_bits, int64_t prev_time,
                           int64_t prevprev_time, uint32_t powlimit);

// scrypt(1024,1,1) of an 80-byte header — the Doge-family PoW hash, exposed
// for tests. out32 is the hash in internal (little-endian uint256) order.
void idx_pow_hash(const uint8_t hdr[80], uint8_t out32[32]);

// Self-check: RFC 7914 scrypt vector, compact round-trips, a Digishield
// sample. Returns 0 ok, else the number of failures (prints to stderr).
int idx_pow_selftest(void);

#ifdef __cplusplus
}
#endif

#endif
