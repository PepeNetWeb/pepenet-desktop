// snapshot.h — offline snapshot header walk (idx-01).
//
// A snapshot is folded state at height H plus its §13.2 digests. Before trusting
// it, a verifier walks the host chain's headers from the profile checkpoint up to
// H: linkage (each prev-hash = sha256d of the last), PoW (scrypt / AuxPoW <=
// target via idx_pow_check2) and the per-block Digishield nBits, and finally the
// last header's hash must be the snapshot's tip. Pure: no db, no network, never
// wired into sync. See docs/SNAPSHOT.md.
#ifndef IDX_SNAPSHOT_H
#define IDX_SNAPSHOT_H
#include <stddef.h>
#include <stdint.h>

typedef struct {
    int64_t  h;              // height of the last accepted header (seed: checkpoint)
    uint8_t  hash[32];       // its hash, internal byte order
    uint32_t bits;           // its nBits (0 = unknown → skip the Digishield check once)
    int64_t  time, prev_time;// its time and its parent's time
    uint32_t powlimit, aux_chain_id;
    int      check_pow;      // 0 = linkage only (powlimit-0 fixture profiles)
    uint8_t  work[32];       // Σ proof-of-work accepted (256-bit LE)
    int64_t  n;              // headers accepted
} IdxSnapWalk;

// Walk one buffer of concatenated `headers` message bodies (varint count, then
// count × (header[+auxpow] + tx-count varint)). Returns 1 when every header is
// accepted, 0 on the first bad one (reason in why; w->h is the last good height).
int idx_snap_walk(IdxSnapWalk *w, const uint8_t *buf, size_t len, char *why, size_t cap);

#endif

// ── idx-04: whole-file SHA-256 pin ───────────────────────────────────────────
// Trust model: a snapshot is trusted ONLY if the SHA-256 of its state.db file
// (the whole file, as shipped) equals an expected pin supplied out of band —
// a `--snapshot-sha256 <hex>` flag, or the compiled-in per-chain default. The
// pin is checked BEFORE the file is opened as sqlite, parsed or applied. The
// on-disk snapshot format (state.db + MANIFEST) is unchanged.
//
// Embedding hook: build with -DIDX_SNAPSHOT_PIN_PEP=\"<64 hex>\" and/or
// -DIDX_SNAPSHOT_PIN_DOGE=\"<64 hex>\" to compile in a default. Empty (the
// default) = no compiled pin: an import with no flag is refused.
#ifndef IDX_SNAPSHOT_PIN_PEP
#define IDX_SNAPSHOT_PIN_PEP ""
#endif
#ifndef IDX_SNAPSHOT_PIN_DOGE
#define IDX_SNAPSHOT_PIN_DOGE ""
#endif
// The compiled-in default for a coin ("pep"/"pepe" or "doge"), or NULL if none.
const char *idx_snap_default_pin(const char *coin);
// Resolve the effective pin: flag (non-NULL) overrides the default. Returns the
// hex string to use, or NULL when neither is set.
const char *idx_snap_effective_pin(const char *coin, const char *flag_hex);
// Exactly 64 hex digits (either case) → 32 bytes. 1 ok, 0 malformed.
int idx_snap_parse_pin(const char *hex, uint8_t out[32]);
// Streamed SHA-256 of a whole file. 1 ok, 0 unreadable. *size gets the length.
int idx_snap_file_sha256(const char *path, uint8_t out[32], int64_t *size);
// Check `path` against `pin_hex`. 1 = match; 0 = refused (why says: no pin,
// malformed pin, unreadable, or mismatch with the actual hash).
int idx_snap_pin_check(const char *path, const char *pin_hex, char *why, size_t cap);
