// RIPEMD-160 — the second hash primitive §4 attribution needs (Identity =
// RIPEMD160(SHA256(x))). Self-rolled, deterministic, zero deps; pinned in
// SPEC-conformance.md §13. Test vectors: ""→9c1185a5…, "abc"→8eb208f7….
#ifndef SM_RIPEMD160_H
#define SM_RIPEMD160_H

#include <stddef.h>
#include <stdint.h>

void ripemd160(const uint8_t *msg, size_t len, uint8_t out[20]);

#endif
