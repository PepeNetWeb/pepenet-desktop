// base58.h — Base58Check for Dogecoin-family addresses (display layer only;
// the indexer's state keys on naked hash160 — see host-profiles.md).
#ifndef IDX_BASE58_H
#define IDX_BASE58_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Encode version+payload with a 4-byte sha256d checksum. Returns 1, or 0 if
// out is too small. Typical address: payload = hash160 (20 bytes).
int idx_b58check_encode(uint8_t version, const uint8_t *payload, size_t n,
                        char *out, size_t out_max);
// Decode + verify checksum. On success returns 1 and fills *version + payload
// (payload_max bytes available, *payload_len set). 0 on bad char/checksum/size.
int idx_b58check_decode(const char *s, uint8_t *version,
                        uint8_t *payload, size_t payload_max, size_t *payload_len);

#ifdef __cplusplus
}
#endif

#endif
