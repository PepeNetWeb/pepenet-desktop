// wire.h — the Dogecoin-family wire primitives shared by every pepenet overlay.
//
// CompactSize varints + little-endian u32, byte-for-byte the encoding the chain
// itself uses (and the vpost mesh, and the namespace protocol) — so an overlay
// message and its on-chain escape-hatch form serialize identically. No I/O, no
// allocation, no globals.
#ifndef PEPENET_WIRE_H
#define PEPENET_WIRE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// CompactSize: <0xFD raw · 0xFD u16 · 0xFE u32 · 0xFF u64, all little-endian.
int      sp_wvar(uint8_t *o, uint64_t v);                        // bytes written (1/3/5/9)
int      sp_rvar(const uint8_t *c, int len, int *off, uint64_t *v); // 1 ok · 0 overrun/malformed

int      sp_wle32(uint8_t *o, uint32_t v);                       // always 4
uint32_t sp_rle32(const uint8_t *c);                             // reads 4 (caller bounds-checks)

#ifdef __cplusplus
}
#endif

#endif
