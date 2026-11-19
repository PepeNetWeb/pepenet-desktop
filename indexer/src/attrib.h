// attrib.h — §4 stateless identity & attribution for REAL Dogecoin txs.
//
// Ports protocol-sm's attrib.c byte-logic (strict-DER + low-S, canonical pubkey
// encoding, P2PKH + P2SH-multisig template + in-order scan, legacy sighash WITH
// FindAndDelete, SIGHASH_ALL-only, Identity = RIPEMD160(SHA256(x))) onto a real
// varint tx parser, with the curve ops resolved by the libsecp shim (NOT the
// reference's injected oracle). This is the production §4 the GUI's P2PKH-only
// attribution never grew into.
#ifndef IDX_ATTRIB_H
#define IDX_ATTRIB_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// status taxonomy (matches the §13 reference): 0 classify-drop, 1 on-curve-drop,
// 2 verify-drop, 3 FOUND. Only FOUND yields a usable identity that also (by
// construction, since every sig's hashtype byte must be 0x01) signs SIGHASH_ALL.
enum { IDX_ATTR_CLASSIFY = 0, IDX_ATTR_ONCURVE = 1, IDX_ATTR_VERIFY = 2, IDX_ATTR_FOUND = 3 };

typedef struct {
    int     status;
    uint8_t identity[20];      // hash160 (bare; type-agnostic key)
    uint8_t type;              // 0 = P2PKH, 1 = P2SH multisig
    uint8_t sighash[32];       // legacy sighash computed for the input (diagnostic)
} IdxAttr;

// Attribute input `k` of a whole serialized (non-witness) tx. Returns the status;
// on IDX_ATTR_FOUND, out->identity/type are the §4 acting identity for that input.
int idx_attribute(const uint8_t *rawtx, size_t rawlen, int k, IdxAttr *out);

#ifdef __cplusplus
}
#endif

#endif
