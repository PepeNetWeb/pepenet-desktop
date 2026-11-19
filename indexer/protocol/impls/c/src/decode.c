// §1/§2/§3 wire payload codec — the byte layer of the strict, fail-closed parse.
//
// The base fold (fold.c) consumes already-decoded SmCarriers; this file is the
// part a real indexer does FIRST: turn an OP_RETURN payload (the bytes of the
// single minimal push, §1) into ACTION / IGNORE, deterministically and
// byte-for-byte identically across indexers. `sm fuzz` feeds millions of random
// + grammar-perturbed payloads through sm_decode_payload. Pinned in
// SPEC-conformance.md §9; field layouts mirror §2's registry.
#include "sm.h"
#include <string.h>

// ── little-endian field readers/writers ──────────────────────────────────────
static uint32_t rd32(const uint8_t *b) { uint32_t v = 0; for (int i = 0; i < 4; i++) v |= (uint32_t)b[i] << (8*i); return v; }
static uint64_t rd64(const uint8_t *b) { uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)b[i] << (8*i); return v; }
static uint64_t rd5 (const uint8_t *b) { uint64_t v = 0; for (int i = 0; i < 5; i++) v |= (uint64_t)b[i] << (8*i); return v; }
static void     wr32(uint8_t *b, uint32_t v) { for (int i = 0; i < 4; i++) b[i] = (uint8_t)(v >> (8*i)); }
static void     wr64(uint8_t *b, uint64_t v) { for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8*i)); }
static void     wr5 (uint8_t *b, uint64_t v) { for (int i = 0; i < 5; i++) b[i] = (uint8_t)(v >> (8*i)); }

// ── action decode (the part after the 4-byte 0xFF 'P' 'N' opcode header) ─────
// b = payload+4, blen = len-4. Returns 1 with `a` filled (a->op set), else 0.
static int decode_action(const uint8_t *b, size_t blen, uint8_t op, SmAction *a) {
    memset(a, 0, sizeof *a);
    a->op = op;
    switch (op) {
    case SM_OP_COMMIT:
        if (blen != 32) return 0;
        memcpy(a->commitment, b, 32);
        return 1;
    case SM_OP_CLAIM: {                                        // salt(32) + name(1..32)
        if (blen < 33 || blen > 64) return 0;
        memcpy(a->salt, b, 32);
        size_t nl = blen - 32;
        if (!sm_name_valid((const char *)(b + 32), nl)) return 0;
        memcpy(a->name, b + 32, nl); a->name[nl] = 0; a->name_len = (uint8_t)nl;
        return 1;
    }
    case SM_OP_RENEW:                                          // 0=all | 5=all-safe | 6..SM_BODY_MAX=selective
        if (blen == 0) { a->has_anchor = 0; a->flags_len = 0; return 1; }
        if (blen == 5) { a->has_anchor = 1; a->anchor = rd5(b); a->flags_len = 0; return 1; }
        if (blen >= 6 && blen <= SM_BODY_MAX) {
            a->has_anchor = 1; a->anchor = rd5(b);
            size_t fl = blen - 5;                              // 1..SM_FLAGS_MAX
            memcpy(a->flags, b + 5, fl); a->flags_len = (uint16_t)fl;
            return 1;
        }
        return 0;
    case SM_OP_TRANSFER:                                       // 20=all | 26..SM_BODY_MAX=selective
        if (blen == 20) { memcpy(a->addr, b, 20); a->has_anchor = 0; return 1; }
        if (blen >= 26 && blen <= SM_BODY_MAX) {
            memcpy(a->addr, b, 20);
            a->has_anchor = 1; a->anchor = rd5(b + 20);
            size_t fl = blen - 25;                             // 1..SM_FLAGS_XFER_MAX
            memcpy(a->flags, b + 25, fl); a->flags_len = (uint16_t)fl;
            return 1;
        }
        return 0;
    case SM_OP_SELL: {                                         // price(8)+window(4)+name(1..32)
        if (blen < 13 || blen > 44) return 0;
        a->price = rd64(b); a->window = rd32(b + 8);
        size_t nl = blen - 12;
        if (!sm_name_valid((const char *)(b + 12), nl)) return 0;
        memcpy(a->name, b + 12, nl); a->name[nl] = 0; a->name_len = (uint8_t)nl;
        return 1;
    }
    case SM_OP_RENEW_NAME:
    case SM_OP_RELEASE_NAME:
    case SM_OP_RESERVE:
    case SM_OP_SETTLE:
    case SM_OP_PAY: {                                          // name(1..32)
        if (blen < 1 || blen > 32) return 0;
        if (!sm_name_valid((const char *)b, blen)) return 0;
        memcpy(a->name, b, blen); a->name[blen] = 0; a->name_len = (uint8_t)blen;
        return 1;
    }
    case SM_OP_TRANSFER_NAME: {                                // target(20)+name(1..32)
        if (blen < 21 || blen > 52) return 0;
        memcpy(a->addr, b, 20);
        size_t nl = blen - 20;
        if (!sm_name_valid((const char *)(b + 20), nl)) return 0;
        memcpy(a->name, b + 20, nl); a->name[nl] = 0; a->name_len = (uint8_t)nl;
        return 1;
    }
    case SM_OP_RELEASE:                                        // anchor(5)+flags(1..SM_FLAGS_MAX)
        if (blen < 6 || blen > SM_BODY_MAX) return 0;
        a->has_anchor = 1; a->anchor = rd5(b);
        { size_t fl = blen - 5; memcpy(a->flags, b + 5, fl); a->flags_len = (uint16_t)fl; }
        return 1;
    case SM_OP_SELL_TO: {                                      // price(8)+buyer(20)+name(1..32)
        if (blen < 29 || blen > 60) return 0;
        a->price = rd64(b); memcpy(a->addr, b + 8, 20);
        size_t nl = blen - 28;
        if (!sm_name_valid((const char *)(b + 28), nl)) return 0;
        memcpy(a->name, b + 28, nl); a->name[nl] = 0; a->name_len = (uint8_t)nl;
        return 1;
    }
    case SM_OP_AS:                                             // index(1)
        if (blen != 1) return 0;
        a->as_index = b[0];
        return 1;
    case SM_OP_TRADE: {                                        // idxA(1)+idxB(1)+ nameA,nameB
        if (blen < 5) return 0;                                // 2 idx + "a,b" minimum
        a->idx_a = b[0]; a->idx_b = b[1];
        const uint8_t *body = b + 2; size_t bl = blen - 2;
        int comma = -1, count = 0;
        for (size_t i = 0; i < bl; i++) if (body[i] == 0x2C) { count++; comma = (int)i; }
        if (count != 1) return 0;                              // exactly one ','
        size_t la = (size_t)comma, lb = bl - (size_t)comma - 1;
        if (!sm_name_valid((const char *)body, la)) return 0;
        if (!sm_name_valid((const char *)(body + comma + 1), lb)) return 0;
        memcpy(a->name,   body, la);            a->name[la]   = 0; a->name_len   = (uint8_t)la;
        memcpy(a->name_b, body + comma + 1, lb); a->name_b[lb] = 0; a->name_b_len = (uint8_t)lb;
        return 1;
    }
    default:
        return 0;                                             // outside 0x01..0x0F
    }
}

void sm_decode_payload(const uint8_t *payload, size_t len, uint64_t value,
                       const uint8_t magic[2], SmCarrier *car) {
    (void)value;
    memset(&car->act, 0, sizeof car->act);
    car->kind = SM_CAR_IGNORE;
    if (!magic) return;

    // §1 action recognition: prefix 0xFF ‖ magic ‖ opcode 0x01..0x0F.
    // Any other magic (the other chain, or unset 0,0) is IGNORE, like unknown data.
    if (len >= 4 && payload[0] == 0xFF && payload[1] == magic[0] && payload[2] == magic[1]) {
        uint8_t op = payload[3];
        if (op >= SM_OP_MIN && op <= SM_OP_MAX &&
            decode_action(payload + 4, len - 4, op, &car->act))
            car->kind = SM_CAR_ACTION;
        // else IGNORE (malformed / unknown opcode / overlay band)
        return;
    }
    // everything else (other chain, UTF-8 noise, overlay, empty) → IGNORE
    car->kind = SM_CAR_IGNORE;
}

// ── canonical action encoder (inverse of decode_action; grammar-aware fuzz) ──
size_t sm_encode_action(const SmAction *a, const uint8_t magic[2], uint8_t out[SM_CARRIER_MAX]) {
    if (!a || !magic || !out) return 0;
    out[0] = 0xFF; out[1] = magic[0]; out[2] = magic[1]; out[3] = a->op;
    uint8_t *b = out + 4;
    switch (a->op) {
    case SM_OP_COMMIT:
        memcpy(b, a->commitment, 32); return 36;
    case SM_OP_CLAIM:
        if (a->name_len < 1 || a->name_len > 32) return 0;
        memcpy(b, a->salt, 32); memcpy(b + 32, a->name, a->name_len); return 36 + a->name_len;
    case SM_OP_RENEW:
        if (!a->has_anchor && a->flags_len == 0) return 4;                 // all
        if (a->has_anchor && a->flags_len == 0) { wr5(b, a->anchor); return 9; }   // all-safe
        if (a->has_anchor && a->flags_len >= 1 && a->flags_len <= SM_FLAGS_MAX) {
            wr5(b, a->anchor); memcpy(b + 5, a->flags, a->flags_len); return 9 + (size_t)a->flags_len;
        }
        return 0;
    case SM_OP_TRANSFER:
        memcpy(b, a->addr, 20);
        if (!a->has_anchor) return 24;                                     // all
        if (a->flags_len >= 1 && a->flags_len <= SM_FLAGS_XFER_MAX) {
            wr5(b + 20, a->anchor); memcpy(b + 25, a->flags, a->flags_len); return 29 + (size_t)a->flags_len;
        }
        return 0;
    case SM_OP_SELL:
        if (a->name_len < 1 || a->name_len > 32) return 0;
        wr64(b, a->price); wr32(b + 8, a->window); memcpy(b + 12, a->name, a->name_len); return 16 + a->name_len;
    case SM_OP_RENEW_NAME:
    case SM_OP_RELEASE_NAME:
    case SM_OP_RESERVE:
    case SM_OP_SETTLE:
    case SM_OP_PAY:
        if (a->name_len < 1 || a->name_len > 32) return 0;
        memcpy(b, a->name, a->name_len); return 4 + a->name_len;
    case SM_OP_TRANSFER_NAME:
        if (a->name_len < 1 || a->name_len > 32) return 0;
        memcpy(b, a->addr, 20); memcpy(b + 20, a->name, a->name_len); return 24 + a->name_len;
    case SM_OP_RELEASE:
        if (a->flags_len < 1 || a->flags_len > SM_FLAGS_MAX) return 0;
        wr5(b, a->anchor); memcpy(b + 5, a->flags, a->flags_len); return 9 + (size_t)a->flags_len;
    case SM_OP_SELL_TO:
        if (a->name_len < 1 || a->name_len > 32) return 0;
        wr64(b, a->price); memcpy(b + 8, a->addr, 20); memcpy(b + 28, a->name, a->name_len); return 32 + a->name_len;
    case SM_OP_AS:
        b[0] = a->as_index; return 5;
    case SM_OP_TRADE:
        if (a->name_len < 1 || a->name_len > 32 || a->name_b_len < 1 || a->name_b_len > 32) return 0;
        b[0] = a->idx_a; b[1] = a->idx_b;
        memcpy(b + 2, a->name, a->name_len);
        b[2 + a->name_len] = 0x2C;
        memcpy(b + 2 + a->name_len + 1, a->name_b, a->name_b_len);
        return 7 + a->name_len + a->name_b_len;   // header(4)+idxA+idxB + A + ',' + B
    default:
        return 0;
    }
}
