// chain.c — Dogecoin block/tx wire decoding (ports the GUI's parse.c logic onto
// protocol-sm's SHA-256). See chain.h.
#include "chain.h"
#include "sha256.h"          // protocol-sm SHA-256 (quoted: resolves to SMDIR)
#include "sm.h"              // SM_CARRIER_MAX — the §6 pinned payload ceiling
#include <string.h>
#include <stdlib.h>

// ── cursor ───────────────────────────────────────────────────────────────────
typedef struct { const uint8_t *p; size_t len, off; int err; } Cur;
static void cur_init(Cur *c, const uint8_t *p, size_t n) { c->p = p; c->len = n; c->off = 0; c->err = 0; }
static const uint8_t *cur_take(Cur *c, size_t n) {
    // Bounds check in subtraction form: `off + n` would wrap for an attacker-chosen
    // varint length near SIZE_MAX and pass a `off+n > len` test. off ≤ len is an
    // invariant (off only advances by checked amounts), so len-off never underflows.
    if (c->err || n > c->len - c->off) { c->err = 1; return NULL; }
    const uint8_t *r = c->p + c->off; c->off += n; return r;
}
static uint8_t  cur_u8 (Cur *c) { const uint8_t *p = cur_take(c, 1); return p ? p[0] : 0; }
static uint16_t cur_u16(Cur *c) { const uint8_t *p = cur_take(c, 2); return p ? (uint16_t)(p[0] | p[1] << 8) : 0; }
static uint32_t cur_u32(Cur *c) { const uint8_t *p = cur_take(c, 4); return p ? ((uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24) : 0; }
static int64_t  cur_i64(Cur *c) { const uint8_t *p = cur_take(c, 8); if (!p) return 0; uint64_t v = 0; for (int i = 7; i >= 0; i--) v = v << 8 | p[i]; return (int64_t)v; }
static uint64_t cur_varint(Cur *c) { uint8_t b = cur_u8(c); if (b < 0xFD) return b; if (b == 0xFD) return cur_u16(c); if (b == 0xFE) return cur_u32(c); return (uint64_t)cur_i64(c); }

void idx_sha256d(const uint8_t *data, size_t len, uint8_t out[32]) {
    SHA256_CTX ctx; uint8_t first[32];
    sha256_init(&ctx); sha256_update(&ctx, data, len); sha256_final(&ctx, first);
    sha256_init(&ctx); sha256_update(&ctx, first, 32); sha256_final(&ctx, out);
}

void idx_hash_to_hex(const uint8_t h[32], char hex[65]) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { uint8_t b = h[31 - i]; hex[2*i] = H[b >> 4]; hex[2*i+1] = H[b & 15]; }
    hex[64] = 0;
}
static int hexnib(char c) { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; if (c >= 'A' && c <= 'F') return c - 'A' + 10; return -1; }
int idx_hex_to_hash(const char *hex, uint8_t out[32]) {
    if (strlen(hex) != 64) return 0;
    for (int i = 0; i < 32; i++) { int hi = hexnib(hex[2*i]), lo = hexnib(hex[2*i+1]); if (hi < 0 || lo < 0) return 0; out[31 - i] = (uint8_t)(hi << 4 | lo); }
    return 1;
}
int idx_hex_to_bytes(const char *hex, uint8_t *out, size_t out_max, size_t *out_len) {
    size_t n = strlen(hex); if (n % 2) return 0; n /= 2; if (n > out_max) return 0;
    for (size_t i = 0; i < n; i++) { int hi = hexnib(hex[2*i]), lo = hexnib(hex[2*i+1]); if (hi < 0 || lo < 0) return 0; out[i] = (uint8_t)(hi << 4 | lo); }
    *out_len = n; return 1;
}

// ── scriptPubKey classification (§4 Rule 2 templates) ─────────────────────────
int idx_script_payee(const uint8_t *spk, size_t n, uint8_t h160[20], uint8_t *type) {
    if (n == 25 && spk[0] == 0x76 && spk[1] == 0xA9 && spk[2] == 0x14 && spk[23] == 0x88 && spk[24] == 0xAC) {
        memcpy(h160, spk + 3, 20); *type = 0; return 1;          // P2PKH
    }
    if (n == 23 && spk[0] == 0xA9 && spk[1] == 0x14 && spk[22] == 0x87) {
        memcpy(h160, spk + 2, 20); *type = 1; return 1;          // P2SH
    }
    return 0;
}

// ── OP_RETURN single-minimal-push (§1) ───────────────────────────────────────
// Exactly OP_RETURN <push> where <push> is ONE minimal push of P ≤ SM_CARRIER_MAX
// bytes (§6: the pinned protocol ceiling, 9996) and nothing follows. Reject
// multi-push / non-minimal / trailing-opcode → ignore. Relay policy
// (datacarriersize) gates FORWARDING far below this; the fold must accept any
// mined carrier the spec accepts, so extraction runs at the §6 pin.
int idx_op_return_payload(const uint8_t *spk, size_t n, const uint8_t **data, size_t *dlen) {
    if (n < 1 || spk[0] != 0x6A) return 0;
    size_t i = 1, len, off;
    if (i >= n) { *data = NULL; *dlen = 0; return 1; }            // bare OP_RETURN (empty payload)
    uint8_t op = spk[i];
    if (op >= 0x01 && op <= 0x4B) { len = op; off = i + 1; }                       // direct push (must be ≥1, minimal)
    else if (op == 0x4C) { if (i + 1 >= n) return 0; len = spk[i + 1]; off = i + 2; // OP_PUSHDATA1
                           if (len < 76) return 0; }                                // minimal-PUSHDATA1: <76 must use direct
    else if (op == 0x4D) { if (i + 2 >= n) return 0;                                // OP_PUSHDATA2
                           len = (size_t)spk[i + 1] | ((size_t)spk[i + 2] << 8); off = i + 3;
                           if (len < 256) return 0; }                               // minimal-PUSHDATA2: <256 must use PUSHDATA1/direct
    else return 0;                                                                  // OP_0 / PUSHDATA4 / opcode → not a lone minimal push
    if (len == 0 || len > SM_CARRIER_MAX) return 0;
    if (off + len != n) return 0;                                                   // exactly one push, nothing trailing
    *data = spk + off; *dlen = len; return 1;
}

// ── tx parse (zero-copy view) ────────────────────────────────────────────────
void idx_tx_free(IdxTx *tx) {
    if (tx->ins  && tx->ins  != tx->in_inline)  free(tx->ins);
    if (tx->outs && tx->outs != tx->out_inline) free(tx->outs);
    tx->ins  = tx->in_inline;  tx->cap_in  = IDX_TX_INLINE_IN;
    tx->outs = tx->out_inline; tx->cap_out = IDX_TX_INLINE_OUT;
    tx->n_in = tx->n_out = 0;
}

static int parse_tx(Cur *c, IdxTx *tx) {
    size_t start = c->off;
    memset(tx, 0, sizeof *tx);
    tx->ins  = tx->in_inline;  tx->cap_in  = IDX_TX_INLINE_IN;
    tx->outs = tx->out_inline; tx->cap_out = IDX_TX_INLINE_OUT;
    cur_u32(c);                                            // version
    // reject SegWit marker (DOGE has none; a witness tx is not ours to attribute)
    if (!c->err && c->off + 2 <= c->len && c->p[c->off] == 0x00 && c->p[c->off + 1] == 0x01) { c->err = 1; return 0; }
    uint64_t vin = cur_varint(c);
    if (c->err || vin == 0 || vin > 100000) { c->err = 1; return 0; }
    if (vin > (uint64_t)tx->cap_in) {                      // spill: store EVERY input, no cap
        tx->ins = malloc((size_t)vin * sizeof(IdxIn));
        if (!tx->ins) { tx->ins = tx->in_inline; c->err = 1; return 0; }
        tx->cap_in = (int)vin;
    }
    for (uint64_t i = 0; i < vin && !c->err; i++) {
        const uint8_t *outpoint = cur_take(c, 36);
        uint64_t slen = cur_varint(c);
        const uint8_t *ss = cur_take(c, slen);
        cur_u32(c);                                        // sequence
        if (c->err) { idx_tx_free(tx); return 0; }
        IdxIn *in = &tx->ins[tx->n_in++];
        memcpy((void *)in->prevout, outpoint, 36);
        in->scriptsig = ss; in->sslen = (size_t)slen;
    }
    uint64_t vout = cur_varint(c);
    if (c->err || vout > 100000) { idx_tx_free(tx); c->err = 1; return 0; }
    if (vout > (uint64_t)tx->cap_out) {                    // spill: store EVERY output, no cap
        tx->outs = malloc((size_t)vout * sizeof(IdxOut));
        if (!tx->outs) { tx->outs = tx->out_inline; idx_tx_free(tx); c->err = 1; return 0; }
        tx->cap_out = (int)vout;
    }
    for (uint64_t i = 0; i < vout && !c->err; i++) {
        int64_t v = cur_i64(c);
        uint64_t slen = cur_varint(c);
        const uint8_t *spk = cur_take(c, slen);
        if (c->err) { idx_tx_free(tx); return 0; }
        IdxOut *o = &tx->outs[tx->n_out];
        o->value = v; o->spk = spk; o->spklen = (size_t)slen; o->vout = (uint32_t)i;
        tx->n_out++;
    }
    cur_u32(c);                                            // locktime
    if (c->err) { idx_tx_free(tx); return 0; }
    tx->raw = c->p + start; tx->rawlen = c->off - start;
    idx_sha256d(tx->raw, tx->rawlen, tx->txid);
    return 1;
}

int idx_tx_parse(const uint8_t *raw, size_t len, IdxTx *tx) {
    Cur c; cur_init(&c, raw, len);
    if (!parse_tx(&c, tx)) return 0;
    if (c.off != len) { idx_tx_free(tx); return 0; }   // one whole tx, nothing trailing
    return 1;
}

// AuxPoW (merged-mining proof) skip — ported from GUI parse.c.
static int tx_skip(Cur *c) {
    cur_u32(c);
    int segwit = 0;
    if (!c->err && c->off + 2 <= c->len && c->p[c->off] == 0x00 && c->p[c->off + 1] == 0x01) { segwit = 1; c->off += 2; }
    uint64_t vin = cur_varint(c);
    if (c->err || vin == 0 || vin > 100000) { c->err = 1; return 0; }
    for (uint64_t i = 0; i < vin && !c->err; i++) { cur_take(c, 36); uint64_t s = cur_varint(c); cur_take(c, s); cur_u32(c); }
    uint64_t vout = cur_varint(c);
    if (c->err || vout > 100000) { c->err = 1; return 0; }
    for (uint64_t i = 0; i < vout && !c->err; i++) { cur_i64(c); uint64_t s = cur_varint(c); cur_take(c, s); }
    if (segwit) for (uint64_t i = 0; i < vin && !c->err; i++) { uint64_t items = cur_varint(c); if (c->err || items > 1000) { c->err = 1; return 0; } for (uint64_t j = 0; j < items && !c->err; j++) { uint64_t il = cur_varint(c); cur_take(c, il); } }
    cur_u32(c);
    return !c->err;
}
static int auxpow_skip(Cur *c) {
    if (!tx_skip(c)) return 0;
    cur_take(c, 32);
    uint64_t n = cur_varint(c); if (c->err || n > 64) { c->err = 1; return 0; } cur_take(c, n * 32);
    cur_u32(c);
    n = cur_varint(c); if (c->err || n > 64) { c->err = 1; return 0; } cur_take(c, n * 32);
    cur_u32(c);
    cur_take(c, 80);
    return !c->err;
}

// Merkle root over the block's txids, with Core's CVE-2012-2459 mutation flag:
// a SUPPLIED duplicate pair (h[i] == h[i+1] before odd-padding) marks the block
// mutated — the same tx set can hash to the same root with duplicated leaves,
// and folding those duplicates would double-count their actions.
static int merkle_root(uint8_t *ids, uint64_t n, uint8_t out[32], int *mutated) {
    *mutated = 0;
    if (n == 0) return 0;
    while (n > 1) {
        for (uint64_t i = 0; i + 1 < n; i += 2)
            if (!memcmp(ids + 32 * i, ids + 32 * (i + 1), 32)) *mutated = 1;
        uint64_t m = 0;
        for (uint64_t i = 0; i < n; i += 2) {
            uint8_t buf[64];
            memcpy(buf, ids + 32 * i, 32);
            memcpy(buf + 32, ids + 32 * (i + 1 < n ? i + 1 : i), 32);
            idx_sha256d(buf, 64, ids + 32 * m++);
        }
        n = m;
    }
    memcpy(out, ids, 32);
    return 1;
}

int idx_parse_block(const uint8_t *raw, size_t len, IdxBlockMeta *meta,
                    void (*cb)(void *, const IdxTx *, uint32_t), void *user) {
    Cur c; cur_init(&c, raw, len);
    memset(meta, 0, sizeof *meta);
    const uint8_t *hdr = cur_take(&c, 80);
    if (c.err) return 0;
    meta->version = (uint32_t)hdr[0] | (uint32_t)hdr[1] << 8 | (uint32_t)hdr[2] << 16 | (uint32_t)hdr[3] << 24;
    memcpy(meta->prev,   hdr + 4,  32);
    memcpy(meta->merkle, hdr + 36, 32);
    meta->time  = (uint32_t)hdr[68] | (uint32_t)hdr[69] << 8 | (uint32_t)hdr[70] << 16 | (uint32_t)hdr[71] << 24;
    meta->bits  = (uint32_t)hdr[72] | (uint32_t)hdr[73] << 8 | (uint32_t)hdr[74] << 16 | (uint32_t)hdr[75] << 24;
    meta->nonce = (uint32_t)hdr[76] | (uint32_t)hdr[77] << 8 | (uint32_t)hdr[78] << 16 | (uint32_t)hdr[79] << 24;
    idx_sha256d(hdr, 80, meta->block_hash);
    if (meta->version & 0x100) { if (!auxpow_skip(&c)) return 0; }   // merged-mined: skip AuxPoW
    uint64_t ntx = cur_varint(&c);
    if (c.err || ntx > 1000000) return 0;
    if (ntx > len / 60 + 1) return 0;              // a real tx is ≥60 bytes — bound the txid alloc
    uint8_t *ids = malloc((size_t)(ntx ? ntx : 1) * 32);
    if (!ids) return 0;
    for (uint64_t i = 0; i < ntx; i++) {
        IdxTx tx;
        if (!parse_tx(&c, &tx)) { free(ids); return 0; }            // parse_tx frees its own spill on error
        memcpy(ids + 32 * i, tx.txid, 32);
        meta->block_bytes += (int64_t)tx.rawlen;                    // §3.4 Σ len(raw_tx)
        if (i == 0) for (int o = 0; o < tx.n_out; o++) meta->coinbase_out_total += tx.outs[o].value;
        if (cb) cb(user, &tx, (uint32_t)i);                         // cb copies what it needs synchronously
        idx_tx_free(&tx);                                           // release any heap spill
    }
    meta->n_tx = (int)ntx;
    uint8_t root[32]; int mutated = 0;
    meta->merkle_ok = merkle_root(ids, ntx, root, &mutated) &&
                      !mutated && !memcmp(root, meta->merkle, 32);
    free(ids);
    return 1;
}
