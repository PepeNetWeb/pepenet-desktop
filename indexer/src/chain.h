// chain.h — real Dogecoin block/tx wire decoding for the indexer.
//
// Self-contained (uses protocol-sm's SHA-256, no GUI crypto) so it never collides
// with the linked engine's symbols. Ports the GUI's proven cursor / tx-iterator /
// AuxPoW-skip logic. Zero-copy: parsed views point into the caller's block buffer.
#ifndef IDX_CHAIN_H
#define IDX_CHAIN_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// A tx has NO protocol cap on inputs/outputs (§0: "any cap is relay, never
// protocol"). The reference fold is capless, so the indexer MUST be too — a fixed
// cap that silently truncated a >N-output tx would make a carrier/named-input past
// the cap invisible and fork this indexer's state from a conformant one. Storage is
// inline for the common case and spills to the heap for large txs; the wire counts
// are already bounded to ≤100000 by parse_tx, so a spill allocates exactly that.
#define IDX_TX_INLINE_IN   8
#define IDX_TX_INLINE_OUT  16

typedef struct { const uint8_t *scriptsig; size_t sslen;
                 const uint8_t prevout[36]; } IdxIn;
typedef struct { int64_t value; const uint8_t *spk; size_t spklen; uint32_t vout; } IdxOut;

// A parsed transaction view (pointers into the block buffer). ins/outs point at the
// inline arrays or a heap spill; call idx_tx_free after use (no-op while inline).
typedef struct {
    const uint8_t *raw; size_t rawlen;     // this tx's serialized bytes (for §3.4 block_bytes + txid)
    uint8_t  txid[32];                     // sha256d(raw), wire order
    IdxIn   *ins;  int n_in;  int cap_in;
    IdxOut  *outs; int n_out; int cap_out;
    IdxIn    in_inline[IDX_TX_INLINE_IN];
    IdxOut   out_inline[IDX_TX_INLINE_OUT];
} IdxTx;

// Release any heap spill held by `tx` and reset it to its inline arrays.
void idx_tx_free(IdxTx *tx);

// Parse a STANDALONE serialized transaction (e.g. a wire `tx` message) into a
// view over `raw`. Like the per-tx parse inside idx_parse_block, but requires
// the buffer to be consumed EXACTLY (no trailing bytes) — a framed `tx` payload
// is one whole tx. Zero-copy: the view points into `raw`, keep it alive; call
// idx_tx_free after use. Returns 1 on success, 0 on malformed / trailing bytes.
int idx_tx_parse(const uint8_t *raw, size_t len, IdxTx *tx);

typedef struct {
    uint32_t version, time, bits, nonce;
    uint8_t  prev[32], merkle[32];
    uint8_t  block_hash[32];               // sha256d of the 80-byte header (wire order)
    int64_t  block_bytes;                  // §3.4: Σ len(raw_tx), AuxPoW/header/count-varint excluded
    int64_t  coinbase_out_total;           // §3.4: Σ outputs of tx 0
    int      n_tx;
    int      merkle_ok;                    // header merkle == computed txid root AND
                                           // no CVE-2012-2459 duplicate mutation —
                                           // sync's accept gate (offline paths that
                                           // fold synthetic fixtures ignore it)
} IdxBlockMeta;

// Parse a raw block: fill `meta`, then call `cb(user, &tx, txindex)` for each tx
// in order. Returns 1 on success, 0 on malformed. `cb` may be NULL (meta only).
int idx_parse_block(const uint8_t *raw, size_t len, IdxBlockMeta *meta,
                    void (*cb)(void *user, const IdxTx *tx, uint32_t txindex), void *user);

// double-SHA256 (wire order).
void idx_sha256d(const uint8_t *data, size_t len, uint8_t out[32]);
// wire 32-byte hash → display-order (reversed) hex, and back.
void idx_hash_to_hex(const uint8_t h[32], char hex[65]);
int  idx_hex_to_hash(const char *hex, uint8_t out[32]);
int  idx_hex_to_bytes(const char *hex, uint8_t *out, size_t out_max, size_t *out_len);

// scriptPubKey classification (§4 Rule 2 reconstruct-target templates):
//   P2PKH  76 a9 14 <h160> 88 ac        → type 0
//   P2SH   a9 14 <h160> 87              → type 1
// Returns 1 and fills h160[20] + *type, else 0 (nonstandard / OP_RETURN).
int idx_script_payee(const uint8_t *spk, size_t n, uint8_t h160[20], uint8_t *type);

// OP_RETURN carrier extraction (§1 "lone minimal push"): returns 1 and the single
// pushed payload iff the script is exactly OP_RETURN <minimal push, ≤80 bytes>;
// 0 for any multi-push / non-minimal / trailing-opcode OP_RETURN (→ ignore, §1).
int idx_op_return_payload(const uint8_t *spk, size_t n, const uint8_t **data, size_t *dlen);

#ifdef __cplusplus
}
#endif

#endif
