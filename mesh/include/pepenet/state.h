// state.h — replicated per-name state: anchor-ordered, per-key last-writer-wins.
//
// The store an overlay uses when its content is CURRENT STATE (a DNS zone, a
// service descriptor), not history. One row per (name, key) holding the single
// highest-anchored signed op; a PUT at the same key REPLACES the old row and
// frees its bytes, so a name's footprint is bounded by what it currently says —
// editing can never exhaust a budget. There is no seq/prev chain, no fold, no
// TTL: eviction is the host's expiry sweep (name lapses on chain → drop rows).
//
// ORDERING is the chain itself. Every op is signed over the header hash at its
// anchor height, so an op provably postdates that block, and "highest anchor
// wins" totally orders each key without any wallet-side counter — a wallet
// restored from seed signs against the current tip and is instantly ahead.
// Admission REJECTS an op that does not strictly raise its key's anchor; the
// block cadence is therefore the per-key update rate limit (one per block).
//
// DELETES leave the signed `del` op in the row as a tombstone — every old
// signed PUT remains a replay bomb until the name expires, and the tombstone
// is what outranks it. A `clear` op voids EVERYTHING anchored below it (the
// per-name floor): one clear supersedes all tombstones at once, so an owner
// reclaims dead-label bytes for free. Republish-after-clear may share the
// clear's own anchor (>= floor admits; the strict rule is per-key only).
//
// EPOCHS: rows verify against the name's CURRENT owner. When the view shows a
// new owner, the held rows are a prior epoch — wiped on first contact, and the
// floor is bumped to (tip − SP_STATE_REORG) so a returning owner's year-old
// ops cannot resurrect (an A→B→A flip inside the reorg window is the one case
// this misses; a returning owner should publish `clear` first regardless).
//
// The on-chain escape hatch composes: a record op settled in a block IS an op
// whose anchor is its inclusion height, authenticated by the spend instead of
// the in-band sig — same axis, one comparison rule. (That path is the host's;
// this module admits the gossiped, in-band-signed form.)
#ifndef PEPENET_STATE_H
#define PEPENET_STATE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ── wire constants ────────────────────────────────────────────────────────────
#define SP_STATE_VER      0xA1   // op envelope version byte (domain-separates the
                                 // sig digest from every vpost/chain preimage)
#define SP_OP_PUT         1
#define SP_OP_DEL         2      // tombstone: key present, no payload
#define SP_OP_CLEAR       3      // floor: no key, no payload
#define SP_STATE_KEY_MAX  96     // opaque key bytes (host packs e.g. label‖type;
                                 // a full DNS sublabel chain is 63 + 2 of type)
#define SP_STATE_OP_MAX   8192   // hard parse cap on one op (>= any sane budget)
#define SP_STATE_REORG    6      // publish anchors this deep; epoch floor backs
                                 // off this much so fresh ops are not orphaned

// §2.2 delegation certs (wire-identical to the vpost form, so already-minted
// certs keep verifying). P2PKH: preimage ‖ sig_K. P2SH: preimage ‖ m sigs.
#define SP_CERT_NONE   0
#define SP_CERT_P2PKH  1
#define SP_CERT_P2SH   2
#define SP_CERT_VER    0x01      // cert preimage version (compat: keep 0x01)

typedef struct {
    int            type;                 // SP_CERT_*
    const uint8_t *name;    int name_len;
    const uint8_t *owner_key;            // P2PKH: 33
    const uint8_t *redeem;  int redeem_len;   // P2SH
    const uint8_t *posting_key;          // 33
    uint64_t       scope;
    uint32_t       not_after;            // exclusive, block height
    const uint8_t *sigs;    int n_sigs;
    uint8_t        cert_id[32];          // sha256(preimage)
    int            wire_len;
} SpCert;

int  sp_cert_parse(int cert_type, const uint8_t *c, int len, SpCert *out);
int  sp_cert_verify(const SpCert *ct, const uint8_t *name, int name_len,
                    const uint8_t posting_key[33], uint32_t height_anchor,
                    const uint8_t owner_h160[20]);
// The ONE builder that touches the owner (money) key — callers stay offline/rare.
int  sp_cert_build_p2pkh(const uint8_t *name, int name_len,
                         const uint8_t owner_priv[32], const uint8_t posting_key[33],
                         uint64_t scope, uint32_t not_after,
                         uint8_t *out, int outmax);

// ── the op ────────────────────────────────────────────────────────────────────
// ver ‖ op ‖ nlen:var name ‖ klen:var key ‖ anchor:le32 ‖ anchor_hash32
//     ‖ plen:var payload ‖ has_cert ‖ [cert] ‖ signer33 ‖ sig64
// op_id = sha256(preimage) — everything through signer33, excluding sig.
typedef struct {
    uint8_t        op;                   // SP_OP_*
    const uint8_t *name;    int name_len;
    const uint8_t *key;     int key_len; // empty iff CLEAR
    uint32_t       anchor;               // height
    const uint8_t *anchor_hash;          // 32
    const uint8_t *payload; int payload_len; // non-empty iff PUT
    uint8_t        has_cert;             // SP_CERT_*
    SpCert         cert;                 // valid iff has_cert
    const uint8_t *signer;               // 33
    const uint8_t *sig;                  // 64
    uint8_t        op_id[32];
    int            wire_len;
} SpStateOp;

// Build + sign one op. DEL: payload NULL/0. CLEAR: key NULL/0 too. A cert of
// SP_CERT_NONE means `priv` must be the owner key itself. Returns wire length,
// -1 on bad args / small buffer.
int sp_state_op_build(uint8_t op, const char *name,
                      const uint8_t *key, int key_len,
                      const uint8_t *payload, int payload_len,
                      uint32_t anchor, const uint8_t anchor_hash[32],
                      const uint8_t priv[32], const uint8_t pub33[33],
                      int cert_type, const uint8_t *cert, int cert_len,
                      uint8_t *out, int outmax);

// Parse (zero-copy view into `e`; no crypto). 1 ok · 0 malformed.
int sp_state_op_parse(const uint8_t *e, int len, SpStateOp *out);

// ── the store ─────────────────────────────────────────────────────────────────
typedef struct SpState SpState;

SpState *sp_state_open(const char *path);        // sqlite; ":memory:" for tests
void     sp_state_close(SpState *s);

// The chain oracle: how admission asks the host about the chain. Kept as
// callbacks (not an SpView) because the answers are host-policy: owner_now
// must apply the LEASE gate (a lapsed name admits nothing), and header_at's
// horizon depends on where the host's header store starts.
//   owner_now : 1 name owned AND lease live (fills owner[20]) · 0 not
//   header_at : 1 hash filled (verify) · 0 beyond tip (admission HOLDS, -2)
//               · -1 below the host's horizon (checkpoint-synced hosts do not
//               have ancient headers; the op admits WITHOUT the hash compare —
//               it is owner-signed either way, and the hash check only guards
//               ahead-of-tip forgery and wrong-branch anchors, both of which
//               are above any horizon a live host keeps)
//   tip       : best known height (epoch floor placement)
typedef struct {
    void    *u;
    int     (*owner_now)(void *u, const char *name, uint8_t owner[20]);
    int     (*header_at)(void *u, uint32_t height, uint8_t out[32]);
    uint32_t(*tip)(void *u);
} SpChainOracle;

// Admit one signed op against the oracle + `budget` bytes per name (sum of
// held op blobs). `scope` is the §2.2 scope bit(s) a delegated signer must
// carry (pass the overlay's bit; owner-signed ops skip it). Returns:
//   1  admitted (stored / floor raised)
//   0  rejected — err says why (sig, owner, budget, anchor below held/floor,
//      anchor hash not on our chain, malformed, oversize)
//  -1  duplicate (this exact op_id already held)
//  -2  anchor ahead of our headers — hold and retry after sync
int sp_state_admit(SpState *s, const SpChainOracle *o,
                   int64_t budget, uint64_t scope,
                   const uint8_t *e, int len, char *err, int errlen);

// ── local performance hooks (no format, rule or result change) ────────────────
// L9: run several admits as ONE write transaction (each admit is a savepoint
// inside it, so one failed op still rolls back alone). begin: 1 opened, 0 not
// (busy / already open: admits then commit one by one as before). end: 1
// committed, 0 rolled back (nothing from the batch landed).
int     sp_state_batch_begin(SpState *s);
int     sp_state_batch_end(SpState *s);
// L10: fn(u, name) after every committed write through this handle (name NULL
// = everything may have changed (failed batch); "" = handle closing). One hook
// per handle.
void    sp_state_set_change_hook(SpState *s, void (*fn)(void *u, const char *name), void *u);
// L10: PRAGMA data_version (changes when ANOTHER connection commits). -1 error.
int64_t sp_state_data_version(SpState *s);

// ── reads ─────────────────────────────────────────────────────────────────────
// One key's held op blob (PUT or DEL). 1 found (malloc'd *blob) · 0 absent.
int     sp_state_get(SpState *s, const char *name, const uint8_t *key, int key_len,
                     uint8_t **blob, int *blen);
// Every held row of a name (PUTs and tombstones), key-ordered. Returns count.
// cb returns 0 to stop. `op` is SP_OP_PUT/SP_OP_DEL.
int     sp_state_iter(SpState *s, const char *name,
                      int (*cb)(void *u, const uint8_t *key, int key_len, int op,
                                uint32_t anchor, const uint8_t *blob, int blen),
                      void *u);
int64_t sp_state_sum(SpState *s, const char *name);        // held bytes (incl clear)
uint32_t sp_state_floor(SpState *s, const char *name);     // 0 = none
// The held clear op, for gossip (peers need the proof, not just the effect).
int     sp_state_clear_get(SpState *s, const char *name, uint8_t **blob, int *blen);
// Names present in the store (for inventory + the expiry sweep). Returns count.
int     sp_state_names(SpState *s, int (*cb)(void *u, const char *name), void *u);
// Drop everything held for a name (expiry sweep: view says unowned → gone).
void    sp_state_drop_name(SpState *s, const char *name);
// paged walk: names > after (NULL/"" = start), name order, <= limit (read-only)
int     sp_state_names_after(SpState *s, const char *after, int limit,
                             int (*cb)(void *u, const char *name), void *u);
// owner the held rows belong to (st_names.owner); 1 known, 0 no row
int     sp_state_owner(SpState *s, const char *name, uint8_t owner[20]);

#ifdef __cplusplus
}
#endif

#endif
