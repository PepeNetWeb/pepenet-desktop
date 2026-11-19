// protocol-sm — the chain-abstracted §5 fold (C reference implementation).
//
// This is the executable reference model for docs/protocol-spec.md: a
// deterministic state machine that consumes ALREADY-DECODED, ALREADY-ATTRIBUTED
// abstract transactions and produces a canonical state digest. It does NO chain
// work — no headers, PoW, scripts, ECDSA, or sockets. §4 identity is injected
// (each input arrives as {h160, type, signs-SIGHASH_ALL}); time (MTP) and the
// CLAIM/RENEW rate are injected per block. See SPEC-conformance.md.
#ifndef SM_H
#define SM_H

#include <stdint.h>
#include <stddef.h>
#include "sha256.h"   // SHA256_CTX (property/reorg fingerprints)

// ── §0 protocol constants ───────────────────────────────────────────────────
// koinu are the base unit; 1 DOGE = 100,000,000 koinu.
#define SM_KOINU_PER_DOGE     100000000LL

#define SM_DUST_FLOOR         1LL            // koinu: rate floor, RESERVE deposit-leg floor, SELL floor basis
#define SM_RATE_CAP           SM_KOINU_PER_DOGE   // 1 DOGE: rent-rate clamp ceiling (§3.4)
#define SM_REF_SIZE           200LL          // bytes: fee-per-byte → per-name rent (§3.4)
#define SM_FEE_WINDOW         10081LL        // blocks: window scanned for fee-bearing blocks (§3.4)
#define SM_MIN_FEE_SAMPLE     1000LL         // min fee-bearing (participant) count for a trusted median; below → DUST_FLOOR (§3.4, boundary inclusive)
#define SM_LEASE_QUANTUM      2419200LL      // s (~28 d): rate is koinu/name/quantum (§3.4)
#define SM_BILLING_UNIT       86400LL        // s (1 d): lease-extension granularity (§3.3)
#define SM_MAX_LEASE          31536000LL     // s (~365 d): cap on lease reach (§3.3)
#define SM_COMMIT_EXPIRY      18000LL        // s (~5 h): a commit's live window (§3.2)
#define SM_RESERVE_WINDOW     18000LL        // s (~5 h): exclusive-buy window / SELL floor (§3.7)
#define SM_DIRECT_WINDOW      7200LL         // s (~2 h): directed-sale offer window (§3.7)
#define SM_REORG_BUFFER       7200LL         // s (~2 h): ordered-boundary margin (§3.7, §5)
#define SM_RESERVE_DEPOSIT_BPS 100           // 1.00% total reserve deposit (§3.7)
#define SM_RESERVE_BURN_BPS   50             // 0.50% burned leg (§3.7)
#define SM_RESERVE_PAY_BPS    50             // 0.50% paid-to-seller leg (§3.7)
#define SM_MAX_ANCHOR_AGE     1024LL         // blocks: max bitmap anchor staleness (§3.5)
#define SM_SELL_PRICE_FLOOR   (3LL * SM_DUST_FLOOR)  // §3.7 SELL price floor

#define SM_NAME_MAX           32             // [a-z0-9-] DNS label, 1..32 bytes + structural rules (§3.1)

// ── §2 opcodes (contiguous 0x01–0x0F; all gate at ACTIVATION_HEIGHT) ────────
enum {
    SM_OP_RENEW_NAME    = 0x01,   // by-name renew: name(1..32)          (§3.5)
    SM_OP_TRANSFER_NAME = 0x02,   // by-name gift:  target(20)+name      (§3.5/§3.6)
    SM_OP_COMMIT        = 0x03,
    SM_OP_CLAIM         = 0x04,
    SM_OP_RENEW         = 0x05,
    SM_OP_TRANSFER      = 0x06,
    SM_OP_SELL          = 0x07,
    SM_OP_RESERVE       = 0x08,
    SM_OP_SETTLE        = 0x09,
    SM_OP_RELEASE       = 0x0A,
    SM_OP_RELEASE_NAME  = 0x0B,   // by-name relinquish: name(1..32)     (§3.5/§3.6)
    SM_OP_SELL_TO       = 0x0C,
    SM_OP_PAY           = 0x0D,
    SM_OP_AS            = 0x0E,
    SM_OP_TRADE         = 0x0F,
};
#define SM_OP_MIN  SM_OP_RENEW_NAME
#define SM_OP_MAX  SM_OP_TRADE

// Script types (§4 Rule 2). Identity keys on the bare hash160; the type is a
// template selector recorded only where a script is later reconstructed.
enum { SM_P2PKH = 0, SM_P2SH = 1 };

// ── the abstract transaction (post-decode, post-attribution) ────────────────
#define SM_MAX_INPUTS    8
#define SM_MAX_CARRIERS  16
#define SM_MAX_OUTS      16

// ── the pinned carrier ceiling (§6) ─────────────────────────────────────────
// A PROTOCOL constant, not an L1 rule: Pepecoin never size-checks an OP_RETURN
// script (IsUnspendable() fires on the opcode; MAX_SCRIPT_SIZE and the 520-byte
// element rule are execution-time, and an unspendable output never executes).
// L1's only true bound is the ~1 MB serialized-tx limit. The pin is the payload
// a MAX_SCRIPT_SIZE-sized script would carry — OP_RETURN(1) + OP_PUSHDATA2(1+2)
// + one push — chosen so every impl keeps fixed-size, boundary-tested buffers;
// raisable at an activation height if 79,896 names/carrier ever stops sufficing.
// Relay policy (datacarriersize, default 83 script bytes → 80-byte payloads)
// gates what nodes FORWARD, never what the fold ACCEPTS once mined.
#define SM_L1_SCRIPT_MAX  10000
#define SM_CARRIER_MAX    (SM_L1_SCRIPT_MAX - 4)   // 9996: max payload bytes
#define SM_BODY_MAX       (SM_CARRIER_MAX - 4)     // 9992: after FF 'P' 'N' op
#define SM_FLAGS_MAX      (SM_BODY_MAX - 5)        // 9987: RENEW/RELEASE bitmap bytes
#define SM_FLAGS_XFER_MAX (SM_FLAGS_MAX - 20)      // 9967: TRANSFER (target eats 20)

// A §4 identity, injected (never computed here).
typedef struct { uint8_t h160[20]; uint8_t type; } SmId;

// One decoded action. Which fields matter depends on `op`; the rest are zero.
typedef struct {
    uint8_t  op;

    char     name[SM_NAME_MAX + 1];   uint8_t name_len;     // CLAIM/SELL/RESERVE/SETTLE/SELL_TO/PAY/TRADE + the by-name ops
    char     name_b[SM_NAME_MAX + 1]; uint8_t name_b_len;   // TRADE second name

    uint8_t  commitment[32];          // COMMIT
    uint8_t  salt[32];                // CLAIM

    uint8_t  addr[20];                // TRANSFER/TRANSFER_NAME target / SELL_TO buyer (hash160)
    uint64_t price;                   // SELL / SELL_TO
    uint32_t window;                  // SELL (0 = default RESERVE_WINDOW)

    // RENEW/TRANSFER/RELEASE bitmap selection. has_anchor=0 & flags_len=0 ⇒
    // "all" mode (RENEW renew-all / TRANSFER transfer-all). RELEASE always has
    // an anchor + flags.
    uint8_t  has_anchor;
    uint64_t anchor;                  // 5-byte absolute height anchor (fits u64)
    uint8_t  flags[SM_FLAGS_MAX];     uint16_t flags_len;   // ≤ SM_FLAGS_MAX (> 255 possible)

    uint8_t  as_index;                // AS: vin[index] becomes acting identity
    uint8_t  idx_a, idx_b;            // TRADE: the two input indices
} SmAction;

typedef enum { SM_CAR_ACTION, SM_CAR_IGNORE } SmCarKind;

// One OP_RETURN output, in vout order.
typedef struct {
    SmCarKind kind;
    SmAction  act;                    // when ACTION
    uint64_t  value;                  // OP_RETURN koinu (rent / RESERVE burn-leg)
    uint32_t  vout;
} SmCarrier;

// One spendable output, in vout order (for §3.5 market payment matching).
typedef struct { uint8_t h160[20]; uint8_t type; uint64_t value; uint32_t vout; } SmOut;

// The abstract tx imposes NO per-tx count cap (spec §0: "any cap is relay, never
// protocol"). Inputs/carriers/outs live behind pointers that default to embedded
// inline storage and spill to the heap past it — so a typical tx allocates little,
// yet a pathological large tx folds identically to an unbounded impl. SM_INLINE_*
// are storage hints, NOT protocol limits. Carriers inline at ONE: an SmCarrier
// embeds the full SM_FLAGS_MAX action, so each inline slot costs ~10 KB — one
// covers the overwhelmingly common single-carrier tx and the rest spill.
// Build via sm_tx_input/carrier/out; release with sm_tx_free (a no-op while
// inline). Never copy an SmTx by value — the pointers would dangle; build in place.
#define SM_INLINE_INPUTS    8
#define SM_INLINE_CARRIERS  1
#define SM_INLINE_OUTS      16
// Synthetic-tx vout layout (test harnesses only: carriers occupy vout 0.., outs
// start here). Digest-relevant, so pinned at the historical value; real chain txs
// use their actual vout from the adapter, never this.
#define SM_SYNTH_VOUT_BASE  16
typedef struct {
    uint32_t  txindex;                            // position in block (priority + ordering)
    SmId     *inputs;                             // heap or &in_inline[0]
    uint8_t  *in_sighash_all;                     // per-input: signs exactly SIGHASH_ALL?
    int       n_inputs;   int cap_inputs;
    SmCarrier *carriers;                          // vout order
    int       n_carriers; int cap_carriers;
    SmOut    *outs;                               // vout order
    int       n_outs;     int cap_outs;
    SmId      in_inline[SM_INLINE_INPUTS];
    uint8_t   sig_inline[SM_INLINE_INPUTS];
    SmCarrier car_inline[SM_INLINE_CARRIERS];
    SmOut     out_inline[SM_INLINE_OUTS];
} SmTx;

// Append one zeroed slot, growing inline→heap as needed; returns the slot. The
// paired index (in_sighash_all) grows with the input array.
SmId     *sm_tx_input(SmTx *t);
SmCarrier *sm_tx_carrier(SmTx *t);
SmOut    *sm_tx_out(SmTx *t);
void      sm_tx_free(SmTx *t);                    // frees any heap spill (no-op inline)

// ── fold state ──────────────────────────────────────────────────────────────
typedef enum {
    SM_OWNED = 0,      // plain owned
    SM_LISTED,         // §3.7 open SELL listing
    SM_OFFERED,        // §3.7 directed SELL_TO offer
    SM_RESERVED,       // §3.7 reserved (an open listing with a winning reserver)
} SmNameState;

typedef struct {
    char     name[SM_NAME_MAX + 1]; uint8_t name_len;
    uint8_t  owner[20];   uint8_t owner_type;
    int64_t  lease_expiry;          // MTP timestamp (exclusive): owned iff MTP < this
    SmNameState st;

    // market fields (LISTED / OFFERED / RESERVED):
    uint8_t  seller[20];  uint8_t seller_type;
    uint64_t price;
    int64_t  offer_expiry;          // listing/offer close (exclusive)
    uint8_t  buyer[20];             // OFFERED buyer / RESERVED reserver
    uint64_t burn_leg, pay_leg;     // reserve deposit legs (credit toward price = burn+pay)
    int64_t  reserve_expiry;        // RESERVED close (exclusive)
} SmNameRow;

typedef struct {
    uint8_t  commitment[32];
    int64_t  commit_height;
    uint32_t tx_index;
    int64_t  commit_time;           // MTP at the commit's block (COMMIT_EXPIRY pruning)
} SmCommit;

typedef struct { uint8_t owner[20]; int64_t height; } SmMut;

// Per-BLOCK claim scratch (§3.2 priority tuple). Reset each begin_block. Records
// names minted THIS block so a same-block claim with a smaller backing-commit
// priority can displace the provisional winner (cross-block claims never displace).
// Priority is the COMMIT's (commit_height, tx_index) — §3.2's tuple tie-break is the
// commit's tx_index (the commit row is {commitment, commit_height, tx_index}), NOT the
// claim's chain order. Never digested — dead the instant the block ends.
typedef struct {
    char     name[SM_NAME_MAX + 1];
    int64_t  commit_height;
    uint32_t commit_tx_index;                    // backing commit's tx_index (final tie-break, §3.2)
    uint8_t  owner[20];                          // provisional winner (must still hold it to displace)
} SmClaimWin;

typedef struct {
    uint64_t activation_height;
    int64_t  cur_height, cur_mtp;
    uint64_t cur_rate;

    SmNameRow  *names;   int n_names,   cap_names;
    SmCommit   *commits; int n_commits, cap_commits;
    SmMut      *muts;    int n_muts,    cap_muts;
    SmClaimWin *claimsc; int n_claimsc, cap_claimsc;   // per-block scratch (not digested)

    int64_t ev[16];                 // coverage event counters (NOT digested — see SM_EV_*)
    uint8_t onchain_magic[2];       // name-carrier prefix after 0xFF; not digested.
                                    // 0,0 accepts nothing (sm_new). The indexer stamps
                                    // the active Coin's onchain_magic before folding.
} SmState;

// Coverage events — bumped at the edge-case branches so the generator can prove
// every one was exercised over a soak. NOT part of the digest / consensus.
enum {
    SM_EV_CLAIM_MINT = 0, SM_EV_CLAIM_DISPLACE, SM_EV_WATERFILL_CAP, SM_EV_WATERFILL_FORFEIT,
    SM_EV_RESERVE_WIN, SM_EV_RESERVE_CLAMP, SM_EV_SETTLE_OK, SM_EV_PAY_OK,
    SM_EV_TRADE_OK, SM_EV_LAPSE, SM_EV_RELEASE_NAME, SM_EV_AS_DROP,
    SM_EV_SELL_OK, SM_EV_SELLTO_OK, SM_EV_COUNT
};

// ── public API ──────────────────────────────────────────────────────────────
SmState *sm_new(uint64_t activation_height);
void     sm_free(SmState *s);
void     sm_clear(SmState *s);      // empty state, keep the pointer (reorg rebuild)

// Begin block H: run pre-block time-triggered transitions against `mtp`
// (reserve→offer→lease + COMMIT_EXPIRY prune), then set the rate for this
// height's CLAIM/RENEW. Call once per height in increasing order.
void     sm_begin_block(SmState *s, int64_t height, int64_t mtp, uint64_t rate);

// Fold one transaction (call in txindex order within the block).
void     sm_apply_tx(SmState *s, const SmTx *tx);

// Canonical, order-independent state digest (SHA-256) — the cross-language
// equality oracle (SPEC-conformance.md §Digest).
void     sm_state_digest(SmState *s, uint8_t out[32]);

// Incremental-friendly ECMH state digest (§13.2): per-table multiset hash over
// the SAME per-row encoding as sm_state_digest, summed on the curve, then the
// five sub-accumulators hashed into a 32-byte combined digest. Same equality
// relation as sm_state_digest; O(rows-changed) to maintain in a production fold.
void     sm_state_ecmh(SmState *s, uint8_t out[32]);

// `sm ecmh` mode — the pinned, portable ECMH primitive vector set (H2C KAT +
// accumulator algebra + tagged multiset sum). Cross-language byte-identical.
int      ecmh_cmd(void);

// Queries (tests / invariants).
const SmNameRow *sm_lookup(SmState *s, const char *name);
int              sm_owns(SmState *s, const uint8_t h160[20], const char *name);

// ── internal helpers shared across the fold .c files (not a stable API) ──────
// §3.1: [a-z0-9-], 1..32, no leading/trailing hyphen, no `--` at positions 3–4.
int      sm_name_valid(const char *name, size_t len);
int64_t  sm_last_mutation(SmState *s, const uint8_t owner[20]);
void     sm_bump_mutation(SmState *s, const uint8_t owner[20], int64_t height);

SmNameRow *sm_find_name(SmState *s, const char *name);
SmNameRow *sm_add_name(SmState *s, const char *name, size_t len);
void       sm_remove_name(SmState *s, SmNameRow *row);

void sm_commit_add(SmState *s, const uint8_t commitment[32], int64_t height,
                   uint32_t txidx, int64_t time);

void sm_preblock(SmState *s, int64_t height, int64_t mtp);   // §5 transitions, used by begin_block

// Per-tx working context. fold.c builds it, updates the acting identity across
// AS markers, and hands it to each op handler. Output consumption is per-tx
// (consume-once, §3.5), so it lives here, not in the global state.
typedef struct SmTxCtx {
    const SmTx *tx;
    int64_t   height, mtp;
    uint64_t  rate;
    uint32_t  txindex;
    uint8_t   txid[32];                 // synthetic per-tx id (pinned: height|txindex), §gen
    uint8_t   actor[20];  uint8_t actor_type;  int actor_valid;   // acting identity (⊥ ⇒ drop segment)
    uint64_t  car_value;  uint32_t car_vout;   // the current carrier's OP_RETURN value + vout
    // per-tx consume-once flags (§3.5), one per spendable output. Sized to the
    // tx's actual n_outs by sm_apply_tx (a tx imposes NO output cap, §0), NOT a
    // fixed 16 — else a tx with >16 outputs would read/write past this array.
    uint8_t  *out_consumed;
} SmTxCtx;

// Match + consume the lowest-vout unconsumed output paying EXACTLY (dest,type,
// amount); marks it consumed and returns 1, else 0 (§3.5 vout-order, consume-
// once, exact-value). Defined in market.c.
int sm_consume_output(SmState *s, SmTxCtx *cx, const uint8_t dest[20],
                      uint8_t type, uint64_t amount);

// Op handlers (fold.c dispatches by opcode; heavy ones live in their modules).
void sm_op_commit  (SmState *s, SmTxCtx *cx, const SmAction *a);
void sm_op_claim   (SmState *s, SmTxCtx *cx, const SmAction *a);
void sm_op_renew   (SmState *s, SmTxCtx *cx, const SmAction *a);
void sm_op_transfer(SmState *s, SmTxCtx *cx, const SmAction *a);
void sm_op_release (SmState *s, SmTxCtx *cx, const SmAction *a);
void sm_op_renew_name   (SmState *s, SmTxCtx *cx, const SmAction *a);   // §3.5 by-name forms
void sm_op_transfer_name(SmState *s, SmTxCtx *cx, const SmAction *a);
void sm_op_release_name (SmState *s, SmTxCtx *cx, const SmAction *a);
void sm_op_sell    (SmState *s, SmTxCtx *cx, const SmAction *a);
void sm_op_reserve (SmState *s, SmTxCtx *cx, const SmAction *a);
void sm_op_settle  (SmState *s, SmTxCtx *cx, const SmAction *a);
void sm_op_sell_to (SmState *s, SmTxCtx *cx, const SmAction *a);
void sm_op_pay     (SmState *s, SmTxCtx *cx, const SmAction *a);
void sm_op_trade   (SmState *s, SmTxCtx *cx, const SmAction *a);

// Lease application: extend the named owned rows by the burn `B` via the §3.5
// water-fill (rate→days, MAX_LEASE cap). Used by CLAIM (single name) and RENEW
// (bitmap set). Defined in lease.c.
void sm_waterfill(SmState *s, int64_t now_mtp, uint64_t rate, uint64_t burn,
                  SmNameRow **rows, int n);
// Does burn `B` at `rate` buy at least one whole day? (128-bit; §3.4 "MUST
// cover at least one day" / "fail closed if T = 0"). Defined in lease.c.
int  sm_lease_covers_day(uint64_t burn, uint64_t rate);

// Collect `who`'s owned-set rows (plain OWNED owner==who, plus LISTED/OFFERED/
// RESERVED seller==who — a listing stays in the owned set, §3.7), sorted
// ascending-lexicographic by name (the bitmap ordering). Returns the count
// written to out[] (≤ max). Defined in bitmap.c.
int  sm_collect_owned(SmState *s, const uint8_t who[20], SmNameRow **out, int max);

// ── §3.4 / §5 oracle helpers (pure; the harness feeds their output into
// begin_block, keeping the fold chain-abstracted). Defined in oracle.c.
//   sm_mtp        — median of the (up to 11) timestamps of the blocks before H.
//   sm_oracle_rate— the §3.4 fee-rate over `n` blocks (signed under-claim clamp,
//                   floor per-block fee/byte, single-element median of an ODD
//                   window, REF_SIZE scale, DUST_FLOOR..RATE_CAP clamp).
int64_t  sm_mtp(const int64_t *timestamps, int n);
uint64_t sm_oracle_rate(const int64_t *coinbase, const int64_t *subsidy,
                        const int64_t *block_bytes, int n);

// The seed-driven generator (gen.c): regenerate the identical action stream from
// `seed`, fold it, and report input_digest (rolling hash of the fed txs) +
// state_digest. trace_blocks>0 prints a checkpoint digest every that-many blocks.
// Returns the number of transactions emitted. cov (≥ SM_EV_COUNT, or NULL) gets
// the final coverage counters. If inv_fail != NULL the structural invariant
// battery runs after every block and *inv_fail accumulates any violations (a
// C-harness correctness net beyond the digest; not part of cross-language
// conformance, so ports may omit it). If prop_digest != NULL, the property-mode
// per-block fingerprint (sm_block_fingerprint) is accumulated into it and its
// violation count flows into *inv_fail (this REPLACES the structural battery for
// that run); pass NULL to keep the legacy structural-only behaviour. The random
// generation (build_tx / PRNG draw order) is untouched either way, so the
// input_digest / state_digest stay frozen.
uint64_t sm_generate(uint64_t seed, uint64_t count, int trace_blocks,
                     uint8_t input_digest[32], uint8_t state_digest[32], int64_t *cov,
                     int64_t *inv_fail, uint8_t *prop_digest);

// Structural invariants over a fold state (gen.c). Returns the number of
// violations (0 = healthy); prints the first few. `mtp` is the block just folded.
int sm_check_invariants(SmState *s, int64_t mtp);

// A recorded block for the reorg harness: its (height, mtp, rate) and the half-open
// range [tx_lo, tx_hi) of the flat tx array it owns. Filled by sm_record_chain.
typedef struct { int64_t height, mtp; uint64_t rate; int tx_lo, tx_hi; } SmRecBlk;

// Generate the SAME state-aware chain as `random` (seed, count) — folding it into a
// throwaway state so build_tx sees correct state — and RECORD each realized tx into
// txs[] and each block into blocks[]. Returns the number of txs recorded; writes the
// block count to *n_blocks. Bounded by max_blocks / max_txs (stops early). The reorg
// harness then re-folds slices of (blocks, txs) into fresh states to prove the fold
// is a pure function of the block sequence (replay / resume / clear-rebuild / fork).
uint64_t sm_record_chain(uint64_t seed, uint64_t count,
                         SmRecBlk *blocks, int *n_blocks, int max_blocks,
                         SmTx *txs, int max_txs);

// ── §1/§2/§3 wire payload codec (decode.c) — the differential-fuzz surface ────
// The base fold consumes already-decoded SmCarriers; this codec is the byte layer
// the real indexer's strict, fail-closed parse ("indexers MUST agree byte-for-byte
// on validity", §0) lives in, exercised by `sm fuzz`. Pinned in SPEC-conformance.md.

// Decode one OP_RETURN payload (the bytes of the single minimal push, §1) into a
// carrier: ACTION (prefix 0xFF ‖ magic[2] + opcode 0x01..0x0F, fields parse per
// §2/§3) or IGNORE (everything else — the other chain's magic, unknown opcode,
// field/length mismatch, non-prefix). `magic` is the active coin's two prefix
// bytes (PepeNet 0x50 0x4E, DogeNet 0x44 0x4E); NULL or a mismatch is IGNORE,
// the same as unknown data. `value` is unused by the demux (kept for call-site
// uniformity); the caller sets car->value/car->vout. Fail-closed. `len` ≤ SM_CARRIER_MAX.
void sm_decode_payload(const uint8_t *payload, size_t len, uint64_t value,
                       const uint8_t magic[2], SmCarrier *car);

// Canonical wire encoding of a well-formed action (the inverse of the action path
// of sm_decode_payload). Writes 0xFF ‖ magic ‖ opcode ‖ body, ≤ SM_CARRIER_MAX
// bytes, and returns the length, or 0 if `a` is not encodable (bad opcode /
// field) or `magic` is NULL. Used by the grammar-aware fuzzer.
size_t sm_encode_action(const SmAction *a, const uint8_t magic[2], uint8_t out[SM_CARRIER_MAX]);

// ── property/reorg fingerprints (harness.c) ──────────────────────────────────
// Per-block property fingerprint: hashes order-independent derived aggregates
// (counts by state, Σlease, Σprice, Σdeposit-legs) into `h`, AND returns the
// count of property violations. Pinned in SPEC §8.
int sm_block_fingerprint(SmState *s, int64_t mtp, SHA256_CTX *h);

// CLI entry points for the harness modes (harness.c).
int sm_cmd_fuzz      (int argc, char **argv);
int sm_cmd_bfuzz     (int argc, char **argv);   // boundary-cluster fuzzer
int sm_cmd_properties(int argc, char **argv);
int sm_cmd_reorg     (int argc, char **argv);
int sm_cmd_reorgfuzz (int argc, char **argv);   // reorg-depth fuzzer
int sm_cmd_meta      (int argc, char **argv);   // metamorphic drop-closed at scale
int sm_cmd_coverage  (int argc, char **argv);   // generator/decode coverage assertion (C meta-test)

#endif
