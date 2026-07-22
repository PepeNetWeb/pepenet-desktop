// wallet.h — the desktop wallet, one module: identity (HD/BIP39/Keychain, WLT)
// plus the typed transaction seam (SwlReq/SwlRes → swl_run). Both halves live in
// wallet.c now; the transaction-building engine used to sit in the headless
// indexer (indexer/src/wallet.c) and be #included through a separate seam — it
// was vendored in here, where it belongs.
//
// Threading: the identity + address helpers are UI-thread. swl_run() BLOCKS
// (utxo reads → sign → a broadcast that can sit on the socket ~28 s) — call it
// only from a worker thread (src/ops.c), never the UI thread. It opens its own
// SQLite read connections (WAL-safe beside the sync thread).
#ifndef DESKTOP_WALLET_H
#define DESKTOP_WALLET_H

#include <stddef.h>
#include <stdint.h>
#include "signer.h"          // SignerKey (SwlReq.key)

// ── identity: the HD wallet ───────────────────────────────────────────────────
typedef struct {
    int     ok;
    int     created;            // fresh keypair generated this launch
    int     denied;             // keystore refused the key read — boot stopped
                                // (never regenerate: the key likely still exists)
    char    coin[16];
    uint8_t ver;                // coin's P2PKH version byte (for re-derivation)
    uint8_t entropy[16];        // BIP39 entropy — the recovery phrase's source
    uint8_t seckey[32];
    uint8_t pub[33];            // compressed
    uint8_t h160[20];
    char    address[64];        // base58check, coin's P2PKH version
    char    path[600];          // the key-file path (signer keypath; not written)
} DeskWallet;

extern DeskWallet WLT;

// Boot the wallet from the OS keystore (macOS Keychain): a stored 16-byte BIP39
// entropy derives the HD key (m/44'/3'/0'/0/0); otherwise a fresh HD wallet is
// created and stored. Every wallet is HD with a recovery phrase. Returns WLT.ok.
int wallet_boot(const char *coin, const char *dbpath);

// 1 once the wallet is booted (every wallet is HD with a recovery phrase).
int  wallet_has_phrase(void);

// The 12-word recovery phrase. UI-thread static buffer — treat as sensitive:
// only render it behind an explicit reveal action.
const char *wallet_mnemonic(void);

// Replace the wallet from a typed 12-word phrase (validates words + checksum).
// Persists the new entropy; WLT reflects the new address immediately, but chain
// balances reload only on restart. 1 ok, 0 invalid phrase / keystore failure.
int  wallet_restore(const char *mnemonic);

// The active coin's name ("pep" until something else boots) — display/checks.
const char *wallet_coin(void);

// Real base58check validation against the active coin's P2PKH version byte
// (demo mode validates too — WLT.coin is set from argv without booting keys).
int wallet_addr_valid(const char *addr);

// Decode a valid address to its hash160 (same version check). 1 on success.
int wallet_addr_decode(const char *addr, uint8_t out160[20]);

// hash160 → the active coin's P2PKH address (display). 1 on success.
int wallet_h160_addr(const uint8_t h160[20], char *out, size_t cap);

// ── the typed transaction seam (SwlReq/SwlRes) ────────────────────────────────
// Structured call per operation: typed args in, txid/status/error out, no argv,
// no stdout scraping. Every guard, byte layout and the pre-broadcast self-check
// gate (synthetic-block parse → §4 attribution → engine decode) live in wallet.c.

// Mirrors wallet.c's MAX_INS (compile-checked in wallet.c).
#define SWL_MAX_INS 16

typedef struct { uint8_t txid[32]; uint32_t vout; } SwlOutpoint;
typedef struct { uint8_t txid[32]; uint32_t vout; int64_t value; } SwlSpendable;

typedef enum {
    SWL_SEND,       // plain P2PKH payment                → to160, amount
    SWL_CLAIM,      // §3.2 commit→claim, auto-phased     → name, amount=rent
    SWL_RENEW,      // §3.5 bare renew-ALL (water-fill)   → amount=rent
    SWL_TRANSFER,   // §3.6 gift: names[]/nnames selective bitmap; nnames == 0
                    // is the bare all-form (EVERY unlocked name) → to160
    SWL_SELL,       // §3.7 open listing                  → name, price, window_s
    SWL_RELEASE,    // §3.6 selective bitmap release      → names[]/nnames (1..16 bits, one tx)
    SWL_RESERVE,    // §3.7 deposit both 0.5% legs        → name
    SWL_SETTLE,     // §3.7 pay the remainder             → name
    SWL_PAY,        // §3.7 pay a directed offer in full  → name
    SWL_OFFER,      // §3.7 SELL_TO directed offer        → name, to160, price (2 h fixed window)
} SwlOp;

typedef struct {
    SwlOp       op;
    const char *dbpath;         // indexer projection (utxos, names, blocks)
    const char *ip;             // broadcast peer
    SignerKey   key;            // caller acquires + releases (signer.h)
    int         dry_run;        // build + sign + self-check, skip broadcast
    int         force_recommit; // SWL_CLAIM: sidecar salt never indexed → redo commit
    int64_t     fee;            // koinu, ≥ the 0.001 relay floor

    // The queue's coin view (ops.c; NULL/0 = plain confirmed-only funding).
    // `virt` are outputs the db doesn't have yet — in-flight change — listed
    // FIRST in the selectable set so the builder chains off the newest link.
    // `locked` are confirmed outpoints already spent by in-flight links;
    // funding from one again would self-double-spend the chain. want_change
    // pads selection by one dust unit so the tx always carries a change
    // output: the next link spends it, and the queue's sweep reads its
    // presence in the db as proof the tx confirmed exactly as built.
    const SwlSpendable *virt;   int nvirt;
    const SwlOutpoint  *locked; int nlocked;
    int         want_change;
    int         sweep;          // SEND: spend every input, leave NO change — the
                                // recipient gets balance − fee (any sub-dust
                                // remainder folds into the fee). Overrides
                                // want_change (a swept wallet has nothing to chain).

    uint8_t     to160[20];      // SEND / TRANSFER destination
    int64_t     amount;         // send amount · post burn · vote weight · claim/renew rent
    char        text[512];      // POST body (≤ 80 UTF-8 bytes enforced)
    uint8_t     target[32];     // VOTE target txid (internal byte order)
    uint32_t    vout;           // VOTE target output
    int         up;             // VOTE direction
    char        name[24];       // CLAIM/SELL/RESERVE/SETTLE/PAY/OFFER
    uint64_t    price;          // SELL/OFFER price, koinu
    uint32_t    window_s;       // SELL listing window (0 = the 5 h floor)

    // §3.5 bitmap batches: RELEASE always uses this list (1..16 names, one
    // tx); RENEW and TRANSFER use it for their SELECTIVE forms — nnames == 0
    // is the bare all-form (renew: water-fill the whole set; transfer: gift
    // every unlocked name).
    char        names[16][24];
    int         nnames;
} SwlReq;

typedef enum {
    SWL_R_OK = 0,           // tx built (+ broadcast unless dry_run)
    SWL_R_ERR,              // refused or failed — res.err says why
    SWL_R_COMMITTED,        // CLAIM phase 1 sent: salt in the sidecar, commit
                            // broadcast; run SWL_CLAIM again once it indexes
    SWL_R_WAIT_COMMIT,      // CLAIM: commit not in the projection yet — sync
                            // on, then retry (same-block claims are dropped)
} SwlCode;

// a fully-signed tx is at most this (16-in / few-out P2PKH stays well under)
#define SWL_RAW_MAX 8192

typedef struct {
    SwlCode  code;
    char     err[192];      // SWL_R_ERR: GUI-ready reason
    char     txid[65];      // display-order hex of the built tx ("" if none)
    int      accepted;      // broadcast: 1 peer echoed it back, -1 sent unechoed
    int      dry;           // 1 = dry run stopped before the socket
    int      net_fail;      // SWL_R_ERR was the broadcast socket, not a guard
                            // refusal — nothing left this machine; retryable
    int64_t  spent_inputs;  // Σ selected utxos (koinu)
    int64_t  change;        // returned to our address in the same tx
    uint8_t  in0_txid[32];  // first spent outpoint — watch it to detect confirm
    uint32_t in0_vout;

    // the queue's link record: every outpoint the tx spends (locks), and the
    // change outpoint the next link may chain off
    uint8_t     txid32[32]; // internal byte order (res.txid is display hex)
    SwlOutpoint ins[SWL_MAX_INS];
    int         nins;
    int         has_change;
    uint32_t    change_vout;
    int64_t     change_value;
    // the signed bytes themselves — the queue keeps them with the link so a tx
    // no mempool ever took can be RE-announced later. Without this, "sent but
    // never echoed" is a signed tx that exists nowhere but in the balance math.
    uint8_t     raw[SWL_RAW_MAX];
    uint32_t    rawlen;
} SwlRes;

// Run one wallet operation start to finish. Returns 1 unless res->code is
// SWL_R_ERR. Every refusal reason mirrors the wallet's own client guards.
int swl_run(const SwlReq *req, SwlRes *res);

// Re-announce an already-signed tx (a pending link no peer has echoed): the
// same candidate ladder as the original broadcast, idempotent for any pool
// that already holds it. 1 = echoed back, -1 = sent unechoed, 0 = rejected or
// nobody reachable. No key material involved — raw bytes in, frames out.
int swl_rebroadcast(const char *coinname, const char *ip, const char *dbpath,
                    const uint8_t *tx, size_t txlen, const uint8_t txid32[32]);

// Built-in vector suite (build/sign/verify through the real indexer pipeline,
// no network) — dev hook, prints to stdout, 0 = all passed.
int swl_selftest(void);

#endif
