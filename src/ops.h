// ops.h — live-mode transaction operations for the UI.
//
// The UI thread SUBMITS an op (copied args, returns immediately); ops.c keeps
// a FIFO of such intents and a worker thread builds each into a signed,
// broadcast tx through src/wallet.c. Ops no longer wait for each other's
// confirmations: every tx spends the previous tx's change, unconfirmed
// ancestors mine together, so a whole burst folds in the next block (~25 ops
// per block, the Doge-family relay cap on unconfirmed ancestors). The queue
// serializes only where the protocol does:
//   · two ops on the SAME name — projection-gated pre-flights need the
//     earlier op folded (a transfer counts as every name);
//   · RELEASE — its §3.5 bitmap anchors the whole owned set, so it waits
//     until no set-mutating tx (claim/settle/pay/transfer/release) is in
//     flight, then anchors fresh;
//   · commit → claim — consensus wants the commit ≥1 block deep; the wait
//     is parked PER NAME (ops_poll fires the claim), the app stays live;
//   · reserve → settle — a bid/reclaim is ONE user action: the settle parks
//     per name and auto-fires once the fold shows us as the winning buyer
//     (outbid / listing-gone give up loudly; the Market row's manual Settle
//     stays as the fallback, e.g. after a restart drops the in-memory park).
// If a chain link is malleated or conflicted away, the sweep detects it,
// returns the dead intents to the queue front, and rebuilds them against the
// confirmed view — funds are single-key and sighash-pinned, so a break costs
// a block of latency, never money. State that can't survive a restart is
// recoverable: commits from the wallet's .commits sidecar (open the claim
// dialog again), anything else by resubmitting.
#ifndef DESKTOP_OPS_H
#define DESKTOP_OPS_H

#include <stdint.h>

typedef enum { OPS_IDLE, OPS_BUSY, OPS_DONE, OPS_FAIL } OpsPhase;

typedef struct {
    OpsPhase phase;
    char     label[48];     // what's building / just ran ("engrave", "claim 'wow'")
    char     txid[65];      // DONE: display-order hex
    char     err[192];      // FAIL: GUI-ready reason
    int      dry;           // DONE was a dry run (PEPENET_DRYRUN=1)
    int      accepted;      // DONE: 1 peer echoed the tx, -1 sent unechoed
    int      pending;       // ≥1 broadcast tx awaits confirmation
    int      claim_wait;    // ≥1 commit is waiting to be claimed (auto)
    int      settle_wait;   // ≥1 reserve is waiting to auto-settle (§3.7)
    int      inflight;      // broadcast, unconfirmed txs (the chain)
    int      queued;        // intents waiting to build
    char     hold[96];      // why the queue head waits ("" = it doesn't)
} OpsStatus;

// main.c, live boot only. Strings are copied; h160 is the watched address
// (public — key material stays behind signer.h).
void ops_init(const char *coin, const char *dbpath, const char *ip,
              const uint8_t h160[20]);

int  ops_available(void);           // signer present — live signing possible
// NULL = an op can be queued now; else the human reason the confirm is dead
// (no signer, or the queue is full). Confirmation waits no longer gate.
const char *ops_gate(void);
void ops_status(OpsStatus *out);
void ops_ack(void);                 // UI consumed DONE/FAIL → IDLE
// Net effect of everything in flight and queued (≤ 0) — the db still shows
// spent inputs unspent until the chain folds; add this for an honest chip.
int64_t ops_balance_delta(void);
// Names in the §3.2 commit→claim pipeline (queued, commit in flight, or
// parked for the claim), deduped — the Names list shows them as CLAIMING
// until the claim folds into the projection. Returns the count.
int ops_claiming(char (*out)[24], int max);

// What's queued or in flight for a name — the UI's action-gating matrix
// (release/transfer pending freeze the name; sell/offer pending keep renew).
// OPS_PEND_OTHER = a buy-side op (reserve/settle/pay) touches it.
typedef enum { OPS_PEND_NONE = 0, OPS_PEND_RENEW, OPS_PEND_SELL, OPS_PEND_OFFER,
               OPS_PEND_TRANSFER, OPS_PEND_RELEASE, OPS_PEND_CLAIM,
               OPS_PEND_OTHER } OpsPend;
OpsPend ops_name_pending(const char *name);
int ops_pending_buckets(const char *name);   // debug: bucket bitfield (ops.c)
// ~1 Hz from model_tick (live): the confirmation sweep + claim parking + the
// queue pump.
void ops_poll(int64_t height, int64_t now);

// Submitters (UI thread). Return 1 if the op was queued — call only when
// ops_gate() is NULL. All amounts koinu; the attached fee is model_fee_k()
// (== UI_FEE_K), read at queue time — the number the dialog just displayed.
// sweep: spend every input, leave no change (the max button) — recipient gets
// `amount` (= balance − fee), any sub-dust remainder folds into the fee.
int ops_send(const uint8_t to160[20], int64_t amount, int sweep);
int ops_claim(const char *name, int64_t rent);      // commit now, claim auto
int ops_renew(int64_t rent);                        // §3.5 bare: water-fills ALL names
// §3.5 selective renew: rent water-fills only these names (one bitmap tx)
int ops_renew_sel(const char (*names)[24], int n, int64_t rent);
int ops_transfer(const uint8_t to160[20]);          // §3.6 bare: ALL unlocked names
// §3.6 selective transfer: ONLY these names move (one bitmap tx, one fee) —
// what the per-name transfer button means
int ops_transfer_sel(const char (*names)[24], int n, const uint8_t to160[20]);
int ops_sell(const char *name, uint64_t price, uint32_t window_s);
// §3.7 SELL_TO: directed offer at price; the named buyer has the fixed 2 h
// window to PAY. Fee-only; the name movement-locks (renew still works).
int ops_offer(const char *name, const uint8_t to160[20], uint64_t price);
int ops_release(const char *name);
// §3.6 batch release: 1..16 names leave in ONE bitmap tx (one fee)
int ops_release_multi(const char (*names)[24], int n);
// §3.7 buy/reclaim phase 1: the settle parks and auto-fires when the reserve
// folds with us as buyer — the dialog gates on funding the WHOLE price + 2
// fees, so the parked settle can always build.
int ops_reserve(const char *name);
int ops_settle(const char *name);       // manual fallback (park lost/timed out)
int ops_payoffer(const char *name);

#endif
