// model.h — the UI-facing data model.
//
// One data source today: the chain projections (engine.h). The dns/web plane
// (mesh status, zone folds, the Discovery directory) lands with the dnsnet/
// webproxy embeds and surfaces here as read-only snapshots the same way.
#ifndef DNET_MODEL_H
#define DNET_MODEL_H

#include <stdint.h>
#include <stddef.h>

#include "dnsnet.h"         // DnsStatus — the dns plane's 1 Hz snapshot
#include "webproxy.h"       // WebStatus — the DANE proxy's 1 Hz snapshot

// per-name byte budget of the DNS overlay (meld §5: the durable 1 yr plane) —
// zone-editor gauges read against this once the dns embed lands
#define ZONE_BUDGET 50000

// NS_CLAIMING is model-local: the §3.2 commit→claim pipeline (ops.c) holds the
// name, the chain doesn't yet — the row shows so the user sees their claim
// working; it converts to NS_OWNED when the claim folds into the projection.
typedef enum { NS_OWNED, NS_LISTED, NS_RESERVED, NS_OFFERED, NS_CLAIMING } NameState;

typedef struct {
    char      name[64];
    NameState st;
    int64_t   expiry;           // lease end
    int64_t   bytes_left;       // of ZONE_BUDGET (dns overlay; wired later)
    int64_t   list_price;       // LISTED
    int64_t   list_window_end;
    char      offered_to[24];   // OFFERED (truncated addr)
    int64_t   offer_price;
    int64_t   reserve_end;      // RESERVED: buyer's settle deadline
    int       pending;          // OpsPend: the op queued/in flight for this
                                // name (0 none) — drives the action matrix
} MyName;

typedef struct {
    char    name[64];
    int64_t price;
    int64_t window_end;
    int     reserved_by_other;
    int     reserved_by_me;
    int64_t reserve_end;
    int     is_mine;            // our own listing — shown in Market, not biddable
    int     pending;            // OpsPend: our op queued/in flight for this name
} Listing;

typedef struct {
    char    name[64];
    int64_t price;
    int64_t expires;
    int     pending;            // OpsPend: our PAY queued/in flight
} OfferToMe;

typedef struct {
    int demo;

    // wallet
    int64_t balance;
    int64_t incoming;           // unconfirmed credits in the relay mempool (koinu);
                                // shown separately in the footer, NOT spendable
    char    address[64];
    int     has_wallet;

    MyName names[16];
    int    nnames;

    Listing listings[16];
    int     nlist;

    OfferToMe offers[4];
    int       noffers;

    // dns plane status (dnsnet.h; refreshed 1 Hz in model_tick)
    DnsStatus dns;

    // DANE proxy status (webproxy.h; refreshed 1 Hz in model_tick)
    WebStatus web;

    // chain status (engine)
    int64_t  height;
    int64_t  activation;        // names live at ≥ this height (0 = unknown)
    uint64_t rate;
    int64_t  year_cost;         // koinu per name-year
    int64_t  fee;               // per-tx network-fee quote, koinu (fee.h)
    int      running, syncing, synced, unreachable;

    int64_t now;                // frame clock (demo: frozen base + wall delta)
} Model;

extern Model M;

void model_init(int demo, int64_t wall_now);
void model_tick(int64_t wall_now);          // ~1 Hz: engine refresh + clock
// Re-read pending-op flags off the live queue (no DB/fold). Call right after a
// dialog submits so its row's action button greys out the same frame.
void model_refresh_pending(void);
void model_demo_load(void);                 // fixtures matching the mockups

// The one network-fee number every surface uses (UI_FEE_K resolves here, ops
// attaches it): demo pins the relay floor, live returns the engine's quote.
// Whatever a dialog just displayed is what the built tx pays.
int64_t model_fee_k(void);

#endif
