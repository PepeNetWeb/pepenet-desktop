// model.c — model plumbing over the chain-projection bridge (engine.h).
// The dns/web plane's status feeds land here with the dnsnet/webproxy embeds.
#include "model.h"
#include "engine.h"
#include "wallet.h"
#include "ops.h"
#include "fee.h"            // FEE_FLOOR_K — model_fee_k's demo/pre-sync value
#include "sm.h"             // SM_OWNED.. states off the names projection

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

Model M;

static int64_t feed_height = -1;

static void addr_short_from_hex(char *out, size_t cap, const char *hex) {
    size_t n = strlen(hex);
    if (n <= 13) snprintf(out, cap, "%s", hex);
    else snprintf(out, cap, "%.6s…%s", hex, hex + n - 5);
}

// The commit→claim pipeline's names, appended as CLAIMING rows so a fresh
// commit shows in Names immediately, plus each row's pending-op flag (the
// action matrix reads it). Rebuilt every tick (the pipeline moves between
// blocks); the projection rows in front never carry NS_CLAIMING, so stripping
// the old tail first makes this idempotent.
static void refresh_claiming(void) {
    int n = 0;
    for (int i = 0; i < M.nnames; i++)
        if (M.names[i].st != NS_CLAIMING) M.names[n++] = M.names[i];
    M.nnames = n;
    char cl[8][24];
    int nc = ops_claiming(cl, 8);
    for (int i = 0; i < nc && M.nnames < 16; i++) {
        int have = 0;                   // claim just folded → the row is real now
        for (int j = 0; j < M.nnames && !have; j++)
            have = !strcmp(M.names[j].name, cl[i]);
        if (have) continue;
        MyName *m = &M.names[M.nnames++];
        memset(m, 0, sizeof *m);
        snprintf(m->name, sizeof m->name, "%s", cl[i]);
        m->st = NS_CLAIMING;
    }
    for (int i = 0; i < M.nnames; i++)
        M.names[i].pending = M.names[i].st == NS_CLAIMING
                           ? OPS_PEND_CLAIM : (int)ops_name_pending(M.names[i].name);
}

// Re-read every row's pending flag straight off the live ops queue (an in-memory
// scan, no DB, no fold). The queue is populated the instant a dialog submits, so
// calling this right after an action flips the row's button to disabled on the
// same frame instead of waiting for the op to fold at the next block.
// OPS_TRACE=1 → log every pending transition for a name and which internal
// bucket still holds it, so a flicker points straight at the gap that caused it.
static void pend_trace(const char *tag, const char *name, int val) {
    static int on = -1;
    if (on < 0) on = getenv("OPS_TRACE") != NULL;
    if (!on) return;
    static struct { char name[24]; int val; } c[64];
    static int n;
    for (int i = 0; i < n; i++)
        if (!strcmp(c[i].name, name)) {
            if (c[i].val != val)
                fprintf(stderr, "[pend] %s %-16s %d->%d buckets=0x%02x\n",
                        tag, name, c[i].val, val, ops_pending_buckets(name));
            c[i].val = val;
            return;
        }
    if (n < 64) { snprintf(c[n].name, 24, "%s", name); c[n].val = val; n++; }
}

void model_refresh_pending(void) {
    if (M.demo) return;
    for (int i = 0; i < M.nnames; i++)
        if (M.names[i].st != NS_CLAIMING) {
            M.names[i].pending = (int)ops_name_pending(M.names[i].name);
            pend_trace("name", M.names[i].name, M.names[i].pending);
        }
    for (int i = 0; i < M.nlist; i++) {
        M.listings[i].pending = (int)ops_name_pending(M.listings[i].name);
        pend_trace("list", M.listings[i].name, M.listings[i].pending);
    }
    for (int i = 0; i < M.noffers; i++)
        M.offers[i].pending = (int)ops_name_pending(M.offers[i].name);
}

// names/market rows owned by (or aimed at) our address, straight off the
// projection. Runs when the tip moves — ownership only changes with blocks.
static void refresh_names_from_chain(void) {
    EngineName rows[16];
    int n = engine_my_names(WLT.h160, rows, 16);
    M.nnames = 0;
    for (int i = 0; i < n; i++) {
        MyName *m = &M.names[M.nnames++];
        memset(m, 0, sizeof *m);
        snprintf(m->name, sizeof m->name, "%s", rows[i].name);
        m->expiry = rows[i].lease_expiry;
        m->bytes_left = ZONE_BUDGET;    // dns-overlay accounting rides the dnsnet embed
        switch (rows[i].st) {
        case SM_LISTED:
            m->st = NS_LISTED;
            m->list_price = (int64_t)rows[i].price;
            m->list_window_end = rows[i].offer_expiry;
            break;
        case SM_OFFERED: {
            m->st = NS_OFFERED;
            m->offer_price = (int64_t)rows[i].price;
            m->reserve_end = rows[i].offer_expiry;      // the directed window
            char a[64];
            if (wallet_h160_addr(rows[i].buyer, a, sizeof a))
                addr_short_from_hex(m->offered_to, sizeof m->offered_to, a);
            break;
        }
        case SM_RESERVED:
            m->st = NS_RESERVED;
            m->reserve_end = rows[i].reserve_expiry;
            break;
        default:
            m->st = NS_OWNED;
            break;
        }
    }

    // the open marketplace: every §3.7 listing across the projection (browse +
    // bid), our OWN listings included and flagged. Reserved rows carry who won,
    // so a name reserved by us shows Settle and one reserved by another blocks.
    n = engine_listings(rows, 16);
    M.nlist = 0;
    for (int i = 0; i < n && M.nlist < 16; i++) {
        Listing *l = &M.listings[M.nlist++];
        memset(l, 0, sizeof *l);
        snprintf(l->name, sizeof l->name, "%s", rows[i].name);
        l->price = (int64_t)rows[i].price;
        l->window_end = rows[i].offer_expiry;               // listing window end
        l->is_mine = M.has_wallet && !memcmp(rows[i].owner, WLT.h160, 20);
        l->pending = (int)ops_name_pending(l->name);
        if (rows[i].st == SM_RESERVED) {
            l->reserve_end = rows[i].reserve_expiry;
            if (M.has_wallet && !memcmp(rows[i].buyer, WLT.h160, 20))
                l->reserved_by_me = 1;
            else
                l->reserved_by_other = 1;
        }
    }
    // directed offers aimed at me (SELL_TO) → the pay-to-settle cards
    n = engine_market_mine(WLT.h160, rows, 16);
    M.noffers = 0;
    for (int i = 0; i < n; i++)
        if (rows[i].st == SM_OFFERED && M.noffers < 4) {
            OfferToMe *o = &M.offers[M.noffers++];
            snprintf(o->name, sizeof o->name, "%s", rows[i].name);
            o->price = (int64_t)rows[i].price;
            o->expires = rows[i].offer_expiry;
            o->pending = (int)ops_name_pending(o->name);
        }
}

void model_init(int demo, int64_t wall_now) {
    memset(&M, 0, sizeof M);
    M.demo = demo;
    M.now = wall_now;
    if (demo) {
        model_demo_load();
        return;
    }
    if (WLT.ok) {                       // dev wallet booted in main.c init
        M.has_wallet = 1;
        snprintf(M.address, sizeof M.address, "%s", WLT.address);
    }
}

void model_tick(int64_t wall_now) {
    M.now = wall_now;
    if (M.demo) return;
    EngineStatus st;
    engine_status(&st);
    M.height = st.height;
    M.activation = st.activation;
    M.rate = st.rate;
    M.year_cost = st.year_cost;
    M.fee = st.fee;
    M.running = st.running;
    // "synced" = at the peer's declared tip (version.start_height, captured one
    // round-trip into each pass) — NOT "no pass on the wire": a caught-up pass
    // idles ~30 s against getblocks-silence before it can end, which would keep
    // the pill on "syncing…" most of the time at tip. "syncing" = on the wire
    // or known-behind (so a mid-pass death while behind doesn't flash green
    // between passes). Peer declares no height → the old pass-boundary signal.
    M.syncing = st.pass_active || (st.peer_height > 0 && st.height < st.peer_height);
    M.synced = st.peer_height > 0 ? st.height >= st.peer_height
                                  : (!st.pass_active && st.last_rc == 0);
    M.unreachable = !st.pass_active && st.last_rc != 0 && st.passes > 0;
    {   // stderr breadcrumb on transitions only (soak logs; the pill must not flap)
        static int last = -1;
        int now = M.synced ? 0 : M.unreachable ? 1 : 2;
        if (now != last) {
            fprintf(stderr, "sync: %s (height %lld, peer %lld)\n",
                    now == 0 ? "at tip" : now == 1 ? "peer unreachable" : "behind",
                    (long long)st.height, (long long)st.peer_height);
            last = now;
        }
    }
    ops_poll(st.height, wall_now);      // confirm watch + the commit→claim chain
    if (M.has_wallet) {                 // an unconfirmed spend isn't in the db yet
        M.balance = engine_balance(WLT.h160) + ops_balance_delta();
        M.incoming = M.demo ? 0 : engine_incoming(WLT.h160);   // unconfirmed credits (mempool)
    } else {
        M.incoming = 0;
    }

    if (st.height != feed_height) {
        refresh_names_from_chain();
        feed_height = st.height;
    }
    refresh_claiming();                 // pipeline moves between blocks too
    model_refresh_pending();            // clear/drain pending flags between blocks
    dnsnet_status(&M.dns);
    webproxy_status(&M.web);
}

int64_t model_fee_k(void) {
    if (M.demo || M.fee < FEE_FLOOR_K) return FEE_FLOOR_K;   // pre-sync too
    return M.fee;
}
