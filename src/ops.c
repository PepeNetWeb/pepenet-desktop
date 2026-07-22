// ops.c — see ops.h. The tx queue: intents in, chained links out, one sweep.
//
// v1 ran one op at a time and gated everything until its tx confirmed —
// 1 action per block. Now a FIFO of INTENTS (op args, replayable) feeds a
// worker that builds LINKS (broadcast, unconfirmed txs) back to back; each
// link spends the previous link's change, unconfirmed ancestors mine
// together, and a whole burst folds in the next block. Three rules keep the
// chain sound:
//   · every confirmed outpoint an in-flight link spends is LOCKED out of
//     later coin selection (a second spend would self-double-spend);
//   · the newest link's change rides the next build as a VIRTUAL utxo,
//     listed first so in-order selection keeps the chain linear;
//   · builds force a ≥dust change output (want_change), so the sweep can
//     prove "confirmed exactly as built" by finding that outpoint in the db.
// Depth stays one under the Doge-family 25-ancestor relay cap; overflow
// intents wait in the queue for a block.
//
// The sweep (each new tip): a link whose spent outpoints all left the utxo
// set has FOLDED — outputs are sighash-pinned and txid-independent, so even
// a malleated variant executed the same op. The as-built txid matters only
// to descendants: the youngest link whose change outpoint IS in the db
// proves itself and every ancestor confirmed as built (each spends the
// previous link's real change). If the head folded but no as-built change
// survived anywhere, one link confirmed under a different txid (malleated)
// or was conflicted away: the fingerprint scan finds the substitute change —
// same value, at our address, under a txid we never built, on a link whose
// inputs are gone — every link through it has folded, everything after it is
// dead and goes back to the queue front to rebuild against the fresh view.
// Funds are single-key and the outputs sighash-pinned: a break costs one
// block of latency, never money. If the picture matches nothing (deep reorg,
// db gap), the queue freezes loudly instead of guessing — rebuilding a
// folded op would run it twice.
//
// Serialization the protocol itself imposes (ops.h has the user story):
// same-name ops hold until the earlier one confirms; RELEASE holds while any
// set-mutating link is in flight (its §3.5 anchor covers the whole owned
// set), then anchors fresh — ops queued BEHIND it are safe, they fold after
// it; commit → claim parks per name until the commit is ≥1 block deep.
#include "ops.h"
#include "wallet.h"
#include "signer.h"
#include "engine.h"
#include "model.h"          // model_fee_k — the fee the dialogs just displayed
#include "chain.h"          // idx_hex_to_hash
#include "sm.h"             // SM_LISTED/SM_RESERVED — the reserve→settle park
                            // reads the fold's verdict off the projection
#include "ui/strings.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PENDING_STALE_S  1800   // oldest link unconfirmed 30 min → hold + warn
#define CLAIM_WAIT_MAX_S 1800   // commit unindexed for 30 min → give up (retry re-commits)
#define LINKS_MAX  24           // in-flight txs — one under the 25-ancestor relay cap
#define Q_MAX      (LINKS_MAX + 16)  // rebuild headroom: user pushes stop at 16
#define Q_USER_MAX 16
#define CLAIMS_MAX  8           // parked commit→claim waits (per name)
#define STALE_MAX   8           // names whose commit never indexed
#define BCAST_TRIES 3           // broadcast attempts before an intent is dropped

typedef struct {                // queued, not yet built (replayable op args)
    SwlReq  req;                // paths/coin-view NULL here — stamped at build
    char    label[48];
    int     from_user;          // manual submit: may force_recommit a stale name
    int     tries;              // broadcast attempts so far
    int64_t est;                // ≥0 koinu the op is expected to move (chip honesty)
} Intent;

typedef struct {                // one broadcast, unconfirmed tx
    uint8_t     txid[32];
    char        label[48];
    SwlOutpoint in[SWL_MAX_INS];
    int         nin;
    int         has_change;
    uint32_t    change_vout;
    int64_t     change_value;
    int64_t     delta;          // ≤0 balance move once it folds
    int         mutator;        // will bump §3.5 last_set_mutation_height
    char        name[24];       // "" none, "*" every name (transfer)
    int64_t     since;          // stamped by the first poll that sees it as head
    SwlReq      intent;         // replay args if a break kills this link
    uint8_t     raw[SWL_RAW_MAX]; uint32_t rawlen;   // the signed bytes — kept so a
                                // tx no mempool took can be RE-announced per tip
} Link;

static struct {
    char coin[16], dbpath[512], ip[64];
    uint8_t h160[20];
    int inited;

    pthread_mutex_t mu;
    int busy;                   // worker alive
    int64_t breaks;             // chain rebuilds so far — the worker discards a
                                // build whose parent chain broke mid-signing

    Intent q[Q_MAX]; int qn;    // FIFO; [0] is the head
    Link links[LINKS_MAX]; int ln;  // broadcast order = chain order
    Intent cur; int cur_on;     // the head being built RIGHT NOW: out of the
                                // queue, link not yet appended. swl_run drops the
                                // mutex for the whole build+broadcast, so without
                                // this the name is pending in neither q nor links
                                // for that window — a UI pending-poll landing
                                // there would flash the row's button back on.
    int stale;                  // head link too old → stop growing the chain
    int rebc_on;                // a re-announce thread is on the wire (single-flight)
    char hold[96];              // why the head waits ("" = it doesn't)

    OpsStatus st;               // the mailbox (phase/label/txid/err/dry/accepted)

    struct {                    // §3.2 parked: commit sent, claim fires per name
        int active;
        char name[24];
        int64_t rent;
        int64_t started;
        int64_t last_try_h;
    } claims[CLAIMS_MAX];
    struct {                    // §3.7 parked: reserve sent, the settle fires
        int active;             // once the fold shows US as the winning buyer
        char name[24];          // (a bid/reclaim is ONE user action: the whole
        int64_t started;        // price is disclosed and gated up front)
        int64_t last_try_h;
    } settles[CLAIMS_MAX];
    char stale_commit[STALE_MAX][24];   // timed-out commits — a manual retry re-commits

    uint8_t done[64][32]; int done_n;   // ring of folded links' txids — their
                                        // unconsumed change is OURS, not a
                                        // malleation fingerprint
    int64_t checked_h;          // last tip the sweep ran at
    int loading;                // load_parks in progress — suppress re-persist
    int reconciled;             // startup settle-from-projection scan done once
} g = { .mu = PTHREAD_MUTEX_INITIALIZER };

// ── durable two-phase parks ──────────────────────────────────────────────────
// A commit→claim (or reserve→settle) is a two-tx flow: tx1 is broadcast, then
// tx2 fires once tx1 folds. The wait for tx2 lives in g.claims[]/g.settles[] —
// RAM only — so an app close between the two txs used to strand the second leg
// silently (the commit's fee is spent, the name never registers, and it even
// vanished from the pending list). We journal the active parks to a small file
// next to the db so a restart resumes them. The claim's salt is already durable
// in wallet's sidecar, so a resumed claim completes the EXISTING commit (no
// wasteful re-commit); the journal only needs the name + the chosen rent.
static void parks_path(char *out, size_t cap) {
    const char *slash = strrchr(g.dbpath, '/');
    if (slash) snprintf(out, cap, "%.*s/ops-pending-%s.txt", (int)(slash - g.dbpath), g.dbpath, g.coin);
    else       snprintf(out, cap, "ops-pending-%s.txt", g.coin);
}
// Rewrite the journal from the live parks (mutex held). tmp+rename = atomic, so
// a crash mid-write never leaves a torn file. Cheap: ≤16 short lines.
static void persist_parks(void) {
    if (g.loading || !g.inited) return;
    char path[600], tmp[640];
    parks_path(path, sizeof path);
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    for (int i = 0; i < CLAIMS_MAX; i++)
        if (g.claims[i].active) fprintf(f, "c %lld %s\n", (long long)g.claims[i].rent, g.claims[i].name);
    for (int i = 0; i < CLAIMS_MAX; i++)
        if (g.settles[i].active) fprintf(f, "s %s\n", g.settles[i].name);
    fclose(f);
    rename(tmp, path);
}
static void load_parks(void);    // defined after the park helpers it calls

void ops_init(const char *coin, const char *dbpath, const char *ip,
              const uint8_t h160[20]) {
    snprintf(g.coin, sizeof g.coin, "%s", coin);
    snprintf(g.dbpath, sizeof g.dbpath, "%s", dbpath);
    snprintf(g.ip, sizeof g.ip, "%s", ip);
    memcpy(g.h160, h160, 20);
    g.inited = 1;
    load_parks();               // resume any two-phase op stranded by a prior close
}

int ops_available(void) { return g.inited && signer_ready(); }

// ── small helpers (mutex held) ───────────────────────────────────────────────
// the op's display/primary name ("" none, "*" every name); CLASH decisions go
// through req_touches/req_clash, which know the §3.5 batch lists
static const char *op_name_key(const SwlReq *r) {
    switch (r->op) {
    case SWL_CLAIM: case SWL_SELL: case SWL_RESERVE:
    case SWL_SETTLE: case SWL_PAY: case SWL_OFFER: return r->name;
    case SWL_RELEASE: return r->nnames ? r->names[0] : r->name;
    case SWL_RENEW: return r->nnames ? r->names[0] : "";
    case SWL_TRANSFER: return r->nnames ? r->names[0] : "*";
    default: return "";
    }
}
static int req_touches(const SwlReq *r, const char *name) {
    if (!name[0]) return 0;
    switch (r->op) {
    case SWL_TRANSFER:
        if (r->nnames == 0) return 1;           // bare: moves every name
        /* selective: fall through to the list check */
        /* FALLTHROUGH */
    case SWL_RELEASE: case SWL_RENEW:           // bare renew (nnames 0) is a
        for (int i = 0; i < r->nnames; i++)     // whole-set water-fill: it
            if (!strcmp(r->names[i], name)) return 1;   // reads no rows and
        return 0;                               // clashes with nothing
    case SWL_CLAIM: case SWL_SELL: case SWL_RESERVE:
    case SWL_SETTLE: case SWL_PAY: case SWL_OFFER:
        return !strcmp(r->name, name);
    default: return 0;
    }
}
static int req_clash(const SwlReq *a, const SwlReq *b) {
    int a_all = a->op == SWL_TRANSFER && a->nnames == 0;
    int b_all = b->op == SWL_TRANSFER && b->nnames == 0;
    if (a_all || b_all) {
        // a bare transfer against any named traffic, either direction
        const SwlReq *o = a_all ? b : a;
        switch (o->op) {
        case SWL_TRANSFER: return 1;            // bare or selective
        case SWL_CLAIM: case SWL_SELL: case SWL_RESERVE:
        case SWL_SETTLE: case SWL_PAY: case SWL_OFFER: return 1;
        case SWL_RELEASE: case SWL_RENEW: return o->nnames > 0;
        default: return 0;
        }
    }
    switch (a->op) {
    case SWL_CLAIM: case SWL_SELL: case SWL_RESERVE:
    case SWL_SETTLE: case SWL_PAY: case SWL_OFFER:
        return req_touches(b, a->name);
    case SWL_TRANSFER:                          // selective (bare handled above)
    case SWL_RELEASE: case SWL_RENEW:
        for (int i = 0; i < a->nnames; i++)
            if (req_touches(b, a->names[i])) return 1;
        return 0;
    default: return 0;
    }
}
// what the op will move, fee included — the chip's projection while queued
// (reserve/settle/pay legs come from rows the build reads; count fee only)
static int64_t est_for(const SwlReq *r) {
    switch (r->op) {
    case SWL_SEND:
    case SWL_CLAIM: case SWL_RENEW: return r->amount + r->fee;
    default: return r->fee;
    }
}

static int stale_has(const char *name) {
    for (int i = 0; i < STALE_MAX; i++)
        if (!strcmp(g.stale_commit[i], name)) return 1;
    return 0;
}
static void stale_del(const char *name) {
    for (int i = 0; i < STALE_MAX; i++)
        if (!strcmp(g.stale_commit[i], name)) g.stale_commit[i][0] = 0;
}
static void stale_add(const char *name) {
    if (stale_has(name)) return;
    for (int i = 0; i < STALE_MAX; i++)
        if (!g.stale_commit[i][0]) {
            snprintf(g.stale_commit[i], 24, "%s", name);
            return;
        }
}

static int park_find(const char *name) {
    for (int i = 0; i < CLAIMS_MAX; i++)
        if (g.claims[i].active && !strcmp(g.claims[i].name, name)) return i;
    return -1;
}
static void park_claim(const char *name, int64_t rent) {
    if (park_find(name) >= 0) return;
    for (int i = 0; i < CLAIMS_MAX; i++)
        if (!g.claims[i].active) {
            g.claims[i].active = 1;
            snprintf(g.claims[i].name, 24, "%s", name);
            g.claims[i].rent = rent;
            g.claims[i].started = 0;        // stamped by the next poll
            g.claims[i].last_try_h = -1;
            persist_parks();
            return;
        }
    g.st.phase = OPS_FAIL;                  // 8 names mid-commit — say it, loudly
    snprintf(g.st.label, sizeof g.st.label, TR(S_OPS_LBL_CLAIM_FMT), name);
    snprintf(g.st.err, sizeof g.st.err,
             "%s", TR(S_OPS_ERR_TOO_MANY_CLAIMS));
}
static void unpark(const char *name) {
    int i = park_find(name);
    if (i >= 0) { g.claims[i].active = 0; persist_parks(); }
}

static int spark_find(const char *name) {
    for (int i = 0; i < CLAIMS_MAX; i++)
        if (g.settles[i].active && !strcmp(g.settles[i].name, name)) return i;
    return -1;
}
static void park_settle(const char *name) {
    if (spark_find(name) >= 0) return;
    for (int i = 0; i < CLAIMS_MAX; i++)
        if (!g.settles[i].active) {
            g.settles[i].active = 1;
            snprintf(g.settles[i].name, 24, "%s", name);
            g.settles[i].started = 0;       // stamped by the next poll
            g.settles[i].last_try_h = -1;
            persist_parks();
            return;
        }
    g.st.phase = OPS_FAIL;                  // 8 reserves mid-fold — say it
    snprintf(g.st.label, sizeof g.st.label, TR(S_OPS_LBL_SETTLE_FMT), name);
    snprintf(g.st.err, sizeof g.st.err,
             "%s", TR(S_OPS_ERR_TOO_MANY_RESERVES));
}
static void unpark_settle(const char *name) {
    int i = spark_find(name);
    if (i >= 0) { g.settles[i].active = 0; persist_parks(); }
}

// Restore the durable parks at startup (mutex held; g fresh, slots free). The
// `loading` guard keeps park_claim/park_settle from rewriting the file per line.
static void load_parks(void) {
    char path[600];
    parks_path(path, sizeof path);
    FILE *f = fopen(path, "r");
    if (!f) return;
    pthread_mutex_lock(&g.mu);
    g.loading = 1;
    char line[160];
    while (fgets(line, sizeof line, f)) {
        char nm[24]; long long rent;
        if (line[0] == 'c' && sscanf(line, "c %lld %23s", &rent, nm) == 2) park_claim(nm, (int64_t)rent);
        else if (line[0] == 's' && sscanf(line, "s %23s", nm) == 1)        park_settle(nm);
    }
    g.loading = 0;
    pthread_mutex_unlock(&g.mu);
    fclose(f);
    persist_parks();            // normalize the file to what actually loaded
}

static int push_front(const Intent *it) {
    if (g.qn >= Q_MAX) return 0;
    memmove(g.q + 1, g.q, (size_t)g.qn * sizeof g.q[0]);
    g.q[0] = *it;
    g.qn++;
    return 1;
}
static void mark_done(const uint8_t txid[32]) {
    memcpy(g.done[g.done_n++ & 63], txid, 32);
}
static void pop_links(int n) {          // oldest n links are done
    for (int i = 0; i < n; i++) mark_done(g.links[i].txid);
    memmove(g.links, g.links + n, (size_t)(g.ln - n) * sizeof g.links[0]);
    g.ln -= n;
    g.stale = 0;                        // progress — restart the head clock
}

// Why the queue head may not build yet. Fills g.hold, returns nonzero if held.
static int head_hold(void) {
    g.hold[0] = 0;
    if (!g.qn) return 0;
    const SwlReq *h = &g.q[0].req;
    if (g.ln >= LINKS_MAX) {
        snprintf(g.hold, sizeof g.hold, TR(S_OPS_HOLD_RELAY_CAP_FMT), LINKS_MAX + 1);
        return 1;
    }
    if (g.stale) {
        snprintf(g.hold, sizeof g.hold, "%s", TR(S_OPS_HOLD_UNCONFIRMED));
        return 1;
    }
    for (int i = 0; i < g.ln; i++)
        if (req_clash(h, &g.links[i].intent)) {
            const char *nk = op_name_key(h);
            snprintf(g.hold, sizeof g.hold, TR(S_OPS_HOLD_NAME_INFLIGHT_FMT),
                     nk[0] && nk[0] != '*' ? nk : g.links[i].name);
            return 1;
        }
    // §3.5 anchored bitmaps (release, selective renew/transfer) cover the
    // whole owned set — they wait out every in-flight set mutation, then
    // anchor fresh
    if (h->op == SWL_RELEASE ||
        ((h->op == SWL_RENEW || h->op == SWL_TRANSFER) && h->nnames > 0)) {
        for (int i = 0; i < g.ln; i++)
            if (g.links[i].mutator) {
                snprintf(g.hold, sizeof g.hold,
                         "%s", TR(S_OPS_HOLD_ANCHORS_SET));
                return 1;
            }
    }
    return 0;
}

static void *worker(void *arg);
static void kick(void) {                // start the worker if there's runnable work
    if (g.busy) return;                 // the worker refreshes g.hold itself
    g.hold[0] = 0;                      // no head, or a fresh look at it
    if (!g.qn || !g.inited || head_hold()) return;
    g.busy = 1;
    pthread_t th;
    if (pthread_create(&th, NULL, worker, NULL) != 0) {
        g.busy = 0;
        g.st.phase = OPS_FAIL;
        snprintf(g.st.err, sizeof g.st.err, "%s", TR(S_OPS_ERR_WORKER_START));
    } else {
        pthread_detach(th);
    }
}

// ── the worker: drain the queue ──────────────────────────────────────────────
static void *worker(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&g.mu);
        if (!g.qn || head_hold()) { g.busy = 0; pthread_mutex_unlock(&g.mu); return NULL; }

        Intent it = g.q[0];                             // take the head
        g.qn--;
        memmove(g.q, g.q + 1, (size_t)g.qn * sizeof g.q[0]);

        // the coin view this build sees: every in-flight input is off the
        // table; the chain tip's change (always consumed when offered, so
        // it's the only unconsumed one) is spendable and preferred
        SwlOutpoint locked[LINKS_MAX * SWL_MAX_INS];
        int nlocked = 0;
        for (int i = 0; i < g.ln; i++)
            for (int k = 0; k < g.links[i].nin; k++) locked[nlocked++] = g.links[i].in[k];
        SwlSpendable virt[1];
        int nvirt = 0;
        if (g.ln && g.links[g.ln - 1].has_change) {
            memcpy(virt[0].txid, g.links[g.ln - 1].txid, 32);
            virt[0].vout  = g.links[g.ln - 1].change_vout;
            virt[0].value = g.links[g.ln - 1].change_value;
            nvirt = 1;
        }
        int64_t breaks_at_build = g.breaks;

        SwlReq req = it.req;
        req.dbpath = g.dbpath;
        req.ip = g.ip;
        req.locked = locked; req.nlocked = nlocked;
        req.virt = virt;     req.nvirt = nvirt;
        req.want_change = !it.req.sweep;   // a sweep leaves no change to chain off
        if (req.op == SWL_CLAIM)
            req.force_recommit = it.from_user && stale_has(req.name);

        memset(&g.st, 0, sizeof g.st);
        g.st.phase = OPS_BUSY;
        snprintf(g.st.label, sizeof g.st.label, "%s", it.label);
        g.cur = it; g.cur_on = 1;       // hold it pending across the build window
        pthread_mutex_unlock(&g.mu);

        SwlRes res;
        if (!signer_acquire(&req.key)) {
            memset(&res, 0, sizeof res);
            res.code = SWL_R_ERR;
            snprintf(res.err, sizeof res.err, "%s", TR(S_OPS_ERR_KEY_UNAVAILABLE));
        } else {
            swl_run(&req, &res);
            signer_release(&req.key);
        }

        pthread_mutex_lock(&g.mu);
        g.cur_on = 0;                   // fate decided below under the lock: the
                                        // intent is now re-queued, parked, failed,
                                        // or about to become a link — all visible
        // the chain we built on broke mid-signing (sweep rebuilt it): this tx
        // spends a phantom outpoint — the peer drops it; rebuild the intent.
        // (Front is close enough: relative order of independent ops is free,
        // same-name order is enforced by the head hold.)
        int discard = (res.code == SWL_R_OK || res.code == SWL_R_COMMITTED) &&
                      !res.dry && g.breaks != breaks_at_build;
        if (discard) {
            it.req.force_recommit = 0;
            push_front(&it);
            g.st.phase = OPS_IDLE;
            pthread_mutex_unlock(&g.mu);
            continue;                                   // loop re-locks at top
        }

        memset(&g.st, 0, sizeof g.st);
        snprintf(g.st.label, sizeof g.st.label, "%s", it.label);
        switch (res.code) {
        case SWL_R_ERR:
            if (res.net_fail && it.tries + 1 < BCAST_TRIES) {
                it.tries++;                             // retry on a later kick
                push_front(&it);
                g.st.phase = OPS_IDLE;
                snprintf(g.hold, sizeof g.hold, "%s", TR(S_OPS_HOLD_BCAST_RETRY));
                g.busy = 0;
                pthread_mutex_unlock(&g.mu);
                return NULL;
            }
            g.st.phase = OPS_FAIL;
            snprintf(g.st.err, sizeof g.st.err, "%s", res.err);
            if (req.op == SWL_CLAIM) unpark(req.name);  // don't auto-retry a refusal
            if (req.op == SWL_SETTLE) unpark_settle(req.name);
            break;
        case SWL_R_WAIT_COMMIT:                         // not indexed yet — park; poll retries
            park_claim(req.name, req.amount);
            g.st.phase = OPS_IDLE;
            break;
        case SWL_R_COMMITTED:
        case SWL_R_OK:
            g.st.phase = OPS_DONE;
            snprintf(g.st.txid, sizeof g.st.txid, "%s", res.txid);
            g.st.dry = res.dry;
            g.st.accepted = res.accepted;
            if (res.code == SWL_R_COMMITTED) {
                snprintf(g.st.label, sizeof g.st.label, TR(S_OPS_LBL_COMMIT_FMT), req.name);
                park_claim(req.name, req.amount);       // phase 2 fires per tip
                stale_del(req.name);                    // fresh salt is in the sidecar
            } else if (req.op == SWL_CLAIM) {
                unpark(req.name);                       // chain complete
                stale_del(req.name);
            } else if (req.op == SWL_RESERVE && !res.dry) {
                park_settle(req.name);                  // §3.7 phase 2: the settle
            } else if (req.op == SWL_SETTLE) {          // fires once the fold shows
                unpark_settle(req.name);                // us as the winning buyer
            }
            if (!res.dry && g.ln < LINKS_MAX) {         // watch it as a chain link
                Link *L = &g.links[g.ln++];
                memset(L, 0, sizeof *L);
                memcpy(L->txid, res.txid32, 32);
                snprintf(L->label, sizeof L->label, "%s", it.label);
                memcpy(L->in, res.ins, sizeof res.ins);
                L->nin = res.nins;
                L->has_change   = res.has_change;
                L->change_vout  = res.change_vout;
                L->change_value = res.change_value;
                L->delta = -(res.spent_inputs - res.change);
                L->mutator = (req.op == SWL_CLAIM && res.code == SWL_R_OK) ||
                             req.op == SWL_SETTLE || req.op == SWL_PAY ||
                             req.op == SWL_TRANSFER || req.op == SWL_RELEASE;
                snprintf(L->name, sizeof L->name, "%s", op_name_key(&req));
                L->intent = it.req;
                L->intent.force_recommit = 0;
                memcpy(L->raw, res.raw, res.rawlen);
                L->rawlen = res.rawlen;
            }
            break;
        }
        pthread_mutex_unlock(&g.mu);
    }
}

// ── the sweep: read the db's verdict on the chain (mutex held, new tip) ─────
// A utxo at our address, holding value, under a txid that is not one of ours.
typedef struct { int64_t value; int found; } FpCtx;
static void fp_cb(void *u, const uint8_t txid[32], uint32_t vout, int64_t value) {
    (void)vout;
    FpCtx *c = u;
    if (c->found || value != c->value) return;
    for (int i = 0; i < g.ln; i++)
        if (!memcmp(txid, g.links[i].txid, 32)) return;
    int cap = g.done_n < 64 ? g.done_n : 64;
    for (int i = 0; i < cap; i++)
        if (!memcmp(txid, g.done[i], 32)) return;
    c->found = 1;
}
static int fingerprint(int64_t value) {
    FpCtx c = { value, 0 };
    engine_utxos(g.h160, fp_cb, &c);
    return c.found;
}

// Is links[j].in[k] the change of an earlier link (not db-checkable)?
static int input_is_virtual(int j, int k) {
    for (int m = 0; m < j; m++)
        if (g.links[m].has_change &&
            g.links[j].in[k].vout == g.links[m].change_vout &&
            !memcmp(g.links[j].in[k].txid, g.links[m].txid, 32)) return 1;
    return 0;
}

// All of a link's db-checkable (non-virtual) inputs have left the utxo set —
// i.e. some variant of it confirmed. Dead links keep theirs unspent.
static int link_folded(int j) {
    for (int k = 0; k < g.links[j].nin; k++)
        if (!input_is_virtual(j, k) &&
            engine_outpoint_unspent(g.h160, g.links[j].in[k].txid, g.links[j].in[k].vout))
            return 0;
    return 1;
}

// The exact opposite: every db-checkable input is STILL unspent — the tx (and
// therefore every descendant chaining on its change) folded in NO variant.
// This is the safety proof for a replay: nothing of it ever ran.
static int link_nowhere(int j) {
    for (int k = 0; k < g.links[j].nin; k++)
        if (!input_is_virtual(j, k) &&
            !engine_outpoint_unspent(g.h160, g.links[j].in[k].txid, g.links[j].in[k].vout))
            return 0;
    return g.links[j].nin > 0;
}

// The link that confirmed NOT as built: folded, and the db holds its change
// value under a txid we never made. Youngest match — dead links can't pass
// the folded filter, so the youngest candidate is the break itself.
static int break_index(void) {
    for (int i = g.ln - 1; i >= 0; i--) {
        if (!g.links[i].has_change) continue;
        if (!link_folded(i)) continue;
        if (fingerprint(g.links[i].change_value)) return i;
    }
    return -1;
}

static void sweep(void) {
    while (g.ln) {
        // youngest link whose as-built change survives: it and every ancestor
        // confirmed exactly as built (each spends the previous real change)
        int proven = -1;
        for (int i = g.ln - 1; i >= 0; i--)
            if (g.links[i].has_change &&
                engine_outpoint_unspent(g.h160, g.links[i].txid, g.links[i].change_vout)) {
                proven = i;
                break;
            }
        if (proven >= 0) { pop_links(proven + 1); continue; }

        // no as-built change anywhere — did the head fold at all? (all its
        // inputs are confirmed outpoints: the previous link, if any, popped)
        if (!link_folded(0)) {
            // Pending… unless it is NOWHERE: stale (30 min) with every input
            // still unspent means no variant of this tx or its descendants can
            // have folded, and the per-tip re-announces haven't landed it — a
            // mempooled tx with a real fee mines in minutes here, so the tx is
            // lost, not slow. Requeue every link's intent (the break path's
            // order-preserving machinery) and rebuild on the confirmed view.
            // Deterministic largest-first funding re-picks the same inputs, so
            // a zombie copy surfacing later CONFLICTS instead of double-running;
            // txids are not marked done — a zombie confirm reads as a break and
            // the forensics converge on it.
            if (g.stale && link_nowhere(0)) {
                int n = g.ln;
                for (int i = g.ln - 1; i >= 0; i--) {
                    Intent it;
                    memset(&it, 0, sizeof it);
                    it.req = g.links[i].intent;
                    it.est = est_for(&it.req);
                    snprintf(it.label, sizeof it.label, "%s", g.links[i].label);
                    push_front(&it);
                }
                g.ln = 0;
                g.stale = 0;
                g.breaks++;                             // discard mid-build results
                g.st.phase = OPS_FAIL;
                snprintf(g.st.label, sizeof g.st.label, "%s", TR(S_OPS_LBL_TXCHAIN));
                snprintf(g.st.err, sizeof g.st.err,
                         TR(S_OPS_ERR_LOST_FMT), n, n == 1 ? "" : "s");
                continue;                               // ln == 0 → loop exits
            }
            return;
        }

        if (!g.links[0].has_change) {                   // changeless: nothing chains
            pop_links(1);                               // off it, outputs identical
            continue;                                   // in any variant — done
        }

        // head folded, has change, no as-built change left: one link was
        // malleated or conflicted away. Everything through it folded (same
        // outputs); everything after is dead — rebuild those intents.
        int broke = break_index();
        if (broke < 0) {
            // db shows a picture we can't explain (deep reorg mid-chain?).
            // Freeze rather than guess: replaying a folded op runs it twice.
            if (!g.stale) {
                g.stale = 1;
                g.st.phase = OPS_FAIL;
                snprintf(g.st.label, sizeof g.st.label, "%s", TR(S_OPS_LBL_TXCHAIN));
                snprintf(g.st.err, sizeof g.st.err,
                         "%s", TR(S_OPS_ERR_CHAIN_DIVERGED));
            }
            return;
        }
        int dead = g.ln - (broke + 1);
        for (int i = g.ln - 1; i > broke; i--) {        // queue front, order kept
            Intent it;
            memset(&it, 0, sizeof it);
            it.req = g.links[i].intent;
            it.est = est_for(&it.req);
            snprintf(it.label, sizeof it.label, "%s", g.links[i].label);
            push_front(&it);                            // headroom is reserved
        }
        for (int i = 0; i <= broke; i++) mark_done(g.links[i].txid);
        g.ln = 0;                                       // 0..broke folded; rest requeued
        g.stale = 0;
        g.breaks++;                                     // mid-build results get discarded
        if (dead > 0) {
            g.st.phase = OPS_FAIL;
            snprintf(g.st.label, sizeof g.st.label, "%s", TR(S_OPS_LBL_TXCHAIN));
            snprintf(g.st.err, sizeof g.st.err,
                     TR(S_OPS_ERR_REBUILT_FMT), dead, dead == 1 ? "" : "s");
        }
    }
}

// ── UI-thread surface ────────────────────────────────────────────────────────
const char *ops_gate(void) {
    if (!ops_available()) return TR(S_OPS_GATE_NO_KEY);
    pthread_mutex_lock(&g.mu);
    const char *r = NULL;
    if (g.qn >= Q_USER_MAX) r = TR(S_OPS_GATE_QUEUE_FULL);
    pthread_mutex_unlock(&g.mu);
    return r;
}

void ops_status(OpsStatus *out) {
    pthread_mutex_lock(&g.mu);
    *out = g.st;
    out->pending = g.ln > 0;
    out->inflight = g.ln;
    out->queued = g.qn;
    out->claim_wait = 0;
    for (int i = 0; i < CLAIMS_MAX; i++)
        if (g.claims[i].active) out->claim_wait = 1;
    out->settle_wait = 0;
    for (int i = 0; i < CLAIMS_MAX; i++)
        if (g.settles[i].active) out->settle_wait = 1;
    snprintf(out->hold, sizeof out->hold, "%s", g.hold);
    pthread_mutex_unlock(&g.mu);
}

void ops_ack(void) {
    pthread_mutex_lock(&g.mu);
    if (g.st.phase == OPS_DONE || g.st.phase == OPS_FAIL) g.st.phase = OPS_IDLE;
    pthread_mutex_unlock(&g.mu);
}

int64_t ops_balance_delta(void) {
    pthread_mutex_lock(&g.mu);
    int64_t d = 0;
    for (int i = 0; i < g.ln; i++) d += g.links[i].delta;
    for (int i = 0; i < g.qn; i++) d -= g.q[i].est;
    for (int i = 0; i < CLAIMS_MAX; i++)
        if (g.claims[i].active) d -= g.claims[i].rent;
    pthread_mutex_unlock(&g.mu);
    return d;
}

static int name_in(char (*out)[24], int n, const char *s) {
    for (int i = 0; i < n; i++)
        if (!strcmp(out[i], s)) return 1;
    return 0;
}

int ops_claiming(char (*out)[24], int max) {
    pthread_mutex_lock(&g.mu);
    int n = 0;
    for (int i = 0; i < CLAIMS_MAX && n < max; i++)         // parked for the claim
        if (g.claims[i].active && !name_in(out, n, g.claims[i].name))
            snprintf(out[n++], 24, "%s", g.claims[i].name);
    for (int i = 0; i < g.qn && n < max; i++)               // waiting to build
        if (g.q[i].req.op == SWL_CLAIM && !name_in(out, n, g.q[i].req.name))
            snprintf(out[n++], 24, "%s", g.q[i].req.name);
    for (int i = 0; i < g.ln && n < max; i++)               // commit/claim in flight
        if (g.links[i].intent.op == SWL_CLAIM && !name_in(out, n, g.links[i].name))
            snprintf(out[n++], 24, "%s", g.links[i].name);
    if (g.cur_on && n < max && g.cur.req.op == SWL_CLAIM    // building right now
        && !name_in(out, n, g.cur.req.name))
        snprintf(out[n++], 24, "%s", g.cur.req.name);
    pthread_mutex_unlock(&g.mu);
    return n;
}

static OpsPend pend_kind(SwlOp op) {
    switch (op) {
    case SWL_RENEW:    return OPS_PEND_RENEW;
    case SWL_SELL:     return OPS_PEND_SELL;
    case SWL_OFFER:    return OPS_PEND_OFFER;
    case SWL_TRANSFER: return OPS_PEND_TRANSFER;
    case SWL_RELEASE:  return OPS_PEND_RELEASE;
    case SWL_CLAIM:    return OPS_PEND_CLAIM;
    default:           return OPS_PEND_OTHER;
    }
}

OpsPend ops_name_pending(const char *name) {
    pthread_mutex_lock(&g.mu);
    OpsPend p = OPS_PEND_NONE;
    if (g.cur_on && req_touches(&g.cur.req, name))          // building right now
        p = pend_kind(g.cur.req.op);
    for (int i = 0; i < g.ln && !p; i++)                    // in flight
        if (req_touches(&g.links[i].intent, name)) p = pend_kind(g.links[i].intent.op);
    for (int i = 0; i < g.qn && !p; i++)
        if (req_touches(&g.q[i].req, name)) p = pend_kind(g.q[i].req.op);
    if (!p && park_find(name) >= 0) p = OPS_PEND_CLAIM;
    if (!p && spark_find(name) >= 0) p = OPS_PEND_OTHER;   // settle parked
    pthread_mutex_unlock(&g.mu);
    return p;
}

// debug: which internal bucket(s) currently hold `name` pending (bitfield)
// bit0 cur (building) · bit1 links (broadcast) · bit2 queue · bit3 park (claim)
// bit4 spark (settle). 0 = nothing here says pending.
int ops_pending_buckets(const char *name) {
    pthread_mutex_lock(&g.mu);
    int b = 0;
    if (g.cur_on && req_touches(&g.cur.req, name)) b |= 1;
    for (int i = 0; i < g.ln; i++)
        if (req_touches(&g.links[i].intent, name)) { b |= 2; break; }
    for (int i = 0; i < g.qn; i++)
        if (req_touches(&g.q[i].req, name)) { b |= 4; break; }
    if (park_find(name) >= 0)  b |= 8;
    if (spark_find(name) >= 0) b |= 16;
    pthread_mutex_unlock(&g.mu);
    return b;
}

// ── submitters ───────────────────────────────────────────────────────────────
static int push_user(SwlOp op, const SwlReq *args, const char *label) {
    if (!ops_available()) return 0;
    pthread_mutex_lock(&g.mu);
    if (g.qn >= Q_USER_MAX) { pthread_mutex_unlock(&g.mu); return 0; }
    Intent *it = &g.q[g.qn++];
    memset(it, 0, sizeof *it);
    it->req = *args;
    it->req.op = op;
    it->req.fee = model_fee_k();        // the number the dialog just showed
    it->req.dry_run = getenv("PEPENET_DRYRUN") != NULL;
    it->from_user = 1;
    it->est = est_for(&it->req);
    snprintf(it->label, sizeof it->label, "%s", label);
    kick();
    pthread_mutex_unlock(&g.mu);
    return 1;
}

int ops_send(const uint8_t to160[20], int64_t amount, int sweep) {
    SwlReq r;
    memset(&r, 0, sizeof r);
    memcpy(r.to160, to160, 20);
    r.amount = amount;
    r.sweep = sweep;                    // spend everything: no change, recipient gets amount
    return push_user(SWL_SEND, &r, TR(S_OPS_LBL_SEND));
}


int ops_claim(const char *name, int64_t rent) {
    // §activation hard guard (the claim dialog gates this too): a commit mined
    // below the activation height never folds, so its claim can never fire —
    // refuse before any tx exists. Fail-closed while the height is unknown.
    if (!M.demo && M.height < M.activation) return 0;
    pthread_mutex_lock(&g.mu);
    int parked = park_find(name);
    if (parked >= 0) {                  // already waiting on its commit — keep
        g.claims[parked].rent = rent;   // waiting (poll fires the claim), with
        g.claims[parked].started = 0;   // the 30-min patience wound fresh
        pthread_mutex_unlock(&g.mu);
        return 1;
    }
    for (int i = 0; i < g.qn; i++)      // a claim for this name is queued
        if (g.q[i].req.op == SWL_CLAIM && !strcmp(g.q[i].req.name, name)) {
            pthread_mutex_unlock(&g.mu);
            return 1;
        }
    pthread_mutex_unlock(&g.mu);
    char label[48];
    snprintf(label, sizeof label, TR(S_OPS_LBL_CLAIM_FMT), name);
    SwlReq r;
    memset(&r, 0, sizeof r);
    snprintf(r.name, sizeof r.name, "%s", name);
    r.amount = rent;
    return push_user(SWL_CLAIM, &r, label);
}

int ops_renew(int64_t rent) {
    SwlReq r;
    memset(&r, 0, sizeof r);
    r.amount = rent;
    return push_user(SWL_RENEW, &r, TR(S_OPS_LBL_RENEW));
}

int ops_renew_sel(const char (*names)[24], int n, int64_t rent) {
    if (n < 1 || n > 16) return 0;
    char label[48];
    if (n == 1) snprintf(label, sizeof label, TR(S_OPS_LBL_RENEW_ONE_FMT), names[0]);
    else        snprintf(label, sizeof label, TR(S_OPS_LBL_RENEW_N_FMT), n);
    SwlReq r;
    memset(&r, 0, sizeof r);
    for (int i = 0; i < n; i++)
        snprintf(r.names[i], sizeof r.names[i], "%s", names[i]);
    r.nnames = n;
    r.amount = rent;
    return push_user(SWL_RENEW, &r, label);
}

int ops_transfer(const uint8_t to160[20]) {
    SwlReq r;
    memset(&r, 0, sizeof r);
    memcpy(r.to160, to160, 20);
    return push_user(SWL_TRANSFER, &r, TR(S_OPS_LBL_TRANSFER_ALL));
}

int ops_transfer_sel(const char (*names)[24], int n, const uint8_t to160[20]) {
    if (n < 1 || n > 16) return 0;
    char label[48];
    if (n == 1) snprintf(label, sizeof label, TR(S_OPS_LBL_TRANSFER_ONE_FMT), names[0]);
    else        snprintf(label, sizeof label, TR(S_OPS_LBL_TRANSFER_N_FMT), n);
    SwlReq r;
    memset(&r, 0, sizeof r);
    for (int i = 0; i < n; i++)
        snprintf(r.names[i], sizeof r.names[i], "%s", names[i]);
    r.nnames = n;
    memcpy(r.to160, to160, 20);
    return push_user(SWL_TRANSFER, &r, label);
}

int ops_sell(const char *name, uint64_t price, uint32_t window_s) {
    char label[48];
    snprintf(label, sizeof label, TR(S_OPS_LBL_LIST_FMT), name);
    SwlReq r;
    memset(&r, 0, sizeof r);
    snprintf(r.name, sizeof r.name, "%s", name);
    r.price = price;
    r.window_s = window_s;
    return push_user(SWL_SELL, &r, label);
}

int ops_release_multi(const char (*names)[24], int n) {
    if (n < 1 || n > 16) return 0;
    char label[48];
    if (n == 1) snprintf(label, sizeof label, TR(S_OPS_LBL_RELEASE_ONE_FMT), names[0]);
    else        snprintf(label, sizeof label, TR(S_OPS_LBL_RELEASE_N_FMT), n);
    SwlReq r;
    memset(&r, 0, sizeof r);
    for (int i = 0; i < n; i++)
        snprintf(r.names[i], sizeof r.names[i], "%s", names[i]);
    r.nnames = n;
    return push_user(SWL_RELEASE, &r, label);
}

int ops_release(const char *name) {
    char one[1][24];
    snprintf(one[0], sizeof one[0], "%s", name);
    return ops_release_multi(one, 1);
}

int ops_offer(const char *name, const uint8_t to160[20], uint64_t price) {
    char label[48];
    snprintf(label, sizeof label, TR(S_OPS_LBL_OFFER_FMT), name);
    SwlReq r;
    memset(&r, 0, sizeof r);
    snprintf(r.name, sizeof r.name, "%s", name);
    memcpy(r.to160, to160, 20);
    r.price = price;
    return push_user(SWL_OFFER, &r, label);
}

int ops_reserve(const char *name) {
    char label[48];
    snprintf(label, sizeof label, TR(S_OPS_LBL_RESERVE_FMT), name);
    SwlReq r;
    memset(&r, 0, sizeof r);
    snprintf(r.name, sizeof r.name, "%s", name);
    return push_user(SWL_RESERVE, &r, label);
}

int ops_settle(const char *name) {
    char label[48];
    snprintf(label, sizeof label, TR(S_OPS_LBL_SETTLE_FMT), name);
    SwlReq r;
    memset(&r, 0, sizeof r);
    snprintf(r.name, sizeof r.name, "%s", name);
    return push_user(SWL_SETTLE, &r, label);
}

int ops_payoffer(const char *name) {
    char label[48];
    snprintf(label, sizeof label, TR(S_OPS_LBL_BUY_FMT), name);
    SwlReq r;
    memset(&r, 0, sizeof r);
    snprintf(r.name, sizeof r.name, "%s", name);
    return push_user(SWL_PAY, &r, label);
}

// ── re-announce: push a pending link's signed bytes at the ladder again ──────
// Fire-and-forget on its own detached thread: broadcast blocks up to 20 s and
// ops_poll is the model tick. Single-flight (g.rebc_on); no key material —
// raw bytes in, frames out. This is what turns "sent but never echoed" from a
// permanent ghost into a late confirm.
typedef struct {
    char coin[16], ip[64], dbpath[512];
    uint8_t raw[SWL_RAW_MAX]; uint32_t rawlen;
    uint8_t txid[32];
} RebcJob;
static void *rebc_main(void *arg) {
    RebcJob *j = arg;
    int r = swl_rebroadcast(j->coin, j->ip, j->dbpath, j->raw, j->rawlen, j->txid);
    fprintf(stderr, "ops: re-announced pending tx (%s)\n",
            r == 1 ? "echoed" : r == -1 ? "sent, no echo" : "no peer took it");
    free(j);
    pthread_mutex_lock(&g.mu);
    g.rebc_on = 0;
    pthread_mutex_unlock(&g.mu);
    return NULL;
}

// ── the ~1 Hz pump ───────────────────────────────────────────────────────────
void ops_poll(int64_t height, int64_t now) {
    if (!g.inited) return;
    pthread_mutex_lock(&g.mu);
    int new_tip = height > 0 && height != g.checked_h;
    if (new_tip) g.checked_h = height;

    // once, when the projection is readable: re-park any reserve→settle the chain
    // still shows us winning but no journal captured (a reserve made on another
    // device / the CLI, or a crash between broadcast and the park write). The
    // claim leg is covered by the journal alone — its rent isn't on the chain.
    if (!g.reconciled && height > 0) {
        g.reconciled = 1;
        EngineName rows[16];
        int n = engine_market_mine(g.h160, rows, 16);
        for (int i = 0; i < n; i++)
            if (rows[i].st == SM_RESERVED && spark_find(rows[i].name) < 0)
                park_settle(rows[i].name);
    }

    if (g.ln) {                         // stale clock runs on the head link
        Link *L = &g.links[0];
        if (!L->since) L->since = now;
        if (!g.stale && now - L->since > PENDING_STALE_S) {
            g.stale = 1;                // stop growing; the sweep keeps watching
            if (g.st.phase == OPS_IDLE) {
                g.st.phase = OPS_FAIL;
                snprintf(g.st.label, sizeof g.st.label, "%s", TR(S_OPS_LBL_CONFIRMATION));
                snprintf(g.st.err, sizeof g.st.err,
                         "%s", TR(S_OPS_ERR_STALE_30MIN));
            }
        }
    }

    if (new_tip && g.ln) sweep();

    // a head link that survived the sweep is unfolded — re-announce its signed
    // bytes each new tip (~1/min) once it has had 90 s to confirm on its own
    if (new_tip && g.ln && !g.rebc_on && g.links[0].rawlen &&
        g.links[0].since && now - g.links[0].since > 90) {
        RebcJob *j = malloc(sizeof *j);
        if (j) {
            snprintf(j->coin, sizeof j->coin, "%s", g.coin);
            snprintf(j->ip, sizeof j->ip, "%s", g.ip);
            snprintf(j->dbpath, sizeof j->dbpath, "%s", g.dbpath);
            memcpy(j->raw, g.links[0].raw, g.links[0].rawlen);
            j->rawlen = g.links[0].rawlen;
            memcpy(j->txid, g.links[0].txid, 32);
            pthread_t th;
            if (pthread_create(&th, NULL, rebc_main, j) == 0) {
                pthread_detach(th);
                g.rebc_on = 1;
            } else free(j);
        }
    }

    for (int i = 0; i < CLAIMS_MAX; i++) {              // parked commit→claim
        if (!g.claims[i].active) continue;
        // already ours? the claim landed on-chain but we never saw the worker's
        // success (crash/quit between broadcast and unpark; the journal re-parks
        // on boot by design). The fold is the truth — dissolve the park instead
        // of re-trying into WAIT_COMMIT forever against a spent commit.
        { uint8_t own[20]; int nst = 0;
          if (engine_name_lookup(g.claims[i].name, own, &nst) == 1 &&
              !memcmp(own, g.h160, 20)) {
              g.st.phase = OPS_DONE;
              g.st.txid[0] = 0;
              snprintf(g.st.label, sizeof g.st.label,
                       TR(S_OPS_LBL_CLAIM_FMT), g.claims[i].name);
              stale_del(g.claims[i].name);
              unpark(g.claims[i].name);
              continue;
          } }
        // the clock and the give-up run UNCONDITIONALLY — behind a busy gate,
        // a commit that never mines would park the name forever
        if (!g.claims[i].started) g.claims[i].started = now;
        if (now - g.claims[i].started > CLAIM_WAIT_MAX_S) {
            g.claims[i].active = 0;     // give up; a manual retry re-commits
            persist_parks();
            stale_add(g.claims[i].name);
            g.st.phase = OPS_FAIL;
            snprintf(g.st.label, sizeof g.st.label, TR(S_OPS_LBL_CLAIM_FMT), g.claims[i].name);
            snprintf(g.st.err, sizeof g.st.err,
                     "%s", TR(S_OPS_ERR_COMMIT_TIMEOUT));
            continue;
        }
        if (!new_tip || g.claims[i].last_try_h == height) continue;
        int busy_name = 0;              // commit still in flight, or already queued
        for (int j = 0; j < g.ln && !busy_name; j++)
            if (req_touches(&g.links[j].intent, g.claims[i].name)) busy_name = 1;
        for (int j = 0; j < g.qn && !busy_name; j++)
            if (g.q[j].req.op == SWL_CLAIM &&
                !strcmp(g.q[j].req.name, g.claims[i].name)) busy_name = 1;
        if (busy_name) continue;
        g.claims[i].last_try_h = height;                // one try per new tip
        Intent it;
        memset(&it, 0, sizeof it);
        it.req.op = SWL_CLAIM;
        snprintf(it.req.name, sizeof it.req.name, "%s", g.claims[i].name);
        it.req.amount = g.claims[i].rent;
        it.req.fee = model_fee_k();
        it.req.dry_run = getenv("PEPENET_DRYRUN") != NULL;
        snprintf(it.label, sizeof it.label, TR(S_OPS_LBL_CLAIM_FMT), g.claims[i].name);
        push_front(&it);                // est 0 — the park already counts the rent
    }

    for (int i = 0; i < CLAIMS_MAX; i++) {              // parked reserve→settle
        if (!g.settles[i].active) continue;
        if (!g.settles[i].started) g.settles[i].started = now;
        if (now - g.settles[i].started > CLAIM_WAIT_MAX_S) {
            g.settles[i].active = 0;    // give up parking; the row's Settle
            persist_parks();
            g.st.phase = OPS_FAIL;      // button stays as the manual fallback
            snprintf(g.st.label, sizeof g.st.label, TR(S_OPS_LBL_SETTLE_FMT), g.settles[i].name);
            snprintf(g.st.err, sizeof g.st.err,
                     "%s", TR(S_OPS_ERR_RESERVE_TIMEOUT));
            continue;
        }
        if (!new_tip || g.settles[i].last_try_h == height) continue;
        int busy_name = 0;              // reserve in flight, or settle queued
        for (int j = 0; j < g.ln && !busy_name; j++)
            if (req_touches(&g.links[j].intent, g.settles[i].name)) busy_name = 1;
        for (int j = 0; j < g.qn && !busy_name; j++)
            if (req_touches(&g.q[j].req, g.settles[i].name)) busy_name = 1;
        if (busy_name) continue;
        g.settles[i].last_try_h = height;               // one look per new tip
        EngineName rows[16];                            // the fold's verdict
        int n = engine_market_mine(g.h160, rows, 16), won = 0;
        for (int j = 0; j < n && !won; j++)
            won = rows[j].st == SM_RESERVED && !strcmp(rows[j].name, g.settles[i].name);
        if (won) {                                      // our reserve folded —
            Intent it;                                  // fire the settle (the
            memset(&it, 0, sizeof it);                  // park clears when the
            it.req.op = SWL_SETTLE;                     // worker resolves it)
            snprintf(it.req.name, sizeof it.req.name, "%s", g.settles[i].name);
            it.req.fee = model_fee_k();
            it.req.dry_run = getenv("PEPENET_DRYRUN") != NULL;
            it.est = est_for(&it.req);
            snprintf(it.label, sizeof it.label, TR(S_OPS_LBL_SETTLE_FMT), g.settles[i].name);
            push_front(&it);
            continue;
        }
        int nst = 0; uint8_t own[20] = { 0 };
        int found = engine_name_lookup(g.settles[i].name, own, &nst);
        if (found && !memcmp(own, g.h160, 20)) {        // we own it — the settle
            g.settles[i].active = 0;                    // landed (crash-replay);
            persist_parks();                            // don't call it a loss
            g.st.phase = OPS_DONE;
            g.st.txid[0] = 0;
            snprintf(g.st.label, sizeof g.st.label,
                     TR(S_OPS_LBL_SETTLE_FMT), g.settles[i].name);
            continue;
        }
        if (found && nst == SM_LISTED) continue;        // not folded yet — wait
        g.settles[i].active = 0;                        // the market moved on
        persist_parks();
        g.st.phase = OPS_FAIL;
        snprintf(g.st.label, sizeof g.st.label, TR(S_OPS_LBL_SETTLE_FMT), g.settles[i].name);
        if (found && nst == SM_RESERVED)                // first-in-chain-order won
            snprintf(g.st.err, sizeof g.st.err,
                     TR(S_OPS_ERR_OUTBID_FMT),
                     g.settles[i].name);
        else
            snprintf(g.st.err, sizeof g.st.err,
                     TR(S_OPS_ERR_NOT_RESERVABLE_FMT), g.settles[i].name);
    }

    kick();
    pthread_mutex_unlock(&g.mu);
}
