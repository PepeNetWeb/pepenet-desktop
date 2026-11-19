// The seed-driven generator (SPEC-conformance.md §Generation).
//
// From `seed` it regenerates a deterministic, state-aware stream of abstract
// transactions, folds them, and reports two digests: input_digest (a rolling
// hash of every tx fed to the fold) and state_digest (the fold result). Because
// every reference implementation runs the IDENTICAL PRNG + generation algorithm
// + fold + digest, all of them print the same two digests for the same
// (seed, count) — that agreement IS the cross-language conformance proof.
//
// Determinism rule: the generator NEVER iterates the fold's internal arrays
// (their order is not canonical). It selects names/ids from its own fixed pools
// via the PRNG, then looks names up BY NAME (sm_find_name is canonical) to derive
// valid actors/prices — so every decision is a pure function of (PRNG, fold
// state), both identical across languages.
#include "sm.h"
#include "prng.h"
#include "sha256.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ── pinned generation constants ──────────────────────────────────────────────
#define N_IDS        16        // identity pool
#define NAME_POOL    400       // candidate-name vocabulary
#define BASE_TS      1700000000LL
#define CLOG_CAP     4096      // commit ring (for CLAIM)
#define NMLOG_CAP    1024      // recently-active name ring (connects the market chains)

typedef struct { uint8_t salt[32]; char name[SM_NAME_MAX + 1]; uint8_t nlen; int author; int64_t height; } Commit;

typedef struct {
    SmRng    rng;
    SmState *st;
    Commit  *clog; int clog_n, clog_head;
    char   (*nmlog)[SM_NAME_MAX + 1]; int nmlog_n, nmlog_head;
    int64_t  ts_ring[16]; int64_t last_ts;
    int64_t  height; uint64_t rate;
    SHA256_CTX ih;
} Gen;

static void push_name(Gen *g, const char *nm, uint8_t nl) {
    memcpy(g->nmlog[g->nmlog_head], nm, (size_t)nl + 1);
    g->nmlog_head = (g->nmlog_head + 1) % NMLOG_CAP;
    if (g->nmlog_n < NMLOG_CAP) g->nmlog_n++;
}

static uint64_t gnext(Gen *g)             { return sm_rng_next(&g->rng); }
static uint64_t gbnd (Gen *g, uint64_t n) { return sm_rng_bounded(&g->rng, n); }

// ── identities (h160 = {idx, 0…, idx}; ~1/4 are P2SH) + name pool ────────────
static void gen_id(int idx, SmId *out) {
    memset(out, 0, sizeof *out);
    out->h160[0] = (uint8_t)idx; out->h160[19] = (uint8_t)idx;
    out->type = (idx % 4 == 3) ? SM_P2SH : SM_P2PKH;
}
static int owner_idx(const uint8_t h160[20]) {     // canonical inverse of gen_id, or −1
    int idx = h160[0];
    if (idx >= N_IDS || h160[19] != idx) return -1;
    for (int i = 1; i < 19; i++) if (h160[i]) return -1;
    return idx;
}
static void name_of(int i, char *out, uint8_t *len) {   // 'n' + base36(i) — all in [a-z0-9] ⊂ [a-z0-9-]
    static const char *D = "0123456789abcdefghijklmnopqrstuvwxyz";
    char buf[8]; int n = 0, v = i;
    if (v == 0) buf[n++] = '0'; else while (v > 0) { buf[n++] = D[v % 36]; v /= 36; }
    out[0] = 'n'; for (int k = 0; k < n; k++) out[1 + k] = buf[n - 1 - k];
    out[1 + n] = '\0'; *len = (uint8_t)(1 + n);
}
static void gen_salt(Gen *g, uint8_t salt[32]) {
    for (int w = 0; w < 4; w++) { uint64_t v = gnext(g); for (int b = 0; b < 8; b++) salt[w*8+b] = (uint8_t)(v >> (8*b)); }
}
// Pick a name: ~3/4 from the recently-active ring (so market chains connect),
// else uniformly from the pool. Both branches consume two draws (determinism).
static void pick_name(Gen *g, char *nm, uint8_t *nl) {
    if (g->nmlog_n && gbnd(g, 4) != 0) {
        int recent = g->nmlog_n < 128 ? g->nmlog_n : 128;
        int idx = (g->nmlog_head - 1 - (int)gbnd(g, (uint64_t)recent) + NMLOG_CAP) % NMLOG_CAP;
        size_t L = strlen(g->nmlog[idx]); memcpy(nm, g->nmlog[idx], L + 1); *nl = (uint8_t)L;
    } else { name_of((int)gbnd(g, NAME_POOL), nm, nl); }
}

// ── tx assembly helpers ──────────────────────────────────────────────────────
static void tx_in(SmTx *t, int idx)  { SmId *d = sm_tx_input(t); gen_id(idx, d); t->in_sighash_all[t->n_inputs - 1] = 1; }
static SmCarrier *tx_act(SmTx *t, SmAction a, uint64_t value) {
    SmCarrier *c = sm_tx_carrier(t);
    c->kind = SM_CAR_ACTION; c->act = a; c->value = value; c->vout = (uint32_t)(t->n_carriers - 1);
    return c;
}
static void tx_out(SmTx *t, const uint8_t dest[20], uint8_t type, uint64_t value) {
    SmOut *o = sm_tx_out(t);
    memcpy(o->h160, dest, 20); o->type = type; o->value = value; o->vout = (uint32_t)(SM_SYNTH_VOUT_BASE + t->n_outs - 1);
}
// Lease/rent burn that buys ~`days` (rate is a multiple of 28 in the generator).
static uint64_t lease_burn(Gen *g, int days) { return (g->rate / 28) * (uint64_t)days; }

// Flags-length draw: mostly the tiny historical 1..3 (dense owned sets are
// rare), ~1/8 mid-range (past the old 80-byte carrier boundary), ~1/32 from
// the full consensus range up to `cap` (wide-carrier coverage, §6).
static uint16_t gen_flags_len(Gen *g, int cap) {
    uint64_t m = gbnd(g, 32);
    if (m == 0) return (uint16_t)(1 + gbnd(g, (uint64_t)cap));
    if (m < 4)  return (uint16_t)(1 + gbnd(g, 200));
    return (uint16_t)(1 + gbnd(g, 3));
}

// ── input digest: stream a FIXED-WIDTH serialization of the tx (pinned) ──────
static void put32(SHA256_CTX *h, uint32_t v) { uint8_t t[4]; for (int i=0;i<4;i++) t[i]=(uint8_t)(v>>(8*i)); sha256_update(h,t,4); }
static void put64(SHA256_CTX *h, uint64_t v) { uint8_t t[8]; for (int i=0;i<8;i++) t[i]=(uint8_t)(v>>(8*i)); sha256_update(h,t,8); }
static void put8 (SHA256_CTX *h, uint8_t v)  { sha256_update(h, &v, 1); }
static void hash_action(SHA256_CTX *h, const SmAction *a) {
    put8(h, a->op);
    sha256_update(h, (const uint8_t*)a->name, SM_NAME_MAX + 1);   put8(h, a->name_len);
    sha256_update(h, (const uint8_t*)a->name_b, SM_NAME_MAX + 1); put8(h, a->name_b_len);
    sha256_update(h, a->commitment, 32); sha256_update(h, a->salt, 32);
    sha256_update(h, a->addr, 20); put64(h, a->price); put32(h, a->window);
    put8(h, a->has_anchor); put64(h, a->anchor);
    // flags hash length-scoped (hashing the full SM_FLAGS_MAX array would burn
    // ~40 SHA blocks of zero padding per action at the §6 ceiling size)
    sha256_update(h, a->flags, a->flags_len); put32(h, a->flags_len);
    put8(h, a->as_index); put8(h, a->idx_a); put8(h, a->idx_b);
}
static void hash_tx(Gen *g, const SmTx *t) {
    SHA256_CTX *h = &g->ih;
    put32(h, t->txindex); put8(h, (uint8_t)t->n_inputs);
    for (int i = 0; i < t->n_inputs; i++) { sha256_update(h, t->inputs[i].h160, 20); put8(h, t->inputs[i].type); put8(h, t->in_sighash_all[i]); }
    put8(h, (uint8_t)t->n_carriers);
    for (int c = 0; c < t->n_carriers; c++) {
        const SmCarrier *cr = &t->carriers[c];
        put8(h, (uint8_t)cr->kind); put64(h, cr->value); put32(h, cr->vout);
        if (cr->kind == SM_CAR_ACTION) hash_action(h, &cr->act);
    }
    put8(h, (uint8_t)t->n_outs);
    for (int o = 0; o < t->n_outs; o++) { sha256_update(h, t->outs[o].h160, 20); put8(h, t->outs[o].type); put64(h, t->outs[o].value); put32(h, t->outs[o].vout); }
}

// ── op weights (pinned) — names/market only ──────────────────────────────────
enum { OP_COMMIT, OP_CLAIM, OP_RENEW, OP_TRANSFER, OP_SELL,
       OP_RESERVE, OP_SETTLE, OP_RELEASE, OP_SELLTO, OP_PAY, OP_TRADE,
       OP_RENEW1, OP_TRANSFER1, OP_RELEASE1, OP_KINDS };
static const int WEIGHT[OP_KINDS] = { 14, 13, 5, 5, 8, 7, 7, 3, 6, 5, 4, 4, 3, 2 };
static int pick_op(Gen *g) {
    int total = 0; for (int i = 0; i < OP_KINDS; i++) total += WEIGHT[i];
    int r = (int)gbnd(g, (uint64_t)total), acc = 0;
    for (int i = 0; i < OP_KINDS; i++) { acc += WEIGHT[i]; if (r < acc) return i; }
    return OP_COMMIT;
}

// price for a SELL/SELL_TO: mostly modest, occasionally near 2^64 (overflow edge).
static uint64_t gen_price(Gen *g) {
    if (gbnd(g, 20) == 0) return UINT64_MAX - gbnd(g, 1000);          // near-2^64 deposit-overflow edge
    return (uint64_t)SM_SELL_PRICE_FLOOR + gbnd(g, 1000000);
}

// ── build one transaction for op `k` ─────────────────────────────────────────
static void build_tx(Gen *g, int k, uint32_t txindex, SmTx *t) {
    memset(t, 0, sizeof *t); t->txindex = txindex;
    SmState *s = g->st;
    char nm[SM_NAME_MAX + 1]; uint8_t nl;

    switch (k) {
    case OP_COMMIT: {
        int signer = (int)gbnd(g, N_IDS);
        name_of((int)gbnd(g, NAME_POOL), nm, &nl);
        SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_COMMIT;
        Commit cm; gen_salt(g, cm.salt); memcpy(cm.name, nm, nl + 1); cm.nlen = nl; cm.author = signer; cm.height = g->height;
        SHA256_CTX h; sha256_init(&h);
        sha256_update(&h, cm.salt, 32); sha256_update(&h, (const uint8_t*)nm, nl);
        SmId sid; gen_id(signer, &sid); sha256_update(&h, sid.h160, 20);
        sha256_final(&h, a.commitment);
        g->clog[g->clog_head] = cm; g->clog_head = (g->clog_head + 1) % CLOG_CAP;
        if (g->clog_n < CLOG_CAP) g->clog_n++;
        tx_in(t, signer); tx_act(t, a, 0);
        break;
    }
    case OP_CLAIM: {
        if (g->clog_n && gbnd(g, 6) != 0) {                          // mostly claim a RECENT commit
            int recent = g->clog_n < 32 ? g->clog_n : 32;           // older ones have expired (COMMIT_EXPIRY)
            int back = (int)gbnd(g, (uint64_t)recent);
            Commit *cm = &g->clog[(g->clog_head - 1 - back + CLOG_CAP) % CLOG_CAP];
            SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_CLAIM;
            memcpy(a.salt, cm->salt, 32);
            memcpy(a.name, cm->name, cm->nlen + 1); a.name_len = cm->nlen;
            tx_in(t, cm->author); tx_act(t, a, lease_burn(g, 1 + (int)gbnd(g, 15)));  // short → churn/lapse
            push_name(g, cm->name, cm->nlen);
        } else {                                                     // naked claim (no commit) → drops
            int signer = (int)gbnd(g, N_IDS);
            name_of((int)gbnd(g, NAME_POOL), nm, &nl);
            SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_CLAIM;
            gen_salt(g, a.salt); memcpy(a.name, nm, nl + 1); a.name_len = nl;
            tx_in(t, signer); tx_act(t, a, lease_burn(g, 1 + (int)gbnd(g, 50)));
        }
        break;
    }
    case OP_RENEW: {
        int signer = (int)gbnd(g, N_IDS);
        SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_RENEW;
        if (gbnd(g, 3) == 0) {                                       // selective (anchor + flags)
            SmId sid; gen_id(signer, &sid);
            int64_t low = sm_last_mutation(s, sid.h160);
            int64_t span = g->height - low; if (span < 0) span = 0;
            a.has_anchor = 1; a.anchor = (uint64_t)(low + (int64_t)gbnd(g, (uint64_t)span + 1));
            a.flags_len = gen_flags_len(g, SM_FLAGS_MAX);
            for (int i = 0; i < a.flags_len; i++) a.flags[i] = (uint8_t)gbnd(g, 256);
        }
        uint64_t burn = lease_burn(g, 1 + (int)gbnd(g, 200));
        if (gbnd(g, 8) == 0) {                                       // ~1/8 AS-attributed (exercise AS)
            int other = (int)gbnd(g, N_IDS);
            uint8_t idx = (gbnd(g, 4) == 0) ? (uint8_t)(2 + gbnd(g, 8)) : 1;  // sometimes OOB → segment drops
            SmAction asx; memset(&asx, 0, sizeof asx); asx.op = SM_OP_AS; asx.as_index = idx;
            tx_in(t, other); tx_in(t, signer); tx_act(t, asx, 0); tx_act(t, a, burn);
        } else {
            tx_in(t, signer); tx_act(t, a, burn);
        }
        break;
    }
    case OP_TRANSFER: {
        int signer = (int)gbnd(g, N_IDS), target = (int)gbnd(g, N_IDS);
        SmId tid; gen_id(target, &tid);
        SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_TRANSFER; memcpy(a.addr, tid.h160, 20);
        tx_in(t, signer); tx_act(t, a, 0);
        break;
    }
    case OP_SELL: case OP_SELLTO: {
        pick_name(g, nm, &nl);
        const SmNameRow *r = sm_find_name(s, nm);
        int oi = (r && r->st == SM_OWNED) ? owner_idx(r->owner) : -1;
        if (oi < 0) { build_tx(g, OP_COMMIT, txindex, t); return; }   // can't sell → fall back
        SmAction a; memset(&a, 0, sizeof a);
        if (k == OP_SELL) {
            a.op = SM_OP_SELL; a.price = gen_price(g);
            a.window = (gbnd(g, 2) == 0) ? 0 : (uint32_t)(SM_RESERVE_WINDOW + gbnd(g, 100000));
        } else {
            a.op = SM_OP_SELL_TO; a.price = gen_price(g);
            SmId b; gen_id((int)gbnd(g, N_IDS), &b); memcpy(a.addr, b.h160, 20);
        }
        memcpy(a.name, nm, nl + 1); a.name_len = nl;
        tx_in(t, oi); tx_act(t, a, 0);
        push_name(g, nm, nl);                                        // keep the chain hot
        break;
    }
    case OP_RESERVE: {
        pick_name(g, nm, &nl);
        const SmNameRow *r = sm_find_name(s, nm);
        if (!r || r->st != SM_LISTED) { build_tx(g, OP_COMMIT, txindex, t); return; }
        int buyer = (int)gbnd(g, N_IDS);
        uint64_t burn_leg = (uint64_t)((unsigned __int128)r->price * SM_RESERVE_BURN_BPS / 10000u);
        if (burn_leg < (uint64_t)SM_DUST_FLOOR) burn_leg = SM_DUST_FLOOR;
        uint64_t pay_leg  = (uint64_t)((unsigned __int128)r->price * SM_RESERVE_PAY_BPS / 10000u);
        if (pay_leg < (uint64_t)SM_DUST_FLOOR) pay_leg = SM_DUST_FLOOR;
        SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_RESERVE; memcpy(a.name, nm, nl + 1); a.name_len = nl;
        tx_in(t, buyer); tx_act(t, a, burn_leg);
        tx_out(t, r->seller, r->seller_type, pay_leg);
        push_name(g, nm, nl);
        break;
    }
    case OP_SETTLE: {
        pick_name(g, nm, &nl);
        const SmNameRow *r = sm_find_name(s, nm);
        int bi = (r && r->st == SM_RESERVED) ? owner_idx(r->buyer) : -1;
        if (bi < 0) { build_tx(g, OP_COMMIT, txindex, t); return; }
        uint64_t remainder = r->price - r->burn_leg - r->pay_leg;
        SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_SETTLE; memcpy(a.name, nm, nl + 1); a.name_len = nl;
        tx_in(t, bi); tx_act(t, a, 0);
        tx_out(t, r->seller, r->seller_type, remainder);
        break;
    }
    case OP_PAY: {
        pick_name(g, nm, &nl);
        const SmNameRow *r = sm_find_name(s, nm);
        int bi = (r && r->st == SM_OFFERED) ? owner_idx(r->buyer) : -1;
        if (bi < 0) { build_tx(g, OP_COMMIT, txindex, t); return; }
        SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_PAY; memcpy(a.name, nm, nl + 1); a.name_len = nl;
        tx_in(t, bi); tx_act(t, a, 0);
        tx_out(t, r->seller, r->seller_type, r->price);
        break;
    }
    case OP_RELEASE: {
        int signer = (int)gbnd(g, N_IDS);
        SmId sid; gen_id(signer, &sid);
        int64_t low = sm_last_mutation(s, sid.h160);
        int64_t span = g->height - low; if (span < 0) span = 0;
        SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_RELEASE;
        a.has_anchor = 1; a.anchor = (uint64_t)(low + (int64_t)gbnd(g, (uint64_t)span + 1));
        a.flags_len = gen_flags_len(g, SM_FLAGS_MAX);
        for (int i = 0; i < a.flags_len; i++) a.flags[i] = (uint8_t)gbnd(g, 256);
        tx_in(t, signer); tx_act(t, a, 0);
        break;
    }
    case OP_TRADE: {
        char na[SM_NAME_MAX+1], nb[SM_NAME_MAX+1]; uint8_t la, lb;
        pick_name(g, na, &la);
        pick_name(g, nb, &lb);
        const SmNameRow *ra = sm_find_name(s, na), *rb = sm_find_name(s, nb);
        int ai = (ra && ra->st == SM_OWNED) ? owner_idx(ra->owner) : -1;
        int bi = (rb && rb->st == SM_OWNED) ? owner_idx(rb->owner) : -1;
        if (ai < 0 || bi < 0 || ai == bi || strcmp(na, nb) == 0) { build_tx(g, OP_COMMIT, txindex, t); return; }
        SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_TRADE; a.idx_a = 0; a.idx_b = 1;
        memcpy(a.name, na, la + 1); a.name_len = la; memcpy(a.name_b, nb, lb + 1); a.name_b_len = lb;
        tx_in(t, ai); tx_in(t, bi); tx_act(t, a, 0);
        break;
    }
    case OP_RENEW1: {                                                // by-name renew (§3.5): owner OR seller (listed names renewable)
        pick_name(g, nm, &nl);
        const SmNameRow *r = sm_find_name(s, nm);
        int oi = r ? owner_idx(r->st == SM_OWNED ? r->owner : r->seller) : -1;
        if (oi < 0) { build_tx(g, OP_COMMIT, txindex, t); return; }
        SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_RENEW_NAME;
        memcpy(a.name, nm, nl + 1); a.name_len = nl;
        tx_in(t, oi); tx_act(t, a, lease_burn(g, 1 + (int)gbnd(g, 200)));
        push_name(g, nm, nl);                                        // keep the chain hot
        break;
    }
    case OP_TRANSFER1: {                                             // by-name gift (§3.5): sometimes to self (still a move)
        pick_name(g, nm, &nl);
        const SmNameRow *r = sm_find_name(s, nm);
        int oi = (r && r->st == SM_OWNED) ? owner_idx(r->owner) : -1;
        if (oi < 0) { build_tx(g, OP_COMMIT, txindex, t); return; }
        int target = (gbnd(g, 8) == 0) ? oi : (int)gbnd(g, N_IDS);   // ~1/8 self-target
        SmId tid; gen_id(target, &tid);
        SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_TRANSFER_NAME; memcpy(a.addr, tid.h160, 20);
        memcpy(a.name, nm, nl + 1); a.name_len = nl;
        tx_in(t, oi); tx_act(t, a, 0);
        push_name(g, nm, nl);
        break;
    }
    case OP_RELEASE1: {                                              // by-name relinquish (§3.5): locked target → no-op path
        pick_name(g, nm, &nl);
        const SmNameRow *r = sm_find_name(s, nm);
        int oi = r ? owner_idx(r->st == SM_OWNED ? r->owner : r->seller) : -1;
        if (oi < 0) { build_tx(g, OP_COMMIT, txindex, t); return; }
        SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_RELEASE_NAME;
        memcpy(a.name, nm, nl + 1); a.name_len = nl;
        tx_in(t, oi); tx_act(t, a, 0);
        break;
    }
    default: build_tx(g, OP_COMMIT, txindex, t); return;
    }
}

// ── adversarial twist (drop-closed coverage): mutate the built tx to force a drop ─
static void maybe_corrupt(Gen *g, SmTx *t) {
    if (gbnd(g, 100) >= 18 || t->n_carriers == 0) return;            // ~18% of txs
    switch (gbnd(g, 4)) {
    case 0: if (t->n_inputs) t->in_sighash_all[0] = 0; break;        // vin[0] not SIGHASH_ALL
    case 1: t->carriers[0].value = 0; break;                         // zero the carrier value
    case 2: t->n_outs = 0; break;                                    // strip payment outputs
    case 3: if (t->carriers[0].kind == SM_CAR_ACTION) {              // OOB AS / scramble indices
                t->carriers[0].act.as_index = 200; t->carriers[0].act.idx_a = 200;
            } break;
    }
}

// ── structural invariant battery (correctness net beyond the digest) ─────────
static int cmp_namep(const void *a, const void *b) {
    return strcmp((*(SmNameRow *const *)a)->name, (*(SmNameRow *const *)b)->name);
}
int sm_check_invariants(SmState *s, int64_t mtp) {
    int viol = 0;
    #define VIOL(msg) do { if (viol < 5) printf("INVARIANT VIOLATION @mtp %lld: %s\n", (long long)mtp, msg); viol++; } while (0)

    // ownership partition: no duplicate names.
    if (s->n_names > 1) {
        SmNameRow **idx = malloc((size_t)s->n_names * sizeof(*idx));
        for (int i = 0; i < s->n_names; i++) idx[i] = &s->names[i];
        qsort(idx, (size_t)s->n_names, sizeof(*idx), cmp_namep);
        for (int i = 1; i < s->n_names; i++)
            if (strcmp(idx[i-1]->name, idx[i]->name) == 0) { VIOL("duplicate name in owned set"); break; }
        free(idx);
    }

    for (int i = 0; i < s->n_names; i++) {
        SmNameRow *r = &s->names[i];
        // lease bound: a live row satisfies mtp < lease_expiry ≤ mtp + MAX_LEASE.
        if (!(mtp < r->lease_expiry)) VIOL("row with lapsed lease survived preblock");
        if (r->lease_expiry > mtp + SM_MAX_LEASE) VIOL("lease_expiry exceeds mtp + MAX_LEASE");
        // state-specific market nesting + sanity.
        if (r->st == SM_LISTED || r->st == SM_OFFERED || r->st == SM_RESERVED) {
            if (r->offer_expiry + SM_REORG_BUFFER > r->lease_expiry) VIOL("offer_expiry + REORG_BUFFER > lease_expiry");
            if (r->st == SM_LISTED && r->price < (uint64_t)SM_SELL_PRICE_FLOOR) VIOL("listed below price floor");
            if (r->st == SM_RESERVED) {
                if (r->reserve_expiry > r->offer_expiry) VIOL("reserve_expiry > offer_expiry (nesting)");
                if (r->price < r->burn_leg + r->pay_leg) VIOL("price < deposit legs (settle would underflow)");
            }
        } else if (r->st != SM_OWNED) {
            VIOL("row in an unknown state");
        }
    }
    #undef VIOL
    return viol;
}

// ── driver ────────────────────────────────────────────────────────────────────
uint64_t sm_generate(uint64_t seed, uint64_t count, int trace_blocks,
                     uint8_t input_digest[32], uint8_t state_digest[32], int64_t *cov,
                     int64_t *inv_fail, uint8_t *prop_digest) {
    Gen g; memset(&g, 0, sizeof g);
    sm_rng_seed(&g.rng, seed);
    g.st = sm_new(0);                                  // activation 0: all ops live in the soak
    g.clog  = malloc(sizeof(Commit) * CLOG_CAP);
    g.nmlog = malloc(sizeof(*g.nmlog) * NMLOG_CAP);
    for (int i = 0; i < 16; i++) g.ts_ring[i] = BASE_TS;
    g.last_ts = BASE_TS; g.height = 0;
    sha256_init(&g.ih);
    SHA256_CTX ph; if (prop_digest) sha256_init(&ph);   // property-mode rolling fingerprint

    uint64_t emitted = 0; int blocks = 0;
    while (emitted < count) {
        g.height += 1;                                 // ── new block ──
        int64_t mtp = sm_mtp(g.ts_ring, 11);
        g.last_ts += 300 + (int64_t)gbnd(&g, 600);
        for (int i = 0; i < 10; i++) g.ts_ring[i] = g.ts_ring[i + 1];
        g.ts_ring[10] = g.last_ts;                     // ring now holds the 11 most-recent timestamps
        g.rate = 28u * (1u + gbnd(&g, 4));
        sm_begin_block(g.st, g.height, mtp, g.rate);

        int ntx = 1 + (int)gbnd(&g, 8);
        for (int j = 0; j < ntx && emitted < count; j++) {
            int k = pick_op(&g);
            SmTx t = {0}; build_tx(&g, k, (uint32_t)j, &t);
            maybe_corrupt(&g, &t);
            hash_tx(&g, &t);
            sm_apply_tx(g.st, &t);
            sm_tx_free(&t);                 // release any heap spill (no-op while inline)
            emitted++;
        }
        blocks++;
        // property mode (prop_digest) supersedes the structural-only battery: it folds
        // the per-block aggregate fingerprint AND counts the richer property violations.
        if (prop_digest)   *inv_fail += sm_block_fingerprint(g.st, mtp, &ph);
        else if (inv_fail) *inv_fail += sm_check_invariants(g.st, mtp);
        if (trace_blocks > 0 && blocks % trace_blocks == 0) {
            uint8_t d[32]; sm_state_digest(g.st, d);
            printf("TRACE %lld ", (long long)g.height);
            for (int i = 0; i < 32; i++) printf("%02x", d[i]);
            printf("\n");
        }
    }

    sha256_final(&g.ih, input_digest);
    sm_state_digest(g.st, state_digest);
    if (prop_digest) sha256_final(&ph, prop_digest);
    if (cov) for (int i = 0; i < SM_EV_COUNT; i++) cov[i] = g.st->ev[i];
    free(g.clog); free(g.nmlog); sm_free(g.st);
    return emitted;
}

// ── recording variant for the reorg harness (same chain as `random`) ─────────
uint64_t sm_record_chain(uint64_t seed, uint64_t count,
                         SmRecBlk *blocks, int *n_blocks, int max_blocks,
                         SmTx *txs, int max_txs) {
    Gen g; memset(&g, 0, sizeof g);
    sm_rng_seed(&g.rng, seed);
    g.st = sm_new(0);
    g.clog  = malloc(sizeof(Commit) * CLOG_CAP);
    g.nmlog = malloc(sizeof(*g.nmlog) * NMLOG_CAP);
    for (int i = 0; i < 16; i++) g.ts_ring[i] = BASE_TS;
    g.last_ts = BASE_TS; g.height = 0;

    uint64_t emitted = 0; int nb = 0, nt = 0;
    while (emitted < count && nb < max_blocks && nt < max_txs) {
        g.height += 1;
        int64_t mtp = sm_mtp(g.ts_ring, 11);
        g.last_ts += 300 + (int64_t)gbnd(&g, 600);
        for (int i = 0; i < 10; i++) g.ts_ring[i] = g.ts_ring[i + 1];
        g.ts_ring[10] = g.last_ts;
        g.rate = 28u * (1u + gbnd(&g, 4));
        sm_begin_block(g.st, g.height, mtp, g.rate);

        SmRecBlk *B = &blocks[nb];
        B->height = g.height; B->mtp = mtp; B->rate = g.rate; B->tx_lo = nt;
        int ntx = 1 + (int)gbnd(&g, 8);
        for (int j = 0; j < ntx && emitted < count && nt < max_txs; j++) {
            int k = pick_op(&g);
            build_tx(&g, k, (uint32_t)j, &txs[nt]);
            maybe_corrupt(&g, &txs[nt]);
            sm_apply_tx(g.st, &txs[nt]);               // fold (build_tx is state-aware) — realizes the chain
            nt++; emitted++;
        }
        B->tx_hi = nt; nb++;
    }
    *n_blocks = nb;
    free(g.clog); free(g.nmlog); sm_free(g.st);
    return (uint64_t)nt;
}
