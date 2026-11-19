/* p2p_test.c — the local-only P2P spam fixes L1..L10 (src/dns_net.c,
 * src/dns_state.c, pepenet-mesh state.c) on a fake clock and a fake chain.
 * Nothing here changes a byte on the wire: every frame the node emits is an
 * ordinary dnzinv / dnzget / dnzdat (the fake peers parse them with the same
 * grammar old nodes use).
 *
 * PROVES:
 *   L1  full tables queue in bounded FIFOs and never fail open: announce
 *       overflow, pull overflow (no zget bypasses P3), bounded drops.
 *   L2  per-name relay credit counted in BLOCKS (1 per 10, burst 4), refills
 *       STAGGERED by a keyed per-name phase: stalled chain, repeated same tip,
 *       reorg down / up, flapping, multi-block and large height jumps,
 *       restart; phases evenly spread and re-keyed per process; per-block
 *       refill load ~1/10; eviction thrash; configurable blocks-per-credit.
 *   L3  pull dispatch by (lane, live-before-AE, age): a quiet name is pulled
 *       before an older busy backlog; a live relay before a bulk AE catch-up; a quiet name's zget that hits PepeNet's GET_COOL_S is
 *       remembered and answered when the cooldown ends (high lane).
 *   L4  dnzinv bytes <= 25% of each link's P6; dumps keep flowing meanwhile.
 *   L5  an op we already hold is skipped before admission (no ECDSA); the
 *       mesh store dedups op_id before verifying the signature.
 *   L6  inbound byte budget per peer; unsolicited useless dumps deprioritise
 *       then disconnect a peer, once; loopback exempt; solicited never count.
 *   L7  peer cap (uplink / 0.52 Mbit/s); P6 refill waits for socket drain.
 *   L8  each link's AE cursor starts at its own random point.
 *   L9  one DB transaction per dump (one WAL commit frame per dump).
 *   L10 cached per-name digests: hits, exact invalidation (admit, foreign
 *       writer, sweep), byte-identical to recomputation.
 */
#include "dns_state.h"
#include "dns_net.h"
#include "zone.h"
#include "pepenet/crypto.h"
#include "pepenet/state.h"
#include "pepenet/wire.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#define _GNU_SOURCE_MEMMEM 1

static int g_fail;
#define CK(c, m) do { if (c) printf("  ok   %s\n", m); \
                      else { printf("  FAIL %s\n", m); g_fail++; } } while (0)
static char M[256];
#define CKF(c, ...) do { snprintf(M, sizeof M, __VA_ARGS__); CK(c, M); } while (0)

static int64_t g_ms = 5000000000LL;
time_t  ft_time(time_t *t) { time_t v = (time_t)(g_ms / 1000); if (t) *t = v; return v; }
int64_t ft_ms(void) { return g_ms; }
static void adv_ms(int64_t d) { g_ms += d; }

static uint32_t g_tip = 1000;
static uint8_t  OWN_A[20], APRIV[32], APUB[33];
static int      g_lapse;            /* 1: every name lapsed (sweep test) */
static int fk_owner(void *u, const char *name, uint8_t owner[20]) {
    (void)u; (void)name; if (g_lapse) return 0; memcpy(owner, OWN_A, 20); return 1;
}
static int fk_header(void *u, uint32_t height, uint8_t out[32]) {
    (void)u;
    uint8_t seed[8] = { 'h','d','r',1, (uint8_t)height, (uint8_t)(height >> 8),
                        (uint8_t)(height >> 16), (uint8_t)(height >> 24) };
    sp_sha256(seed, sizeof seed, out);
    return 1;
}
static uint32_t fk_tip(void *u) { (void)u; return g_tip; }
static SpChainOracle ORC = { NULL, fk_owner, fk_header, fk_tip };

/* ── fake peers ─────────────────────────────────────────────────────────────── */
#define NP 8
typedef struct {
    int  id;
    long n_inv, n_get, n_dat, bytes, inv_bytes, dat_bytes, inv_entries;
    int  ne; char ent[4096][SP_NAME_MAX + 1];
    int  ng; char gets[4096][SP_NAME_MAX + 1];
    int  nd; char dats[4096][SP_NAME_MAX + 1];
    size_t pending; int local, drops;
} FP;
static FP *fp[NP];
static void *h[NP];
static void fp_send(void *peer, const char *cmd, const uint8_t *pay, size_t n) {
    FP *f = peer;
    f->bytes += (long)n + 24;
    if (!strcmp(cmd, "dnzinv")) {
        f->n_inv++; f->inv_bytes += (long)n + 24;
        int off = 0; uint64_t c;
        if (!sp_rvar(pay, (int)n, &off, &c)) return;
        for (uint64_t i = 0; i < c; i++) {
            int nl = pay[off++];
            if (f->ne < 4096) { memcpy(f->ent[f->ne], pay + off, (size_t)nl); f->ent[f->ne][nl] = 0; f->ne++; }
            off += nl + 32; f->inv_entries++;
        }
    } else if (!strcmp(cmd, "dnzget")) {
        f->n_get++;
        if (f->ng < 4096) { memcpy(f->gets[f->ng], pay + 1, pay[0]); f->gets[f->ng][pay[0]] = 0; f->ng++; }
    } else if (!strcmp(cmd, "dnzdat")) {
        f->n_dat++; f->dat_bytes += (long)n + 24;
        if (f->nd < 4096) { memcpy(f->dats[f->nd], pay + 1, pay[0]); f->dats[f->nd][pay[0]] = 0; f->nd++; }
    }
}
static void fp_reset(FP *f) { int id = f->id, l = f->local; memset(f, 0, sizeof *f); f->id = id; f->local = l; }
static size_t tr_pending(void *peer) { return ((FP *)peer)->pending; }
static void   tr_drop(void *peer, const char *why) { (void)why; ((FP *)peer)->drops++; }
static int    tr_local(void *peer) { return ((FP *)peer)->local; }

static void node(SpState *st, int npeers) {
    dnsnet_init(st, ORC, 0);
    dnsnet_set_transport(tr_pending, tr_drop, tr_local);
    for (int i = 0; i < NP; i++) { fp[i]->local = 0; fp_reset(fp[i]); h[i] = NULL; }
    for (int i = 0; i < npeers; i++) h[i] = dnsnet_up(fp[i], fp_send);
    for (int i = 0; i < npeers; i++) fp_reset(fp[i]);
}
static void tick_for(int64_t ms, int64_t step) {
    for (int64_t t = 0; t < ms; t += step) { adv_ms(step); dnsnet_tick(); }
}
static unsigned long C(const char *n) { return dnsnet_counter(n); }

static int put_a(SpState *st, const char *name, const char *label, uint8_t v) {
    zone_rec r; memset(&r, 0, sizeof r);
    snprintf(r.label, sizeof r.label, "%s", label);
    r.type = 1; r.ttl = 300; r.rdlen = 4;
    r.rdata[0] = 192; r.rdata[1] = 0; r.rdata[2] = 2; r.rdata[3] = v;
    char err[128];
    return dns_state_put(st, &ORC, name, &r, APRIV, APUB, SP_CERT_NONE, NULL, 0, err, sizeof err);
}
typedef struct { uint8_t buf[2 * DNS_BUDGET]; int off, count; } DA;
static int da_cb(void *u, const uint8_t *k, int kl, int op, uint32_t a, const uint8_t *b, int bl) {
    (void)k; (void)kl; (void)op; (void)a;
    DA *d = u; d->off += sp_wvar(d->buf + d->off, (uint64_t)bl);
    memcpy(d->buf + d->off, b, (size_t)bl); d->off += bl; d->count++; return 1;
}
static int mk_zdat(SpState *src, const char *name, uint8_t *out) {
    static DA d; d.off = 0; d.count = 0;
    uint8_t *cb; int cl;
    if (sp_state_clear_get(src, name, &cb, &cl)) { da_cb(&d, NULL, 0, 0, 0, cb, cl); free(cb); }
    sp_state_iter(src, name, da_cb, &d);
    int o = 0, nl = (int)strlen(name);
    out[o++] = (uint8_t)nl; memcpy(out + o, name, (size_t)nl); o += nl;
    o += sp_wvar(out + o, (uint64_t)d.count);
    memcpy(out + o, d.buf, (size_t)d.off); o += d.off;
    return o;
}
/* one dnzinv entry (name, digest) from peer i */
static void inv1(int i, const char *name, const uint8_t dg[32]) {
    uint8_t b[1 + 1 + SP_NAME_MAX + 32]; int o = 0, nl = (int)strlen(name);
    b[o++] = 1; b[o++] = (uint8_t)nl; memcpy(b + o, name, (size_t)nl); o += nl; memcpy(b + o, dg, 32); o += 32;
    dnsnet_msg(h[i], "zinv", b, o);
}
static void rnd_dg(uint8_t dg[32], uint32_t k) { uint8_t s[4] = { (uint8_t)k, (uint8_t)(k >> 8), (uint8_t)(k >> 16), 0x5a }; sp_sha256(s, 4, dg); }
static void zget1(int i, const char *name) {
    uint8_t q[1 + SP_NAME_MAX]; int nl = (int)strlen(name);
    q[0] = (uint8_t)nl; memcpy(q + 1, name, (size_t)nl);
    dnsnet_msg(h[i], "zget", q, 1 + nl);
}


/* first held op of a name (optionally the one at label `want`) / all ops */
static struct { uint8_t b[SP_STATE_OP_MAX]; int l; const char *want; } g_row;
static int row_cb(void *u, const uint8_t *k, int kl, int op, uint32_t a, const uint8_t *b, int bl) {
    (void)u; (void)op; (void)a;
    if (g_row.l) return 1;
    if (g_row.want) { int wl = (int)strlen(g_row.want); if (kl < wl || !memmem(k, (size_t)kl, g_row.want, (size_t)wl)) return 1; }
    memcpy(g_row.b, b, (size_t)bl); g_row.l = bl; return 1;
}
static struct { uint8_t b[64][SP_STATE_OP_MAX]; int l[64]; int n; } g_all;
static int all_cb(void *u, const uint8_t *k, int kl, int op, uint32_t a, const uint8_t *b, int bl) {
    (void)u; (void)k; (void)kl; (void)op; (void)a;
    if (g_all.n < 64) { memcpy(g_all.b[g_all.n], b, (size_t)bl); g_all.l[g_all.n++] = bl; }
    return 1;
}

/* ── L2 ─────────────────────────────────────────────────────────────────────── */
static long burst_relays(const char *name, int n) {
    unsigned long r0 = C("relay");
    for (int i = 0; i < n; i++) dnsnet_announce(name);
    return (long)(C("relay") - r0);
}
static long relays_during(int64_t ms) { unsigned long r0 = C("relay"); tick_for(ms, 1000); return (long)(C("relay") - r0); }
/* the first height > after on which `name` gains a credit (staggered refill) */
static uint32_t next_hit(const char *name, uint32_t after, uint32_t cb) {
    uint32_t ph = (uint32_t)dnsnet_credit_phase(name), hh = after + 1;
    while (hh % cb != ph) hh++;
    return hh;
}
static long hits_in(const char *name, uint32_t lo, uint32_t hi, uint32_t cb) {   /* phase heights in (lo, hi] */
    long n = 0; uint32_t ph = (uint32_t)dnsnet_credit_phase(name);
    for (uint32_t hh = lo + 1; hh <= hi; hh++) if (hh % cb == ph) n++;
    return n;
}
static void sec_l2(void) {
    printf("-- L2: per-name relay credit in blocks (1 per 10, staggered, burst 4) --\n");
    SpState *st = sp_state_open(":memory:");
    g_tip = 1000; node(st, 1);
    CKF(C("blk") == 1000, "max-seen height starts at the tip (%lu)", C("blk"));
    CKF(burst_relays("x", 8) == 4, "8 edits at one tip: exactly the burst (4) relayed, the rest owed");
    CKF(relays_during(2 * 3600 * 1000) == 0, "stalled chain: 2 h with no new block mints no credit (0 relays)");
    uint32_t h1 = next_hit("x", 1000, 10);              /* x's first refill height (1001..1010) */
    long flap = 0;
    g_tip = 995; flap += relays_during(5000);
    CKF(flap == 0 && C("blk") == 1000, "reorg DOWN to 995: no credit, max-seen stays 1000 (%lu)", C("blk"));
    for (int k = 0; k < 50; k++) { g_tip = (k & 1) ? h1 - 1 : 990; flap += relays_during(2000); }
    CKF(flap == 0, "reorg up to %u (just below x's phase height %u) and 50 flaps 990<->%u: 0 relays (no farmed credit)", h1 - 1, h1, h1 - 1);
    g_tip = h1; long one = relays_during(2000);
    CKF(one == 1, "x's phase height %u reached: exactly one coalesced relay (%ld)", h1, one);
    CKF(burst_relays("x", 3) == 0, "... which spent it: repeated edits at the same tip relay nothing");
    for (int k = 0; k < 30; k++) { adv_ms(1000); dnsnet_tick(); }   /* same tip seen 30 more times */
    CKF(relays_during(5000) == 0, "repeated same tip: no credit");
    for (int k = 0; k < 20; k++) { g_tip = (k & 1) ? h1 : h1 - 7; flap += relays_during(1000); }
    CKF(relays_during(1000) == 0 && C("blk") == h1, "flapping back across the phase height %u (20x) mints nothing", h1);
    g_tip = h1 + 9; long nine = burst_relays("x", 3) + relays_during(3000);
    CKF(nine == 0, "9 more blocks (no phase height crossed): 0 relays");
    g_tip = h1 + 10; long ten = relays_during(3000) + burst_relays("x", 3);
    CKF(ten == 1, "the 10th block (next phase height): exactly 1 relay (%ld)", ten);
    /* multi-block jumps credit every phase height crossed, capped at the burst */
    for (uint32_t jump = 15; jump <= 45; jump += 10) {
        uint32_t from = (uint32_t)C("blk");
        burst_relays("x", 6); relays_during(1000);      /* spend whatever is left */
        long want = hits_in("x", from, from + jump, 10); if (want > 4) want = 4;
        g_tip = from + jump;
        long got = relays_during(2000) + burst_relays("x", 6);
        CKF(got == want, "jump +%u blocks: credits = phase heights crossed (%ld relays, expected %ld)", jump, got, want);
    }
    g_tip = (uint32_t)C("blk") + 100000;
    long big = burst_relays("x", 20) + relays_during(3000);
    CKF(big == 4, "large jump (+100000 blocks): credit capped at the burst (%ld relays, not 10000)", big);
    uint32_t top = (uint32_t)C("blk");
    g_tip = 7;                                         /* a huge reorg / bad tip */
    long under = burst_relays("x", 5) + relays_during(5000);
    CKF(under == 0 && C("blk") == top, "tip falls to 7: no underflow, no credit (max-seen %lu)", C("blk"));
    /* restart: a fresh process with a LOWER tip than the old max */
    g_tip = 900; node(st, 1);
    CKF(C("blk") == 900, "restart: max-seen = the tip at start (%lu)", C("blk"));
    long rs = burst_relays("x", 6);
    CKF(rs == 4, "restart: a name starts at the burst (%ld), never more", rs);
    uint32_t hr = next_hit("x", 900, 10);
    g_tip = hr - 1; long rb = relays_during(3000);
    g_tip = hr;     long ra = relays_during(3000);
    CKF(rb == 0 && ra == 1, "restart: credit counts from the start height (%u: %ld, phase height %u: %ld)", hr - 1, rb, hr, ra);
    /* stagger: phases evenly spread, and keyed per process */
    {
        enum { NN = 20000 };
        static int ph0[NN]; int bin[10] = {0}, lo = NN, hi = 0;
        char pn[16];
        for (int i = 0; i < NN; i++) { snprintf(pn, sizeof pn, "s%05d", i); ph0[i] = dnsnet_credit_phase(pn); if (ph0[i] >= 0 && ph0[i] < 10) bin[ph0[i]]++; }
        for (int b = 0; b < 10; b++) { if (bin[b] < lo) lo = bin[b]; if (bin[b] > hi) hi = bin[b]; }
        CKF(lo >= NN / 10 * 9 / 10 && hi <= NN / 10 * 11 / 10,
            "%d names over 10 phases: every phase holds %d..%d (expected %d +-10%%) -> ~1/10 of names refill per block", NN, lo, hi, NN / 10);
        /* sequential / grindable-looking names are spread too (no phase follows the name) */
        int run = 0, maxrun = 0, prev = -1;
        for (int i = 0; i < NN; i++) { if (ph0[i] == prev) run++; else run = 1; if (run > maxrun) maxrun = run; prev = ph0[i]; }
        CKF(maxrun <= 8, "consecutive names never share a phase for long (longest run %d)", maxrun);
        g_tip = 950; node(st, 1);                        /* restart = a new random key */
        int same = 0;
        for (int i = 0; i < NN; i++) { snprintf(pn, sizeof pn, "s%05d", i); if (dnsnet_credit_phase(pn) == ph0[i]) same++; }
        CKF(same < NN / 10 * 13 / 10, "a new process draws a new key: %d of %d names keep their phase (chance ~%d)", same, NN, NN / 10);
        /* per-block refill load: 2000 names that all spent their burst at one tip,
         * then one block at a time -> each block refills ~1/10 of them, never all */
        g_tip = 5000; node(st, 1);
        for (int i = 0; i < 2000; i++) { snprintf(pn, sizeof pn, "w%04d", i); burst_relays(pn, 5); }
        tick_for(60000, 1000);
        long worst = 0, total = 0;
        for (int b = 1; b <= 10; b++) {
            g_tip++;
            unsigned long r0 = C("relay"); tick_for(2000, 1000);
            long r = (long)(C("relay") - r0); total += r; if (r > worst) worst = r;
        }
        CKF(total == 2000 && worst <= 2000 / 10 * 13 / 10,
            "2000 owed names, 10 blocks: %ld relays in all, at most %ld on one block (synchronized would be 2000 on one)", total, worst);
    }
    /* configurable */
    dnsnet_set_credit_blocks(1);
    g_tip = 2000; node(st, 1);
    burst_relays("y", 4);
    long per = 0;
    for (int b = 0; b < 10; b++) { g_tip++; per += burst_relays("y", 1); tick_for(1000, 1000); }
    CKF(per == 10, "--relay-credit-blocks 1: one relay per block (%ld in 10 blocks)", per);
    dnsnet_set_credit_blocks(10);
    g_tip = 3000; node(st, 1);
    burst_relays("z", 4);
    per = 0;
    for (int b = 0; b < 100; b++) { g_tip++; per += burst_relays("z", 1); tick_for(1000, 1000); }
    CKF(per == 10, "default: one edit per block for 100 blocks -> 10 relays after the burst (%ld)", per);
    /* eviction thrash: more names than the credit table holds (2^16 sets x 4
     * ways) cycled at one tip; an evicted young record's credit is inherited,
     * so eviction can never mint credit (old: a fresh burst per eviction) */
    g_tip = 4000; node(st, 1);
    {
        const int TN = 300000; unsigned long r0 = C("relay"), e0 = C("nr_evict_young");
        char tn[16];
        for (int r = 0; r < 5; r++) for (int i = 0; i < TN; i++) { snprintf(tn, sizeof tn, "t%06d", i); dnsnet_announce(tn); }
        unsigned long tr = C("relay") - r0, ev = C("nr_evict_young") - e0;
        CKF(tr <= 4UL * TN && ev > 0, "eviction thrash: %d names (> 262144 slots) x 5 edits at one tip: %lu relays <= 4 per name (%lu young evictions)", TN, tr, ev);
    }
    sp_state_close(st);
}

/* ── L1 ─────────────────────────────────────────────────────────────────────── */
static void sec_l1(void) {
    printf("-- L1: bounded queues when the tables are full --\n");
    SpState *st = sp_state_open(":memory:");
    g_tip = 5000; node(st, 1);
    const int N = 8192 + 3000;
    unsigned long r0 = C("relay");
    char nm[16];
    for (int r = 0; r < 5; r++) for (int i = 0; i < N; i++) { snprintf(nm, sizeof nm, "o%05d", i); dnsnet_announce(nm); }
    unsigned long relays = C("relay") - r0;
    CKF(relays <= 4UL * N && relays + 64 >= 4UL * N, "%d names x 5 edits at one tip: <= 4 relays each (%lu of %lu), none unthrottled", N, relays, 4UL * N);
    CKF(C("ann_open") > 0 && C("ann_ovf") > 0, "announce table full -> overflow FIFO (open=%lu ovf=%lu)", C("ann_open"), C("ann_ovf"));
    CKF(C("ann_ovf") <= 2 * 2048, "... bounded (%lu <= 4096); beyond it AE re-offers (dropped %lu)", C("ann_ovf"), C("ann_ovf_drop"));
    g_tip += 10; r0 = C("relay");
    tick_for(5000, 1000);
    unsigned long owed = C("relay") - r0;
    CKF(owed > 0 && owed <= (unsigned long)N, "next credit: owed names relayed once each at most (%lu <= %d)", owed, N);
    /* pull overflow: an advertiser floods > PULL_SLOTS differing names */
    fp_reset(fp[0]);
    uint8_t dg[32];
    for (int i = 0; i < 8192 + 2000; i++) { snprintf(nm, sizeof nm, "p%05d", i); rnd_dg(dg, (uint32_t)i); inv1(0, nm, dg); }
    CKF(fp[0]->n_get <= 32, "10192 differing names from one peer: %ld zgets on the wire (<= 32 in flight; no P3 bypass)", fp[0]->n_get);
    CKF(C("pull_ovf") + C("pull_full") > 0 || C("pull_ovf_drop") > 0, "pull table full -> bounded overflow FIFO (ovf=%lu drop=%lu)", C("pull_ovf"), C("pull_ovf_drop"));
    CKF(C("pull_ovf") <= 2 * 2048, "... bounded (%lu <= 4096)", C("pull_ovf"));
    tick_for(60000, 1000);
    CKF(fp[0]->n_get <= 32 * 7, "60 s later: still <= 32 in flight per 10 s timeout (%ld zgets)", fp[0]->n_get);
    sp_state_close(st);
}

/* ── L3 ─────────────────────────────────────────────────────────────────────── */
static void sec_l3(void) {
    printf("-- L3: priority dispatch + a high lane in the responder --\n");
    SpState *st = sp_state_open(":memory:");
    g_tip = 6000; node(st, 1);
    char nm[16]; uint8_t dg[32];
    for (int i = 0; i < 40; i++) { snprintf(nm, sizeof nm, "b%03d", i); dnsnet_announce(nm); }   /* busy: relayed just now */
    tick_for(2000, 1000); fp_reset(fp[0]);
    for (int i = 0; i < 40; i++) { snprintf(nm, sizeof nm, "b%03d", i); rnd_dg(dg, (uint32_t)i + 100); inv1(0, nm, dg); }
    rnd_dg(dg, 7); inv1(0, "quiet", dg);
    int early = 0; for (int k = 0; k < fp[0]->ng; k++) if (!strcmp(fp[0]->gets[k], "quiet")) early = 1;
    /* PepeNet: DNSNET_PULL_PER_PEER = 2 in flight, paced 1 per GET_COOL_S (its peers drop the rest) */
    CKF(fp[0]->ng >= 1 && fp[0]->ng <= 2 && !early, "40 busy names fill the peer's 2 paced pull slots (%d zgets); the quiet name waits", fp[0]->ng);
    int ng0 = fp[0]->ng;
    tick_for(11000, 1000);                             /* timeouts free the slots */
    CKF(fp[0]->ng > ng0 && !strcmp(fp[0]->gets[ng0], "quiet"),
        "slots free: the quiet (stale-first) name is pulled FIRST, ahead of 38 older busy pulls (%s)", fp[0]->ng > ng0 ? fp[0]->gets[ng0] : "-");
    /* responder: PepeNet answers one dump per peer per GET_COOL_S (2 s) and
     * drops the rest (unchanged); L3 remembers a quiet name's zget that hit the
     * cooldown and answers it as soon as the cooldown ends */
    for (int i = 0; i < 2000; i++) { snprintf(nm, sizeof nm, "c%04d", i); dnsnet_announce(nm); }
    tick_for(30000, 1000); fp_reset(fp[0]);
    for (int i = 0; i < 2000; i++) { snprintf(nm, sizeof nm, "c%04d", i); zget1(0, nm); }
    zget1(0, "stale");
    int nd0 = fp[0]->nd;
    tick_for(2000, 1000);
    CKF(nd0 == 1 && fp[0]->nd > nd0 && !strcmp(fp[0]->dats[nd0], "stale"),
        "2000 busy zgets inside the 2 s cooldown (1 answered, rest dropped as before); the quiet name's zget is answered when it ends (%s)", fp[0]->nd > nd0 ? fp[0]->dats[nd0] : "-");
    CKF(C("get_hi") >= 1 && C("get_hi_sent") >= 1, "... via the high lane (get_hi=%lu sent=%lu)", C("get_hi"), C("get_hi_sent"));
    /* a live relay (small dnzinv frame) is pulled ahead of a bulk anti-entropy
     * catch-up in the same lane, even when the pull table has overflowed */
    node(st, 1); fp_reset(fp[0]);
    {
        static uint8_t pg[1 + 64 * (1 + SP_NAME_MAX + 32)];
        for (int f = 0; f < 200; f++) {                 /* 200 AE-page frames x 64 never-seen names */
            int o = 0; pg[o++] = 64;
            for (int k = 0; k < 64; k++) {
                snprintf(nm, sizeof nm, "a%05d", f * 64 + k); int nl = (int)strlen(nm);
                pg[o++] = (uint8_t)nl; memcpy(pg + o, nm, (size_t)nl); o += nl;
                rnd_dg(dg, 50000u + (uint32_t)(f * 64 + k)); memcpy(pg + o, dg, 32); o += 32;
            }
            dnsnet_msg(h[0], "zinv", pg, o);
            adv_ms(10);
        }
        int ng1 = fp[0]->ng;
        rnd_dg(dg, 9); inv1(0, "live", dg);
        tick_for(25000, 1000);
        int pos = -1; for (int k = ng1; k < fp[0]->ng; k++) if (!strcmp(fp[0]->gets[k], "live")) { pos = k - ng1; break; }
        CKF(C("pull_full") > 0 && pos >= 0 && pos < 64,
            "12800-name AE catch-up (pull table overflowed): a live 1-name relay is pulled within the next 2 slot rounds (zget #%d after it, of %d)", pos, fp[0]->ng - ng1);
    }
    sp_state_close(st);
}

/* ── L4 ─────────────────────────────────────────────────────────────────────── */
static void sec_l4(SpState *big) {
    printf("-- L4: announcements <= 25%% of each link's P6 budget --\n");
    g_tip = 7000; node(big, 1);
    fp_reset(fp[0]);
    char nm[16];
    for (int r = 0; r < 3; r++) { g_tip += 10; for (int i = 0; i < 10000; i++) { snprintf(nm, sizeof nm, "n%05d", i); dnsnet_announce(nm); } }
    long worst = 0, starve = 0, d_prev = 0;
    for (int s = 1; s <= 30; s++) {
        for (int k = 0; k < 200; k++) zget1(0, "zone");
        adv_ms(1000); dnsnet_tick();
        long cap = 131072 + 16384L * s;
        if (fp[0]->inv_bytes - cap > worst) worst = fp[0]->inv_bytes - cap;
        if (s % 2 == 0) { if (fp[0]->n_dat == d_prev) starve++; d_prev = fp[0]->n_dat; }   /* PepeNet: 1 dump per 2 s */
    }
    CKF(worst <= 0, "30 s of announce backlog: inv bytes %ld <= 128 KiB + 16 KiB/s * t", fp[0]->inv_bytes);
    CKF(starve == 0 && fp[0]->dat_bytes > 0, "... while dumps flowed at the GET_COOL_S pace, 1 per 2 s (%ld dumps, %ld B)", fp[0]->n_dat, fp[0]->dat_bytes);
    CKF(fp[0]->bytes <= 524288 + 65536L * 30, "... and the link total stays within P6 (%ld B)", fp[0]->bytes);
}

/* ── L5 ─────────────────────────────────────────────────────────────────────── */
static void sec_l5(void) {
    printf("-- L5: dedup before ECDSA, skip unchanged ops --\n");
    SpState *src = sp_state_open(":memory:"), *st = sp_state_open(":memory:");
    g_tip = 8000;
    for (int i = 0; i < 10; i++) { char lb[8]; snprintf(lb, sizeof lb, "h%d", i); put_a(src, "zone", lb, (uint8_t)i); }
    node(st, 1);
    static uint8_t f[3 * DNS_BUDGET]; int n = mk_zdat(src, "zone", f);
    unsigned long a0 = C("admit_calls");
    dnsnet_msg(h[0], "zdat", f, n);
    CKF(C("admit_new") == 10 && C("admit_calls") - a0 == 10, "a 10-op dump: 10 admitted (10 ECDSA verifies)");
    unsigned long a1 = C("admit_calls"), s1 = C("l5_skip");
    for (int r = 0; r < 50; r++) { adv_ms(200); dnsnet_msg(h[0], "zdat", f, n); }
    CKF(C("admit_calls") == a1 && C("l5_skip") - s1 == 500,
        "the same dump 50x: 500 ops skipped before admission, 0 admit calls (500 ECDSA verifies saved)");
    /* mesh store: a held op_id is a dup BEFORE the signature is checked: the
     * same op with a corrupted signature is -1 (dup, no verify), while a NEW op
     * with a corrupted signature is 0 (rejected by the verify) */
    g_row.l = 0; sp_state_iter(st, "zone", row_cb, &g_row);
    char err[128];
    uint8_t bad[SP_STATE_OP_MAX]; memcpy(bad, g_row.b, (size_t)g_row.l); bad[g_row.l - 2] ^= 0x01;
    int rd = sp_state_admit(st, &ORC, DNS_BUDGET, DNS_SCOPE, bad, g_row.l, err, sizeof err);
    CKF(rd == -1, "mesh: a held op_id with a corrupted signature -> dup (-1) without ECDSA (rc=%d)", rd);
    put_a(src, "zone", "fresh", 77);
    g_row.l = 0; g_row.want = "fresh"; sp_state_iter(src, "zone", row_cb, &g_row); g_row.want = NULL;
    memcpy(bad, g_row.b, (size_t)g_row.l); bad[g_row.l - 2] ^= 0x01;
    int rn = sp_state_admit(st, &ORC, DNS_BUDGET, DNS_SCOPE, bad, g_row.l, err, sizeof err);
    CKF(rn == 0, "mesh: a NEW op with a corrupted signature is still rejected by the verify (rc=%d)", rn);
    sp_state_close(src); sp_state_close(st);
}

/* ── L6 ─────────────────────────────────────────────────────────────────────── */
static void sec_l6(void) {
    printf("-- L6: inbound budget + usefulness (deprioritise, then disconnect) --\n");
    SpState *src = sp_state_open(":memory:"), *st = sp_state_open(":memory:");
    g_tip = 9000;
    put_a(src, "zone", "www", 1);
    node(st, 4);
    fp[2]->local = 1;
    static uint8_t f[3 * DNS_BUDGET]; int n = mk_zdat(src, "zone", f);
    dnsnet_msg(h[3], "zdat", f, n);                    /* we now hold it: its dumps are useless */
    /* inbound byte budget */
    static uint8_t junk[65536]; junk[0] = 0;            /* zinv count 0: parsed, harmless */
    unsigned long d0 = C("in_drop");
    for (int k = 0; k < 100; k++) dnsnet_msg(h[3], "zinv", junk, sizeof junk);   /* 6.5 MB at once */
    unsigned long dropped = C("in_drop") - d0;
    CKF(dropped > 0 && dropped < 100, "6.5 MB from one peer at once: %lu of 100 frames over the 4 MiB burst dropped", dropped);
    adv_ms(20000);
    d0 = C("in_drop"); dnsnet_msg(h[3], "zinv", junk, sizeof junk);
    CKF(C("in_drop") == d0, "... 20 s later its frames are accepted again (256 KiB/s refill)");
    /* useless unsolicited dumps */
    int low_at = -1;
    unsigned long l0 = C("lowprio");
    for (int k = 0; k < 4200; k++) {
        dnsnet_msg(h[0], "zdat", f, n);
        dnsnet_msg(h[2], "zdat", f, n);
        if (low_at < 0 && C("lowprio") > l0) low_at = k + 1;
        if (k % 100 == 99) { adv_ms(1000); dnsnet_tick(); }
    }
    adv_ms(1000); dnsnet_tick(); adv_ms(1000); dnsnet_tick();
    CKF(low_at > 0 && low_at <= 64, "unsolicited useless dumps: deprioritised after %d", low_at);
    CKF(fp[0]->drops == 1, "... and disconnected after >= 4096 (drop called %d time)", fp[0]->drops);
    CKF(fp[2]->drops == 0, "a loopback peer sending the same is never disconnected");
    /* solicited dumps never count: we ask peer 1, it answers with stale data */
    unsigned long u0 = C("useless");
    for (int k = 0; k < 200; k++) {
        char nm[16]; snprintf(nm, sizeof nm, "s%03d", k);
        uint8_t dg[32]; rnd_dg(dg, (uint32_t)k + 9000); inv1(1, nm, dg);   /* it claims a different set */
        uint8_t e[1 + 16 + 1]; int nl = (int)strlen(nm);
        e[0] = (uint8_t)nl; memcpy(e + 1, nm, (size_t)nl); e[1 + nl] = 0;   /* answers: empty dump */
        dnsnet_msg(h[1], "zdat", e, 2 + nl);
        if (k % 30 == 29) { adv_ms(1000); dnsnet_tick(); }
    }
    CKF(C("useless") == u0 && fp[1]->drops == 0, "200 answers to OUR zgets that teach nothing: not scored (useless +%lu)", C("useless") - u0);
    sp_state_close(src); sp_state_close(st);
}

/* ── L7 ─────────────────────────────────────────────────────────────────────── */
static void sec_l7(void) {
    printf("-- L7: Pi profile (peer cap) + P6 refill tied to socket drain --\n");
    CKF(dnsnet_peer_cap_for_uplink(1.0) == 2 && dnsnet_peer_cap_for_uplink(5.0) == 9 &&
        dnsnet_peer_cap_for_uplink(10.0) == 19 && dnsnet_peer_cap_for_uplink(1000.0) == 64,
        "cap = uplink / 0.52 Mbit/s, clamped [2, 64]: 1->%d 5->%d 10->%d 1000->%d",
        dnsnet_peer_cap_for_uplink(1.0), dnsnet_peer_cap_for_uplink(5.0),
        dnsnet_peer_cap_for_uplink(10.0), dnsnet_peer_cap_for_uplink(1000.0));
    SpState *st = sp_state_open(":memory:");
    g_tip = 10000;
    dnsnet_set_peer_cap(2);
    node(st, 3);
    CKF(h[0] && h[1] && !h[2] && C("peer_capped") == 1, "cap 2: the third dn* peer gets no gossip handle");
    dnsnet_set_peer_cap(64);
    node(st, 1);
    for (int i = 0; i < 40; i++) { char lb[8]; snprintf(lb, sizeof lb, "h%d", i); put_a(st, "zone", lb, 7); }
    for (int s = 0; s < 15; s++) { for (int k = 0; k < 400; k++) zget1(0, "zone"); adv_ms(1000); dnsnet_tick(); }
    fp[0]->pending = 1 << 20;                            /* 1 MiB unsent in the socket */
    for (int s = 0; s < 3; s++) { for (int k = 0; k < 400; k++) zget1(0, "zone"); adv_ms(1000); dnsnet_tick(); }
    long b0 = fp[0]->bytes;
    for (int s = 0; s < 20; s++) { for (int k = 0; k < 400; k++) zget1(0, "zone"); adv_ms(1000); dnsnet_tick(); }
    CKF(fp[0]->bytes - b0 == 0, "1 MiB stuck in the socket: 0 new dn* bytes in 20 s (sent %ld)", fp[0]->bytes - b0);
    fp[0]->pending = 0; b0 = fp[0]->bytes;
    for (int s = 0; s < 5; s++) { for (int k = 0; k < 400; k++) zget1(0, "zone"); adv_ms(1000); dnsnet_tick(); }
    CKF(fp[0]->bytes - b0 > 0 && fp[0]->bytes - b0 <= 65536L * 6, "drained: sending resumes at the P6 rate (%ld B in 5 s)", fp[0]->bytes - b0);
    sp_state_close(st);
}

/* ── L8 ─────────────────────────────────────────────────────────────────────── */
static void sec_l8(void) {
    printf("-- L8: per-link staggered AE cursor --\n");
    g_tip = 11000;
    SpState *big = sp_state_open(":memory:");
    for (int i = 0; i < 6000; i++) {                  /* names spread over the namespace */
        uint8_t d[32]; uint8_t sd[4] = { (uint8_t)i, (uint8_t)(i >> 8), 0x18, 0x08 }; sp_sha256(sd, 4, d);
        char nm[9]; for (int k = 0; k < 8; k++) nm[k] = "abcdefghijklmnopqrstuvwxyz0123456789"[d[k] % 36]; nm[8] = 0;
        put_a(big, nm, "www", 1);
    }
    dnsnet_init(big, ORC, 0);
    char first[NP][SP_NAME_MAX + 1];
    for (int i = 0; i < NP; i++) { fp_reset(fp[i]); h[i] = dnsnet_up(fp[i], fp_send); snprintf(first[i], sizeof first[i], "%s", fp[i]->ne ? fp[i]->ent[0] : ""); }
    int distinct = 0;
    for (int i = 0; i < NP; i++) { int dup = 0; for (int j = 0; j < i; j++) if (!strcmp(first[i], first[j])) dup = 1; if (!dup) distinct++; }
    CKF(distinct >= 6, "8 links to a 6000-name store start paging at %d different points", distinct);
    /* each link still covers the whole store within a few periods */
    for (int i = 0; i < NP; i++) fp_reset(fp[i]);
    tick_for(200000, 1000);
    long minE = 1L << 40; for (int i = 0; i < NP; i++) if (fp[i]->inv_entries < minE) minE = fp[i]->inv_entries;
    CKF(minE >= 6000, "... and every link is offered >= the whole store within 200 s (min %ld entries)", minE);
    dnsnet_init(NULL, ORC, 0);
    sp_state_close(big);
}

/* ── L9 ─────────────────────────────────────────────────────────────────────── */
static int64_t dv(sqlite3 *db) {
    sqlite3_stmt *q; int64_t v = -1;
    if (sqlite3_prepare_v2(db, "PRAGMA data_version", -1, &q, NULL) == SQLITE_OK && sqlite3_step(q) == SQLITE_ROW) v = sqlite3_column_int64(q, 0);
    sqlite3_finalize(q); return v;
}
/* commits in the WAL since the last TRUNCATE checkpoint: frames whose header
 * "db size after commit" field is non-zero */
static int wal_commits(const char *path) {
    char w[256]; snprintf(w, sizeof w, "%s-wal", path);
    FILE *f = fopen(w, "rb"); if (!f) return 0;
    uint8_t hd[32]; int n = 0;
    if (fread(hd, 1, 32, f) != 32) { fclose(f); return 0; }
    uint32_t ps = (uint32_t)hd[8] << 24 | (uint32_t)hd[9] << 16 | (uint32_t)hd[10] << 8 | hd[11];
    if (ps == 1) ps = 65536;
    uint8_t fh[24];
    while (fread(fh, 1, 24, f) == 24) {
        if (fh[4] | fh[5] | fh[6] | fh[7]) n++;
        if (fseek(f, (long)ps, SEEK_CUR) != 0) break;
    }
    fclose(f); return n;
}
static void wal_reset(sqlite3 *obs) { int lg = -1, ck = -1; int rc = sqlite3_wal_checkpoint_v2(obs, NULL, SQLITE_CHECKPOINT_TRUNCATE, &lg, &ck); if (rc) printf("    (checkpoint rc=%d log=%d ckpt=%d)\n", rc, lg, ck); }
static void sec_l9(const char *path) {
    printf("-- L9: one DB transaction per dump --\n");
    SpState *src = sp_state_open(":memory:");
    g_tip = 12000;
    for (int i = 0; i < 20; i++) { char lb[8]; snprintf(lb, sizeof lb, "h%d", i); put_a(src, "zone", lb, (uint8_t)i); }
    unlink(path);
    SpState *st = sp_state_open(path);
    sqlite3 *obs; sqlite3_open(path, &obs);
    node(st, 1);
    static uint8_t f[3 * DNS_BUDGET];
    put_a(src, "warm", "www", 1); int n = mk_zdat(src, "warm", f); dnsnet_msg(h[0], "zdat", f, n);   /* first write: schema/WAL setup commits */
    n = mk_zdat(src, "zone", f);
    (void)dv(obs);                                     /* obs joins the WAL before checkpointing */
    wal_reset(obs);
    int64_t v0 = dv(obs);
    unsigned long a0 = C("admit_new"), b0 = C("batch");
    dnsnet_msg(h[0], "zdat", f, n);
    int c1 = wal_commits(path);
    int64_t v1 = dv(obs);
    CKF(C("admit_new") - a0 == 20 && C("batch") - b0 == 1 && c1 == 1 && v1 != v0,
        "a 20-op dump: 20 admitted in ONE commit (admitted %lu, batches %lu, %d WAL commit frame)", C("admit_new") - a0, C("batch") - b0, c1);
    int one_each = 1; char sizes[64] = ""; int sl = 0;
    for (int k = 1; k <= 40; k += (k < 3 ? 1 : 17)) { char zn[16]; snprintf(zn, sizeof zn, "zk%d", k);
      for (int i = 0; i < k; i++) { char lb[8]; snprintf(lb, sizeof lb, "e%d", i); put_a(src, zn, lb, (uint8_t)i); }
      int nn = mk_zdat(src, zn, f); wal_reset(obs); unsigned long ab = C("admit_new");
      adv_ms(1000);                                    /* PepeNet: refill the per-peer ECDSA tokens (64/s) */
      dnsnet_msg(h[0], "zdat", f, nn);
      int cm = wal_commits(path);
      if (C("admit_new") - ab != (unsigned long)k || cm != 1) one_each = 0;
      sl += snprintf(sizes + sl, sizeof sizes - (size_t)sl, "%s%d:%d", sl ? " " : "", k, cm); }
    CKF(one_each, "dumps of 1/2/3/20/37 new ops: one commit each (ops:commits %s)", sizes);
    SpState *st2 = sp_state_open(path);
    for (int i = 0; i < 20; i++) { char lb[8]; snprintf(lb, sizeof lb, "h%d", i); put_a(src, "zonf", lb, (uint8_t)i); }
    g_all.n = 0; sp_state_iter(src, "zonf", all_cb, &g_all);
    wal_reset(obs); char err[128];
    int okc = 0;
    for (int i = 0; i < g_all.n; i++) {
        int rc = sp_state_admit(st2, &ORC, DNS_BUDGET, DNS_SCOPE, g_all.b[i], g_all.l[i], err, sizeof err);
        if (rc == 1) okc++; else printf("    (admit rc=%d %s)\n", rc, err);
    }
    int c2 = wal_commits(path);
    CKF(okc == 20 && c2 == 20, "... vs %d commits for the same 20 ops admitted one by one (old path)", c2);
    sp_state_close(st2);
    sqlite3_close(obs);
    sp_state_close(st); sp_state_close(src); unlink(path);
}

/* ── L10 ────────────────────────────────────────────────────────────────────── */
static void sec_l10(const char *path) {
    printf("-- L10: cached per-name digests --\n");
    g_tip = 13000;
    unlink(path);
    SpState *st = sp_state_open(path), *other = sp_state_open(path), *src = sp_state_open(":memory:");
    put_a(st, "zone", "www", 1);
    node(st, 1);
    uint8_t a[32], b[32], c[32];
    unsigned long h0, m0, h1, m1;
    dns_state_cache_stats(&h0, &m0, NULL, NULL);
    dns_state_digest(st, "zone", a); dns_state_digest(st, "zone", b);
    dns_state_cache_stats(&h1, &m1, NULL, NULL);
    dns_state_digest(other, "zone", c);
    CKF(h1 - h0 >= 1 && !memcmp(a, b, 32) && !memcmp(a, c, 32), "repeat lookup is a hit (%lu hit, %lu miss), identical to an uncached compute", h1 - h0, m1 - m0);
    g_tip++; put_a(src, "zone", "www", 2);
    static uint8_t f[3 * DNS_BUDGET]; int n = mk_zdat(src, "zone", f);
    adv_ms(1000);
    dnsnet_msg(h[0], "zdat", f, n);
    dns_state_digest(st, "zone", a); dns_state_digest(other, "zone", c);
    CKF(memcmp(a, b, 32) && !memcmp(a, c, 32), "after an admit the cached digest follows the store");
    put_a(other, "zone", "mail", 3);                     /* a different connection writes */
    dns_state_digest(st, "zone", a); dns_state_digest(other, "zone", c);
    CKF(!memcmp(a, c, 32), "a write by another connection invalidates the cache (data_version)");
    g_lapse = 1; char cur[SP_NAME_MAX + 1] = ""; int seen = 0;
    dns_state_sweep_step(st, &ORC, cur, 256, &seen); g_lapse = 0;
    dns_state_digest(st, "zone", a); dns_state_digest(other, "zone", c);
    CKF(!memcmp(a, c, 32) && sp_state_sum(st, "zone") == 0, "a sweep drop invalidates the entry");
    int bad = 0;
    for (int i = 0; i < 300; i++) {
        char nm[16]; snprintf(nm, sizeof nm, "q%02d", i % 37);
        if (i % 3 == 0) put_a(st, nm, "www", (uint8_t)i); else if (i % 7 == 0) put_a(other, nm, "w2", (uint8_t)i);
        dns_state_digest(st, nm, a); dns_state_digest(other, nm, c);
        if (memcmp(a, c, 32)) bad++;
    }
    CKF(bad == 0, "300 mixed writes/reads over 37 names: cached digest always == recomputed (%d mismatches)", bad);
    sp_state_close(other); sp_state_close(src);
    sp_state_close(st); unlink(path);
}

int main(void) {
    for (int i = 0; i < NP; i++) { fp[i] = calloc(1, sizeof(FP)); fp[i]->id = i; }
    sp_sha256((const uint8_t *)"owner-a", 7, APRIV);
    while (!sp_pubkey(APRIV, APUB)) sp_sha256(APRIV, 32, APRIV);
    sp_hash160(APUB, 33, OWN_A);
    sec_l2();
    sec_l1();
    sec_l3();
    SpState *big = sp_state_open(":memory:");
    g_tip = 6500;
    for (int i = 0; i < 10000; i++) { char nm[16]; snprintf(nm, sizeof nm, "n%05d", i); put_a(big, nm, "www", 1); }
    for (int i = 0; i < 40; i++) { char lb[8]; snprintf(lb, sizeof lb, "h%d", i); put_a(big, "zone", lb, 7); }
    sec_l4(big);
    sp_state_close(big);
    sec_l8();
    sec_l5();
    sec_l6();
    sec_l7();
    sec_l9("/tmp/p2p_l9.db");
    sec_l10("/tmp/p2p_l10.db");
    if (g_fail) { printf("\np2p_test: %d FAILED\n", g_fail); return 1; }
    printf("\np2p_test: all passed\n");
    return 0;
}
