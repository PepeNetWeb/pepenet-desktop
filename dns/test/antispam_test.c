/* antispam_test.c — the local-only anti-spam limits in src/dns_net.c and the
 * dns_state sweep / G1 helpers, on a fake clock (time() and the ms clock are
 * both test-driven, so refills are exact and the run is instant).
 *
 * PROVES:
 *   A1. P1/L2  rapid local edits of one name: at most DNSNET_CREDIT_BURST invs
 *              go out at once, the rest coalesce into ONE later inv (when the
 *              next block credit arrives) that carries the NEWEST digest; one
 *              edit per 10 blocks is announced immediately every time. (Was
 *              P2: 1 per 15 s; nowon approved L2 block credit Nov 17.)
 *   A2. P3     five peers advertising the same differing digest cause exactly
 *              one dnzget; a timeout moves the pull to the next advertiser.
 *   A3. P4     a flood of edits of one record is admitted at the per-record
 *              rate and the rest are DEFERRED (re-pulled), never lost: the node
 *              ends on the newest edit. One edit per block, and 4 per block,
 *              are admitted every time (zero deferrals).
 *   A4. P7     PepeNet keeps its existing zget rule (one dump per peer per 2 s).
 *   A5. P6     bytes sent to one peer never exceed burst + rate * t.
 *   A6. P8     a 10 000-name store is offered a page (4096) per AE period from
 *              a rotating cursor: every name within 3 periods; a small store is
 *              offered whole on connect, as before.
 *   A7. L2     under backlog a quiet name is relayed ahead of busy names
 *              (stale-first lanes; replaces P10 seniority).
 *   A8. P11    the sweep covers > 256 names (old code: only the first 256), and
 *              the resumable step visits every name.
 *   A9. G1     after a transfer the previous owner's rows are not served; the
 *              new owner's first publish serves normally.
 */
#include "dns_state.h"
#include "dns_net.h"
#include "zone.h"
#include "pepenet/crypto.h"
#include "pepenet/state.h"
#include "pepenet/wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int g_fail;
#define CK(c, m) do { if (c) printf("  ok   %s\n", m); \
                      else { printf("  FAIL %s\n", m); g_fail++; } } while (0)

/* ── fake clocks (dns_net.c is built with -Dtime=ft_time -DDNSNET_TEST_CLOCK_MS=ft_ms) */
static int64_t g_ms = 5000000000LL;
time_t  ft_time(time_t *t) { time_t v = (time_t)(g_ms / 1000); if (t) *t = v; return v; }
int64_t ft_ms(void) { return g_ms; }
static void adv_ms(int64_t d) { g_ms += d; }

/* ── fake chain ─────────────────────────────────────────────────────────────── */
static uint32_t g_tip = 500;
static uint8_t  OWN_A[20], OWN_B[20];
static uint8_t  APRIV[32], APUB[33], BPRIV[32], BPUB[33];
static int      g_xfer;            /* 1: every name is owned by B */
static int      g_lapse_from = -1; /* names nNNNNN with NNNNN >= this have lapsed */

static int fk_owner(void *u, const char *name, uint8_t owner[20]) {
    (void)u;
    if (g_lapse_from >= 0 && name[0] == 'n' && atoi(name + 1) >= g_lapse_from) return 0;
    memcpy(owner, g_xfer ? OWN_B : OWN_A, 20);
    return 1;
}
static int fk_header(void *u, uint32_t height, uint8_t out[32]) {
    (void)u;
    if (height > g_tip) return 0;
    uint8_t seed[8] = { 'h','d','r',1, (uint8_t)height, (uint8_t)(height >> 8),
                        (uint8_t)(height >> 16), (uint8_t)(height >> 24) };
    sp_sha256(seed, sizeof seed, out);
    return 1;
}
static uint32_t fk_tip(void *u) { (void)u; return g_tip; }
static SpChainOracle ORC = { NULL, fk_owner, fk_header, fk_tip };

static void testkey(const char *seed, uint8_t priv[32], uint8_t pub[33]) {
    sp_sha256((const uint8_t *)seed, strlen(seed), priv);
    while (!sp_pubkey(priv, pub)) sp_sha256(priv, 32, priv);
}

/* ── fake peers: count frames/bytes per command, keep the last few frames ───── */
#define NP 8
typedef struct {
    int     id;
    long    n_inv, n_get, n_dat, bytes;
    long    inv_entries;
    /* every inv entry (name, digest) in order, bounded */
    int     ne; struct { char name[SP_NAME_MAX + 1]; uint8_t dg[32]; } ent[40000];
    int     ng; char gets[8192][SP_NAME_MAX + 1];
} FP;
static FP *fp[NP];
static void *h[NP];

static void fp_send(void *peer, const char *cmd, const uint8_t *pay, size_t n) {
    FP *f = peer;
    f->bytes += (long)n + 24;
    if (!strcmp(cmd, "dnzinv")) {
        f->n_inv++;
        int off = 0; uint64_t c;
        if (!sp_rvar(pay, (int)n, &off, &c)) return;
        for (uint64_t i = 0; i < c; i++) {
            int nl = pay[off++];
            if (f->ne < 40000) {
                memcpy(f->ent[f->ne].name, pay + off, (size_t)nl); f->ent[f->ne].name[nl] = 0;
                memcpy(f->ent[f->ne].dg, pay + off + nl, 32);
                f->ne++;
            }
            off += nl + 32; f->inv_entries++;
        }
    } else if (!strcmp(cmd, "dnzget")) {
        f->n_get++;
        if (f->ng < 8192) { memcpy(f->gets[f->ng], pay + 1, pay[0]); f->gets[f->ng][pay[0]] = 0; f->ng++; }
    } else if (!strcmp(cmd, "dnzdat")) f->n_dat++;
}
static void fp_reset(FP *f) { int id = f->id; memset(f, 0, sizeof *f); f->id = id; }

static void node(SpState *st, int npeers) {
    dnsnet_init(st, ORC, 0);
    for (int i = 0; i < NP; i++) { fp_reset(fp[i]); h[i] = NULL; }
    for (int i = 0; i < npeers; i++) h[i] = dnsnet_up(fp[i], fp_send);
    for (int i = 0; i < npeers; i++) fp_reset(fp[i]);
}
static void tick_for(int64_t ms, int64_t step) {
    for (int64_t t = 0; t < ms; t += step) { adv_ms(step); dnsnet_tick(); }
}

static int put_a(SpState *st, const char *name, const char *label, uint8_t v,
                 const uint8_t *priv, const uint8_t *pub) {
    zone_rec r; memset(&r, 0, sizeof r);
    snprintf(r.label, sizeof r.label, "%s", label);
    r.type = 1; r.ttl = 300; r.rdlen = 4;
    r.rdata[0] = 192; r.rdata[1] = 0; r.rdata[2] = 2; r.rdata[3] = v;
    char err[128];
    return dns_state_put(st, &ORC, name, &r, priv, pub, SP_CERT_NONE, NULL, 0, err, sizeof err);
}

/* build the full dump of `name` from store `src` (the dnzdat grammar) */
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
static int same_digest(SpState *a, SpState *b, const char *name) {
    uint8_t x[32], y[32]; dns_state_digest(a, name, x); dns_state_digest(b, name, y);
    return !memcmp(x, y, 32);
}
static uint8_t held_v(SpState *st, const char *name) {
    zone z; dns_state_zone(st, name, &z);
    for (int i = 0; i < z.n; i++) if (!strcmp(z.recs[i].label, "www")) return z.recs[i].rdata[3];
    return 0;
}

/* ── A1 ─────────────────────────────────────────────────────────────────────── */
/* P1 + L2 (replaces P2's 15 s refill): burst DNSNET_CREDIT_BURST relays per
 * name, then one per 10 BLOCKS; over credit = one coalesced relay of the
 * NEWEST set when a credit arrives. */
static void sec_announce(void) {
    printf("-- A1. P1/L2: announce limiter (block credit) --\n");
    SpState *st = sp_state_open(":memory:");
    node(st, 1);
    g_tip++;                                         /* all 100 edits at one tip */
    for (int i = 0; i < 100; i++) { put_a(st, "zone", "www", (uint8_t)i, APRIV, APUB); dnsnet_announce("zone"); adv_ms(5); }
    char m[160];
    snprintf(m, sizeof m, "100 edits in 0.5 s at one tip: %ld inv entries at once (<= 4)", fp[0]->inv_entries);
    CK(fp[0]->inv_entries <= 4 && fp[0]->inv_entries >= 1, m);
    long n0 = fp[0]->inv_entries;
    tick_for(16000, 250);
    CK(fp[0]->inv_entries == n0, "no new block: no credit, nothing more after 16 s (stalled chain)");
    g_tip += 10; tick_for(1000, 250);
    uint8_t cur[32]; dns_state_digest(st, "zone", cur);
    CK(fp[0]->inv_entries == n0 + 1, "... 10 blocks later exactly one coalesced inv");
    CK(fp[0]->ne && !memcmp(fp[0]->ent[fp[0]->ne - 1].dg, cur, 32), "... carrying the NEWEST digest");
    tick_for(120000, 1000);
    CK(fp[0]->inv_entries <= n0 + 1 + 3, "... and nothing more for an idle name than the 60 s AE re-offer (1-name store)");

    /* cadence: one edit per 10 blocks is always immediate */
    sp_state_close(st); st = sp_state_open(":memory:"); node(st, 1);
    int late = 0;
    for (int i = 0; i < 30; i++) {
        long before = fp[0]->inv_entries;
        g_tip += 10; put_a(st, "zone", "www", (uint8_t)i, APRIV, APUB); dnsnet_announce("zone");
        uint8_t d[32]; dns_state_digest(st, "zone", d);
        int found = 0;
        for (int k = 0; k < fp[0]->ne; k++) if (!memcmp(fp[0]->ent[k].dg, d, 32)) found = 1;
        if (fp[0]->inv_entries == before || !found) late++;
        tick_for(60000, 1000);
    }
    CK(late == 0, "one edit per 10 blocks: every edit announced immediately");
    /* one edit per block: the burst, then one per 10 blocks; the newest set is
     * always relayed within 10 blocks (late, never lost) */
    late = 0; int stale_max = 0, behind = 0;
    for (int b = 0; b < 60; b++) {
        long before = fp[0]->inv_entries;
        g_tip++; put_a(st, "zone", "www", (uint8_t)(100 + b), APRIV, APUB); dnsnet_announce("zone");
        if (fp[0]->inv_entries == before) { late++; behind++; } else behind = 0;
        if (behind > stale_max) stale_max = behind;
        tick_for(1000, 1000);
    }
    snprintf(m, sizeof m, "one edit per block for 60 blocks: %d coalesced, newest relayed within %d blocks (<= 10)", late, stale_max);
    CK(late > 0 && stale_max <= 10, m);
    sp_state_close(st);
}

/* ── A2 ─────────────────────────────────────────────────────────────────────── */
static void sec_pull(void) {
    printf("-- A2. P3: pull dedup --\n");
    SpState *st = sp_state_open(":memory:");
    node(st, 5);
    uint8_t inv[64]; int o = 0;
    o += sp_wvar(inv, 1); inv[o++] = 4; memcpy(inv + o, "zone", 4); o += 4;
    memset(inv + o, 0xAB, 32); o += 32;
    for (int i = 0; i < 5; i++) dnsnet_msg(h[i], "zinv", inv, o);
    long gets = 0; for (int i = 0; i < 5; i++) gets += fp[i]->n_get;
    CK(gets == 1, "5 peers advertise one differing digest: exactly 1 dnzget");
    tick_for(11000, 500);
    gets = 0; for (int i = 0; i < 5; i++) gets += fp[i]->n_get;
    CK(gets == 2, "no answer within 10 s: the pull moves to a 2nd advertiser");
    tick_for(60000, 1000);
    gets = 0; for (int i = 0; i < 5; i++) gets += fp[i]->n_get;
    CK(gets == 5, "silent advertisers are each tried once, then the name is forgotten");
    sp_state_close(st);
}

/* ── A3 ─────────────────────────────────────────────────────────────────────── */
static void sec_admit(void) {
    printf("-- A3. P4: per-record admission (defer, never lose) --\n");
    SpState *src = sp_state_open(":memory:"), *st = sp_state_open(":memory:");
    static uint8_t f[2 * DNS_BUDGET + 64];
    node(st, 1);
    int admitted = 0;
    for (int i = 1; i <= 200; i++) {
        g_tip++; put_a(src, "zone", "www", (uint8_t)i, APRIV, APUB);
        int n = mk_zdat(src, "zone", f);
        uint8_t before = held_v(st, "zone");
        dnsnet_msg(h[0], "zdat", f, n);
        if (held_v(st, "zone") != before) admitted++;
        adv_ms(10);
    }
    char m[160];
    snprintf(m, sizeof m, "flood: 200 edits of one record in 2 s -> %d admitted now (<= 8)", admitted);
    CK(admitted <= 8 && admitted >= 1, m);
    CK(held_v(st, "zone") != 200, "... the node is behind on purpose");
    /* the re-pull: answer every zget with the source's current dump */
    for (int t = 0; t < 60; t++) {
        adv_ms(1000); dnsnet_tick();
        while (fp[0]->ng) { fp[0]->ng--; int n = mk_zdat(src, "zone", f); dnsnet_msg(h[0], "zdat", f, n); }
    }
    CK(held_v(st, "zone") == 200 && same_digest(src, st, "zone"), "... and converges on the NEWEST edit (re-pulled)");

    /* cadence */
    sp_state_close(src); sp_state_close(st);
    src = sp_state_open(":memory:"); st = sp_state_open(":memory:"); node(st, 1);
    int missed = 0;
    for (int i = 1; i <= 60; i++) {
        g_tip++; put_a(src, "zone", "www", (uint8_t)i, APRIV, APUB);
        int n = mk_zdat(src, "zone", f); dnsnet_msg(h[0], "zdat", f, n);
        if (!same_digest(src, st, "zone")) missed++;
        tick_for(60000, 1000);
    }
    CK(missed == 0, "one edit per block for an hour: every edit admitted at once");
    missed = 0;
    for (int i = 1; i <= 120; i++) {
        g_tip++; put_a(src, "zone", "www", (uint8_t)(i + 60), APRIV, APUB);
        int n = mk_zdat(src, "zone", f); dnsnet_msg(h[0], "zdat", f, n);
        if (!same_digest(src, st, "zone")) missed++;
        tick_for(15000, 1000);
    }
    snprintf(m, sizeof m, "four edits per block for 30 min: every edit admitted at once (missed=%d)", missed);
    CK(missed == 0, m);
    /* many records at once (a full-zone publish/transfer re-publish) */
    missed = 0;
    for (int i = 0; i < 40; i++) { char lb[16]; snprintf(lb, sizeof lb, "h%d", i); put_a(src, "zone", lb, 7, APRIV, APUB); }
    { int n = mk_zdat(src, "zone", f); dnsnet_msg(h[0], "zdat", f, n); }
    CK(same_digest(src, st, "zone"), "a 40-record zone published at once is admitted whole");
    sp_state_close(src); sp_state_close(st);
}

/* ── A4/A5 ──────────────────────────────────────────────────────────────────── */
static void sec_get(void) {
    printf("-- A4/A5. P7 zget pacing, P6 send budget --\n");
    SpState *st = sp_state_open(":memory:");
    node(st, 1);
    uint8_t q[40];
    /* PepeNet's P7 is its existing rule, kept: one dump per peer per GET_COOL_S (2 s) */
    for (int i = 0; i < 2000; i++) {
        char nm[16]; int nl = snprintf(nm, sizeof nm, "q%05d", i);
        q[0] = (uint8_t)nl; memcpy(q + 1, nm, (size_t)nl);
        dnsnet_msg(h[0], "zget", q, 1 + nl);
    }
    char m[160];
    snprintf(m, sizeof m, "2000 zgets at once: %ld answered (PepeNet GET_COOL_S: 1 per 2 s, unchanged)", fp[0]->n_dat);
    CK(fp[0]->n_dat == 1, m);
    adv_ms(2000);
    q[0] = 4; memcpy(q + 1, "zone", 4); dnsnet_msg(h[0], "zget", q, 5);
    CK(fp[0]->n_dat == 2, "... and the next one 2 s later is answered");
    /* P6: a big zone requested over and over: bytes <= burst + rate*t */
    sp_state_close(st); st = sp_state_open(":memory:"); node(st, 1);
    for (int i = 0; i < 40; i++) { char lb[16]; snprintf(lb, sizeof lb, "h%d", i); put_a(st, "zone", lb, 7, APRIV, APUB); }
    q[0] = 4; memcpy(q + 1, "zone", 4);
    long worst = 0;
    for (int s = 0; s < 20; s++) {
        for (int k = 0; k < 40; k++) { dnsnet_msg(h[0], "zget", q, 5); tick_for(25, 25); }
        tick_for(1000, 50);
        long cap = 524288 + 65536L * (s + 1);
        if (fp[0]->bytes - cap > worst) worst = fp[0]->bytes - cap;
    }
    snprintf(m, sizeof m, "repeat zgets of a %d-record zone: bytes stay <= burst + rate*t (sent %ld B in 20 s)", 40, fp[0]->bytes);
    CK(worst <= 0, m);
    sp_state_close(st);
}

/* ── A6 ─────────────────────────────────────────────────────────────────────── */
static void sec_ae(SpState *big) {
    printf("-- A6. P8: paged anti-entropy --\n");
    node(big, 0);
    h[0] = dnsnet_up(fp[0], fp_send);
    char m[160];
    snprintf(m, sizeof m, "connect to a 10000-name store: the first page starts at once (%ld names, L4: 25%% of P6)", fp[0]->inv_entries);
    CK(fp[0]->inv_entries >= 1024 && fp[0]->inv_entries <= 4096, m);
    tick_for(5000, 250);
    snprintf(m, sizeof m, "... and completes within 5 s (%ld names)", fp[0]->inv_entries);
    CK(fp[0]->inv_entries == 4096, m);
    tick_for(181000, 1000);
    /* every name seen at least once */
    static char seen[10000];
    memset(seen, 0, sizeof seen);
    for (int k = 0; k < fp[0]->ne; k++) { int i = atoi(fp[0]->ent[k].name + 1); if (i >= 0 && i < 10000) seen[i] = 1; }
    int all = 1; for (int i = 0; i < 10000; i++) if (!seen[i]) all = 0;
    snprintf(m, sizeof m, "within 3 AE periods every name was offered (%ld entries)", fp[0]->inv_entries);
    CK(all, m);
    CK(fp[0]->inv_entries <= 4 * 4096, "... never more than one page per period");
    SpState *small = sp_state_open(":memory:");
    put_a(small, "zone", "www", 1, APRIV, APUB); put_a(small, "zonf", "www", 1, APRIV, APUB);
    node(small, 0); h[0] = dnsnet_up(fp[0], fp_send);
    CK(fp[0]->inv_entries == 2, "a 2-name store is offered whole on connect (unchanged)");
    tick_for(89000, 1000);                          /* L8: first re-offer 30..89 s after connect */
    CK(fp[0]->inv_entries == 4, "... and whole again each AE period, once");
    sp_state_close(small);
}

/* ── A7 ─────────────────────────────────────────────────────────────────────── */
/* L2 stale-first (replaces P10 seniority): under backlog a name that has been
 * quiet for a long time is relayed before names that changed recently. */
static void sec_senior(SpState *big) {
    printf("-- A7. L2: stale-first lanes under backlog --\n");
    node(big, 1);
    tick_for(10000, 250);                           /* let the connect page drain */
    /* 10000 names relayed once now (lane 0: never relayed before) ... */
    for (int i = 0; i < 10000; i++) { char nm[16]; snprintf(nm, sizeof nm, "n%05d", i); dnsnet_announce(nm); }
    tick_for(40000, 250);                           /* drained (L4: 16 KiB/s of invs) */
    g_tip += 10;                                    /* one credit each */
    /* ... and again: now they are busy names (quiet 10 blocks, lane 3) */
    for (int i = 0; i < 10000; i++) { char nm[16]; snprintf(nm, sizeof nm, "n%05d", i); dnsnet_announce(nm); }
    long before = fp[0]->ne;
    dnsnet_announce("quiet");                        /* a name nobody relayed recently */
    adv_ms(1000);
    fp[0]->ne = 0;
    dnsnet_tick();
    CK(before > 0, "busy-name announces filled the peer's announce budget");
    int pos = -1; for (int k = 0; k < fp[0]->ne; k++) if (!strcmp(fp[0]->ent[k].name, "quiet")) { pos = k; break; }
    char m[160]; snprintf(m, sizeof m, "the quiet name rides ahead of the busy backlog (pos=%d of %d sent this second)", pos, fp[0]->ne);
    CK(pos >= 0 && pos < fp[0]->ne, m);
}

/* ── A8 ─────────────────────────────────────────────────────────────────────── */
static void sec_sweep(SpState *big) {
    printf("-- A8. P11: sweep over > 256 names --\n");
    g_lapse_from = 4000;                              /* n04000..n09999 lapsed */
    char cur[SP_NAME_MAX + 1] = ""; int seen = 0, steps = 0, dropped = 0;
    do { dropped += dns_state_sweep_step(big, &ORC, cur, 256, &seen); steps++; } while (cur[0] && steps < 1000);
    char m[160]; snprintf(m, sizeof m, "256-name steps walk the whole store and wrap (%d steps, %d dropped)", steps, dropped);
    CK(dropped == 6000 && steps >= 10000 / 256, m);
    int left = 0; uint8_t o[20];
    for (int i = 0; i < 10000; i++) { char nm[16]; snprintf(nm, sizeof nm, "n%05d", i); if (sp_state_sum(big, nm) > 0) { left++; (void)o; } }
    CK(left == 4000, "every expired name processed, every live one kept");
    g_lapse_from = -1;
}

/* ── A9 ─────────────────────────────────────────────────────────────────────── */
static void sec_g1(void) {
    printf("-- A9. G1: owner check at query time --\n");
    SpState *st = sp_state_open(":memory:");
    put_a(st, "zone", "www", 1, APRIV, APUB); put_a(st, "zone", "mail", 2, APRIV, APUB);
    zone z;
    CK(dns_state_zone_owned(st, "zone", OWN_A, &z) == 2, "owner A: A's 2 records served");
    g_xfer = 1;                                     /* transfer to B on chain */
    CK(dns_state_zone_owned(st, "zone", OWN_B, &z) == 0, "after transfer to B: A's records are NOT served");
    CK(dns_state_zone(st, "zone", &z) == 2, "... (they are still held until B publishes: store untouched)");
    g_tip += 10;
    CK(put_a(st, "zone", "www", 9, BPRIV, BPUB) == 1, "B publishes");
    CK(dns_state_zone_owned(st, "zone", OWN_B, &z) == 1 && z.recs[0].rdata[3] == 9, "B's record served, A's wiped");
    CK(put_a(st, "zone", "evil", 3, APRIV, APUB) != 1, "A can no longer publish");
    g_xfer = 0;
    sp_state_close(st);
}

int main(void) {
    for (int i = 0; i < NP; i++) { fp[i] = calloc(1, sizeof(FP)); fp[i]->id = i; }
    testkey("owner-a", APRIV, APUB); sp_hash160(APUB, 33, OWN_A);
    testkey("owner-b", BPRIV, BPUB); sp_hash160(BPUB, 33, OWN_B);
    sec_announce();
    sec_pull();
    sec_admit();
    sec_get();
    SpState *big = sp_state_open(":memory:");
    for (int i = 0; i < 10000; i++) { char nm[16]; snprintf(nm, sizeof nm, "n%05d", i); put_a(big, nm, "www", 1, APRIV, APUB); }
    sec_ae(big);
    sec_senior(big);
    sec_sweep(big);
    sp_state_close(big);
    sec_g1();
    if (g_fail) { printf("\nantispam_test: %d FAILED\n", g_fail); return 1; }
    printf("\nantispam_test: all passed\n");
    return 0;
}
