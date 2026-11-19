// protocol-sm C reference — CLI.
//
//   sm selftest              PRNG/digest/fold sanity (exit non-zero on failure)
//   sm random <seed> <count> (generator — pending)
//   sm scenario <id>         (directed scenarios — pending)
#include "sm.h"
#include "prng.h"
#include "sha256.h"
#include "attrib.h"
#include "secp256k1.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void hexout(const uint8_t *d, int n, char *out) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[2*i] = H[d[i] >> 4]; out[2*i+1] = H[d[i] & 15]; }
    out[2*n] = '\0';
}

static int g_fail = 0, g_pass = 0;
#define CHECK(c, msg) do { if (c) g_pass++; else { g_fail++; printf("FAIL: %s\n", (msg)); } } while (0)

// ── small tx builders (the abstraction in action — no chain bytes) ───────────
static SmId id_of(uint8_t tag) { SmId d; memset(&d, 0, sizeof d); d.h160[0] = tag; d.h160[19] = tag; d.type = SM_P2PKH; return d; }

static void tx1(SmTx *t, uint8_t signer, uint32_t txindex) {   // one P2PKH input, SIGHASH_ALL
    sm_tx_free(t); memset(t, 0, sizeof *t);
    t->txindex = txindex;
    *sm_tx_input(t) = id_of(signer); t->in_sighash_all[0] = 1;
}
static void add_action(SmTx *t, SmAction a, uint64_t value) {
    SmCarrier *c = sm_tx_carrier(t);
    c->kind = SM_CAR_ACTION; c->act = a;
    c->value = value; c->vout = (uint32_t)(t->n_carriers - 1);
}
static SmAction commit(uint8_t c0) {
    SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_COMMIT; a.commitment[0] = c0; return a;
}
static void mk_h160(uint8_t out[20], uint8_t tag) { memset(out, 0, 20); out[0] = tag; out[19] = tag; }

static SmAction mk_commit(const char *name, const uint8_t author[20], uint8_t salt0) {
    SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_COMMIT;
    uint8_t salt[32]; memset(salt, salt0, 32);
    SHA256_CTX h; sha256_init(&h);
    sha256_update(&h, salt, 32);
    sha256_update(&h, (const uint8_t *)name, (unsigned)strlen(name));
    sha256_update(&h, author, 20);
    sha256_final(&h, a.commitment);
    return a;
}
static SmAction mk_claim(const char *name, uint8_t salt0) {
    SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_CLAIM;
    memset(a.salt, salt0, 32);
    snprintf(a.name, sizeof a.name, "%s", name); a.name_len = (uint8_t)strlen(name);
    return a;
}
static SmAction xfer_all(const uint8_t target[20]) {       // TRANSFER, all owned, gift
    SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_TRANSFER; memcpy(a.addr, target, 20); return a;
}
static SmAction xfer_bits(uint64_t anchor, const uint8_t *flags, int flen, const uint8_t target[20]) {
    SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_TRANSFER; memcpy(a.addr, target, 20);
    a.has_anchor = 1; a.anchor = anchor; memcpy(a.flags, flags, (size_t)flen); a.flags_len = (uint8_t)flen;
    return a;
}
static SmAction renew_all(void) {
    SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_RENEW; return a;
}
static SmAction release_bits(uint64_t anchor, const uint8_t *flags, int flen) {
    SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_RELEASE;
    a.has_anchor = 1; a.anchor = anchor; memcpy(a.flags, flags, (size_t)flen); a.flags_len = (uint8_t)flen;
    return a;
}

static void add_out(SmTx *t, const uint8_t dest[20], uint8_t type, uint64_t value) {
    SmOut *so = sm_tx_out(t); int o = t->n_outs - 1;
    memcpy(so->h160, dest, 20); so->type = type; so->value = value;
    so->vout = (uint32_t)(SM_SYNTH_VOUT_BASE + o);   // outputs sit after carriers in vout space
}
static SmAction nameact(uint8_t op, const char *n) {
    SmAction a; memset(&a, 0, sizeof a); a.op = op;
    snprintf(a.name, sizeof a.name, "%s", n); a.name_len = (uint8_t)strlen(n); return a;
}
static SmAction sell(uint64_t price, uint32_t window, const char *n) {
    SmAction a = nameact(SM_OP_SELL, n); a.price = price; a.window = window; return a;
}
static SmAction sell_to(uint64_t price, const uint8_t buyer[20], const char *n) {
    SmAction a = nameact(SM_OP_SELL_TO, n); a.price = price; memcpy(a.addr, buyer, 20); return a;
}

// ── tests ─────────────────────────────────────────────────────────────────────

static void test_prng(void) {
    SmRng r; sm_rng_seed(&r, 0);
    uint64_t v = sm_rng_next(&r);
    CHECK(v == 0xE220A8397B1DCDAFULL, "splitmix64 seed-0 first output");
    // determinism: same seed → same stream
    SmRng a, b; sm_rng_seed(&a, 42); sm_rng_seed(&b, 42);
    int ok = 1; for (int i = 0; i < 100; i++) ok &= (sm_rng_next(&a) == sm_rng_next(&b));
    CHECK(ok, "splitmix64 deterministic");
}

static void test_empty_digest_stable(void) {
    SmState *x = sm_new(0), *y = sm_new(0);
    uint8_t dx[32], dy[32]; sm_state_digest(x, dx); sm_state_digest(y, dy);
    CHECK(memcmp(dx, dy, 32) == 0, "empty digest stable across instances");
    sm_free(x); sm_free(y);
}

static void test_activation_gate(void) {
    SmState *s = sm_new(50);                 // COMMIT gated at height 50
    sm_begin_block(s, 40, 1000, 1);
    SmTx a = {0}; tx1(&a, 0xAA, 0); add_action(&a, commit(0x01), 0); sm_apply_tx(s, &a);
    CHECK(s->n_commits == 0, "gated COMMIT below activation height drops");
    sm_begin_block(s, 60, 2000, 1);
    SmTx b = {0}; tx1(&b, 0xAA, 0); add_action(&b, commit(0x01), 0); sm_apply_tx(s, &b);
    CHECK(s->n_commits == 1, "COMMIT at/after activation height records");
    sm_free(s);
}

static void test_fold_determinism(void) {
    // Same script twice → identical digest.
    uint8_t d[2][32];
    for (int run = 0; run < 2; run++) {
        SmState *s = sm_new(0);
        sm_begin_block(s, 100, 1000, 1);
        SmTx t = {0}; tx1(&t, 0xAA, 0); add_action(&t, commit(0x22), 0); sm_apply_tx(s, &t);
        sm_begin_block(s, 101, 1100, 1);
        SmTx u = {0}; tx1(&u, 0xBB, 0); add_action(&u, commit(0x44), 0); sm_apply_tx(s, &u);
        sm_state_digest(s, d[run]); sm_free(s);
    }
    CHECK(memcmp(d[0], d[1], 32) == 0, "fold determinism: same script → same digest");
}

// rate = 28 makes the burn equal the number of days: T = B·LEASE_QUANTUM/(rate·BILLING_UNIT)
// = B·2419200/(28·86400) = B. Convenient for asserting exact lease lengths.
#define RATE_DAYS 28

static void test_commit_claim(void) {
    SmState *s = sm_new(0);
    uint8_t A[20]; mk_h160(A, 0xAA);
    sm_begin_block(s, 10, 1000, RATE_DAYS);
    SmTx tc = {0}; tx1(&tc, 0xAA, 0); add_action(&tc, mk_commit("bob", A, 0x11), 0); sm_apply_tx(s, &tc);
    CHECK(s->n_commits == 1, "commit recorded");
    sm_begin_block(s, 11, 1500, RATE_DAYS);
    SmTx tk = {0}; tx1(&tk, 0xAA, 0); add_action(&tk, mk_claim("bob", 0x11), 10); sm_apply_tx(s, &tk);  // 10 days
    const SmNameRow *r = sm_lookup(s, "bob");
    CHECK(r && r->st == SM_OWNED && memcmp(r->owner, A, 20) == 0, "claim mints to author");
    CHECK(r && r->lease_expiry == 1500 + 10*86400, "lease = now + 10 days (burn 10, rate 28)");
    sm_free(s);
}

static void test_claim_drops(void) {
    // naked claim (no commit) drops.
    SmState *s = sm_new(0);
    sm_begin_block(s, 11, 1500, RATE_DAYS);
    SmTx tk = {0}; tx1(&tk, 0xAA, 0); add_action(&tk, mk_claim("bob", 0x11), 10); sm_apply_tx(s, &tk);
    CHECK(sm_lookup(s, "bob") == NULL, "naked claim (no commit) drops");
    sm_free(s);

    // same-block commit is too shallow → claim drops, commit still recorded.
    s = sm_new(0); uint8_t A[20]; mk_h160(A, 0xAA);
    sm_begin_block(s, 11, 1500, RATE_DAYS);
    SmTx t = {0}; tx1(&t, 0xAA, 0);
    add_action(&t, mk_commit("bob", A, 0x11), 0);
    add_action(&t, mk_claim("bob", 0x11), 10);
    sm_apply_tx(s, &t);
    CHECK(sm_lookup(s, "bob") == NULL, "same-block commit too shallow → claim drops");
    CHECK(s->n_commits == 1, "the too-shallow commit is still recorded");
    sm_free(s);

    // claim with too-small burn (0 days) drops even with a good commit.
    s = sm_new(0); mk_h160(A, 0xAA);
    sm_begin_block(s, 10, 1000, RATE_DAYS);
    SmTx c = {0}; tx1(&c, 0xAA, 0); add_action(&c, mk_commit("bob", A, 0x11), 0); sm_apply_tx(s, &c);
    sm_begin_block(s, 11, 1500, RATE_DAYS);
    SmTx k = {0}; tx1(&k, 0xAA, 0); add_action(&k, mk_claim("bob", 0x11), 0); sm_apply_tx(s, &k);  // 0 koinu → 0 days
    CHECK(sm_lookup(s, "bob") == NULL, "claim that buys <1 day drops (fail-closed)");
    sm_free(s);
}

static void test_claim_priority(void) {
    // A commits at h=10, B at h=12; both claim at h=20. Lower commit_height (A)
    // MUST win regardless of the claims' tx order.
    for (int order = 0; order < 2; order++) {
        SmState *s = sm_new(0);
        uint8_t A[20], B[20]; mk_h160(A, 0xAA); mk_h160(B, 0xBB);
        sm_begin_block(s, 10, 1000, RATE_DAYS);
        SmTx ca = {0}; tx1(&ca, 0xAA, 0); add_action(&ca, mk_commit("bob", A, 0x11), 0); sm_apply_tx(s, &ca);
        sm_begin_block(s, 12, 1100, RATE_DAYS);
        SmTx cb = {0}; tx1(&cb, 0xBB, 0); add_action(&cb, mk_commit("bob", B, 0x22), 0); sm_apply_tx(s, &cb);
        sm_begin_block(s, 20, 1200, RATE_DAYS);
        SmTx kA = {0}; tx1(&kA, 0xAA, order == 0 ? 1 : 0); add_action(&kA, mk_claim("bob", 0x11), 10);
        SmTx kB = {0}; tx1(&kB, 0xBB, order == 0 ? 0 : 1); add_action(&kB, mk_claim("bob", 0x22), 10);
        if (order == 0) { sm_apply_tx(s, &kB); sm_apply_tx(s, &kA); }   // B first, A displaces
        else            { sm_apply_tx(s, &kA); sm_apply_tx(s, &kB); }   // A first, B can't displace
        const SmNameRow *r = sm_lookup(s, "bob");
        CHECK(r && memcmp(r->owner, A, 20) == 0, "lower commit_height wins regardless of tx order");
        sm_free(s);
    }
}

// Helper: mint `name` to `tag` with `days` lease, leaving the fold at the claim's block.
static SmState *minted(uint8_t tag, const char *name, int days, int64_t claim_mtp) {
    SmState *s = sm_new(0);
    uint8_t H[20]; mk_h160(H, tag);
    sm_begin_block(s, 10, claim_mtp - 100, RATE_DAYS);
    SmTx c = {0}; tx1(&c, tag, 0); add_action(&c, mk_commit(name, H, 0x33), 0); sm_apply_tx(s, &c);
    sm_begin_block(s, 11, claim_mtp, RATE_DAYS);
    SmTx k = {0}; tx1(&k, tag, 0); add_action(&k, mk_claim(name, 0x33), (uint64_t)days); sm_apply_tx(s, &k);
    return s;
}

static void test_lease_lapse(void) {
    SmState *s = minted(0xAA, "bob", 10, 1500);           // expiry 1500 + 10*86400 = 865500
    sm_begin_block(s, 12, 865499, RATE_DAYS);
    CHECK(sm_lookup(s, "bob") != NULL, "owned while MTP < lease_expiry");
    sm_begin_block(s, 13, 865500, RATE_DAYS);             // MTP == expiry → lapse (exclusive)
    CHECK(sm_lookup(s, "bob") == NULL, "lapse at MTP == lease_expiry");
    // same-block reclaim by B.
    uint8_t B[20]; mk_h160(B, 0xBB);
    SmTx c = {0}; tx1(&c, 0xBB, 0); add_action(&c, mk_commit("bob", B, 0x44), 0); sm_apply_tx(s, &c);  // commit too shallow here
    CHECK(sm_lookup(s, "bob") == NULL, "fresh commit alone does not reclaim");
    sm_free(s);
}

static void test_renew(void) {
    SmState *s = minted(0xAA, "bob", 10, 1500);           // expiry 865500
    sm_begin_block(s, 12, 1600, RATE_DAYS);
    SmTx t = {0}; tx1(&t, 0xAA, 0); add_action(&t, renew_all(), 5); sm_apply_tx(s, &t);   // +5 days
    CHECK(sm_lookup(s, "bob")->lease_expiry == 865500 + 5*86400, "renew-all adds 5 days, lease stacks");
    sm_free(s);
}

// §6 ceiling reach: a selective RENEW whose flag bit sits PAST the old
// 80-byte carrier (bit 590 needs 74 flag bytes) folds correctly — the bitmap
// ops scale to Pepecoin's script ceiling, not to the relay default.
static void test_wide_bitmap(void) {
    SmState *s = sm_new(0);
    uint8_t H[20]; mk_h160(H, 0xAA);
    char nm[8];
    sm_begin_block(s, 10, 1400, RATE_DAYS);
    for (int i = 0; i < 600; i++) {
        snprintf(nm, sizeof nm, "n%03d", i);
        SmTx c = {0}; tx1(&c, 0xAA, 0); add_action(&c, mk_commit(nm, H, 0x33), 0);
        sm_apply_tx(s, &c); sm_tx_free(&c);
    }
    sm_begin_block(s, 11, 1500, RATE_DAYS);
    for (int i = 0; i < 600; i++) {
        snprintf(nm, sizeof nm, "n%03d", i);
        SmTx k = {0}; tx1(&k, 0xAA, 0); add_action(&k, mk_claim(nm, 0x33), 10);
        sm_apply_tx(s, &k); sm_tx_free(&k);
    }
    CHECK(sm_lookup(s, "n590") != NULL, "600-name owned set minted");
    int64_t exp0 = sm_lookup(s, "n590")->lease_expiry;
    int64_t nb0  = sm_lookup(s, "n589")->lease_expiry;
    sm_begin_block(s, 12, 1600, RATE_DAYS);
    SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_RENEW;
    a.has_anchor = 1; a.anchor = 12;
    a.flags_len = 74;                        // impossible under the old 71-byte cap
    a.flags[73] = 0x40;                      // LSB-first bit 590 = byte 73, bit 6
    SmTx t = {0}; tx1(&t, 0xAA, 0); add_action(&t, a, 5);
    sm_apply_tx(s, &t); sm_tx_free(&t);
    CHECK(sm_lookup(s, "n590")->lease_expiry == exp0 + 5*86400,
          "wide-bitmap RENEW (bit 590, 74 flag bytes) water-fills the flagged name");
    CHECK(sm_lookup(s, "n589")->lease_expiry == nb0, "neighbor at bit 589 untouched");
    sm_free(s);
}

static void test_transfer_release(void) {
    SmState *s = minted(0xAA, "bob", 10, 1500);
    int64_t exp0 = sm_lookup(s, "bob")->lease_expiry;
    uint8_t A[20], B[20]; mk_h160(A, 0xAA); mk_h160(B, 0xBB);
    sm_begin_block(s, 12, 1600, RATE_DAYS);
    SmTx tt = {0}; tx1(&tt, 0xAA, 0); add_action(&tt, xfer_all(B), 0); sm_apply_tx(s, &tt);
    const SmNameRow *r = sm_lookup(s, "bob");
    CHECK(r && memcmp(r->owner, B, 20) == 0 && r->lease_expiry == exp0, "transfer gifts to B, lease conveys");
    CHECK(sm_last_mutation(s, A) == 12 && sm_last_mutation(s, B) == 12, "transfer bumps both mutation heights");

    // B releases bob (anchor 12, bit 0).
    sm_begin_block(s, 13, 1700, RATE_DAYS);
    uint8_t flags[1] = { 0x01 };
    SmTx tr = {0}; tx1(&tr, 0xBB, 0); add_action(&tr, release_bits(12, flags, 1), 0); sm_apply_tx(s, &tr);
    CHECK(sm_lookup(s, "bob") == NULL, "RELEASE returns bob to the pool");
    sm_free(s);
}

static void test_market_open(void) {
    SmState *s = minted(0xAA, "w", 300, 1500);            // A owns w, long lease
    uint8_t A[20], B[20]; mk_h160(A, 0xAA); mk_h160(B, 0xBB);
    int64_t exp0 = sm_lookup(s, "w")->lease_expiry;

    sm_begin_block(s, 12, 1600, RATE_DAYS);              // SELL @ 20000, window 50000
    SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell(20000, 50000, "w"), 0); sm_apply_tx(s, &ts);
    const SmNameRow *r = sm_lookup(s, "w");
    CHECK(r->st == SM_LISTED && r->price == 20000 && r->offer_expiry == 1600 + 50000 &&
          memcmp(r->seller, A, 20) == 0, "SELL lists at fixed price");

    sm_begin_block(s, 13, 1700, RATE_DAYS);              // RESERVE by B: legs 100/100
    SmTx tr = {0}; tx1(&tr, 0xBB, 0); add_action(&tr, nameact(SM_OP_RESERVE, "w"), 100);
    add_out(&tr, A, SM_P2PKH, 100); sm_apply_tx(s, &tr);
    r = sm_lookup(s, "w");
    CHECK(r->st == SM_RESERVED && memcmp(r->buyer, B, 20) == 0 && r->reserve_expiry == 1700 + 18000,
          "RESERVE wins the option; reserve_expiry = now + RESERVE_WINDOW");

    sm_begin_block(s, 14, 1800, RATE_DAYS);              // SETTLE: remainder 19800
    SmTx tt = {0}; tx1(&tt, 0xBB, 0); add_action(&tt, nameact(SM_OP_SETTLE, "w"), 0);
    add_out(&tt, A, SM_P2PKH, 19800); sm_apply_tx(s, &tt);
    r = sm_lookup(s, "w");
    CHECK(r->st == SM_OWNED && memcmp(r->owner, B, 20) == 0 && r->lease_expiry == exp0,
          "SETTLE → B owns, lease conveys (buyer outlay 100+100+19800 = price)");
    CHECK(sm_last_mutation(s, A) == 14 && sm_last_mutation(s, B) == 14, "SETTLE bumps both parties");
    sm_free(s);
}

static void test_market_reserve_guards(void) {
    SmState *s = minted(0xAA, "w", 300, 1500); uint8_t A[20], B[20]; mk_h160(A, 0xAA); mk_h160(B, 0xBB);
    sm_begin_block(s, 12, 1600, RATE_DAYS);
    SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell(20000, 50000, "w"), 0); sm_apply_tx(s, &ts);
    sm_begin_block(s, 13, 1700, RATE_DAYS);

    SmTx r1 = {0}; tx1(&r1, 0xBB, 0); add_action(&r1, nameact(SM_OP_RESERVE, "w"), 99);   // burn short
    add_out(&r1, A, SM_P2PKH, 100); sm_apply_tx(s, &r1);
    CHECK(sm_lookup(s, "w")->st == SM_LISTED, "RESERVE burn-leg short → stays listed");

    SmTx r2 = {0}; tx1(&r2, 0xBB, 0); add_action(&r2, nameact(SM_OP_RESERVE, "w"), 100); sm_apply_tx(s, &r2); // no pay-leg
    CHECK(sm_lookup(s, "w")->st == SM_LISTED, "RESERVE pay-leg missing → stays listed");

    SmTx r3 = {0}; tx1(&r3, 0xBB, 0); add_action(&r3, nameact(SM_OP_RESERVE, "w"), 100);  // summed, not single
    add_out(&r3, A, SM_P2PKH, 60); add_out(&r3, A, SM_P2PKH, 60); sm_apply_tx(s, &r3);
    CHECK(sm_lookup(s, "w")->st == SM_LISTED, "RESERVE pay-leg not summed");

    SmTx r4 = {0}; tx1(&r4, 0xBB, 0); add_action(&r4, nameact(SM_OP_RESERVE, "w"), 100);  // valid
    add_out(&r4, A, SM_P2PKH, 100); sm_apply_tx(s, &r4);
    CHECK(sm_lookup(s, "w")->st == SM_RESERVED, "RESERVE both legs → reserved");

    SmTx r5 = {0}; tx1(&r5, 0xCC, 0); add_action(&r5, nameact(SM_OP_RESERVE, "w"), 100);  // already reserved
    add_out(&r5, A, SM_P2PKH, 100); sm_apply_tx(s, &r5);
    CHECK(memcmp(sm_lookup(s, "w")->buyer, B, 20) == 0, "second RESERVE loses the option (first-in-order)");
    sm_free(s);
}

static void test_market_sell_guards(void) {
    SmState *s = minted(0xAA, "w", 300, 1500);
    sm_begin_block(s, 12, 1600, RATE_DAYS);
    SmTx t1 = {0}; tx1(&t1, 0xAA, 0); add_action(&t1, sell(2, 0, "w"), 0); sm_apply_tx(s, &t1);
    CHECK(sm_lookup(s, "w")->st == SM_OWNED, "SELL below price floor (3·DUST) ignored");
    SmTx t2 = {0}; tx1(&t2, 0xAA, 0); add_action(&t2, sell(20000, 17999, "w"), 0); sm_apply_tx(s, &t2);
    CHECK(sm_lookup(s, "w")->st == SM_OWNED, "SELL window below RESERVE_WINDOW ignored");
    sm_free(s);

    // short lease tail: near expiry the default window no longer fits (add-form bound).
    s = minted(0xAA, "w", 1, 1500);                      // expiry 1500 + 86400 = 87900
    sm_begin_block(s, 12, 65000, RATE_DAYS);             // 65000 + 18000 + 7200 = 90200 > 87900
    SmTx t3 = {0}; tx1(&t3, 0xAA, 0); add_action(&t3, sell(20000, 0, "w"), 0); sm_apply_tx(s, &t3);
    CHECK(sm_lookup(s, "w")->st == SM_OWNED, "SELL with too-short lease tail ignored (add-form)");
    sm_free(s);
}

static void test_market_directed(void) {
    SmState *s = minted(0xAA, "w", 300, 1500);
    uint8_t A[20], B[20]; mk_h160(A, 0xAA); mk_h160(B, 0xBB);
    int64_t exp0 = sm_lookup(s, "w")->lease_expiry;

    sm_begin_block(s, 12, 1600, RATE_DAYS);
    SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell_to(5000, B, "w"), 0); sm_apply_tx(s, &ts);
    const SmNameRow *r = sm_lookup(s, "w");
    CHECK(r->st == SM_OFFERED && memcmp(r->buyer, B, 20) == 0 && r->price == 5000 &&
          r->offer_expiry == 1600 + SM_DIRECT_WINDOW, "SELL_TO offers to the named buyer");

    sm_begin_block(s, 13, 1700, RATE_DAYS);
    SmTx tc = {0}; tx1(&tc, 0xCC, 0); add_action(&tc, nameact(SM_OP_PAY, "w"), 0);     // stranger
    add_out(&tc, A, SM_P2PKH, 5000); sm_apply_tx(s, &tc);
    CHECK(sm_lookup(s, "w")->st == SM_OFFERED, "PAY by a stranger drops (directed exclusivity)");

    SmTx tb = {0}; tx1(&tb, 0xBB, 0); add_action(&tb, nameact(SM_OP_PAY, "w"), 0);     // named buyer
    add_out(&tb, A, SM_P2PKH, 5000); sm_apply_tx(s, &tb);
    r = sm_lookup(s, "w");
    CHECK(r->st == SM_OWNED && memcmp(r->owner, B, 20) == 0 && r->lease_expiry == exp0,
          "PAY by the named buyer → B owns, lease conveys");
    CHECK(sm_last_mutation(s, A) == 13 && sm_last_mutation(s, B) == 13, "PAY bumps both parties");
    sm_free(s);
}

// A two-input tx; both inputs sign SIGHASH_ALL unless overridden.
static void tx2(SmTx *t, uint8_t s0, uint8_t s1, uint32_t txindex) {
    sm_tx_free(t); memset(t, 0, sizeof *t); t->txindex = txindex;
    *sm_tx_input(t) = id_of(s0); t->in_sighash_all[0] = 1;
    *sm_tx_input(t) = id_of(s1); t->in_sighash_all[1] = 1;
}
static SmAction as_to(uint8_t index) {
    SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_AS; a.as_index = index; return a;
}
static SmAction trade(uint8_t ia, uint8_t ib, const char *na, const char *nb) {
    SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_TRADE; a.idx_a = ia; a.idx_b = ib;
    snprintf(a.name,   sizeof a.name,   "%s", na); a.name_len   = (uint8_t)strlen(na);
    snprintf(a.name_b, sizeof a.name_b, "%s", nb); a.name_b_len = (uint8_t)strlen(nb);
    return a;
}

static void test_as(void) {
    SmState *s = sm_new(0);
    uint8_t B[20]; mk_h160(B, 0xBB);
    sm_begin_block(s, 10, 1000, RATE_DAYS);
    SmTx c = {0}; tx1(&c, 0xBB, 0); add_action(&c, mk_commit("bob", B, 0x55), 0); sm_apply_tx(s, &c);

    // Inputs [A, B]; AS 1 attributes the CLAIM to B, matching B's commitment.
    sm_begin_block(s, 11, 1500, RATE_DAYS);
    SmTx t = {0}; tx2(&t, 0xAA, 0xBB, 0);
    add_action(&t, as_to(1), 0);
    add_action(&t, mk_claim("bob", 0x55), 10);
    sm_apply_tx(s, &t);
    CHECK(sm_owns(s, B, "bob"), "AS re-points CLAIM attribution to vin[1]");
    sm_free(s);

    // AS to an input that does NOT sign SIGHASH_ALL → segment drops.
    s = sm_new(0); mk_h160(B, 0xBB);
    sm_begin_block(s, 10, 1000, RATE_DAYS);
    SmTx c2 = {0}; tx1(&c2, 0xBB, 0); add_action(&c2, mk_commit("bob", B, 0x55), 0); sm_apply_tx(s, &c2);
    sm_begin_block(s, 11, 1500, RATE_DAYS);
    SmTx t2 = {0}; tx2(&t2, 0xAA, 0xBB, 0); t2.in_sighash_all[1] = 0;     // B did not sign SIGHASH_ALL
    add_action(&t2, as_to(1), 0);
    add_action(&t2, mk_claim("bob", 0x55), 10);
    sm_apply_tx(s, &t2);
    CHECK(!sm_owns(s, B, "bob") && sm_lookup(s, "bob") == NULL, "AS to non-SIGHASH_ALL input drops the segment");
    sm_free(s);
}

// Mint `na`→A and `nb`→B, leaving the fold at height 11.
static SmState *two_names(void) {
    SmState *s = sm_new(0);
    uint8_t A[20], B[20]; mk_h160(A, 0xAA); mk_h160(B, 0xBB);
    sm_begin_block(s, 10, 1000, RATE_DAYS);
    SmTx ca = {0}; tx1(&ca, 0xAA, 0); add_action(&ca, mk_commit("aaa", A, 0x01), 0); sm_apply_tx(s, &ca);
    SmTx cb = {0}; tx1(&cb, 0xBB, 1); add_action(&cb, mk_commit("bbb", B, 0x02), 0); sm_apply_tx(s, &cb);
    sm_begin_block(s, 11, 1500, RATE_DAYS);
    SmTx ka = {0}; tx1(&ka, 0xAA, 0); add_action(&ka, mk_claim("aaa", 0x01), 30); sm_apply_tx(s, &ka);
    SmTx kb = {0}; tx1(&kb, 0xBB, 1); add_action(&kb, mk_claim("bbb", 0x02), 30); sm_apply_tx(s, &kb);
    return s;
}

static void test_trade(void) {
    uint8_t A[20], B[20], C[20]; mk_h160(A, 0xAA); mk_h160(B, 0xBB); mk_h160(C, 0xCC);

    // happy path: aaa ↔ bbb.
    SmState *s = two_names();
    CHECK(sm_owns(s, A, "aaa") && sm_owns(s, B, "bbb"), "setup: A owns aaa, B owns bbb");
    sm_begin_block(s, 12, 1600, RATE_DAYS);
    SmTx t = {0}; tx2(&t, 0xAA, 0xBB, 0); add_action(&t, trade(0, 1, "aaa", "bbb"), 0); sm_apply_tx(s, &t);
    CHECK(sm_owns(s, B, "aaa") && sm_owns(s, A, "bbb"), "TRADE swaps aaa↔bbb atomically");
    CHECK(sm_last_mutation(s, A) == 12 && sm_last_mutation(s, B) == 12, "TRADE bumps both parties");
    sm_free(s);

    // anti-rug: A moves aaa away earlier in the same block → TRADE drops in full.
    s = two_names();
    sm_begin_block(s, 12, 1600, RATE_DAYS);
    SmTx mv = {0}; tx1(&mv, 0xAA, 0); add_action(&mv, xfer_all(C), 0); sm_apply_tx(s, &mv);   // aaa → C
    SmTx t2 = {0}; tx2(&t2, 0xAA, 0xBB, 1); add_action(&t2, trade(0, 1, "aaa", "bbb"), 0); sm_apply_tx(s, &t2);
    CHECK(sm_owns(s, C, "aaa") && sm_owns(s, B, "bbb"),
          "TRADE drops when a pledged name moved same-block (anti-rug); counterparties keep theirs");
    sm_free(s);
}

// charset + structural rules (§3.1): [a-z0-9-], 1..32; no leading/trailing hyphen;
// no `--` at positions 3–4. Pins the OUTCOME behind scenario 52.
static void test_dotted_names(void) {
    uint8_t A[20]; mk_h160(A, 0xAA);
    CHECK(sm_name_valid("shib-p2p", 8), "hyphen name valid");
    CHECK(sm_name_valid("abcdefghijklmnopqrstuvwxyz0123ab", 32), "32-byte name valid");
    CHECK(!sm_name_valid("abcdefghijklmnopqrstuvwxyz0123abc", 33), "33-byte name invalid (max 32)");
    CHECK(!sm_name_valid("shib.p2p", 8), "dot now invalid");
    CHECK(!sm_name_valid("shib_p2p", 8), "underscore now invalid");
    CHECK(!sm_name_valid("Shib-p2p", 8), "uppercase still invalid");
    CHECK(!sm_name_valid("a,b", 3), "comma still invalid (TRADE pair split relies on it)");
    CHECK(!sm_name_valid("-a", 2), "leading hyphen invalid");
    CHECK(!sm_name_valid("a-", 2), "trailing hyphen invalid");
    CHECK(!sm_name_valid("xn--x", 5), "ACE prefix (xn--) invalid");
    SmState *s = sm_new(0);
    sm_begin_block(s, 10, 1000, RATE_DAYS);
    { SmTx c = {0}; tx1(&c, 0xAA, 0); add_action(&c, mk_commit("shib-p2p", A, 0x71), 0); sm_apply_tx(s, &c); }
    { SmTx c = {0}; tx1(&c, 0xAA, 1); add_action(&c, mk_commit("shib.p2p", A, 0x74), 0); sm_apply_tx(s, &c); }
    sm_begin_block(s, 11, 1500, RATE_DAYS);
    { SmTx k = {0}; tx1(&k, 0xAA, 0); add_action(&k, mk_claim("shib-p2p", 0x71), 10); sm_apply_tx(s, &k); }
    { SmTx k = {0}; tx1(&k, 0xAA, 1); add_action(&k, mk_claim("shib.p2p", 0x74), 10); sm_apply_tx(s, &k); }
    CHECK(sm_owns(s, A, "shib-p2p"), "hyphen claim mints");
    CHECK(sm_find_name(s, "shib.p2p") == NULL && s->n_names == 1, "dotted claim drops");
    sm_free(s);
}

// Outcome lock for vector 54: no per-tx count cap — 17 COMMIT carriers fold.
static void test_tx_bounds(void) {
    { SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, RATE_DAYS);
      SmTx t = {0}; tx1(&t, 0xAA, 0);
      for (int i = 0; i < 17; i++) {
          SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_COMMIT; a.commitment[0] = (uint8_t)i;
          add_action(&t, a, 0);
      }
      CHECK(t.n_carriers == 17 && t.carriers != t.car_inline, "SmTx folds 17 carriers (spilled past inline, no cap)");
      sm_apply_tx(s, &t);
      CHECK(s->n_commits == 17, "17 COMMITs all record");
      sm_tx_free(&t); sm_free(s); }
}

// ── §9 wire-codec round-trip + demux/drop tests ──────────────────────────────
// enc(a) → decode → enc again must reproduce the bytes (the codec is a bijection
// on well-formed actions); the demux/drop cases pin the fail-closed parse.
// The historical suite is the PepeNet prefix. DogeNet is the same bijection
// under a different magic (test_magic_profiles).
static const uint8_t MAG_PN[2] = { 0x50, 0x4E };
static const uint8_t MAG_DN[2] = { 0x44, 0x4E };
static int codec_rt_m(const SmAction *a, const uint8_t mag[2]) {
    static uint8_t b1[SM_CARRIER_MAX]; size_t l1 = sm_encode_action(a, mag, b1);
    if (l1 == 0) return 0;
    if (b1[0] != 0xFF || b1[1] != mag[0] || b1[2] != mag[1]) return 0;
    static SmCarrier c; sm_decode_payload(b1, l1, 0, mag, &c);
    if (c.kind != SM_CAR_ACTION) return 0;
    static uint8_t b2[SM_CARRIER_MAX]; size_t l2 = sm_encode_action(&c.act, mag, b2);
    return l2 == l1 && memcmp(b1, b2, l1) == 0;
}
static int codec_rt(const SmAction *a) { return codec_rt_m(a, MAG_PN); }
static void test_codec(void) {
    uint8_t A[20], B[20]; mk_h160(A, 0xAA); mk_h160(B, 0xBB);
    SmAction a;
    a = mk_commit("bob", A, 0x11);     CHECK(codec_rt(&a), "codec round-trip COMMIT");
    a = mk_claim("bob", 0x11);         CHECK(codec_rt(&a), "codec round-trip CLAIM");
    a = mk_claim("abcdefghijklmnopqrstuvwxyz0123ab", 0x11); CHECK(codec_rt(&a), "codec round-trip CLAIM name32 (encoder 1..32)");
    a = renew_all();                   CHECK(codec_rt(&a), "codec round-trip RENEW-all");
    { SmAction r; memset(&r, 0, sizeof r); r.op = SM_OP_RENEW; r.has_anchor = 1; r.anchor = 0x0102030405ULL;
      CHECK(codec_rt(&r), "codec round-trip RENEW-all-safe");
      r.flags[0] = 0x05; r.flags[1] = 0x80; r.flags_len = 2; CHECK(codec_rt(&r), "codec round-trip RENEW-selective"); }
    a = xfer_all(B);                   CHECK(codec_rt(&a), "codec round-trip TRANSFER-all");
    { SmAction t = xfer_all(B); t.has_anchor = 1; t.anchor = 99; t.flags[0] = 0x03; t.flags_len = 1;
      CHECK(codec_rt(&t), "codec round-trip TRANSFER-selective"); }
    a = sell(20000, 50000, "wname");   CHECK(codec_rt(&a), "codec round-trip SELL");
    a = nameact(SM_OP_RESERVE, "wname"); CHECK(codec_rt(&a), "codec round-trip RESERVE");
    a = nameact(SM_OP_SETTLE, "wname");  CHECK(codec_rt(&a), "codec round-trip SETTLE");
    a = nameact(SM_OP_PAY, "wname");     CHECK(codec_rt(&a), "codec round-trip PAY");
    { uint8_t f[2] = { 0x01, 0x40 }; SmAction r = release_bits(12, f, 2); CHECK(codec_rt(&r), "codec round-trip RELEASE"); }
    a = sell_to(5000, B, "wname");     CHECK(codec_rt(&a), "codec round-trip SELL_TO");
    a = as_to(3);                      CHECK(codec_rt(&a), "codec round-trip AS");
    a = trade(0, 1, "aaa", "bbb");     CHECK(codec_rt(&a), "codec round-trip TRADE");

    // §6 pinned carrier ceiling: flags at the exact consensus caps
    // round-trip; one byte past fails BOTH directions (fail-closed codec).
    { SmAction r; memset(&r, 0, sizeof r); r.op = SM_OP_RENEW; r.has_anchor = 1; r.anchor = 7;
      r.flags_len = SM_FLAGS_MAX;
      for (int i = 0; i < SM_FLAGS_MAX; i++) r.flags[i] = (uint8_t)(i * 7 + 1);
      CHECK(codec_rt(&r), "codec round-trip RENEW-selective at SM_FLAGS_MAX (9987 flag bytes)");
      static uint8_t w[SM_CARRIER_MAX + 8]; size_t l = sm_encode_action(&r, MAG_PN, w);
      CHECK(l == (size_t)SM_CARRIER_MAX, "RENEW at cap encodes to exactly SM_CARRIER_MAX (9996) bytes");
      SmCarrier cw; sm_decode_payload(w, l, 0, MAG_PN, &cw);
      CHECK(cw.kind == SM_CAR_ACTION && cw.act.flags_len == SM_FLAGS_MAX,
            "...and decodes with every flag byte intact");
      w[l] = 0x00; sm_decode_payload(w, l + 1, 0, MAG_PN, &cw);
      CHECK(cw.kind == SM_CAR_IGNORE, "one byte past the L1 carrier ceiling -> ignore"); }
    { SmAction t; memset(&t, 0, sizeof t); t.op = SM_OP_TRANSFER; mk_h160(t.addr, 0xBB);
      t.has_anchor = 1; t.anchor = 7;
      t.flags_len = SM_FLAGS_XFER_MAX;
      for (int i = 0; i < SM_FLAGS_XFER_MAX; i++) t.flags[i] = (uint8_t)(i + 1);
      CHECK(codec_rt(&t), "codec round-trip TRANSFER-selective at SM_FLAGS_XFER_MAX (9967)");
      static uint8_t w2[SM_CARRIER_MAX + 8];
      t.flags_len = SM_FLAGS_XFER_MAX + 1;
      CHECK(sm_encode_action(&t, MAG_PN, w2) == 0, "TRANSFER flags past the cap refuse to encode"); }
    { SmAction r; memset(&r, 0, sizeof r); r.op = SM_OP_RELEASE; r.has_anchor = 1; r.anchor = 3;
      r.flags_len = SM_FLAGS_MAX;
      for (int i = 0; i < SM_FLAGS_MAX; i++) r.flags[i] = 0xFF;
      CHECK(codec_rt(&r), "codec round-trip RELEASE at SM_FLAGS_MAX"); }

    // demux: non-prefix / overlay / bare UTF-8 → IGNORE; only name actions → ACTION.
    SmCarrier c;
    const uint8_t hello[5] = { 'h','e','l','l','o' };
    sm_decode_payload(hello, 5, 1, MAG_PN, &c); CHECK(c.kind == SM_CAR_IGNORE, "demux bare UTF-8 → ignore");
    const uint8_t ff[1] = { 0xFF };
    sm_decode_payload(ff, 1, 1, MAG_PN, &c);    CHECK(c.kind == SM_CAR_IGNORE, "demux lone 0xFF → ignore");
    { uint8_t ov[5] = { 0xFF, 0x50, 0x4E, 0xD6, 0x00 };
      sm_decode_payload(ov, 5, 0, MAG_PN, &c);  CHECK(c.kind == SM_CAR_IGNORE, "demux overlay opcode → ignore"); }

    // fail-closed action parse: truncated / wrong-length / bad-name / bad-opcode → IGNORE.
    { static uint8_t b[SM_CARRIER_MAX]; a = mk_claim("bob", 0x11); size_t l = sm_encode_action(&a, MAG_PN, b);
      sm_decode_payload(b, 36, 0, MAG_PN, &c);    CHECK(c.kind == SM_CAR_IGNORE, "parse CLAIM with no name (salt only) → ignore");
      sm_decode_payload(b, l, 0, MAG_PN, &c);     CHECK(c.kind == SM_CAR_ACTION && c.act.op == SM_OP_CLAIM, "parse exact CLAIM → action"); }
    { static uint8_t b[SM_CARRIER_MAX]; a = mk_commit("bob", A, 0x11); size_t l = sm_encode_action(&a, MAG_PN, b);
      sm_decode_payload(b, l - 1, 0, MAG_PN, &c); CHECK(c.kind == SM_CAR_IGNORE, "parse short COMMIT → ignore"); }
    { uint8_t b[5] = { 0xFF, 0x50, 0x4E, SM_OP_RESERVE, ',' };       // comma is not a name char
      sm_decode_payload(b, 5, 0, MAG_PN, &c);     CHECK(c.kind == SM_CAR_IGNORE, "parse RESERVE bad-name → ignore"); }
    { uint8_t b[4] = { 0xFF, 0x50, 0x4E, 0x00 };
      sm_decode_payload(b, 4, 1, MAG_PN, &c);     CHECK(c.kind == SM_CAR_IGNORE, "parse opcode 0x00 → ignore"); }
    { uint8_t b[4] = { 0xFF, 0x50, 0x4E, 0x10 };
      sm_decode_payload(b, 4, 1, MAG_PN, &c);     CHECK(c.kind == SM_CAR_IGNORE, "parse opcode 0x10 (>0x0F) → ignore"); }
    { uint8_t b[9] = { 0xFF, 0x50, 0x4E, SM_OP_TRADE, 0, 1, 'a', 'b', 'c' };   // no comma
      sm_decode_payload(b, 9, 0, MAG_PN, &c);     CHECK(c.kind == SM_CAR_IGNORE, "parse TRADE no-comma → ignore"); }
    { uint8_t b[10] = { 0xFF, 0x50, 0x4E, SM_OP_TRADE, 0, 1, 'a', ',', 'b', ',' }; // two commas → wait that's a,(b,)
      // construct a clean double-comma: a,,b
      uint8_t d[10] = { 0xFF, 0x50, 0x4E, SM_OP_TRADE, 0, 1, 'a', ',', ',', 'b' };
      sm_decode_payload(d, 10, 0, MAG_PN, &c);    CHECK(c.kind == SM_CAR_IGNORE, "parse TRADE double-comma → ignore"); (void)b; }
    { uint8_t b[5] = { 0xFF, 0x50, 0x4E, SM_OP_AS, 2 };
      sm_decode_payload(b, 5, 0, MAG_PN, &c);     CHECK(c.kind == SM_CAR_ACTION && c.act.op == SM_OP_AS && c.act.as_index == 2, "parse AS exact → action"); }
    { uint8_t b[6] = { 0xFF, 0x50, 0x4E, SM_OP_AS, 2, 0 };
      sm_decode_payload(b, 6, 0, MAG_PN, &c);     CHECK(c.kind == SM_CAR_IGNORE, "parse AS over-length → ignore"); }
}

// Every digested field MUST affect the digest (catch an accidental omission), and
// owner_type — deliberately NOT digested — MUST NOT. White-box: build a state with
// every field type populated, perturb each, assert the digest moves (or, for
// owner_type, stays). Guards the canonical digest against silent drift.
static void test_digest_sensitivity(void) {
    SmState *s = sm_new(0);
    SmNameRow *R = sm_add_name(s, "x", 1);           // a RESERVED row exercises every market field
    R->owner[0] = 0xA1; R->owner_type = SM_P2SH; R->st = SM_RESERVED; R->lease_expiry = 1000;
    R->seller[0] = 0xB2; R->seller_type = 1; R->price = 500; R->offer_expiry = 900;
    R->buyer[0] = 0xC3; R->burn_leg = 2; R->pay_leg = 3; R->reserve_expiry = 800;
    uint8_t cm[32]; memset(cm, 0x11, 32); sm_commit_add(s, cm, 7, 2, 1234);
    uint8_t mo[20]; memset(mo, 0x33, 20); sm_bump_mutation(s, mo, 99);

    uint8_t base[32]; sm_state_digest(s, base);
    R = sm_find_name(s, "x");
    #define SENS(stmt, undo, label) do { stmt; uint8_t d[32]; sm_state_digest(s, d); \
        CHECK(memcmp(d, base, 32) != 0, "digest-sensitive: " label); undo; } while (0)

    SENS(R->name[0] = 'y',      R->name[0] = 'x',      "name");
    SENS(R->owner[0] ^= 1,      R->owner[0] ^= 1,      "owner");
    SENS(R->st = SM_LISTED,     R->st = SM_RESERVED,   "state");
    SENS(R->lease_expiry++,     R->lease_expiry--,     "lease_expiry");
    SENS(R->seller[0] ^= 1,     R->seller[0] ^= 1,     "seller");
    SENS(R->seller_type ^= 1,   R->seller_type ^= 1,   "seller_type");
    SENS(R->price++,            R->price--,            "price");
    SENS(R->offer_expiry++,     R->offer_expiry--,     "offer_expiry");
    SENS(R->buyer[0] ^= 1,      R->buyer[0] ^= 1,      "buyer");
    SENS(R->burn_leg++,         R->burn_leg--,         "burn_leg");
    SENS(R->pay_leg++,          R->pay_leg--,          "pay_leg");
    SENS(R->reserve_expiry++,   R->reserve_expiry--,   "reserve_expiry");
    SENS(s->commits[0].commitment[0] ^= 1, s->commits[0].commitment[0] ^= 1, "commitment");
    SENS(s->commits[0].commit_height++,    s->commits[0].commit_height--,    "commit_height");
    SENS(s->commits[0].tx_index++,         s->commits[0].tx_index--,         "commit_tx_index");
    SENS(s->commits[0].commit_time++,      s->commits[0].commit_time--,      "commit_time");
    SENS(s->muts[0].owner[0] ^= 1,         s->muts[0].owner[0] ^= 1,         "mut_owner");
    SENS(s->muts[0].height++,              s->muts[0].height--,              "mut_height");
    #undef SENS

    // negative: owner_type is deliberately NOT digested (ownership is by bare hash160).
    R->owner_type ^= 1; uint8_t d[32]; sm_state_digest(s, d);
    CHECK(memcmp(d, base, 32) == 0, "digest IGNORES owner_type (by design)"); R->owner_type ^= 1;
    sm_free(s);
}

// Behavioral assertions for the pre-block / intra-block market-race vectors (38–41):
// the scenario digests only prove cross-language *agreement*; these pin the OUTCOME so
// a deterministic-but-wrong construction can't slip through (cf. the "passing for the
// right reason" bar). Each mirrors its scenario vector above.
static void test_scenario_races(void) {
    uint8_t A[20], B[20], C[20]; mk_h160(A, 0xAA); mk_h160(B, 0xBB); mk_h160(C, 0xCC);

    // 38: pre-block lapse runs before txs → old owner's RENEW skips bob; hunter wins.
    { SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, RATE_DAYS);
      SmTx cbob = {0}; tx1(&cbob, 0xAA, 0); add_action(&cbob, mk_commit("bob",  A, 0x33), 0); sm_apply_tx(s, &cbob);
      SmTx ckep = {0}; tx1(&ckep, 0xAA, 1); add_action(&ckep, mk_commit("keep", A, 0x34), 0); sm_apply_tx(s, &ckep);
      sm_begin_block(s, 11, 1500, RATE_DAYS);
      SmTx kbob = {0}; tx1(&kbob, 0xAA, 0); add_action(&kbob, mk_claim("bob",  0x33), 10);  sm_apply_tx(s, &kbob);
      SmTx kkep = {0}; tx1(&kkep, 0xAA, 1); add_action(&kkep, mk_claim("keep", 0x34), 300); sm_apply_tx(s, &kkep);
      int64_t keep0 = sm_lookup(s, "keep")->lease_expiry;
      sm_begin_block(s, 12, 860000, RATE_DAYS);
      SmTx cb = {0}; tx1(&cb, 0xBB, 0); add_action(&cb, mk_commit("bob", B, 0x44), 0); sm_apply_tx(s, &cb);
      sm_begin_block(s, 13, 865500, RATE_DAYS);
      SmTx ra = {0}; tx1(&ra, 0xAA, 0); add_action(&ra, renew_all(), 5); sm_apply_tx(s, &ra);
      SmTx kb = {0}; tx1(&kb, 0xBB, 1); add_action(&kb, mk_claim("bob", 0x44), 10); sm_apply_tx(s, &kb);
      CHECK(sm_owns(s, B, "bob"),  "38: hunter B mints the lapsed name");
      CHECK(!sm_owns(s, A, "bob"), "38: old owner A does not keep the lapsed name");
      CHECK(sm_owns(s, A, "keep"), "38: A still owns the surviving name");
      CHECK(sm_lookup(s, "keep")->lease_expiry == keep0 + 5*86400, "38: RENEW extended only the surviving name");
      sm_free(s); }

    // 39: one tick crosses reserve_expiry then offer_expiry → back to seller, plain owned.
    { SmState *s = minted(0xAA, "w", 300, 1500);
      sm_begin_block(s, 12, 1600, RATE_DAYS); SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell(20000, 50000, "w"), 0); sm_apply_tx(s, &ts);
      sm_begin_block(s, 13, 1700, RATE_DAYS); SmTx tr = {0}; tx1(&tr, 0xBB, 0); add_action(&tr, nameact(SM_OP_RESERVE, "w"), 100); add_out(&tr, A, SM_P2PKH, 100); sm_apply_tx(s, &tr);
      sm_begin_block(s, 14, 51600, RATE_DAYS);
      const SmNameRow *r = sm_lookup(s, "w");
      CHECK(r && r->st == SM_OWNED && sm_owns(s, A, "w"), "39: both legs fire in one tick → back to seller");
      CHECK(r && r->price == 0 && r->offer_expiry == 0 && r->reserve_expiry == 0, "39: market fields cleared (no orphan)");
      sm_free(s); }

    // 40: first reserve wins the exclusive option; the loser's reserve + settle both drop.
    { SmState *s = minted(0xAA, "w", 300, 1500);
      sm_begin_block(s, 12, 1600, RATE_DAYS); SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell(20000, 50000, "w"), 0); sm_apply_tx(s, &ts);
      sm_begin_block(s, 13, 1700, RATE_DAYS);
      SmTx r0 = {0}; tx1(&r0, 0xBB, 0); add_action(&r0, nameact(SM_OP_RESERVE, "w"), 100); add_out(&r0, A, SM_P2PKH, 100); sm_apply_tx(s, &r0);
      SmTx r1 = {0}; tx1(&r1, 0xCC, 1); add_action(&r1, nameact(SM_OP_RESERVE, "w"), 100); add_out(&r1, A, SM_P2PKH, 100); sm_apply_tx(s, &r1);
      SmTx st = {0}; tx1(&st, 0xCC, 2); add_action(&st, nameact(SM_OP_SETTLE, "w"), 0);    add_out(&st, A, SM_P2PKH, 19800); sm_apply_tx(s, &st);
      const SmNameRow *r = sm_lookup(s, "w");
      CHECK(r && r->st == SM_RESERVED && memcmp(r->buyer, B, 20) == 0, "40: first reserver B holds the option");
      CHECK(!sm_owns(s, C, "w"), "40: loser C's settle does not take the name");
      sm_free(s); }

    // 41: consume-once, exact-value, vout-order matching across two ops in one tx.
    { SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, RATE_DAYS);
      SmTx cxn = {0}; tx1(&cxn, 0xAA, 0); add_action(&cxn, mk_commit("x", A, 0x71), 0); sm_apply_tx(s, &cxn);
      SmTx cyn = {0}; tx1(&cyn, 0xAA, 1); add_action(&cyn, mk_commit("y", A, 0x72), 0); sm_apply_tx(s, &cyn);
      sm_begin_block(s, 11, 1500, RATE_DAYS);
      SmTx kxn = {0}; tx1(&kxn, 0xAA, 0); add_action(&kxn, mk_claim("x", 0x71), 300); sm_apply_tx(s, &kxn);
      SmTx kyn = {0}; tx1(&kyn, 0xAA, 1); add_action(&kyn, mk_claim("y", 0x72), 300); sm_apply_tx(s, &kyn);
      sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx sx = {0}; tx1(&sx, 0xAA, 0); add_action(&sx, sell(1000,  50000, "x"), 0); sm_apply_tx(s, &sx);
      SmTx sy = {0}; tx1(&sy, 0xAA, 1); add_action(&sy, sell(20000, 50000, "y"), 0); sm_apply_tx(s, &sy);
      sm_begin_block(s, 13, 1700, RATE_DAYS);
      SmTx ry = {0}; tx1(&ry, 0xBB, 0); add_action(&ry, nameact(SM_OP_RESERVE, "y"), 100); add_out(&ry, A, SM_P2PKH, 100); sm_apply_tx(s, &ry);
      sm_begin_block(s, 14, 1800, RATE_DAYS);
      SmTx col = {0}; tx1(&col, 0xBB, 0);
      add_action(&col, nameact(SM_OP_RESERVE, "x"), 5);
      add_action(&col, nameact(SM_OP_SETTLE,  "y"), 0);
      add_out(&col, A, SM_P2PKH, 19800);
      add_out(&col, A, SM_P2PKH, 5);
      sm_apply_tx(s, &col);
      CHECK(sm_owns(s, B, "y"), "41: SETTLE consumed vout[0] → B owns y");
      const SmNameRow *rx = sm_lookup(s, "x");
      CHECK(rx && rx->st == SM_RESERVED && memcmp(rx->buyer, B, 20) == 0, "41: RESERVE skipped vout[0], took vout[1] → x reserved to B");
      sm_free(s); }
}

// Behavioral assertions for the audit-follow-up vectors (42–48).
static void test_scenario_races2(void) {
    uint8_t A[20], B[20]; mk_h160(A, 0xAA); mk_h160(B, 0xBB);

    // 42: lower COMMIT tx_index wins the same-block claim contest in BOTH claim orderings.
    for (int order = 0; order < 2; order++) {
        SmState *s = sm_new(0);
        sm_begin_block(s, 10, 1000, RATE_DAYS);
        SmTx cA = {0}; tx1(&cA, 0xAA, 5); add_action(&cA, mk_commit("bob", A, 0x81), 0); sm_apply_tx(s, &cA);
        SmTx cB = {0}; tx1(&cB, 0xBB, 2); add_action(&cB, mk_commit("bob", B, 0x82), 0); sm_apply_tx(s, &cB);  // B's commit tx_index 2 < 5
        sm_begin_block(s, 20, 1500, RATE_DAYS);
        SmTx kA = {0}; tx1(&kA, 0xAA, order == 0 ? 0 : 1); add_action(&kA, mk_claim("bob", 0x81), 10);
        SmTx kB = {0}; tx1(&kB, 0xBB, order == 0 ? 1 : 0); add_action(&kB, mk_claim("bob", 0x82), 10);
        if (order == 0) { sm_apply_tx(s, &kA); sm_apply_tx(s, &kB); }   // A's claim first
        else            { sm_apply_tx(s, &kB); sm_apply_tx(s, &kA); }   // B's claim first
        CHECK(sm_owns(s, B, "bob"), "42: lower commit tx_index wins regardless of claim order");
        sm_free(s);
    }

    // 43: a listed name rejects TRANSFER / RELEASE / re-SELL / SELL_TO.
    { SmState *s = minted(0xAA, "w", 300, 1500);
      sm_begin_block(s, 12, 1600, RATE_DAYS); SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell(20000, 50000, "w"), 0); sm_apply_tx(s, &ts);
      sm_begin_block(s, 13, 1700, RATE_DAYS);
      uint8_t f[1] = { 0x01 };
      SmTx mv = {0}; tx1(&mv, 0xAA, 0); add_action(&mv, xfer_all(B), 0);              sm_apply_tx(s, &mv);
      SmTx rl = {0}; tx1(&rl, 0xAA, 1); add_action(&rl, release_bits(11, f, 1), 0);   sm_apply_tx(s, &rl);
      SmTx rs = {0}; tx1(&rs, 0xAA, 2); add_action(&rs, sell(30000, 50000, "w"), 0);  sm_apply_tx(s, &rs);
      SmTx rt = {0}; tx1(&rt, 0xAA, 3); add_action(&rt, sell_to(5000, B, "w"), 0);    sm_apply_tx(s, &rt);
      const SmNameRow *r = sm_lookup(s, "w");
      CHECK(r && r->st == SM_LISTED && memcmp(r->owner, A, 20) == 0 && r->price == 20000, "43: listed name immovable, owner+price unchanged");
      CHECK(r && memcmp(r->owner, B, 20) != 0, "43: no move slipped through to B");
      sm_free(s); }

    // 44: a stale anchor (older than last set-mutation) drops the bitmap op.
    { SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, RATE_DAYS);
      SmTx ca = {0}; tx1(&ca, 0xAA, 0); add_action(&ca, mk_commit("a", A, 0x91), 0); sm_apply_tx(s, &ca);
      sm_begin_block(s, 11, 1500, RATE_DAYS);
      SmTx ka = {0}; tx1(&ka, 0xAA, 0); add_action(&ka, mk_claim("a", 0x91), 30); sm_apply_tx(s, &ka);
      SmTx cb = {0}; tx1(&cb, 0xAA, 1); add_action(&cb, mk_commit("b", A, 0x92), 0); sm_apply_tx(s, &cb);
      sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx kb = {0}; tx1(&kb, 0xAA, 0); add_action(&kb, mk_claim("b", 0x92), 30); sm_apply_tx(s, &kb);
      sm_begin_block(s, 13, 1700, RATE_DAYS);
      uint8_t f[1] = { 0x01 };
      SmTx rl = {0}; tx1(&rl, 0xAA, 0); add_action(&rl, release_bits(11, f, 1), 0); sm_apply_tx(s, &rl);   // anchor 11 < lm 12
      CHECK(sm_owns(s, A, "a") && sm_owns(s, A, "b"), "44: stale-anchor RELEASE rejected (nothing released)");
      sm_free(s); }

    // 45: an expired commit no longer backs a claim.
    { SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, RATE_DAYS); SmTx c = {0}; tx1(&c, 0xAA, 0); add_action(&c, mk_commit("bob", A, 0x33), 0); sm_apply_tx(s, &c);
      sm_begin_block(s, 11, 19001, RATE_DAYS);
      SmTx k = {0}; tx1(&k, 0xAA, 0); add_action(&k, mk_claim("bob", 0x33), 10); sm_apply_tx(s, &k);
      CHECK(sm_lookup(s, "bob") == NULL, "45: claim drops once its commit is COMMIT_EXPIRY-pruned");
      sm_free(s); }

    // 46: an over-funded burn leg still wins the reserve.
    { SmState *s = minted(0xAA, "w", 300, 1500); sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell(20000, 50000, "w"), 0); sm_apply_tx(s, &ts);
      sm_begin_block(s, 13, 1700, RATE_DAYS); SmTx tr = {0}; tx1(&tr, 0xBB, 0); add_action(&tr, nameact(SM_OP_RESERVE, "w"), 150); add_out(&tr, A, SM_P2PKH, 100); sm_apply_tx(s, &tr);
      const SmNameRow *r = sm_lookup(s, "w");
      CHECK(r && r->st == SM_RESERVED && memcmp(r->buyer, B, 20) == 0, "46: over-funded burn (150>100) still reserves");
      sm_free(s); }

    // 47: malformed TRADEs leave the two-name state untouched.
    { SmState *s = two_names();
      sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx t1 = {0}; tx2(&t1, 0xAA, 0xBB, 0); add_action(&t1, trade(0, 5, "aaa", "bbb"), 0); sm_apply_tx(s, &t1);
      SmTx t2 = {0}; tx2(&t2, 0xAA, 0xBB, 1); add_action(&t2, trade(0, 0, "aaa", "bbb"), 0); sm_apply_tx(s, &t2);
      SmTx t3 = {0}; tx2(&t3, 0xAA, 0xBB, 2); add_action(&t3, trade(0, 1, "aaa", "aaa"), 0); sm_apply_tx(s, &t3);
      CHECK(sm_owns(s, A, "aaa") && sm_owns(s, B, "bbb"), "47: OOB / one-party / self-name TRADEs all drop");
      sm_free(s); }

    // 48: selective transfer moves exactly the flagged subset.
    { SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, RATE_DAYS);
      SmTx ca = {0}; tx1(&ca, 0xAA, 0); add_action(&ca, mk_commit("a", A, 0xA1), 0); sm_apply_tx(s, &ca);
      SmTx cb = {0}; tx1(&cb, 0xAA, 1); add_action(&cb, mk_commit("b", A, 0xA2), 0); sm_apply_tx(s, &cb);
      SmTx cc = {0}; tx1(&cc, 0xAA, 2); add_action(&cc, mk_commit("c", A, 0xA3), 0); sm_apply_tx(s, &cc);
      sm_begin_block(s, 11, 1500, RATE_DAYS);
      SmTx ka = {0}; tx1(&ka, 0xAA, 0); add_action(&ka, mk_claim("a", 0xA1), 30); sm_apply_tx(s, &ka);
      SmTx kb = {0}; tx1(&kb, 0xAA, 1); add_action(&kb, mk_claim("b", 0xA2), 30); sm_apply_tx(s, &kb);
      SmTx kc = {0}; tx1(&kc, 0xAA, 2); add_action(&kc, mk_claim("c", 0xA3), 30); sm_apply_tx(s, &kc);
      sm_begin_block(s, 12, 1600, RATE_DAYS);
      uint8_t f[1] = { 0x05 };
      SmTx tv = {0}; tx1(&tv, 0xAA, 0); add_action(&tv, xfer_bits(11, f, 1, B), 0); sm_apply_tx(s, &tv);
      CHECK(sm_owns(s, B, "a") && sm_owns(s, A, "b") && sm_owns(s, B, "c"), "48: selective transfer moves bits {0,2}, keeps b");
      sm_free(s); }
}

// Outcome locks for the 2026-07 divergence fixes (mirror scenarios 55/55b/56/58).
static void test_scenario_races3(void) {
    uint8_t A[20], B[20]; mk_h160(A, 0xAA); mk_h160(B, 0xBB);

    // 55: mint → same-block RELEASE → same-block re-CLAIM re-mints the name to A.
    { SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, RATE_DAYS);
      SmTx tc = {0}; tx1(&tc, 0xAA, 0); add_action(&tc, mk_commit("foo", A, 0x91), 0); sm_apply_tx(s, &tc);
      sm_begin_block(s, 11, 1500, RATE_DAYS);
      SmTx tk = {0}; tx1(&tk, 0xAA, 0); add_action(&tk, mk_claim("foo", 0x91), 10); sm_apply_tx(s, &tk);
      uint8_t rel[1] = { 0x01 };
      SmTx tr = {0}; tx1(&tr, 0xAA, 1); add_action(&tr, release_bits(11, rel, 1), 0); sm_apply_tx(s, &tr);
      CHECK(sm_lookup(s, "foo") == NULL, "55: RELEASE removed foo mid-block");
      SmTx tk2 = {0}; tx1(&tk2, 0xAA, 2); add_action(&tk2, mk_claim("foo", 0x91), 10); sm_apply_tx(s, &tk2);
      CHECK(sm_owns(s, A, "foo"), "55: same-block CLAIM after RELEASE re-mints foo→A");
      sm_free(s); }

    // 55b: after A releases, a lower-priority B still mints the freed name.
    { SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, RATE_DAYS);
      SmTx t0 = {0}; tx1(&t0, 0xAA, 0); add_action(&t0, mk_commit("foo", A, 0x91), 0); sm_apply_tx(s, &t0);
      SmTx t1 = {0}; tx1(&t1, 0xBB, 1); add_action(&t1, mk_commit("foo", B, 0x92), 0); sm_apply_tx(s, &t1);
      sm_begin_block(s, 11, 1500, RATE_DAYS);
      SmTx tk = {0}; tx1(&tk, 0xAA, 0); add_action(&tk, mk_claim("foo", 0x91), 10); sm_apply_tx(s, &tk);
      uint8_t rel[1] = { 0x01 };
      SmTx tr = {0}; tx1(&tr, 0xAA, 1); add_action(&tr, release_bits(11, rel, 1), 0); sm_apply_tx(s, &tr);
      SmTx tk2 = {0}; tx1(&tk2, 0xBB, 2); add_action(&tk2, mk_claim("foo", 0x92), 10); sm_apply_tx(s, &tk2);
      CHECK(sm_owns(s, B, "foo") && !sm_owns(s, A, "foo"), "55b: freed name mints to B regardless of A's old priority");
      sm_free(s); }

    // 56: self-transfer bumps the owner's set-mutation height (11 → 12).
    { SmState *s = minted(0xAA, "bar", 10, 1500);
      CHECK(sm_last_mutation(s, A) == 11, "56: pre-condition mut height 11 from claim");
      sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx tt = {0}; tx1(&tt, 0xAA, 0); add_action(&tt, xfer_all(A), 0); sm_apply_tx(s, &tt);
      CHECK(sm_last_mutation(s, A) == 12, "56: self-transfer bumps mut height to 12 (not a no-op)");
      sm_free(s); }

    // 58: burn near 2⁶⁴ at rate 1 clamps the lease to MAX_LEASE (365 days), no overflow.
    { SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, 1);
      SmTx tc = {0}; tx1(&tc, 0xAA, 0); add_action(&tc, mk_commit("foo", A, 0x95), 0); sm_apply_tx(s, &tc);
      sm_begin_block(s, 11, 1500, 1);
      SmTx tk = {0}; tx1(&tk, 0xAA, 0); add_action(&tk, mk_claim("foo", 0x95), 0xFFFFFFFFFFFFFFFFULL); sm_apply_tx(s, &tk);
      const SmNameRow *r = sm_lookup(s, "foo");
      CHECK(r && r->lease_expiry == 1500 + 365LL * 86400, "58: huge-burn lease clamps to MAX_LEASE (365 days)");
      sm_free(s); }
}

static void test_secp(void) {
    // §4 Strategy B: the real secp256k1 (constants, 2G KAT, n·G=∞, decompress,
    // RFC-6979 sign/verify round-trips). secp_selftest returns the failure count.
    CHECK(secp_selftest() == 0, "secp256k1 selftest (real curve KATs)");
}

static void test_ecmh(void) {
    // §13.2: ECMH primitive algebra (identity / commutativity / inverse / round-trip).
    CHECK(secp_ecmh_selftest() == 0, "ECMH algebra (identity/commutativity/inverse)");

    // Empty-state ECMH is stable across independent recomputes.
    { SmState *a = sm_new(0), *b = sm_new(0);
      uint8_t ea[32], eb[32]; sm_state_ecmh(a, ea); sm_state_ecmh(b, eb);
      CHECK(!memcmp(ea, eb, 32), "ECMH empty-state stable");
      sm_free(a); sm_free(b); }

    // ECMH induces the SAME equality relation as sm_state_digest. Build the same
    // logical rows in two different insertion orders (⇒ order-independent, the
    // from-scratch determinism property) and a third, smaller state. Whenever the
    // canonical digest calls two states equal, ECMH must agree — and vice versa.
    SmState *s1 = sm_new(0), *s2 = sm_new(0), *s3 = sm_new(0);
    uint8_t A[20]; mk_h160(A, 0xAA);
    sm_begin_block(s1, 10, 1000, RATE_DAYS);
    { SmTx c = {0}; tx1(&c, 0xAA,0); add_action(&c, mk_commit("a",A,0xA1),0); sm_apply_tx(s1,&c); }
    { SmTx c = {0}; tx1(&c, 0xAA,1); add_action(&c, mk_commit("b",A,0xA2),0); sm_apply_tx(s1,&c); }
    sm_begin_block(s1, 11, 1500, RATE_DAYS);
    { SmTx k = {0}; tx1(&k, 0xAA,0); add_action(&k, mk_claim("a",0xA1),30); sm_apply_tx(s1,&k); }
    { SmTx k = {0}; tx1(&k, 0xAA,1); add_action(&k, mk_claim("b",0xA2),30); sm_apply_tx(s1,&k); }
    // Identical COMMITs (so the commits rows — which carry tx_index — match s1),
    // but CLAIM in the reverse order ⇒ the names array is permuted with identical
    // content. digest sorts; ECMH sums commutatively; both must still call s1==s2.
    sm_begin_block(s2, 10, 1000, RATE_DAYS);
    { SmTx c = {0}; tx1(&c, 0xAA,0); add_action(&c, mk_commit("a",A,0xA1),0); sm_apply_tx(s2,&c); }
    { SmTx c = {0}; tx1(&c, 0xAA,1); add_action(&c, mk_commit("b",A,0xA2),0); sm_apply_tx(s2,&c); }
    sm_begin_block(s2, 11, 1500, RATE_DAYS);
    { SmTx k = {0}; tx1(&k, 0xAA,1); add_action(&k, mk_claim("b",0xA2),30); sm_apply_tx(s2,&k); }
    { SmTx k = {0}; tx1(&k, 0xAA,0); add_action(&k, mk_claim("a",0xA1),30); sm_apply_tx(s2,&k); }
    sm_begin_block(s3, 10, 1000, RATE_DAYS);
    { SmTx c = {0}; tx1(&c, 0xAA,0); add_action(&c, mk_commit("a",A,0xA1),0); sm_apply_tx(s3,&c); }
    sm_begin_block(s3, 11, 1500, RATE_DAYS);
    { SmTx k = {0}; tx1(&k, 0xAA,0); add_action(&k, mk_claim("a",0xA1),30); sm_apply_tx(s3,&k); }

    uint8_t d1[32],d2[32],d3[32], e1[32],e2[32],e3[32];
    sm_state_digest(s1,d1); sm_state_digest(s2,d2); sm_state_digest(s3,d3);
    sm_state_ecmh  (s1,e1); sm_state_ecmh  (s2,e2); sm_state_ecmh  (s3,e3);
    CHECK(!memcmp(d1,d2,32), "ECMH test setup: reordered builds give equal digest");
    CHECK((memcmp(d1,d2,32)==0) == (memcmp(e1,e2,32)==0), "ECMH equality tracks digest (equal states)");
    CHECK((memcmp(d1,d3,32)==0) == (memcmp(e1,e3,32)==0), "ECMH equality tracks digest (differing states)");
    sm_free(s1); sm_free(s2); sm_free(s3);
}

// DN twin of every PN codec vector: the same action round-trips under 0x44 0x4E,
// the fold of the decoded action matches the PN fold, and each chain's bytes
// are IGNORE under the other profile. The inert harness payloads (truncated
// CLAIM, opcode 0x20, bare UTF-8, overlay 0xD6) get the same twin.
static int decode_round(const SmAction *a, const uint8_t mag[2], SmAction *out) {
    uint8_t b[SM_CARRIER_MAX];
    size_t n = sm_encode_action(a, mag, b);
    if (!n) return 0;
    SmCarrier c; memset(&c, 0, sizeof c);
    sm_decode_payload(b, n, 0, mag, &c);
    if (c.kind != SM_CAR_ACTION) return 0;
    *out = c.act;
    return 1;
}
static void fold_decoded(const SmAction *a, uint8_t dig[32]) {
    SmState *s = sm_new(0);
    sm_begin_block(s, 10, 1000, 1);
    SmTx t; memset(&t, 0, sizeof t);
    tx1(&t, 0xAA, 1);
    add_action(&t, *a, 0);
    sm_apply_tx(s, &t);
    sm_state_digest(s, dig);
    sm_tx_free(&t); sm_free(s);
}
static void twin_bytes(const uint8_t *pn, size_t n, const char *msg) {
    SmCarrier c;
    sm_decode_payload(pn, n, 0, MAG_PN, &c);
    SmCarKind pn_kind = c.kind;
    uint8_t dn[64];
    if (n > sizeof dn) n = sizeof dn;
    memcpy(dn, pn, n);
    if (n >= 3 && pn[0] == 0xFF) { dn[1] = MAG_DN[0]; dn[2] = MAG_DN[1]; }
    sm_decode_payload(dn, n, 0, MAG_DN, &c);
    CHECK(c.kind == pn_kind, msg);
    sm_decode_payload(dn, n, 0, MAG_PN, &c);
    CHECK(c.kind == SM_CAR_IGNORE, "DN payload under the PN profile is ignored");
    sm_decode_payload(pn, n, 0, MAG_DN, &c);
    CHECK(c.kind == SM_CAR_IGNORE, "PN payload under the DN profile is ignored");
}
static void test_magic_profiles(void) {
    uint8_t A[20], B[20]; mk_h160(A, 0xAA); mk_h160(B, 0xBB);
    SmAction acts[18]; int n = 0;
    acts[n++] = mk_commit("bob", A, 0x11);
    acts[n++] = mk_claim("bob", 0x11);
    acts[n++] = mk_claim("abcdefghijklmnopqrstuvwxyz0123ab", 0x11);
    acts[n++] = renew_all();
    { SmAction r; memset(&r, 0, sizeof r); r.op = SM_OP_RENEW; r.has_anchor = 1; r.anchor = 0x0102030405ULL;
      acts[n++] = r;
      r.flags[0] = 0x05; r.flags[1] = 0x80; r.flags_len = 2; acts[n++] = r; }
    acts[n++] = xfer_all(B);
    { SmAction t = xfer_all(B); t.has_anchor = 1; t.anchor = 99; t.flags[0] = 0x03; t.flags_len = 1; acts[n++] = t; }
    acts[n++] = sell(20000, 50000, "wname");
    acts[n++] = nameact(SM_OP_RESERVE, "wname");
    acts[n++] = nameact(SM_OP_SETTLE, "wname");
    acts[n++] = nameact(SM_OP_PAY, "wname");
    { uint8_t f[2] = { 0x01, 0x40 }; acts[n++] = release_bits(12, f, 2); }
    acts[n++] = sell_to(5000, B, "wname");
    acts[n++] = as_to(3);
    acts[n++] = trade(0, 1, "aaa", "bbb");
    for (int i = 0; i < n; i++) {
        CHECK(codec_rt_m(&acts[i], MAG_DN), "DN codec round-trip matches the PN vector");
        SmAction pn, dn;
        CHECK(decode_round(&acts[i], MAG_PN, &pn) && decode_round(&acts[i], MAG_DN, &dn),
              "PN and DN both decode the vector to an action");
        uint8_t dp[32], dd[32];
        fold_decoded(&pn, dp); fold_decoded(&dn, dd);
        CHECK(memcmp(dp, dd, 32) == 0, "DN fold digest equals the PN fold");
        uint8_t wire[SM_CARRIER_MAX];
        size_t ln = sm_encode_action(&acts[i], MAG_DN, wire);
        SmCarrier c; sm_decode_payload(wire, ln, 0, MAG_PN, &c);
        CHECK(c.kind == SM_CAR_IGNORE, "DN payload under the PN profile is ignored");
        ln = sm_encode_action(&acts[i], MAG_PN, wire);
        sm_decode_payload(wire, ln, 0, MAG_DN, &c);
        CHECK(c.kind == SM_CAR_IGNORE, "PN payload under the DN profile is ignored");
    }
    // harness inert vectors + the demux/drop fixtures, each with a DN twin.
    { uint8_t bad[8] = { 0xFF, 0x50, 0x4E, SM_OP_CLAIM, 0, 0, 0, 0 };
      twin_bytes(bad, 8, "DN twin: truncated CLAIM stays IGNORE"); }
    { uint8_t unk[4] = { 0xFF, 0x50, 0x4E, 0x20 };
      twin_bytes(unk, 4, "DN twin: opcode 0x20 stays IGNORE"); }
    { const uint8_t hello[5] = { 'h','e','l','l','o' };
      twin_bytes(hello, 5, "DN twin: bare UTF-8 stays IGNORE"); }
    { uint8_t ov[5] = { 0xFF, 0x50, 0x4E, 0xD6, 0x00 };
      twin_bytes(ov, 5, "DN twin: overlay opcode stays IGNORE"); }
    { uint8_t z[4] = { 0xFF, 0x50, 0x4E, 0x00 };
      twin_bytes(z, 4, "DN twin: opcode 0x00 stays IGNORE"); }
    { uint8_t z[4] = { 0xFF, 0x50, 0x4E, 0x10 };
      twin_bytes(z, 4, "DN twin: opcode 0x10 stays IGNORE"); }
    { uint8_t b[5] = { 0xFF, 0x50, 0x4E, SM_OP_RESERVE, ',' };
      twin_bytes(b, 5, "DN twin: RESERVE bad-name stays IGNORE"); }
    { uint8_t b[9] = { 0xFF, 0x50, 0x4E, SM_OP_TRADE, 0, 1, 'a', 'b', 'c' };
      twin_bytes(b, 9, "DN twin: TRADE no-comma stays IGNORE"); }
    { uint8_t d[10] = { 0xFF, 0x50, 0x4E, SM_OP_TRADE, 0, 1, 'a', ',', ',', 'b' };
      twin_bytes(d, 10, "DN twin: TRADE double-comma stays IGNORE"); }
    { uint8_t b[5] = { 0xFF, 0x50, 0x4E, SM_OP_AS, 2 };
      twin_bytes(b, 5, "DN twin: AS exact stays ACTION"); }
    { uint8_t b[6] = { 0xFF, 0x50, 0x4E, SM_OP_AS, 2, 0 };
      twin_bytes(b, 6, "DN twin: AS over-length stays IGNORE"); }
}

static int selftest(void) {
    test_prng();
    test_secp();
    test_ecmh();
    test_codec();
    test_magic_profiles();
    test_digest_sensitivity();
    test_empty_digest_stable();
    test_activation_gate();
    test_fold_determinism();
    test_commit_claim();
    test_claim_drops();
    test_claim_priority();
    test_lease_lapse();
    test_renew();
    test_wide_bitmap();
    test_transfer_release();
    test_market_open();
    test_market_reserve_guards();
    test_market_sell_guards();
    test_market_directed();
    test_as();
    test_trade();
    test_dotted_names();
    test_tx_bounds();
    test_scenario_races();
    test_scenario_races2();
    test_scenario_races3();

    SmState *e = sm_new(0); uint8_t d[32]; char hx[65];
    sm_state_digest(e, d); hexout(d, 32, hx);
    printf("empty_state_digest=%s\n", hx);
    uint8_t de[32]; sm_state_ecmh(e, de); hexout(de, 32, hx); sm_free(e);
    printf("empty_state_ecmh=%s\n", hx);
    printf("selftest: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}

static const char *EV_NAME[SM_EV_COUNT] = {
    "claim_mint", "claim_displace", "waterfill_cap", "waterfill_forfeit",
    "reserve_win", "reserve_clamp", "settle_ok", "pay_ok",
    "trade_ok", "lapse", "release_name", "as_drop",
    "sell_ok", "sellto_ok",
};

static int cmd_random(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s random <seed> <count> [--trace N] [--cov]\n", argv[0]); return 2; }
    uint64_t seed = strtoull(argv[2], NULL, 0), count = strtoull(argv[3], NULL, 0);
    int trace = 0, cov = 0;
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--trace") == 0 && i + 1 < argc) trace = atoi(argv[++i]);
        else if (strcmp(argv[i], "--cov") == 0) cov = 1;
    }
    uint8_t idig[32], sdig[32]; int64_t ev[SM_EV_COUNT];
    uint64_t n = sm_generate(seed, count, trace, idig, sdig, ev, NULL, NULL);
    char ih[65], sh[65]; hexout(idig, 32, ih); hexout(sdig, 32, sh);
    printf("txs=%llu\ninput_digest=%s\nstate_digest=%s\n", (unsigned long long)n, ih, sh);
    if (cov) {
        printf("coverage:");
        for (int i = 0; i < SM_EV_COUNT; i++) printf(" %s=%lld", EV_NAME[i], (long long)ev[i]);
        printf("\n");
    }
    return 0;
}

// Soak + the structural invariant battery after every block + a 2nd-run
// determinism check. Exits non-zero on any violation or digest mismatch.
static int cmd_invariants(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s invariants <seed> <count> [--cov]\n", argv[0]); return 2; }
    uint64_t seed = strtoull(argv[2], NULL, 0), count = strtoull(argv[3], NULL, 0);
    int cov = (argc > 4 && strcmp(argv[4], "--cov") == 0);
    uint8_t i1[32], s1[32], i2[32], s2[32]; int64_t ev[SM_EV_COUNT], fail = 0;
    sm_generate(seed, count, 0, i1, s1, ev, &fail, NULL);
    sm_generate(seed, count, 0, i2, s2, NULL, NULL, NULL);    // determinism replay
    int det = (memcmp(i1, i2, 32) == 0 && memcmp(s1, s2, 32) == 0);
    char sh[65]; hexout(s1, 32, sh);
    printf("invariants: %lld violation(s); determinism: %s\nstate_digest=%s\n",
           (long long)fail, det ? "OK" : "MISMATCH", sh);
    if (cov) { printf("coverage:"); for (int i = 0; i < SM_EV_COUNT; i++) printf(" %s=%lld", EV_NAME[i], (long long)ev[i]); printf("\n"); }
    return (fail == 0 && det) ? 0 : 1;
}

// ── directed conformance vectors (cross-language adversarial scenarios) ──────
// Each builds a deterministic, named construction and emits `name <digest>`; the
// rolling `combined` hash is the single-line cross-language check. These pin the
// spec's named edge cases (§5) with auditable outcomes, and cover the rare
// branches the random soak almost never hits (deep displacement, i128
// accumulation past 2^64, the fee oracle).
static void emit_state(SHA256_CTX *comb, const char *name, SmState *s) {
    uint8_t d[32]; sm_state_digest(s, d); char hx[65]; hexout(d, 32, hx);
    printf("%s %s\n", name, hx); sha256_update(comb, d, 32);
}
static void emit_u64(SHA256_CTX *comb, const char *name, uint64_t v) {
    uint8_t b[8]; for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8 * i));
    printf("%s %llu\n", name, (unsigned long long)v); sha256_update(comb, b, 8);
}
// Commit `name`(author=tag, salt) at block `ch`, then CLAIM `days` at block `kh`.
static void commit_then_claim(SmState *s, uint8_t tag, const char *nm, uint8_t salt,
                              int days, int64_t cmtp, int ch, int64_t kmtp, int kh) {
    uint8_t A[20]; mk_h160(A, tag);
    sm_begin_block(s, ch, cmtp, RATE_DAYS); SmTx c = {0}; tx1(&c, tag, 0); add_action(&c, mk_commit(nm, A, salt), 0); sm_apply_tx(s, &c);
    sm_begin_block(s, kh, kmtp, RATE_DAYS); SmTx k = {0}; tx1(&k, tag, 0); add_action(&k, mk_claim(nm, salt), (uint64_t)days); sm_apply_tx(s, &k);
}

static int cmd_scenario(void) {
    SHA256_CTX comb; sha256_init(&comb);
    uint8_t A[20], B[20], Cc[20]; mk_h160(A, 0xAA); mk_h160(B, 0xBB); mk_h160(Cc, 0xCC);

    { SmState *s = sm_new(0); emit_state(&comb, "01_empty", s); sm_free(s); }

    { SmState *s = sm_new(0); commit_then_claim(s, 0xAA, "bob", 0x11, 10, 1000, 10, 1500, 11);
      emit_state(&comb, "02_commit_claim", s); sm_free(s); }

    { SmState *s = sm_new(0); sm_begin_block(s, 11, 1500, RATE_DAYS);
      SmTx k = {0}; tx1(&k, 0xAA, 0); add_action(&k, mk_claim("bob", 0x11), 10); sm_apply_tx(s, &k);
      emit_state(&comb, "03_naked_claim_drop", s); sm_free(s); }

    { SmState *s = sm_new(0); sm_begin_block(s, 11, 1500, RATE_DAYS);
      SmTx t = {0}; tx1(&t, 0xAA, 0); add_action(&t, mk_commit("bob", A, 0x11), 0); add_action(&t, mk_claim("bob", 0x11), 10); sm_apply_tx(s, &t);
      emit_state(&comb, "04_shallow_commit_drop", s); sm_free(s); }

    // priority: lower commit_height (A@10) wins ownership in BOTH claim orderings (the selftest
    // asserts A owns bob either way). The two digests differ — a transiently-displaced mint leaves
    // an incidental mutation-height bump that depends on tx order — but each is cross-language-exact.
    for (int order = 0; order < 2; order++) {
      SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, RATE_DAYS); SmTx ca = {0}; tx1(&ca, 0xAA, 0); add_action(&ca, mk_commit("bob", A, 0x11), 0); sm_apply_tx(s, &ca);
      sm_begin_block(s, 12, 1100, RATE_DAYS); SmTx cb = {0}; tx1(&cb, 0xBB, 0); add_action(&cb, mk_commit("bob", B, 0x22), 0); sm_apply_tx(s, &cb);
      sm_begin_block(s, 20, 1200, RATE_DAYS);
      SmTx kA = {0}; tx1(&kA, 0xAA, order == 0 ? 1 : 0); add_action(&kA, mk_claim("bob", 0x11), 10);
      SmTx kB = {0}; tx1(&kB, 0xBB, order == 0 ? 0 : 1); add_action(&kB, mk_claim("bob", 0x22), 10);
      if (order == 0) { sm_apply_tx(s, &kB); sm_apply_tx(s, &kA); } else { sm_apply_tx(s, &kA); sm_apply_tx(s, &kB); }
      emit_state(&comb, order == 0 ? "05_priority_b_first" : "06_priority_a_first", s); sm_free(s);
    }

    // commitment-copy: B reposts A's commitment bytes, then B claims → drop (author-bound); A claims → owns.
    { SmState *s = sm_new(0); SmAction ca = mk_commit("bob", A, 0x33);  // A-bound commitment
      sm_begin_block(s, 10, 1000, RATE_DAYS);
      SmTx t1 = {0}; tx1(&t1, 0xAA, 0); add_action(&t1, ca, 0); sm_apply_tx(s, &t1);
      SmAction copy; memset(&copy, 0, sizeof copy); copy.op = SM_OP_COMMIT; memcpy(copy.commitment, ca.commitment, 32);
      SmTx t2 = {0}; tx1(&t2, 0xBB, 1); add_action(&t2, copy, 0); sm_apply_tx(s, &t2);     // B copies the commitment
      sm_begin_block(s, 11, 1100, RATE_DAYS);
      SmTx kB = {0}; tx1(&kB, 0xBB, 0); add_action(&kB, mk_claim("bob", 0x33), 10); sm_apply_tx(s, &kB);  // B can't satisfy → drop
      SmTx kA = {0}; tx1(&kA, 0xAA, 1); add_action(&kA, mk_claim("bob", 0x33), 10); sm_apply_tx(s, &kA);  // A wins
      emit_state(&comb, "07_commitment_copy", s); sm_free(s); }

    { SmState *s = minted(0xAA, "bob", 10, 1500);   // expiry 865500
      sm_begin_block(s, 12, 865500, RATE_DAYS);     // MTP == expiry → lapse (exclusive)
      emit_state(&comb, "08_lease_lapse", s); sm_free(s); }

    { SmState *s = minted(0xAA, "bob", 10, 1500); sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx t = {0}; tx1(&t, 0xAA, 0); add_action(&t, renew_all(), 5); sm_apply_tx(s, &t);
      emit_state(&comb, "09_renew_stack", s); sm_free(s); }

    // water-fill even split: 3 names, renew-all buys 30 name-days → +10 each.
    { SmState *s = sm_new(0); const char *nm[3] = { "a", "b", "c" };
      sm_begin_block(s, 10, 1000, RATE_DAYS);
      for (int i = 0; i < 3; i++) { SmTx c = {0}; tx1(&c, 0xAA, (uint32_t)i); add_action(&c, mk_commit(nm[i], A, (uint8_t)(0x40 + i)), 0); sm_apply_tx(s, &c); }
      sm_begin_block(s, 11, 1100, RATE_DAYS);
      for (int i = 0; i < 3; i++) { SmTx k = {0}; tx1(&k, 0xAA, (uint32_t)i); add_action(&k, mk_claim(nm[i], (uint8_t)(0x40 + i)), 1); sm_apply_tx(s, &k); }
      sm_begin_block(s, 12, 1200, RATE_DAYS); SmTx r = {0}; tx1(&r, 0xAA, 0); add_action(&r, renew_all(), 30); sm_apply_tx(s, &r);
      emit_state(&comb, "10_waterfill_even", s); sm_free(s); }

    { SmState *s = sm_new(0); commit_then_claim(s, 0xAA, "bob", 0x11, 100000, 1000, 10, 1500, 11);  // huge → caps at 365d
      emit_state(&comb, "11_waterfill_maxlease", s); sm_free(s); }

    { SmState *s = minted(0xAA, "bob", 10, 1500); sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx t = {0}; tx1(&t, 0xAA, 0); add_action(&t, xfer_all(B), 0); sm_apply_tx(s, &t);
      emit_state(&comb, "12_transfer_gift", s); sm_free(s); }

    { SmState *s = minted(0xAA, "bob", 10, 1500); sm_begin_block(s, 12, 1600, RATE_DAYS);
      uint8_t flags[1] = { 0x01 }; SmTx t = {0}; tx1(&t, 0xAA, 0); add_action(&t, release_bits(11, flags, 1), 0); sm_apply_tx(s, &t);
      emit_state(&comb, "13_release", s); sm_free(s); }

    { SmState *s = minted(0xAA, "w", 300, 1500);
      sm_begin_block(s, 12, 1600, RATE_DAYS); SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell(20000, 50000, "w"), 0); sm_apply_tx(s, &ts);
      sm_begin_block(s, 13, 1700, RATE_DAYS); SmTx tr = {0}; tx1(&tr, 0xBB, 0); add_action(&tr, nameact(SM_OP_RESERVE, "w"), 100); add_out(&tr, A, SM_P2PKH, 100); sm_apply_tx(s, &tr);
      sm_begin_block(s, 14, 1800, RATE_DAYS); SmTx tt = {0}; tx1(&tt, 0xBB, 0); add_action(&tt, nameact(SM_OP_SETTLE, "w"), 0); add_out(&tt, A, SM_P2PKH, 19800); sm_apply_tx(s, &tt);
      emit_state(&comb, "14_market_full", s); sm_free(s); }

    { SmState *s = minted(0xAA, "w", 300, 1500); sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell(20000, 50000, "w"), 0); sm_apply_tx(s, &ts);
      sm_begin_block(s, 13, 1700, RATE_DAYS); SmTx tr = {0}; tx1(&tr, 0xBB, 0); add_action(&tr, nameact(SM_OP_RESERVE, "w"), 99); add_out(&tr, A, SM_P2PKH, 100); sm_apply_tx(s, &tr);
      emit_state(&comb, "15_reserve_burn_short", s); sm_free(s); }

    { SmState *s = minted(0xAA, "w", 300, 1500); sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell(20000, 50000, "w"), 0); sm_apply_tx(s, &ts);
      sm_begin_block(s, 13, 1700, RATE_DAYS); SmTx tr = {0}; tx1(&tr, 0xBB, 0); add_action(&tr, nameact(SM_OP_RESERVE, "w"), 100); add_out(&tr, A, SM_P2PKH, 60); add_out(&tr, A, SM_P2PKH, 60); sm_apply_tx(s, &tr);
      emit_state(&comb, "16_reserve_pay_summed", s); sm_free(s); }

    // reserve near offer end → reserve_expiry clamps to offer_expiry.
    { SmState *s = minted(0xAA, "w", 300, 1500); sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell(20000, 0, "w"), 0); sm_apply_tx(s, &ts);     // window default 18000 → offer_expiry 19600
      sm_begin_block(s, 13, 5000, RATE_DAYS); SmTx tr = {0}; tx1(&tr, 0xBB, 0); add_action(&tr, nameact(SM_OP_RESERVE, "w"), 100); add_out(&tr, A, SM_P2PKH, 100); sm_apply_tx(s, &tr);  // 5000+18000>19600 → clamp
      emit_state(&comb, "17_reserve_clamp", s); sm_free(s); }

    { SmState *s = minted(0xAA, "w", 300, 1500); sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell(2, 0, "w"), 0); sm_apply_tx(s, &ts);   // below 3·DUST
      emit_state(&comb, "18_sell_price_floor", s); sm_free(s); }

    { SmState *s = minted(0xAA, "w", 1, 1500); sm_begin_block(s, 12, 65000, RATE_DAYS);   // short tail
      SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell(20000, 0, "w"), 0); sm_apply_tx(s, &ts);
      emit_state(&comb, "19_sell_window_overflow", s); sm_free(s); }

    { SmState *s = minted(0xAA, "w", 300, 1500); sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell_to(5000, B, "w"), 0); sm_apply_tx(s, &ts);
      sm_begin_block(s, 13, 1700, RATE_DAYS);
      SmTx tc = {0}; tx1(&tc, 0xCC, 0); add_action(&tc, nameact(SM_OP_PAY, "w"), 0); add_out(&tc, A, SM_P2PKH, 5000); sm_apply_tx(s, &tc);   // stranger → drop
      SmTx tb = {0}; tx1(&tb, 0xBB, 1); add_action(&tb, nameact(SM_OP_PAY, "w"), 0); add_out(&tb, A, SM_P2PKH, 5000); sm_apply_tx(s, &tb);   // buyer → owns
      emit_state(&comb, "20_directed_pay", s); sm_free(s); }

    // 2^64-1 price: the 128-bit deposit legs must be exact (a 64-bit impl wraps).
    { SmState *s = minted(0xAA, "w", 300, 1500); sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell(UINT64_MAX, 50000, "w"), 0); sm_apply_tx(s, &ts);
      uint64_t leg = (uint64_t)((unsigned __int128)UINT64_MAX * 50 / 10000);
      sm_begin_block(s, 13, 1700, RATE_DAYS); SmTx tr = {0}; tx1(&tr, 0xBB, 0); add_action(&tr, nameact(SM_OP_RESERVE, "w"), leg); add_out(&tr, A, SM_P2PKH, leg); sm_apply_tx(s, &tr);
      emit_state(&comb, "21_deposit_2pow64", s); sm_free(s); }

    // AS attribution: claim attributed to vin[1]=B (matches B's commit).
    { SmState *s = sm_new(0); sm_begin_block(s, 10, 1000, RATE_DAYS);
      SmTx c = {0}; tx1(&c, 0xBB, 0); add_action(&c, mk_commit("bob", B, 0x55), 0); sm_apply_tx(s, &c);
      sm_begin_block(s, 11, 1500, RATE_DAYS); SmTx t = {0}; tx2(&t, 0xAA, 0xBB, 0); add_action(&t, as_to(1), 0); add_action(&t, mk_claim("bob", 0x55), 10); sm_apply_tx(s, &t);
      emit_state(&comb, "22_as_attribution", s); sm_free(s); }

    { SmState *s = sm_new(0); sm_begin_block(s, 10, 1000, RATE_DAYS);
      SmTx c = {0}; tx1(&c, 0xBB, 0); add_action(&c, mk_commit("bob", B, 0x55), 0); sm_apply_tx(s, &c);
      sm_begin_block(s, 11, 1500, RATE_DAYS); SmTx t = {0}; tx2(&t, 0xAA, 0xBB, 0); t.in_sighash_all[1] = 0; add_action(&t, as_to(1), 0); add_action(&t, mk_claim("bob", 0x55), 10); sm_apply_tx(s, &t);
      emit_state(&comb, "23_as_oob_drop", s); sm_free(s); }

    { SmState *s = two_names(); sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx t = {0}; tx2(&t, 0xAA, 0xBB, 0); add_action(&t, trade(0, 1, "aaa", "bbb"), 0); sm_apply_tx(s, &t);
      emit_state(&comb, "24_trade_swap", s); sm_free(s); }

    { SmState *s = two_names(); sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx mv = {0}; tx1(&mv, 0xAA, 0); add_action(&mv, xfer_all(Cc), 0); sm_apply_tx(s, &mv);   // aaa→C before the trade
      SmTx t2 = {0}; tx2(&t2, 0xAA, 0xBB, 1); add_action(&t2, trade(0, 1, "aaa", "bbb"), 0); sm_apply_tx(s, &t2);   // anti-rug → drop
      emit_state(&comb, "25_trade_rug_before", s); sm_free(s); }

    // fee oracle (§3.4): signed under-claim clamp + participant filter + MIN_FEE_SAMPLE
    // degrade + lower-median + REF_SIZE scale + clamp. 4 participants < MIN_FEE_SAMPLE
    // ⇒ this small window now degrades to DUST_FLOOR (the big-window vectors are 49–51).
    { int64_t sub[5] = { 1000000000000LL, 1000000000000LL, 1000000000000LL, 1000000000000LL, 1000000000000LL };
      int64_t cb[5]  = { 1000000200000LL, 1000000400000LL, 999999999950LL, 1000001000000LL, 1000000600000LL };  // 3rd under-claims
      int64_t by[5]  = { 1000, 1000, 1000, 1000, 1000 };
      emit_u64(&comb, "29_oracle_rate", sm_oracle_rate(cb, sub, by, 5)); }            // |P|=4 < 1000 → DUST_FLOOR = 1
    { int64_t sub[3] = { 1000000000000LL, 1000000000000LL, 1000000000000LL };
      int64_t cb[3]  = { 0, 0, 0 }; int64_t by[3] = { 1000, 1000, 1000 };             // all under-claim → fees 0 → rate floor
      emit_u64(&comb, "30_oracle_floor", sm_oracle_rate(cb, sub, by, 3)); }
    { int64_t ts[11] = { 100, 50, 200, 30, 150, 80, 220, 10, 175, 60, 190 };
      emit_u64(&comb, "31_mtp_median", (uint64_t)sm_mtp(ts, 11)); }                    // median of 11

    // ── water-fill rare branches ──
    // 32: T < count — burn buys fewer name-days than names; the first T names
    // (ascending-lex) get +1 day, the rest none (§3.5 floor).
    { SmState *s = sm_new(0); const char *nm[3] = { "a", "b", "c" };
      sm_begin_block(s, 10, 1000, RATE_DAYS);
      for (int i = 0; i < 3; i++) { SmTx c = {0}; tx1(&c, 0xAA, (uint32_t)i); add_action(&c, mk_commit(nm[i], A, (uint8_t)(0x50 + i)), 0); sm_apply_tx(s, &c); }
      sm_begin_block(s, 11, 1100, RATE_DAYS);
      for (int i = 0; i < 3; i++) { SmTx k = {0}; tx1(&k, 0xAA, (uint32_t)i); add_action(&k, mk_claim(nm[i], (uint8_t)(0x50 + i)), 1); sm_apply_tx(s, &k); }
      sm_begin_block(s, 12, 1200, RATE_DAYS); SmTx r = {0}; tx1(&r, 0xAA, 0); add_action(&r, renew_all(), 2); sm_apply_tx(s, &r);  // T=2 over 3 → a,b +1d, c none
      emit_state(&comb, "32_waterfill_floor", s); sm_free(s); }

    // 33: every targeted name hits MAX_LEASE with T still remaining → surplus forfeited.
    { SmState *s = sm_new(0); const char *nm[2] = { "a", "b" };
      sm_begin_block(s, 10, 1000, RATE_DAYS);
      for (int i = 0; i < 2; i++) { SmTx c = {0}; tx1(&c, 0xAA, (uint32_t)i); add_action(&c, mk_commit(nm[i], A, (uint8_t)(0x60 + i)), 0); sm_apply_tx(s, &c); }
      sm_begin_block(s, 11, 1100, RATE_DAYS);
      for (int i = 0; i < 2; i++) { SmTx k = {0}; tx1(&k, 0xAA, (uint32_t)i); add_action(&k, mk_claim(nm[i], (uint8_t)(0x60 + i)), 360); sm_apply_tx(s, &k); }  // ~360d each
      sm_begin_block(s, 12, 1100, RATE_DAYS); SmTx r = {0}; tx1(&r, 0xAA, 0); add_action(&r, renew_all(), 100000); sm_apply_tx(s, &r);  // huge → both cap @MAX_LEASE, forfeit
      emit_state(&comb, "33_waterfill_allcap_forfeit", s); sm_free(s); }

    // ── reorg edge cases as deterministic vectors (the fold's answer for two
    //    chains that differ only across a reorg boundary) ──
    // 34: a same-block lapse-and-reclaim. (a) bob lapses at MTP==expiry, B reclaims
    //     → B owns. (b) the reorg restores A's earlier RENEW, so bob never lapses and
    //     B's reclaim drops → A keeps it. The reclaim is valid IFF the lapse happened.
    { SmState *s = minted(0xAA, "bob", 10, 1500);                 // expiry 865500
      sm_begin_block(s, 12, 860000, RATE_DAYS); SmTx cb = {0}; tx1(&cb, 0xBB, 0); add_action(&cb, mk_commit("bob", B, 0x44), 0); sm_apply_tx(s, &cb);
      sm_begin_block(s, 13, 865500, RATE_DAYS); SmTx kb = {0}; tx1(&kb, 0xBB, 0); add_action(&kb, mk_claim("bob", 0x44), 10); sm_apply_tx(s, &kb);  // lapse then B mints
      emit_state(&comb, "34a_reorg_lapse_reclaim", s); sm_free(s); }
    { SmState *s = minted(0xAA, "bob", 10, 1500);
      sm_begin_block(s, 12, 860000, RATE_DAYS);
      SmTx cb = {0}; tx1(&cb, 0xBB, 0); add_action(&cb, mk_commit("bob", B, 0x44), 0); sm_apply_tx(s, &cb);
      SmTx ra = {0}; tx1(&ra, 0xAA, 1); add_action(&ra, renew_all(), 10); sm_apply_tx(s, &ra);   // A renews → bob survives past 865500
      sm_begin_block(s, 13, 865500, RATE_DAYS); SmTx kb = {0}; tx1(&kb, 0xBB, 0); add_action(&kb, mk_claim("bob", 0x44), 10); sm_apply_tx(s, &kb);  // bob owned → drop
      emit_state(&comb, "34b_reorg_renew_blocks_reclaim", s); sm_free(s); }

    // 35: a SETTLE un-confirmed by a reorg. (a) the reserve lapses without a settle →
    //     the listing reverts to the seller; (b) the settle confirms → buyer owns.
    { SmState *s = minted(0xAA, "w", 300, 1500);
      sm_begin_block(s, 12, 1600, RATE_DAYS); SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell(20000, 50000, "w"), 0); sm_apply_tx(s, &ts);
      sm_begin_block(s, 13, 1700, RATE_DAYS); SmTx tr = {0}; tx1(&tr, 0xBB, 0); add_action(&tr, nameact(SM_OP_RESERVE, "w"), 100); add_out(&tr, A, SM_P2PKH, 100); sm_apply_tx(s, &tr);
      sm_begin_block(s, 14, 20000, RATE_DAYS);                    // MTP past reserve_expiry (19700) → revert to listing
      emit_state(&comb, "35a_settle_dropped_relisted", s); sm_free(s); }
    { SmState *s = minted(0xAA, "w", 300, 1500);
      sm_begin_block(s, 12, 1600, RATE_DAYS); SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell(20000, 50000, "w"), 0); sm_apply_tx(s, &ts);
      sm_begin_block(s, 13, 1700, RATE_DAYS); SmTx tr = {0}; tx1(&tr, 0xBB, 0); add_action(&tr, nameact(SM_OP_RESERVE, "w"), 100); add_out(&tr, A, SM_P2PKH, 100); sm_apply_tx(s, &tr);
      sm_begin_block(s, 14, 1800, RATE_DAYS); SmTx tt = {0}; tx1(&tt, 0xBB, 0); add_action(&tt, nameact(SM_OP_SETTLE, "w"), 0); add_out(&tt, A, SM_P2PKH, 19800); sm_apply_tx(s, &tt);
      emit_state(&comb, "35b_settle_confirmed", s); sm_free(s); }

    // 36: an MTP boundary call that flips under a one-tick reorg. lease_expiry is an
    //     EXCLUSIVE bound: MTP == expiry−1 stays owned; MTP == expiry lapses.
    { SmState *s = minted(0xAA, "bob", 10, 1500); sm_begin_block(s, 12, 865499, RATE_DAYS); emit_state(&comb, "36a_mtp_below_owned", s); sm_free(s); }
    { SmState *s = minted(0xAA, "bob", 10, 1500); sm_begin_block(s, 12, 865500, RATE_DAYS); emit_state(&comb, "36b_mtp_at_lapsed", s); sm_free(s); }

    // ── pre-block ordering & intra-block market races ──
    // 38: a same-block RENEW-vs-CLAIM race at the exact lapse tie. A owns `bob` (lapsing
    //     at this block's MTP) and `keep` (long lease). The pre-block lapse returns `bob`
    //     to the pool BEFORE any tx runs, so A's renew-all renews only `keep` (bob is no
    //     longer A's) and the hunter B's CLAIM (commit ≥1 block deep) mints `bob`. A lazy
    //     "evaluate expiry on access" impl would let the RENEW revive `bob` and B's CLAIM
    //     would then drop on an owned name — a clean fork.
    { SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, RATE_DAYS);
      SmTx cbob = {0}; tx1(&cbob, 0xAA, 0); add_action(&cbob, mk_commit("bob",  A, 0x33), 0); sm_apply_tx(s, &cbob);
      SmTx ckep = {0}; tx1(&ckep, 0xAA, 1); add_action(&ckep, mk_commit("keep", A, 0x34), 0); sm_apply_tx(s, &ckep);
      sm_begin_block(s, 11, 1500, RATE_DAYS);
      SmTx kbob = {0}; tx1(&kbob, 0xAA, 0); add_action(&kbob, mk_claim("bob",  0x33), 10);  sm_apply_tx(s, &kbob);   // bob expiry 865500
      SmTx kkep = {0}; tx1(&kkep, 0xAA, 1); add_action(&kkep, mk_claim("keep", 0x34), 300); sm_apply_tx(s, &kkep);   // keep long-lived
      sm_begin_block(s, 12, 860000, RATE_DAYS);
      SmTx cb = {0}; tx1(&cb, 0xBB, 0); add_action(&cb, mk_commit("bob", B, 0x44), 0); sm_apply_tx(s, &cb);         // hunter commits
      sm_begin_block(s, 13, 865500, RATE_DAYS);             // MTP == bob's expiry → bob lapses pre-block
      SmTx ra = {0}; tx1(&ra, 0xAA, 0); add_action(&ra, renew_all(), 5); sm_apply_tx(s, &ra);                       // renews `keep` only
      SmTx kb = {0}; tx1(&kb, 0xBB, 1); add_action(&kb, mk_claim("bob", 0x44), 10); sm_apply_tx(s, &kb);            // hunter mints bob
      emit_state(&comb, "38_lapse_renew_vs_claim", s); sm_free(s); }

    // 39: a single pre-block tick that crosses reserve_expiry AND offer_expiry at once,
    //     cascading RESERVED→LISTED→OWNED in one pass (§5 type-order reserve→offer→lease).
    //     Step 2 (offer) must see step 1's LISTED mutation; an impl that evaluates the legs
    //     against block-initial state, or runs offer before reserve, would skip step 2 and
    //     orphan a row past its offer_expiry. (35a stops after just the reserve leg.) The
    //     *triple* tie with lease is unconstructible — the nesting invariant forces
    //     offer_expiry + REORG_BUFFER ≤ lease_expiry, so the lease leg is always ≥2h out.
    { SmState *s = minted(0xAA, "w", 300, 1500);             // lease_expiry = 25,921,500
      sm_begin_block(s, 12, 1600, RATE_DAYS); SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell(20000, 50000, "w"), 0); sm_apply_tx(s, &ts);  // offer_expiry = 51600
      sm_begin_block(s, 13, 1700, RATE_DAYS); SmTx tr = {0}; tx1(&tr, 0xBB, 0); add_action(&tr, nameact(SM_OP_RESERVE, "w"), 100); add_out(&tr, A, SM_P2PKH, 100); sm_apply_tx(s, &tr);  // reserve_expiry = 19700 < 51600
      sm_begin_block(s, 14, 51600, RATE_DAYS);               // MTP == offer_expiry, > reserve_expiry → both legs fire
      emit_state(&comb, "39_preblock_reserve_offer_collapse", s); sm_free(s); }

    // 40: intra-block RESERVE option theft. Two buyers race the same listing in one block:
    //     the first (chain-order) wins the exclusive option; the second sees a non-LISTED
    //     row and drops (no overwrite), so its later SETTLE fails the buyer-match. (The
    //     abstracted SM can't model the loser's on-chain deposit burn — it pins the option
    //     lock + the settle-drop, the consensus-relevant half.)
    { SmState *s = minted(0xAA, "w", 300, 1500);
      sm_begin_block(s, 12, 1600, RATE_DAYS); SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell(20000, 50000, "w"), 0); sm_apply_tx(s, &ts);
      sm_begin_block(s, 13, 1700, RATE_DAYS);
      SmTx r0 = {0}; tx1(&r0, 0xBB, 0); add_action(&r0, nameact(SM_OP_RESERVE, "w"), 100); add_out(&r0, A, SM_P2PKH, 100); sm_apply_tx(s, &r0);  // B wins the option
      SmTx r1 = {0}; tx1(&r1, 0xCC, 1); add_action(&r1, nameact(SM_OP_RESERVE, "w"), 100); add_out(&r1, A, SM_P2PKH, 100); sm_apply_tx(s, &r1);  // C loses (row RESERVED) → drop
      SmTx st = {0}; tx1(&st, 0xCC, 2); add_action(&st, nameact(SM_OP_SETTLE, "w"), 0);    add_out(&st, A, SM_P2PKH, 19800); sm_apply_tx(s, &st);  // C settles → buyer-mismatch → drop
      emit_state(&comb, "40_reserve_option_theft", s); sm_free(s); }

    // 41: value-collision in spendable-output matching. One tx does RESERVE(x)+SETTLE(y),
    //     both paying seller A, with two outputs to A: vout[0]=19800 (settle remainder) and
    //     vout[1]=5 (reserve pay-leg). The consume-once, exact-value, vout-order matcher must
    //     let RESERVE skip the larger vout[0] and take vout[1], then SETTLE take vout[0]. A
    //     greedy / dest-only / summing matcher mis-assigns and one op drops.
    { SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, RATE_DAYS);
      SmTx cxn = {0}; tx1(&cxn, 0xAA, 0); add_action(&cxn, mk_commit("x", A, 0x71), 0); sm_apply_tx(s, &cxn);
      SmTx cyn = {0}; tx1(&cyn, 0xAA, 1); add_action(&cyn, mk_commit("y", A, 0x72), 0); sm_apply_tx(s, &cyn);
      sm_begin_block(s, 11, 1500, RATE_DAYS);
      SmTx kxn = {0}; tx1(&kxn, 0xAA, 0); add_action(&kxn, mk_claim("x", 0x71), 300); sm_apply_tx(s, &kxn);
      SmTx kyn = {0}; tx1(&kyn, 0xAA, 1); add_action(&kyn, mk_claim("y", 0x72), 300); sm_apply_tx(s, &kyn);
      sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx sx = {0}; tx1(&sx, 0xAA, 0); add_action(&sx, sell(1000,  50000, "x"), 0); sm_apply_tx(s, &sx);   // pay_leg(x) = 5
      SmTx sy = {0}; tx1(&sy, 0xAA, 1); add_action(&sy, sell(20000, 50000, "y"), 0); sm_apply_tx(s, &sy);   // remainder(y) = 19800
      sm_begin_block(s, 13, 1700, RATE_DAYS);
      SmTx ry = {0}; tx1(&ry, 0xBB, 0); add_action(&ry, nameact(SM_OP_RESERVE, "y"), 100); add_out(&ry, A, SM_P2PKH, 100); sm_apply_tx(s, &ry);  // B reserves y
      sm_begin_block(s, 14, 1800, RATE_DAYS);
      SmTx col = {0}; tx1(&col, 0xBB, 0);
      add_action(&col, nameact(SM_OP_RESERVE, "x"), 5);   // car_value 5 ≥ burn_leg(x)=5
      add_action(&col, nameact(SM_OP_SETTLE,  "y"), 0);
      add_out(&col, A, SM_P2PKH, 19800);                  // vout[0] (lower) = settle remainder
      add_out(&col, A, SM_P2PKH, 5);                      // vout[1] (higher) = reserve pay-leg
      sm_apply_tx(s, &col);
      emit_state(&comb, "41_vout_value_collision", s); sm_free(s); }

    // ── priority tie-break + Tier-4 coverage (audit follow-ups) ──
    // 42: CLAIM priority tie-break is the COMMIT's tx_index (§3.2 tuple), NOT claim chain
    //     order. Two authors commit `bob` in ONE block at different tx_index (B's commit
    //     tx_index 2 < A's 5); both claim a later block with A's claim applied FIRST. The
    //     lower-commit-tx_index author (B) MUST win regardless of claim order. (Pre-fix the
    //     same-block displacement compared commit_height only and kept the first-applied claim.)
    { SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, RATE_DAYS);
      SmTx cA = {0}; tx1(&cA, 0xAA, 5); add_action(&cA, mk_commit("bob", A, 0x81), 0); sm_apply_tx(s, &cA);
      SmTx cB = {0}; tx1(&cB, 0xBB, 2); add_action(&cB, mk_commit("bob", B, 0x82), 0); sm_apply_tx(s, &cB);
      sm_begin_block(s, 20, 1500, RATE_DAYS);
      SmTx kA = {0}; tx1(&kA, 0xAA, 0); add_action(&kA, mk_claim("bob", 0x81), 10); sm_apply_tx(s, &kA);   // applied first
      SmTx kB = {0}; tx1(&kB, 0xBB, 1); add_action(&kB, mk_claim("bob", 0x82), 10); sm_apply_tx(s, &kB);   // lower commit tx_index → wins
      emit_state(&comb, "42_claim_commit_txindex_tiebreak", s); sm_free(s); }

    // 43: escrow movement-lock (§3.7 headline) — a LISTED name rejects every move:
    //     TRANSFER, RELEASE, re-SELL, and SELL_TO all no-op while it sits on the market.
    { SmState *s = minted(0xAA, "w", 300, 1500);
      sm_begin_block(s, 12, 1600, RATE_DAYS); SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell(20000, 50000, "w"), 0); sm_apply_tx(s, &ts);
      sm_begin_block(s, 13, 1700, RATE_DAYS);
      uint8_t f43[1] = { 0x01 };
      SmTx mv = {0}; tx1(&mv, 0xAA, 0); add_action(&mv, xfer_all(B), 0);                 sm_apply_tx(s, &mv);   // gift → locked, skip
      SmTx rl = {0}; tx1(&rl, 0xAA, 1); add_action(&rl, release_bits(11, f43, 1), 0);    sm_apply_tx(s, &rl);   // release → locked, skip
      SmTx rs = {0}; tx1(&rs, 0xAA, 2); add_action(&rs, sell(30000, 50000, "w"), 0);     sm_apply_tx(s, &rs);   // re-SELL → not OWNED, reject
      SmTx rt = {0}; tx1(&rt, 0xAA, 3); add_action(&rt, sell_to(5000, B, "w"), 0);       sm_apply_tx(s, &rt);   // SELL_TO → not OWNED, reject
      emit_state(&comb, "43_escrow_movement_lock", s); sm_free(s); }

    // 44: anchor-guard reject (§3.5) — a bitmap op whose anchor is OLDER than the owner's
    //     last set-mutation is dropped (stale set-view could select the wrong names).
    { SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, RATE_DAYS);
      SmTx ca = {0}; tx1(&ca, 0xAA, 0); add_action(&ca, mk_commit("a", A, 0x91), 0); sm_apply_tx(s, &ca);
      sm_begin_block(s, 11, 1500, RATE_DAYS);
      SmTx ka = {0}; tx1(&ka, 0xAA, 0); add_action(&ka, mk_claim("a", 0x91), 30); sm_apply_tx(s, &ka);    // lm(A)=11
      SmTx cb = {0}; tx1(&cb, 0xAA, 1); add_action(&cb, mk_commit("b", A, 0x92), 0); sm_apply_tx(s, &cb);
      sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx kb = {0}; tx1(&kb, 0xAA, 0); add_action(&kb, mk_claim("b", 0x92), 30); sm_apply_tx(s, &kb);    // lm(A)=12 (set grew)
      sm_begin_block(s, 13, 1700, RATE_DAYS);
      uint8_t f44[1] = { 0x01 };                                                                // select bit0 = "a"
      SmTx rl = {0}; tx1(&rl, 0xAA, 0); add_action(&rl, release_bits(11, f44, 1), 0); sm_apply_tx(s, &rl);  // anchor 11 < lm 12 → reject
      emit_state(&comb, "44_anchor_guard_reject", s); sm_free(s); }

    // 45: COMMIT_EXPIRY prune — a commit older than COMMIT_EXPIRY (18000s) is pruned pre-block,
    //     so a later matching claim finds no live commit and drops (§3.2).
    { SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, RATE_DAYS); SmTx c = {0}; tx1(&c, 0xAA, 0); add_action(&c, mk_commit("bob", A, 0x33), 0); sm_apply_tx(s, &c);
      sm_begin_block(s, 11, 19001, RATE_DAYS);                                                  // 19001 > 1000 + 18000 → prune
      SmTx k = {0}; tx1(&k, 0xAA, 0); add_action(&k, mk_claim("bob", 0x33), 10); sm_apply_tx(s, &k);     // no live commit → drop
      emit_state(&comb, "45_commit_expiry_prune", s); sm_free(s); }

    // 46: RESERVE burn leg is an inequality (car_value ≥ burn_leg), not exact — an OVER-funded
    //     burn (car_value 150 > burn_leg 100) still wins the option (cf. 15: 99 < 100 drops).
    { SmState *s = minted(0xAA, "w", 300, 1500); sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx ts = {0}; tx1(&ts, 0xAA, 0); add_action(&ts, sell(20000, 50000, "w"), 0); sm_apply_tx(s, &ts);
      sm_begin_block(s, 13, 1700, RATE_DAYS); SmTx tr = {0}; tx1(&tr, 0xBB, 0); add_action(&tr, nameact(SM_OP_RESERVE, "w"), 150); add_out(&tr, A, SM_P2PKH, 100); sm_apply_tx(s, &tr);
      emit_state(&comb, "46_reserve_overfunded_burn", s); sm_free(s); }

    // 47: TRADE malformed drops — OOB index, idxA==idxB (one party), and nameA==nameB are
    //     each fail-closed; the two-name state is left untouched (§3.10).
    { SmState *s = two_names();
      sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx t1 = {0}; tx2(&t1, 0xAA, 0xBB, 0); add_action(&t1, trade(0, 5, "aaa", "bbb"), 0); sm_apply_tx(s, &t1);   // idx_b OOB → drop
      SmTx t2 = {0}; tx2(&t2, 0xAA, 0xBB, 1); add_action(&t2, trade(0, 0, "aaa", "bbb"), 0); sm_apply_tx(s, &t2);   // idxA==idxB → drop
      SmTx t3 = {0}; tx2(&t3, 0xAA, 0xBB, 2); add_action(&t3, trade(0, 1, "aaa", "aaa"), 0); sm_apply_tx(s, &t3);   // nameA==nameB → drop
      emit_state(&comb, "47_trade_malformed_drops", s); sm_free(s); }

    // 48: selective TRANSFER (anchor+flags) gifts a SUBSET — bits {0,2} of A's sorted set
    //     {a,b,c} move to B; b stays with A. Exercises the bitmap-selected positive transfer.
    { SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, RATE_DAYS);
      SmTx ca = {0}; tx1(&ca, 0xAA, 0); add_action(&ca, mk_commit("a", A, 0xA1), 0); sm_apply_tx(s, &ca);
      SmTx cb = {0}; tx1(&cb, 0xAA, 1); add_action(&cb, mk_commit("b", A, 0xA2), 0); sm_apply_tx(s, &cb);
      SmTx cc = {0}; tx1(&cc, 0xAA, 2); add_action(&cc, mk_commit("c", A, 0xA3), 0); sm_apply_tx(s, &cc);
      sm_begin_block(s, 11, 1500, RATE_DAYS);
      SmTx ka = {0}; tx1(&ka, 0xAA, 0); add_action(&ka, mk_claim("a", 0xA1), 30); sm_apply_tx(s, &ka);
      SmTx kb = {0}; tx1(&kb, 0xAA, 1); add_action(&kb, mk_claim("b", 0xA2), 30); sm_apply_tx(s, &kb);
      SmTx kc = {0}; tx1(&kc, 0xAA, 2); add_action(&kc, mk_claim("c", 0xA3), 30); sm_apply_tx(s, &kc);
      sm_begin_block(s, 12, 1600, RATE_DAYS);
      uint8_t f48[1] = { 0x05 };                                                                // bits 0 and 2 → a, c
      SmTx tv = {0}; tx1(&tv, 0xAA, 0); add_action(&tv, xfer_bits(11, f48, 1, B), 0); sm_apply_tx(s, &tv);
      emit_state(&comb, "48_transfer_selective", s); sm_free(s); }

    // ── §3.4 participant-median oracle (fee-bearing filter + MIN_FEE_SAMPLE) ──
    // 49: |P| = 1000 EXACTLY (inclusive boundary) and EVEN, with an under-claim
    //     block inside the window. Lower median = index (1000−1)/2 = 499 of the
    //     sorted 100..1099 → 599 → rate 119,800. Every rival reading forks to a
    //     different number: unsigned-wrap enrolls the under-claim as a huge 1001st
    //     participant → index 500 → 600 → 120,000; an exclusive boundary (|P| ≤
    //     MIN degrades) → 1; an upper median → 600 → 120,000.
    { enum { N49 = 1500 };
      static int64_t sub49[N49], cb49[N49], by49[N49];
      for (int i = 0; i < N49; i++) {
          sub49[i] = 1000000000000LL; by49[i] = 1000;
          if (i < 499)       cb49[i] = sub49[i];                                       // zero-fee → non-participant
          else if (i == 499) cb49[i] = sub49[i] - 50;                                  // under-claim → non-participant
          else               cb49[i] = sub49[i] + (int64_t)(100 + (i - 500)) * 1000;   // fpb 100..1099
      }
      emit_u64(&comb, "49_oracle_even_boundary", sm_oracle_rate(cb49, sub49, by49, N49)); }  // → 119800

    // 50: odd |P| = 1101 through the participant filter — the historical middle
    //     rule unchanged by the rewrite: index 550 of 100..1200 → 650 → 130,000.
    { enum { N50 = 2000 };
      static int64_t sub50[N50], cb50[N50], by50[N50];
      for (int i = 0; i < N50; i++) {
          sub50[i] = 1000000000000LL; by50[i] = 1000;
          cb50[i] = (i < 899) ? sub50[i] : sub50[i] + (int64_t)(100 + (i - 899)) * 1000;  // fpb 100..1200
      }
      emit_u64(&comb, "50_oracle_odd_median", sm_oracle_rate(cb50, sub50, by50, N50)); }     // → 130000

    // 51: |P| = 999 — one short of MIN_FEE_SAMPLE → degrade to DUST_FLOOR exactly.
    { enum { N51 = 1500 };
      static int64_t sub51[N51], cb51[N51], by51[N51];
      for (int i = 0; i < N51; i++) {
          sub51[i] = 1000000000000LL; by51[i] = 1000;
          cb51[i] = (i < 501) ? sub51[i] : sub51[i] + (int64_t)(100 + (i - 501)) * 1000;  // 999 participants
      }
      emit_u64(&comb, "51_oracle_subsample_floor", sm_oracle_rate(cb51, sub51, by51, N51)); } // → 1

    // 52: charset = a DNS label [a-z0-9-], 1..32: hyphen and a 32-byte name MINT;
    // '.' and '_' DROP (uppercase still drops), leaving exactly the two valid names.
    { SmState *s = sm_new(0);
      commit_then_claim(s, 0xAA, "shib-p2p",                         0x71, 10, 1000, 10, 1500, 11);
      commit_then_claim(s, 0xAA, "abcdefghijklmnopqrstuvwxyz0123ab", 0x72, 10, 2000, 12, 2500, 13);
      commit_then_claim(s, 0xAA, "shib.p2p",                         0x73, 10, 3000, 14, 3500, 15);
      commit_then_claim(s, 0xAA, "shib_p2p",                         0x74, 10, 4000, 16, 4500, 17);
      emit_state(&comb, "52_charset", s); sm_free(s); }

    // 52b: structural name rejects — leading/trailing hyphen and xn-- ACE drop.
    { SmState *s = sm_new(0);
      commit_then_claim(s, 0xAA, "-lead", 0x81, 10, 1000, 10, 1500, 11);
      commit_then_claim(s, 0xAA, "trail-", 0x82, 10, 2000, 12, 2500, 13);
      commit_then_claim(s, 0xAA, "xn--x",  0x83, 10, 3000, 14, 3500, 15);
      commit_then_claim(s, 0xAA, "ok-name",0x84, 10, 4000, 16, 4500, 17);
      emit_state(&comb, "52b_structural", s); sm_free(s); }

    // 54: NO per-tx count cap (§0). One tx carries 17 COMMIT carriers past the
    // historical 16; all fold (SmTx spills to the heap).
    { SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, RATE_DAYS);
      SmTx t = {0}; tx1(&t, 0xAA, 0);
      for (int i = 0; i < 17; i++) {
          SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_COMMIT; a.commitment[0] = (uint8_t)i;
          add_action(&t, a, 0);
      }
      for (int i = 0; i < 17; i++) add_out(&t, A, SM_P2PKH, 1);
      sm_apply_tx(s, &t); sm_tx_free(&t);
      emit_state(&comb, "54_no_txcap", s); sm_free(s); }

    // 55: a name minted then RELEASEd earlier in the SAME block re-mints fresh on a
    // later CLAIM in that block (§3.6 "immediately reclaimable"; row existence is
    // authoritative, the block-local claim scratch never blocks a re-mint).
    { SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, RATE_DAYS);
      SmTx tc = {0}; tx1(&tc, 0xAA, 0); add_action(&tc, mk_commit("foo", A, 0x91), 0); sm_apply_tx(s, &tc);
      sm_begin_block(s, 11, 1500, RATE_DAYS);
      SmTx tk = {0}; tx1(&tk, 0xAA, 0); add_action(&tk, mk_claim("foo", 0x91), 10); sm_apply_tx(s, &tk);   // mint foo→A (A mut=11)
      uint8_t rel[1] = { 0x01 };
      SmTx tr = {0}; tx1(&tr, 0xAA, 1); add_action(&tr, release_bits(11, rel, 1), 0); sm_apply_tx(s, &tr); // release foo (row gone, scratch lingers)
      SmTx tk2 = {0}; tx1(&tk2, 0xAA, 2); add_action(&tk2, mk_claim("foo", 0x91), 10); sm_apply_tx(s, &tk2); // MUST re-mint foo→A
      emit_state(&comb, "55_claim_release_reclaim_sameblock", s); sm_free(s); }

    // 55b: same, but the re-claim is by a DIFFERENT party B whose backing commit has
    // LOWER priority than the departed A's — B still mints fresh (a released name's
    // former owner priority is irrelevant once the row is gone).
    { SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, RATE_DAYS);
      SmTx t0 = {0}; tx1(&t0, 0xAA, 0); add_action(&t0, mk_commit("foo", A, 0x91), 0); sm_apply_tx(s, &t0);  // A commit (10, tx0) — higher priority
      SmTx t1 = {0}; tx1(&t1, 0xBB, 1); add_action(&t1, mk_commit("foo", B, 0x92), 0); sm_apply_tx(s, &t1);  // B commit (10, tx1) — lower priority
      sm_begin_block(s, 11, 1500, RATE_DAYS);
      SmTx tk = {0}; tx1(&tk, 0xAA, 0); add_action(&tk, mk_claim("foo", 0x91), 10); sm_apply_tx(s, &tk);      // A mints
      uint8_t rel[1] = { 0x01 };
      SmTx tr = {0}; tx1(&tr, 0xAA, 1); add_action(&tr, release_bits(11, rel, 1), 0); sm_apply_tx(s, &tr);   // A releases
      SmTx tk2 = {0}; tx1(&tk2, 0xBB, 2); add_action(&tk2, mk_claim("foo", 0x92), 10); sm_apply_tx(s, &tk2);  // B mints fresh (owns foo)
      emit_state(&comb, "55b_reclaim_by_other", s); sm_free(s); }

    // 56: a self-transfer (TRANSFER-all whose target == the current owner) is a real
    // move — it bumps last_set_mutation_height (owner's mut goes 11 → 12), NOT a no-op.
    { SmState *s = minted(0xAA, "bar", 10, 1500);
      sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmTx tt = {0}; tx1(&tt, 0xAA, 0); add_action(&tt, xfer_all(A), 0); sm_apply_tx(s, &tt);
      emit_state(&comb, "56_self_transfer_bumps_mut", s); sm_free(s); }

    // 57: fee oracle with block_bytes == 0 — the /0 guard substitutes divisor 1 (NOT
    // fee-per-byte 0), so the block still participates. 1000 blocks (== MIN_FEE_SAMPLE),
    // each fee 5000 ⇒ per-byte 5000 ⇒ median 5000 × REF_SIZE 200 = 1_000_000.
    { int64_t sub[1000], cb[1000], by[1000];
      for (int i = 0; i < 1000; i++) { sub[i] = 1000000000000LL; cb[i] = 1000000005000LL; by[i] = 0; }
      emit_u64(&comb, "57_oracle_zero_bytes", sm_oracle_rate(cb, sub, by, 1000)); }

    // 58: CLAIM burn near 2⁶⁴ at rate = DUST_FLOOR (1) — the lease day-count T overflows
    // 64 bits (computed in 128-bit / bignum, guarded so Go's bits.Div64 never panics)
    // and clamps to MAX_LEASE (365 days): lease_expiry = 1500 + 365·86400.
    { SmState *s = sm_new(0);
      sm_begin_block(s, 10, 1000, 1);
      SmTx tc = {0}; tx1(&tc, 0xAA, 0); add_action(&tc, mk_commit("foo", A, 0x95), 0); sm_apply_tx(s, &tc);
      sm_begin_block(s, 11, 1500, 1);
      SmTx tk = {0}; tx1(&tk, 0xAA, 0); add_action(&tk, mk_claim("foo", 0x95), 0xFFFFFFFFFFFFFFFFULL); sm_apply_tx(s, &tk);
      emit_state(&comb, "58_lease_clamp_huge_burn", s); sm_free(s); }

    // 59: RENEW_NAME (§3.5) — the by-name renew extends exactly the named lease
    // (no anchor, no bump); the same op from a non-owner drops (state unchanged).
    { SmState *s = minted(0xAA, "bar", 10, 1500);
      sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_RENEW_NAME;
      memcpy(a.name, "bar", 4); a.name_len = 3;
      SmTx t = {0}; tx1(&t, 0xAA, 0); add_action(&t, a, 7); sm_apply_tx(s, &t);    // +7 days
      SmTx t2 = {0}; tx1(&t2, 0xBB, 1); add_action(&t2, a, 7); sm_apply_tx(s, &t2); // not B's → drop
      emit_state(&comb, "59_renew_name", s); sm_free(s); }

    // 60: TRANSFER_NAME (§3.5/§3.6) — gifts exactly the named name to the target,
    // lease conveys, and the move bumps BOTH parties' last_set_mutation_height.
    { SmState *s = minted(0xAA, "bar", 10, 1500);
      sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_TRANSFER_NAME;
      memcpy(a.addr, B, 20); memcpy(a.name, "bar", 4); a.name_len = 3;
      SmTx t = {0}; tx1(&t, 0xAA, 0); add_action(&t, a, 0); sm_apply_tx(s, &t);
      emit_state(&comb, "60_transfer_name", s); sm_free(s); }

    // 61: RELEASE_NAME (§3.5/§3.6) — returns exactly the named name to the pool
    // (bump), and it is immediately reclaimable by a later CLAIM in the same block.
    { SmState *s = minted(0xAA, "bar", 10, 1500);
      sm_begin_block(s, 12, 1600, RATE_DAYS);
      SmAction a; memset(&a, 0, sizeof a); a.op = SM_OP_RELEASE_NAME;
      memcpy(a.name, "bar", 4); a.name_len = 3;
      SmTx t = {0}; tx1(&t, 0xAA, 0); add_action(&t, a, 0); sm_apply_tx(s, &t);
      emit_state(&comb, "61_release_name", s); sm_free(s); }

    uint8_t cd[32]; sha256_final(&comb, cd); char hx[65]; hexout(cd, 32, hx);
    printf("combined %s\n", hx);
    return 0;
}

// ── fork-risk differential vectors (TV-1..TV-8, fold layer) ──────────────────
// Runs each TV-N construction (see SPEC-RATIONALE.md) against THIS impl
// and reports whether impls/c's outcome matches the spec-pinned (2026-06-29) reading.
// A "*** DIVERGE ***" line is a confirmed divergence between impls/c and the hardened
// prose / the fresh-eyes Java reference. Non-destructive: touches no frozen golden.
static void fv_line(const char *tv, const char *desc, const char *got, const char *want) {
    int match = strcmp(got, want) == 0;
    printf("  %-6s %-42s impls/c=%-7s spec=%-7s %s\n", tv, desc, got, want,
           match ? "MATCH" : "*** DIVERGE ***");
    if (match) g_pass++; else g_fail++;
}

static int cmd_forkvectors(void) {
    uint8_t A[20], B[20], T[20];
    mk_h160(A, 0xAA); mk_h160(B, 0xBB); mk_h160(T, 0x77);

    // TV-1: COMMIT_EXPIRY inclusive — a claim at MTP == commit_time + COMMIT_EXPIRY mints.
    {
        SmState *s = sm_new(0);
        int64_t ct = 1000;
        sm_begin_block(s, 5, ct, RATE_DAYS);
        SmTx c = {0}; tx1(&c, 0xAA, 0); add_action(&c, mk_commit("edge", A, 0x11), 0); sm_apply_tx(s, &c);
        sm_begin_block(s, 6, ct + SM_COMMIT_EXPIRY, RATE_DAYS);     // MTP exactly at the boundary
        SmTx k = {0}; tx1(&k, 0xAA, 0); add_action(&k, mk_claim("edge", 0x11), 10); sm_apply_tx(s, &k);
        fv_line("TV-1", "COMMIT_EXPIRY inclusive boundary", sm_owns(s, A, "edge") ? "mint" : "drop", "mint");
        sm_free(s);
    }
    // TV-5b: one author, two matching commits (tx0,tx2) + rival (tx1) — author (min tx_index) wins.
    {
        SmState *s = sm_new(0);
        sm_begin_block(s, 5, 1000, RATE_DAYS);
        SmTx c0 = {0}; tx1(&c0, 0xAA, 0); add_action(&c0, mk_commit("dup", A, 0x11), 0); sm_apply_tx(s, &c0);
        SmTx c1 = {0}; tx1(&c1, 0xBB, 1); add_action(&c1, mk_commit("dup", B, 0x22), 0); sm_apply_tx(s, &c1);
        SmTx c2 = {0}; tx1(&c2, 0xAA, 2); add_action(&c2, mk_commit("dup", A, 0x11), 0); sm_apply_tx(s, &c2);
        sm_begin_block(s, 6, 1500, RATE_DAYS);
        SmTx kB = {0}; tx1(&kB, 0xBB, 0); add_action(&kB, mk_claim("dup", 0x22), 10); sm_apply_tx(s, &kB);   // rival first
        SmTx kA = {0}; tx1(&kA, 0xAA, 1); add_action(&kA, mk_claim("dup", 0x11), 10); sm_apply_tx(s, &kA);   // author second
        fv_line("TV-5b", "claim multiplicity (author min-tuple wins)",
                sm_owns(s, A, "dup") ? "A wins" : (sm_owns(s, B, "dup") ? "B wins" : "none"), "A wins");
        sm_free(s);
    }
    // TV-6: bitmap LSB-first — flag 0x01 selects lexicographic name 0 (aa).
    {
        SmState *s = sm_new(0);
        sm_begin_block(s, 5, 1000, RATE_DAYS);
        SmTx c = {0}; tx1(&c, 0xAA, 0);
        add_action(&c, mk_commit("aa", A, 0x01), 0); add_action(&c, mk_commit("bb", A, 0x02), 0);
        add_action(&c, mk_commit("cc", A, 0x03), 0); sm_apply_tx(s, &c);
        sm_begin_block(s, 6, 1500, RATE_DAYS);
        SmTx k = {0}; tx1(&k, 0xAA, 0);
        add_action(&k, mk_claim("aa", 0x01), 1); add_action(&k, mk_claim("bb", 0x02), 1);
        add_action(&k, mk_claim("cc", 0x03), 1); sm_apply_tx(s, &k);
        int64_t aa0 = sm_lookup(s, "aa")->lease_expiry, bb0 = sm_lookup(s, "bb")->lease_expiry;
        sm_begin_block(s, 7, 1600, RATE_DAYS);
        SmAction rn; memset(&rn, 0, sizeof rn); rn.op = SM_OP_RENEW; rn.has_anchor = 1; rn.anchor = 6; rn.flags[0] = 0x01; rn.flags_len = 1;
        SmTx r = {0}; tx1(&r, 0xAA, 0); add_action(&r, rn, 10); sm_apply_tx(s, &r);
        int aa_up = sm_lookup(s, "aa")->lease_expiry > aa0, bb_up = sm_lookup(s, "bb")->lease_expiry > bb0;
        fv_line("TV-6", "bitmap LSB-first (0x01 -> aa)", (aa_up && !bb_up) ? "aa" : "other", "aa");
        sm_free(s);
    }
    // TV-7: a pre-block LAPSE must bump last_set_mutation_height (§3.5) so a same-block selective
    // RENEW anchored at H-1 is REJECTED. (impls/c omits the lapse bump → it ACCEPTS → DIVERGE.)
    {
        SmState *s = sm_new(0);
        int64_t M = 1000000;
        sm_begin_block(s, 5, M, RATE_DAYS);
        SmTx c = {0}; tx1(&c, 0xAA, 0);
        add_action(&c, mk_commit("aa", A, 0x11), 0); add_action(&c, mk_commit("keep", A, 0x22), 0);
        sm_apply_tx(s, &c);
        sm_begin_block(s, 6, M, RATE_DAYS);
        SmTx k = {0}; tx1(&k, 0xAA, 0);
        add_action(&k, mk_claim("aa", 0x11), 1); add_action(&k, mk_claim("keep", 0x22), 100);
        sm_apply_tx(s, &k);
        int64_t aa_exp = sm_lookup(s, "aa")->lease_expiry, keep0 = sm_lookup(s, "keep")->lease_expiry;
        sm_begin_block(s, 7, aa_exp, RATE_DAYS);                    // "aa" lapses pre-block
        SmAction rn; memset(&rn, 0, sizeof rn); rn.op = SM_OP_RENEW; rn.has_anchor = 1; rn.anchor = 6; rn.flags[0] = 0x01; rn.flags_len = 1;
        SmTx r = {0}; tx1(&r, 0xAA, 0); add_action(&r, rn, 10); sm_apply_tx(s, &r);
        int keep_up = sm_lookup(s, "keep")->lease_expiry > keep0;
        fv_line("TV-7", "lapse bumps mutation height (stale RENEW)", keep_up ? "ACCEPT" : "REJECT", "REJECT");
        sm_free(s);
    }
    // TV-8: a selective TRANSFER selecting a LOCKED (listed) name skips it, moves the rest.
    {
        SmState *s = sm_new(0);
        sm_begin_block(s, 5, 1000, RATE_DAYS);
        SmTx c = {0}; tx1(&c, 0xAA, 0);
        add_action(&c, mk_commit("aa", A, 0x01), 0); add_action(&c, mk_commit("bb", A, 0x02), 0);
        add_action(&c, mk_commit("cc", A, 0x03), 0); sm_apply_tx(s, &c);
        sm_begin_block(s, 6, 1500, RATE_DAYS);
        SmTx k = {0}; tx1(&k, 0xAA, 0);
        add_action(&k, mk_claim("aa", 0x01), 200); add_action(&k, mk_claim("bb", 0x02), 200);
        add_action(&k, mk_claim("cc", 0x03), 200); sm_apply_tx(s, &k);
        sm_begin_block(s, 7, 1600, RATE_DAYS);
        SmTx sl = {0}; tx1(&sl, 0xAA, 0); add_action(&sl, sell(300, 0, "bb"), 0); sm_apply_tx(s, &sl);   // bb LISTED
        sm_begin_block(s, 8, 1700, RATE_DAYS);
        uint8_t f03[1] = { 0x03 };                                  // bits 0,1 → aa, bb
        SmTx x = {0}; tx1(&x, 0xAA, 0); add_action(&x, xfer_bits(6, f03, 1, T), 0); sm_apply_tx(s, &x);
        const SmNameRow *bb = sm_lookup(s, "bb");
        int ok = sm_owns(s, T, "aa") && bb && bb->st == SM_LISTED && memcmp(bb->seller, A, 20) == 0 && sm_owns(s, A, "cc");
        fv_line("TV-8", "locked-name selective skip", ok ? "skip" : "other", "skip");
        sm_free(s);
    }
    // M9: TRADE is attributed to its OWN named inputs (idxA/idxB), NOT the acting identity. A TRADE
    // whose vin[0] is ⊥ (did not sign SIGHASH_ALL) still settles iff both named parties are valid.
    {
        SmState *s = sm_new(0);
        sm_begin_block(s, 5, 1000, RATE_DAYS);
        SmTx ca = {0}; tx1(&ca, 0xAA, 0); add_action(&ca, mk_commit("na", A, 0x11), 0); sm_apply_tx(s, &ca);
        SmTx cb = {0}; tx1(&cb, 0xBB, 1); add_action(&cb, mk_commit("nb", B, 0x22), 0); sm_apply_tx(s, &cb);
        sm_begin_block(s, 6, 1100, RATE_DAYS);
        SmTx ka = {0}; tx1(&ka, 0xAA, 0); add_action(&ka, mk_claim("na", 0x11), 50); sm_apply_tx(s, &ka);
        SmTx kb = {0}; tx1(&kb, 0xBB, 1); add_action(&kb, mk_claim("nb", 0x22), 50); sm_apply_tx(s, &kb);
        sm_begin_block(s, 7, 1200, RATE_DAYS);
        SmTx t = {0}; t.txindex = 0;
        *sm_tx_input(&t) = id_of(0x99); t.in_sighash_all[0] = 0;   // vin[0] = ⊥ (no SIGHASH_ALL → acting identity bottom)
        *sm_tx_input(&t) = id_of(0xAA); t.in_sighash_all[1] = 1;   // party A
        *sm_tx_input(&t) = id_of(0xBB); t.in_sighash_all[2] = 1;   // party B
        add_action(&t, trade(1, 2, "na", "nb"), 0); sm_apply_tx(s, &t);
        int swap = sm_owns(s, B, "na") && sm_owns(s, A, "nb");
        fv_line("M9", "TRADE bypasses bottom acting identity", swap ? "swap" : "drop", "swap");
        sm_free(s);
    }

    printf("────\n");
    printf("forkvectors: %d match, %d diverge (fold layer + M9; attribution TV-11..14 settled by inspection)\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "selftest") == 0)   return selftest();
    if (argc >= 2 && strcmp(argv[1], "scenario") == 0)   return cmd_scenario();
    if (argc >= 2 && strcmp(argv[1], "random") == 0)     return cmd_random(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "invariants") == 0) return cmd_invariants(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "fuzz") == 0)       return sm_cmd_fuzz(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "bfuzz") == 0)      return sm_cmd_bfuzz(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "properties") == 0) return sm_cmd_properties(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "reorg") == 0)      return sm_cmd_reorg(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "reorgfuzz") == 0)  return sm_cmd_reorgfuzz(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "meta") == 0)       return sm_cmd_meta(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "coverage") == 0)   return sm_cmd_coverage(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "attrib") == 0)        return attrib_cmd_fuzz(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "attrib-scenario") == 0) return attrib_cmd_scenario(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "attrib-curve") == 0)   return attrib_cmd_curve();
    if (argc >= 2 && strcmp(argv[1], "ecmh") == 0)           return ecmh_cmd();
    if (argc >= 2 && strcmp(argv[1], "attrib-selftest") == 0) return attrib_selftest();
    if (argc >= 2 && strcmp(argv[1], "forkvectors") == 0)   return cmd_forkvectors();
    fprintf(stderr,
        "usage: %s <mode> ...\n"
        "  selftest                       PRNG/digest/fold/codec sanity + invariant battery\n"
        "  random     <seed> <count> [--trace N] [--cov]   seed-driven soak (fold agreement)\n"
        "  scenario                       directed adversarial conformance vectors + combined\n"
        "  ecmh                           pinned ECMH primitive vector set (H2C + multiset sum) + combined\n"
        "  fuzz       <seed> <count> [--cov]   differential fuzz: byte payloads → decode → fold\n"
        "  bfuzz      <seed> <count> [--cov]   boundary-cluster fuzz (values snapped to §-constants)\n"
        "  properties <seed> <count>          invariant battery + cross-language property_digest\n"
        "  reorg      <seed> <count>          replay / resume / clear-rebuild / fork confluence\n"
        "  reorgfuzz  <seed> <count>          reorg-depth fuzzer (64 PRNG fork/divergence trials)\n"
        "  meta       <seed> <count>          metamorphic drop-closed (inert actions are inert)\n"
        "  coverage   [seed] [count]          assert every generator + decode branch is exercised\n"
        "  invariants <seed> <count> [--cov]  structural battery + determinism replay\n", argv[0]);
    return 2;
}
