// state_test.c — the sp_state battery: codec, certs, and the admission matrix
// (LWW ordering, tombstones, clear/floor, budget, anchors, epochs, sweep).
//
// The chain is faked: header_at() answers a deterministic hash for heights
// <= FAKE_TIP and 0 above (exactly the contract a real header store gives),
// and the ownership view is view.c's test mode loaded from a temp file.
#include "pepenet/state.h"
#include "pepenet/view.h"
#include "pepenet/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_fail;
#define CK(c, m) do { if (c) printf("  ok   %s\n", m); \
                      else { printf("  FAIL %s\n", m); g_fail++; } } while (0)

// ── fake chain ───────────────────────────────────────────────────────────────
// headers exist in (HORIZON, TIP]; below the horizon answers -1 (checkpoint
// bootstrap), above the tip 0 (peer ahead of us).
#define FAKE_TIP     1000u
#define FAKE_HORIZON 50u
static int header_at(void *u, uint32_t height, uint8_t out[32]) {
    (void)u;
    if (height > FAKE_TIP) return 0;
    if (height <= FAKE_HORIZON) return -1;
    uint8_t seed[8] = { 'h','d','r',0,
                        (uint8_t)height, (uint8_t)(height >> 8),
                        (uint8_t)(height >> 16), (uint8_t)(height >> 24) };
    sp_sha256(seed, sizeof seed, out);
    return 1;
}
static void anchor_of(uint32_t h, uint8_t out[32]) {
    if (header_at(NULL, h, out) != 1) memset(out, 0xAB, 32);   // below-horizon ops
}
static uint32_t fake_tip(void *u) { (void)u; return FAKE_TIP; }
// oracle: ownership from a view.c test view, headers/tip from the fakes above
static int oracle_owner(void *u, const char *name, uint8_t owner[20]) {
    return sp_view_owner_now((SpView *)u, name, owner);
}
static SpChainOracle mkoracle(SpView *vw) {
    SpChainOracle o = { vw, oracle_owner, header_at, fake_tip };
    return o;
}

// deterministic test keys (never real funds)
static void testkey(const char *seed, uint8_t priv[32], uint8_t pub[33]) {
    sp_sha256((const uint8_t *)seed, strlen(seed), priv);
    while (!sp_pubkey(priv, pub)) sp_sha256(priv, 32, priv);
}

static SpView *mkview(const char *line1, const char *line2) {
    char path[128];
    snprintf(path, sizeof path, "/tmp/state_test_view_%d.txt", getpid());
    FILE *f = fopen(path, "w");
    if (line1) fprintf(f, "%s\n", line1);
    if (line2) fprintf(f, "%s\n", line2);
    fclose(f);
    return sp_view_open_test(path, FAKE_TIP);
}

static void hex20(const uint8_t b[20], char out[41]) {
    for (int i = 0; i < 20; i++) sprintf(out + 2 * i, "%02x", b[i]);
}

// build+admit helper: one PUT/DEL/CLEAR signed by (priv,pub), optional cert
static int emit(SpState *st, const SpChainOracle *o, uint8_t op, const char *name,
                const char *key, const char *payload, uint32_t anchor,
                const uint8_t priv[32], const uint8_t pub[33],
                int cert_type, const uint8_t *cert, int cert_len,
                int64_t budget, char *err, int errlen) {
    uint8_t ah[32]; anchor_of(anchor, ah);
    uint8_t blob[SP_STATE_OP_MAX];
    int n = sp_state_op_build(op, name,
                              (const uint8_t *)key, key ? (int)strlen(key) : 0,
                              (const uint8_t *)payload, payload ? (int)strlen(payload) : 0,
                              anchor, ah, priv, pub, cert_type, cert, cert_len,
                              blob, sizeof blob);
    if (n < 0) { snprintf(err, (size_t)errlen, "build failed"); return -99; }
    return sp_state_admit(st, o, budget, 0x20, blob, n, err, errlen);
}

int main(void) {
    uint8_t opriv[32], opub[33], o160[20];      // the owner
    uint8_t dpriv[32], dpub[33];                // a delegate (hot key)
    uint8_t xpriv[32], xpub[33], x160[20];      // a stranger / second owner
    testkey("owner", opriv, opub);  sp_hash160(opub, 33, o160);
    testkey("hot",   dpriv, dpub);
    testkey("thief", xpriv, xpub);  sp_hash160(xpub, 33, x160);

    char oh[41], xh[41]; hex20(o160, oh); hex20(x160, xh);
    char line1[80], line2[80];
    snprintf(line1, sizeof line1, "zone %s", oh);
    snprintf(line2, sizeof line2, "other %s", xh);
    SpView *vw = mkview(line1, line2);
    SpChainOracle orc = mkoracle(vw);
    SpState *st = sp_state_open(":memory:");
    char err[128];
    const int64_t B = 8192;

    printf("-- codec --\n");
    {
        uint8_t ah[32]; anchor_of(500, ah);
        uint8_t blob[512]; SpStateOp p;
        int n = sp_state_op_build(SP_OP_PUT, "zone", (const uint8_t *)"k1", 2,
                                  (const uint8_t *)"hello", 5, 500, ah,
                                  opriv, opub, SP_CERT_NONE, NULL, 0, blob, sizeof blob);
        CK(n > 0, "build PUT");
        CK(sp_state_op_parse(blob, n, &p), "parse PUT");
        CK(p.op == SP_OP_PUT && p.anchor == 500 && p.key_len == 2 &&
           p.payload_len == 5 && !memcmp(p.payload, "hello", 5), "fields round-trip");
        CK(!sp_state_op_parse(blob, n - 1, &p), "truncated rejects");
        blob[0] = 0x01;
        CK(!sp_state_op_parse(blob, n, &p), "wrong version rejects");
        blob[0] = SP_STATE_VER;
        int m = sp_state_op_build(SP_OP_DEL, "zone", (const uint8_t *)"k1", 2,
                                  NULL, 0, 500, ah, opriv, opub,
                                  SP_CERT_NONE, NULL, 0, blob, sizeof blob);
        CK(m > 0 && sp_state_op_parse(blob, m, &p) && p.op == SP_OP_DEL, "DEL round-trip");
        m = sp_state_op_build(SP_OP_CLEAR, "zone", NULL, 0, NULL, 0, 500, ah,
                              opriv, opub, SP_CERT_NONE, NULL, 0, blob, sizeof blob);
        CK(m > 0 && sp_state_op_parse(blob, m, &p) && p.op == SP_OP_CLEAR, "CLEAR round-trip");
        CK(sp_state_op_build(SP_OP_PUT, "zone", NULL, 0, (const uint8_t *)"x", 1,
                             500, ah, opriv, opub, SP_CERT_NONE, NULL, 0,
                             blob, sizeof blob) < 0, "PUT without key refuses to build");
    }

    printf("-- authority --\n");
    {
        CK(emit(st, &orc, SP_OP_PUT, "zone", "a", "1.2.3.4", 100,
                opriv, opub, SP_CERT_NONE, NULL, 0, B, err, sizeof err) == 1,
           "owner-signed PUT admits");
        CK(emit(st, &orc, SP_OP_PUT, "zone", "a", "6.6.6.6", 101,
                xpriv, xpub, SP_CERT_NONE, NULL, 0, B, err, sizeof err) == 0,
           "stranger-signed PUT rejects");
        CK(emit(st, &orc, SP_OP_PUT, "nope", "a", "1.2.3.4", 100,
                opriv, opub, SP_CERT_NONE, NULL, 0, B, err, sizeof err) == 0,
           "unowned name rejects");
    }

    printf("-- delegation certs --\n");
    {
        uint8_t cert[256];
        int cl = sp_cert_build_p2pkh((const uint8_t *)"zone", 4, opriv, dpub,
                                     0x20, 900, cert, sizeof cert);
        CK(cl > 0, "cert builds");
        SpCert c;
        CK(sp_cert_parse(SP_CERT_P2PKH, cert, cl, &c), "cert parses");
        CK(sp_cert_verify(&c, (const uint8_t *)"zone", 4, dpub, 200, o160),
           "cert verifies in window");
        CK(!sp_cert_verify(&c, (const uint8_t *)"zone", 4, dpub, 900, o160),
           "cert dead at not_after");
        CK(emit(st, &orc, SP_OP_PUT, "zone", "b", "delegated", 102,
                dpriv, dpub, SP_CERT_P2PKH, cert, cl, B, err, sizeof err) == 1,
           "delegate PUT under cert admits");
        int cl2 = sp_cert_build_p2pkh((const uint8_t *)"zone", 4, opriv, dpub,
                                      0x01, 900, cert, sizeof cert);   // wrong scope
        CK(emit(st, &orc, SP_OP_PUT, "zone", "c", "delegated", 103,
                dpriv, dpub, SP_CERT_P2PKH, cert, cl2, B, err, sizeof err) == 0,
           "cert without the overlay scope rejects");
        int cl3 = sp_cert_build_p2pkh((const uint8_t *)"zone", 4, xpriv, dpub,
                                      0x20, 900, cert, sizeof cert);   // stranger mints
        CK(emit(st, &orc, SP_OP_PUT, "zone", "c", "delegated", 103,
                dpriv, dpub, SP_CERT_P2PKH, cert, cl3, B, err, sizeof err) == 0,
           "cert minted by a non-owner rejects");
    }

    printf("-- LWW ordering --\n");
    {
        CK(emit(st, &orc, SP_OP_PUT, "zone", "a", "2.2.2.2", 105,
                opriv, opub, SP_CERT_NONE, NULL, 0, B, err, sizeof err) == 1,
           "higher anchor replaces");
        uint8_t *blob; int bl; SpStateOp p;
        sp_state_get(st, "zone", (const uint8_t *)"a", 1, &blob, &bl);
        sp_state_op_parse(blob, bl, &p);
        CK(p.payload_len == 7 && !memcmp(p.payload, "2.2.2.2", 7), "held row is the new op");
        free(blob);
        CK(emit(st, &orc, SP_OP_PUT, "zone", "a", "3.3.3.3", 105,
                opriv, opub, SP_CERT_NONE, NULL, 0, B, err, sizeof err) == 0,
           "same anchor rejects (rate limit)");
        CK(emit(st, &orc, SP_OP_PUT, "zone", "a", "old", 99,
                opriv, opub, SP_CERT_NONE, NULL, 0, B, err, sizeof err) == 0,
           "lower anchor (replay) rejects");
        // exact duplicate → -1: rebuild the identical op bytes
        uint8_t ah[32]; anchor_of(105, ah);
        uint8_t dupb[512];
        int dn = sp_state_op_build(SP_OP_PUT, "zone", (const uint8_t *)"a", 1,
                                   (const uint8_t *)"2.2.2.2", 7, 105, ah,
                                   opriv, opub, SP_CERT_NONE, NULL, 0, dupb, sizeof dupb);
        CK(sp_state_admit(st, &orc, B, 0x20, dupb, dn, err, sizeof err) == -1,
           "exact re-broadcast is a duplicate");
    }

    printf("-- anchors --\n");
    {
        CK(emit(st, &orc, SP_OP_PUT, "zone", "d", "x", FAKE_TIP + 10,
                opriv, opub, SP_CERT_NONE, NULL, 0, B, err, sizeof err) == -2,
           "anchor beyond tip holds (-2)");
        uint8_t wrong[32]; memset(wrong, 0xEE, 32);
        uint8_t blob[512];
        int n = sp_state_op_build(SP_OP_PUT, "zone", (const uint8_t *)"d", 1,
                                  (const uint8_t *)"x", 1, 200, wrong,
                                  opriv, opub, SP_CERT_NONE, NULL, 0, blob, sizeof blob);
        CK(sp_state_admit(st, &orc, B, 0x20, blob, n, err, sizeof err) == 0,
           "anchor hash off our chain rejects");
        CK(emit(st, &orc, SP_OP_PUT, "zone", "h", "ancient", FAKE_HORIZON - 20,
                opriv, opub, SP_CERT_NONE, NULL, 0, B, err, sizeof err) == 1,
           "anchor below the header horizon admits on the signature");
    }

    printf("-- tombstones --\n");
    {
        CK(emit(st, &orc, SP_OP_DEL, "zone", "a", NULL, 110,
                opriv, opub, SP_CERT_NONE, NULL, 0, B, err, sizeof err) == 1,
           "DEL admits over the PUT");
        CK(emit(st, &orc, SP_OP_PUT, "zone", "a", "2.2.2.2", 105,
                opriv, opub, SP_CERT_NONE, NULL, 0, B, err, sizeof err) == 0,
           "replayed old PUT loses to the tombstone");
        CK(emit(st, &orc, SP_OP_PUT, "zone", "a", "4.4.4.4", 120,
                opriv, opub, SP_CERT_NONE, NULL, 0, B, err, sizeof err) == 1,
           "fresh PUT supersedes the tombstone");
    }

    printf("-- clear / floor --\n");
    {
        // build some churn to void
        emit(st, &orc, SP_OP_DEL, "zone", "b", NULL, 130, opriv, opub, SP_CERT_NONE, NULL, 0, B, err, sizeof err);
        int64_t before = sp_state_sum(st, "zone");
        CK(before > 0, "sum tracks rows");
        CK(emit(st, &orc, SP_OP_CLEAR, "zone", NULL, NULL, 300,
                opriv, opub, SP_CERT_NONE, NULL, 0, B, err, sizeof err) == 1,
           "clear admits");
        CK(sp_state_floor(st, "zone") == 300, "floor is the clear anchor");
        uint8_t *cb2; int cbl;
        CK(sp_state_clear_get(st, "zone", &cb2, &cbl) && cbl > 0, "clear blob is held (gossip proof)");
        free(cb2);
        CK(sp_state_sum(st, "zone") < before, "voided rows freed their bytes");
        CK(emit(st, &orc, SP_OP_PUT, "zone", "a", "9.9.9.9", 250,
                opriv, opub, SP_CERT_NONE, NULL, 0, B, err, sizeof err) == 0,
           "op below the floor rejects");
        CK(emit(st, &orc, SP_OP_PUT, "zone", "a", "9.9.9.9", 300,
                opriv, opub, SP_CERT_NONE, NULL, 0, B, err, sizeof err) == 1,
           "republish AT the clear anchor admits");
        CK(emit(st, &orc, SP_OP_CLEAR, "zone", NULL, NULL, 300,
                opriv, opub, SP_CERT_NONE, NULL, 0, B, err, sizeof err) == -1,
           "identical clear re-broadcast is a duplicate");
        CK(emit(st, &orc, SP_OP_CLEAR, "zone", NULL, NULL, 299,
                opriv, opub, SP_CERT_NONE, NULL, 0, B, err, sizeof err) == 0,
           "older clear rejects");
    }

    printf("-- budget --\n");
    {
        char big[600]; memset(big, 'x', sizeof big - 1); big[sizeof big - 1] = 0;
        int64_t tight = 1000;   // fits one big record + envelope, not two
        SpState *st2 = sp_state_open(":memory:");
        CK(emit(st2, &orc, SP_OP_PUT, "zone", "k1", big, 100,
                opriv, opub, SP_CERT_NONE, NULL, 0, tight, err, sizeof err) == 1,
           "first record fits the tight budget");
        CK(emit(st2, &orc, SP_OP_PUT, "zone", "k2", big, 101,
                opriv, opub, SP_CERT_NONE, NULL, 0, tight, err, sizeof err) == 0,
           "second record over budget rejects");
        CK(emit(st2, &orc, SP_OP_PUT, "zone", "k1", "tiny", 102,
                opriv, opub, SP_CERT_NONE, NULL, 0, tight, err, sizeof err) == 1,
           "shrinking the same key frees bytes (edit never bricks)");
        CK(emit(st2, &orc, SP_OP_PUT, "zone", "k2", big, 103,
                opriv, opub, SP_CERT_NONE, NULL, 0, tight, err, sizeof err) == 1,
           "freed bytes admit the new record");
        int64_t sum = sp_state_sum(st2, "zone");
        CK(sum > 0 && sum <= tight, "sum stays within budget");
        sp_state_close(st2);
    }

    printf("-- epochs (owner change) --\n");
    {
        // same names file, but "zone" now belongs to the stranger
        char l1[80]; snprintf(l1, sizeof l1, "zone %s", xh);
        SpView *vw2 = mkview(l1, line2);
        SpChainOracle orc2 = mkoracle(vw2);
        CK(emit(st, &orc, SP_OP_PUT, "zone", "e", "epoch1", 400,
                opriv, opub, SP_CERT_NONE, NULL, 0, B, err, sizeof err) == 1,
           "old epoch still writable pre-transfer");
        CK(emit(st, &orc2, SP_OP_PUT, "zone", "e", "epoch2", FAKE_TIP - SP_STATE_REORG,
                xpriv, xpub, SP_CERT_NONE, NULL, 0, B, err, sizeof err) == 1,
           "new owner's first op wipes the epoch and admits");
        CK(sp_state_floor(st, "zone") >= FAKE_TIP - SP_STATE_REORG,
           "epoch wipe raised the floor");
        uint8_t *blob; int bl;
        CK(!sp_state_get(st, "zone", (const uint8_t *)"a", 1, &blob, &bl),
           "prior epoch's rows are gone");
        CK(emit(st, &orc2, SP_OP_PUT, "zone", "a", "9.9.9.9", 300,
                opriv, opub, SP_CERT_NONE, NULL, 0, B, err, sizeof err) == 0,
           "prior owner's replay rejects after transfer");
        sp_view_close(vw2);
    }

    printf("-- sweep --\n");
    {
        sp_state_drop_name(st, "zone");
        CK(sp_state_sum(st, "zone") == 0 && sp_state_floor(st, "zone") == 0,
           "drop_name removes rows and meta");
    }

    sp_state_close(st);
    sp_view_close(vw);
    if (g_fail) { printf("state_test: %d FAILED\n", g_fail); return 1; }
    printf("state_test: all passed\n");
    return 0;
}
