/* state_dns_test.c — the DNS overlay over sp_state, in isolation:
 * key/payload codecs, publish→zone→del→clear, the 8 KB budget, digests, the
 * expiry sweep, and a two-node gossip convergence run over an in-memory wire
 * (dnsnet is single-instance, so the "two nodes" share one process by swapping
 * which store the module is bound to — enough to prove the frame codecs and
 * the inv→get→dat cycle end-to-end). */
#include "dns_state.h"
#include "dns_net.h"
#include "zone.h"
#include "pepenet/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail;
#define CK(c, m) do { if (c) printf("  ok   %s\n", m); \
                      else { printf("  FAIL %s\n", m); g_fail++; } } while (0)

/* Coin prefixes. PN is the pep row; DN is the doge row. Tests may carry them. */
static const uint8_t MAG_PN[2] = { 0x50, 0x4E };
static const uint8_t MAG_DN[2] = { 0x44, 0x4E };

/* ── fake chain: one owner table + deterministic headers ─────────────────────── */
static uint32_t g_tip = 500;
static uint8_t g_owner160[20];
static int owner_live = 1;

static int fk_owner(void *u, const char *name, uint8_t owner[20]) {
    (void)u;
    if (!owner_live || strcmp(name, "zone") != 0) return 0;
    memcpy(owner, g_owner160, 20);
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

/* ── an in-memory wire: capture frames a "peer" is sent ──────────────────────── */
typedef struct { char cmd[16]; uint8_t pay[2 * DNS_BUDGET + 64]; int len; } Frame;
static Frame g_q[64]; static int g_qn;
static void wire_send(void *peer, const char *cmd, const uint8_t *pay, size_t n) {
    (void)peer;
    if (g_qn >= 64 || n > sizeof g_q[0].pay) return;
    snprintf(g_q[g_qn].cmd, sizeof g_q[g_qn].cmd, "%s", cmd);
    memcpy(g_q[g_qn].pay, pay, n);
    g_q[g_qn].len = (int)n;
    g_qn++;
}

int main(void) {
    uint8_t opriv[32], opub[33];
    testkey("owner", opriv, opub);
    sp_hash160(opub, 33, g_owner160);
    char err[128];

    printf("-- codecs --\n");
    {
        uint8_t key[SP_STATE_KEY_MAX];
        int kl = dns_key_pack("_443._tcp.WWW", 52, key, sizeof key);
        CK(kl == 13 + 2, "key packs (label + type)");
        char label[64]; uint16_t type;
        CK(dns_key_unpack(key, kl, label, &type) &&
           !strcmp(label, "_443._tcp.www") && type == 52,
           "key unpacks lowercased");
        uint8_t pay[600];
        uint8_t rd[4] = { 192, 0, 2, 9 };
        int pl = dns_payload_pack(3600, rd, 4, pay, sizeof pay);
        CK(pl > 4, "payload packs");
        uint32_t ttl; const uint8_t *prd; int prdl;
        CK(dns_payload_unpack(pay, pl, &ttl, &prd, &prdl) &&
           ttl == 3600 && prdl == 4 && !memcmp(prd, rd, 4),
           "payload unpacks");
        zone_rec r; memset(&r, 0, sizeof r);
        snprintf(r.label, sizeof r.label, "www"); r.type = 1; r.ttl = 60;
        r.rdlen = 4; memcpy(r.rdata, rd, 4);
        uint8_t car[128], dn[128];
        int cl = dns_rec_encode(&r, MAG_PN, car, sizeof car);
        CK(cl > 0 && cl <= DNS_ONCHAIN_MAX, "on-chain carrier fits 80B");
        CK(car[1] == 'P' && car[2] == 'N', "carrier wears the PN prefix");
        zone_rec r2;
        CK(dns_rec_decode(car, cl, MAG_PN, &r2) && r2.type == 1 && r2.ttl == 60 &&
           r2.rdlen == 4 && !strcmp(r2.label, "www"), "carrier decodes");
        int dnl = dns_rec_encode(&r, MAG_DN, dn, sizeof dn);
        zone_rec r3;
        CK(dnl == cl && dn[0] == 0xFF && dn[1] == 'D' && dn[2] == 'N' && dn[3] == car[3] &&
           memcmp(dn + 4, car + 4, (size_t)(cl - 4)) == 0,
           "DN twin matches PN except the magic");
        CK(dns_rec_decode(dn, dnl, MAG_DN, &r3) && r3.type == 1 && r3.ttl == 60 &&
           r3.rdlen == 4 && !strcmp(r3.label, "www"), "DN carrier round-trips");
        CK(!dns_rec_decode(dn, dnl, MAG_PN, &r3), "DN payload under the pep profile is ignored");
        CK(!dns_rec_decode(car, cl, MAG_DN, &r3), "PN payload under the doge profile is ignored");
        CK(dns_rec_encode(&r, NULL, dn, sizeof dn) < 0, "NULL magic refuses to encode");
        CK(!dns_rec_decode(car, cl, NULL, &r3), "NULL magic refuses to decode");
    }

    printf("-- publish → zone → del → clear --\n");
    SpState *st = sp_state_open(":memory:");
    {
        zone_rec r; memset(&r, 0, sizeof r);
        snprintf(r.label, sizeof r.label, "%s", ""); r.type = 1; r.ttl = 300;
        r.rdlen = 4; memcpy(r.rdata, (uint8_t[]){ 10, 0, 0, 1 }, 4);
        CK(dns_state_put(st, &ORC, "zone", &r, opriv, opub,
                         SP_CERT_NONE, NULL, 0, err, sizeof err) == 1,
           "apex A publishes");
        snprintf(r.label, sizeof r.label, "www");
        CK(dns_state_put(st, &ORC, "zone", &r, opriv, opub,
                         SP_CERT_NONE, NULL, 0, err, sizeof err) == 1,
           "www A publishes");
        CK(dns_state_put(st, &ORC, "zone", &r, opriv, opub,
                         SP_CERT_NONE, NULL, 0, err, sizeof err) == -1,
           "identical re-publish is a duplicate");
        r.ttl = 999;                             /* different op, same block */
        CK(dns_state_put(st, &ORC, "zone", &r, opriv, opub,
                         SP_CERT_NONE, NULL, 0, err, sizeof err) == 0,
           "same-block edit rate-limited");
        r.ttl = 300;
        zone z;
        CK(dns_state_zone(st, "zone", &z) == 2 && z.n == 2, "zone assembles (2 records)");
        CK(dns_state_del(st, &ORC, "zone", "www", 1, opriv, opub,
                         SP_CERT_NONE, NULL, 0, err, sizeof err) == 0,
           "del in the same block rate-limited (per-key)");
        /* deletes land a block later in real life; here: bump the tip is not
           possible (fixed fake), so delete the OTHER key to see a tombstone */
        CK(dns_state_del(st, &ORC, "zone", "mail", 1, opriv, opub,
                         SP_CERT_NONE, NULL, 0, err, sizeof err) == 1,
           "del of an absent key admits (tombstone)");
        CK(dns_state_zone(st, "zone", &z) == 2, "tombstone does not enter the zone");
        int64_t before = sp_state_sum(st, "zone");
        g_tip = 520;                             /* a new block arrives; the clear
                                                    anchors above the puts */
        CK(dns_state_clear(st, &ORC, "zone", opriv, opub,
                           SP_CERT_NONE, NULL, 0, err, sizeof err) == 1,
           "clear publishes");
        CK(dns_state_zone(st, "zone", &z) == 0, "clear voids the zone");
        CK(sp_state_sum(st, "zone") < before, "clear reclaims bytes");
        CK(sp_state_floor(st, "zone") == g_tip - SP_STATE_REORG, "floor at the clear anchor");
    }

    printf("-- budget --\n");
    {
        /* rdata is capped at ZONE_MAX_RDATA (512), so one op is ~600B and the
           8 KB budget holds ~13 of them; the 14th must bounce. */
        int admitted = 0, rejected = 0;
        for (int i = 0; i < 20; i++) {
            zone_rec r; memset(&r, 0, sizeof r);
            snprintf(r.label, sizeof r.label, "big%d", i);
            r.type = 16; r.ttl = 60;
            r.rdlen = ZONE_MAX_RDATA;
            memset(r.rdata, 'x', r.rdlen);
            int rc = dns_state_put(st, &ORC, "zone", &r, opriv, opub,
                                   SP_CERT_NONE, NULL, 0, err, sizeof err);
            if (rc == 1) admitted++;
            else { rejected++; CK(strstr(err, "budget") != NULL, "over-budget names the budget"); break; }
        }
        CK(admitted >= 10 && rejected == 1, "budget admits ~13 fat records then refuses");
        int64_t sum = sp_state_sum(st, "zone");
        CK(sum > 0 && sum <= DNS_BUDGET, "held bytes within 8 KB");
    }

    printf("-- digest --\n");
    {
        uint8_t d1[32], d2[32];
        dns_state_digest(st, "zone", d1);
        dns_state_digest(st, "zone", d2);
        CK(!memcmp(d1, d2, 32), "digest is deterministic");
        g_tip = 530;                              /* free room in the full budget:
                                                     tombstone one fat record */
        CK(dns_state_del(st, &ORC, "zone", "big0", 16, opriv, opub,
                         SP_CERT_NONE, NULL, 0, err, sizeof err) == 1,
           "del frees budget headroom");
        zone_rec r; memset(&r, 0, sizeof r);
        snprintf(r.label, sizeof r.label, "dig");
        r.type = 16; r.ttl = 60; r.rdlen = 3; memcpy(r.rdata, "abc", 3);
        CK(dns_state_put(st, &ORC, "zone", &r, opriv, opub,
                         SP_CERT_NONE, NULL, 0, err, sizeof err) == 1,
           "freed bytes admit the new record");
        dns_state_digest(st, "zone", d2);
        CK(memcmp(d1, d2, 32) != 0, "digest moves with the store");
    }

    printf("-- gossip: inv → get → dat --\n");
    {
        /* node A = `st` (has the zone), node B = empty store. One wire. */
        SpState *stB = sp_state_open(":memory:");
        dnsnet_init(st, ORC, 0);                 /* be node A */
        g_qn = 0;
        void *hA = dnsnet_up((void *)"B", wire_send);   /* A greets: full inv */
        CK(hA && g_qn >= 1 && !strcmp(g_q[0].cmd, "dnzinv"), "connect sends dnzinv");
        Frame inv = g_q[0];

        dnsnet_init(stB, ORC, 0);                /* be node B */
        g_qn = 0;
        void *hB = dnsnet_up((void *)"A", wire_send);
        g_qn = 0;                                /* drop B's (empty) greeting */
        dnsnet_msg(hB, inv.cmd + 2, inv.pay, inv.len);
        CK(g_qn == 1 && !strcmp(g_q[0].cmd, "dnzget"), "digest mismatch pulls (dnzget)");
        Frame get = g_q[0];

        dnsnet_init(st, ORC, 0);                 /* be node A again */
        g_qn = 0;
        hA = dnsnet_up((void *)"B", wire_send);
        g_qn = 0;
        dnsnet_msg(hA, get.cmd + 2, get.pay, get.len);
        CK(g_qn == 1 && !strcmp(g_q[0].cmd, "dnzdat"), "pull answered with the dump");
        Frame dat = g_q[0];

        dnsnet_init(stB, ORC, 0);                /* be node B again */
        g_qn = 0;
        hB = dnsnet_up((void *)"A", wire_send);
        g_qn = 0;
        dnsnet_msg(hB, dat.cmd + 2, dat.pay, dat.len);
        uint8_t dA[32], dB[32];
        dns_state_digest(st, "zone", dA);
        dns_state_digest(stB, "zone", dB);
        CK(!memcmp(dA, dB, 32), "dump admits — digests converge");
        zone z;
        CK(dns_state_zone(stB, "zone", &z) == dns_state_zone(st, "zone", &z),
           "node B serves the same zone");
        CK(g_qn >= 1 && !strcmp(g_q[0].cmd, "dnzinv"), "admitting re-announces");
        sp_state_close(stB);
    }

    printf("-- sweep --\n");
    {
        owner_live = 0;                          /* the lease lapses */
        CK(dns_state_sweep(st, &ORC) == 1, "sweep drops the lapsed name");
        CK(sp_state_sum(st, "zone") == 0, "its bytes are gone");
        owner_live = 1;
    }

    sp_state_close(st);
    if (g_fail) { printf("state_dns_test: %d FAILED\n", g_fail); return 1; }
    printf("state_dns_test: all passed\n");
    return 0;
}
