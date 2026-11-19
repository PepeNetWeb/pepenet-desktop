/* dnsd_core_test.c — src/dnsd_core.c's query -> answer path, end to end and
 * entirely in-process: a real sp_state store (":memory:"), a fake chain oracle,
 * real records published through dns_state_put, and real wire built by
 * dns_wire. No sockets are opened and no port is bound.
 *
 * PROVEN HERE
 *   • RESOLUTION: a known name answers with the exact rdata that was published,
 *     at the apex and at subdomains, for A / AAAA / TXT / TLSA / ANY, and an
 *     A query on a CNAME-only label falls back to the CNAME.
 *   • NEGATIVE ANSWERS, and WHICH one: NXDOMAIN for an unknown label, for an
 *     apex this server does not host, and for an apex that is not a valid §3.1
 *     pepenet name; REFUSED for a name outside the server's TLD and for a class
 *     other than IN; NOERROR with zero answers (NODATA) for a known label with
 *     no record of the asked type.
 *   • NEVER A WRONG ANSWER: across a matrix of names x types, every answer RR
 *     returned carries the requested owner and the requested type (or the query
 *     was ANY), class IN — and every non-NOERROR response is empty.
 *   • ECHO INTEGRITY: over 2000 seeded-random queries the response's
 *     transaction ID and the whole question section are byte-identical to the
 *     request's, with QR/AA set, opcode and RD echoed, RA and Z clear. An ID or
 *     question mismatch is a cache-poisoning vector, so this is exact.
 *   • CASE-INSENSITIVITY of the name match (label, apex and TLD).
 *   • EDNS0 / TC: the OPT is echoed with our 1232-byte cap, an over-budget UDP
 *     answer sets TC and drops the RRs, and the same query over TCP returns
 *     them all. Answers never exceed the negotiated budget.
 *   • THE ACCEPTANCE TEST — the --tls-redirect DANE policy, including the exact
 *     documented case of a subdomain that has an A record but NO _443._tcp
 *     TLSA (README: "Names without a _443._tcp TLSA are untouched"; pepenet-tls
 *     origin.h: "No TLSA => the origin cannot be DANE-authenticated, so it is
 *     NOT servable ... never fall back to an unverified connection" — so the
 *     resolver must NOT steer such a name at the proxy).
 *   • the two zone-level user bugs (a label that carries the TLD suffix; a CNAME
 *     pointing at an IP literal): that zone_build_rec now refuses both, AND —
 *     since the store is also fed by gossip from other peers — the end-to-end
 *     behaviour if such a record reaches the store anyway, injected raw here.
 *   • buffer safety: dnsd_core_answer against every output cap from 0 upwards,
 *     with 0xA5 canaries past the cap.
 */
#include "dnsd_core.h"
#include "dns_state.h"
#include "dns_wire.h"
#include "zone.h"
#include "pepenet/crypto.h"

#include <ctype.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_ok, g_fail;
#define CK(c, m) do { if (c) { g_ok++; printf("  ok   %s\n", m); } \
                      else { g_fail++; printf("  FAIL %s\n", m); } } while (0)

/* ── SplitMix64 (never rand(); the seed is printed) ──────────────────────── */
static uint64_t g_seed, g_s;
static uint64_t sm64(void) {
    uint64_t z = (g_s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static uint32_t rnd(uint32_t n) { return n ? (uint32_t)(sm64() % n) : 0u; }

/* ── fake chain: owns "pepenet" and "gpt", nothing else ──────────────────── */
static uint32_t g_tip = 500;
static uint8_t  g_owner160[20];
static int fk_owner(void *u, const char *name, uint8_t owner[20]) {
    (void)u;
    if (strcmp(name, "pepenet") != 0 && strcmp(name, "gpt") != 0) return 0;
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

/* ── wire helpers ────────────────────────────────────────────────────────── */
static void p16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint16_t g16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

static size_t mkquery(uint8_t *b, size_t cap, uint16_t id, uint16_t flags,
                      const char *qname, uint16_t qtype, uint16_t qclass,
                      int edns, uint16_t payload) {
    if (cap < 12) return 0;
    p16(b, id); p16(b + 2, flags);
    p16(b + 4, 1); p16(b + 6, 0); p16(b + 8, 0); p16(b + 10, edns ? 1 : 0);
    size_t o = 12;
    int n = dns_encode_name(b + o, cap - o, qname);
    if (n < 0) return 0;
    o += (size_t)n;
    p16(b + o, qtype); o += 2; p16(b + o, qclass); o += 2;
    if (edns) {
        b[o++] = 0; p16(b + o, 41); o += 2; p16(b + o, payload); o += 2;
        b[o++] = 0; b[o++] = 0; b[o++] = 0; b[o++] = 0; p16(b + o, 0); o += 2;
    }
    return o;
}

/* one decoded answer RR */
typedef struct { char owner[300]; uint16_t type, cls; uint32_t ttl;
                 uint16_t rdlen; uint8_t rd[600]; } ans;
typedef struct {
    int      valid;
    uint16_t id, flags;
    int      qd, an, ns, ar;
    char     qname[300];
    uint16_t qtype, qclass;
    size_t   qsec_off, qsec_len;   /* the raw question-section bytes */
    ans      a[32];
    int      na;
    int      opt;                  /* an OPT pseudo-RR was present */
    uint16_t opt_payload;
    uint8_t  opt_version;
} resp;

static int rd_name(const uint8_t *b, size_t len, size_t *off, char *out, size_t cap) {
    size_t p = *off, o = 0; int jumped = 0, guard = 0; size_t adv = 0;
    for (;;) {
        if (p >= len) return -1;
        uint8_t l = b[p];
        if ((l & 0xC0) == 0xC0) {
            if (p + 1 >= len || ++guard > 64) return -1;
            size_t t = ((size_t)(l & 0x3F) << 8) | b[p + 1];
            if (!jumped) { adv = p + 2; jumped = 1; }
            if (t >= len) return -1;
            p = t; continue;
        }
        if ((l & 0xC0) != 0) return -1;
        if (l == 0) { if (!jumped) adv = p + 1; break; }
        p++;
        if (p + l > len) return -1;
        if (o && o + 1 < cap) out[o++] = '.';
        if (o + l >= cap) return -1;
        for (uint8_t i = 0; i < l; i++) out[o++] = (char)tolower(b[p + i]);
        p += l;
    }
    out[o] = '\0'; *off = adv; return 0;
}

static void decode(const uint8_t *b, size_t len, resp *r) {
    memset(r, 0, sizeof *r);
    if (len < 12) return;
    r->id = g16(b); r->flags = g16(b + 2);
    r->qd = g16(b + 4); r->an = g16(b + 6); r->ns = g16(b + 8); r->ar = g16(b + 10);
    size_t off = 12;
    r->qsec_off = 12;
    if (r->qd != 1) return;
    if (rd_name(b, len, &off, r->qname, sizeof r->qname) != 0) return;
    if (off + 4 > len) return;
    r->qtype = g16(b + off); r->qclass = g16(b + off + 2); off += 4;
    r->qsec_len = off - 12;
    for (int i = 0; i < r->an && r->na < 32; i++) {
        ans *a = &r->a[r->na];
        if (rd_name(b, len, &off, a->owner, sizeof a->owner) != 0) return;
        if (off + 10 > len) return;
        a->type = g16(b + off); a->cls = g16(b + off + 2);
        a->ttl = ((uint32_t)b[off + 4] << 24) | ((uint32_t)b[off + 5] << 16) |
                 ((uint32_t)b[off + 6] << 8) | b[off + 7];
        a->rdlen = g16(b + off + 8); off += 10;
        if (off + a->rdlen > len || a->rdlen > sizeof a->rd) return;
        memcpy(a->rd, b + off, a->rdlen); off += a->rdlen;
        r->na++;
    }
    for (int i = 0; i < r->ar; i++) {
        char nm[300];
        if (rd_name(b, len, &off, nm, sizeof nm) != 0) return;
        if (off + 10 > len) return;
        if (g16(b + off) == 41) { r->opt = 1; r->opt_payload = g16(b + off + 2);
                                  r->opt_version = b[off + 5]; }
        off += 10 + g16(b + off + 8);
        if (off > len) return;
    }
    r->valid = (off == len);
}

/* ── the core under test ─────────────────────────────────────────────────── */
static DnsdCore DC;
static uint8_t g_req[1024], g_out[4096];
static size_t  g_reqlen, g_outlen;

/* ask: build the query, run the core, decode the answer. Returns rcode. */
static int ask_ex(const char *qname, uint16_t qtype, uint16_t qclass,
                  int edns, uint16_t payload, int over_tcp, uint16_t id, resp *r) {
    g_reqlen = mkquery(g_req, sizeof g_req, id, 0x0100, qname, qtype, qclass, edns, payload);
    if (g_reqlen == 0) { memset(r, 0, sizeof *r); return -1; }
    dns_query q;
    if (dns_parse_query(g_req, g_reqlen, &q) != 0) { memset(r, 0, sizeof *r); return -1; }
    memset(g_out, 0, sizeof g_out);
    g_outlen = dnsd_core_answer(&DC, &q, g_out, sizeof g_out, over_tcp);
    decode(g_out, g_outlen, r);
    return g_outlen ? (r->flags & 0xF) : -1;
}
static int ask(const char *qname, uint16_t qtype, resp *r) {
    return ask_ex(qname, qtype, DNS_CLASS_IN, 0, 0, 0, 0x2A2A, r);
}
/* is the request's whole question section byte-identical in the response? */
static int qsec_echoed(const resp *r) {
    if (!r->qsec_len || g_reqlen < 12 + r->qsec_len || g_outlen < 12 + r->qsec_len) return 0;
    size_t rq = g_reqlen - 12;
    /* the request's question runs from 12 to the end (no OPT) or to the OPT */
    if (g16(g_req + 10)) rq -= 11;
    return rq == r->qsec_len && memcmp(g_req + 12, g_out + 12, rq) == 0;
}

/* ── record fixtures ─────────────────────────────────────────────────────── */
static uint8_t OPRIV[32], OPUB[33];
static char g_err[160];

static int put(SpState *st, const char *name, const char *label,
               const char *type, uint32_t ttl, const char *text) {
    zone_rec r;
    if (zone_build_rec(label, type, ttl, text, &r) != 0) return -99;
    return dns_state_put(st, &ORC, name, &r, OPRIV, OPUB, SP_CERT_NONE, NULL, 0,
                         g_err, sizeof g_err);
}

/* Publish a record WITHOUT going through zone_build_rec's policy checks, by
 * filling the zone_rec directly. Needed for the two records of section_user_bugs:
 * the text front door now refuses them (a label carrying the TLD suffix, and a
 * CNAME whose target is an IP literal — see zone_test), but the store is fed by
 * gossip from other peers too, and dnsd_core has no say in what arrives there.
 * So the resolver's behaviour on such rows still has to be pinned end to end. */
static int put_raw(SpState *st, const char *name, const char *label,
                   uint16_t type, uint32_t ttl, const uint8_t *rd, uint16_t rdlen) {
    zone_rec r;
    memset(&r, 0, sizeof r);
    snprintf(r.label, sizeof r.label, "%s", label);
    r.type = type; r.ttl = ttl; r.rdlen = rdlen;
    memcpy(r.rdata, rd, rdlen);
    return dns_state_put(st, &ORC, name, &r, OPRIV, OPUB, SP_CERT_NONE, NULL, 0,
                         g_err, sizeof g_err);
}

static const char HEX32[] = "0123456789abcdef0123456789abcdef"
                            "0123456789abcdef0123456789abcdef";

static void publish(SpState *st) {
    int bad = 0;
    struct { const char *zone, *label, *type, *text; } R[] = {
        { "pepenet", "@",              "A",     "10.0.0.1" },
        { "pepenet", "www",            "A",     "10.0.0.2" },
        { "pepenet", "www",            "AAAA",  "2001:db8::2" },
        { "pepenet", "plain",          "A",     "10.0.0.9" },   /* A, NO TLSA */
        { "pepenet", "alias",          "CNAME", "www.pepenet.pepe" },
        { "pepenet", "txt",            "TXT",   "\"hello world\"" },
        { "pepenet", "_443._tcp",      "TLSA",  NULL },
        { "pepenet", "_443._tcp.www",  "TLSA",  NULL },
        { "gpt",     "@",              "A",     "10.1.1.1" },
    };
    char tlsa[128]; snprintf(tlsa, sizeof tlsa, "3 1 1 %s", HEX32);
    for (unsigned i = 0; i < sizeof R / sizeof R[0]; i++) {
        const char *txt = R[i].text ? R[i].text : tlsa;
        int rc = put(st, R[i].zone, R[i].label, R[i].type, 300, txt);
        if (rc != 1) { bad++; printf("       publish %s/%s %s -> rc=%d %s\n",
                                     R[i].zone, R[i].label, R[i].type, rc, g_err); }
    }
    /* a fat label, for the UDP-budget / TC proof */
    { char big[600]; big[0] = '"'; memset(big + 1, 'x', 250); strcpy(big + 251, "\"");
      if (put(st, "pepenet", "big", "TXT", 300, big) != 1) bad++; }
    { char hex[1100]; for (int i = 0; i < 400; i++) memcpy(hex + 2 * i, "ab", 2);
      hex[800] = '\0';
      if (put(st, "pepenet", "big", "OPENPGPKEY", 300, hex) != 1) bad++; }
    if (put(st, "pepenet", "big", "A", 300, "10.0.0.7") != 1) bad++;
    if (put(st, "pepenet", "big", "AAAA", 300, "2001:db8::7") != 1) bad++;
    CK(bad == 0, "every fixture record publishes into the store");

    /* The two zone-level user bugs, as store rows. zone_build_rec now refuses
     * both (asserted in section_user_bugs), so they enter by the raw route —
     * the shape a peer's gossiped op would take — and section_user_bugs proves
     * what dnsd_core does when it meets them. */
    int raw = 0;
    { uint8_t ip[4] = { 216, 24, 57, 1 };                       /* the fold bug */
      if (put_raw(st, "gpt", "gpt.pepe", DNS_A, 300, ip, 4) != 1) raw++; }
    { uint8_t nm[64];                                           /* the literal bug */
      int n = dns_encode_name(nm, sizeof nm, "216.24.57.1");
      if (n != 13 || put_raw(st, "gpt", "bad", DNS_CNAME, 300, nm, (uint16_t)n) != 1) raw++; }
    CK(raw == 0, "the two policy-refused records still reach the store by the raw route");
}

/* ═══════════ resolution ════════════════════════════════════════════════ */
static void section_resolve(void) {
    resp r;
    CK(ask("www.pepenet.pepe", DNS_A, &r) == DNS_RCODE_NOERROR && r.valid &&
       r.na == 1 && r.a[0].type == DNS_A && r.a[0].cls == DNS_CLASS_IN &&
       r.a[0].rdlen == 4 && memcmp(r.a[0].rd, "\x0a\x00\x00\x02", 4) == 0 &&
       strcmp(r.a[0].owner, "www.pepenet.pepe") == 0 && r.a[0].ttl == 300,
       "a known subdomain resolves with the exact published rdata");

    CK(ask("pepenet.pepe", DNS_A, &r) == DNS_RCODE_NOERROR && r.na == 1 &&
       memcmp(r.a[0].rd, "\x0a\x00\x00\x01", 4) == 0,
       "the apex resolves (empty label)");

    CK(ask("www.pepenet.pepe", DNS_AAAA, &r) == DNS_RCODE_NOERROR && r.na == 1 &&
       r.a[0].type == DNS_AAAA && r.a[0].rdlen == 16 && r.a[0].rd[0] == 0x20,
       "AAAA resolves with 16 bytes of rdata");

    CK(ask("txt.pepenet.pepe", DNS_TXT, &r) == DNS_RCODE_NOERROR && r.na == 1 &&
       r.a[0].rdlen == 12 && r.a[0].rd[0] == 11 &&
       memcmp(r.a[0].rd + 1, "hello world", 11) == 0, "TXT resolves");

    CK(ask("_443._tcp.www.pepenet.pepe", DNS_TLSA, &r) == DNS_RCODE_NOERROR &&
       r.na == 1 && r.a[0].type == DNS_TLSA && r.a[0].rdlen == 35 &&
       r.a[0].rd[0] == 3 && r.a[0].rd[1] == 1 && r.a[0].rd[2] == 1,
       "a DANE TLSA at _443._tcp.<sub> resolves");

    CK(ask("www.pepenet.pepe", 255, &r) == DNS_RCODE_NOERROR && r.na == 2,
       "ANY returns every record at the label");

    CK(ask("alias.pepenet.pepe", DNS_A, &r) == DNS_RCODE_NOERROR && r.na == 1 &&
       r.a[0].type == DNS_CNAME, "an A query on a CNAME-only label returns the CNAME");
    CK(ask("alias.pepenet.pepe", DNS_CNAME, &r) == DNS_RCODE_NOERROR && r.na == 1 &&
       r.a[0].type == DNS_CNAME, "a CNAME query returns the CNAME once, not twice");
}

/* ═══════════ case insensitivity ════════════════════════════════════════ */
static void section_case(void) {
    resp lo, hi;
    ask("www.pepenet.pepe", DNS_A, &lo);
    CK(ask("WWW.PEPENET.PEPE", DNS_A, &hi) == DNS_RCODE_NOERROR && hi.na == lo.na &&
       hi.na == 1 && memcmp(hi.a[0].rd, lo.a[0].rd, 4) == 0,
       "an all-uppercase query resolves identically");
    CK(ask("wWw.PePeNeT.pEpE", DNS_A, &hi) == DNS_RCODE_NOERROR && hi.na == 1,
       "mixed case in label, apex and TLD all match");
    CK(ask("_443._TCP.WwW.pepenet.pepe", DNS_TLSA, &hi) == DNS_RCODE_NOERROR &&
       hi.na == 1, "a mixed-case multi-label subdomain matches");

    /* dns_parse_query keeps the request's own octets in qname_orig (qname stays
     * lowercased, for matching) and dns_resp_begin re-emits qname_orig, so the
     * response's question section is byte-identical to the request's. RFC 1035
     * §4.1.2 requires the question to be copied from the query; a client using
     * DNS-0x20 case randomisation (the standard off-path spoofing defence)
     * discards any answer that folds it. */
    ask_ex("WwW.PePeNeT.PePe", DNS_A, DNS_CLASS_IN, 0, 0, 0, 0x1234, &hi);
    printf("       request qname 'WwW.PePeNeT.PePe' -> response question '%s'\n", hi.qname);
    CK(qsec_echoed(&hi), "[RFC 1035 4.1.2] a mixed-case question is echoed byte-for-byte");
}

/* ═══════════ negative answers ══════════════════════════════════════════ */
static void section_negative(void) {
    resp r;
    CK(ask("nope.pepenet.pepe", DNS_A, &r) == DNS_RCODE_NXDOMAIN && r.na == 0,
       "an unknown label in a hosted zone is NXDOMAIN with no answers");
    CK(ask("a.b.c.pepenet.pepe", DNS_A, &r) == DNS_RCODE_NXDOMAIN && r.na == 0,
       "a deep unknown subdomain is NXDOMAIN");
    CK(ask("nobody.pepe", DNS_A, &r) == DNS_RCODE_NXDOMAIN && r.na == 0,
       "an apex this server does not host is NXDOMAIN, not REFUSED");
    CK(ask("www.nobody.pepe", DNS_A, &r) == DNS_RCODE_NXDOMAIN && r.na == 0,
       "a subdomain of an unhosted apex is NXDOMAIN");

    CK(ask("www.pepenet.pepe", DNS_MX, &r) == DNS_RCODE_NOERROR && r.na == 0,
       "a known label with no record of that type is NODATA (NOERROR, 0 answers)");
    CK(ask("www.pepenet.pepe", DNS_TLSA, &r) == DNS_RCODE_NOERROR && r.na == 0,
       "a known label with no TLSA is NODATA, never a wrong record");

    CK(ask("example.com", DNS_A, &r) == DNS_RCODE_REFUSED && r.na == 0,
       "a name outside the server's TLD is REFUSED");
    CK(ask("pepe", DNS_A, &r) == DNS_RCODE_REFUSED && r.na == 0,
       "the bare TLD is REFUSED");
    CK(ask("", DNS_A, &r) == DNS_RCODE_REFUSED && r.na == 0,
       "the root name is REFUSED");
    CK(ask("notpepe", DNS_A, &r) == DNS_RCODE_REFUSED && r.na == 0,
       "a name that merely ends in the TLD's letters is REFUSED");
    CK(ask("xpepe", DNS_A, &r) == DNS_RCODE_REFUSED && r.na == 0,
       "a suffix match must be on a label boundary");

    /* apexes that are not valid §3.1 pepenet names */
    CK(ask("ab--cd.pepe", DNS_A, &r) == DNS_RCODE_NXDOMAIN && r.na == 0,
       "an ACE-prefixed apex (-- at 3-4) is NXDOMAIN");
    CK(ask("-lead.pepe", DNS_A, &r) == DNS_RCODE_NXDOMAIN && r.na == 0,
       "an apex with a leading hyphen is NXDOMAIN");
    CK(ask("under_score.pepe", DNS_A, &r) == DNS_RCODE_NXDOMAIN && r.na == 0,
       "an apex outside [a-z0-9-] is NXDOMAIN");
    { char n[80]; memset(n, 'a', 33); strcpy(n + 33, ".pepe");
      CK(ask(n, DNS_A, &r) == DNS_RCODE_NXDOMAIN && r.na == 0,
         "a 33-byte apex (over SP_NAME_MAX) is NXDOMAIN"); }

    /* class */
    CK(ask_ex("www.pepenet.pepe", DNS_A, 3 /* CH */, 0, 0, 0, 1, &r) == DNS_RCODE_REFUSED &&
       r.na == 0, "a CHAOS-class query is REFUSED with no answers");
    CK(ask_ex("www.pepenet.pepe", DNS_A, 255 /* ANY class */, 0, 0, 0, 1, &r) ==
       DNS_RCODE_REFUSED && r.na == 0, "class ANY is REFUSED (we serve IN only)");
    CK(ask_ex("www.pepenet.pepe", DNS_A, 0, 0, 0, 0, 1, &r) == DNS_RCODE_REFUSED,
       "class 0 is REFUSED");
    CK(ask_ex("example.com", DNS_A, 3, 0, 0, 0, 1, &r) == DNS_RCODE_REFUSED,
       "a wrong-class query for an unhosted name is still REFUSED");
}

/* ═══════════ never a wrong answer + echo integrity ═════════════════════ */
static void section_integrity(void) {
    static const char *NAMES[] = {
        "www.pepenet.pepe", "pepenet.pepe", "plain.pepenet.pepe",
        "alias.pepenet.pepe", "txt.pepenet.pepe", "big.pepenet.pepe",
        "_443._tcp.www.pepenet.pepe", "_443._tcp.pepenet.pepe",
        "nope.pepenet.pepe", "nobody.pepe", "example.com", "pepe", "",
        "gpt.pepe", "gpt.pepe.gpt.pepe", "bad.gpt.pepe", "ab--cd.pepe",
    };
    static const uint16_t QT[] = { DNS_A, DNS_AAAA, DNS_CNAME, DNS_NS, DNS_MX,
                                   DNS_TXT, DNS_TLSA, DNS_SOA, 255, 65535 };
    int wrong_owner = 0, wrong_type = 0, wrong_class = 0, nonempty_err = 0, undecodable = 0;
    int cases = 0;
    resp r;
    for (unsigned i = 0; i < sizeof NAMES / sizeof NAMES[0]; i++)
        for (unsigned t = 0; t < sizeof QT / sizeof QT[0]; t++) {
            int rc = ask(NAMES[i], QT[t], &r);
            cases++;
            if (rc < 0) { undecodable++; continue; }
            if (!r.valid) { undecodable++; continue; }
            if (rc != DNS_RCODE_NOERROR && r.na != 0) nonempty_err++;
            for (int k = 0; k < r.na; k++) {
                if (strcasecmp(r.a[k].owner, r.qname) != 0) wrong_owner++;
                if (r.a[k].cls != DNS_CLASS_IN) wrong_class++;
                if (QT[t] != 255 && r.a[k].type != QT[t] && r.a[k].type != DNS_CNAME)
                    wrong_type++;
            }
        }
    printf("       (%d name x type combinations)\n", cases);
    CK(undecodable == 0, "every response in the matrix is a well-formed message");
    CK(wrong_owner == 0, "no answer RR is ever returned under the wrong owner name");
    CK(wrong_type == 0, "no answer RR is ever of an unrequested type (CNAME aside)");
    CK(wrong_class == 0, "every answer RR is class IN");
    CK(nonempty_err == 0, "a non-NOERROR response never carries answer records");

    /* transaction ID + question echo, over seeded-random queries */
    int badid = 0, badq = 0, badflags = 0, n = 2000;
    for (int i = 0; i < n; i++) {
        uint16_t id = (uint16_t)rnd(65536);
        const char *nm = NAMES[rnd(sizeof NAMES / sizeof NAMES[0])];
        uint16_t qt = QT[rnd(sizeof QT / sizeof QT[0])];
        int edns = (int)rnd(2);
        if (ask_ex(nm, qt, DNS_CLASS_IN, edns, 1232, (int)rnd(2), id, &r) < 0) continue;
        if (r.id != id) badid++;
        if (!qsec_echoed(&r) || r.qtype != qt || r.qclass != DNS_CLASS_IN || r.qd != 1) badq++;
        if (!(r.flags & 0x8000) || !(r.flags & 0x0400) ||   /* QR, AA */
            ((r.flags >> 8) & 1) != 1 ||                    /* RD echoed */
            (r.flags & 0x0080) ||                           /* RA must be 0 */
            (r.flags & 0x0070))                             /* Z must be 0 */
            badflags++;
    }
    CK(badid == 0, "the transaction ID is echoed exactly (2000 random queries)");
    CK(badq == 0, "the question section is echoed byte-for-byte (2000 random queries)");
    CK(badflags == 0, "QR/AA set, RD echoed, RA and Z clear on every response");

    /* RD=0 must come back RD=0 */
    g_reqlen = mkquery(g_req, sizeof g_req, 7, 0x0000, "www.pepenet.pepe", DNS_A, DNS_CLASS_IN, 0, 0);
    { dns_query q; dns_parse_query(g_req, g_reqlen, &q);
      g_outlen = dnsd_core_answer(&DC, &q, g_out, sizeof g_out, 0);
      decode(g_out, g_outlen, &r);
      CK(((r.flags >> 8) & 1) == 0, "RD=0 is echoed as RD=0"); }
}

/* ═══════════ EDNS0 / TC / budgets ══════════════════════════════════════ */
static void section_edns(void) {
    resp r;
    CK(ask_ex("www.pepenet.pepe", DNS_A, DNS_CLASS_IN, 0, 0, 0, 1, &r) == DNS_RCODE_NOERROR &&
       r.ar == 0 && !r.opt, "a non-EDNS query gets no OPT back");
    CK(ask_ex("www.pepenet.pepe", DNS_A, DNS_CLASS_IN, 1, 4096, 0, 1, &r) == DNS_RCODE_NOERROR &&
       r.ar == 1 && r.opt && r.opt_payload == 1232 && r.opt_version == 0,
       "an EDNS query gets an OPT advertising our 1232-byte cap, version 0");

    /* the fat label: ANY over plain UDP must not fit 512 bytes */
    int rc = ask_ex("big.pepenet.pepe", 255, DNS_CLASS_IN, 0, 0, 0, 1, &r);
    printf("       ANY big.pepenet.pepe: udp512 -> %zu bytes, %d answers, TC=%d\n",
           g_outlen, r.na, (r.flags >> 9) & 1);
    CK(rc == DNS_RCODE_NOERROR && g_outlen <= 512, "a UDP answer never exceeds the 512 budget");
    CK((r.flags & 0x0200) != 0, "an over-budget UDP answer sets TC");
    CK(r.valid, "the truncated response is still a well-formed message");
    CK(r.id == 1 && qsec_echoed(&r), "a truncated response still echoes the ID and question");
    int udp_na = r.na;

    rc = ask_ex("big.pepenet.pepe", 255, DNS_CLASS_IN, 1, 1232, 0, 1, &r);
    CK(rc == DNS_RCODE_NOERROR && g_outlen <= 1232, "an EDNS answer respects the 1232 cap");
    CK(r.opt && r.ar == 1, "the OPT is present even on a truncated EDNS answer");

    rc = ask_ex("big.pepenet.pepe", 255, DNS_CLASS_IN, 0, 0, 1 /*tcp*/, 1, &r);
    printf("       ANY big.pepenet.pepe: tcp -> %zu bytes, %d answers, TC=%d\n",
           g_outlen, r.na, (r.flags >> 9) & 1);
    CK(rc == DNS_RCODE_NOERROR && r.na == 4, "over TCP the whole RRset is returned");
    CK((r.flags & 0x0200) == 0, "TC is clear over TCP");
    CK(r.na > udp_na, "TCP returns strictly more than the UDP budget allowed");

    /* an EDNS client advertising less than 512 is floored at 512 */
    rc = ask_ex("www.pepenet.pepe", DNS_A, DNS_CLASS_IN, 1, 200, 0, 1, &r);
    CK(rc == DNS_RCODE_NOERROR && r.na == 1 && g_outlen <= 512,
       "an EDNS payload below 512 is floored at 512, not honoured literally");
}

/* ═══════════ ACCEPTANCE: the --tls-redirect DANE policy ════════════════ */
static void section_tls_redirect(void) {
    resp r;
    CK(ask("www.pepenet.pepe", DNS_A, &r) == DNS_RCODE_NOERROR && r.na == 1 &&
       memcmp(r.a[0].rd, "\x0a\x00\x00\x02", 4) == 0,
       "with --tls-redirect OFF a DANE name still answers its real A");

    DC.tls_redirect = 1;
    DC.tls_redirect_ip[0] = 127; DC.tls_redirect_ip[1] = 0;
    DC.tls_redirect_ip[2] = 0;   DC.tls_redirect_ip[3] = 1;

    CK(ask("www.pepenet.pepe", DNS_A, &r) == DNS_RCODE_NOERROR && r.na == 1 &&
       memcmp(r.a[0].rd, "\x7f\x00\x00\x01", 4) == 0,
       "a name WITH _443._tcp.<sub> TLSA is steered to the proxy IP");
    { int leaked = 0;
      for (int i = 0; i < r.na; i++)
          if (r.a[i].type == DNS_A && memcmp(r.a[i].rd, "\x0a\x00\x00\x02", 4) == 0) leaked = 1;
      CK(!leaked, "  ... and the real origin A is NOT also returned"); }

    CK(ask("pepenet.pepe", DNS_A, &r) == DNS_RCODE_NOERROR && r.na == 1 &&
       memcmp(r.a[0].rd, "\x7f\x00\x00\x01", 4) == 0,
       "the apex, whose TLSA is at _443._tcp, is steered too");

    /* ── THE ACCEPTANCE CASE: an A record but NO TLSA ─────────────────────
     * README: "Names without a _443._tcp TLSA are untouched, so plain A
     * lookups still resolve normally." pepenet-tls src/origin.h: "No TLSA =>
     * the origin cannot be DANE-authenticated, so it is NOT servable (0) —
     * never fall back to an unverified connection." Steering such a name at
     * the proxy would therefore turn a working plain-HTTP name into a hard
     * failure, so the resolver MUST return the real A. */
    CK(ask("plain.pepenet.pepe", DNS_A, &r) == DNS_RCODE_NOERROR && r.na == 1 &&
       r.a[0].type == DNS_A && memcmp(r.a[0].rd, "\x0a\x00\x00\x09", 4) == 0,
       "ACCEPTANCE: a subdomain with an A but NO _443._tcp TLSA answers its REAL A");
    CK(memcmp(r.a[0].rd, "\x7f\x00\x00\x01", 4) != 0,
       "ACCEPTANCE:   ... and is never steered at the DANE proxy");
    CK(ask("plain.pepenet.pepe", DNS_TLSA, &r) == DNS_RCODE_NOERROR && r.na == 0,
       "ACCEPTANCE:   ... and its TLSA query is NODATA, never a fabricated pin");

    /* the redirect touches A (and ANY) only */
    CK(ask("www.pepenet.pepe", DNS_AAAA, &r) == DNS_RCODE_NOERROR && r.na == 1 &&
       r.a[0].type == DNS_AAAA && r.a[0].rd[0] == 0x20,
       "AAAA is untouched by --tls-redirect (v6 keeps the real origin)");
    CK(ask("_443._tcp.www.pepenet.pepe", DNS_TLSA, &r) == DNS_RCODE_NOERROR &&
       r.na == 1 && r.a[0].rdlen == 35,
       "the TLSA record itself is still served verbatim under --tls-redirect");

    { int rc = ask("www.pepenet.pepe", 255, &r);
      int have_redirect = 0, have_real = 0, have_v6 = 0;
      for (int i = 0; i < r.na; i++) {
          if (r.a[i].type == DNS_A && !memcmp(r.a[i].rd, "\x7f\x00\x00\x01", 4)) have_redirect = 1;
          if (r.a[i].type == DNS_A && !memcmp(r.a[i].rd, "\x0a\x00\x00\x02", 4)) have_real = 1;
          if (r.a[i].type == DNS_AAAA) have_v6 = 1;
      }
      CK(rc == DNS_RCODE_NOERROR && have_redirect && !have_real && have_v6,
         "ANY under --tls-redirect swaps the A and keeps the other types"); }

    /* an unknown label is still NXDOMAIN, never a redirect */
    CK(ask("nope.pepenet.pepe", DNS_A, &r) == DNS_RCODE_NXDOMAIN && r.na == 0,
       "--tls-redirect never invents an answer for an unknown name");
    DC.tls_redirect = 0;
}

/* ═══════════ the two zone bugs, end to end ═════════════════════════════ */
/* Both are now refused at the publishing front door (zone.c). That is asserted
 * first. dnsd_core is downstream of the store, though, and the store also takes
 * gossiped ops from other peers — so the records were injected raw (see publish)
 * and the resolver's behaviour on them is still pinned end to end, unchanged:
 * this is precisely the wrong-answer surface the front-door check exists to
 * keep users away from. */
static void section_user_bugs(void) {
    resp r;
    zone_rec tmp;
    CK(zone_build_rec("gpt.pepe", "A", 300, "216.24.57.1", &tmp) == -1,
       "(evidence) the publishing front door refuses the TLD-bearing label outright");
    CK(zone_build_rec("bad", "CNAME", 300, "216.24.57.1", &tmp) == -1,
       "(evidence) ... and refuses a CNAME whose target is an IP literal");

    CK(ask("gpt.pepe.gpt.pepe", DNS_A, &r) == DNS_RCODE_NOERROR && r.na == 1 &&
       memcmp(r.a[0].rd, "\xd8\x18\x39\x01", 4) == 0,
       "(evidence) a record labelled \"gpt.pepe\" in the gpt zone answers at gpt.pepe.gpt.pepe");
    CK(ask("gpt.pepe", DNS_A, &r) == DNS_RCODE_NOERROR && r.na == 1 &&
       memcmp(r.a[0].rd, "\x0a\x01\x01\x01", 4) == 0,
       "(evidence) ... and the name the user meant, gpt.pepe, serves the apex record instead");

    CK(ask("bad.gpt.pepe", DNS_A, &r) == DNS_RCODE_NOERROR && r.na == 1 &&
       r.a[0].type == DNS_CNAME && r.a[0].rdlen == 13 &&
       r.a[0].rd[0] == 3 && memcmp(r.a[0].rd + 1, "216", 3) == 0,
       "(evidence) a CNAME to an IP literal is served as a 4-label dname, not an address");
    /* every other type at that label CNAME-chases to the same dead end */
    CK(ask("bad.gpt.pepe", DNS_TLSA, &r) == DNS_RCODE_NOERROR && r.na == 1 &&
       r.a[0].type == DNS_CNAME,
       "(evidence) ... every other qtype chases the same CNAME");
    { char tgt[128]; size_t o = 0; const uint8_t *rd = r.a[0].rd;
      for (int p = 0; p < r.a[0].rdlen && rd[p]; p += 1 + rd[p]) {
          if (o) tgt[o++] = '.';
          memcpy(tgt + o, rd + p + 1, rd[p]); o += rd[p]; }
      tgt[o] = '\0';
      size_t tl = strlen(tgt);
      CK(strcmp(tgt, "216.24.57.1") == 0 && !(tl > 5 && !strcmp(tgt + tl - 5, ".pepe")),
         "(evidence) ... and the target \"216.24.57.1\" is in no zone — the chain dead-ends"); }
}

/* ═══════════ output-buffer safety ══════════════════════════════════════ */
#define CANARY 0xA5
static void section_bounds(void) {
    static uint8_t arena[2048];
    dns_query q;
    g_reqlen = mkquery(g_req, sizeof g_req, 9, 0x0100, "www.pepenet.pepe", DNS_A, DNS_CLASS_IN, 0, 0);
    dns_parse_query(g_req, g_reqlen, &q);
    int bad = 0; size_t firstfit = 0;
    for (size_t cap = 0; cap <= 200; cap++) {
        memset(arena, CANARY, sizeof arena);
        size_t n = dnsd_core_answer(&DC, &q, arena, cap, 0);
        if (n > cap) { bad = 1; printf("       cap=%zu returned %zu\n", cap, n); break; }
        for (size_t i = cap; i < sizeof arena; i++)
            if (arena[i] != CANARY) { bad = 1; printf("       cap=%zu wrote past the end\n", cap); break; }
        if (bad) break;
        if (n && !firstfit) firstfit = cap;
    }
    CK(!bad, "dnsd_core_answer never returns more than cap nor writes past it (cap 0..200)");
    CK(firstfit >= 12, "  ... and reports 0 until a header+question actually fits");

    /* the same, with EDNS on (limit = budget - 11 can underflow at tiny caps) */
    g_reqlen = mkquery(g_req, sizeof g_req, 9, 0x0100, "www.pepenet.pepe", DNS_A, DNS_CLASS_IN, 1, 4096);
    dns_parse_query(g_req, g_reqlen, &q);
    bad = 0;
    for (size_t cap = 0; cap <= 200; cap++) {
        memset(arena, CANARY, sizeof arena);
        size_t n = dnsd_core_answer(&DC, &q, arena, cap, 0);
        if (n > cap) { bad = 1; printf("       edns cap=%zu returned %zu\n", cap, n); break; }
        for (size_t i = cap; i < sizeof arena; i++)
            if (arena[i] != CANARY) { bad = 1; printf("       edns cap=%zu wrote past the end\n", cap); break; }
        if (bad) break;
    }
    CK(!bad, "the same holds with EDNS on (budget - 11 must not underflow the cap)");
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    const char *s = getenv("DNSD_SEED");
    g_seed = s ? strtoull(s, NULL, 0) : 0xD0D0CAFEULL;
    g_s = g_seed;
    printf("dnsd_core_test: seed %llu\n", (unsigned long long)g_seed);

    testkey("owner", OPRIV, OPUB);
    sp_hash160(OPUB, 33, g_owner160);
    SpState *st = sp_state_open(":memory:");
    if (!st) { printf("dnsd_core_test: cannot open the store\n"); return 2; }

    memset(&DC, 0, sizeof DC);
    DC.st = st; DC.oracle = ORC; DC.suffix = "pepe";
    DC.ufd = DC.tfd = -1;

    printf("-- fixtures --\n");                     publish(st);
    printf("-- resolution --\n");                   section_resolve();
    printf("-- case insensitivity --\n");           section_case();
    printf("-- negative answers (NXDOMAIN vs REFUSED vs NODATA) --\n"); section_negative();
    printf("-- never a wrong answer + ID/question echo --\n"); section_integrity();
    printf("-- EDNS0, TC and the UDP budget --\n"); section_edns();
    printf("-- ACCEPTANCE: --tls-redirect DANE policy --\n"); section_tls_redirect();
    printf("-- the zone-level user bugs, end to end --\n"); section_user_bugs();
    printf("-- output buffer safety --\n");         section_bounds();

    sp_state_close(st);
    printf("dnsd_core_test: %d ok, %d failed\n", g_ok, g_fail);
    return g_fail ? 1 : 0;
}
