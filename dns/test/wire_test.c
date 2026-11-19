/* wire_test.c — src/dns_wire.c, the network-facing RFC 1035 codec, under
 * adversarial load. This is the only module in the repo that parses bytes an
 * unauthenticated stranger chose, so it is tested as an attack surface, not as
 * a convenience library.
 *
 * PROVEN HERE
 *   1. ROUND-TRIP (property test, seeded-random, thousands of messages):
 *      dns_encode_name/dns_resp_* produce wire that dns_parse_query and an
 *      INDEPENDENT reference decoder in this file both read back byte-exact —
 *      id, flags, qname, qtype, qclass, every answer RR's owner/type/class/
 *      ttl/rdlen/rdata, and the EDNS0 OPT. Covers A, NS, CNAME, SOA, PTR, MX,
 *      TXT, AAAA, SRV, SSHFP, TLSA, OPENPGPKEY; the root name; single-label,
 *      multi-label and 63-byte-label names; a 255-byte (maximal) name; 1..8
 *      answer RRs per message. The RNG is a SplitMix64 written here (never
 *      rand()) and the seed is printed so any failure reproduces exactly:
 *      WIRE_SEED=<n> ./wire_test.
 *   2. ADVERSARIAL DECODE — the malicious-packet battery. Compression-pointer
 *      self-loops, mutual loops and long chains; pointers past the end, into
 *      the middle of a label, and 0xC0 as the final byte; reserved label types
 *      0x40..0xBF; unterminated names; over-long names; count/body mismatch and
 *      0xFFFF counts; rdlength overrun/underrun; the empty, 1-byte and 64 KB
 *      messages. Then the loops that actually find bugs: EVERY prefix of every
 *      valid fixture is decoded (truncation sweep), and tens of thousands of
 *      byte-mutations, random buffers and "pointer soup" packets are decoded.
 *      A SIGALRM watchdog turns any hang into a FAILURE, and a SIGSEGV/SIGBUS
 *      handler hex-dumps the exact input that killed the parser.
 *   3. ENCODE BOUNDARY SAFETY: dns_encode_name / dns_resp_begin / dns_resp_add /
 *      dns_resp_add_opt against buffers that are exactly big enough, one byte
 *      too small, and zero bytes — with 0xA5 canaries past the nominal end, so
 *      a single byte written out of bounds is caught even without a sanitizer.
 *
 * Links nothing but src/dns_wire.c — no store, no mesh, no chain.
 */
#include "dns_wire.h"

#include <ctype.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* ── house harness ───────────────────────────────────────────────────────── */
static int g_ok, g_fail;
#define CK(c, m) do { if (c) { g_ok++; printf("  ok   %s\n", m); } \
                      else { g_fail++; printf("  FAIL %s\n", m); } } while (0)

/* ── SplitMix64 (never rand(); the seed is printed so failures reproduce) ── */
static uint64_t g_seed, g_s;
static uint64_t sm64(void) {
    uint64_t z = (g_s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static uint32_t rnd(uint32_t n) { return n ? (uint32_t)(sm64() % n) : 0u; }

/* ── watchdog + crash reporter ───────────────────────────────────────────── */
static const char  *g_where = "startup";
static const uint8_t *g_cur; static size_t g_curlen;

static void wr(const char *s) { ssize_t r = write(2, s, strlen(s)); (void)r; }
static void wrhex(const uint8_t *p, size_t n) {
    static const char H[] = "0123456789abcdef";
    char line[3 * 32 + 2];
    if (n > 256) n = 256;
    for (size_t i = 0; i < n;) {
        size_t j = 0, k = 0;
        for (; k < 32 && i < n; k++, i++) {
            line[j++] = H[p[i] >> 4]; line[j++] = H[p[i] & 15]; line[j++] = ' ';
        }
        line[j++] = '\n';
        ssize_t r = write(2, line, j); (void)r;
    }
}
static void on_alarm(int s) {
    (void)s;
    wr("\nWATCHDOG: dns_wire hung (no progress) in section: "); wr(g_where); wr("\n");
    wr("offending input (hex):\n"); if (g_cur) wrhex(g_cur, g_curlen);
    wr("wire_test: FAILED (hang)\n");
    _exit(1);
}
static void on_crash(int s) {
    wr("\nCRASH: signal "); wr(s == SIGSEGV ? "SIGSEGV" : "SIGBUS");
    wr(" in section: "); wr(g_where); wr("\n");
    wr("offending input (hex):\n"); if (g_cur) wrhex(g_cur, g_curlen);
    wr("wire_test: FAILED (crash)\n");
    _exit(1);
}
/* Every decode goes through here: the watchdog is re-armed per call, so a hang
 * inside one dns_parse_query fails the test instead of wedging the run. */
static int parse(const uint8_t *b, size_t n, dns_query *q) {
    int rc;
    g_cur = b; g_curlen = n;
    memset(q, 0xCC, sizeof *q);          /* poison: catch fields left unset */
    alarm(10);
    rc = dns_parse_query(b, n, q);
    alarm(0);
    g_cur = NULL;
    return rc;
}

/* ── the guard page: an OOB detector that needs no sanitizer ──────────────
 * Two pages; the second is PROT_NONE. A message is copied so its LAST byte
 * sits on the last byte of the first page, so any read one byte past `len`
 * faults immediately and on_crash() hex-dumps the exact packet. (ASAN is not
 * usable here — its malloc interposer deadlocks at startup on this macOS — so
 * this is how the adversarial and fuzz decodes prove "no out-of-bounds read".) */
static uint8_t *g_page; static size_t g_pgsz;
static void guard_init(void) {
    g_pgsz = (size_t)sysconf(_SC_PAGESIZE);
    g_page = mmap(NULL, g_pgsz * 2, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANON, -1, 0);
    if (g_page == MAP_FAILED) { g_page = NULL; return; }
    if (mprotect(g_page + g_pgsz, g_pgsz, PROT_NONE) != 0) g_page = NULL;
}
static int parse_g(const uint8_t *b, size_t n, dns_query *q) {
    if (!g_page || n > g_pgsz) return parse(b, n, q);
    uint8_t *p = g_page + g_pgsz - n;
    if (n) memcpy(p, b, n);
    return parse(p, n, q);
}

/* ── tiny wire helpers (test-owned, deliberately not the product's) ──────── */
static void p16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint16_t g16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t g32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

/* An INDEPENDENT name reader: no compression (the encoder must never emit a
 * pointer), so a pointer here is an encoder bug. */
static int ref_name(const uint8_t *b, size_t len, size_t *off, char *out, size_t cap) {
    size_t p = *off, o = 0;
    for (;;) {
        if (p >= len) return -1;
        uint8_t l = b[p];
        if (l == 0) { p++; break; }
        if ((l & 0xC0) != 0) return -1;
        p++;
        if (p + l > len) return -1;
        if (o && o + 1 < cap) out[o++] = '.';
        if (o + l >= cap) return -1;
        for (uint8_t i = 0; i < l; i++) out[o++] = (char)tolower(b[p + i]);
        p += l;
    }
    out[o] = '\0'; *off = p; return 0;
}

/* ── message construction ────────────────────────────────────────────────── */
static size_t build_query(uint8_t *b, size_t cap, uint16_t id, uint16_t flags,
                          const char *qname, uint16_t qtype, uint16_t qclass,
                          int edns, uint16_t payload) {
    if (cap < 12) return 0;
    p16(b + 0, id); p16(b + 2, flags);
    p16(b + 4, 1); p16(b + 6, 0); p16(b + 8, 0); p16(b + 10, edns ? 1 : 0);
    size_t o = 12;
    int n = dns_encode_name(b + o, cap - o, qname);
    if (n < 0) return 0;
    o += (size_t)n;
    if (o + 4 > cap) return 0;
    p16(b + o, qtype); o += 2; p16(b + o, qclass); o += 2;
    if (edns) {
        if (o + 11 > cap) return 0;
        b[o++] = 0;                        /* root owner */
        p16(b + o, 41); o += 2;            /* TYPE = OPT */
        p16(b + o, payload); o += 2;       /* CLASS = advertised UDP payload */
        b[o++] = 0; b[o++] = 0; b[o++] = 0; b[o++] = 0;   /* ext-rcode/version/flags */
        p16(b + o, 0); o += 2;             /* RDLEN */
    }
    return o;
}

/* Encode a dotted name into wire labels WITHOUT the RFC 1035 §2.3.4 total-name
 * limit — label syntax only. dns_encode_name now (correctly) refuses to emit a
 * name over 255 octets, so an over-long fixture can no longer be built through
 * it. The DECODER still has to be proven against such bytes, and a hostile peer
 * can trivially put them on the wire, so the test assembles them itself. */
static size_t raw_encode_name(uint8_t *out, size_t cap, const char *dotted) {
    size_t o = 0;
    const char *p = dotted;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        if (l == 0 || l > 63 || o + 1 + l >= cap) return 0;
        out[o++] = (uint8_t)l;
        memcpy(out + o, p, l);
        o += l;
        if (!dot) break;
        p = dot + 1;
    }
    if (o + 1 > cap) return 0;
    out[o++] = 0;                                  /* root label */
    return o;
}

/* build_query, but with the question name encoded by raw_encode_name — the only
 * way to hand the parser a name longer than the encoder will now produce. */
static size_t build_query_raw(uint8_t *b, size_t cap, uint16_t id, uint16_t flags,
                              const char *qname, uint16_t qtype, uint16_t qclass) {
    if (cap < 12) return 0;
    p16(b + 0, id); p16(b + 2, flags);
    p16(b + 4, 1); p16(b + 6, 0); p16(b + 8, 0); p16(b + 10, 0);
    size_t o = 12;
    size_t n = raw_encode_name(b + o, cap - o, qname);
    if (n == 0) return 0;
    o += n;
    if (o + 4 > cap) return 0;
    p16(b + o, qtype); o += 2; p16(b + o, qclass); o += 2;
    return o;
}

/* ── random names ────────────────────────────────────────────────────────── */
static const char ALPHA[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-";

/* Random dotted name whose WIRE form is <= wire_max bytes. */
static void rnd_name(char *out, size_t cap, int wire_max) {
    size_t o = 0; int wire = 1;                 /* the root byte */
    int labels = 1 + (int)rnd(5);
    for (int i = 0; i < labels; i++) {
        int room = wire_max - wire - 1;
        if (room > 63) room = 63;
        if (room < 1) break;
        int l = 1 + (int)rnd((uint32_t)room);
        if (rnd(12) == 0 && room >= 63) l = 63;  /* exercise the max label */
        if (o + (o ? 1 : 0) + (size_t)l + 1 >= cap) break;
        if (o) out[o++] = '.';
        for (int k = 0; k < l; k++) out[o++] = ALPHA[rnd(sizeof ALPHA - 1)];
        wire += 1 + l;
    }
    out[o] = '\0';
}
/* The maximal legal name: 3 x 63-byte labels + one 61-byte label = 255 wire. */
static void max_name(char *out) {
    size_t o = 0;
    for (int i = 0; i < 3; i++) {
        if (o) out[o++] = '.';
        for (int k = 0; k < 63; k++) out[o++] = (char)('a' + (k + i) % 26);
    }
    out[o++] = '.';
    for (int k = 0; k < 61; k++) out[o++] = (char)('a' + k % 26);
    out[o] = '\0';
}
static void lower(char *s) { for (; *s; s++) *s = (char)tolower((unsigned char)*s); }

/* ── random rdata, per record type ───────────────────────────────────────── */
static const uint16_t TYPES[] = { DNS_A, DNS_NS, DNS_CNAME, DNS_SOA, DNS_PTR,
                                  DNS_MX, DNS_TXT, DNS_AAAA, DNS_SRV,
                                  DNS_SSHFP, DNS_TLSA, DNS_OPENPGPKEY };
#define NTYPES ((int)(sizeof TYPES / sizeof TYPES[0]))

static uint16_t rnd_rdata(uint16_t type, uint8_t *rd, size_t cap) {
    char nm[300];
    int n, o = 0;
    switch (type) {
    case DNS_A:    for (int i = 0; i < 4; i++)  rd[i] = (uint8_t)rnd(256); return 4;
    case DNS_AAAA: for (int i = 0; i < 16; i++) rd[i] = (uint8_t)rnd(256); return 16;
    case DNS_NS: case DNS_CNAME: case DNS_PTR:
        rnd_name(nm, sizeof nm, 255);
        n = dns_encode_name(rd, cap, nm);
        return n < 0 ? 0 : (uint16_t)n;
    case DNS_MX:
        p16(rd, (uint16_t)rnd(65536)); o = 2;
        rnd_name(nm, sizeof nm, 200);
        n = dns_encode_name(rd + o, cap - (size_t)o, nm);
        return n < 0 ? 0 : (uint16_t)(o + n);
    case DNS_SRV:
        p16(rd, (uint16_t)rnd(65536)); p16(rd + 2, (uint16_t)rnd(65536));
        p16(rd + 4, (uint16_t)rnd(65536)); o = 6;
        rnd_name(nm, sizeof nm, 200);
        n = dns_encode_name(rd + o, cap - (size_t)o, nm);
        return n < 0 ? 0 : (uint16_t)(o + n);
    case DNS_SOA: {                                 /* mname rname + 5 x u32 */
        rnd_name(nm, sizeof nm, 100);
        n = dns_encode_name(rd, cap, nm);           if (n < 0) return 0;
        o = n;
        rnd_name(nm, sizeof nm, 100);
        n = dns_encode_name(rd + o, cap - (size_t)o, nm); if (n < 0) return 0;
        o += n;
        for (int i = 0; i < 5; i++) {
            uint32_t v = (uint32_t)sm64();
            rd[o++] = (uint8_t)(v >> 24); rd[o++] = (uint8_t)(v >> 16);
            rd[o++] = (uint8_t)(v >> 8);  rd[o++] = (uint8_t)v;
        }
        return (uint16_t)o;
    }
    case DNS_TXT: {
        uint8_t l = (uint8_t)(1 + rnd(200));
        rd[0] = l;
        for (int i = 0; i < l; i++) rd[1 + i] = (uint8_t)(32 + rnd(95));
        return (uint16_t)(1 + l);
    }
    case DNS_SSHFP:
        rd[0] = (uint8_t)(1 + rnd(4)); rd[1] = (uint8_t)(1 + rnd(2));
        for (int i = 0; i < 32; i++) rd[2 + i] = (uint8_t)rnd(256);
        return 34;
    case DNS_TLSA:
        rd[0] = (uint8_t)rnd(4); rd[1] = (uint8_t)rnd(2); rd[2] = (uint8_t)rnd(3);
        for (int i = 0; i < 32; i++) rd[3 + i] = (uint8_t)rnd(256);
        return 35;
    default: {                                        /* OPENPGPKEY & friends */
        uint16_t l = (uint16_t)(1 + rnd(120));
        for (int i = 0; i < l; i++) rd[i] = (uint8_t)rnd(256);
        return l;
    }
    }
}

/* ── the reference response verifier ─────────────────────────────────────── */
typedef struct { char owner[300]; uint16_t type; uint32_t ttl;
                 uint16_t rdlen; uint8_t rd[600]; } exp_rr;

static int verify_resp(const uint8_t *b, size_t len, const dns_query *q,
                       const exp_rr *want, int nwant, int expect_opt, int rcode,
                       char *why, size_t wcap) {
#define BAD(...) do { snprintf(why, wcap, __VA_ARGS__); return 0; } while (0)
    if (len < 12) BAD("short response (%zu)", len);
    if (g16(b) != q->id) BAD("ID echo: got %u want %u", g16(b), q->id);
    uint16_t f = g16(b + 2);
    if (!(f & 0x8000)) BAD("QR not set");
    if (!(f & 0x0400)) BAD("AA not set");
    if (((f >> 11) & 0xF) != ((q->flags >> 11) & 0xF)) BAD("opcode not echoed");
    if (((f >> 8) & 1) != ((q->flags >> 8) & 1)) BAD("RD not echoed");
    if ((f & 0xF) != (uint16_t)rcode) BAD("rcode %u want %d", f & 0xF, rcode);
    if (g16(b + 4) != 1) BAD("QDCOUNT %u", g16(b + 4));
    if (g16(b + 6) != (uint16_t)nwant) BAD("ANCOUNT %u want %d", g16(b + 6), nwant);
    if (g16(b + 8) != 0) BAD("NSCOUNT %u", g16(b + 8));
    if (g16(b + 10) != (uint16_t)(expect_opt ? 1 : 0)) BAD("ARCOUNT %u", g16(b + 10));

    size_t off = 12; char nm[300];
    if (ref_name(b, len, &off, nm, sizeof nm) != 0) BAD("question name unreadable");
    if (strcmp(nm, q->qname) != 0) BAD("question echo '%s' want '%s'", nm, q->qname);
    if (off + 4 > len) BAD("question truncated");
    if (g16(b + off) != q->qtype) BAD("qtype echo");
    if (g16(b + off + 2) != q->qclass) BAD("qclass echo");
    off += 4;

    for (int i = 0; i < nwant; i++) {
        if (ref_name(b, len, &off, nm, sizeof nm) != 0) BAD("rr%d owner unreadable", i);
        if (strcmp(nm, want[i].owner) != 0) BAD("rr%d owner '%s' want '%s'", i, nm, want[i].owner);
        if (off + 10 > len) BAD("rr%d header truncated", i);
        if (g16(b + off) != want[i].type) BAD("rr%d type", i);
        if (g16(b + off + 2) != DNS_CLASS_IN) BAD("rr%d class", i);
        if (g32(b + off + 4) != want[i].ttl) BAD("rr%d ttl", i);
        uint16_t rl = g16(b + off + 8);
        if (rl != want[i].rdlen) BAD("rr%d rdlen %u want %u", i, rl, want[i].rdlen);
        off += 10;
        if (off + rl > len) BAD("rr%d rdata truncated", i);
        if (memcmp(b + off, want[i].rd, rl) != 0) BAD("rr%d rdata bytes", i);
        off += rl;
    }
    if (expect_opt) {
        if (off + 11 > len) BAD("OPT truncated");
        if (b[off] != 0) BAD("OPT owner not root");
        if (g16(b + off + 1) != 41) BAD("OPT type %u", g16(b + off + 1));
        if (g16(b + off + 9) != 0) BAD("OPT rdlen");
        off += 11;
    }
    if (off != len) BAD("trailing %zu bytes", len - off);
    return 1;
#undef BAD
}

/* ═══════════════ 1. round-trip property test ════════════════════════════ */
static void section_roundtrip(int iters) {
    g_where = "round-trip";
    int bad_q = 0, bad_r = 0, bad_reparse = 0, built = 0;
    char whyq[160] = "", whyr[160] = "";
    int type_seen[NTYPES]; memset(type_seen, 0, sizeof type_seen);
    int saw_root = 0, saw_max = 0, saw_63 = 0;

    for (int it = 0; it < iters; it++) {
        char nm[300];
        int shape = (int)rnd(16);
        if (shape == 0)      { nm[0] = '\0'; saw_root = 1; }        /* root */
        else if (shape == 1) { max_name(nm); saw_max = 1; }         /* 255 wire */
        else if (shape == 2) { for (int k = 0; k < 63; k++) nm[k] = 'q'; nm[63] = '\0'; saw_63 = 1; }
        else                 rnd_name(nm, sizeof nm, 255);

        uint16_t id    = (uint16_t)rnd(65536);
        uint16_t rd    = (uint16_t)(rnd(2) << 8);
        uint16_t flags = rd | (uint16_t)((rnd(2) ? 0 : 0) << 11);
        uint16_t qtype = TYPES[rnd(NTYPES)];
        int edns = (int)rnd(2);
        uint16_t payload = (uint16_t)(512 + rnd(3600));

        uint8_t qbuf[1024];
        size_t qn = build_query(qbuf, sizeof qbuf, id, flags, nm, qtype,
                                DNS_CLASS_IN, edns, payload);
        if (qn == 0) continue;
        built++;

        char want_nm[300]; snprintf(want_nm, sizeof want_nm, "%s", nm); lower(want_nm);

        dns_query q;
        if (parse(qbuf, qn, &q) != 0) { if (!bad_q++) snprintf(whyq, sizeof whyq, "parse rc<0 for '%s'", nm); continue; }
        if (q.id != id || q.flags != flags || q.qtype != qtype ||
            q.qclass != DNS_CLASS_IN || strcmp(q.qname, want_nm) != 0 ||
            q.edns != (uint8_t)edns || (edns && q.udp_payload != payload) ||
            (edns && q.edns_version != 0)) {
            if (!bad_q++) snprintf(whyq, sizeof whyq, "field mismatch: qname '%s' want '%s'", q.qname, want_nm);
            continue;
        }

        /* build a response carrying 1..8 answers of random supported types */
        int nrr = 1 + (int)rnd(8);
        exp_rr want[8];
        uint8_t out[4096];
        dns_resp r;
        dns_resp_begin(&r, out, sizeof out, &q, DNS_RCODE_NOERROR);
        int added = 0;
        for (int i = 0; i < nrr; i++) {
            int ti = (int)rnd(NTYPES);
            uint16_t t = TYPES[ti];
            exp_rr *w = &want[added];
            /* owner: the qname (the product's own path) or another random name */
            if (rnd(4) == 0) { char o2[300]; rnd_name(o2, sizeof o2, 200);
                               snprintf(w->owner, sizeof w->owner, "%s", o2); lower(w->owner); }
            else snprintf(w->owner, sizeof w->owner, "%s", want_nm);
            w->type = t;
            w->ttl  = (uint32_t)sm64();
            w->rdlen = rnd_rdata(t, w->rd, sizeof w->rd);
            if (w->rdlen == 0) continue;
            if (dns_resp_add(&r, w->owner, w->type, w->ttl, w->rd, w->rdlen) != 0) break;
            type_seen[ti] = 1;
            added++;
        }
        if (edns) dns_resp_add_opt(&r, 1232);
        size_t rn = dns_resp_finish(&r);
        if (rn == 0) { if (!bad_r++) snprintf(whyr, sizeof whyr, "finish returned 0"); continue; }

        char why[160];
        if (!verify_resp(out, rn, &q, want, added, edns, DNS_RCODE_NOERROR, why, sizeof why)) {
            if (!bad_r++) snprintf(whyr, sizeof whyr, "%s", why);
            continue;
        }
        /* and the product's own decoder must read its own output back */
        dns_query q2;
        if (parse(out, rn, &q2) != 0 || q2.id != q.id || q2.qtype != q.qtype ||
            q2.qclass != q.qclass || strcmp(q2.qname, q.qname) != 0)
            bad_reparse++;
    }
    printf("  (%d messages built from seed %llu)\n", built, (unsigned long long)g_seed);
    CK(built > iters / 2, "the generator produced messages");
    if (bad_q)  printf("       first query mismatch: %s\n", whyq);
    if (bad_r)  printf("       first response mismatch: %s\n", whyr);
    CK(bad_q == 0, "encode->dns_parse_query round-trips every query field");
    CK(bad_r == 0, "dns_resp_* output verifies against an independent decoder");
    CK(bad_reparse == 0, "the codec re-parses its own responses (id/qname/qtype/qclass)");
    int all = 1; for (int i = 0; i < NTYPES; i++) if (!type_seen[i]) all = 0;
    CK(all, "every supported record type was round-tripped");
    CK(saw_root && saw_max && saw_63, "root, 63-byte-label and 255-byte names covered");
}

/* ── the 255-byte-name edge, pinned exactly ──────────────────────────────── */
static void section_name_limits(void) {
    g_where = "name limits";
    uint8_t b[1024]; char nm[400];

    max_name(nm);
    size_t n = build_query(b, sizeof b, 1, 0, nm, DNS_A, DNS_CLASS_IN, 0, 0);
    CK(n == 12 + 255 + 4, "a maximal name encodes to exactly 255 wire bytes");
    dns_query q;
    CK(parse_g(b, n, &q) == 0 && strcmp(q.qname, nm) == 0, "the 255-byte name round-trips");

    /* 256 wire bytes: 3 x 63 + 62. RFC 1035 §2.3.4 caps a name at 255 octets, and
     * dns_encode_name now enforces that on the way out — so the one-octet-over
     * fixture is assembled by the test's own encoder (build_query_raw), which
     * checks label syntax only. That is exactly the packet a hostile peer sends;
     * the point of the fixture is the DECODER's reaction to it. */
    size_t o = 0;
    for (int i = 0; i < 3; i++) { if (o) nm[o++] = '.'; for (int k = 0; k < 63; k++) nm[o++] = 'a'; }
    nm[o++] = '.'; for (int k = 0; k < 62; k++) nm[o++] = 'b';
    nm[o] = '\0';
    CK(dns_encode_name(b, sizeof b, nm) == -1,
       "[RFC 1035 2.3.4] dns_encode_name will not emit the 256-octet name");
    n = build_query_raw(b, sizeof b, 1, 0, nm, DNS_A, DNS_CLASS_IN);
    CK(n == 12 + 256 + 4, "the 256-byte fixture really is 256 wire bytes");
    CK(parse_g(b, n, &q) == -1, "[RFC 1035 2.3.4] a 256-octet name is rejected");

    /* an unambiguously over-long name must be rejected (out_cap guard) */
    o = 0;
    for (int i = 0; i < 5; i++) { if (o) nm[o++] = '.'; for (int k = 0; k < 63; k++) nm[o++] = 'c'; }
    nm[o] = '\0';
    n = build_query_raw(b, sizeof b, 1, 0, nm, DNS_A, DNS_CLASS_IN);
    CK(n > 0 && parse_g(b, n, &q) == -1, "a 320-octet name is rejected");
}

/* ═══════════════ 2. adversarial decode battery ══════════════════════════ */
#define MUST_REJECT 1
#define NO_CRASH    0

static void hdr(uint8_t *b, uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar) {
    p16(b + 0, 0x1234); p16(b + 2, 0x0100);
    p16(b + 4, qd); p16(b + 6, an); p16(b + 8, ns); p16(b + 10, ar);
}
static void adv(const char *what, const uint8_t *b, size_t n, int strict) {
    dns_query q;
    int rc = parse_g(b, n, &q);
    if (strict) CK(rc == -1, what);
    else        CK(rc == 0 || rc == -1, what);
}

static void section_adversarial(void) {
    g_where = "adversarial battery";
    uint8_t b[70000];

    /* — compression-pointer loops — */
    memset(b, 0, 32); hdr(b, 1, 0, 0, 0);
    b[12] = 0xC0; b[13] = 0x0C;                    /* points at itself */
    p16(b + 14, DNS_A); p16(b + 16, DNS_CLASS_IN);
    adv("ptr loop: self-referential 0xC00C rejected", b, 18, MUST_REJECT);

    memset(b, 0, 32); hdr(b, 1, 0, 0, 0);
    b[12] = 0xC0; b[13] = 0x0E; b[14] = 0xC0; b[15] = 0x0C;   /* A→B→A */
    p16(b + 16, DNS_A); p16(b + 18, DNS_CLASS_IN);
    adv("ptr loop: two pointers pointing at each other rejected", b, 20, MUST_REJECT);

    /* a 300-link forward chain, then a loop back to the start */
    memset(b, 0, 1024); hdr(b, 1, 0, 0, 0);
    for (int i = 0; i < 300; i++) { size_t at = 12 + (size_t)i * 2;
        b[at] = 0xC0; b[at + 1] = (uint8_t)(at + 2); }
    b[12 + 600] = 0xC0; b[12 + 601] = 0x0C;        /* close the loop */
    adv("ptr loop: a 300-link pointer chain rejected (guard bounds it)", b, 12 + 604, MUST_REJECT);

    /* a legal 100-link chain that terminates in a real name must still work
     * (the question's own name is one pointer into a chain parked at 300) */
    memset(b, 0, 1024); hdr(b, 1, 0, 0, 0);
    {   size_t chain = 300, tail = 300 + 200;
        b[tail] = 3; memcpy(b + tail + 1, "www", 3); b[tail + 4] = 0;
        for (int i = 0; i < 99; i++) { size_t at = chain + (size_t)i * 2;
            uint16_t nxt = (uint16_t)(i == 98 ? tail : at + 2);
            b[at] = (uint8_t)(0xC0 | (nxt >> 8)); b[at + 1] = (uint8_t)nxt; }
        b[12] = (uint8_t)(0xC0 | (chain >> 8)); b[13] = (uint8_t)chain;
        p16(b + 14, DNS_A); p16(b + 16, DNS_CLASS_IN);
        dns_query q;
        CK(parse_g(b, 1024, &q) == 0 && strcmp(q.qname, "www") == 0,
           "ptr chain: 100 legal links still resolve (guard does not over-trip)");
    }

    /* — pointers out of bounds / into the middle of a label — */
    memset(b, 0, 32); hdr(b, 1, 0, 0, 0);
    b[12] = 0xC1; b[13] = 0xFF;                    /* target 0x1FF, past the end */
    adv("ptr past end of buffer rejected", b, 20, MUST_REJECT);

    memset(b, 0, 32); hdr(b, 1, 0, 0, 0);
    b[12] = 0xC0; b[13] = 0x13;                    /* forward, past our own data */
    adv("ptr forward past the written body rejected", b, 16, MUST_REJECT);

    memset(b, 0, 64); hdr(b, 1, 0, 0, 0);
    b[12] = 3; memcpy(b + 13, "www", 3); b[16] = 0;   /* a real name at 12 */
    p16(b + 17, DNS_A); p16(b + 19, DNS_CLASS_IN);
    b[21] = 0xC0; b[22] = 0x0E;                    /* into the middle of "www" */
    adv("ptr into the middle of a label does not crash", b, 24, NO_CRASH);

    /* — reserved / malformed label length bytes — */
    for (unsigned L = 0x40; L <= 0xBF; L += 0x10) {
        memset(b, 0, 32); hdr(b, 1, 0, 0, 0);
        b[12] = (uint8_t)L; b[13] = 'a'; b[14] = 0;
        char m[64]; snprintf(m, sizeof m, "reserved label length 0x%02X rejected", L);
        adv(m, b, 20, MUST_REJECT);
    }
    memset(b, 0, 32); hdr(b, 1, 0, 0, 0);
    b[12] = 0xC0;                                   /* pointer as the LAST byte */
    adv("0xC0 as the final byte (no offset octet) rejected", b, 13, MUST_REJECT);
    memset(b, 0, 32); hdr(b, 1, 0, 0, 0);
    b[12] = 0x3F;                                   /* 63-byte label, no bytes */
    adv("label length past the end of the buffer rejected", b, 13, MUST_REJECT);

    /* — unterminated names — */
    memset(b, 0, 32); hdr(b, 1, 0, 0, 0);
    b[12] = 3; memcpy(b + 13, "abc", 3);            /* no root byte, no qtype */
    adv("name with no terminating zero rejected", b, 16, MUST_REJECT);

    memset(b, 0, 600); hdr(b, 1, 0, 0, 0);
    { size_t o = 12; for (int i = 0; i < 8; i++) { b[o++] = 63; memset(b + o, 'z', 63); o += 63; }
      b[o] = 0;
      adv("name longer than 255 bytes rejected", b, o + 1, MUST_REJECT); }

    /* — degenerate message sizes — */
    adv("zero-length message rejected", b, 0, MUST_REJECT);
    adv("1-byte message rejected", b, 1, MUST_REJECT);
    memset(b, 0, 12); hdr(b, 1, 0, 0, 0);
    adv("header-only message (QDCOUNT=1, no question) rejected", b, 12, MUST_REJECT);
    hdr(b, 0, 0, 0, 0);
    adv("QDCOUNT=0 rejected", b, 12, MUST_REJECT);

    /* — count / body mismatch — */
    memset(b, 0, 64); hdr(b, 1, 5, 0, 0);
    b[12] = 3; memcpy(b + 13, "www", 3); b[16] = 0;
    p16(b + 17, DNS_A); p16(b + 19, DNS_CLASS_IN);
    { dns_query q;
      CK(parse_g(b, 21, &q) == 0 && strcmp(q.qname, "www") == 0,
         "ANCOUNT=5 with an empty body: question still parses, no crash"); }
    hdr(b, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF);
    adv("all counts 0xFFFF with a 21-byte body terminates", b, 21, NO_CRASH);
    hdr(b, 1, 0xFFFF, 0xFFFF, 0xFFFF);
    adv("AN/NS/AR = 0xFFFF each terminates", b, 21, NO_CRASH);

    /* — rdlength abuse — */
    memset(b, 0, 64); hdr(b, 1, 1, 0, 0);
    b[12] = 3; memcpy(b + 13, "www", 3); b[16] = 0;
    p16(b + 17, DNS_A); p16(b + 19, DNS_CLASS_IN);
    b[21] = 0xC0; b[22] = 0x0C;                     /* answer owner = ptr to q */
    p16(b + 23, DNS_A); p16(b + 25, DNS_CLASS_IN);
    p16(b + 27, 0); p16(b + 29, 0);                 /* ttl hi/lo */
    p16(b + 31, 0xFFFF);                            /* rdlen overruns wildly */
    adv("rdlength overrunning the buffer does not crash", b, 33, NO_CRASH);
    p16(b + 31, 0);                                 /* rdlen 0 for an A record */
    adv("rdlength 0 on an A record does not crash", b, 33, NO_CRASH);
    p16(b + 31, 2);                                 /* under-runs: A needs 4 */
    adv("rdlength under-running the record type does not crash", b, 35, NO_CRASH);

    /* — a 64 KB message of random bytes — */
    for (size_t i = 0; i < 65536; i++) b[i] = (uint8_t)sm64();
    adv("64 KB of random bytes terminates", b, 65536, NO_CRASH);
    memset(b, 0xC0, 65536);                         /* 32k self/near pointers */
    adv("64 KB of 0xC0 pointer bytes terminates", b, 65536, NO_CRASH);
    memset(b, 0xFF, 65536);
    adv("64 KB of 0xFF terminates", b, 65536, NO_CRASH);
}

/* ═══════════════ truncation sweep + mutation fuzz ═══════════════════════ */
static size_t fixture(int which, uint8_t *b, size_t cap) {
    char nm[300];
    switch (which) {
    case 0: return build_query(b, cap, 0xBEEF, 0x0100, "www.pepenet.pepe", DNS_A, DNS_CLASS_IN, 0, 0);
    case 1: return build_query(b, cap, 0xBEEF, 0x0100, "_443._tcp.www.pepenet.pepe", DNS_TLSA, DNS_CLASS_IN, 1, 4096);
    case 2: return build_query(b, cap, 0x0001, 0x0000, "", DNS_NS, DNS_CLASS_IN, 0, 0);
    case 3: { max_name(nm); return build_query(b, cap, 0x7FFF, 0x0100, nm, DNS_TXT, DNS_CLASS_IN, 1, 1232); }
    case 4: {   /* a full response: question + 4 answers + OPT */
        size_t qn = build_query(b, cap, 0x4242, 0x0100, "a.b.c.pepe", 255, DNS_CLASS_IN, 1, 1232);
        if (!qn) return 0;
        dns_query q; if (dns_parse_query(b, qn, &q) != 0) return 0;
        dns_resp r; dns_resp_begin(&r, b, cap, &q, DNS_RCODE_NOERROR);
        uint8_t rd[600];
        for (int i = 0; i < 4; i++) {
            uint16_t t = TYPES[i % NTYPES];
            uint16_t l = rnd_rdata(t, rd, sizeof rd);
            if (l) dns_resp_add(&r, q.qname, t, 3600, rd, l);
        }
        dns_resp_add_opt(&r, 1232);
        return dns_resp_finish(&r);
    }
    case 5: {   /* hand-built message with legal backward compression pointers */
        hdr(b, 1, 1, 0, 0);
        size_t o = 12;
        b[o++] = 3; memcpy(b + o, "www", 3); o += 3;
        b[o++] = 4; memcpy(b + o, "pepe", 4); o += 4;
        b[o++] = 0;
        p16(b + o, DNS_A); o += 2; p16(b + o, DNS_CLASS_IN); o += 2;
        b[o++] = 0xC0; b[o++] = 0x0C;                 /* owner -> offset 12 */
        p16(b + o, DNS_A); o += 2; p16(b + o, DNS_CLASS_IN); o += 2;
        p16(b + o, 0); o += 2; p16(b + o, 60); o += 2;
        p16(b + o, 4); o += 2;
        b[o++] = 10; b[o++] = 0; b[o++] = 0; b[o++] = 1;
        return o;
    }
    default: return 0;
    }
}
#define NFIX 6

static void section_truncation(void) {
    g_where = "truncation sweep";
    uint8_t b[4096], t[4096];
    long sweeps = 0;
    int rejected_short = 1;
    for (int f = 0; f < NFIX; f++) {
        size_t n = fixture(f, b, sizeof b);
        if (n == 0) { CK(0, "truncation fixture built"); continue; }
        for (size_t cut = 0; cut <= n; cut++) {
            memcpy(t, b, cut);
            dns_query q;
            int rc = parse_g(t, cut, &q);
            sweeps++;
            if (cut < 12 && rc != -1) rejected_short = 0;
        }
    }
    printf("  (%ld prefixes decoded across %d fixtures)\n", sweeps, NFIX);
    CK(sweeps > 500, "every byte prefix of every fixture was decoded");
    CK(rejected_short, "every prefix shorter than the 12-byte header is rejected");
    CK(1, "no prefix crashed, hung or read out of bounds");
}

static void section_fuzz(int mut_iters, int rnd_iters, int soup_iters) {
    uint8_t b[4096], t[4096];
    dns_query q;

    g_where = "mutation fuzz";
    for (int i = 0; i < mut_iters; i++) {
        size_t n = fixture((int)rnd(NFIX), b, sizeof b);
        if (n == 0) continue;
        memcpy(t, b, n);
        int k = 1 + (int)rnd(8);
        for (int j = 0; j < k; j++) t[rnd((uint32_t)n)] = (uint8_t)sm64();
        parse_g(t, n, &q);
        if (rnd(4) == 0) parse_g(t, 1 + rnd((uint32_t)n), &q);   /* mutate + truncate */
    }
    CK(1, "mutation fuzz: byte-flipped fixtures never crash or hang");

    g_where = "random-buffer fuzz";
    for (int i = 0; i < rnd_iters; i++) {
        size_t n = rnd(1200);
        for (size_t j = 0; j < n; j++) t[j] = (uint8_t)sm64();
        if (n >= 12 && rnd(2)) { p16(t + 4, 1); }   /* half get a plausible QDCOUNT */
        parse_g(t, n, &q);
    }
    CK(1, "random-buffer fuzz: arbitrary bytes never crash or hang");

    g_where = "pointer-soup fuzz";
    for (int i = 0; i < soup_iters; i++) {
        size_t n = 12 + 2 * (size_t)(1 + rnd(400));
        hdr(t, (uint16_t)(1 + rnd(4)), (uint16_t)rnd(8), 0, (uint16_t)rnd(4));
        for (size_t j = 12; j + 1 < n; j += 2) {
            uint32_t r = rnd(10);
            if (r < 7) { uint16_t tgt = (uint16_t)rnd((uint32_t)n);   /* mostly pointers */
                         t[j] = (uint8_t)(0xC0 | (tgt >> 8)); t[j + 1] = (uint8_t)tgt; }
            else { t[j] = (uint8_t)rnd(64); t[j + 1] = (uint8_t)sm64(); }
        }
        parse_g(t, n, &q);
    }
    CK(1, "pointer-soup fuzz: dense compression pointers never loop forever");
    printf("  (%d mutation + %d random + %d pointer-soup decodes)\n",
           mut_iters, rnd_iters, soup_iters);
}

/* ═══════════════ 3. encode boundary safety ══════════════════════════════ */
#define CANARY 0xA5
static uint8_t arena[2048];
static void arena_reset(void) { memset(arena, CANARY, sizeof arena); }
static int arena_clean(size_t from) {
    for (size_t i = from; i < sizeof arena; i++) if (arena[i] != CANARY) return 0;
    return 1;
}

static void section_encode_bounds(void) {
    g_where = "encode bounds";
    const char *nm = "www.pepenet.pepe";
    uint8_t scratch[512];
    int need = dns_encode_name(scratch, sizeof scratch, nm);
    CK(need == 18, "dns_encode_name reports the exact wire length");

    arena_reset();
    CK(dns_encode_name(arena, (size_t)need, nm) == need, "encode into an exactly-sized buffer succeeds");
    CK(arena_clean((size_t)need), "  ... and writes not one byte past it");

    arena_reset();
    CK(dns_encode_name(arena, (size_t)need - 1, nm) == -1, "encode into a one-byte-short buffer fails");
    CK(arena_clean((size_t)need - 1), "  ... and writes nothing past the short cap");

    arena_reset();
    CK(dns_encode_name(arena, 0, nm) == -1, "encode into a zero-byte buffer fails");
    CK(arena_clean(0), "  ... and writes nothing at all");

    arena_reset();
    CK(dns_encode_name(arena, 1, "") == 1 && arena[0] == 0, "the root name encodes to a single 0 byte");
    CK(arena_clean(1), "  ... and writes nothing past it");
    arena_reset();
    CK(dns_encode_name(arena, 0, "") == -1, "the root name into 0 bytes fails");
    CK(arena_clean(0), "  ... writing nothing");

    /* malformed dotted input */
    char big[80]; memset(big, 'a', 64); big[64] = '\0';
    CK(dns_encode_name(scratch, sizeof scratch, big) == -1, "a 64-byte label is rejected");
    memset(big, 'a', 63); big[63] = '\0';
    CK(dns_encode_name(scratch, sizeof scratch, big) == 65, "a 63-byte label encodes (65 bytes)");
    { uint8_t fq[64], bare[64];
      int a = dns_encode_name(fq, sizeof fq, "www.pepe.");
      int c = dns_encode_name(bare, sizeof bare, "www.pepe");
      CK(a == c && a == 10 && memcmp(fq, bare, (size_t)a) == 0,
         "a trailing dot (FQDN form) encodes identically to the bare name"); }
    CK(dns_encode_name(scratch, sizeof scratch, "a..b") == -1, "an empty interior label is rejected");
    CK(dns_encode_name(scratch, sizeof scratch, ".www") == -1, "a leading dot is rejected");

    /* The total-name limit is the encoder's, not the caller buffer's: a 320-octet
     * name is refused even though `scratch` is easily big enough for it. */
    { char lng[400]; size_t o = 0;
      for (int i = 0; i < 5; i++) { if (o) lng[o++] = '.'; for (int k = 0; k < 63; k++) lng[o++] = 'd'; }
      lng[o] = '\0';
      CK(dns_encode_name(scratch, sizeof scratch, lng) == -1,
         "[RFC 1035 2.3.4] encoding a 320-octet name is rejected"); }

    /* ── the response builder against tight buffers ── */
    uint8_t qb[128];
    size_t qn = build_query(qb, sizeof qb, 0x1111, 0x0100, nm, DNS_A, DNS_CLASS_IN, 0, 0);
    dns_query q; CK(parse(qb, qn, &q) == 0, "fixture query parses");

    size_t hdrq = 12 + 18 + 4;                       /* header + question */
    dns_resp r;
    for (size_t cap = 0; cap < hdrq; cap++) {
        arena_reset();
        dns_resp_begin(&r, arena, cap, &q, DNS_RCODE_NOERROR);
        if (dns_resp_finish(&r) != 0 || !arena_clean(cap)) {
            char m[80]; snprintf(m, sizeof m, "dns_resp_begin with cap=%zu stays in bounds", cap);
            CK(0, m); break;
        }
    }
    CK(1, "dns_resp_begin fails cleanly (len 0, no OOB write) for every cap < header+question");

    arena_reset();
    dns_resp_begin(&r, arena, hdrq, &q, DNS_RCODE_NOERROR);
    CK(dns_resp_finish(&r) == hdrq, "dns_resp_begin fits an exactly-sized header+question");
    CK(arena_clean(hdrq), "  ... with no write past the cap");

    /* adding one A RR needs 18 + 10 + 4 = 32 more bytes */
    uint8_t ip[4] = { 10, 0, 0, 1 };
    arena_reset();
    dns_resp_begin(&r, arena, hdrq + 32, &q, DNS_RCODE_NOERROR);
    CK(dns_resp_add(&r, nm, DNS_A, 60, ip, 4) == 0, "dns_resp_add fits an exactly-sized RR");
    CK(dns_resp_finish(&r) == hdrq + 32 && arena_clean(hdrq + 32), "  ... writing exactly cap bytes");

    arena_reset();
    dns_resp_begin(&r, arena, hdrq + 31, &q, DNS_RCODE_NOERROR);
    CK(dns_resp_add(&r, nm, DNS_A, 60, ip, 4) == -1, "dns_resp_add refuses a one-byte-short buffer");
    CK(arena_clean(hdrq + 31), "  ... and writes nothing past the cap");

    /* the soft budget: over-limit RRs set TC, never overflow */
    arena_reset();
    dns_resp_begin(&r, arena, 1024, &q, DNS_RCODE_NOERROR);
    dns_resp_set_limit(&r, hdrq + 10);
    CK(dns_resp_add(&r, nm, DNS_A, 60, ip, 4) == -1, "an RR over the soft budget is dropped");
    CK(r.truncated == 1, "  ... and marks the response truncated");
    size_t tn = dns_resp_finish(&r);
    CK(tn == hdrq && (arena[2] & 0x02), "  ... TC is set in the finished header");
    CK(arena_clean(1024), "  ... nothing written past the hard cap");

    /* set_limit is clamped to [len, cap] */
    arena_reset();
    dns_resp_begin(&r, arena, 128, &q, DNS_RCODE_NOERROR);
    dns_resp_set_limit(&r, 0);
    CK(r.limit == r.len, "dns_resp_set_limit clamps below to the bytes already written");
    dns_resp_set_limit(&r, 1 << 20);
    CK(r.limit == 128, "dns_resp_set_limit clamps above to the hard cap");

    /* OPT against a tight cap */
    arena_reset();
    dns_resp_begin(&r, arena, hdrq + 10, &q, DNS_RCODE_NOERROR);
    CK(dns_resp_add_opt(&r, 1232) == -1, "dns_resp_add_opt refuses when 11 bytes do not fit");
    CK(arena_clean(hdrq + 10), "  ... and writes nothing past the cap");
    arena_reset();
    dns_resp_begin(&r, arena, hdrq + 11, &q, DNS_RCODE_NOERROR);
    CK(dns_resp_add_opt(&r, 1232) == 0, "dns_resp_add_opt fits an exactly-sized OPT");
    CK(dns_resp_finish(&r) == hdrq + 11 && arena_clean(hdrq + 11), "  ... writing exactly cap bytes");

    /* a max-size rdata RR against a max-size buffer */
    { uint8_t rd[65535]; memset(rd, 0x5A, sizeof rd);
      static uint8_t big2[70000];
      dns_resp r2;
      dns_resp_begin(&r2, big2, sizeof big2, &q, DNS_RCODE_NOERROR);
      CK(dns_resp_add(&r2, nm, DNS_A, 60, rd, 65535) == 0, "a 65535-byte rdata RR encodes");
      CK(dns_resp_finish(&r2) == hdrq + 18 + 10 + 65535, "  ... at the expected length"); }
}

/* ═══════════════ main ═══════════════════════════════════════════════════ */
int main(int argc, char **argv) {
    const char *s = getenv("WIRE_SEED");
    if (argc > 1) g_seed = strtoull(argv[1], NULL, 0);
    else if (s)   g_seed = strtoull(s, NULL, 0);
    else          g_seed = 0x5EEDD09EULL;
    g_s = g_seed;
    printf("wire_test: seed %llu  (reproduce: WIRE_SEED=%llu ./wire_test)\n",
           (unsigned long long)g_seed, (unsigned long long)g_seed);

    guard_init();
    CK(g_page != NULL, "guard page armed (a 1-byte overread past the message faults)");

    signal(SIGALRM, on_alarm);
    signal(SIGSEGV, on_crash);
    signal(SIGBUS,  on_crash);

    printf("-- round-trip (encode -> decode, seeded-random property test) --\n");
    section_roundtrip(6000);

    printf("-- name length limits --\n");
    section_name_limits();

    printf("-- adversarial decode battery --\n");
    section_adversarial();

    printf("-- truncation sweep (every byte prefix of every fixture) --\n");
    section_truncation();

    printf("-- fuzz --\n");
    { const char *m = getenv("WIRE_FUZZ_X");        /* soak multiplier for CI/manual runs */
      int x = m ? atoi(m) : 1; if (x < 1) x = 1;
      section_fuzz(40000 * x, 20000 * x, 20000 * x); }

    printf("-- encode buffer-boundary safety --\n");
    section_encode_bounds();

    g_where = "done"; alarm(0);
    printf("wire_test: %d ok, %d failed\n", g_ok, g_fail);
    return g_fail ? 1 : 0;
}
