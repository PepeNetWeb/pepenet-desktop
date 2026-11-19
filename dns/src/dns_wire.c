/* dns_wire.c — see dns_wire.h. */
#include "dns_wire.h"

#include <string.h>
#include <ctype.h>

/* ── name reading (with compression-pointer support) ───────────────────── */

/* Read a wire name starting at buf[*off] into `out` (dotted, lowercased).
 * If `orig` is non-NULL it receives the same name with its octets UNFOLDED —
 * exactly as they appeared on the wire — so a responder can echo the question
 * verbatim (RFC 1035 §4.1.2) while still matching case-insensitively. It must
 * be at least out_cap bytes.
 * Follows one or more 0xC0 compression pointers, guarding against loops.
 * Advances *off past the name in the *current* stream (i.e. to just after the
 * first pointer, per RFC 1035). Returns 0 on success, -1 on malformed. */
static int read_name(const uint8_t *buf, size_t len, size_t *off,
                     char *out, size_t out_cap, char *orig)
{
    size_t pos = *off;
    size_t opos = 0;
    size_t wire = 1;           /* octets the name occupies, incl. the root label */
    int    jumped = 0;
    int    guard = 0;          /* bound pointer chains */
    size_t advanced_to = 0;    /* where *off lands (first pointer, if any) */

    for (;;) {
        if (pos >= len) return -1;
        uint8_t l = buf[pos];

        if ((l & 0xC0) == 0xC0) {           /* compression pointer */
            if (pos + 1 >= len) return -1;
            size_t target = ((size_t)(l & 0x3F) << 8) | buf[pos + 1];
            if (!jumped) advanced_to = pos + 2;
            jumped = 1;
            if (++guard > 128) return -1;
            if (target >= len) return -1;
            pos = target;
            continue;
        }
        if ((l & 0xC0) != 0) return -1;      /* reserved label type */

        if (l == 0) {                         /* end of name */
            if (!jumped) advanced_to = pos + 1;
            break;
        }
        wire += (size_t)l + 1;
        if (wire > DNS_NAME_MAX) return -1;   /* RFC 1035 §2.3.4: 255 octets */
        pos++;
        if (pos + l > len) return -1;
        if (opos && opos + 1 < out_cap) { if (orig) orig[opos] = '.'; out[opos++] = '.'; }
        for (uint8_t i = 0; i < l; i++) {
            if (opos + 1 >= out_cap) return -1;
            if (orig) orig[opos] = (char)buf[pos + i];
            out[opos++] = (char)tolower(buf[pos + i]);
        }
        pos += l;
    }
    out[opos] = '\0';
    if (orig) orig[opos] = '\0';
    *off = advanced_to;
    return 0;
}

/* Skip a wire name (following pointers) — discards the decoded text. */
static int skip_name(const uint8_t *buf, size_t len, size_t *off)
{
    char tmp[DNS_NAME_MAX + 1];
    return read_name(buf, len, off, tmp, sizeof tmp, NULL);
}

/* Skip one RR (name + fixed fields + rdata). */
static int skip_rr(const uint8_t *buf, size_t len, size_t *off)
{
    if (skip_name(buf, len, off) != 0) return -1;
    if (*off + 10 > len) return -1;
    size_t rdlen = ((size_t)buf[*off + 8] << 8) | buf[*off + 9];
    *off += 10 + rdlen;
    return (*off <= len) ? 0 : -1;
}

int dns_parse_query(const uint8_t *buf, size_t len, dns_query *q)
{
    if (len < 12) return -1;
    q->id    = (uint16_t)((buf[0] << 8) | buf[1]);
    q->flags = (uint16_t)((buf[2] << 8) | buf[3]);
    uint16_t qd = (uint16_t)((buf[4] << 8) | buf[5]);
    uint16_t an = (uint16_t)((buf[6] << 8) | buf[7]);
    uint16_t ns = (uint16_t)((buf[8] << 8) | buf[9]);
    uint16_t ar = (uint16_t)((buf[10] << 8) | buf[11]);
    if (qd < 1) return -1;

    q->edns = 0; q->edns_version = 0; q->udp_payload = 0;

    size_t off = 12;
    if (read_name(buf, len, &off, q->qname, sizeof q->qname, q->qname_orig) != 0)
        return -1;
    if (off + 4 > len) return -1;
    q->qtype  = (uint16_t)((buf[off]     << 8) | buf[off + 1]);
    q->qclass = (uint16_t)((buf[off + 2] << 8) | buf[off + 3]);
    off += 4;

    /* Walk to the additional section and pick up an EDNS0 OPT if present. A
     * well-formed query has an=ns=0, but skip them defensively. Malformed tails
     * are not fatal here — the question is already parsed; just stop scanning. */
    for (int i = 1; i < qd; i++) {
        if (skip_name(buf, len, &off) != 0 || off + 4 > len) return 0;
        off += 4;
    }
    for (int i = 0; i < an + ns; i++)
        if (skip_rr(buf, len, &off) != 0) return 0;

    for (int i = 0; i < ar; i++) {
        if (skip_name(buf, len, &off) != 0 || off + 10 > len) return 0;
        uint16_t type  = (uint16_t)((buf[off]     << 8) | buf[off + 1]);
        uint16_t cls   = (uint16_t)((buf[off + 2] << 8) | buf[off + 3]);
        size_t   rdlen = ((size_t)buf[off + 8] << 8) | buf[off + 9];
        if (type == 41) {                      /* OPT: class=UDP size, ttl[1]=version */
            q->edns = 1;
            q->udp_payload = cls;
            q->edns_version = buf[off + 5];
        }
        off += 10 + rdlen;
        if (off > len) return 0;
    }
    return 0;
}

/* ── name writing (uncompressed) ───────────────────────────────────────── */

int dns_encode_name(uint8_t *out, size_t cap, const char *dotted)
{
    size_t o = 0;
    const char *p = dotted;

    while (*p) {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        if (l == 0 || l > 63) return -1;         /* empty/oversize label */
        /* RFC 1035 §2.3.4: 255 octets total, root label included. */
        if (o + 1 + l + 1 > DNS_NAME_MAX) return -1;
        if (o + 1 + l >= cap) return -1;
        out[o++] = (uint8_t)l;
        memcpy(out + o, p, l);
        o += l;
        if (!dot) break;
        p = dot + 1;
    }
    if (o + 1 > cap) return -1;
    out[o++] = 0;                                 /* root label */
    return (int)o;
}

/* ── response builder ──────────────────────────────────────────────────── */

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

void dns_resp_begin(dns_resp *r, uint8_t *buf, size_t cap,
                    const dns_query *q, int rcode)
{
    r->buf = buf; r->cap = cap; r->limit = cap; r->len = 0;
    r->ancount = 0; r->arcount = 0; r->truncated = 0; r->ok = 1;
    if (cap < 12) { r->ok = 0; return; }

    /* Header. flags: QR=1, Opcode from request, AA=1, RD echoed, RA=0, rcode. */
    uint16_t opcode = (q->flags >> 11) & 0x0F;
    uint16_t rd     = (q->flags >> 8)  & 0x01;
    uint16_t flags  = 0x8000                 /* QR */
                    | (uint16_t)(opcode << 11)
                    | 0x0400                 /* AA */
                    | (uint16_t)(rd << 8)
                    | (uint16_t)(rcode & 0x0F);

    put16(buf + 0, q->id);
    put16(buf + 2, flags);
    put16(buf + 4, 1);   /* QDCOUNT */
    put16(buf + 6, 0);   /* ANCOUNT (patched at finish) */
    put16(buf + 8, 0);   /* NSCOUNT */
    put16(buf + 10, 0);  /* ARCOUNT */
    r->len = 12;

    /* Question section: echo the question EXACTLY as it was asked — the
     * original octets, not the folded lookup key (RFC 1035 §4.1.2). Callers
     * that fill a dns_query by hand and leave qname_orig empty fall back to
     * qname (identical for the root name, where both are empty). */
    const char *qn = q->qname_orig[0] ? q->qname_orig : q->qname;
    int n = dns_encode_name(buf + r->len, cap - r->len, qn);
    if (n < 0 || r->len + (size_t)n + 4 > cap) { r->ok = 0; return; }
    r->len += (size_t)n;
    put16(buf + r->len, q->qtype);  r->len += 2;
    put16(buf + r->len, q->qclass); r->len += 2;
}

void dns_resp_set_limit(dns_resp *r, size_t limit)
{
    if (limit < r->len) limit = r->len;   /* never below what's already written */
    if (limit > r->cap) limit = r->cap;
    r->limit = limit;
}

int dns_resp_add(dns_resp *r, const char *owner, uint16_t type,
                 uint32_t ttl, const uint8_t *rdata, uint16_t rdlen)
{
    /* Once truncated, stop adding — a DNS answer must not carry RRs past the
     * one that overflowed the budget (the client will retry over TCP). */
    if (!r->ok || r->truncated) return -1;
    int n = dns_encode_name(r->buf + r->len, r->cap - r->len, owner);
    if (n < 0) { r->ok = 0; return -1; }       /* hard buffer overflow on the name */
    size_t need = (size_t)n + 10 + rdlen;      /* name + type,class,ttl,rdlen + rdata */
    if (r->len + need > r->limit) { r->truncated = 1; return -1; }   /* soft budget → TC */

    r->len += (size_t)n;
    put16(r->buf + r->len, type);          r->len += 2;
    put16(r->buf + r->len, DNS_CLASS_IN);  r->len += 2;
    put32(r->buf + r->len, ttl);           r->len += 4;
    put16(r->buf + r->len, rdlen);         r->len += 2;
    memcpy(r->buf + r->len, rdata, rdlen); r->len += rdlen;
    r->ancount++;
    return 0;
}

int dns_resp_add_opt(dns_resp *r, uint16_t udp_payload)
{
    if (!r->ok) return -1;
    /* OPT pseudo-RR: root name (1 byte) + type,class,ttl,rdlen (10) = 11 bytes,
     * no options. CLASS carries our max UDP payload; TTL is ext-rcode|version|
     * flags, all zero (version 0, DO=0 — we do not do DNSSEC). Callers reserve
     * these 11 bytes when setting the answer budget, so check the hard cap. */
    if (r->len + 11 > r->cap) return -1;
    uint8_t *p = r->buf + r->len;
    p[0] = 0x00;                       /* root name */
    put16(p + 1, 41);                  /* TYPE = OPT */
    put16(p + 3, udp_payload);         /* CLASS = our UDP payload size */
    put32(p + 5, 0);                   /* TTL = ext-rcode 0, version 0, flags 0 */
    put16(p + 9, 0);                   /* RDLEN = 0 */
    r->len += 11;
    r->arcount++;
    return 0;
}

size_t dns_resp_finish(dns_resp *r)
{
    if (!r->ok) return 0;
    put16(r->buf + 6, (uint16_t)r->ancount);
    put16(r->buf + 10, (uint16_t)r->arcount);
    if (r->truncated) {                              /* set TC in the flags word */
        uint16_t flags = (uint16_t)((r->buf[2] << 8) | r->buf[3]);
        put16(r->buf + 2, flags | 0x0200);
    }
    return r->len;
}
