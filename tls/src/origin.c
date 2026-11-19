/* origin.c — see origin.h. Pure logic; no I/O. */
#include "origin.h"
#include "dns_wire.h"   /* DNS_A, DNS_CNAME, DNS_TLSA */

#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

int origin_split(const char *sni, const char *suffix,
                 char *apex, size_t apexcap, char *sub, size_t subcap) {
    if (!sni || !suffix || !*suffix) return 0;
    size_t nl = strlen(sni), sl = strlen(suffix);

    /* must end with ".<suffix>" */
    if (nl <= sl + 1) return 0;
    if (sni[nl - sl - 1] != '.') return 0;
    if (strcasecmp(sni + nl - sl, suffix) != 0) return 0;

    /* `left` = the name minus ".<suffix>" */
    size_t leftlen = nl - sl - 1;
    char left[256];
    if (leftlen >= sizeof left) return 0;
    memcpy(left, sni, leftlen);
    left[leftlen] = '\0';

    /* apex = last label; sub = everything before it (may be empty) */
    const char *dot = strrchr(left, '.');
    const char *ap = dot ? dot + 1 : left;
    if (!*ap) return 0;                       /* empty apex, e.g. "foo..doge" */
    if (strlen(ap) >= apexcap) return 0;
    snprintf(apex, apexcap, "%s", ap);

    if (dot) {
        size_t subl = (size_t)(dot - left);
        if (subl >= subcap) return 0;
        memcpy(sub, left, subl);
        sub[subl] = '\0';
    } else {
        if (subcap < 1) return 0;
        sub[0] = '\0';
    }
    return 1;
}

/* Linear scan for the first record at (label, type) — same match rule dnsd uses
 * (case-insensitive label). Returns NULL if absent. */
static const zone_rec *look(const zone *z, const char *label, uint16_t type) {
    for (int i = 0; i < z->n; i++)
        if (z->recs[i].type == type && strcasecmp(z->recs[i].label, label) == 0)
            return &z->recs[i];
    return NULL;
}

/* Wire dname → dotted text (stored rdata is built by dns_encode_name and is
 * never compressed). Returns 0 on malformed bytes. */
static int dname_text(const uint8_t *p, int len, char *out, size_t cap) {
    size_t o = 0;
    int i = 0;
    while (i < len && p[i]) {
        int l = p[i++];
        if (l > 63 || l > len - i) return 0;
        if (o + (size_t)l + 2 > cap) return 0;
        if (o) out[o++] = '.';
        memcpy(out + o, p + i, (size_t)l);
        o += (size_t)l;
        i += l;
    }
    out[o] = '\0';
    return o > 0;
}

/* Map a CNAME target back to a label of THIS zone:
 *   "<apex>.<suffix>"     → ""        (the apex)
 *   "x.y.<apex>.<suffix>" → "x.y"
 *   "bare"  (no dots)     → "bare"    (zone-relative shorthand)
 * Anything else (another apex, an ICANN name) is outside this zone → 0.
 * Cross-zone/cross-DNS chasing is deliberately not done here: the pin is
 * per-SNI in OUR mesh, and dialing origins named by foreign DNS would pull
 * an unauthenticated resolver into the trust path. */
static int inzone_label(const char *target, const char *apex, const char *suffix,
                        char *out, size_t cap) {
    if (!strchr(target, '.')) {               /* bare label */
        if (strlen(target) >= cap) return 0;
        snprintf(out, cap, "%s", target);
        return 1;
    }
    char zone_fqdn[160];
    snprintf(zone_fqdn, sizeof zone_fqdn, "%s.%s", apex, suffix);
    size_t tl = strlen(target), fl = strlen(zone_fqdn);
    if (tl == fl && strcasecmp(target, zone_fqdn) == 0) {
        if (cap < 1) return 0;
        out[0] = '\0';                        /* the apex itself */
        return 1;
    }
    if (tl > fl + 1 && target[tl - fl - 1] == '.' &&
        strcasecmp(target + tl - fl, zone_fqdn) == 0) {
        size_t subl = tl - fl - 1;
        if (subl >= cap) return 0;
        memcpy(out, target, subl);
        out[subl] = '\0';
        return 1;
    }
    return 0;
}

int origin_from_zone(const zone *z, const char *sub, const char *suffix,
                     OriginInfo *out) {
    if (!z || !sub || !out) return 0;

    /* A record at `sub` → origin IP; chase in-zone CNAMEs (9c draws
     * `www CNAME <apex>.<tld>`) up to 4 hops — the hop cap is also the
     * cycle guard. The TLSA lookup below stays at the ORIGINAL sub: pins
     * are per-SNI hostname, never inherited through a CNAME. */
    char cur[128];
    snprintf(cur, sizeof cur, "%s", sub);
    const zone_rec *a = NULL;
    for (int hop = 0; hop < 5; hop++) {
        a = look(z, cur, DNS_A);
        if (a) break;
        const zone_rec *c = look(z, cur, DNS_CNAME);
        if (!c || !suffix) return 0;
        char tgt[256];
        if (!dname_text(c->rdata, c->rdlen, tgt, sizeof tgt)) return 0;
        if (!inzone_label(tgt, z->apex, suffix, cur, sizeof cur)) return 0;
    }
    if (!a || a->rdlen != 4) return 0;
    /* never dial loopback / unspecified / link-local: A=127.0.0.1 plus the
     * lo0 :443→proxy rdr recurses into this process until PROXY_CONN_MAX. */
    { unsigned b0 = a->rdata[0], b1 = a->rdata[1];
      if (b0 == 0 || b0 == 127 || b0 == 10 || b0 >= 224) return 0;
      if (b0 == 169 && b1 == 254) return 0;
      if (b0 == 172 && b1 >= 16 && b1 <= 31) return 0;
      if (b0 == 192 && b1 == 168) return 0; }

    /* TLSA lives at `_443._tcp` for the apex, or `_443._tcp.<sub>` otherwise. */
    char tlsa_label[80];
    if (*sub) snprintf(tlsa_label, sizeof tlsa_label, "_443._tcp.%s", sub);
    else      snprintf(tlsa_label, sizeof tlsa_label, "_443._tcp");

    const zone_rec *t = look(z, tlsa_label, DNS_TLSA);
    if (!t || t->rdlen < 4) return 0;         /* need header + ≥1 assoc byte */

    size_t alen = (size_t)t->rdlen - 3;
    if (alen > sizeof out->assoc) return 0;   /* refuse an oversized association */

    memset(out, 0, sizeof *out);
    if (!inet_ntop(AF_INET, a->rdata, out->host, sizeof out->host)) return 0;
    out->port     = 443;
    /* v1 is DANE-EE 3 1 1 only (DESIGN.md). Passing other usage/selector
     * through to OpenSSL would let a zone pin a public CA (DANE-TA). */
    if (t->rdata[0] != 3 || t->rdata[1] != 1 || t->rdata[2] != 1 || alen != 32)
        return 0;
    out->usage    = 3;
    out->selector = 1;
    out->mtype    = 1;
    memcpy(out->assoc, t->rdata + 3, alen);
    out->assoc_len = alen;
    return 1;
}

/* GreatDANE (additive): does the zone carry ANY TLSA at this name's _443._tcp
 * label? Lets a caller tell "no TLSA published" from "bad/unusable record"
 * after origin_from_zone refused. Pure read; no format change. */
int origin_has_tlsa(const zone *z, const char *sub) {
    if (!z || !sub) return 0;
    char tlsa_label[80];
    if (*sub) snprintf(tlsa_label, sizeof tlsa_label, "_443._tcp.%s", sub);
    else      snprintf(tlsa_label, sizeof tlsa_label, "_443._tcp");
    return look(z, tlsa_label, DNS_TLSA) != NULL;
}
