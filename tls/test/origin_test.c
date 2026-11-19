/* origin_test.c — hermetic proof of the resolver's pure core (DESIGN.md §7
 * slice 4). No store, no db, no network: we hand-build a folded `zone` and
 * assert the name split + the A/TLSA extraction that feeds the DANE dial.
 *
 * The security-critical assertions: (1) the TLSA 35 bytes are split into
 * usage/selector/mtype/assoc EXACTLY as dane_connect expects, and (2) a name
 * with an A but NO TLSA is refused — we never hand the proxy an origin it
 * cannot DANE-authenticate.
 */
#include "origin.h"
#include "dns_wire.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

static int pass = 0, fail = 0;
static void ok(const char *w)  { pass++; printf("  ok   %s\n", w); }
static void bad(const char *w) { fail++; printf("FAIL   %s\n", w); }

static void add_A(zone *z, const char *label, const char *ip) {
    zone_rec *r = &z->recs[z->n++];
    memset(r, 0, sizeof *r);
    snprintf(r->label, sizeof r->label, "%s", label);
    r->type = DNS_A; r->ttl = 3600;
    inet_pton(AF_INET, ip, r->rdata); r->rdlen = 4;
}
static void add_TLSA(zone *z, const char *label,
                     uint8_t u, uint8_t s, uint8_t m, const uint8_t assoc[32]) {
    zone_rec *r = &z->recs[z->n++];
    memset(r, 0, sizeof *r);
    snprintf(r->label, sizeof r->label, "%s", label);
    r->type = DNS_TLSA; r->ttl = 3600;
    r->rdata[0] = u; r->rdata[1] = s; r->rdata[2] = m;
    memcpy(r->rdata + 3, assoc, 32);
    r->rdlen = 3 + 32;                       /* canonical "3 1 1" = 35 bytes */
}

static void add_CNAME(zone *z, const char *label, const char *target) {
    zone_rec *r = &z->recs[z->n++];
    memset(r, 0, sizeof *r);
    snprintf(r->label, sizeof r->label, "%s", label);
    r->type = DNS_CNAME; r->ttl = 3600;
    /* wire-encode the dname the same way dns_encode_name does */
    size_t o = 0;
    const char *p = target;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        r->rdata[o++] = (uint8_t)l;
        memcpy(r->rdata + o, p, l);
        o += l;
        p += l + (dot ? 1 : 0);
        if (!dot) break;
    }
    r->rdata[o++] = 0;
    r->rdlen = (uint16_t)o;
}

int main(void) {
    printf("── origin: name split + A/TLSA extraction (pure) ──\n");

    /* ── name split ── */
    char apex[64], sub[128];
    if (origin_split("www.pepenet.doge", "doge", apex, sizeof apex, sub, sizeof sub)
        && !strcmp(apex, "pepenet") && !strcmp(sub, "www"))
        ok("split www.pepenet.doge → apex=pepenet sub=www");
    else bad("split www.pepenet.doge");

    if (origin_split("pepenet.doge", "doge", apex, sizeof apex, sub, sizeof sub)
        && !strcmp(apex, "pepenet") && !strcmp(sub, ""))
        ok("split pepenet.doge → apex=pepenet sub=(apex)");
    else bad("split pepenet.doge (apex)");

    if (origin_split("a.b.pepenet.doge", "doge", apex, sizeof apex, sub, sizeof sub)
        && !strcmp(apex, "pepenet") && !strcmp(sub, "a.b"))
        ok("split a.b.pepenet.doge → apex=pepenet sub=a.b");
    else bad("split a.b.pepenet.doge");

    /* wrong suffix (this box serves .doge, name is .pepe) → refuse */
    if (!origin_split("www.pepenet.pepe", "doge", apex, sizeof apex, sub, sizeof sub))
        ok("split refuses a .pepe name on a .doge resolver");
    else bad("split should refuse cross-suffix");

    /* case-insensitive suffix match */
    if (origin_split("www.pepenet.DOGE", "doge", apex, sizeof apex, sub, sizeof sub)
        && !strcmp(apex, "pepenet"))
        ok("split is case-insensitive on the suffix");
    else bad("split case-insensitive suffix");

    /* ── A + TLSA extraction ── */
    uint8_t assoc[32];
    for (int i = 0; i < 32; i++) assoc[i] = (uint8_t)(i * 7 + 1);

    zone z; memset(&z, 0, sizeof z);
    snprintf(z.apex, sizeof z.apex, "pepenet");
    add_A(&z, "www", "192.0.2.7");
    add_TLSA(&z, "_443._tcp.www", 3, 1, 1, assoc);
    add_A(&z, "naked", "192.0.2.8");             /* A but NO TLSA */
    add_A(&z, "", "192.0.2.1");                  /* apex A */
    add_TLSA(&z, "_443._tcp", 3, 1, 1, assoc);   /* apex TLSA */

    OriginInfo oi;
    if (origin_from_zone(&z, "www", "doge", &oi)
        && !strcmp(oi.host, "192.0.2.7") && oi.port == 443
        && oi.usage == 3 && oi.selector == 1 && oi.mtype == 1
        && oi.assoc_len == 32 && memcmp(oi.assoc, assoc, 32) == 0)
        ok("www → 192.0.2.7:443 + TLSA 3 1 1, assoc bytes exact");
    else bad("www origin extraction");

    if (origin_from_zone(&z, "", "doge", &oi)
        && !strcmp(oi.host, "192.0.2.1") && oi.assoc_len == 32)
        ok("apex → apex A + _443._tcp TLSA");
    else bad("apex origin extraction");

    /* A present, TLSA absent → NOT servable (can't DANE-authenticate) */
    if (!origin_from_zone(&z, "naked", "doge", &oi))
        ok("A but no TLSA → refused (never serve an unauthenticatable origin)");
    else bad("naked should be refused");

    /* unknown subdomain → not servable */
    if (!origin_from_zone(&z, "nope", "doge", &oi))
        ok("unknown subdomain → refused");
    else bad("unknown subdomain should be refused");

    /* ── CNAME chase (9c: `www CNAME <apex>.<tld>`) ── */
    add_CNAME(&z, "alias", "pepenet.doge");          /* alias → apex A */
    add_TLSA(&z, "_443._tcp.alias", 3, 1, 1, assoc);
    if (origin_from_zone(&z, "alias", "doge", &oi)
        && !strcmp(oi.host, "192.0.2.1"))
        ok("CNAME alias → apex A chased; pin read at _443._tcp.alias");
    else bad("CNAME to apex");

    add_CNAME(&z, "hop", "alias.pepenet.doge");      /* hop → alias → apex */
    add_TLSA(&z, "_443._tcp.hop", 3, 1, 1, assoc);
    if (origin_from_zone(&z, "hop", "doge", &oi)
        && !strcmp(oi.host, "192.0.2.1"))
        ok("two-hop CNAME chain chased");
    else bad("two-hop CNAME");

    add_CNAME(&z, "bare", "www");                    /* zone-relative target */
    add_TLSA(&z, "_443._tcp.bare", 3, 1, 1, assoc);
    if (origin_from_zone(&z, "bare", "doge", &oi)
        && !strcmp(oi.host, "192.0.2.7"))
        ok("bare-label CNAME target resolves zone-relative");
    else bad("bare-label CNAME");

    add_CNAME(&z, "ext", "example.com");             /* outside the zone */
    add_TLSA(&z, "_443._tcp.ext", 3, 1, 1, assoc);
    if (!origin_from_zone(&z, "ext", "doge", &oi))
        ok("CNAME to a foreign name refused (no cross-DNS trust)");
    else bad("foreign CNAME should refuse");

    add_CNAME(&z, "othr", "other.doge");             /* another apex, our TLD */
    add_TLSA(&z, "_443._tcp.othr", 3, 1, 1, assoc);
    if (!origin_from_zone(&z, "othr", "doge", &oi))
        ok("CNAME to another apex refused (single-zone chase)");
    else bad("cross-apex CNAME should refuse");

    add_CNAME(&z, "loopa", "loopb.pepenet.doge");    /* cycle */
    add_CNAME(&z, "loopb", "loopa.pepenet.doge");
    add_TLSA(&z, "_443._tcp.loopa", 3, 1, 1, assoc);
    if (!origin_from_zone(&z, "loopa", "doge", &oi))
        ok("CNAME cycle refused (hop cap)");
    else bad("CNAME cycle should refuse");

    /* the chased pin rule: alias with the A but WITHOUT its own TLSA refuses
     * even though the apex has one — pins are per-SNI, never inherited */
    add_CNAME(&z, "nopin", "pepenet.doge");
    if (!origin_from_zone(&z, "nopin", "doge", &oi))
        ok("chased alias without its own TLSA refused (no pin inheritance)");
    else bad("pin must not be inherited through CNAME");

    printf("\n%d ok, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
