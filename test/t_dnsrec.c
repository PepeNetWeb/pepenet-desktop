/* t_dnsrec.c — the DNS record-editor validators from src/ui/dialogs.c.
 *
 * Proves the two foot-gun guards and the charset gate behave exactly as their
 * comment claims: a zone-RELATIVE host that was typed as an FQDN (anything
 * ending in ".pepe", case-insensitively) is refused before it can fold to
 * "gpt.pepe.gpt.pepe"; an IPv4/IPv6 literal typed as a CNAME/NS target is
 * refused because it encodes as a legal-but-unchaseable dname; "@" and a bare
 * host are accepted; and the composite `val_ok` predicate the dialog actually
 * gates its Save button on wires those two guards together with the REAL
 * rdata parser (dns/src/zone.c zone_build_rec — linked, not mirrored).
 *
 * MIRRORED COPY — KEEP IN SYNC. dnsm_host_ok / dnsm_host_is_fqdn /
 * dnsm_val_is_ip and the val_ok composite below are byte-for-byte copies of
 * src/ui/dialogs.c:1226-1277. They are `static` inside a translation unit that
 * pulls in nuklear and the whole GUI, so they cannot be linked here. Only
 * zone_build_rec (the part that can be isolated) is the genuine article. If
 * dialogs.c changes those helpers, change them here too — this suite pins the
 * mirror, not the original.
 */
#include "appconf.h"        /* APP_DOT_TLD — the real ".pepe" the dialog uses */
#include "zone.h"           /* the REAL rdata parser */
#include "dns_wire.h"       /* DNS_A / DNS_CNAME / DNS_NS / … type codes */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static int g_fail;
#define CHECK(cond, name) do { \
    if (cond) printf("ok   %s\n", name); \
    else      { printf("FAIL %s\n", name); g_fail = 1; } \
} while (0)

/* ── MIRROR of src/ui/dialogs.c:1226-1249 ─────────────────────────────────── */
static int dnsm_host_ok(const char *h) {
    if (!h[0] || !strcmp(h, "@")) return 1;
    for (const char *p = h; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
              *p == '-' || *p == '_' || *p == '.'))
            return 0;
    return 1;
}
static int dnsm_host_is_fqdn(const char *h) {
    size_t hl = strlen(h), tl = strlen(APP_DOT_TLD);
    if (hl && h[hl - 1] == '.') hl--;      // one optional DNS root dot: "www.pepe."
    return hl >= tl && strncasecmp(h + hl - tl, APP_DOT_TLD, tl) == 0;
}
static int dnsm_val_is_ip(const char *v) {
    struct in_addr a4;
    struct in6_addr a6;
    return inet_pton(AF_INET, v, &a4) == 1 || inet_pton(AF_INET6, v, &a6) == 1;
}

/* ── MIRROR of the d_dns_rec gate (dialogs.c:1266-1278) ───────────────────── */
/* Returns the dialog's `val_ok` for a (type mnemonic, code, host, ttl, value)
 * exactly as typed: host_len/val_len are strlen of the field contents. */
static int dlg_val_ok(const char *type_mnemonic, int tcode,
                      const char *host, unsigned ttl, const char *val,
                      int *host_fqdn_out, int *cname_ip_out) {
    const char *label = (!host[0] || !strcmp(host, "@")) ? "@" : host;
    int host_fqdn = host[0] != 0 && dnsm_host_is_fqdn(host);
    int host_ok   = dnsm_host_ok(host) && !host_fqdn;
    int cname_ip  = (tcode == DNS_CNAME || tcode == DNS_NS) &&
                    val[0] != 0 && dnsm_val_is_ip(val);
    zone_rec rec;
    int val_ok = val[0] != 0 && host_ok && !cname_ip &&
                 zone_build_rec(label, type_mnemonic, ttl ? ttl : 3600, val, &rec) == 0 &&
                 rec.rdlen > 0;
    if (host_fqdn_out) *host_fqdn_out = host_fqdn;
    if (cname_ip_out)  *cname_ip_out  = cname_ip;
    return val_ok;
}

int main(void) {
    printf("-- the TLD is what the app config says --\n");
    CHECK(strcmp(APP_DOT_TLD, ".pepe") == 0, "APP_DOT_TLD is \".pepe\"");
    CHECK(strcmp(APP_TLD, "pepe") == 0, "APP_TLD is \"pepe\"");

    printf("-- dnsm_host_is_fqdn: hosts are zone-RELATIVE --\n");
    CHECK(dnsm_host_is_fqdn("gpt.pepe") == 1, "\"gpt.pepe\" is an FQDN (would fold to gpt.pepe.gpt.pepe)");
    CHECK(dnsm_host_is_fqdn("gpt.PEPE") == 1, "\".PEPE\" caught case-insensitively");
    CHECK(dnsm_host_is_fqdn("gpt.Pepe") == 1, "\".Pepe\" caught case-insensitively");
    CHECK(dnsm_host_is_fqdn("GPT.PEPE") == 1, "\"GPT.PEPE\" caught case-insensitively");
    CHECK(dnsm_host_is_fqdn(".pepe") == 1, "the bare suffix \".pepe\" is itself an FQDN");
    CHECK(dnsm_host_is_fqdn("www") == 0, "a bare host is not an FQDN");
    CHECK(dnsm_host_is_fqdn("@") == 0, "\"@\" (the apex) is not an FQDN");
    CHECK(dnsm_host_is_fqdn("") == 0, "the empty host is not an FQDN");
    CHECK(dnsm_host_is_fqdn("pepe") == 0, "\"pepe\" alone is a legal label, not an FQDN");
    CHECK(dnsm_host_is_fqdn("mypepe") == 0, "\"mypepe\" ends in pepe WITHOUT the dot -> not an FQDN");
    CHECK(dnsm_host_is_fqdn("apepe") == 0, "\"apepe\" (suffix minus the dot) -> not an FQDN");
    CHECK(dnsm_host_is_fqdn("_pepe") == 0, "\"_pepe\" -> not an FQDN (underscore, not dot)");
    CHECK(dnsm_host_is_fqdn("pep") == 0, "a host shorter than the suffix -> not an FQDN");
    CHECK(dnsm_host_is_fqdn("a.b.c.pepe") == 1, "a deep FQDN is still an FQDN");
    /* trailing dot: "www.pepe." is the same typo with the DNS root dot on it.
     * The guard compares the last 5 bytes literally, so ".pepe." misses. */
    CHECK(dnsm_host_is_fqdn("www.pepe.") == 1,
          "FAILS: \"www.pepe.\" (trailing root dot) is the same FQDN typo, not caught");
    CHECK(dnsm_host_is_fqdn("www.") == 0, "a plain trailing dot is not an FQDN");

    printf("-- dnsm_val_is_ip: an IP literal is not a dname --\n");
    CHECK(dnsm_val_is_ip("216.24.57.1") == 1, "\"216.24.57.1\" is an IPv4 literal");
    CHECK(dnsm_val_is_ip("0.0.0.0") == 1, "\"0.0.0.0\" is an IPv4 literal");
    CHECK(dnsm_val_is_ip("255.255.255.255") == 1, "\"255.255.255.255\" is an IPv4 literal");
    CHECK(dnsm_val_is_ip("2606:4700:4700::1111") == 1, "an IPv6 literal is caught");
    CHECK(dnsm_val_is_ip("::1") == 1, "\"::1\" is caught");
    CHECK(dnsm_val_is_ip("::ffff:216.24.57.1") == 1, "an IPv4-mapped IPv6 literal is caught");
    CHECK(dnsm_val_is_ip("example.com") == 0, "a real hostname is not an IP");
    CHECK(dnsm_val_is_ip("1.2.3.4.example") == 0, "\"1.2.3.4.example\" merely LOOKS numeric");
    CHECK(dnsm_val_is_ip("1.2.3.4.5") == 0, "five dotted octets is not an IPv4 literal");
    CHECK(dnsm_val_is_ip("216.24.57") == 0, "a three-octet literal is rejected (no inet_aton shorthand)");
    CHECK(dnsm_val_is_ip("256.1.1.1") == 0, "an out-of-range octet is not an IP");
    CHECK(dnsm_val_is_ip("") == 0, "the empty value is not an IP");

    printf("-- dnsm_host_ok: the charset gate --\n");
    CHECK(dnsm_host_ok("") == 1, "empty host means the apex -> allowed");
    CHECK(dnsm_host_ok("@") == 1, "\"@\" means the apex -> allowed");
    CHECK(dnsm_host_ok("www") == 1, "a bare label is allowed");
    CHECK(dnsm_host_ok("_443._tcp") == 1, "the TLSA underscore labels are allowed");
    CHECK(dnsm_host_ok("a-b.c-d") == 1, "hyphens and dots are allowed");
    CHECK(dnsm_host_ok("WWW") == 0, "uppercase is refused (labels are lowercased on the wire)");
    CHECK(dnsm_host_ok("w w") == 0, "a space is refused");
    CHECK(dnsm_host_ok("w/w") == 0, "a slash is refused");
    CHECK(dnsm_host_ok("w\xC3\xA9") == 0, "non-ASCII is refused");

    printf("-- the dialog gate: CNAME / NS targets --\n");
    {
        int fqdn = 0, ip = 0;
        CHECK(dlg_val_ok("CNAME", DNS_CNAME, "www", 3600, "216.24.57.1", &fqdn, &ip) == 0 && ip == 1,
              "IPv4 as a CNAME target is REJECTED");
        CHECK(dlg_val_ok("CNAME", DNS_CNAME, "www", 3600, "2606:4700:4700::1111", &fqdn, &ip) == 0 && ip == 1,
              "IPv6 as a CNAME target is REJECTED");
        CHECK(dlg_val_ok("NS", DNS_NS, "sub", 3600, "216.24.57.1", &fqdn, &ip) == 0 && ip == 1,
              "IPv4 as an NS target is REJECTED");
        CHECK(dlg_val_ok("NS", DNS_NS, "sub", 3600, "::1", &fqdn, &ip) == 0 && ip == 1,
              "IPv6 as an NS target is REJECTED");
        CHECK(dlg_val_ok("CNAME", DNS_CNAME, "www", 3600, "target.example.com", &fqdn, &ip) == 1 && ip == 0,
              "a real hostname CNAME target is ACCEPTED");
        CHECK(dlg_val_ok("CNAME", DNS_CNAME, "www", 3600, "1.2.3.4.example", &fqdn, &ip) == 1 && ip == 0,
              "\"1.2.3.4.example\" is a dname, not an IP -> ACCEPTED");
        CHECK(dlg_val_ok("A", DNS_A, "www", 3600, "216.24.57.1", &fqdn, &ip) == 1 && ip == 0,
              "the same IPv4 in an A record is ACCEPTED (that is where it belongs)");
        CHECK(dlg_val_ok("AAAA", DNS_AAAA, "www", 3600, "2606:4700:4700::1111", &fqdn, &ip) == 1 && ip == 0,
              "an IPv6 in an AAAA record is ACCEPTED");
    }

    printf("-- the dialog gate: host forms --\n");
    {
        int fqdn = 0, ip = 0;
        CHECK(dlg_val_ok("A", DNS_A, "", 3600, "216.24.57.1", &fqdn, &ip) == 1 && fqdn == 0,
              "an empty host (the apex) is ACCEPTED");
        CHECK(dlg_val_ok("A", DNS_A, "@", 3600, "216.24.57.1", &fqdn, &ip) == 1 && fqdn == 0,
              "\"@\" is ACCEPTED");
        CHECK(dlg_val_ok("A", DNS_A, "www", 3600, "216.24.57.1", &fqdn, &ip) == 1 && fqdn == 0,
              "a bare host is ACCEPTED");
        CHECK(dlg_val_ok("A", DNS_A, "gpt.pepe", 3600, "216.24.57.1", &fqdn, &ip) == 0 && fqdn == 1,
              "a host typed as an FQDN is REJECTED");
        CHECK(dlg_val_ok("A", DNS_A, "gpt.PEPE", 3600, "216.24.57.1", &fqdn, &ip) == 0 && fqdn == 1,
              "\".PEPE\" is REJECTED (case-insensitive)");
        CHECK(dlg_val_ok("A", DNS_A, "gpt.Pepe", 3600, "216.24.57.1", &fqdn, &ip) == 0 && fqdn == 1,
              "\".Pepe\" is REJECTED (case-insensitive)");
        CHECK(dlg_val_ok("A", DNS_A, ".pepe", 3600, "216.24.57.1", &fqdn, &ip) == 0 && fqdn == 1,
              "the host \".pepe\" exactly is REJECTED");
        CHECK(dlg_val_ok("A", DNS_A, "mypepe", 3600, "216.24.57.1", &fqdn, &ip) == 1 && fqdn == 0,
              "a host ending in \"pepe\" WITHOUT the dot is ACCEPTED");
        CHECK(dlg_val_ok("A", DNS_A, "www.", 3600, "216.24.57.1", &fqdn, &ip) == 1 && fqdn == 0,
              "a lone trailing dot passes the FQDN guard");
        CHECK(dlg_val_ok("A", DNS_A, "WWW", 3600, "216.24.57.1", &fqdn, &ip) == 0,
              "an uppercase host is REJECTED by the charset gate");
        CHECK(dlg_val_ok("A", DNS_A, "www", 3600, "", &fqdn, &ip) == 0,
              "an empty value is REJECTED");
    }

    printf("-- the dialog gate: the REAL rdata parser still has the last word --\n");
    {
        int fqdn = 0, ip = 0;
        CHECK(dlg_val_ok("A", DNS_A, "www", 3600, "not-an-ip", &fqdn, &ip) == 0,
              "a non-IP in an A record is REJECTED by zone_build_rec");
        CHECK(dlg_val_ok("AAAA", DNS_AAAA, "www", 3600, "216.24.57.1", &fqdn, &ip) == 0,
              "an IPv4 in an AAAA record is REJECTED by zone_build_rec");
        CHECK(dlg_val_ok("TXT", DNS_TXT, "_site", 3600, "a small pepenet site", &fqdn, &ip) == 1,
              "a _site TXT blurb is ACCEPTED");
        CHECK(dlg_val_ok("MX", DNS_MX, "@", 3600, "10 mail.example.com", &fqdn, &ip) == 1,
              "a well-formed MX is ACCEPTED");
        CHECK(dlg_val_ok("MX", DNS_MX, "@", 3600, "mail.example.com", &fqdn, &ip) == 0,
              "an MX missing its preference is REJECTED");
        /* the guards only run ahead of the parser — they never rescue it */
        zone_rec rec;
        CHECK(zone_build_rec("@", "A", 3600, "216.24.57.1", &rec) == 0 && rec.rdlen == 4,
              "zone_build_rec is the linked, genuine article (A -> 4 rdata bytes)");
    }

    printf("-- ttl handling --\n");
    {
        int fqdn = 0, ip = 0;
        /* ttl 0 falls back to 3600 for the rdata build; the Save button is
         * gated separately on ttl_ok (ttlv > 0), which val_ok does not see. */
        CHECK(dlg_val_ok("A", DNS_A, "www", 0, "216.24.57.1", &fqdn, &ip) == 1,
              "ttl 0 still builds valid rdata (the Save gate refuses it separately)");
        CHECK(dlg_val_ok("A", DNS_A, "www", 60, "216.24.57.1", &fqdn, &ip) == 1,
              "an explicit ttl builds valid rdata");
    }

    printf("%s\n", g_fail ? "t_dnsrec: FAIL" : "t_dnsrec: all ok");
    return g_fail;
}
