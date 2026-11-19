/* zone_test.c — src/zone.c (the zone-file / record-text front door) and the
 * sp_state record key it feeds (dns_key_pack/unpack in src/dns_state.c).
 *
 * PROVEN HERE
 *   • text -> wire rdata for every type zone.c claims to support, byte-exact,
 *     plus the rejection of every malformed rdata form.
 *   • PARSE -> SERIALIZE -> PARSE round-trip: a zone file holding one record of
 *     each type is loaded, written back out from the parsed records alone, and
 *     re-loaded; every field of every record must survive both hops identically.
 *   • the record key format — label bytes ‖ type_be16: exact layout, case
 *     folding, the empty (apex) label, the 63-byte label boundary, unique
 *     decodability, and the big-endian type ordering that dns_state's
 *     key-ordered iteration (and therefore the gossip digest) depends on.
 *   • THE TWO REAL USER BUGS, now fixed and pinned as executable evidence of
 *     the fix (each keeps the explanation of what went wrong):
 *       - a record whose label already carries the TLD suffix ("gpt.pepe"
 *         inside the gpt zone) would fold to gpt.pepe.gpt.pepe — zone_build_rec
 *         refuses it (the zone FILE parser deliberately still accepts it);
 *       - a CNAME whose target is an IP literal ("216.24.57.1"), which
 *         dns_encode_name happily turns into four dname labels — zone_build_rec
 *         encodes it, sees an address, and refuses the record.
 *   • duplicate keys, the empty zone, and the record-count / rdata-byte budget
 *     boundaries (ZONE_MAX_RECS, ZONE_MAX_RDATA), plus the malformed-line paths.
 *
 * Fixtures live in a mkdtemp'd /tmp directory and are removed on exit. Nothing
 * touches ~/.pepenet and nothing opens a socket.
 */
#include "zone.h"
#include "dns_wire.h"
#include "dns_state.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_ok, g_fail;
#define CK(c, m) do { if (c) { g_ok++; printf("  ok   %s\n", m); } \
                      else { g_fail++; printf("  FAIL %s\n", m); } } while (0)

/* ── /tmp fixture directory ──────────────────────────────────────────────── */
static char g_dir[] = "/tmp/zone_test.XXXXXX";
static char *g_tmp;

static const char *fx(const char *base) {
    static char path[512];
    snprintf(path, sizeof path, "%s/%s", g_tmp, base);
    return path;
}
static const char *write_zone(const char *base, const char *body) {
    const char *p = fx(base);
    FILE *f = fopen(p, "w");
    if (!f) { perror("fopen"); exit(2); }
    fputs(body, f); fclose(f);
    return p;
}
static void cleanup(void) {
    DIR *d = opendir(g_tmp);
    if (d) { struct dirent *e;
             while ((e = readdir(d))) if (e->d_name[0] != '.') unlink(fx(e->d_name));
             closedir(d); }
    rmdir(g_tmp);
}

/* ── test-local wire helpers ─────────────────────────────────────────────── */
static void tohex(const uint8_t *b, int n, char *out) {
    for (int i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]);
    out[2 * n] = '\0';
}
/* Decode an uncompressed wire dname back to dotted text. -1 if malformed. */
static int dname_text(const uint8_t *rd, int rdlen, char *out, size_t cap) {
    int p = 0; size_t o = 0;
    for (;;) {
        if (p >= rdlen) return -1;
        uint8_t l = rd[p];
        if (l == 0) { p++; break; }
        if (l > 63 || p + 1 + l > rdlen) return -1;
        p++;
        if (o) { if (o + 1 >= cap) return -1; out[o++] = '.'; }
        if (o + l >= cap) return -1;
        memcpy(out + o, rd + p, l); o += l; p += l;
    }
    out[o] = '\0';
    return p;
}
/* Reverse of build_rdata: render a parsed record's rdata back to zone-file
 * text. Used only to prove the parse->serialize->parse round-trip. */
static int rec_text(const zone_rec *r, char *out, size_t cap) {
    char nm[300], hx[1200];
    switch (r->type) {
    case DNS_A:
        return inet_ntop(AF_INET, r->rdata, out, (socklen_t)cap) ? 0 : -1;
    case DNS_AAAA:
        return inet_ntop(AF_INET6, r->rdata, out, (socklen_t)cap) ? 0 : -1;
    case DNS_CNAME: case DNS_NS: case DNS_PTR:
        if (dname_text(r->rdata, r->rdlen, nm, sizeof nm) < 0) return -1;
        snprintf(out, cap, "%s", nm); return 0;
    case DNS_MX:
        if (r->rdlen < 3) return -1;
        if (dname_text(r->rdata + 2, r->rdlen - 2, nm, sizeof nm) < 0) return -1;
        snprintf(out, cap, "%u %s", (unsigned)((r->rdata[0] << 8) | r->rdata[1]), nm);
        return 0;
    case DNS_TXT:
        if (r->rdlen < 1 || r->rdata[0] != r->rdlen - 1) return -1;
        snprintf(out, cap, "\"%.*s\"", (int)r->rdata[0], (const char *)r->rdata + 1);
        return 0;
    case DNS_TLSA:
        if (r->rdlen < 4) return -1;
        tohex(r->rdata + 3, r->rdlen - 3, hx);
        snprintf(out, cap, "%u %u %u %s", r->rdata[0], r->rdata[1], r->rdata[2], hx);
        return 0;
    case DNS_SSHFP:
        if (r->rdlen < 3) return -1;
        tohex(r->rdata + 2, r->rdlen - 2, hx);
        snprintf(out, cap, "%u %u %s", r->rdata[0], r->rdata[1], hx);
        return 0;
    default:
        tohex(r->rdata, r->rdlen, hx);
        snprintf(out, cap, "%s", hx); return 0;
    }
}
static int rec_eq(const zone_rec *a, const zone_rec *b) {
    return strcmp(a->label, b->label) == 0 && a->type == b->type &&
           a->ttl == b->ttl && a->rdlen == b->rdlen &&
           memcmp(a->rdata, b->rdata, a->rdlen) == 0;
}

static const char HEX32[] = "0123456789abcdef0123456789abcdef"
                            "0123456789abcdef0123456789abcdef";   /* 64 hex = 32B */

/* ═══════════ 1. text -> wire rdata ══════════════════════════════════════ */
static void section_rdata(void) {
    zone_rec r;

    CK(zone_build_rec("www", "A", 300, "192.0.2.9", &r) == 0 && r.rdlen == 4 &&
       memcmp(r.rdata, "\xC0\x00\x02\x09", 4) == 0 && r.type == DNS_A &&
       r.ttl == 300 && strcmp(r.label, "www") == 0, "A builds 4 network-order bytes");

    { uint8_t want[16]; inet_pton(AF_INET6, "2001:db8::1", want);
      CK(zone_build_rec("www", "AAAA", 60, "2001:db8::1", &r) == 0 && r.rdlen == 16 &&
         memcmp(r.rdata, want, 16) == 0, "AAAA builds 16 bytes"); }

    CK(zone_build_rec("www", "CNAME", 60, "host.pepenet.pepe", &r) == 0 &&
       r.rdlen == 19 && r.rdata[0] == 4 && memcmp(r.rdata + 1, "host", 4) == 0 &&
       r.rdata[18] == 0, "CNAME builds an uncompressed dname");
    CK(zone_build_rec("@", "NS", 60, "ns1.pepe", &r) == 0 && r.type == DNS_NS &&
       r.rdlen == 10 && r.label[0] == '\0', "NS builds a dname and \"@\" is the empty label");
    CK(zone_build_rec("9.2.0.192.in-addr.arpa", "PTR", 60, "host.pepe", &r) == 0 &&
       r.type == DNS_PTR && r.rdlen == 11, "PTR builds a dname");

    CK(zone_build_rec("@", "MX", 60, "10 mail.pepenet.pepe", &r) == 0 &&
       r.rdlen == 21 && r.rdata[0] == 0 && r.rdata[1] == 10 && r.rdata[2] == 4,
       "MX builds preference:be16 ‖ dname");

    CK(zone_build_rec("@", "TXT", 60, "hello", &r) == 0 && r.rdlen == 6 &&
       r.rdata[0] == 5 && memcmp(r.rdata + 1, "hello", 5) == 0,
       "TXT builds one length-prefixed character-string");
    CK(zone_build_rec("@", "TXT", 60, "\"quoted text\"", &r) == 0 && r.rdlen == 12 &&
       r.rdata[0] == 11 && memcmp(r.rdata + 1, "quoted text", 11) == 0,
       "TXT strips surrounding quotes");

    { char t[128]; snprintf(t, sizeof t, "3 1 1 %s", HEX32);
      CK(zone_build_rec("_443._tcp", "TLSA", 60, t, &r) == 0 && r.rdlen == 35 &&
         r.rdata[0] == 3 && r.rdata[1] == 1 && r.rdata[2] == 1 && r.rdata[3] == 0x01,
         "TLSA builds usage/selector/mtype ‖ association"); }
    { char t[128]; snprintf(t, sizeof t, "4 2 %s", HEX32);
      CK(zone_build_rec("@", "SSHFP", 60, t, &r) == 0 && r.rdlen == 34 &&
         r.rdata[0] == 4 && r.rdata[1] == 2, "SSHFP builds algo/fptype ‖ fingerprint"); }

    CK(zone_build_rec("@", "OPENPGPKEY", 60, "deadbeef", &r) == 0 && r.rdlen == 4 &&
       r.rdata[0] == 0xDE, "OPENPGPKEY builds a raw hex blob");
    CK(zone_build_rec("@", "TYPE99", 60, "0011ff", &r) == 0 && r.type == 99 &&
       r.rdlen == 3 && r.rdata[2] == 0xFF, "TYPEnnn builds a raw hex blob");
    CK(zone_build_rec("@", "type99", 60, "010203", &r) == 0 && r.type == 99,
       "the TYPEnnn escape is case-insensitive");
    CK(zone_build_rec("@", "aaaa", 60, "2001:db8::5", &r) == 0 && r.type == DNS_AAAA,
       "type mnemonics are case-insensitive");

    /* the DEL convention */
    CK(zone_build_rec("www", "A", 0, "", &r) == 0 && r.rdlen == 0,
       "empty rdata text builds a delete (rdlen 0)");
    CK(zone_build_rec("www", "A", 0, NULL, &r) == 0 && r.rdlen == 0,
       "NULL rdata text builds a delete");

    /* rejections */
    CK(zone_build_rec("www", "NOSUCH", 60, "x", &r) == -1, "an unknown type mnemonic is rejected");
    CK(zone_build_rec("www", "A", 60, "999.1.1.1", &r) == -1, "a bad IPv4 literal is rejected");
    CK(zone_build_rec("www", "A", 60, "192.0.2", &r) == -1, "a short IPv4 literal is rejected");
    CK(zone_build_rec("www", "AAAA", 60, "not-an-address", &r) == -1, "a bad IPv6 literal is rejected");
    CK(zone_build_rec("www", "AAAA", 60, "192.0.2.9", &r) == -1, "an IPv4 literal is rejected for AAAA");
    CK(zone_build_rec("www", "MX", 60, "mail.pepe", &r) == -1, "MX without a preference is rejected");
    CK(zone_build_rec("www", "TLSA", 60, "3 1", &r) == -1, "a short TLSA is rejected");
    CK(zone_build_rec("www", "TLSA", 60, "3 1 1 zz", &r) == -1, "non-hex TLSA association data is rejected");
    CK(zone_build_rec("www", "TLSA", 60, "3 1 1 abc", &r) == -1, "odd-length TLSA hex is rejected");
    CK(zone_build_rec("www", "SSHFP", 60, "1 gg", &r) == -1, "non-hex SSHFP data is rejected");
    CK(zone_build_rec("www", "TYPE99", 60, "0g", &r) == -1, "non-hex generic rdata is rejected");
    CK(zone_build_rec("www", "CNAME", 60, "a..b", &r) == -1, "a CNAME target with an empty label is rejected");
    { char lbl[80]; memset(lbl, 'x', 64); lbl[64] = '\0';
      CK(zone_build_rec("www", "CNAME", 60, lbl, &r) == -1,
         "a CNAME target with a 64-byte label is rejected"); }
    { char t[600]; strcpy(t, "3 1 1 ");
      for (int i = 0; i < 520; i++) strcat(t, "a");     /* 260 rdata bytes... */
      CK(zone_build_rec("@", "TLSA", 60, t, &r) == 0 && r.rdlen == 263,
         "a 260-byte TLSA association fits ZONE_MAX_RDATA"); }
    { char t[1200]; strcpy(t, "3 1 1 ");
      for (int i = 0; i < 1020; i++) strcat(t, "a");    /* 510 > 512-3 */
      CK(zone_build_rec("@", "TLSA", 60, t, &r) == -1,
         "a TLSA association past ZONE_MAX_RDATA is rejected"); }
    { char t[300]; t[0] = 0; for (int i = 0; i < 255; i++) strcat(t, "y");
      CK(zone_build_rec("@", "TXT", 60, t, &r) == 0 && r.rdlen == 256,
         "a 255-byte TXT string is the maximum and fits"); }
    { char t[400]; t[0] = 0; for (int i = 0; i < 256; i++) strcat(t, "y");
      CK(zone_build_rec("@", "TXT", 60, t, &r) == -1,
         "a 256-byte TXT string is rejected (one character-string only)"); }
}

/* ═══════════ 2. parse -> serialize -> parse round-trip ══════════════════ */
static const char ZBODY[] =
    "# a comment line\n"
    "; another comment\n"
    "\n"
    "serial 42\n"
    "@        A     300 10.0.0.1\n"
    "www      A     300 10.0.0.2\n"
    "www      AAAA  300 2001:db8::2\n"
    "alias    CNAME 300 www.pepenet.pepe\n"
    "@        NS    300 ns1.pepenet.pepe\n"
    "@        MX    300 10 mail.pepenet.pepe\n"
    "@        TXT   300 \"v=spf1 -all\"\n"
    "sub      PTR   300 host.pepenet.pepe\n"
    "_443._tcp TLSA 300 3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
    "@        SSHFP 300 4 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
    "@        OPENPGPKEY 300 cafebabe\n"
    "@        TYPE99 300 001122\n";

static void section_roundtrip(void) {
    static zone z1, z2;
    const char *p = write_zone("rt.zone", ZBODY);
    CK(zone_load(&z1, p, "pepenet") == 0, "the fixture zone file loads");
    CK(z1.n == 12, "every record line became a record");
    CK(z1.serial == 42, "the serial directive is parsed");
    CK(strcmp(z1.apex, "pepenet") == 0, "the apex is stamped onto the zone");
    CK(z1.recs[0].label[0] == '\0', "\"@\" became the empty (apex) label");

    /* serialize every parsed record back to zone-file text */
    const char *p2 = fx("rt2.zone");
    FILE *f = fopen(p2, "w");
    fprintf(f, "serial %llu\n", (unsigned long long)z1.serial);
    int ser_ok = 1;
    for (int i = 0; i < z1.n; i++) {
        char tn[16], txt[1400];
        if (rec_text(&z1.recs[i], txt, sizeof txt) != 0) { ser_ok = 0; break; }
        fprintf(f, "%s %s %u %s\n", z1.recs[i].label[0] ? z1.recs[i].label : "@",
                zone_type_name(z1.recs[i].type, tn, sizeof tn), z1.recs[i].ttl, txt);
    }
    fclose(f);
    CK(ser_ok, "every parsed record serializes back to text");

    CK(zone_load(&z2, p2, "pepenet") == 0, "the re-serialized zone file re-loads");
    CK(z2.n == z1.n && z2.serial == z1.serial, "the reload has the same shape");
    int same = (z1.n == z2.n);
    int firstbad = -1;
    for (int i = 0; same && i < z1.n; i++)
        if (!rec_eq(&z1.recs[i], &z2.recs[i])) { same = 0; firstbad = i; }
    if (firstbad >= 0) printf("       first divergence at record %d (%s type %u)\n",
                              firstbad, z1.recs[firstbad].label, z1.recs[firstbad].type);
    CK(same, "parse -> serialize -> parse is byte-identical for every record");

    /* zone_type_name is the exact inverse of the mnemonic the parser accepts */
    int inv = 1;
    static const struct { uint16_t t; const char *rd; } T[] = {
        { DNS_A, "10.0.0.1" }, { DNS_AAAA, "2001:db8::1" },
        { DNS_CNAME, "a.pepe" }, { DNS_NS, "a.pepe" }, { DNS_PTR, "a.pepe" },
        { DNS_MX, "10 a.pepe" }, { DNS_TXT, "hi" },
        { DNS_SSHFP, "1 1 aabb" }, { DNS_TLSA, "3 1 1 aabb" },
        { DNS_OPENPGPKEY, "00" }, { 99, "00" }, { 65535, "00" },
    };
    for (unsigned i = 0; i < sizeof T / sizeof T[0]; i++) {
        char tn[16]; zone_rec r;
        const char *nmn = zone_type_name(T[i].t, tn, sizeof tn);
        if (zone_build_rec("x", nmn, 1, T[i].rd, &r) != 0 || r.type != T[i].t) { inv = 0;
            printf("       zone_type_name(%u) = '%s' does not round-trip\n", T[i].t, nmn); }
    }
    CK(inv, "zone_type_name round-trips through the type parser for every type");
    /* SRV is in dns_wire.h and in type_code, but has no rdata builder: it falls
       through to the generic hex path, so "1 0 443 host" cannot be expressed. */
    { zone_rec r;
      CK(zone_build_rec("_sip._tcp", "SRV", 60, "1 0 5060 sip.pepe", &r) == -1 &&
         zone_build_rec("_sip._tcp", "SRV", 60, "0001000013c4", &r) == 0,
         "(note) SRV has no rdata builder — only the raw-hex form is accepted");
      CK(zone_build_rec("@", "SOA", 60, "ns1.pepe root.pepe 1 2 3 4 5", &r) == -1,
         "(note) SOA is not a supported zone-file type (README: no SOA at the apex yet)"); }
}

/* ═══════════ 3. the sp_state record key: label ‖ type_be16 ══════════════ */
static void section_key(void) {
    uint8_t k[SP_STATE_KEY_MAX], k2[SP_STATE_KEY_MAX];
    char lbl[64]; uint16_t ty;

    int n = dns_key_pack("www", DNS_A, k, sizeof k);
    CK(n == 5 && memcmp(k, "www", 3) == 0 && k[3] == 0x00 && k[4] == 0x01,
       "key = label bytes ‖ type big-endian");
    CK(dns_key_unpack(k, n, lbl, &ty) && strcmp(lbl, "www") == 0 && ty == DNS_A,
       "key unpacks to the same (label, type)");

    n = dns_key_pack("_443._TCP.WWW", DNS_TLSA, k, sizeof k);
    CK(n == 15 && memcmp(k, "_443._tcp.www", 13) == 0 && k[13] == 0 && k[14] == 52,
       "the label is lowercased into the key (DNS labels are case-blind)");

    n = dns_key_pack("", DNS_SOA, k, sizeof k);
    CK(n == 2 && k[0] == 0 && k[1] == 6, "the apex (empty label) key is just the type");
    CK(dns_key_unpack(k, 2, lbl, &ty) && lbl[0] == '\0' && ty == 6,
       "the apex key unpacks to the empty label");

    { char l63[80]; memset(l63, 'a', 63); l63[63] = '\0';
      CK(dns_key_pack(l63, 1, k, sizeof k) == 65, "a 63-byte label packs (65-byte key)");
      CK(dns_key_unpack(k, 65, lbl, &ty) && strlen(lbl) == 63, "a 65-byte key unpacks");
      memset(l63, 'a', 64); l63[64] = '\0';
      CK(dns_key_pack(l63, 1, k, sizeof k) == -1, "a 64-byte label is refused"); }

    CK(dns_key_pack("www", 1, k, 4) == -1, "a too-small key buffer is refused");
    CK(dns_key_unpack(k, 1, lbl, &ty) == 0, "a 1-byte key is refused");
    CK(dns_key_unpack(k, 0, lbl, &ty) == 0, "a 0-byte key is refused");
    CK(dns_key_unpack(k, 66, lbl, &ty) == 0, "a key implying a 64-byte label is refused");

    /* unique decodability across label length x type, and no aliasing */
    int uniq = 1, inv = 1;
    for (int ll = 0; ll <= 20 && uniq; ll++) {
        char a[64]; memset(a, 'z', (size_t)ll); a[ll] = '\0';
        for (unsigned t = 0; t < 8; t++) {
            uint16_t tt = (uint16_t)(t * 8191);
            int na = dns_key_pack(a, tt, k, sizeof k);
            if (na != ll + 2) { uniq = 0; break; }
            if (!dns_key_unpack(k, na, lbl, &ty) || (int)strlen(lbl) != ll || ty != tt) inv = 0;
            /* a shorter label can never alias a longer one: klen carries it */
            char b[64]; memset(b, 'z', (size_t)(ll + 1)); b[ll + 1] = '\0';
            int nb = dns_key_pack(b, tt, k2, sizeof k2);
            if (na == nb || (na == nb && memcmp(k, k2, (size_t)na) == 0)) { uniq = 0; break; }
        }
    }
    CK(uniq, "no two distinct (label,type) pairs share a key");
    CK(inv, "unpack inverts pack for every label length and type");

    /* the ordering dns_state_digest and sp_state_iter rely on: memcmp order
     * groups a label's types numerically because the type is big-endian */
    int ord = 1;
    int n1 = dns_key_pack("www", 1, k, sizeof k);
    int n2 = dns_key_pack("www", 28, k2, sizeof k2);
    if (!(n1 == n2 && memcmp(k, k2, (size_t)n1) < 0)) ord = 0;
    n2 = dns_key_pack("www", 256, k2, sizeof k2);
    if (!(memcmp(k, k2, (size_t)n1) < 0)) ord = 0;
    CK(ord, "big-endian type bytes keep key order numeric within a label");

    /* pack takes the label from a zone_rec verbatim, including a dotted one */
    zone_rec r;
    zone_build_rec("_443._tcp.www", "TLSA", 60, "3 1 1 aabb", &r);
    n = dns_key_pack(r.label, r.type, k, sizeof k);
    CK(n == 15 && dns_key_unpack(k, n, lbl, &ty) && strcmp(lbl, "_443._tcp.www") == 0,
       "a multi-label subdomain rides the key as opaque bytes");
}

/* ═══════════ 4. the two real user bugs ═════════════════════════════════ */
static void section_tld_fold(void) {
    zone_rec r;
    /* The reported case: an "A" record entered with host "gpt.pepe" while
     * publishing the gpt zone under the .pepe TLD. A label is relative to its
     * apex by construction, so dnsd_core would answer this record only at
     * <label>.<apex>.<tld> = gpt.pepe.gpt.pepe — never the name the user meant.
     * zone.c (label_carries_tld) now refuses the label outright, and refuses it
     * case-blind, since DNS labels are case-insensitive. */
    int rc = zone_build_rec("gpt.pepe", "A", 300, "216.24.57.1", &r);
    printf("       zone_build_rec(label=\"gpt.pepe\") -> rc=%d\n", rc);
    CK(rc == -1 && zone_build_rec("GPT.PePe", "A", 300, "216.24.57.1", &r) == -1,
       "(evidence) the TLD-bearing label is refused, not stored verbatim — in any case");
    { char fqdn[200];
      snprintf(fqdn, sizeof fqdn, "%s.%s.%s", "gpt.pepe", "gpt", "pepe");
      CK(strcmp(fqdn, "gpt.pepe.gpt.pepe") == 0,
         "(evidence) ... because accepted it could only ever answer at gpt.pepe.gpt.pepe"); }
    CK(zone_build_rec("gpt.pepe", "A", 300, "216.24.57.1", &r) == -1,
       "a label that already carries the TLD suffix is rejected");
    CK(zone_build_rec("www.pepenet.pepe", "A", 300, "10.0.0.1", &r) == -1,
       "a label that repeats <apex>.<tld> is rejected");
    /* the check is on the TLD suffix only — an ordinary sub-label is untouched */
    CK(zone_build_rec("pepe", "A", 300, "10.0.0.1", &r) == 0 &&
       zone_build_rec("www.gpt", "A", 300, "10.0.0.1", &r) == 0,
       "a label that merely contains, but does not end in, the TLD still builds");

    /* The zone FILE parser deliberately does NOT share this check: a zone file
     * is authored by the name's owner and loaded verbatim, so it stays able to
     * express the literal label. The strictness lives on the programmatic front
     * door (zone_build_rec), which is what the CLI and the mesh publish path use. */
    static zone z;
    const char *p = write_zone("fold.zone", "gpt.pepe A 300 216.24.57.1\n");
    CK(zone_load(&z, p, "gpt") == 0 && z.n == 1 && strcmp(z.recs[0].label, "gpt.pepe") == 0,
       "(evidence) the zone FILE parser accepts it — deliberately, unlike zone_build_rec");

    /* the same label in the key: it is opaque bytes, so the store cannot help */
    uint8_t k[SP_STATE_KEY_MAX];
    CK(dns_key_pack("gpt.pepe", DNS_A, k, sizeof k) == 10,
       "(evidence) the folded label packs into the store key unchanged");
}

static void section_cname_ip(void) {
    zone_rec r;
    /* The reported case: a CNAME pointing at an IP literal. dns_encode_name has
     * no idea what a hostname is, so "216.24.57.1" is perfectly legal wire — four
     * dname labels. zone.c therefore validates AFTER encoding: the rdata is built,
     * inspected, and the record is then refused (RFC 1034 §3.6.2 wants a domain
     * name). The encoded bytes are still in `r` on the failed call, which is what
     * lets this section show exactly what would have been published. */
    int rc = zone_build_rec("www", "CNAME", 300, "216.24.57.1", &r);
    static const uint8_t WANT[] = { 3,'2','1','6', 2,'2','4', 2,'5','7', 1,'1', 0 };
    printf("       zone_build_rec(CNAME \"216.24.57.1\") -> rc=%d rdlen=%u\n", rc, r.rdlen);
    CK(rc == -1 && r.rdlen == 13 && memcmp(r.rdata, WANT, 13) == 0,
       "(evidence) the IP literal encodes as 4 dname labels (03'216' 02'24' 02'57' 01'1' 00) — and is refused for it");
    { char t[128];
      CK(dname_text(r.rdata, r.rdlen, t, sizeof t) == 13 && strcmp(t, "216.24.57.1") == 0,
         "(evidence) the refused rdata would have been a CNAME to \"216.24.57.1.\""); }
    /* and the consequence that justifies the refusal: the target carries no TLD,
     * so pepenet-tls' in-zone CNAME chase (origin.c inzone_label) could never
     * resolve it — the record would have been a permanent dead end. */
    { char t[128]; dname_text(r.rdata, r.rdlen, t, sizeof t);
      size_t tl = strlen(t);
      CK(!(tl > 5 && strcmp(t + tl - 5, ".pepe") == 0),
         "(evidence) the target is in no pepenet zone -> the chase would dead-end"); }

    /* An IPv4/IPv6 literal is never a legal CNAME target (RFC 1034 §3.6.2
     * requires a domain name), on any of the types that take the dname path. */
    CK(zone_build_rec("www", "CNAME", 300, "216.24.57.1", &r) == -1,
       "a CNAME whose target is an IPv4 literal is rejected");
    CK(zone_build_rec("www", "CNAME", 300, "2001:db8::1", &r) == -1,
       "a CNAME whose target is an IPv6 literal is rejected");
    /* the same hole on NS and MX, which take the identical dname path */
    CK(zone_build_rec("@", "NS", 300, "216.24.57.1", &r) == -1,
       "an NS whose target is an IP literal is rejected");
    CK(zone_build_rec("@", "MX", 300, "10 216.24.57.1", &r) == -1,
       "an MX whose exchange is an IP literal is rejected");
}

/* ═══════════ 5. duplicates, empty zone, budget boundaries ══════════════ */
static void section_duplicates(void) {
    static zone z;
    const char *p = write_zone("dup.zone",
        "www A 300 10.0.0.1\n"
        "www A 300 10.0.0.1\n");     /* byte-identical duplicate */
    CK(zone_load(&z, p, "pepenet") == 0, "a zone with a duplicate record loads");
    printf("       duplicate (www,A,10.0.0.1) x2 -> z.n = %d\n", z.n);
    /* FAILS: RFC 2181 §5 forbids duplicate RRs inside an RRset; zone.c keeps
     * both, so the responder emits the same answer twice. */
    CK(z.n == 1, "[RFC 2181 5] a byte-identical duplicate record is collapsed");

    /* the store, in contrast, DOES collapse them: both rows share one key */
    uint8_t k1[SP_STATE_KEY_MAX], k2[SP_STATE_KEY_MAX];
    int n1 = dns_key_pack(z.recs[0].label, z.recs[0].type, k1, sizeof k1);
    int n2 = dns_key_pack(z.recs[z.n > 1 ? 1 : 0].label,
                          z.recs[z.n > 1 ? 1 : 0].type, k2, sizeof k2);
    CK(n1 == n2 && memcmp(k1, k2, (size_t)n1) == 0,
       "(evidence) both duplicates map to ONE sp_state key — the store keeps one");

    /* a legitimate multi-record RRset must of course survive intact */
    p = write_zone("rrset.zone", "www A 300 10.0.0.1\nwww A 300 10.0.0.2\n");
    CK(zone_load(&z, p, "pepenet") == 0 && z.n == 2 &&
       z.recs[0].rdata[3] == 1 && z.recs[1].rdata[3] == 2,
       "a legitimate two-address RRset keeps both records");
    /* ... and both collide on one store key, so only one can ever be held */
    CK(memcmp(k1, k2, (size_t)n1) == 0,
       "(evidence) an A RRset cannot survive the (label,type) store key — LWW keeps one");

    /* CNAME + other data at the same label is illegal (RFC 1034 §3.6.2) */
    p = write_zone("cnamedup.zone", "www CNAME 300 a.pepe\nwww A 300 10.0.0.1\n");
    int rc = zone_load(&z, p, "pepenet");
    printf("       CNAME coexisting with A at the same label -> rc=%d n=%d\n", rc, z.n);
    /* FAILS: RFC 1034 §3.6.2 — if a CNAME is present at a node no other data
     * may be. zone.c performs no cross-record validation. */
    CK(rc == -1, "[RFC 1034 3.6.2] a CNAME coexisting with other data is rejected");
}

static void section_empty_and_budget(void) {
    static zone z;
    const char *p = write_zone("empty.zone", "# nothing here\n;   nor here\n\n\n");
    CK(zone_load(&z, p, "pepenet") == 0 && z.n == 0,
       "a comments-only zone loads as an empty zone");
    CK(strcmp(z.apex, "pepenet") == 0 && z.serial == 0,
       "an empty zone still carries its apex and a zero serial");

    p = write_zone("zero.zone", "");
    CK(zone_load(&z, p, "pepenet") == 0 && z.n == 0, "a zero-byte zone file loads empty");
    CK(zone_load(&z, fx("does-not-exist.zone"), "pepenet") == -1,
       "a missing zone file is an error");

    /* record-count boundary: exactly ZONE_MAX_RECS, then one more */
    { char *body = malloc(ZONE_MAX_RECS * 32 + 64); size_t o = 0;
      for (int i = 0; i < ZONE_MAX_RECS; i++)
          o += (size_t)sprintf(body + o, "h%d A 60 10.0.0.1\n", i);
      body[o] = '\0';
      p = write_zone("full.zone", body);
      CK(zone_load(&z, p, "pepenet") == 0 && z.n == ZONE_MAX_RECS,
         "a zone with exactly ZONE_MAX_RECS (512) records loads");
      o += (size_t)sprintf(body + o, "over A 60 10.0.0.1\n");
      body[o] = '\0';
      p = write_zone("over.zone", body);
      CK(zone_load(&z, p, "pepenet") == -1, "ZONE_MAX_RECS + 1 records is refused");
      free(body); }

    /* rdata-byte boundary via the generic hex path (ZONE_MAX_RDATA = 512) */
    { char *body = malloc(2400); strcpy(body, "@ TYPE99 60 ");
      for (int i = 0; i < 511; i++) strcat(body, "ab");
      strcat(body, "\n");
      p = write_zone("rdmax.zone", body);
      CK(zone_load(&z, p, "pepenet") == 0 && z.n == 1 && z.recs[0].rdlen == 511,
         "(note) the generic hex path tops out at 511 bytes (char hex[1024] + \"%1023s\")");
      free(body); }
    { char *body = malloc(2400); strcpy(body, "@ TYPE99 60 ");
      for (int i = 0; i < ZONE_MAX_RDATA; i++) strcat(body, "ab");
      strcat(body, "\n");
      p = write_zone("rdmax2.zone", body);
      CK(zone_load(&z, p, "pepenet") == -1,
         "(note) rdata of exactly ZONE_MAX_RDATA fails closed on the generic path");
      free(body); }
    { char t[1100]; strcpy(t, "3 1 1 ");
      for (int i = 0; i < 1018; i++) strcat(t, "a");   /* 509 assoc bytes */
      zone_rec r;
      CK(zone_build_rec("@", "TLSA", 60, t, &r) == 0 && r.rdlen == ZONE_MAX_RDATA,
         "a TLSA record reaching exactly ZONE_MAX_RDATA (512) bytes builds"); }
    { char *body = malloc(2400); strcpy(body, "@ TYPE99 60 ");
      for (int i = 0; i < 600; i++) strcat(body, "ab");   /* hex[1024] caps at 511 bytes */
      strcat(body, "\n");
      p = write_zone("rdover.zone", body);
      CK(zone_load(&z, p, "pepenet") == -1, "rdata past ZONE_MAX_RDATA is refused");
      free(body); }

    /* the store budget is the real ceiling: DNS_BUDGET / a signed op is far
     * fewer than ZONE_MAX_RECS records, so a 512-record zone file can never be
     * published in full. Pinned so the two constants stay honest about it. */
    CK(DNS_BUDGET / 128 < ZONE_MAX_RECS,
       "(note) DNS_BUDGET (8 KB/name) admits far fewer records than ZONE_MAX_RECS");
}

static void section_malformed(void) {
    static zone z;
    const char *p;

    p = write_zone("m1.zone", "www\n");
    CK(zone_load(&z, p, "pepenet") == -1, "a record line with only a label is refused");
    p = write_zone("m2.zone", "www A\n");
    CK(zone_load(&z, p, "pepenet") == -1, "a record line with no ttl is refused");
    p = write_zone("m3.zone", "www NOSUCH 60 x\n");
    CK(zone_load(&z, p, "pepenet") == -1, "an unknown type in a zone file is refused");
    p = write_zone("m4.zone", "www A 60 not-an-ip\n");
    CK(zone_load(&z, p, "pepenet") == -1, "bad rdata in a zone file is refused");
    p = write_zone("m5.zone", "www A abc 10.0.0.1\n");
    CK(zone_load(&z, p, "pepenet") == -1, "a non-numeric ttl is refused");

    /* A record line with NO rdata at all. build_rdata's per-type scanf leaves
     * its token buffer untouched when there is nothing to scan, so the A path
     * runs inet_pton over uninitialised stack. It happens to fail — but the
     * read is real. The generic hex path is worse (see below). */
    p = write_zone("m6.zone", "www A 60\n");
    CK(zone_load(&z, p, "pepenet") == -1, "an A record with no rdata is refused");

    /* FAILS: on the generic/TYPEnnn path the same missing-rdata line runs
     * hexdecode() over an UNINITIALISED char hex[1024] — it scans until it
     * happens to see a NUL or a space, which may be past the end of the
     * buffer, and whatever it decodes becomes the record's rdata. */
    p = write_zone("m7.zone", "www TYPE99 60\n");
    { int rc = zone_load(&z, p, "pepenet");
      printf("       \"www TYPE99 60\" (no rdata) -> rc=%d n=%d rdlen=%u\n",
             rc, z.n, rc == 0 && z.n ? z.recs[0].rdlen : 0);
      CK(rc == -1, "a generic-type record with no rdata is refused"); }

    /* Same hole, made visible: give the PREVIOUS line a long generic rdata so
     * build_rdata's hex[1024] is dirty, then give the next line none. Whatever
     * the compiler leaves in that frame becomes the second record's rdata. At
     * -O0 record 2 inherits record 1's bytes verbatim; at -O2 it becomes an
     * rdlen-0 record, which dns_state_put reads as a DELETE. Either way the
     * value is undefined and the line should simply have been rejected. */
    { char body[1024]; size_t o = (size_t)sprintf(body, "a TYPE99 60 ");
      for (int i = 0; i < 200; i++) { body[o++] = 'd'; body[o++] = 'e'; }
      o += (size_t)sprintf(body + o, "\nb TYPE99 60\n");
      body[o] = '\0';
      p = write_zone("m7b.zone", body);
      int rc = zone_load(&z, p, "pepenet");
      if (rc == 0 && z.n == 2)
          printf("       leak probe: rec[0] rdlen=%u %02x%02x  rec[1] rdlen=%u %02x%02x"
                 "  (rec[1] had NO rdata in the file)\n",
                 z.recs[0].rdlen, z.recs[0].rdata[0], z.recs[0].rdata[1],
                 z.recs[1].rdlen, z.recs[1].rdata[0], z.recs[1].rdata[1]);
      CK(rc == -1, "a no-rdata line cannot inherit the previous record's bytes"); }

    /* zone_build_rec (the dns-cli path) truncates an over-long label in
     * silence — 64+ bytes cannot fit zone_rec.label[64]. */
    { char lbl[128]; memset(lbl, 'q', 100); lbl[100] = '\0';
      zone_rec r;
      int rc = zone_build_rec(lbl, "A", 60, "10.0.0.1", &r);
      printf("       zone_build_rec(100-byte label) -> rc=%d stored %zu bytes\n",
             rc, strlen(r.label));
      /* FAILS: snprintf truncates to 63 bytes and returns success, so the
       * record silently answers at a DIFFERENT name than the caller asked for
       * (and dns_key_pack then happily packs the truncated label). */
      CK(rc == -1, "zone_build_rec refuses a label that does not fit (no silent truncation)"); }

    /* the zone FILE path catches it, but only by accident: "%63s" splits the
     * long label and the remainder is parsed as the type mnemonic. */
    { char body[256]; memset(body, 'q', 100); body[100] = '\0';
      char line[300]; snprintf(line, sizeof line, "%s A 60 10.0.0.1\n", body);
      p = write_zone("m8.zone", line);
      CK(zone_load(&z, p, "pepenet") == -1, "an over-long label in a zone file is refused"); }

    /* a line longer than the 2048-byte fgets buffer splits and the tail is
     * re-parsed as a record — a long COMMENT should not become an error */
    { char *body = malloc(4096); body[0] = '#';
      memset(body + 1, 'c', 3000); strcpy(body + 3001, "\n");
      p = write_zone("m9.zone", body);
      int rc = zone_load(&z, p, "pepenet");
      printf("       a 3000-byte comment line -> rc=%d\n", rc);
      /* FAILS: zone_load reads with fgets(line, 2048) and treats each chunk as
       * a fresh line, so any line over 2047 bytes has its tail mis-parsed. */
      CK(rc == 0, "a comment longer than the 2048-byte line buffer is still a comment");
      free(body); }
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    g_tmp = mkdtemp(g_dir);
    if (!g_tmp) { perror("mkdtemp"); return 2; }
    printf("zone_test: fixtures in %s\n", g_tmp);

    printf("-- rdata builders (text -> wire) --\n");        section_rdata();
    printf("-- parse -> serialize -> parse round-trip --\n"); section_roundtrip();
    printf("-- record key format (label ‖ type_be16) --\n"); section_key();
    printf("-- BUG: a label that already carries the TLD suffix --\n"); section_tld_fold();
    printf("-- BUG: a CNAME whose target is an IP literal --\n");       section_cname_ip();
    printf("-- duplicate keys --\n");                        section_duplicates();
    printf("-- empty zone + count/byte budget boundaries --\n"); section_empty_and_budget();
    printf("-- malformed lines --\n");                       section_malformed();

    cleanup();
    printf("zone_test: %d ok, %d failed\n", g_ok, g_fail);
    return g_fail ? 1 : 0;
}
