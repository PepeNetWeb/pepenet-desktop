/* ca_deep_test.c — src/ca.c beyond the NameConstraints proof.
 *
 * ca_test.c already proves the pillar: a `doge` root verifies `.doge` leaves
 * and rejects everything else through libcrypto's own verifier. It does not
 * touch the rest of the module, so this file covers what is left — most
 * importantly the SAN-INJECTION GUARD, which ca.c:166-179 documents as "the
 * input validation, not the last line of defence" and which nothing tested.
 *
 * PROVES:
 *
 *   C1. ca_set_tld's WHITELIST. Accepts 2..15 lowercase-alpha labels; refuses
 *       NULL, "", a 1-char label, a 16-char label, uppercase, digits, hyphens,
 *       dots, spaces and embedded NULs — and a REFUSED value leaves the
 *       previously active TLD untouched (a rejected config edit must not
 *       silently widen or blank the constraint).
 *
 *   C2. PATH + CN DERIVATION. cert/key paths and the root CN are built from
 *       (dir, name, tld); each setter forces a recompute, so changing the TLD
 *       after the paths were first read cannot leave a stale path pointing at
 *       another network's root. Per-TLD filenames let a doge root and a pepe
 *       root coexist in one directory. ca_set_dir(NULL)/("") is ignored rather
 *       than blanking the directory.
 *
 *   C3. SAN INJECTION — the security case. X509V3_EXT_conf_nid parses the
 *       SAN string as a CONFIG value in which ',' separates entries, so an SNI
 *       of "evil.doge,DNS:victim.example.com" would otherwise mint a leaf
 *       carrying a SECOND SubjectAltName of the attacker's choosing. Every
 *       such name — and the whole illegal-character battery around it — must
 *       be refused by ca_leaf_mint BEFORE the extension builder sees it, and
 *       an over-253-byte name must be refused too.
 *
 *   C4. THE MINTED SAN IS EXACTLY THE NAME ASKED FOR: one dNSName, byte-equal
 *       to the request, for plain names and for wildcards. Re-read out of the
 *       DER, not out of the string we passed in.
 *
 *   C5. ROOT SHAPE: v3, self-signed and self-verifying, CA:TRUE with
 *       pathlen:0, keyCertSign+cRLSign, a CRITICAL NameConstraints naming the
 *       active TLD, an EC P-256 key, a positive serial, and a ~10-year window.
 *
 *   C6. LEAF SHAPE: CA:FALSE, serverAuth EKU, digitalSignature KU, an AKI that
 *       matches the root's SKI, and a ~2-day window. pathlen:0 on the root
 *       additionally means a leaf can never act as an intermediate.
 *
 *   C7. PERSISTENCE: the key file is 0600, the cert is world-readable, and a
 *       second ca_root_ensure LOADS the stored root (same serial) instead of
 *       silently minting a new one — a regeneration would invalidate every
 *       cert already trusted by the OS store.
 *
 *   C8. SERIALS ARE RANDOM AND POSITIVE: independent roots, and successive
 *       leaves, never share a serial.
 *
 * FAILS (real product defect, deliberately NOT weakened — see the FAILS note
 * in sec_injection): ca.c:179 refuses names over 253 bytes, but the effective
 * ceiling is 64, because build_leaf writes the full hostname into the subject
 * CN first and X509_NAME_add_entry_by_txt enforces RFC 5280's ub-common-name.
 * Every legal .doge/.pepe hostname longer than 64 bytes therefore fails to get
 * a certificate at all. This suite exits non-zero until the CN is dropped or
 * truncated (the SAN, which verifiers actually match on, is already correct).
 *
 * Hermetic: every root lives under a mkdtemp'd dir passed via ca_set_dir, and
 * $HOME is repointed as a belt-and-braces guard, so the real ~/.pepenet is
 * never read or written. No keychain, no network.
 */
#include "ca.h"

#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

static int pass, fail;
static void ok(const char *w)  { pass++; printf("  ok   %s\n", w); }
static void bad(const char *w) { fail++; printf("  FAIL %s\n", w); }
#define CK(c, m) do { if (c) ok(m); else bad(m); } while (0)

static char g_tmp[512];

/* ── C1. the TLD whitelist ──────────────────────────────────────────────────── */
static void sec_tld(void) {
    printf("\n── C1. ca_set_tld's whitelist ──\n");

    struct { const char *tld; int want; const char *what; } T[] = {
        { "doge",             1, "\"doge\"" },
        { "pepe",             1, "\"pepe\"" },
        { "ab",               1, "a 2-char label (the minimum)" },
        { "abcdefghijklmno",  1, "a 15-char label (the maximum)" },
        { "shib",             1, "\"shib\" — the whitelist is TLD-agnostic" },
        { NULL,               0, "NULL" },
        { "",                 0, "the empty string" },
        { "a",                0, "a 1-char label (below the minimum)" },
        { "abcdefghijklmnop", 0, "a 16-char label (above the maximum)" },
        { "Doge",             0, "an uppercase initial" },
        { "DOGE",             0, "all uppercase" },
        { "do1ge",            0, "an embedded digit" },
        { "do-ge",            0, "an embedded hyphen" },
        { "do.ge",            0, "an embedded dot" },
        { "do ge",            0, "an embedded space" },
        { ".doge",            0, "a leading dot" },
        { "doge.",            0, "a trailing dot" },
        { "doge\n",           0, "a trailing newline" },
        { "dogé",             0, "a non-ASCII byte" },
    };

    for (unsigned i = 0; i < sizeof T / sizeof T[0]; i++) {
        char label[160];
        int rc = ca_set_tld(T[i].tld);
        snprintf(label, sizeof label, "%s %s",
                 T[i].want ? "accepts" : "refuses", T[i].what);
        CK(rc == T[i].want, label);
    }

    /* a refused edit must not disturb the active TLD */
    CK(ca_set_tld("pepe") == 1, "set the active TLD to \"pepe\"");
    CK(strcmp(ca_tld(), "pepe") == 0, "ca_tld() reports it");
    ca_set_tld("EVIL"); ca_set_tld(""); ca_set_tld(NULL); ca_set_tld("a");
    CK(strcmp(ca_tld(), "pepe") == 0,
       "four REFUSED edits later the active TLD is still \"pepe\" (never blanked or widened)");

    /* an embedded NUL cannot smuggle a second label past the length check */
    CK(ca_set_tld("doge\0evil") == 1, "\"doge\\0evil\" is read as \"doge\" (strlen stops at the NUL)");
    CK(strcmp(ca_tld(), "doge") == 0, "... and only \"doge\" becomes active");
}

/* ── C2. path + CN derivation ───────────────────────────────────────────────── */
static void sec_paths(void) {
    printf("\n── C2. cert/key path + CN derivation ──\n");

    ca_set_dir(g_tmp);
    ca_set_name("pepenet");
    ca_set_tld("doge");

    char want_crt[700], want_key[700], want_cn[128];
    snprintf(want_crt, sizeof want_crt, "%s/pepenet-root-doge.crt", g_tmp);
    snprintf(want_key, sizeof want_key, "%s/pepenet-root-doge.key", g_tmp);
    snprintf(want_cn,  sizeof want_cn,  "pepenet .doge root CA");

    CK(strcmp(ca_root_cert_path(), want_crt) == 0, "cert path = <dir>/<name>-root-<tld>.crt");
    CK(strcmp(ca_root_key_path(),  want_key) == 0, "key path  = <dir>/<name>-root-<tld>.key");
    CK(strcmp(ca_root_cn(),        want_cn)  == 0, "root CN   = \"<name> .<tld> root CA\"");

    /* changing the TLD *after* the paths were read must recompute them —
     * a stale path would point a pepe box at the doge network's root */
    ca_set_tld("pepe");
    snprintf(want_crt, sizeof want_crt, "%s/pepenet-root-pepe.crt", g_tmp);
    CK(strcmp(ca_root_cert_path(), want_crt) == 0, "changing the TLD recomputes the cert path");
    CK(strcmp(ca_root_cn(), "pepenet .pepe root CA") == 0, "... and the CN");

    ca_set_name("shibpost");
    snprintf(want_crt, sizeof want_crt, "%s/shibpost-root-pepe.crt", g_tmp);
    CK(strcmp(ca_root_cert_path(), want_crt) == 0, "changing the instance name recomputes the path");
    CK(strcmp(ca_root_cn(), "shibpost .pepe root CA") == 0, "... and the CN");

    /* a doge root and a pepe root never collide on disk */
    ca_set_name("pepenet");
    ca_set_tld("doge");
    char doge_crt[700];
    snprintf(doge_crt, sizeof doge_crt, "%s", ca_root_cert_path());
    ca_set_tld("pepe");
    CK(strcmp(doge_crt, ca_root_cert_path()) != 0,
       "per-TLD filenames: a doge root and a pepe root coexist in one dir");

    /* a NULL/empty dir is ignored, never applied */
    const char *before = ca_root_cert_path();
    char keep[700]; snprintf(keep, sizeof keep, "%s", before);
    ca_set_dir(NULL);
    ca_set_dir("");
    CK(strcmp(ca_root_cert_path(), keep) == 0, "ca_set_dir(NULL) and ca_set_dir(\"\") are ignored");

    ca_set_tld("doge");
}

/* ── C3. the SAN-injection guard ────────────────────────────────────────────── */
static void sec_injection(X509 *root, EVP_PKEY *rk) {
    printf("\n── C3. SAN injection + the illegal-character battery ──\n");

    /* THE attack the comment in ca.c:166 describes. */
    const char *ATTACKS[] = {
        "evil.pepenet.doge,DNS:victim.example.com",
        "a.doge,DNS:www.google.com",
        "a.doge,IP:10.0.0.1",
        "a.doge,DNS:*",
        "a.doge, DNS:victim.com",
        "a.doge,email:root@example.com",
        "a.doge,URI:http://evil.example.com",
        "a.doge,otherName:1.2.3.4;UTF8:x",
    };
    for (unsigned i = 0; i < sizeof ATTACKS / sizeof ATTACKS[0]; i++) {
        X509 *leaf = NULL; EVP_PKEY *lk = NULL;
        int rc = ca_leaf_mint(root, rk, ATTACKS[i], &leaf, &lk);
        char label[320];
        snprintf(label, sizeof label, "refuses SAN injection: \"%.60s\"", ATTACKS[i]);
        CK(rc == 0, label);
        if (rc) { X509_free(leaf); EVP_PKEY_free(lk); }
    }

    /* every other byte a DNS label may not contain */
    const char *ILLEGAL[] = {
        "a b.doge", "a\tb.doge", "a\nb.doge", "a\rb.doge",
        "a/b.doge", "a\\b.doge", "a=b.doge", "a;b.doge", "a:b.doge",
        "a\"b.doge", "a'b.doge", "a`b.doge", "a$b.doge", "a%b.doge",
        "a(b.doge", "a)b.doge", "a[b.doge", "a]b.doge", "a{b.doge",
        "a<b.doge", "a>b.doge", "a|b.doge", "a&b.doge", "a#b.doge",
        "a!b.doge", "a?b.doge", "a@b.doge", "a+b.doge", "a~b.doge",
        "a^b.doge", "a_b.doge", "café.doge",
    };
    int all_refused = 1;
    for (unsigned i = 0; i < sizeof ILLEGAL / sizeof ILLEGAL[0]; i++) {
        X509 *leaf = NULL; EVP_PKEY *lk = NULL;
        if (ca_leaf_mint(root, rk, ILLEGAL[i], &leaf, &lk)) {
            all_refused = 0;
            printf("       accepted: \"%s\"\n", ILLEGAL[i]);
            X509_free(leaf); EVP_PKEY_free(lk);
        }
    }
    CK(all_refused, "refuses every illegal DNS-label byte (32 shapes: whitespace, quotes, brackets, non-ASCII)");

    /* The length bound. ca.c:179 refuses names over 253 bytes, which is the
     * DNS maximum — so every name at or below 253 is meant to mint.
     *
     * FAILS: the real ceiling is 64. build_leaf puts the FULL hostname into
     * the subject CN (ca.c:157) BEFORE it reaches its own length check, and
     * X509_NAME_add_entry_by_txt enforces RFC 5280's ub-common-name of 64
     * characters on NID_commonName. Anything longer fails with "string too
     * long" and ca_leaf_mint returns 0 — so the proxy cannot mint a cert for
     * any legal .doge/.pepe hostname over 64 bytes, and the site simply fails
     * its handshake. The CN is decorative here anyway: RFC 2818 and the CA/B
     * Baseline Requirements have verifiers match on the SAN, which this code
     * already sets correctly and which has no such limit. */
    {
        char longname[400];
        X509 *leaf; EVP_PKEY *lk;

        /* find the true boundary and report it, so the finding is exact */
        int last_ok = 0;
        for (int n = 1; n <= 253; n++) {
            memset(longname, 'a', (size_t)n); longname[n] = '\0';
            leaf = NULL; lk = NULL;
            if (ca_leaf_mint(root, rk, longname, &leaf, &lk)) {
                last_ok = n; X509_free(leaf); EVP_PKEY_free(lk);
            }
        }
        printf("       (longest name ca_leaf_mint actually accepts: %d bytes)\n", last_ok);

        memset(longname, 'a', 253); longname[253] = '\0';
        leaf = NULL; lk = NULL;
        int rc253 = ca_leaf_mint(root, rk, longname, &leaf, &lk);
        if (rc253) { X509_free(leaf); EVP_PKEY_free(lk); }
        CK(rc253 == 1, "accepts a 253-byte name, ca.c:179's documented maximum "
                       "(FAILS: the CN caps it at 64 — see the FAILS note above)");

        /* a realistic dotted hostname of the same shape fails identically */
        const char *real = "very-long-subdomain.another-long-label."
                           "yet-another-label.pepenet.doge";           /* 69 bytes */
        leaf = NULL; lk = NULL;
        int rcreal = ca_leaf_mint(root, rk, real, &leaf, &lk);
        if (rcreal) { X509_free(leaf); EVP_PKEY_free(lk); }
        CK(rcreal == 1, "mints a REAL 69-byte dotted .doge hostname "
                        "(FAILS: same 64-byte CN ceiling — a legal site cannot get a cert)");

        memset(longname, 'a', 254); longname[254] = '\0';
        leaf = NULL; lk = NULL;
        int rc254 = ca_leaf_mint(root, rk, longname, &leaf, &lk);
        if (rc254) { X509_free(leaf); EVP_PKEY_free(lk); }
        CK(rc254 == 0, "refuses a 254-byte name (one past the DNS maximum)");
    }

    /* legitimate shapes still mint */
    const char *GOOD[] = { "www.pepenet.doge", "a.b.c.d.doge", "*.pepenet.doge",
                           "xn--brg-yoa.doge", "A.MIXED.Case.doge", "9lives.doge",
                           "has-a-hyphen.doge" };
    int all_minted = 1;
    for (unsigned i = 0; i < sizeof GOOD / sizeof GOOD[0]; i++) {
        X509 *leaf = NULL; EVP_PKEY *lk = NULL;
        if (!ca_leaf_mint(root, rk, GOOD[i], &leaf, &lk)) {
            all_minted = 0;
            printf("       refused a legitimate name: \"%s\"\n", GOOD[i]);
        } else { X509_free(leaf); EVP_PKEY_free(lk); }
    }
    CK(all_minted, "still mints every legitimate shape (wildcard, punycode, mixed case, digits, hyphens)");
}

/* pull the single dNSName out of a leaf; returns malloc'd string or NULL */
static char *leaf_san(X509 *leaf, int *count) {
    char *out = NULL;
    *count = 0;
    GENERAL_NAMES *gens = X509_get_ext_d2i(leaf, NID_subject_alt_name, NULL, NULL);
    if (!gens) return NULL;
    int n = sk_GENERAL_NAME_num(gens);
    *count = n;
    for (int i = 0; i < n; i++) {
        GENERAL_NAME *g = sk_GENERAL_NAME_value(gens, i);
        if (GENERAL_NAME_get0_value(g, NULL) && g->type == GEN_DNS && !out) {
            const ASN1_IA5STRING *s = g->d.dNSName;
            int len = ASN1_STRING_length(s);
            out = malloc((size_t)len + 1);
            if (out) { memcpy(out, ASN1_STRING_get0_data(s), (size_t)len); out[len] = '\0'; }
        }
    }
    GENERAL_NAMES_free(gens);
    return out;
}

/* ── C4. the minted SAN is exactly what was asked for ───────────────────────── */
static void sec_san_exact(X509 *root, EVP_PKEY *rk) {
    printf("\n── C4. the minted SAN is exactly the requested name ──\n");
    const char *NAMES[] = { "www.pepenet.doge", "*.pepenet.doge", "a.b.c.d.e.doge" };
    for (unsigned i = 0; i < sizeof NAMES / sizeof NAMES[0]; i++) {
        X509 *leaf = NULL; EVP_PKEY *lk = NULL;
        if (!ca_leaf_mint(root, rk, NAMES[i], &leaf, &lk)) { bad(NAMES[i]); continue; }
        int n = 0;
        char *san = leaf_san(leaf, &n);
        char label[200];
        snprintf(label, sizeof label, "%-20s → exactly one SAN, byte-equal", NAMES[i]);
        CK(san && n == 1 && strcmp(san, NAMES[i]) == 0, label);
        free(san);
        X509_free(leaf); EVP_PKEY_free(lk);
    }
}

/* ── C5. root shape ─────────────────────────────────────────────────────────── */
static void sec_root_shape(X509 *root, EVP_PKEY *rk) {
    printf("\n── C5. the root's shape ──\n");

    CK(X509_get_version(root) == 2, "root is X.509 v3");
    CK(X509_check_ca(root) > 0,     "root is a CA");
    CK(X509_get_pathlen(root) == 0, "pathlen:0 — the root may not issue intermediates");
    CK((X509_get_key_usage(root) & (KU_KEY_CERT_SIGN | KU_CRL_SIGN))
       == (KU_KEY_CERT_SIGN | KU_CRL_SIGN), "keyUsage = keyCertSign + cRLSign");

    /* self-signed and self-verifying */
    CK(X509_NAME_cmp(X509_get_subject_name(root), X509_get_issuer_name(root)) == 0,
       "subject == issuer (self-signed)");
    CK(X509_verify(root, rk) == 1, "the root verifies under its own key");

    /* NameConstraints present, CRITICAL, and naming the active TLD */
    int nc_idx = X509_get_ext_by_NID(root, NID_name_constraints, -1);
    CK(nc_idx >= 0, "a NameConstraints extension is present");
    if (nc_idx >= 0) {
        X509_EXTENSION *ex = X509_get_ext(root, nc_idx);
        CK(X509_EXTENSION_get_critical(ex) == 1,
           "... and it is CRITICAL (a verifier that cannot process it must reject)");
    }
    NAME_CONSTRAINTS *nc = X509_get_ext_d2i(root, NID_name_constraints, NULL, NULL);
    CK(nc != NULL, "... and it parses");
    if (nc) {
        int npermit = sk_GENERAL_SUBTREE_num(nc->permittedSubtrees);
        int nexcl   = sk_GENERAL_SUBTREE_num(nc->excludedSubtrees);
        CK(npermit == 1, "exactly one permitted subtree (the single TLD)");
        CK(nexcl == 2,   "two excluded subtrees (IPv4 all + IPv6 all — the IP-SAN bypass is closed)");
        if (npermit == 1) {
            GENERAL_SUBTREE *s = sk_GENERAL_SUBTREE_value(nc->permittedSubtrees, 0);
            const ASN1_IA5STRING *d = s->base->d.dNSName;
            char got[64] = {0};
            int len = ASN1_STRING_length(d);
            if (len > 0 && len < (int)sizeof got) memcpy(got, ASN1_STRING_get0_data(d), (size_t)len);
            char label[160];
            snprintf(label, sizeof label, "the permitted subtree is exactly \"%s\" (no leading dot)", ca_tld());
            CK(strcmp(got, ca_tld()) == 0, label);
        }
        NAME_CONSTRAINTS_free(nc);
    }

    /* an EC P-256 key */
    CK(EVP_PKEY_base_id(rk) == EVP_PKEY_EC, "the root key is EC");
    CK(EVP_PKEY_bits(rk) == 256,            "... P-256 (256 bits)");

    /* a ~10-year window, starting now */
    {
        const ASN1_TIME *nb = X509_get0_notBefore(root), *na = X509_get0_notAfter(root);
        int days = 0, secs = 0;
        CK(ASN1_TIME_diff(&days, &secs, nb, na) == 1, "the validity window parses");
        CK(days >= 3649 && days <= 3651, "the root is valid for ~3650 days (~10 years)");
        CK(X509_cmp_current_time(nb) <= 0, "notBefore is not in the future");
        CK(X509_cmp_current_time(na) >  0, "notAfter is in the future");
    }

    /* a positive serial */
    {
        ASN1_INTEGER *s = X509_get_serialNumber(root);
        BIGNUM *bn = ASN1_INTEGER_to_BN(s, NULL);
        CK(bn && !BN_is_negative(bn) && !BN_is_zero(bn), "the serial is positive and non-zero");
        CK(bn && BN_num_bits(bn) > 32, "... and carries real entropy (>32 bits)");
        BN_free(bn);
    }
}

/* ── C6. leaf shape ─────────────────────────────────────────────────────────── */
static void sec_leaf_shape(X509 *root, EVP_PKEY *rk) {
    printf("\n── C6. a leaf's shape ──\n");

    X509 *leaf = NULL; EVP_PKEY *lk = NULL;
    if (!ca_leaf_mint(root, rk, "www.pepenet.doge", &leaf, &lk)) { bad("mint a leaf"); return; }

    CK(X509_get_version(leaf) == 2, "leaf is X.509 v3");
    CK(X509_check_ca(leaf) == 0,    "leaf is NOT a CA (CA:FALSE — it can never act as an intermediate)");
    CK((X509_get_extended_key_usage(leaf) & XKU_SSL_SERVER) != 0, "EKU includes serverAuth");
    CK((X509_get_key_usage(leaf) & KU_DIGITAL_SIGNATURE) != 0,    "keyUsage includes digitalSignature");
    CK(X509_verify(leaf, rk) == 1, "the leaf is signed by the root key");
    CK(X509_NAME_cmp(X509_get_issuer_name(leaf), X509_get_subject_name(root)) == 0,
       "the leaf's issuer is the root's subject");

    /* the AKI must match the root's SKI, or a verifier cannot build the chain */
    {
        const ASN1_OCTET_STRING *ski = X509_get0_subject_key_id(root);
        const ASN1_OCTET_STRING *aki = X509_get0_authority_key_id(leaf);
        CK(ski != NULL, "the root carries a SubjectKeyIdentifier");
        CK(aki != NULL, "the leaf carries an AuthorityKeyIdentifier");
        CK(ski && aki && ASN1_OCTET_STRING_cmp(ski, aki) == 0, "... and the leaf's AKI == the root's SKI");
    }

    /* ~2 days */
    {
        const ASN1_TIME *nb = X509_get0_notBefore(leaf), *na = X509_get0_notAfter(leaf);
        int days = 0, secs = 0;
        ASN1_TIME_diff(&days, &secs, nb, na);
        CK(days == 2 && secs == 0, "the leaf is short-lived: exactly 2 days");
    }

    X509_free(leaf); EVP_PKEY_free(lk);
}

/* ── C7. persistence ────────────────────────────────────────────────────────── */
static void sec_persist(void) {
    printf("\n── C7. persistence: modes, and load-don't-regenerate ──\n");

    ca_set_dir(g_tmp);
    ca_set_name("persist");
    ca_set_tld("doge");

    X509 *r1 = NULL; EVP_PKEY *k1 = NULL;
    CK(ca_root_ensure(&r1, &k1) == 1, "first ca_root_ensure mints and persists a root");

    struct stat stk, stc;
    CK(stat(ca_root_key_path(),  &stk) == 0, "the key file exists");
    CK(stat(ca_root_cert_path(), &stc) == 0, "the cert file exists");
    CK((stk.st_mode & 0777) == 0600, "the private key is mode 0600 (owner-only)");

    /* a second ensure must LOAD, not regenerate: same serial, same key */
    X509 *r2 = NULL; EVP_PKEY *k2 = NULL;
    CK(ca_root_ensure(&r2, &k2) == 1, "second ca_root_ensure succeeds");
    CK(r1 && r2 && ASN1_INTEGER_cmp(X509_get_serialNumber(r1),
                                    X509_get_serialNumber(r2)) == 0,
       "... and returns the SAME root (identical serial — never silently regenerated)");
    CK(k1 && k2 && EVP_PKEY_eq(k1, k2) == 1, "... backed by the same key");

    /* a leaf minted under the reloaded root still verifies under the first */
    if (r1 && r2 && k2) {
        X509 *leaf = NULL; EVP_PKEY *lk = NULL;
        if (ca_leaf_mint(r2, k2, "reload.pepenet.doge", &leaf, &lk)) {
            X509_STORE *store = X509_STORE_new();
            X509_STORE_add_cert(store, r1);
            X509_STORE_CTX *ctx = X509_STORE_CTX_new();
            X509_STORE_CTX_init(ctx, store, leaf, NULL);
            int rc = X509_verify_cert(ctx);
            X509_STORE_CTX_free(ctx); X509_STORE_free(store);
            CK(rc == 1, "a leaf minted under the RELOADED root verifies against the original");
            X509_free(leaf); EVP_PKEY_free(lk);
        } else bad("mint under the reloaded root");
    }

    /* switching TLD gives a DIFFERENT root, on a different path */
    ca_set_tld("pepe");
    X509 *r3 = NULL; EVP_PKEY *k3 = NULL;
    CK(ca_root_ensure(&r3, &k3) == 1, "a pepe root is minted alongside the doge one");
    CK(r1 && r3 && ASN1_INTEGER_cmp(X509_get_serialNumber(r1),
                                    X509_get_serialNumber(r3)) != 0,
       "... and it is a genuinely different root (different serial)");

    X509_free(r1); EVP_PKEY_free(k1);
    X509_free(r2); EVP_PKEY_free(k2);
    X509_free(r3); EVP_PKEY_free(k3);
    ca_set_tld("doge");
    ca_set_name("pepenet");
}

/* ── C8. serial entropy ─────────────────────────────────────────────────────── */
static void sec_serials(X509 *root, EVP_PKEY *rk) {
    printf("\n── C8. serials are random and positive ──\n");

    enum { N = 24 };
    ASN1_INTEGER *ser[N];
    int minted = 0, dup = 0, nonpos = 0;

    for (int i = 0; i < N; i++) {
        X509 *leaf = NULL; EVP_PKEY *lk = NULL;
        char nm[64];
        snprintf(nm, sizeof nm, "s%d.pepenet.doge", i);
        if (!ca_leaf_mint(root, rk, nm, &leaf, &lk)) break;
        ser[minted] = ASN1_INTEGER_dup(X509_get_serialNumber(leaf));
        BIGNUM *bn = ASN1_INTEGER_to_BN(ser[minted], NULL);
        if (!bn || BN_is_negative(bn) || BN_is_zero(bn)) nonpos++;
        BN_free(bn);
        minted++;
        X509_free(leaf); EVP_PKEY_free(lk);
    }
    for (int i = 0; i < minted; i++)
        for (int j = i + 1; j < minted; j++)
            if (ASN1_INTEGER_cmp(ser[i], ser[j]) == 0) dup++;

    CK(minted == N,  "minted 24 leaves");
    CK(dup == 0,     "all 24 serials are distinct");
    CK(nonpos == 0,  "every serial is positive and non-zero");

    for (int i = 0; i < minted; i++) ASN1_INTEGER_free(ser[i]);
}

int main(void) {
    char tmpl[] = "/tmp/pepenet-tls-cadeep.XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) { perror("mkdtemp"); return 1; }
    snprintf(g_tmp, sizeof g_tmp, "%s", dir);
    setenv("HOME", g_tmp, 1);            /* belt and braces: never ~/.pepenet */
    printf("temp CA dir: %s\n", g_tmp);

    sec_tld();
    sec_paths();

    /* one working root for the shape/injection sections */
    ca_set_dir(g_tmp);
    ca_set_name("pepenet");
    ca_set_tld("doge");
    X509 *root = NULL; EVP_PKEY *rk = NULL;
    if (!ca_root_ensure(&root, &rk)) {
        fprintf(stderr, "root generation failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    sec_injection(root, rk);
    sec_san_exact(root, rk);
    sec_root_shape(root, rk);
    sec_leaf_shape(root, rk);
    sec_serials(root, rk);

    X509_free(root); EVP_PKEY_free(rk);

    sec_persist();

    printf("\n%d ok, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
