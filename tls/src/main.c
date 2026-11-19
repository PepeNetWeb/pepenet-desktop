/* main.c — pepenet-tls CLI (CA lifecycle + trust install + the DANE proxy).
 *
 *   pepenet-tls [--tld pep|doge|...] gen-ca    create/persist the root
 *   pepenet-tls [--tld ...] mint <name>        print a leaf for <name> (PEM)
 *   pepenet-tls [--tld ...] show               print the root cert as text
 *   pepenet-tls [--tld ...] origin-cert <name> [dir]
 *                                              ensure the self-signed ORIGIN
 *                                              cert+key for <name>.<tld> and
 *                                              print its TLSA 3 1 1 rdata
 *   pepenet-tls [--tld ...] install-ca         trust the root (macOS keychain / Linux NSS)
 *   pepenet-tls [--tld ...] uninstall-ca       remove it
 *   pepenet-tls [--tld ...] serve --db <indexer> --store <carrier> [--listen IP] [--port N]
 *                                              run the DANE proxy (slice 4)
 *
 * This box serves ONE TLD — pick it with --tld (or $PEPENET_TLD); default doge.
 * `serve` reuses the TLD as the DNS suffix: it resolves `<name>.<tld>` against
 * the pepenet ownership View + carrier Store, DANE-verifies the origin, and
 * presents the browser a per-SNI leaf off the name-constrained root.
 */
#include "ca.h"
#include "trust.h"
#include "proxy.h"
#include "resolve.h"
#include "sscert.h"

#include <stdint.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int usage(void) {
    fprintf(stderr,
        "usage: pepenet-tls [--tld pep|doge|...] {gen-ca | mint <name> | show |\n"
        "         origin-cert <name> [dir] | probe <name> <host[:port]> |\n"
        "         install-ca | uninstall-ca |\n"
        "         serve --db <indexer> --store <carrier> [--listen IP] [--port N]}\n");
    return 2;
}

/* probe — the BRING-YOUR-OWN-CERT half of DANE: TLS-connect a live origin the
 * operator already runs (e.g. a Let's Encrypt server), read the leaf's public
 * key, and print the `TLSA 3 1 1` rdata to pin. SNI = <name>.<tld>, the same
 * SNI the proxy dials the origin with, so the printed pin is exactly what the
 * proxy will match. Reads only the public half — never a private key. */
static int cmd_probe(const char *name, const char *hostport) {
    char host[256]; int port = 443;
    const char *colon = strrchr(hostport, ':');
    if (colon && colon != hostport && !strchr(colon, ']')) {  /* host:port (not [v6]) */
        size_t hl = (size_t)(colon - hostport);
        if (hl >= sizeof host) return 1;
        memcpy(host, hostport, hl); host[hl] = 0; port = atoi(colon + 1);
    } else snprintf(host, sizeof host, "%s", hostport);

    char fqdn[300];
    snprintf(fqdn, sizeof fqdn, "%s.%s", name, ca_tld());
    uint8_t spki[32]; char subj[256] = "", err[200] = ""; int64_t na = 0;
    if (!sscert_probe(host, port, fqdn, NULL, spki, subj, sizeof subj, &na, err, sizeof err)) {
        fprintf(stderr, "probe: %s\n", err);
        return 1;
    }
    printf("probed %s:%d  (SNI %s)\n  subject %s\n", host, port, fqdn, subj);
    if (na) { char t[32]; time_t tt = (time_t)na; struct tm tm; gmtime_r(&tt, &tm);
              strftime(t, sizeof t, "%Y-%m-%d", &tm); printf("  notAfter %s\n", t); }
    printf("publish at _443._tcp:  TLSA 3 1 1 ");
    for (int i = 0; i < 32; i++) printf("%02x", spki[i]);
    printf("\n");
    return 0;
}

/* origin-cert — the SERVER half of DANE: ensure a self-signed cert+key for
 * <name>.<tld> (default dir ~/.pepenet) and print the `TLSA 3 1 1` rdata the
 * owner publishes at `_443._tcp`. Idempotent: an existing pair is reported,
 * never rotated. */
static int cmd_origin_cert(const char *name, const char *dir) {
    char home_dir[512], fqdn[300], crt[900], key[900];
    if (!dir) {
        const char *home = getenv("HOME");
        if (!home || !home[0]) home = ".";
        snprintf(home_dir, sizeof home_dir, "%s/.pepenet", home);
        dir = home_dir;
    }
    snprintf(fqdn, sizeof fqdn, "%s.%s", name, ca_tld());
    snprintf(crt, sizeof crt, "%s/origin-%s.crt", dir, fqdn);
    snprintf(key, sizeof key, "%s/origin-%s.key", dir, fqdn);

    uint8_t spki[32];
    int created = 0;
    if (!sscert_ensure(fqdn, crt, key, 1, spki, &created)) {
        fprintf(stderr, "origin-cert: failed for '%s' (is %s writable?)\n", fqdn, dir);
        return 1;
    }
    printf("origin cert %s for %s:\n  %s\n  %s\n",
           created ? "created" : "already present", fqdn, crt, key);
    printf("publish at _443._tcp:  TLSA 3 1 1 ");
    for (int i = 0; i < 32; i++) printf("%02x", spki[i]);
    printf("\n");
    return 0;
}

static void ev_sync(void *u, int64_t *h, int64_t *ph) {
    resolver_sync(u, h, ph);
}

/* serve — the DANE proxy: listen on loopback:port, resolve each SNI against the
 * pepenet store, DANE-verify the origin, splice on success (slice 4). */
static int cmd_serve(int argc, char **argv) {
    const char *db = NULL, *store = NULL, *listen = "127.0.0.1";
    int port = 8443;
    for (int i = 2; i < argc; i++) {
        if      (!strcmp(argv[i], "--db")     && i+1 < argc) db = argv[++i];
        else if (!strcmp(argv[i], "--store")  && i+1 < argc) store = argv[++i];
        else if (!strcmp(argv[i], "--listen") && i+1 < argc) listen = argv[++i];
        else if (!strcmp(argv[i], "--port")   && i+1 < argc) port = atoi(argv[++i]);
        else return usage();
    }
    if (!db || !store) return usage();
    if (strcmp(listen, "127.0.0.1") != 0 && strcmp(listen, "::1") != 0) {
        fprintf(stderr, "serve: --listen must be 127.0.0.1 or ::1 (not a network service)\n");
        return 1;
    }

    X509 *root; EVP_PKEY *rk;
    if (!ca_root_ensure(&root, &rk)) { fprintf(stderr, "serve: no root CA\n"); return 1; }

    Resolver *rv = resolver_open(ca_tld(), store, db);
    if (!rv) {
        fprintf(stderr, "serve: cannot open store '%s' / indexer '%s'\n", store, db);
        X509_free(root); EVP_PKEY_free(rk);
        return 1;
    }

    fprintf(stderr, "pepenet-tls: serving .%s on %s:%d (store=%s indexer=%s)\n",
            ca_tld(), listen, port, store, db);
    int lfd = proxy_listen(listen, port);
    if (lfd < 0) {
        fprintf(stderr, "serve: cannot bind %s:%d\n", listen, port);
        resolver_close(rv);
        X509_free(root); EVP_PKEY_free(rk);
        return 1;
    }
    ProxyEvents ev = { .u = rv, .sync = ev_sync };
    int rc = proxy_serve_ctl(lfd, root, rk, resolver_resolve, rv, &ev, NULL);
    if (rc) fprintf(stderr, "serve: proxy loop failed\n");

    resolver_close(rv);
    X509_free(root); EVP_PKEY_free(rk);
    return rc;
}

static int cmd_gen_ca(void) {
    X509 *c; EVP_PKEY *k;
    if (!ca_root_ensure(&c, &k)) { fprintf(stderr, "gen-ca: failed\n"); return 1; }
    printf("root CA ready (name-constrained: .%s only):\n  %s\n  %s\n",
           ca_tld(), ca_root_cert_path(), ca_root_key_path());
    X509_free(c); EVP_PKEY_free(k);
    return 0;
}

static int cmd_mint(const char *name) {
    X509 *root, *leaf; EVP_PKEY *rk, *lk;
    if (!ca_root_ensure(&root, &rk)) { fprintf(stderr, "mint: no root\n"); return 1; }
    int rc = 1;
    if (ca_leaf_mint(root, rk, name, &leaf, &lk)) {
        PEM_write_X509(stdout, leaf);
        X509_free(leaf); EVP_PKEY_free(lk);
        rc = 0;
    } else {
        fprintf(stderr, "mint: failed for '%s'\n", name);
    }
    X509_free(root); EVP_PKEY_free(rk);
    return rc;
}

static int cmd_show(void) {
    X509 *c; EVP_PKEY *k;
    if (!ca_root_ensure(&c, &k)) { fprintf(stderr, "show: no root\n"); return 1; }
    X509_print_fp(stdout, c);
    X509_free(c); EVP_PKEY_free(k);
    return 0;
}

int main(int argc, char **argv) {
    /* TLD selection: --tld <t> (highest priority), else $PEPENET_TLD, else the
     * ca.c default ("doge"). Strip the flag so subcommand parsing is unchanged. */
    const char *env = getenv("PEPENET_TLD");
    if (env && !ca_set_tld(env)) { fprintf(stderr, "bad $PEPENET_TLD '%s'\n", env); return 2; }
    if (argc >= 3 && !strcmp(argv[1], "--tld")) {
        if (!ca_set_tld(argv[2])) { fprintf(stderr, "bad --tld '%s' (a lowercase label, e.g. pep|doge)\n", argv[2]); return 2; }
        argv += 2; argc -= 2;
    }

    if (argc < 2) return usage();

    if (!strcmp(argv[1], "gen-ca"))  return cmd_gen_ca();
    if (!strcmp(argv[1], "show"))    return cmd_show();
    if (!strcmp(argv[1], "mint") && argc == 3) return cmd_mint(argv[2]);
    if (!strcmp(argv[1], "probe") && argc == 4) return cmd_probe(argv[2], argv[3]);
    if (!strcmp(argv[1], "origin-cert") && (argc == 3 || argc == 4))
        return cmd_origin_cert(argv[2], argc == 4 ? argv[3] : NULL);
    if (!strcmp(argv[1], "serve"))   return cmd_serve(argc, argv);

    if (!strcmp(argv[1], "install-ca")) {
        X509 *c; EVP_PKEY *k;
        if (!ca_root_ensure(&c, &k)) { fprintf(stderr, "install: no root\n"); return 1; }
        X509_free(c); EVP_PKEY_free(k);
        int ok = trust_install(ca_root_cert_path());
#ifdef __APPLE__
        printf(ok ? "installed .%s root into login keychain\n" : "install failed\n", ca_tld());
#elif defined(__linux__)
        printf(ok ? "installed .%s root into the user NSS db (~/.pki/nssdb)\n"
                  : "install failed\n", ca_tld());
#else
        printf(ok ? "installed .%s root\n" : "install failed\n", ca_tld());
#endif
        return ok ? 0 : 1;
    }
    if (!strcmp(argv[1], "uninstall-ca")) {
        int ok = trust_uninstall(ca_root_cert_path(), ca_root_cn());
#ifdef __APPLE__
        printf(ok ? "removed .%s root from login keychain\n" : "uninstall failed\n", ca_tld());
#elif defined(__linux__)
        printf(ok ? "removed .%s root from the user NSS db\n" : "uninstall failed\n", ca_tld());
#else
        printf(ok ? "removed .%s root\n" : "uninstall failed\n", ca_tld());
#endif
        return ok ? 0 : 1;
    }
    return usage();
}
