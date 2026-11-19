/* ca_test.c — the security proof for slice 1 (DESIGN.md §7 slice 1).
 *
 * Builds the name-constrained root, mints leaves, and runs each through
 * libcrypto's X509_verify_cert with the root as the sole trust anchor — the
 * exact NameConstraints-checking path a browser/OS verifier uses. This box
 * serves ONE TLD, so we prove BOTH configurations:
 *   - a `doge` root VERIFIES `.doge` leaves and REJECTS `.pepe` (and `.com`,
 *     dotless near-misses) with X509_V_ERR_PERMITTED_VIOLATION;
 *   - a `pepe` root does the mirror image.
 * The cross-TLD rejection is the point: a doge box's key cannot mint a pepe
 * leaf at all.
 *
 * Hermetic: points $HOME at a temp dir so it never touches the real
 * ~/.pepenet root. No keychain, no network — safe to run unattended.
 */
#include "ca.h"

#include <openssl/x509_vfy.h>
#include <openssl/err.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int pass = 0, fail = 0;

static void ok(const char *what)  { pass++; printf("  ok   %s\n", what); }
static void bad(const char *what) { fail++; printf("FAIL   %s\n", what); }

/* Verify `leaf` against `root` as trust anchor. Returns 1 if it verifies;
 * writes the verify error code to *err either way. */
static int verify(X509 *root, X509 *leaf, int *err) {
    X509_STORE *store = X509_STORE_new();
    X509_STORE_add_cert(store, root);
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, leaf, NULL);
    int rc = X509_verify_cert(ctx);
    *err = X509_STORE_CTX_get_error(ctx);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return rc == 1;
}

/* Mint a leaf for `name`, expect it to verify (want_ok=1) or be rejected by the
 * name constraint (want_ok=0). */
static void check(X509 *root, EVP_PKEY *rk, const char *name, int want_ok) {
    X509 *leaf; EVP_PKEY *lk;
    char label[256];
    if (!ca_leaf_mint(root, rk, name, &leaf, &lk)) { bad(name); return; }

    int err = 0, verified = verify(root, leaf, &err);
    X509_free(leaf); EVP_PKEY_free(lk);

    if (want_ok) {
        snprintf(label, sizeof label, "%-26s verifies under the root", name);
        if (verified) ok(label);
        else { bad(label); printf("       err=%d (%s)\n", err,
                                   X509_verify_cert_error_string(err)); }
    } else {
        snprintf(label, sizeof label, "%-26s rejected by NameConstraints", name);
        if (!verified && err == X509_V_ERR_PERMITTED_VIOLATION) ok(label);
        else if (!verified) { bad(label); printf("       rejected, but err=%d (%s) "
                              "— wanted PERMITTED_VIOLATION\n", err,
                              X509_verify_cert_error_string(err)); }
        else bad(label);   /* verified when it must not have */
    }
}

/* Generate a fresh root for `tld` and prove: names under `tld` verify; names
 * under the OTHER TLD, `.com`, and dotless near-misses are rejected. */
static void prove_tld(const char *tld, const char *mine, const char *other) {
    if (!ca_set_tld(tld)) { bad(tld); return; }
    printf("\n── ca: %s root (permit .%s only) ──\n", tld, tld);

    X509 *root; EVP_PKEY *rk;
    if (!ca_root_ensure(&root, &rk)) {
        fprintf(stderr, "root generation failed\n");
        ERR_print_errors_fp(stderr);
        fail++;
        return;
    }
    ok("root generated + persisted");

    char buf[64];
    snprintf(buf, sizeof buf, "www.pepenet.%s", mine);  check(root, rk, buf, 1);
    snprintf(buf, sizeof buf, "a.b.c.%s", mine);        check(root, rk, buf, 1);
    snprintf(buf, sizeof buf, "pepenet.%s", other);     check(root, rk, buf, 0);  /* other TLD */
    check(root, rk, "evil.com",              0);
    check(root, rk, "www.google.com",        0);
    snprintf(buf, sizeof buf, "not%s", mine);           check(root, rk, buf, 0);  /* dotless near-miss */
    snprintf(buf, sizeof buf, "pepenet.%s.evil.com", mine); check(root, rk, buf, 0);

    X509_free(root); EVP_PKEY_free(rk);
}

int main(void) {
    /* Hermetic HOME so we never touch the real ~/.pepenet. Per-TLD filenames
     * mean both roots coexist in the same temp dir without collision. */
    char tmpl[] = "/tmp/pepenet-tls-catest.XXXXXX";
    char *home = mkdtemp(tmpl);
    if (!home) { perror("mkdtemp"); return 1; }
    setenv("HOME", home, 1);

    prove_tld("doge", "doge", "pepe");
    prove_tld("pepe", "pepe", "doge");

    printf("\n%d ok, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
