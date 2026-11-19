/* sscert_test.c — the origin-cert half of the DANE story.
 *
 * Proves: generate persists a loadable self-signed pair (key 0600) whose SPKI
 * hash equals what dane_spki_sha256 computes on the reloaded cert (i.e. the
 * pin we hand the owner is the pin the proxy will match); the SAN covers the
 * fqdn and its wildcard; a second ensure LOADS (created=0, same pin) instead
 * of rotating the key; probe-only never creates.
 */
#include "sscert.h"
#include "dane.h"

#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static int g_fail;
#define CHECK(cond, name) do { \
    if (cond) printf("ok   %s\n", name); \
    else      { printf("FAIL %s\n", name); g_fail = 1; } \
} while (0)

int main(void) {
    char dir[256], crt[512], key[512];
    snprintf(dir, sizeof dir, "/tmp/sscert_test_%d", (int)getpid());
    mkdir(dir, 0700);
    snprintf(crt, sizeof crt, "%s/origin-www.pepe.crt", dir);
    snprintf(key, sizeof key, "%s/origin-www.pepe.key", dir);

    /* probe on nothing: must not create */
    uint8_t spki[32], spki2[32];
    CHECK(sscert_spki(crt, spki) == 0, "probe of absent cert fails");
    CHECK(access(crt, F_OK) != 0, "probe created nothing");

    int created = -1;
    CHECK(sscert_ensure("www.pepe", crt, key, 1, spki, &created) == 1, "ensure generates");
    CHECK(created == 1, "created flag set on fresh generate");

    struct stat st;
    CHECK(stat(key, &st) == 0 && (st.st_mode & 0777) == 0600, "key file is 0600");

    /* reload the persisted cert; recompute the pin with the proxy's function */
    FILE *f = fopen(crt, "rb");
    X509 *c = f ? PEM_read_X509(f, NULL, NULL, NULL) : NULL;
    if (f) fclose(f);
    CHECK(c != NULL, "persisted cert parses");
    if (c) {
        CHECK(dane_spki_sha256(c, spki2) == 1 && memcmp(spki, spki2, 32) == 0,
              "reported SPKI == dane_spki_sha256 of the reloaded cert");

        /* self-signed: verifies under its own public key */
        EVP_PKEY *pub = X509_get_pubkey(c);
        CHECK(pub && X509_verify(c, pub) == 1, "cert verifies self-signed");
        EVP_PKEY_free(pub);

        /* SAN covers fqdn + wildcard */
        GENERAL_NAMES *sans = X509_get_ext_d2i(c, NID_subject_alt_name, NULL, NULL);
        int have_fqdn = 0, have_wild = 0;
        for (int i = 0; sans && i < sk_GENERAL_NAME_num(sans); i++) {
            GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, i);
            if (gn->type != GEN_DNS) continue;
            const char *d = (const char *)ASN1_STRING_get0_data(gn->d.dNSName);
            if (!strcmp(d, "www.pepe"))   have_fqdn = 1;
            if (!strcmp(d, "*.www.pepe")) have_wild = 1;
        }
        GENERAL_NAMES_free(sans);
        CHECK(have_fqdn && have_wild, "SAN carries fqdn and *.fqdn");
        X509_free(c);
    }

    /* second ensure: loads, never rotates */
    created = -1;
    CHECK(sscert_ensure("www.pepe", crt, key, 1, spki2, &created) == 1 &&
          created == 0 && memcmp(spki, spki2, 32) == 0,
          "second ensure loads the same pin (no key rotation)");

    /* probe-only now succeeds with the same pin */
    memset(spki2, 0, sizeof spki2);
    CHECK(sscert_spki(crt, spki2) == 1 && memcmp(spki, spki2, 32) == 0,
          "probe returns the persisted pin");

    unlink(crt); unlink(key); rmdir(dir);
    printf(g_fail ? "sscert_test: FAIL\n" : "sscert_test: all ok\n");
    return g_fail;
}
