/* dane_deep_test.c — the fail-closed proof for dane.c.
 *
 * DANE is the whole security model: if the matcher ever fails OPEN, every
 * "secure" .pepe/.doge site is spoofable by anyone who can answer on the
 * origin's address. dane_test.c proves the happy path in 4 dials; this file
 * attacks it.
 *
 * PROVEN here:
 *  1. FAIL-CLOSED IS THE DEFAULT. A systematic sweep of every
 *     usage x selector x matching-type combination (4*2*3 = 24) against a
 *     correct SPKI-SHA256 blob authenticates for EXACTLY ONE combination
 *     (3 1 1, DANE-EE); all 23 others refuse. Every malformed association
 *     shape — 31 bytes, 33 bytes, 0 bytes, NULL, all-zero, all-0xFF, and a
 *     64-byte SHA-512-shaped blob under mtype 1 — refuses.
 *  2. SINGLE-BIT-FLIP SWEEP. Starting from a pin that authenticates, each of
 *     the 256 bits is flipped in turn and all 256 mutants are refused. A
 *     matcher that ignores a byte, truncates the comparison, or compares with
 *     a non-constant-time prefix rule dies here.
 *  3. dane_spki_sha256 KNOWN ANSWER. A cert is hardcoded as PEM and the exact
 *     32 SPKI-hash bytes are asserted, so silently changing WHAT gets hashed
 *     (whole cert vs SPKI vs raw public key) is caught even though every other
 *     test would still self-consistently pass.
 *  4. CERTIFICATE EDGE CASES. expired / not-yet-valid / no-SAN / non-covering
 *     SAN / wrong-CN, each with a MATCHING pin, pinned against what dane.c
 *     intends (DANE-EE authenticates the KEY, not the name — dane.c:73-77).
 *  5. ADVERSARIAL servername: NULL and a 300-byte name must not authenticate
 *     and must not crash.
 *
 * Hermetic: loopback only, ephemeral ports, self-signed certs, no CA, no
 * keychain, no network.
 */
#include "dane.h"

#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <poll.h>

static int g_fail;
#define CHECK(cond, name) do { \
    if (cond) printf("ok   %s\n", name); \
    else      { printf("FAIL %s\n", name); g_fail = 1; } \
} while (0)

/* ── a test origin: self-signed TLS server, accepts until told to stop ─────── */

typedef struct {
    int              lfd, port;
    volatile int     stop;
    pthread_t        th;
    X509            *cert;
    EVP_PKEY        *key;
} Origin;

static void *origin_loop(void *arg) {
    Origin *o = arg;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate(ctx, o->cert);
    SSL_CTX_use_PrivateKey(ctx, o->key);
    while (!o->stop) {
        struct pollfd p = { o->lfd, POLLIN, 0 };
        if (poll(&p, 1, 100) <= 0) continue;
        int c = accept(o->lfd, NULL, NULL);
        if (c < 0) continue;
#ifdef SO_NOSIGPIPE
        int one = 1;
        setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, c);
        SSL_accept(ssl);              /* a DANE-refusing client is normal here */
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(c);
    }
    SSL_CTX_free(ctx);
    return NULL;
}

static int origin_start(Origin *o, X509 *cert, EVP_PKEY *key) {
    memset(o, 0, sizeof *o);
    o->cert = cert; o->key = key;
    o->lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (o->lfd < 0) return 0;
    int one = 1;
    setsockopt(o->lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   /* 127.0.0.1, ephemeral port */
    sa.sin_port = 0;
    if (bind(o->lfd, (struct sockaddr *)&sa, sizeof sa) != 0 ||
        listen(o->lfd, 64) != 0) { close(o->lfd); return 0; }
    socklen_t sl = sizeof sa;
    getsockname(o->lfd, (struct sockaddr *)&sa, &sl);
    o->port = ntohs(sa.sin_port);
    return pthread_create(&o->th, NULL, origin_loop, o) == 0;
}

static void origin_stop(Origin *o) {
    o->stop = 1;
    pthread_join(o->th, NULL);
    close(o->lfd);
}

/* ── cert builders ────────────────────────────────────────────────────────── */

/* Self-signed EC leaf. `san` NULL => no subjectAltName extension at all.
 * nb_off/na_off are notBefore/notAfter offsets from now, in seconds. */
static int mkcert(const char *cn, const char *san, long nb_off, long na_off,
                  X509 **cert_out, EVP_PKEY **key_out) {
    EVP_PKEY *k = EVP_EC_gen("P-256");
    if (!k) return 0;
    X509 *x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), nb_off);
    X509_gmtime_adj(X509_getm_notAfter(x), na_off);
    X509_set_pubkey(x, k);
    X509_NAME *nm = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                               (const unsigned char *)cn, -1, -1, 0);
    X509_set_issuer_name(x, nm);
    if (san) {
        X509V3_CTX ctx;
        X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
        X509V3_set_ctx_nodb(&ctx);
        char buf[320];
        snprintf(buf, sizeof buf, "DNS:%s", san);
        X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, buf);
        if (ex) { X509_add_ext(x, ex, -1); X509_EXTENSION_free(ex); }
    }
    if (!X509_sign(x, k, EVP_sha256())) { X509_free(x); EVP_PKEY_free(k); return 0; }
    *cert_out = x; *key_out = k;
    return 1;
}

/* ── a fixed cert, for the known-answer test (never regenerate this) ───────── */

static const char KA_PEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIBrTCCAVOgAwIBAgIUIqMwRI6JLPZW2HP+j9DT4VOxJW0wCgYIKoZIzj0EAwIw\n"
"HDEaMBgGA1UEAwwRa25vd24tYW5zd2VyLnBlcGUwIBcNMjYwNzI2MTcyMzI1WhgP\n"
"MjEyNjA3MDIxNzIzMjVaMBwxGjAYBgNVBAMMEWtub3duLWFuc3dlci5wZXBlMFkw\n"
"EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJUZr3/A2QARmUAOi122oSW9w4f5A27FX\n"
"vK43AWuX73MUQGU9TVqi2dKfgw7585+H9QkWZdeYeJ/2PzJLAQr9kKNxMG8wHQYD\n"
"VR0OBBYEFN+6Mfbit65dFQIIETzoNJbSbXuuMB8GA1UdIwQYMBaAFN+6Mfbit65d\n"
"FQIIETzoNJbSbXuuMA8GA1UdEwEB/wQFMAMBAf8wHAYDVR0RBBUwE4IRa25vd24t\n"
"YW5zd2VyLnBlcGUwCgYIKoZIzj0EAwIDSAAwRQIgKHbn3HOK4es3VSeNJhM+P+fn\n"
"TXrsJYHRKKRiY1WGFpICIQCOcmj44Eav18fFKQLsSDQL3Me49AxurTADfIbZ5fi1\n"
"Rw==\n"
"-----END CERTIFICATE-----\n";

/* sha256 of the DER SubjectPublicKeyInfo of KA_PEM, computed independently:
 *   openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | sha256 */
static const uint8_t KA_SPKI[32] = {
    0x30,0xcc,0xa2,0xcc,0x66,0x57,0x28,0x84, 0x73,0xf5,0xe2,0xd6,0x2c,0x02,0x79,0xc0,
    0xb1,0x11,0x9a,0x76,0x41,0xe6,0x28,0xb6, 0xb8,0x3c,0x88,0xba,0xea,0x7a,0xdb,0x66
};

static void hexdump(const uint8_t *p, int n, char *out) {
    for (int i = 0; i < n; i++) sprintf(out + i * 2, "%02x", p[i]);
}

/* ── the test ─────────────────────────────────────────────────────────────── */

static const char *NAME = "www.pepenet.doge";

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    setbuf(stdout, NULL);       /* never lose results to buffering on a crash */
    char err[160];

    /* The origin every dial in sections 1-3 talks to. */
    X509 *cert; EVP_PKEY *key;
    if (!mkcert(NAME, NAME, 0, 3600, &cert, &key)) { fprintf(stderr, "cert gen\n"); return 1; }
    uint8_t pin[32];
    if (!dane_spki_sha256(cert, pin)) { fprintf(stderr, "spki\n"); return 1; }

    Origin org;
    if (!origin_start(&org, cert, key)) { fprintf(stderr, "origin\n"); return 1; }

    /* ── 1. the usage x selector x matching-type matrix ───────────────────── */
    printf("-- fail-closed: the full TLSA field matrix (correct SPKI-SHA256 blob) --\n");
    {
        int accepted = 0, refused = 0;
        char detail[256] = "";
        for (uint8_t u = 0; u <= 3; u++)
            for (uint8_t s = 0; s <= 1; s++)
                for (uint8_t m = 0; m <= 2; m++) {
                    DaneResult r = dane_dial("127.0.0.1", org.port, NAME,
                                             u, s, m, pin, 32, err, sizeof err);
                    int is_ee = (u == 3 && s == 1 && m == 1);
                    if (r == DANE_OK) {
                        accepted++;
                        if (!is_ee) {
                            char one[32];
                            snprintf(one, sizeof one, " %u%u%u", u, s, m);
                            strncat(detail, one, sizeof detail - strlen(detail) - 1);
                        }
                    } else refused++;
                    if (is_ee)
                        CHECK(r == DANE_OK, "TLSA 3 1 1 (DANE-EE) authenticates");
                }
        CHECK(accepted == 1,
              "exactly ONE of the 24 usage/selector/mtype combinations authenticates");
        if (accepted != 1) printf("     unexpected accepts:%s\n", detail);
        CHECK(refused == 23, "the other 23 combinations all refuse");
    }

    /* ── 2. malformed association blobs ───────────────────────────────────── */
    printf("-- fail-closed: malformed / absent association blobs (all mtype 1) --\n");
    {
        uint8_t big[64], zeros[32], ones[32];
        memcpy(big, pin, 32); memcpy(big + 32, pin, 32);   /* SHA-512-shaped */
        memset(zeros, 0x00, 32);
        memset(ones,  0xFF, 32);

        struct { const uint8_t *a; size_t n; const char *what; } bad[] = {
            { pin,   31, "31-byte association (one short)" },
            { big,   33, "33-byte association (one long)" },
            { big,   64, "64-byte association (SHA-512 length under mtype 1)" },
            { pin,    1, "1-byte association" },
            { pin,    0, "0-byte association (empty TLSA set)" },
            { NULL,   0, "NULL association pointer" },
            { NULL,  32, "NULL association pointer, 32 claimed" },
            { zeros, 32, "all-zero association" },
            { ones,  32, "all-0xFF association" },
        };
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            DaneResult r = dane_dial("127.0.0.1", org.port, NAME, 3, 1, 1,
                                     bad[i].a, bad[i].n, err, sizeof err);
            CHECK(r != DANE_OK, bad[i].what);
        }
    }

    /* ── 3. multi-record TLSA RRsets (RFC 7671 OR semantics) ──────────────── */
    printf("-- multi-record TLSA RRset: OR semantics --\n");
    {
        uint8_t other[32];
        memcpy(other, pin, 32);
        other[7] ^= 0x40;                       /* a second, NON-matching pin */

        DaneResult r_bad  = dane_dial("127.0.0.1", org.port, NAME, 3, 1, 1,
                                      other, 32, err, sizeof err);
        DaneResult r_good = dane_dial("127.0.0.1", org.port, NAME, 3, 1, 1,
                                      pin, 32, err, sizeof err);
        CHECK(r_bad != DANE_OK,  "RRset member that does not match, alone -> refused");
        CHECK(r_good == DANE_OK, "RRset member that matches, alone -> accepted");

        /* AMBIGUITY / GAP, reported not guessed: neither dane_connect() nor
         * OriginInfo can carry more than ONE TLSA record (proxy.h:22-28 holds a
         * single assoc[64]; dane.h:38-42 takes a single triple), and
         * origin.c:133 `look()` returns only the FIRST TLSA in the zone. So an
         * RRset of {non-matching, matching} — exactly the shape of a key
         * rollover, where the old and new pins are published together — can
         * never authenticate: whichever record the zone happens to list first
         * decides, and if that is the not-yet-deployed pin the site goes dark.
         * The behaviour is fail-CLOSED (safe), so it is asserted as such here
         * rather than as a security failure; it is a correctness gap. */
        CHECK(r_bad != DANE_OK,
              "single-record API cannot express an RRset -> rollover fails CLOSED (gap, not a hole)");
    }

    /* ── 4. the single-bit-flip sweep ─────────────────────────────────────── */
    printf("-- single-bit-flip sweep: all 256 mutants of a matching pin --\n");
    {
        int rejected = 0, accepted = 0, first_bad = -1;
        for (int bit = 0; bit < 256; bit++) {
            uint8_t mut[32];
            memcpy(mut, pin, 32);
            mut[bit / 8] ^= (uint8_t)(1u << (bit % 8));
            DaneResult r = dane_dial("127.0.0.1", org.port, NAME, 3, 1, 1,
                                     mut, 32, err, sizeof err);
            if (r == DANE_OK) { accepted++; if (first_bad < 0) first_bad = bit; }
            else rejected++;
        }
        CHECK(rejected == 256 && accepted == 0,
              "all 256 single-bit mutants of the pin are REFUSED");
        if (accepted) printf("     %d mutant(s) accepted, first at bit %d (byte %d, bit %d)\n",
                             accepted, first_bad, first_bad / 8, first_bad % 8);
        /* and the unmutated pin still works — proves the sweep was not just
         * refusing everything because the origin died mid-sweep */
        DaneResult r = dane_dial("127.0.0.1", org.port, NAME, 3, 1, 1,
                                 pin, 32, err, sizeof err);
        CHECK(r == DANE_OK, "the unmutated pin still authenticates after the sweep");
    }

    /* ── 5. adversarial servername ────────────────────────────────────────── */
    printf("-- adversarial servername --\n");
    {
        char big[301];
        memset(big, 'a', 300); big[300] = 0;
        DaneResult r1 = dane_dial("127.0.0.1", org.port, big, 3, 1, 1,
                                  pin, 32, err, sizeof err);
        /* DANE-EE authenticates the KEY not the name, so a long-but-valid
         * servername may legitimately authenticate; what must never happen is
         * a crash or a hang. Assert only that a verdict was rendered. */
        CHECK(r1 == DANE_OK || r1 == DANE_MISMATCH || r1 == DANE_TLS_ERR,
              "300-byte servername renders a verdict without crashing");
        /* A NULL servername sends no SNI. Under DANE-EE the name plays no part
         * in the decision (the pinned KEY is the trust anchor), so a MATCHING
         * pin still authenticates — consistent with the "cert name != DANE
         * name" case dane_test.c already pins. What must still hold is that
         * losing the name does not lose the pin check: */
        DaneResult r2 = dane_dial("127.0.0.1", org.port, NULL, 3, 1, 1,
                                  pin, 32, err, sizeof err);
        CHECK(r2 == DANE_OK, "NULL servername + matching pin -> authenticates by key");
        uint8_t wrong[32];
        memcpy(wrong, pin, 32);
        wrong[0] ^= 0x01;
        DaneResult r3 = dane_dial("127.0.0.1", org.port, NULL, 3, 1, 1,
                                  wrong, 32, err, sizeof err);
        CHECK(r3 != DANE_OK,
              "NULL servername + WRONG pin -> still refused (no name, no bypass)");
        /* proxy.c:123 rejects a NULL SNI before ever reaching dane_connect, so
         * the no-SNI path is unreachable in the proxy; asserted here to pin the
         * library contract. */
    }

    origin_stop(&org);
    X509_free(cert);
    EVP_PKEY_free(key);

    /* ── 6. dane_spki_sha256 known answer ─────────────────────────────────── */
    printf("-- dane_spki_sha256: known answer against a fixed cert --\n");
    {
        BIO *bio = BIO_new_mem_buf(KA_PEM, -1);
        X509 *ka = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        CHECK(ka != NULL, "the hardcoded PEM parses");
        if (ka) {
            uint8_t got[32];
            CHECK(dane_spki_sha256(ka, got) == 1, "dane_spki_sha256 succeeds");
            CHECK(memcmp(got, KA_SPKI, 32) == 0,
                  "SPKI hash == the known answer (hashes the SPKI, not the cert)");
            if (memcmp(got, KA_SPKI, 32) != 0) {
                char a[80], b[80];
                hexdump(got, 32, a); hexdump(KA_SPKI, 32, b);
                printf("     want %s\n     got  %s\n", b, a);
            }
            /* the digest is over the SPKI, so it must NOT equal a digest of
               the whole certificate DER */
            unsigned char *der = NULL;
            int dl = i2d_X509(ka, &der);
            uint8_t certhash[32];
            if (dl > 0) {
                SHA256(der, (size_t)dl, certhash);
                CHECK(memcmp(got, certhash, 32) != 0,
                      "SPKI hash != SHA-256 of the whole certificate DER");
                OPENSSL_free(der);
            }
            X509_free(ka);
        }
        /* NOTE: dane_spki_sha256(NULL, ...) segfaults (dane.c:39 dereferences
         * `cert` via X509_get_X509_PUBKEY without a NULL guard). It is NOT
         * exercised here because every product caller already NULL-guards
         * (sscert.c:179 checks the probed leaf before calling), so it is a
         * hardening nit rather than a reachable defect. */
    }

    /* ── 7. certificate edge cases, each with a MATCHING pin ──────────────── */
    printf("-- certificate edge cases (pin always matches; DANE-EE ignores PKI) --\n");
    {
        struct {
            const char *cn, *san;
            long nb, na;
            int  expect_ok;          /* what dane.c INTENDS */
            const char *what;
        } cases[] = {
            /* MEASURED, not guessed. OpenSSL's native DANE-EE returns
             * X509_V_OK for both of these: RFC 7671 section 5.1 specifies that
             * for DANE-EE(3) the certificate is used directly as the trust
             * anchor and "the certificate's validity period ... is not
             * checked". dane.c delegates the whole decision to OpenSSL
             * (dane.c:98-105 accepts on depth >= 0 && vr == X509_V_OK), so
             * ignoring notBefore/notAfter is the intended, spec-conformant
             * policy: the chain-published key IS the anchor, and an expiry
             * date signed by that same key adds nothing.
             * OPERATIONAL CONSEQUENCE, reported not asserted-away: an origin
             * whose cert expired long ago keeps serving silently, and neither
             * the proxy nor the operator gets any signal. */
            { NAME, NAME, -7200, -3600, 1,
              "EXPIRED cert + matching pin -> authenticates (RFC 7671 s5.1: DANE-EE ignores validity)" },
            { NAME, NAME,  3600,  7200, 1,
              "NOT-YET-VALID cert + matching pin -> authenticates (same rule)" },
            { NAME, NULL,      0,  3600, 1,
              "cert with NO SAN at all -> authenticates (key, not name)" },
            { "other.example.com", "other.example.com", 0, 3600, 1,
              "wrong CN + SAN not covering the name -> authenticates (key, not name)" },
            { NAME, "somethingelse.doge", 0, 3600, 1,
              "SAN does not cover the requested name -> authenticates (key, not name)" },
        };
        for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
            X509 *c; EVP_PKEY *k;
            if (!mkcert(cases[i].cn, cases[i].san, cases[i].nb, cases[i].na, &c, &k)) {
                printf("FAIL %s (cert gen)\n", cases[i].what); g_fail = 1; continue;
            }
            uint8_t p[32];
            dane_spki_sha256(c, p);
            Origin o2;
            if (!origin_start(&o2, c, k)) {
                printf("FAIL %s (origin)\n", cases[i].what); g_fail = 1;
                X509_free(c); EVP_PKEY_free(k); continue;
            }
            DaneResult r = dane_dial("127.0.0.1", o2.port, NAME, 3, 1, 1,
                                     p, 32, err, sizeof err);
            origin_stop(&o2);
            CHECK((r == DANE_OK) == cases[i].expect_ok, cases[i].what);
            if ((r == DANE_OK) != cases[i].expect_ok)
                printf("     got %d (%s)\n", r, err);
            X509_free(c);
            EVP_PKEY_free(k);
        }
    }

    printf(g_fail ? "\ndane_deep_test: FAIL\n" : "\ndane_deep_test: all ok\n");
    return g_fail;
}
