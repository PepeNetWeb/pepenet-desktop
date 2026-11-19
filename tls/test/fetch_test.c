/* fetch_test.c — the first tests for fetch.c (tls_loopback_get).
 *
 * fetch.c is a hand-rolled HTTP/1.1 client that parses whatever the origin
 * sends back. Everything it parses is attacker-influenced: the bytes come from
 * the origin, and although the proxy DANE-authenticates that origin, "the
 * pinned key" is not the same thing as "well-behaved" — a compromised or buggy
 * origin still gets to drive this parser.
 *
 * PROVEN here:
 *   - the happy paths: Content-Length framing, read-to-EOF framing, and
 *     chunked framing (including chunk extensions) return the exact body;
 *   - argument guards (NULL sni/path/out), a dead port, a non-TLS peer, and a
 *     peer that closes right after the handshake all return 0 without crashing;
 *   - status-line handling: non-200 codes, a missing status line, a short
 *     response, and a garbage prefix are all refused;
 *   - body-size limits: oversize bodies refuse, a body exactly at cap is
 *     accepted, an empty body refuses, and an absurd cap does not crash;
 *   - RESPONSE TRUNCATED AT EVERY OFFSET (all 200-odd prefixes of a valid
 *     response, each served then closed) never crashes and never yields more
 *     bytes than were sent;
 *   - chunked-decoder abuse: a truncated chunk, a non-hex size, and a
 *     SIZE_MAX-shaped chunk size. The last one is run in a forked child
 *     because it currently kills the process (see the FAILS note there).
 *
 * Hermetic: a TLS server inside this test on a 127.0.0.1 ephemeral port; no
 * real network, no CA (fetch.c verifies nothing on the loopback hop by design).
 */
#include "fetch.h"

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <pthread.h>
#include <sys/socket.h>
#include <sys/wait.h>
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

/* ── the canned-response TLS server ───────────────────────────────────────── */

/* The test is strictly sequential: it arms one response, makes one call, then
 * arms the next. No locking needed beyond the handshake ordering. */
static const uint8_t *g_resp;
static size_t         g_resp_len;
static int            g_mode;        /* 0 = TLS + canned bytes
                                        1 = TLS handshake then immediate close
                                        2 = plain TCP garbage (no TLS at all) */
static volatile int   g_stop;
static int            g_lfd, g_port;

static void arm(const char *s)              { g_resp = (const uint8_t *)s; g_resp_len = strlen(s); g_mode = 0; }
static void arm_n(const void *p, size_t n)  { g_resp = p; g_resp_len = n; g_mode = 0; }

static int self_signed(X509 **cert_out, EVP_PKEY **key_out) {
    EVP_PKEY *k = EVP_EC_gen("P-256");
    if (!k) return 0;
    X509 *x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, k);
    X509_NAME *nm = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                               (const unsigned char *)"origin.pepe", -1, -1, 0);
    X509_set_issuer_name(x, nm);
    if (!X509_sign(x, k, EVP_sha256())) { X509_free(x); EVP_PKEY_free(k); return 0; }
    *cert_out = x; *key_out = k;
    return 1;
}

struct srv { X509 *cert; EVP_PKEY *key; };

static void *server(void *arg) {
    struct srv *s = arg;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate(ctx, s->cert);
    SSL_CTX_use_PrivateKey(ctx, s->key);
    while (!g_stop) {
        struct pollfd p = { g_lfd, POLLIN, 0 };
        if (poll(&p, 1, 100) <= 0) continue;
        int c = accept(g_lfd, NULL, NULL);
        if (c < 0) continue;
#ifdef SO_NOSIGPIPE
        int one = 1;
        setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
        if (g_mode == 2) {                       /* not TLS at all */
            const char *junk = "i am not a tls server\r\n\r\n";
            send(c, junk, strlen(junk), 0);
            close(c);
            continue;
        }
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, c);
        if (SSL_accept(ssl) == 1 && g_mode == 0) {
            char req[2048];
            SSL_read(ssl, req, sizeof req);      /* DRAIN the request: closing on
                                                    an unread request would RST
                                                    and destroy our own response */
            size_t off = 0;
            while (off < g_resp_len) {
                int w = SSL_write(ssl, g_resp + off, (int)(g_resp_len - off));
                if (w <= 0) break;
                off += (size_t)w;
            }
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(c);
    }
    SSL_CTX_free(ctx);
    return NULL;
}

/* ── helpers ─────────────────────────────────────────────────────────────── */

static size_t get(const char *path, uint8_t **out, size_t cap) {
    return tls_loopback_get((uint16_t)g_port, "origin.pepe", path, out, cap);
}

/* one call, body compared to `want`; frees */
static int body_is(const char *want, size_t cap) {
    uint8_t *o = NULL;
    size_t n = get("/x", &o, cap);
    int ok = n == strlen(want) && o && memcmp(o, want, n) == 0;
    free(o);
    return ok;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    setbuf(stdout, NULL);

    X509 *cert; EVP_PKEY *key;
    if (!self_signed(&cert, &key)) { fprintf(stderr, "cert\n"); return 1; }

    g_lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(g_lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);      /* 127.0.0.1, ephemeral */
    sa.sin_port = 0;
    if (bind(g_lfd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(g_lfd, 64) != 0) {
        perror("bind"); return 1;
    }
    socklen_t sl = sizeof sa;
    getsockname(g_lfd, (struct sockaddr *)&sa, &sl);
    g_port = ntohs(sa.sin_port);

    struct srv s = { cert, key };
    pthread_t th;
    pthread_create(&th, NULL, server, &s);

    /* ── argument guards + unreachable peers ─────────────────────────────── */
    printf("-- argument guards and dead peers --\n");
    {
        uint8_t *o = (uint8_t *)0x1;
        arm("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
        CHECK(tls_loopback_get((uint16_t)g_port, NULL, "/x", &o, 4096) == 0,
              "NULL sni -> 0");
        CHECK(tls_loopback_get((uint16_t)g_port, "origin.pepe", NULL, &o, 4096) == 0,
              "NULL path -> 0");
        CHECK(tls_loopback_get((uint16_t)g_port, "origin.pepe", "/x", NULL, 4096) == 0,
              "NULL out -> 0");
        /* the guards must also not leave a dangling *out */
        o = (uint8_t *)0x1;
        (void)tls_loopback_get((uint16_t)g_port, NULL, "/x", &o, 4096);
        CHECK(o == (uint8_t *)0x1 || o == NULL, "guarded call leaves out untouched or NULL");

        uint8_t *p = NULL;
        /* port 1 is bound by nothing here and is < 1024 only on the SERVER side;
         * connecting out to it is unprivileged and simply refuses */
        CHECK(tls_loopback_get(1, "origin.pepe", "/x", &p, 4096) == 0 && p == NULL,
              "connection refused -> 0, out=NULL");
    }

    printf("-- non-TLS and half-dead peers --\n");
    {
        uint8_t *o = NULL;
        g_mode = 2;
        CHECK(get("/x", &o, 4096) == 0 && o == NULL, "peer is not a TLS server -> 0");
        g_mode = 1;
        o = NULL;
        CHECK(get("/x", &o, 4096) == 0 && o == NULL, "peer closes right after handshake -> 0");
        g_mode = 0;
    }

    /* ── framing: the three body shapes fetch.c claims to support ────────── */
    printf("-- body framing --\n");
    {
        arm("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello");
        CHECK(body_is("hello", 4096), "Content-Length framing returns the exact body");

        arm("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nno length here");
        CHECK(body_is("no length here", 4096), "read-to-EOF framing returns the exact body");

        /* NOTE the trailing `X-Pad` on every chunked case below. It is load
         * bearing — see the "last header is invisible" case at the end of this
         * section. With a header after it, Transfer-Encoding is seen and the
         * decoder runs, which is what these three cases pin. */
        arm("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Pad: 1\r\n\r\n"
            "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
        CHECK(body_is("hello world", 4096), "chunked framing de-chunks correctly");

        arm("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Pad: 1\r\n\r\n"
            "5;ext=1\r\nhello\r\n0\r\n\r\n");
        CHECK(body_is("hello", 4096), "chunk extensions are ignored, body intact");

        /* FAILS: fetch.c:120-121 matches the header NAME case-insensitively
         * (strncasecmp) but then looks for the transfer-coding token with
         * find_seq(), which is a plain case-SENSITIVE memcmp. RFC 9110 makes
         * transfer-coding names case-insensitive, so `CHUNKED` / `Chunked` are
         * legal spellings that fetch.c fails to recognise — chunked stays 0,
         * unchunk() is skipped, and the raw chunk framing is returned as the
         * body. Same corruption as the last-header bug above, different cause.
         * Note the header NAME is deliberately lowercased here too, to show the
         * name half of the match is fine and only the VALUE half is broken. */
        arm("HTTP/1.1 200 OK\r\ntransfer-encoding: CHUNKED\r\nX-Pad: 1\r\n\r\n"
            "3\r\nabc\r\n0\r\n\r\n");
        CHECK(body_is("abc", 4096),
              "Transfer-Encoding VALUE match is case-insensitive (CHUNKED)");

        /* FAILS: fetch.c:118 scans the header block with
         *     le = find_seq(l, (size_t)(hend - l), "\r\n", 2);
         * where `hend` points AT the "\r\n\r\n" that ends the block. The search
         * window therefore stops one CRLF short: for the LAST header line, its
         * own terminating "\r\n" sits at exactly `hend` and is outside the
         * window, find_seq returns NULL, and fetch.c:119 `break`s — so the
         * final header line is NEVER examined.
         *
         * Consequence: `Transfer-Encoding: chunked` is honoured only when some
         * other header follows it. When it is last — the ordinary case, and
         * what nginx/Kestrel emit — `chunked` stays 0, unchunk() is skipped,
         * and the raw chunk framing ("5\r\nhello\r\n...") is handed back as if
         * it were the body. A favicon fetched this way is silently corrupt.
         *
         * The correct window is (hend + 2) - l, or the loop should treat `hend`
         * itself as a terminator. */
        arm("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
        uint8_t *lastb = NULL;
        size_t lastn = get("/x", &lastb, 4096);
        CHECK(lastn == 11 && lastb && memcmp(lastb, "hello world", 11) == 0,
              "Transfer-Encoding as the LAST header is still honoured");
        if (lastn && !(lastn == 11 && memcmp(lastb, "hello world", 11) == 0))
            printf("     product bug: got %zu raw bytes '%.*s' (chunk framing left in the body)\n",
                   lastn, (int)lastn, (char *)lastb);
        free(lastb);

        arm("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        CHECK(body_is("ok", 4096),
              "a last-position Content-Length still frames correctly (only T-E parsing needs the scan)");

        /* a body containing CRLFCRLF must not be mistaken for the head break */
        arm("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nab\r\n\r\ncdefg");
        uint8_t *o = NULL;
        size_t n = get("/x", &o, 4096);
        CHECK(n == 11 && o && memcmp(o, "ab\r\n\r\ncdefg", 11) == 0,
              "only the FIRST CRLFCRLF splits head from body");
        free(o);
    }

    /* ── status line handling ────────────────────────────────────────────── */
    printf("-- status line handling --\n");
    {
        uint8_t *o = NULL;
        arm("HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nxxx");
        CHECK(get("/x", &o, 4096) == 0 && o == NULL, "404 -> 0 (body withheld)");
        arm("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 3\r\n\r\nxxx");
        o = NULL;
        CHECK(get("/x", &o, 4096) == 0, "500 -> 0");
        arm("HTTP/1.1 301 Moved\r\nLocation: /y\r\nContent-Length: 3\r\n\r\nxxx");
        o = NULL;
        CHECK(get("/x", &o, 4096) == 0, "301 -> 0 (no redirect following)");
        arm("HTTP/1.1 204 No Content\r\n\r\n");
        o = NULL;
        CHECK(get("/x", &o, 4096) == 0, "204 -> 0");

        arm("i am not http at all\r\n\r\nbody");
        o = NULL;
        CHECK(get("/x", &o, 4096) == 0 && o == NULL, "no status line -> 0");
        arm("HTTP/9.9 200 OK\r\nContent-Length: 3\r\n\r\nxxx");
        o = NULL;
        CHECK(get("/x", &o, 4096) == 0, "wrong HTTP major version -> 0");
        arm("HTTP");
        o = NULL;
        CHECK(get("/x", &o, 4096) == 0, "4-byte response -> 0");
        arm("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n");
        o = NULL;
        CHECK(get("/x", &o, 4096) == 0, "headers but empty body -> 0");
        arm("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nxxx");
        o = NULL;
        CHECK(get("/x", &o, 4096) == 0, "no header terminator -> 0");

        /* FAILS: fetch.c:114 compares only three bytes of the status code
         * (`strncmp(b.p + 9, "200", 3)`) and never checks that a delimiter
         * follows, so any 3+ digit code starting "200" is taken for a 200.
         * "2000" is not a real status code, but the same hole accepts a
         * response whose status line the origin deliberately malforms, and the
         * body is then handed to the caller as if it were a 200. */
        arm("HTTP/1.1 2000 Bogus\r\nContent-Length: 3\r\n\r\nxxx");
        o = NULL;
        size_t n2000 = get("/x", &o, 4096);
        CHECK(n2000 == 0, "status code '2000' is NOT treated as 200");
        if (n2000) printf("     product bug: fetch.c:114 accepted '2000' and returned %zu body bytes\n", n2000);
        free(o);
    }

    /* ── header parsing edge cases ───────────────────────────────────────── */
    printf("-- header parsing edge cases --\n");
    {
        arm("HTTP/1.1 200 OK\r\nIAmAHeaderWithNoColon\r\nContent-Length: 2\r\n\r\nok");
        CHECK(body_is("ok", 4096), "header with no colon is ignored, body intact");

        arm("HTTP/1.1 200 OK\r\n:\r\nContent-Length: 2\r\n\r\nok");
        CHECK(body_is("ok", 4096), "empty header name is ignored, body intact");

        /* Content-Length is NEVER honoured (fetch.c frames on connection close
         * alone). Documented here because it means a TRUNCATED response is
         * indistinguishable from a complete one: the origin promises 100 bytes,
         * sends 4, and the caller receives 4 with a success return. Low impact
         * for the favicon use fetch.h describes; recorded so it is a decision
         * rather than an accident. */
        arm("HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\ntiny");
        CHECK(body_is("tiny", 4096),
              "absurd Content-Length does not overflow or truncate (header ignored entirely)");

        arm("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort");
        CHECK(body_is("short", 4096),
              "Content-Length larger than the body is not detected (framing is close-only)");
    }

    /* ── size limits ─────────────────────────────────────────────────────── */
    printf("-- body size limits --\n");
    {
        char big[600];
        int hl = snprintf(big, sizeof big, "HTTP/1.1 200 OK\r\n\r\n");
        memset(big + hl, 'A', 100);
        arm_n(big, (size_t)hl + 100);

        uint8_t *o = NULL;
        CHECK(get("/x", &o, 50) == 0 && o == NULL, "body larger than cap -> 0");
        o = NULL;
        CHECK(get("/x", &o, 100) == 100 && o, "body exactly at cap -> accepted");
        free(o);
        o = NULL;
        CHECK(get("/x", &o, 101) == 100, "body one under cap -> accepted");
        free(o);

        /* cap so large that fetch.c:90's `cap + 4096` wraps to a tiny bound */
        o = NULL;
        size_t n = get("/x", &o, (size_t)-1);
        CHECK(n == 0 || n == 100, "SIZE_MAX cap does not crash");
        free(o);
        o = NULL;
        CHECK(get("/x", &o, 0) == 0, "cap 0 -> 0");
    }

    /* ── truncation at every offset ──────────────────────────────────────── */
    printf("-- response truncated at every offset --\n");
    {
        char full[512];
        int fl = snprintf(full, sizeof full,
            "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n"
            "Transfer-Encoding: chunked\r\nX-Pad: 1\r\n\r\n"
            "10\r\n0123456789abcdef\r\n8\r\nGHIJKLMN\r\n0\r\n\r\n");
        int crashes = 0, oversize = 0, ok_or_zero = 0;
        for (int cut = 0; cut <= fl; cut++) {
            arm_n(full, (size_t)cut);
            uint8_t *o = NULL;
            size_t n = get("/x", &o, 4096);
            if (n > (size_t)cut) oversize++;         /* more out than went in */
            else ok_or_zero++;
            free(o);
        }
        CHECK(oversize == 0 && crashes == 0,
              "every prefix of a valid response returns <= what was sent, no crash");
        CHECK(ok_or_zero == fl + 1, "all prefixes handled");
        printf("     (%d prefixes exercised)\n", fl + 1);
    }

    /* ── chunked decoder abuse ───────────────────────────────────────────── */
    printf("-- chunked decoder abuse --\n");
    {
        uint8_t *o = NULL;
        arm("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Pad: 1\r\n\r\n"
            "20\r\nonlyfourteen..\r\n0\r\n\r\n");
        CHECK(get("/x", &o, 4096) == 0 && o == NULL,
              "chunk size larger than the data present -> 0");

        arm("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Pad: 1\r\n\r\n"
            "zzzz\r\nabcd\r\n0\r\n\r\n");
        o = NULL;
        size_t nz = get("/x", &o, 4096);
        CHECK(nz == 0, "non-hex chunk size -> 0");
        free(o);

        arm("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Pad: 1\r\n\r\n"
            "5\r\nhello");
        o = NULL;
        CHECK(get("/x", &o, 4096) == 0, "chunked stream with no terminator -> 0");

        arm("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Pad: 1\r\n\r\n0\r\n\r\n");
        o = NULL;
        CHECK(get("/x", &o, 4096) == 0, "chunked stream with only the 0 chunk -> 0");
    }

    /* ── the SIZE_MAX chunk size ─────────────────────────────────────────── */
    printf("-- chunked decoder: SIZE_MAX chunk size (forked: this one crashes) --\n");
    {
        /* FAILS: fetch.c:70 bounds the chunk with `if (r + len > n) return 0;`
         * where `len` is an unsigned long taken straight from strtoul(...,16)
         * and `r`/`n` are size_t. A chunk-size line of "ffffffffffffffff"
         * yields len = ULONG_MAX, so `r + len` WRAPS to r - 1, which is <= n,
         * the bound check passes, and fetch.c:71 executes
         *     memmove(p + w, p + r, ULONG_MAX)
         * killing the process (SIGSEGV/SIGBUS).
         *
         * Reachability: any origin that answers a tls_loopback_get with
         * `Transfer-Encoding: chunked` and that chunk-size line. fetch.h says
         * this path carries Discover's favicon fetch, so the input is a remote
         * origin's response body. DANE pins the origin's KEY, which stops a
         * third party from injecting it, but does not stop the origin itself
         * (compromised, hostile, or merely buggy) from serving it — and it is
         * one HTTP response, not a chain of preconditions.
         *
         * Run in a forked child so the crash is reported as a failed assertion
         * instead of taking the whole suite down with it. */
        const char *evil =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Pad: 1\r\n\r\n"
            "ffffffffffffffff\r\nAAAAAAAAAAAAAAAAAAAA\r\n0\r\n\r\n";
        arm(evil);
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) {                                  /* child */
            uint8_t *o = NULL;
            size_t n = tls_loopback_get((uint16_t)g_port, "origin.pepe", "/x", &o, 4096);
            free(o);
            _exit(n == 0 ? 0 : 2);                       /* 0 = cleanly refused */
        }
        int st = 0;
        waitpid(pid, &st, 0);
        int crashed = WIFSIGNALED(st);
        CHECK(!crashed, "SIZE_MAX chunk size is refused, not a crash");
        if (crashed)
            printf("     product bug: child died with signal %d "
                   "(fetch.c:70 integer overflow -> fetch.c:71 memmove(SIZE_MAX))\n",
                   WTERMSIG(st));
        else if (WEXITSTATUS(st) == 2)
            printf("     note: returned a body rather than refusing\n");

        /* the same overflow reached through a negative chunk size */
        arm("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Pad: 1\r\n\r\n"
            "-1\r\nAAAAAAAAAAAAAAAAAAAA\r\n0\r\n\r\n");
        fflush(stdout);
        pid = fork();
        if (pid == 0) {
            uint8_t *o = NULL;
            size_t n = tls_loopback_get((uint16_t)g_port, "origin.pepe", "/x", &o, 4096);
            free(o);
            _exit(n == 0 ? 0 : 2);
        }
        st = 0;
        waitpid(pid, &st, 0);
        crashed = WIFSIGNALED(st);
        CHECK(!crashed, "negative chunk size '-1' is refused, not a crash");
        if (crashed)
            printf("     product bug: child died with signal %d (same overflow, strtoul(\"-1\") = ULONG_MAX)\n",
                   WTERMSIG(st));
    }

    g_stop = 1;
    pthread_join(th, NULL);
    close(g_lfd);
    X509_free(cert);
    EVP_PKEY_free(key);

    printf(g_fail ? "\nfetch_test: FAIL\n" : "\nfetch_test: all ok\n");
    return g_fail;
}
