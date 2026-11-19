/* proxy_test.c — the end-to-end proof for slice 3 (DESIGN.md §7 slice 3).
 *
 * Wires the whole path with no CA and no real network:
 *   - a name-constrained root (temp HOME),
 *   - a self-signed loopback ORIGIN serving "HELLO FROM ORIGIN" over TLS, with a
 *     known DANE 3 1 1 association,
 *   - the proxy, with a stub resolver mapping SNIs to that origin + a TLSA,
 *   - a BROWSER that trusts only the root (in-memory) and demands a verified
 *     chain + hostname match (green-lock semantics).
 *
 * Asserts:
 *   1. GOOD  name (correct TLSA)  → browser TLS verifies AND gets origin bytes,
 *      and the presented leaf's CN == the SNI (per-SNI mint off the root).
 *   2. BAD   name (wrong TLSA)    → browser TLS STILL verifies (leaf trusted),
 *      but gets the fail-closed page — never the origin bytes.
 *   3. UNKNOWN name (no route)    → verifies, gets the local 404, no origin dial.
 */
#include "proxy.h"
#include "dane.h"
#include "ca.h"

#include <openssl/ssl.h>
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
#include <errno.h>
#include <time.h>
#include <stdint.h>

static int pass = 0, fail = 0;
static void ok(const char *m)  { pass++; printf("  ok   %s\n", m); }
static void bad(const char *m) { fail++; printf("FAIL   %s\n", m); }

static const char *ORIGIN_BODY = "HELLO FROM ORIGIN";

/* Why the last browser read stopped — used only to explain the fail-closed
 * 404 case below when it trips. */
static int g_last_ssl_err, g_last_errno;

/* ── shared helpers ──────────────────────────────────────────────────────── */

static void nosigpipe(int fd) {
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
}

static int tcp_connect(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    nosigpipe(fd);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) { close(fd); return -1; }
    return fd;
}

static int self_signed(const char *name, X509 **cert_out, EVP_PKEY **key_out) {
    EVP_PKEY *k = EVP_EC_gen("P-256");
    if (!k) return 0;
    X509 *x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, k);
    X509_NAME *nm = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)name, -1, -1, 0);
    X509_set_issuer_name(x, nm);
    X509V3_CTX ctx;
    X509V3_set_ctx(&ctx, x, x, NULL, NULL, 0);
    X509V3_set_ctx_nodb(&ctx);
    char san[300];
    snprintf(san, sizeof san, "DNS:%s", name);
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_alt_name, san);
    if (ex) { X509_add_ext(x, ex, -1); X509_EXTENSION_free(ex); }
    if (!X509_sign(x, k, EVP_sha256())) { X509_free(x); EVP_PKEY_free(k); return 0; }
    *cert_out = x; *key_out = k;
    return 1;
}

/* ── the origin (self-signed TLS server speaking a tiny HTTP) ─────────────── */

struct origin { int fd; X509 *cert; EVP_PKEY *key; };

static void *origin_thread(void *arg) {
    struct origin *s = arg;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate(ctx, s->cert);
    SSL_CTX_use_PrivateKey(ctx, s->key);
    for (;;) {
        int c = accept(s->fd, NULL, NULL);
        if (c < 0) break;
        nosigpipe(c);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, c);
        if (SSL_accept(ssl) == 1) {
            char buf[1024];
            SSL_read(ssl, buf, sizeof buf);          /* consume request */
            char resp[256];
            int rl = snprintf(resp, sizeof resp,
                "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n"
                "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                strlen(ORIGIN_BODY), ORIGIN_BODY);
            SSL_write(ssl, resp, rl);
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(c);
    }
    SSL_CTX_free(ctx);
    return NULL;
}

/* ── the stub resolver ───────────────────────────────────────────────────── */

struct route { char origin_ip[16]; int origin_port; uint8_t good[32], bad[32]; };

static int resolve(const char *sni, OriginInfo *out, void *ud) {
    struct route *rt = ud;
    memset(out, 0, sizeof *out);
    snprintf(out->host, sizeof out->host, "%s", rt->origin_ip);
    out->port = rt->origin_port;
    out->usage = 3; out->selector = 1; out->mtype = 1;
    out->assoc_len = 32;
    if (!strcmp(sni, "www.pepenet.doge")) { memcpy(out->assoc, rt->good, 32); return 1; }
    if (!strcmp(sni, "bad.pepenet.doge"))  { memcpy(out->assoc, rt->bad,  32); return 1; }
    if (!strcmp(sni, "down.pepenet.doge")) { memcpy(out->assoc, rt->good, 32); out->port = 1; return 1; }
    return 0;   /* unknown name → not served */
}

/* ── the browser ─────────────────────────────────────────────────────────── */

/* Connect to the proxy with SNI, trusting ONLY `root`, demanding a verified
 * chain + hostname match. Returns 1 if TLS verified; fills body + leaf CN. */
static int browser_get(const char *ip, int port, const char *sni, X509 *root,
                       char *body, size_t bodycap, char *leaf_cn, size_t cncap) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), root);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);        /* green-lock: trust required */

    SSL *ssl = SSL_new(ctx);
    SSL_set_tlsext_host_name(ssl, sni);
    SSL_set1_host(ssl, sni);                               /* SAN must match the name too */

    int fd = tcp_connect(ip, port);
    SSL_set_fd(ssl, fd);
    int verified = SSL_connect(ssl) == 1 && SSL_get_verify_result(ssl) == X509_V_OK;

    if (leaf_cn && cncap) {
        leaf_cn[0] = 0;
        X509 *lf = SSL_get1_peer_certificate(ssl);
        if (lf) {
            X509_NAME_get_text_by_NID(X509_get_subject_name(lf), NID_commonName,
                                      leaf_cn, (int)cncap);
            X509_free(lf);
        }
    }
    if (body && bodycap) {
        body[0] = 0;
        if (verified) {
            const char *req = "GET / HTTP/1.0\r\nHost: x\r\n\r\n";
            SSL_write(ssl, req, (int)strlen(req));
            size_t total = 0;
            int n;
            for (;;) {
                if (total >= bodycap - 1) break;
                errno = 0;
                n = SSL_read(ssl, body + total, (int)(bodycap - 1 - total));
                if (n > 0) { total += (size_t)n; continue; }
                int e = SSL_get_error(ssl, n);
                /* a signal mid-read is not the end of the body */
                if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) continue;
                if (e == SSL_ERROR_SYSCALL && errno == EINTR) continue;
                g_last_ssl_err = e;              /* kept for the diagnostic below */
                g_last_errno   = errno;
                break;
            }
            body[total] = 0;
        }
    }
    SSL_shutdown(ssl);
    close(fd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return verified;
}

/* ── the test ────────────────────────────────────────────────────────────── */

/* Run the proxy accept loop in a thread (proxy_serve blocks). */
struct serve_args { int lfd; X509 *root; EVP_PKEY *rootkey; struct route *rt; };

static void *serve_tramp(void *a) {
    struct serve_args *s = a;
    proxy_serve(s->lfd, s->root, s->rootkey, resolve, s->rt);
    return NULL;
}

/* — proxy_serve_ctl case plumbing — */
static struct { int mints, verdicts, last_ok; } g_evs;
static void ev_mint(void *u, const char *sni) { (void)u; (void)sni; g_evs.mints++; }
static void ev_verd(void *u, const char *sni, int dane_ok, const char *origin) {
    (void)u; (void)sni; (void)origin; g_evs.verdicts++; g_evs.last_ok = dane_ok;
}
static volatile int g_stopf;
struct ctl_args { int lfd; X509 *root; EVP_PKEY *rk; struct route *rt; const ProxyEvents *ev; };
static void *ctl_tramp(void *a) {
    struct ctl_args *c = a;
    proxy_serve_ctl(c->lfd, c->root, c->rk, resolve, c->rt, c->ev, &g_stopf);
    return NULL;
}

/* Fail-closed pages report fold vs peer tip through ev.sync. The daemon
 * (cmd_serve) and the desktop/pepenet-web embed both wire this; the page
 * HTML lives in proxy.c so get.sh and the GUI show the same strip. */
static int64_t g_sync_h, g_sync_ph;
static void ev_sync(void *u, int64_t *h, int64_t *ph) {
    (void)u;
    if (h)  *h  = g_sync_h;
    if (ph) *ph = g_sync_ph;
}

static void dump_page(const char *path, const char *body) {
    const char *html = strstr(body, "<!doctype");
    if (!html) html = strstr(body, "<!DOCTYPE");
    if (!html) return;
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return; }
    fputs(html, f);
    fclose(f);
    printf("  dumped %s\n", path);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    printf("── proxy: browser → mint+DANE → splice (end to end) ──\n");

    /* Hermetic HOME → temp root, never the real ~/.pepenet. */
    char tmpl[] = "/tmp/pepenet-tls-proxytest.XXXXXX";
    char *home = mkdtemp(tmpl);
    if (!home) { perror("mkdtemp"); return 1; }
    setenv("HOME", home, 1);

    X509 *root; EVP_PKEY *rootkey;
    if (!ca_root_ensure(&root, &rootkey)) { fprintf(stderr, "root\n"); return 1; }

    /* Origin: self-signed cert for the served name + its DANE 3 1 1 association. */
    X509 *ocert; EVP_PKEY *okey;
    if (!self_signed("www.pepenet.doge", &ocert, &okey)) { fprintf(stderr, "origin cert\n"); return 1; }
    struct route rt;
    memset(&rt, 0, sizeof rt);
    dane_spki_sha256(ocert, rt.good);
    memcpy(rt.bad, rt.good, 32);
    rt.bad[0] ^= 0xFF;                                       /* wrong TLSA */
    snprintf(rt.origin_ip, sizeof rt.origin_ip, "127.0.0.1");

    int ofd = proxy_listen("127.0.0.1", 0);                 /* reuse the bind helper */
    struct sockaddr_in sa; socklen_t sl = sizeof sa;
    getsockname(ofd, (struct sockaddr *)&sa, &sl);
    rt.origin_port = ntohs(sa.sin_port);
    struct origin osrv = { ofd, ocert, okey };
    pthread_t oth; pthread_create(&oth, NULL, origin_thread, &osrv);

    /* Proxy on its own loopback port. */
    int pfd = proxy_listen("127.0.0.1", 0);
    getsockname(pfd, (struct sockaddr *)&sa, &sl);
    int pport = ntohs(sa.sin_port);
    struct serve_args *psa = malloc(sizeof *psa);
    *psa = (struct serve_args){ pfd, root, rootkey, &rt };
    pthread_t pth; pthread_create(&pth, NULL, serve_tramp, psa);

    /* The diagnostic page is ~5 KB (inline CSS + logo + the diagnostics block),
     * and the rows this file asserts on sit near its end. At 4096 the read
     * stopped mid-page and the assertions failed on text that was present but
     * unread — a truncated buffer masquerading as a product regression. */
    char body[16384], cn[128];

    /* 1. GOOD — correct TLSA → verified chain + origin bytes. */
    int v1 = browser_get("127.0.0.1", pport, "www.pepenet.doge", root, body, sizeof body, cn, sizeof cn);
    if (v1 && strstr(body, ORIGIN_BODY)) ok("good name: green lock + origin content spliced through");
    else { bad("good name should verify and splice origin bytes");
           printf("       verified=%d cn=%s body=%.80s\n", v1, cn, body); }
    if (!strcmp(cn, "www.pepenet.doge")) ok("leaf minted per-SNI (CN == requested name)");
    else { bad("leaf CN should equal the SNI"); printf("       cn=%s\n", cn); }

    /* 2. BAD — wrong TLSA → still trusted leaf, but fail-closed page, no origin.
     * 502 on the status line + the DANE verdict named in the diagnostics. */
    int v2 = browser_get("127.0.0.1", pport, "bad.pepenet.doge", root, body, sizeof body, cn, sizeof cn);
    if (v2 && strstr(body, "HTTP/1.0 502") && strstr(body, "DANE") && !strstr(body, ORIGIN_BODY))
        ok("bad TLSA: fail-closed page served, origin bytes withheld");
    else { bad("bad TLSA should fail closed without leaking origin");
           printf("       verified=%d body=%.80s\n", v2, body); }

    /* 3. UNKNOWN — no route → local 404, no origin dial.
     * Asserted on the STATUS LINE, not on page copy: the fail-closed contract
     * is "404 and not one origin byte", and the diagnostic page's wording is
     * expected to keep changing. Greping its prose made this test fail on a
     * pure copy edit, which told us nothing about the behaviour. */
    int v3 = browser_get("127.0.0.1", pport, "nope.pepenet.doge", root, body, sizeof body, cn, sizeof cn);
    if (v3 && strstr(body, "HTTP/1.0 404") && !strstr(body, ORIGIN_BODY))
        ok("unknown name: verified leaf + local 404, no origin bytes");
    else { bad("unknown name should serve a local 404");
           printf("       verified=%d body=%.80s\n", v3, body);
           printf("       ssl_err=%d errno=%d (%s)\n",
                  g_last_ssl_err, g_last_errno, strerror(g_last_errno));
           if (g_last_errno == ECONNRESET)
               printf("       ^ PRODUCT BUG, not a flaky test: proxy.c:126 writes the 404,\n"
                      "         then proxy.c:144 close()s the socket with this request still\n"
                      "         UNREAD in its receive queue. BSD/macOS turns close()-with-unread-\n"
                      "         data into a TCP RST, and the RST makes the client kernel discard\n"
                      "         its whole receive buffer -- including the 404 already delivered.\n"
                      "         No client-side read loop can recover it. See proxy_jitter_test.c\n"
                      "         (\"fail-closed 404 path\") for the measured rate.\n"); }

    /* 4. CTL — a second proxy through proxy_serve_ctl: events fire on mint +
     * verdict, and flipping the stop flag ends the accept loop (join returns). */
    printf("── proxy_serve_ctl: events + stop flag ──\n");
    {
        int cfd2 = proxy_listen("127.0.0.1", 0);
        getsockname(cfd2, (struct sockaddr *)&sa, &sl);
        int cport = ntohs(sa.sin_port);
        ProxyEvents ev = { .minted = ev_mint, .verdict = ev_verd };
        struct ctl_args ca2 = { cfd2, root, rootkey, &rt, &ev };
        pthread_t cth; pthread_create(&cth, NULL, ctl_tramp, &ca2);

        (void)browser_get("127.0.0.1", cport, "www.pepenet.doge", root, body, sizeof body, cn, sizeof cn);
        (void)browser_get("127.0.0.1", cport, "nope.pepenet.doge", root, body, sizeof body, cn, sizeof cn);
        for (int w = 0; w < 100 && (g_evs.mints < 2 || g_evs.verdicts < 2); w++)
            usleep(20 * 1000);                    /* let the conn threads finish */
        if (g_evs.mints >= 2) ok("ctl: minted event fired per SNI");
        else { bad("ctl: minted events missing"); printf("       mints=%d\n", g_evs.mints); }
        if (g_evs.verdicts >= 2 && !g_evs.last_ok)
            ok("ctl: verdict events fired (last = unknown name, dane_ok=0)");
        else { bad("ctl: verdict events wrong"); printf("       verdicts=%d last_ok=%d\n", g_evs.verdicts, g_evs.last_ok); }

        g_stopf = 1;
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        pthread_join(cth, NULL);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double ms = (double)(t1.tv_sec - t0.tv_sec) * 1000.0 + (double)(t1.tv_nsec - t0.tv_nsec) / 1e6;
        if (ms < 1500) ok("ctl: stop flag ends the accept loop (join < 1.5 s)");
        else { bad("ctl: stop flag did not end the loop promptly"); printf("       join=%.0fms\n", ms); }
        close(cfd2);
    }

    /* 4b. SYNC STRIP — fail-closed HTML in proxy.c, fed by ev.sync. The page
     * is the same for pepenet-tls serve, get.sh, pepenet-web, and desktop. */
    printf("── fail-closed page: chain sync strip ──\n");
    {
        int sfd = proxy_listen("127.0.0.1", 0);
        getsockname(sfd, (struct sockaddr *)&sa, &sl);
        int sport = ntohs(sa.sin_port);
        ProxyEvents ev = { .sync = ev_sync };
        g_stopf = 0;
        struct ctl_args ca = { sfd, root, rootkey, &rt, &ev };
        pthread_t th; pthread_create(&th, NULL, ctl_tramp, &ca);

        g_sync_h = 0; g_sync_ph = 0;
        (void)browser_get("127.0.0.1", sport, "nope.pepenet.doge", root, body, sizeof body, cn, sizeof cn);
        if (strstr(body, "HTTP/1.0 404") && strstr(body, "NOT SYNCED")
            && strstr(body, "this node has not downloaded the chain yet"))
            ok("404 at height 0: NOT SYNCED");
        else { bad("404 at height 0 should say NOT SYNCED");
               printf("       body=%.120s\n", body); }

        g_sync_h = 1234567; g_sync_ph = 2000000;
        (void)browser_get("127.0.0.1", sport, "nope.pepenet.doge", root, body, sizeof body, cn, sizeof cn);
        if (strstr(body, "CATCHING UP") && strstr(body, "1,234,567")
            && strstr(body, "2,000,000")
            && strstr(body, "will not resolve here until catch-up finishes"))
            ok("404 while behind: CATCHING UP + heights + copy");
        else { bad("404 while behind should say CATCHING UP with both heights");
               printf("       body=%.160s\n", strstr(body, "CATCHING UP") ? strstr(body, "CATCHING UP") : body); }
        const char *dump = getenv("PEPENET_DUMP_ERROR_PAGES");
        if (dump && *dump) dump_page("design/error-pages/404-no-such-name.html", body);

        g_sync_h = 2000000; g_sync_ph = 2000000;
        (void)browser_get("127.0.0.1", sport, "nope.pepenet.doge", root, body, sizeof body, cn, sizeof cn);
        if (strstr(body, "AT TIP") && strstr(body, "block <b>2,000,000</b>")
            && !strstr(body, "will not resolve here until catch-up finishes"))
            ok("404 at tip: AT TIP, no catch-up copy");
        else { bad("404 at tip should say AT TIP without the behind note");
               printf("       body=%.160s\n", strstr(body, "AT TIP") ? strstr(body, "AT TIP") : body); }

        g_sync_h = 1234567; g_sync_ph = 0;
        (void)browser_get("127.0.0.1", sport, "nope.pepenet.doge", root, body, sizeof body, cn, sizeof cn);
        if (strstr(body, ">CHAIN<") && strstr(body, "1,234,567") && !strstr(body, "CATCHING UP"))
            ok("404 with unknown peer tip: CHAIN");
        else { bad("404 with unknown peer should say CHAIN");
               printf("       body=%.160s\n", strstr(body, "CHAIN") ? strstr(body, "CHAIN") : body); }

        g_sync_h = 1234567; g_sync_ph = 2000000;
        (void)browser_get("127.0.0.1", sport, "bad.pepenet.doge", root, body, sizeof body, cn, sizeof cn);
        if (strstr(body, "HTTP/1.0 502") && strstr(body, "CATCHING UP")
            && !strstr(body, "will not resolve here until catch-up finishes"))
            ok("502 while behind: CATCHING UP, no 404-only copy");
        else { bad("502 while behind should show the strip without 404 copy");
               printf("       body=%.160s\n", strstr(body, "CATCHING UP") ? strstr(body, "CATCHING UP") : body); }
        if (dump && *dump) dump_page("design/error-pages/502-key-mismatch.html", body);

        g_sync_h = 1234567; g_sync_ph = 2000000;
        (void)browser_get("127.0.0.1", sport, "down.pepenet.doge", root, body, sizeof body, cn, sizeof cn);
        if (strstr(body, "HTTP/1.0 504") && strstr(body, "CATCHING UP")
            && !strstr(body, ORIGIN_BODY))
            ok("504 while behind: CATCHING UP, origin bytes withheld");
        else { bad("504 while behind should fail closed with the strip");
               printf("       body=%.160s\n", body); }
        if (dump && *dump) dump_page("design/error-pages/504-origin-unreachable.html", body);

        g_stopf = 1;
        pthread_join(th, NULL);
        close(sfd);
    }

    /* 5. ABORT STORM — connections that reset while queued must not kill the
     * accept loop. SO_LINGER{1,0} close() sends an RST; an RST that lands
     * before accept() surfaces as ECONNABORTED, which the loop used to treat
     * as fatal: the listener stayed bound (the port LOOKS alive) while every
     * later dial died in its backlog — the desktop front door then answered
     * every CONNECT with 502 until an app restart. Whether the kernel
     * actually surfaces ECONNABORTED is timing/OS-dependent, so this is a
     * probabilistic net, not a proof — but under the old code one surfaced
     * abort here fails the follow-up fetch. */
    printf("── abort storm: acceptor survives resets ──\n");
    {
        for (int i = 0; i < 50; i++) {
            int afd = socket(AF_INET, SOCK_STREAM, 0);
            if (afd < 0) continue;
            struct sockaddr_in aa; memset(&aa, 0, sizeof aa);
            aa.sin_family = AF_INET;
            aa.sin_port = htons((uint16_t)pport);
            inet_pton(AF_INET, "127.0.0.1", &aa.sin_addr);
            if (connect(afd, (struct sockaddr *)&aa, sizeof aa) == 0) {
                struct linger lg = { 1, 0 };          /* close() → RST */
                setsockopt(afd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
            }
            close(afd);
        }
        int v5 = browser_get("127.0.0.1", pport, "www.pepenet.doge", root, body, sizeof body, cn, sizeof cn);
        if (v5 && strstr(body, ORIGIN_BODY)) ok("acceptor alive after 50 aborted connections");
        else bad("abort storm killed the accept loop (dead listener, 502-forever)");
    }

    printf("\n%d ok, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}
