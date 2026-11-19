/* proxy.c — see proxy.h. */
#include "proxy.h"
#include "ca.h"
#include "dane.h"

#include <openssl/ssl.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <time.h>

#define SPLICE_IDLE_S 120           /* drop a quiet tunnel; holds a jetsam slot */

typedef struct {
    X509           *root;
    EVP_PKEY       *rootkey;
    SSL_CTX        *server_ctx;   /* browser side; mints per-SNI leaves */
    SSL_CTX        *client_ctx;   /* origin side; DANE-enabled          */
    proxy_resolver  resolve;
    void           *ud;
    const ProxyEvents *ev;        /* may be NULL (CLI) */
    volatile int   *stop;         /* host stop flag; splice polls it    */
} Proxy;

static void nosigpipe(int fd) {
#ifdef SO_NOSIGPIPE
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
}

/* SNI callback: mint a leaf for the requested name and install it on this
 * handshake. This is where the browser-facing cert comes from — one per SNI,
 * signed by the name-constrained root. */
static int sni_cb(SSL *ssl, int *al, void *arg) {
    Proxy *px = arg;
    const char *sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!sni) return SSL_TLSEXT_ERR_NOACK;

    X509 *leaf; EVP_PKEY *lk;
    if (!ca_leaf_mint(px->root, px->rootkey, sni, &leaf, &lk)) {
        *al = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    int ok = SSL_use_certificate(ssl, leaf) == 1 && SSL_use_PrivateKey(ssl, lk) == 1;
    X509_free(leaf);            /* SSL_use_* took their own references */
    EVP_PKEY_free(lk);
    if (!ok) { *al = SSL_AD_INTERNAL_ERROR; return SSL_TLSEXT_ERR_ALERT_FATAL; }
    if (px->ev && px->ev->minted) px->ev->minted(px->ev->u, sni);
    return SSL_TLSEXT_ERR_OK;
}

/* The desktop build passes -DPEPENET_VERSION from CMake (CMakeLists.txt:38 —
 * the one source of truth). A standalone pepenet-tls build has no version of
 * its own, so it says "dev" rather than carrying a hardcoded copy that would
 * silently drift the next time the app's version is bumped. */
#ifndef PEPENET_VERSION
#define PEPENET_VERSION "dev"
#endif

/* ── the fail-closed diagnostic page ─────────────────────────────────────────
 *
 * Everything this page interpolates is attacker-influenced: the SNI arrives on
 * the wire, and the origin address + TLSA come from records the name's owner
 * publishes. Escaping is therefore load-bearing rather than hygiene. The page
 * is served ON the site's own origin, over a TLS session the browser trusts,
 * and it is served EXACTLY when DANE refused the origin — so interpolating raw
 * would hand a server we just declined to authenticate a scripting context on
 * the very name it failed to prove it owns. esc() is applied to every field. */
static void esc(char *dst, size_t cap, const char *src) {
    if (!cap) return;
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)(src ? src : ""); *p; p++) {
        char one[2] = { 0, 0 };
        const char *rep;
        switch (*p) {
            case '&':  rep = "&amp;";  break;
            case '<':  rep = "&lt;";   break;
            case '>':  rep = "&gt;";   break;
            case '"':  rep = "&quot;"; break;
            case '\'': rep = "&#39;";  break;
            default:
                /* control bytes become spaces; anything else (incl. UTF-8
                 * continuation bytes) passes through unchanged */
                one[0] = (*p < 0x20 || *p == 0x7f) ? ' ' : (char)*p;
                rep = one;
        }
        size_t rl = strlen(rep);
        if (o + rl >= cap) break;
        memcpy(dst + o, rep, rl);
        o += rl;
    }
    dst[o] = '\0';
}

static void hexs(char *dst, size_t cap, const uint8_t *b, size_t n) {
    static const char H[] = "0123456789abcdef";
    size_t o = 0;
    for (size_t i = 0; i < n && o + 3 <= cap; i++) {
        dst[o++] = H[b[i] >> 4];
        dst[o++] = H[b[i] & 15];
    }
    dst[o < cap ? o : cap - 1] = '\0';
}

/* What the page can tell the user about this failure. origin_host NULL means
 * the name never resolved, so there is no endpoint or pin to show. */
typedef struct {
    const char    *sni;
    const char    *origin_host;
    int            origin_port;
    int            have_tlsa;
    uint8_t        usage, selector, mtype;
    const uint8_t *assoc;
    size_t         assoc_len;
    const char    *detail;          /* dane_connect's diagnostic string */
    int64_t        height;          /* this node's fold height (0 = none) */
    int64_t        peer_height;     /* last peer tip (0 = unknown) */
} ErrDiag;

static void fmt_h(char *dst, size_t cap, int64_t n) {
    char tmp[32];
    int len = snprintf(tmp, sizeof tmp, "%lld", (long long)(n < 0 ? 0 : n));
    if (len <= 0 || cap < 2) { if (cap) dst[0] = 0; return; }
    int commas = (len - 1) / 3;
    if ((size_t)len + (size_t)commas >= cap) { snprintf(dst, cap, "%s", tmp); return; }
    int o = len + commas;
    dst[o] = 0;
    for (int t = len, g = 0; t--; ) {
        dst[--o] = tmp[t];
        if (t && ++g == 3) { dst[--o] = ','; g = 0; }
    }
}

/* The PepeNet mark: the Pepecoin "P with a stroke", tilted and edged in the
 * badge green, over a white globe. Inline SVG rather than
 * design/pepenetlogo.png — that source is 1024x1024 / 775 KB and would base64
 * to roughly a megabyte on every error page; this is ~1.3 KB.
 *
 * design/logo.svg is the source of truth; keep the two in step.
 *
 * Load-bearing and easy to break:
 *   • EVERY attribute value is single-quoted. Unquoted values (fill=none) make
 *     Chrome's HTML parser silently drop the entire enclosing <g> — that is
 *     how the globe vanished the first time. Double quotes would need C
 *     escaping, hence single throughout.
 *   • pnWp/pnGu carry gradientTransform='rotate(-9.8 ...)' to cancel the glyph
 *     group's rotation. Without it both ramps tilt with the letter, and the
 *     green edge stops matching the badge behind it — which is the whole point
 *     of the edge.
 *   • paint-order='stroke' draws the edge before the fill, so the fill covers
 *     its inner half and the glyph keeps its weight; a centred stroke would
 *     eat into the letterform instead.
 *
 * Colours sampled from the raster: badge #6cb274/#429856/#368b4c (three stops —
 * the measured midpoint is darker than a linear ramp), white #ffffff→#dcddd9
 * shared by the globe and the P. */
#define PN_LOGO \
 "<svg class='lg' aria-hidden='true' viewBox='0 0 64 64' width='44' height='44'>" \
 "<defs><linearGradient id='pnG' x1='0' y1='0' x2='0' y2='1'>" \
 "<stop offset='0' stop-color='#6cb274'/><stop offset='.5' stop-color='#429856'/>" \
 "<stop offset='1' stop-color='#368b4c'/></linearGradient>" \
 "<linearGradient id='pnW' gradientUnits='userSpaceOnUse' x1='0' y1='0' x2='0' y2='64'>" \
 "<stop offset='0' stop-color='#ffffff'/><stop offset='1' stop-color='#dcddd9'/>" \
 "</linearGradient>" \
 "<linearGradient id='pnWp' href='#pnW' gradientTransform='rotate(-9.8 32 32)'/>" \
 "<linearGradient id='pnGu' href='#pnG' gradientUnits='userSpaceOnUse'" \
 " x1='0' y1='0' x2='0' y2='64' gradientTransform='rotate(-9.8 32 32)'/></defs>" \
 "<circle cx='32' cy='32' r='32' fill='url(#pnG)'/>" \
 "<g fill='none' stroke='url(#pnW)' stroke-width='2.15'>" \
 "<circle cx='32' cy='32' r='27.6'/><ellipse cx='32' cy='32' rx='16' ry='27.6'/>" \
 "<path d='M32 4.4v55.2M4.4 32h55.2M11.2 13.8Q32 25.4 52.8 13.8M11.2 50.2Q32 38.6 52.8 50.2'/>" \
 "</g><g transform='rotate(9.8 32 32)'>" \
 "<path d='" PN_P "' fill='url(#pnWp)' stroke='url(#pnGu)' stroke-width='4'" \
 " stroke-linejoin='miter' stroke-miterlimit='12' paint-order='stroke'/></g></svg>"

/* the glyph outline */
#define PN_P \
 "M21.1 17.1h19.4c4.8 0 7.4 4.8 7.4 10.9s-2.6 10.9-7.4 10.9H28.1v13.35h-7V30.4" \
 "h-3.6v-4.4h3.6zm7 5.8v3.1h6.3v4.4h-6.3v2.5h7.9c3 0 4.3-2.2 4.3-5s-1.3-5-4.3-5z"

/* Serve a local page over the (trusted) browser session. Used fail-closed: we
 * present a leaf the browser trusts, but the body is OUR diagnostic — never
 * origin bytes we could not authenticate. */
static void serve_error(SSL *b, int code, const char *title,
                        const char *human, const ErrDiag *d) {
    static const ErrDiag EMPTY = { 0 };
    if (!d) d = &EMPTY;

    char e_sni[512], e_host[256], e_detail[640], e_title[160], e_human[1024];
    char hex[160], e_hex[160];
    esc(e_sni,    sizeof e_sni,    d->sni && d->sni[0] ? d->sni : "(none sent)");
    esc(e_host,   sizeof e_host,   d->origin_host);
    esc(e_detail, sizeof e_detail, d->detail);
    esc(e_title,  sizeof e_title,  title);
    esc(e_human,  sizeof e_human,  human);
    hexs(hex, sizeof hex, d->assoc, d->assoc_len);
    esc(e_hex, sizeof e_hex, hex);

    size_t cap = 16384;
    char *body = malloc(cap);
    if (!body) return;
    int o = 0;

    o += snprintf(body + o, cap - (size_t)o,
      "<!doctype html><html lang=en><meta charset=utf-8>"
      "<meta name=viewport content='width=device-width,initial-scale=1'>"
      "<title>%d %s</title><style>"
      ":root{--bg:#f7f8f7;--fg:#12160f;--mut:#5c6659;--card:#fff;--line:#e2e6e0;"
      "--accent:#43a75e;--err:#c0342b;--code:#f0f2ef}"
      "@media(prefers-color-scheme:dark){:root{--bg:#0f1210;--fg:#e8ece6;"
      "--mut:#98a394;--card:#171b18;--line:#252b26;--err:#ff7b6b;--code:#1e231f}}"
      "*{box-sizing:border-box}"
      "body{margin:0;min-height:100vh;display:flex;align-items:center;"
      "justify-content:center;padding:24px;background:var(--bg);color:var(--fg);"
      "font:15px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}"
      ".card{width:100%%;max-width:40rem;background:var(--card);border:1px solid var(--line);"
      "border-radius:14px;padding:30px 32px}"
      ".hd{display:flex;align-items:center;gap:12px;padding-bottom:18px;"
      "border-bottom:1px solid var(--line);margin-bottom:22px}"
      ".lg{flex:none;display:block}"
      ".bn{font-weight:700;letter-spacing:-.01em}"
      ".bs{color:var(--mut);font-size:12px}"
      /* red, not green: this pill is the first thing read, and a green badge
         reads as "all clear" on a page whose entire purpose is refusal */
      ".code{display:inline-block;font-size:12px;font-weight:700;letter-spacing:.08em;"
      "color:var(--err);border:1px solid var(--err);border-radius:999px;"
      "padding:2px 10px;margin-bottom:10px}"
      "h1{margin:0 0 12px;font-size:22px;line-height:1.25;letter-spacing:-.02em}"
      "p{margin:0 0 14px;color:var(--mut)}"
      ".sync{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0 0 16px;"
      "padding:10px 12px;border:1px solid var(--line);border-radius:10px;"
      "background:var(--code);font-size:13px}"
      ".sync.behind{border-color:var(--err)}"
      ".sync .pill{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.08em;"
      "border:1px solid var(--accent);color:var(--accent);border-radius:999px;"
      "padding:2px 9px;flex:none}"
      ".sync.behind .pill{color:var(--err);border-color:var(--err)}"
      ".sync .nums{color:var(--mut)}"
      ".sync b{color:var(--fg);font-weight:600}"
      ".syncnote{margin:0 0 14px;font-size:13.5px}"
      /* sits between the code pill and the headline, so it stays tight to the
         pill and carries no rule of its own — the details block below supplies
         the only horizontal divider in this region */
      ".req{margin:0 0 8px}"
      ".exp{margin:14px 0 2px}"
      ".nm{color:var(--fg);font-weight:600;word-break:break-all}"
      "details{margin-top:20px;border-top:1px solid var(--line);padding-top:16px}"
      "summary{cursor:pointer;font-size:13px;font-weight:600;color:var(--mut);"
      "list-style:none;user-select:none;display:flex;align-items:center;gap:8px}"
      "summary:hover{color:var(--fg)}"
      "summary::-webkit-details-marker{display:none}"
      "summary::before{content:'';flex:none;width:0;height:0;"
      "border-left:5px solid var(--accent);border-top:4px solid transparent;"
      "border-bottom:4px solid transparent;transition:transform .12s}"
      "details[open] summary::before{transform:rotate(90deg)}"
      "dl{margin:16px 0 0;font-size:13px}"
      "dt{color:var(--mut);font-size:11px;text-transform:uppercase;"
      "letter-spacing:.06em;margin-top:14px}"
      "dt:first-child{margin-top:0}"
      "dd{margin:3px 0 0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;"
      "font-size:12.5px;word-break:break-all;background:var(--code);"
      "border-radius:6px;padding:6px 9px}"
      ".ft{margin-top:22px;padding-top:14px;border-top:1px solid var(--line);"
      "font-size:11.5px;color:var(--mut)}"
      "</style><body><main class=card>"
      "<div class=hd>" PN_LOGO
      "<div><div class=bn>PepeNet</div>"
      "<div class=bs>powered by Pepecoin</div></div></div>"
      /* order: error code -> requested name -> diagnostics -> description.
         The name belongs beside the code (it identifies WHAT failed); the
         prose explanation is the least urgent thing on the page, so it sits
         below the diagnostics rather than pushing them under the fold. */
      "<div class=code>ERROR %d</div>"
      "<p class=req>Requested name <span class=nm>%s</span></p>"
      "<h1>%s</h1>",
      code, e_title, code, e_sni, e_title);

    /* Chain sync — visible, not buried in Diagnostics. A name 404 while this
     * node is still catching up is usually "not in our fold yet", not "does
     * not exist". */
    {
        char ours[40], net[40];
        fmt_h(ours, sizeof ours, d->height);
        fmt_h(net, sizeof net, d->peer_height);
        int behind = (d->height == 0) ||
                     (d->peer_height > 0 && d->height < d->peer_height);
        if (d->height == 0)
            o += snprintf(body + o, cap - (size_t)o,
              "<div class='sync behind'><span class=pill>NOT SYNCED</span>"
              "<span class=nums>this node has not downloaded the chain yet</span></div>");
        else if (d->peer_height > 0 && d->height < d->peer_height)
            o += snprintf(body + o, cap - (size_t)o,
              "<div class='sync behind'><span class=pill>CATCHING UP</span>"
              "<span class=nums>this node <b>%s</b> · network <b>%s</b></span></div>",
              ours, net);
        else if (d->peer_height > 0)
            o += snprintf(body + o, cap - (size_t)o,
              "<div class='sync'><span class=pill>AT TIP</span>"
              "<span class=nums>block <b>%s</b></span></div>", ours);
        else
            o += snprintf(body + o, cap - (size_t)o,
              "<div class='sync'><span class=pill>CHAIN</span>"
              "<span class=nums>this node <b>%s</b></span></div>", ours);
        if (behind && code == 404)
            o += snprintf(body + o, cap - (size_t)o,
              "<p class=syncnote>Names registered after this node&#39;s current height "
              "will not resolve here until catch-up finishes. If the name is older "
              "than that, it is not published.</p>");
    }

    /* The expandable diagnostics — what we resolved, what we expected, and what
     * the origin actually did. The prose explanation leads the panel: collapsed,
     * the page is just code + title + name, and everything discretionary is one
     * click away. It also puts the description directly above the verdict rows
     * it refers to. */
    o += snprintf(body + o, cap - (size_t)o,
      "<details><summary>Diagnostics</summary>"
      "<p class=exp>%s</p>"
      "<dl><dt>name (SNI)</dt><dd>%s</dd>", e_human, e_sni);

    if (d->origin_host && d->origin_host[0])
        o += snprintf(body + o, cap - (size_t)o,
          "<dt>published origin (A record)</dt><dd>%s:%d</dd>", e_host, d->origin_port);
    else
        o += snprintf(body + o, cap - (size_t)o,
          "<dt>published origin (A record)</dt><dd>none published</dd>");

    if (d->have_tlsa)
        o += snprintf(body + o, cap - (size_t)o,
          "<dt>published TLSA (pinned key)</dt><dd>%u %u %u %s</dd>",
          d->usage, d->selector, d->mtype, e_hex[0] ? e_hex : "(empty)");
    else
        o += snprintf(body + o, cap - (size_t)o,
          "<dt>published TLSA (pinned key)</dt><dd>none published</dd>");

    {
        char ours[40], net[40];
        fmt_h(ours, sizeof ours, d->height);
        fmt_h(net, sizeof net, d->peer_height);
        o += snprintf(body + o, cap - (size_t)o,
          "<dt>this node</dt><dd>block %s</dd>", ours[0] ? ours : "—");
        o += snprintf(body + o, cap - (size_t)o,
          "<dt>network tip</dt><dd>%s</dd>",
          d->peer_height > 0 ? net : "unknown");
    }

    o += snprintf(body + o, cap - (size_t)o,
      "<dt>DANE verdict</dt><dd>%s</dd></dl>"
      "<p style='margin:16px 0 0;font-size:12.5px'>These records are signed by "
      "the name&#39;s owner, not supplied by the server that answered. The proxy "
      "refuses to relay any byte from an origin whose key does not match the "
      "published pin.</p>"
      "</details>"
      "<div class=ft>pepenet-tls " PEPENET_VERSION "</div>"
      "</main>", e_detail[0] ? e_detail : "(no detail)");

    if (o < 0) { free(body); return; }
    if ((size_t)o >= cap) o = (int)cap - 1;    /* snprintf truncated: stay honest */

    char hdr[256];
    int hl = snprintf(hdr, sizeof hdr,
        "HTTP/1.0 %d %s\r\nContent-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %d\r\nCache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        code, title, o);
    SSL_write(b, hdr, hl);
    SSL_write(b, body, o);
    free(body);

    /* Drain whatever the browser already sent before we close.
     *
     * We answer these pages without ever reading the request, so the client's
     * GET is still sitting unread in our receive queue. On BSD/macOS, close()
     * on a socket with unread received data sends a TCP RST rather than a FIN,
     * and an RST makes the peer's kernel discard ITS receive buffer — including
     * the page we just wrote into it. The browser then shows a connection reset
     * instead of the diagnostic, which matters most on the 502 path: that IS
     * the fail-closed explanation of why the site was blocked.
     *
     * Bounded two ways so a silent or hostile peer cannot pin this thread: a
     * short receive timeout (we are closing regardless, so a slow client only
     * costs the timeout) and a cap on how much we are willing to swallow. */
    int fd = SSL_get_fd(b);
    if (fd >= 0) {
        struct timeval tv = { 0, 250000 };            /* 250 ms */
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    }
    char sink[4096];
    for (size_t drained = 0; drained < 64 * 1024; ) {
        int n = SSL_read(b, sink, sizeof sink);
        if (n <= 0) break;                            /* EOF, timeout, or error */
        drained += (size_t)n;
    }
}

/* Move any readable+decryptable data from `from` to `to`. 1 = keep going,
 * 0 = this direction is done (peer closed or hard error).
 *
 * The loop condition must be SSL_has_pending(), not SSL_pending() alone.
 * SSL_pending() reports only the decrypted bytes left in the record OpenSSL has
 * ALREADY processed; it says nothing about further whole records OpenSSL has
 * read off the socket into its own buffer but not yet unwrapped. When a request
 * spans several records — every POST, every upload, and TLS 1.3 routinely —
 * SSL_pending() goes to 0 with data still buffered, splice() returns to
 * select(), and the kernel reports the socket as empty because those bytes are
 * inside OpenSSL rather than the receive queue. The connection then blocks
 * forever, leaking a thread and two fds. SSL_has_pending() covers both cases. */
static int pump(SSL *from, SSL *to) {
    do {
        char buf[16384];
        int n = SSL_read(from, buf, sizeof buf);
        if (n <= 0) {
            int e = SSL_get_error(from, n);
            return (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) ? 1 : 0;
        }
        for (int off = 0; off < n; ) {
            int w = SSL_write(to, buf + off, n - off);
            if (w <= 0) {
                int e = SSL_get_error(to, w);
                if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE) return 0;
                /* Non-blocking: wait for the far side to be ready rather than
                 * spinning on it. */
                struct pollfd wp = { SSL_get_fd(to),
                                     (short)(e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT), 0 };
                if (poll(&wp, 1, 500) <= 0) return 0;
                continue;
            }
            off += w;
        }
    } while (SSL_pending(from) > 0 || SSL_has_pending(from));
    return 1;
}

/* Does this session hold bytes that select() cannot see? SSL_pending() covers
 * plaintext already decrypted; SSL_has_pending() also covers whole records read
 * off the socket but not yet unwrapped. Either way the kernel receive queue is
 * empty, so select() would report "nothing to read" and block on data we are
 * already holding. */
static int buffered(SSL *s) { return SSL_pending(s) > 0 || SSL_has_pending(s); }

/* Bidirectional plaintext relay between the two authenticated TLS sessions.
 *
 * The pre-select drain below is load-bearing, not an optimisation. OpenSSL reads
 * in record-sized gulps, and SSL_accept() itself can pull the client's first
 * application-data records off the socket while completing the handshake — so a
 * request can be sitting INSIDE the SSL object before this loop runs even once.
 * Blocking in select() first would then wait forever on a socket whose bytes we
 * already have: the browser waits for a response, we wait for a request we are
 * holding, and the origin waits for the rest of it. Draining what is buffered
 * before every poll() is what makes the relay safe. */
static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl != -1) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* Bidirectional plaintext relay between the two authenticated TLS sessions. */
static void splice(Proxy *px, SSL *b, SSL *o) {
    int fb = SSL_get_fd(b), fo = SSL_get_fd(o);

    /* Both sides must be non-blocking for the relay to be safe.
     *
     * select() reporting a socket readable does NOT mean application data is
     * available: the bytes may be a TLS record that yields none. TLS 1.3 origins
     * routinely send NewSessionTicket right after the handshake, and a KeyUpdate
     * or renegotiation can do the same at any time. On a BLOCKING socket,
     * SSL_read then consumes that record, finds no application data, and blocks
     * — starving the opposite direction. That is a genuine three-way deadlock:
     * the browser waits for a response, we wait inside SSL_read on the origin,
     * and the origin waits for the rest of a request still sitting unread in our
     * browser socket. It strikes whenever a request spans several records, which
     * is every POST, every upload, and TLS 1.3 as a matter of course.
     * Non-blocking turns that block into WANT_READ, which pump() treats as
     * "nothing more this direction" and returns, so the loop keeps serving both. */
    set_nonblock(fb);
    set_nonblock(fo);
    time_t last = time(NULL);
    for (;;) {
        int moved = 0;
        if (buffered(b)) { if (!pump(b, o)) break; moved = 1; }
        if (buffered(o)) { if (!pump(o, b)) break; moved = 1; }
        if (moved) { last = time(NULL); continue; }

        /* poll(), not select(): FD_SET on a descriptor >= FD_SETSIZE (1024)
         * writes past the 128-byte fd_set on this thread's stack, and select()
         * with nfds > FD_SETSIZE just fails with EINVAL. A busy proxy holds two
         * fds per tunnel, so that is reachable rather than theoretical. */
        struct pollfd pf[2] = { { fb, POLLIN, 0 }, { fo, POLLIN, 0 } };
        if (px && px->stop && *px->stop) break;
        int pr = poll(pf, 2, 500);
        if (pr < 0) break;
        if (px && px->stop && *px->stop) break;
        if (pr == 0) {
            if (time(NULL) - last >= SPLICE_IDLE_S) break;
            continue;
        }
        last = time(NULL);
        if ((pf[0].revents & (POLLIN | POLLHUP | POLLERR)) && !pump(b, o)) break;
        if ((pf[1].revents & (POLLIN | POLLHUP | POLLERR)) && !pump(o, b)) break;
    }
}

static void handle(Proxy *px, int cfd) {
    nosigpipe(cfd);
    SSL *b = SSL_new(px->server_ctx);
    if (!b) { close(cfd); return; }
    SSL_set_fd(b, cfd);

    if (SSL_accept(b) == 1) {                       /* leaf minted in sni_cb */
        const char *sni = SSL_get_servername(b, TLSEXT_NAMETYPE_host_name);
        OriginInfo oi;
        /* Wide enough for the mismatch verdict in full: "verify=<n>: <OpenSSL
         * text> - origin presented spki-sha256 <64 hex>". At 160 the hash was
         * truncated, which silently destroyed the pinned-vs-presented
         * comparison the page exists to show. */
        char err[288];
        int64_t h = 0, ph = 0;
        if (px->ev && px->ev->sync) px->ev->sync(px->ev->u, &h, &ph);
        if (!sni || !px->resolve(sni, &oi, px->ud)) {
            if (px->ev && px->ev->verdict && sni)
                px->ev->verdict(px->ev->u, sni, 0, "");
            ErrDiag d = { sni, NULL, 0, 0, 0, 0, 0, NULL, 0,
                          sni ? "no zone published for this name"
                              : "the client sent no SNI, so no name could be resolved",
                          h, ph };
            serve_error(b, 404, "No such name on the chain",
                "Nothing is published for this name. Either it was never registered, "
                "its lease has lapsed, or its owner has not added any DNS records yet.",
                &d);
        } else {
            SSL *o = NULL; int ofd = -1;
            DaneResult r = dane_connect(px->client_ctx, oi.host, oi.port, sni,
                                        oi.usage, oi.selector, oi.mtype,
                                        oi.assoc, oi.assoc_len, &o, &ofd, err, sizeof err);
            if (px->ev && px->ev->verdict)
                px->ev->verdict(px->ev->u, sni, r == DANE_OK, oi.host);
            if (r == DANE_OK) {
                splice(px, b, o);
                SSL_shutdown(o); close(ofd); SSL_free(o);
            } else {
                /* One code per failure mode. Collapsing all three into a bare
                 * 502 told the user nothing about whether the site was down,
                 * misconfigured, or being impersonated — which are three very
                 * different things to act on. */
                ErrDiag d = { sni, oi.host, oi.port, 1,
                              oi.usage, oi.selector, oi.mtype,
                              oi.assoc, oi.assoc_len, err, h, ph };
                switch (r) {
                case DANE_CONNECT_ERR:
                    serve_error(b, 504, "Origin unreachable",
                        "This name is registered and its records resolved, but nothing "
                        "answered at the published address. The site is probably "
                        "offline, or its A record is out of date. The verdict below "
                        "carries the exact connection error.", &d);
                    break;
                case DANE_MISMATCH:
                    serve_error(b, 502, "Origin key does not match its published pin",
                        "The server answered, but the certificate it presented is not "
                        "the one this name's owner published. Access was refused. This "
                        "is the protection working as intended — either someone is "
                        "impersonating this name, or its operator rotated keys without "
                        "publishing a matching TLSA record. Compare the pinned key with "
                        "the one the origin actually presented in the verdict below; "
                        "its verify code names the precise reason.", &d);
                    break;
                default:
                    serve_error(b, 502, "TLS error talking to the origin",
                        "The origin was reachable, but the TLS connection to it failed "
                        "before its identity could be checked against the published "
                        "pin. The verify code in the verdict below names the reason.", &d);
                    break;
                }
            }
        }
        SSL_shutdown(b);
    }
    SSL_free(b);
    close(cfd);
}

struct conn { Proxy *px; int fd; };

/* Unbounded per-connection pthreads plus a host that closes the Resolver the
 * moment the accept loop exits was a UAF on quit. Cap in-flight conns so a
 * CONNECT storm cannot fork-bomb the process; extras reset, clients retry.
 * 64 is above the jitter suite's default 24-way load and well under what a
 * local DANE proxy ever needs. */
#ifndef PROXY_CONN_MAX
#define PROXY_CONN_MAX 64
#endif
static volatile int g_live;

static void *conn_thread(void *a) {
    struct conn *c = a;
    handle(c->px, c->fd);
    free(c);
    __sync_fetch_and_sub(&g_live, 1);
    return NULL;
}

int proxy_listen(const char *ip, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1 ||
        bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0 ||
        listen(fd, 64) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int proxy_serve_ctl(int lfd, X509 *root, EVP_PKEY *rootkey,
                    proxy_resolver resolve, void *ud,
                    const ProxyEvents *ev, volatile int *stop) {
    Proxy *px = calloc(1, sizeof *px);
    if (!px) return 1;
    px->root = root;
    px->rootkey = rootkey;
    px->resolve = resolve;
    px->ud = ud;
    px->ev = ev;
    px->stop = stop;
    px->client_ctx = dane_client_ctx();
    px->server_ctx = SSL_CTX_new(TLS_server_method());
    if (!px->client_ctx || !px->server_ctx) { free(px); return 1; }
    SSL_CTX_set_min_proto_version(px->server_ctx, TLS1_2_VERSION);
    SSL_CTX_set_tlsext_servername_callback(px->server_ctx, sni_cb);
    SSL_CTX_set_tlsext_servername_arg(px->server_ctx, px);

    for (;;) {
        if (stop) {                        /* poll the flag between accepts */
            struct pollfd pfd = { lfd, POLLIN, 0 };
            if (*stop) break;
            if (poll(&pfd, 1, 500) <= 0) { if (*stop) break; continue; }
        }
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) {
            /* A transient accept failure must not kill the loop. ECONNABORTED
             * is routine (a queued client reset before we accepted — a PAC
             * toggle's browser churn produces bursts of these) and EMFILE/
             * ENFILE are fd-pressure spikes that pass. Exiting here leaves
             * the bound listener open with nobody accepting: the port still
             * looks alive while every dial dies in its backlog (the desktop
             * front door then answers every CONNECT with 502 until the app
             * restarts). Break only when the listener itself is gone. */
            if (errno == EBADF || errno == EINVAL || errno == ENOTSOCK) break;
            if (errno == EMFILE || errno == ENFILE) poll(NULL, 0, 100);
            continue;
        }
        if (__sync_add_and_fetch(&g_live, 1) > PROXY_CONN_MAX) {
            __sync_fetch_and_sub(&g_live, 1);
            close(cfd);
            continue;
        }
        struct conn *c = malloc(sizeof *c);
        if (!c) { __sync_fetch_and_sub(&g_live, 1); close(cfd); continue; }
        c->px = px;
        c->fd = cfd;
        pthread_t t;
        if (pthread_create(&t, NULL, conn_thread, c) != 0) {
            __sync_fetch_and_sub(&g_live, 1);
            free(c); close(cfd); continue;
        }
        pthread_detach(t);
    }
    /* Host closes the Resolver as soon as we return; in-flight handle() still
     * calls px->resolve(px->ud). Drain before returning so that is not a UAF. */
    while (__sync_add_and_fetch(&g_live, 0) > 0)
        poll(NULL, 0, 50);
    return 0;
}

int proxy_serve(int lfd, X509 *root, EVP_PKEY *rootkey,
                proxy_resolver resolve, void *ud) {
    return proxy_serve_ctl(lfd, root, rootkey, resolve, ud, NULL, NULL);
}

int proxy_run(const char *ip, int port, X509 *root, EVP_PKEY *rootkey,
              proxy_resolver resolve, void *ud) {
    int lfd = proxy_listen(ip, port);
    if (lfd < 0) return 1;
    return proxy_serve(lfd, root, rootkey, resolve, ud);
}
