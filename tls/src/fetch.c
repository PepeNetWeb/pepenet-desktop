/* fetch.c — see fetch.h. A deliberately small HTTP/1.1 client: one request,
 * Connection: close, Content-Length or chunked or read-to-EOF bodies. */
#include "fetch.h"

#include <openssl/ssl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* portable memmem (absent on MinGW) */
static uint8_t *find_seq(uint8_t *h, size_t hn, const char *nd, size_t nn) {
    if (nn == 0 || hn < nn) return NULL;
    for (size_t i = 0; i + nn <= hn; i++)
        if (h[i] == (uint8_t)nd[0] && memcmp(h + i, nd, nn) == 0) return h + i;
    return NULL;
}

/* Case-insensitive variant. RFC 9110 makes the transfer-coding token
 * case-insensitive, so a `Transfer-Encoding: CHUNKED` reply is legal and must
 * not silently fall through as an unchunked body. */
static uint8_t *find_ci(uint8_t *h, size_t hn, const char *nd, size_t nn) {
    if (nn == 0 || hn < nn) return NULL;
    for (size_t i = 0; i + nn <= hn; i++)
        if (strncasecmp((const char *)h + i, nd, nn) == 0) return h + i;
    return NULL;
}

static int dial_loop(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval tv = { 5, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
#ifdef SO_NOSIGPIPE
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) { close(fd); return -1; }
    return fd;
}

/* grow-append into a bounded buffer; 0 on overflow/oom */
typedef struct { uint8_t *p; size_t n, alloc, cap; } Buf;
static int buf_add(Buf *b, const uint8_t *d, size_t n) {
    if (b->n + n > b->cap) return 0;
    if (b->n + n > b->alloc) {
        size_t na = b->alloc ? b->alloc : 8192;
        while (na < b->n + n) na *= 2;
        if (na > b->cap) na = b->cap;
        uint8_t *np = realloc(b->p, na);
        if (!np) return 0;
        b->p = np; b->alloc = na;
    }
    memcpy(b->p + b->n, d, n);
    b->n += n;
    return 1;
}

/* de-chunk in place; returns body size or 0 on a malformed stream */
static size_t unchunk(uint8_t *p, size_t n) {
    size_t r = 0, w = 0;
    for (;;) {
        size_t ls = r;
        while (r < n && p[r] != '\n') r++;
        if (r >= n) return 0;
        unsigned long len = strtoul((char *)p + ls, NULL, 16);
        r++;                                    /* past \n */
        if (len == 0) return w;
        /* Compare against what is LEFT; never r + len. The length is an
         * attacker-chosen hex field, so a chunk header of ffffffffffffffff
         * makes r + len wrap to a small value, sail past the check, and reach
         * the memmove below with len == SIZE_MAX. A chunk size of -1 arrives
         * here as ULONG_MAX by the same route. r <= n holds above, so the
         * subtraction is always well defined. */
        if (len > (unsigned long)(n - r)) return 0;
        memmove(p + w, p + r, len);
        w += len; r += len;
        if (r + 1 < n && p[r] == '\r') r += 2;  /* CRLF after each chunk */
        else if (r < n && p[r] == '\n') r += 1;
    }
}

size_t tls_loopback_get(uint16_t port, const char *sni, const char *path,
                        uint8_t **out, size_t cap) {
    if (!sni || !path || !out) return 0;
    *out = NULL;
    int fd = dial_loop(port);
    if (fd < 0) return 0;

    SSL_CTX *cx = SSL_CTX_new(TLS_client_method());
    if (!cx) { close(fd); return 0; }
    /* loopback hop into our own proxy — the upstream is DANE-verified there */
    SSL_CTX_set_verify(cx, SSL_VERIFY_NONE, NULL);
    SSL *s = SSL_new(cx);
    size_t got = 0;
    Buf b = { NULL, 0, 0, cap + 4096 };         /* head + capped body */
    if (!s) goto done;
    SSL_set_fd(s, fd);
    SSL_set_tlsext_host_name(s, sni);
    if (SSL_connect(s) != 1) goto done;

    char req[512];
    int rn = snprintf(req, sizeof req,
                      "GET %s HTTP/1.1\r\nHost: %s\r\n"
                      "User-Agent: pepenet-desktop\r\nAccept: */*\r\n"
                      "Connection: close\r\n\r\n", path, sni);
    if (SSL_write(s, req, rn) != rn) goto done;

    uint8_t chunk[8192];
    int n;
    while ((n = SSL_read(s, chunk, sizeof chunk)) > 0)
        if (!buf_add(&b, chunk, (size_t)n)) goto done;
    if (b.n < 12) goto done;

    /* head: status + headers */
    uint8_t *hend = find_seq(b.p, b.n, "\r\n\r\n", 4);
    if (!hend) goto done;
    size_t hlen = (size_t)(hend - b.p) + 4;
    if (memcmp(b.p, "HTTP/1.", 7) != 0 || b.n < 13) goto done;
    /* The delimiter check matters: without it "HTTP/1.1 2000" passes as 200,
     * because only the first three digits are compared. */
    if (strncmp((char *)b.p + 9, "200", 3) != 0 ||
        (b.p[12] != ' ' && b.p[12] != '\r')) goto done;

    /* Scan up to and INCLUDING the final header's own CRLF. `hend` points at
     * the start of the "\r\n\r\n" terminator, so the last header line's CRLF
     * IS that first "\r\n" — stopping at hend hides the last header entirely,
     * and `Transfer-Encoding: chunked` last is the ordinary nginx/Kestrel
     * shape, not a corner case. */
    uint8_t *hstop = hend + 2;
    int chunked = 0;
    for (uint8_t *l = b.p; l < hstop; ) {
        uint8_t *le = find_seq(l, (size_t)(hstop - l), "\r\n", 2);
        if (!le) break;
        if (!strncasecmp((char *)l, "Transfer-Encoding:", 18) &&
            find_ci(l, (size_t)(le - l), "chunked", 7)) chunked = 1;
        l = le + 2;
    }

    size_t bodyn = b.n - hlen;
    if (bodyn == 0 || bodyn > cap) goto done;
    if (chunked) {
        bodyn = unchunk(b.p + hlen, bodyn);
        if (bodyn == 0 || bodyn > cap) goto done;
    }
    *out = malloc(bodyn);
    if (!*out) goto done;
    memcpy(*out, b.p + hlen, bodyn);
    got = bodyn;

done:
    free(b.p);
    if (s) SSL_free(s);
    SSL_CTX_free(cx);
    close(fd);
    return got;
}
