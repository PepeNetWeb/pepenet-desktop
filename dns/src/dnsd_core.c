/* dnsd_core.c — the resolver core (see dnsd_core.h). Moved verbatim from
 * dnsd.c's main-thread half, with the file-scope globals folded into DnsdCore. */
#include "dnsd_core.h"
#include "dns_wire.h"
#include "pepenet/crypto.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

static void split_apex(const char *left, char *apex, size_t acap, char *sub, size_t scap) {
    const char *dot = strrchr(left, '.');
    if (dot) {
        snprintf(apex, acap, "%s", dot + 1);
        size_t n = (size_t)(dot - left); if (n >= scap) n = scap - 1;
        memcpy(sub, left, n); sub[n] = '\0';
    } else { snprintf(apex, acap, "%s", left); sub[0] = '\0'; }
}

/* Does `sub` publish a DANE record at _443._tcp? (drives tls_redirect.) */
static int has_443_tlsa(const zone *z, const char *sub) {
    char lbl[80];
    if (*sub) snprintf(lbl, sizeof lbl, "_443._tcp.%s", sub);
    else      snprintf(lbl, sizeof lbl, "_443._tcp");
    for (int i = 0; i < z->n; i++)
        if (z->recs[i].type == DNS_TLSA && strcasecmp(z->recs[i].label, lbl) == 0)
            return 1;
    return 0;
}

/* Modern DNS-flag-day default: cap our UDP answers at 1232 bytes even when the
 * client advertises more, to dodge IP fragmentation. Anything larger sets TC and
 * the client retries over TCP. */
#define DNS_MAX_UDP 1232

/* begin a response and immediately clamp it to the answer budget (below the OPT
 * reservation, if any) — one call so every rcode branch gets the same limit. */
static void resp_start(dns_resp *r, uint8_t *out, size_t cap, size_t limit,
                       const dns_query *q, int rcode) {
    dns_resp_begin(r, out, cap, q, rcode);
    dns_resp_set_limit(r, limit);
}

/* Build the full response for `q` into out[cap]. `over_tcp` lifts the 512/EDNS
 * UDP budget to the whole buffer (TCP has no such limit). Returns the response
 * length (a well-formed query always yields at least a header+question). */
size_t dnsd_core_answer(DnsdCore *dc, const dns_query *q,
                        uint8_t *out, size_t cap, int over_tcp) {
    dns_resp r;
    size_t budget;
    if (over_tcp)      budget = cap;
    else if (q->edns)  budget = q->udp_payload < 512 ? 512
                              : q->udp_payload > DNS_MAX_UDP ? DNS_MAX_UDP
                              : q->udp_payload;
    else               budget = 512;
    if (budget > cap) budget = cap;
    size_t limit = budget - (q->edns ? 11u : 0u);   /* reserve the echoed OPT */

    if (q->qclass != DNS_CLASS_IN) { resp_start(&r, out, cap, limit, q, DNS_RCODE_REFUSED); goto done; }
    size_t ql = strlen(q->qname), sl = strlen(dc->suffix);
    if (ql <= sl + 1 || q->qname[ql - sl - 1] != '.' || strcasecmp(q->qname + ql - sl, dc->suffix) != 0) {
        resp_start(&r, out, cap, limit, q, DNS_RCODE_REFUSED); goto done;
    }
    char left[256]; size_t leftlen = ql - sl - 1;
    memcpy(left, q->qname, leftlen); left[leftlen] = '\0';
    char apex[64], sub[192];
    split_apex(left, apex, sizeof apex, sub, sizeof sub);

    /* Apex must be a §3.1 pepenet name (DNS label). Subdomain labels are free
     * form (e.g. _443._tcp) and are matched later against the zone. */
    if (!sp_name_valid(apex, strlen(apex))) {
        resp_start(&r, out, cap, limit, q, DNS_RCODE_NXDOMAIN); goto done;
    }

    uint8_t owner[20];
    int owned = dc->oracle.owner_now(dc->oracle.u, apex, owner);
    if (dc->verbose)
        fprintf(stderr, "query %s → apex=%s sub=%s owned=%d edns=%d tcp=%d\n",
                q->qname, apex, sub[0] ? sub : "@", owned, q->edns, over_tcp);
    if (!owned) { resp_start(&r, out, cap, limit, q, DNS_RCODE_NXDOMAIN); goto done; }

    zone z; dns_state_zone_owned(dc->st, apex, owner, &z);   /* G1: current owner's rows only */
    resp_start(&r, out, cap, limit, q, DNS_RCODE_NOERROR);

    /* TLS interception: for an A (or ANY) query on a DANE-enabled name, answer
     * the proxy's loopback IP instead of the real origin A. The browser then
     * hits the local proxy, which DANE-verifies the true origin (read straight
     * from the store) before relaying. Names without a _443._tcp TLSA are
     * untouched, so plain A lookups still resolve normally. */
    int redirect_a = dc->tls_redirect && (q->qtype == DNS_A || q->qtype == 255)
                     && has_443_tlsa(&z, sub);

    int label_seen = 0, cname = 0;
    for (int i = 0; i < z.n; i++) {
        zone_rec *rec = &z.recs[i];
        if (strcasecmp(rec->label, sub) != 0) continue;
        label_seen = 1;
        if (redirect_a && rec->type == DNS_A) continue;   /* replaced below */
        if (q->qtype == 255 || rec->type == q->qtype)
            dns_resp_add(&r, q->qname, rec->type, rec->ttl, rec->rdata, rec->rdlen);
    }
    if (redirect_a)
        dns_resp_add(&r, q->qname, DNS_A, 60, dc->tls_redirect_ip, 4);
    if (r.ancount == 0)
        for (int i = 0; i < z.n; i++) {
            zone_rec *rec = &z.recs[i];
            if (strcasecmp(rec->label, sub) == 0 && rec->type == DNS_CNAME) {
                dns_resp_add(&r, q->qname, DNS_CNAME, rec->ttl, rec->rdata, rec->rdlen); cname = 1; break;
            }
        }
    if (r.ancount == 0 && !label_seen && !cname)
        resp_start(&r, out, cap, limit, q, DNS_RCODE_NXDOMAIN);

done:;
    if (q->edns) dns_resp_add_opt(&r, DNS_MAX_UDP);   /* signal we speak EDNS0 */
    return dns_resp_finish(&r);
}

/* ── transports ──────────────────────────────────────────────────────────────── */
static void serve_udp(DnsdCore *dc) {
    uint8_t buf[4096];
    struct sockaddr_storage cli; socklen_t cl = sizeof cli;
    ssize_t n = recvfrom(dc->ufd, buf, sizeof buf, 0, (struct sockaddr *)&cli, &cl);
    if (n < 0) return;
    dns_query q;
    if (dns_parse_query(buf, (size_t)n, &q) != 0) return;
    uint8_t out[4096];
    size_t rn = dnsd_core_answer(dc, &q, out, sizeof out, 0);
    if (rn) sendto(dc->ufd, out, rn, 0, (struct sockaddr *)&cli, cl);
}

/* ── TCP (RFC 7766), non-blocking ─────────────────────────────────────────────
 * The resolver thread also answers UDP, so TCP must never block it. The old
 * inline loop (3 s SO_RCVTIMEO per read, served until EOF) let ONE client that
 * sent a query every <3 s — or trickled bytes, or merely connected and idled —
 * starve every UDP query for as long as it liked. Now each client is a slot in
 * dc->tcp polled alongside the UDP socket:
 *   DNSD_TCP_MAX    16 clients total; DNSD_TCP_PER_IP 2 per IPv4 source
 *                   (over the cap: accepted and closed at once, backlog drains)
 *   TCP_IDLE_MS     3 s without a byte in or out (the old per-read timeout)
 *   TCP_LIFE_MS     10 s absolute per connection, however chatty — plenty for
 *                   a stub's TC-fallback retry or a short pipeline (RFC 7766
 *                   lets servers close idle/long conns; clients reconnect)
 * Queries over DNSD_TCP_QMAX (4096) bytes close the conn; real queries are a
 * few hundred bytes. Answers are queued per client and written as the socket
 * drains; a client that stops reading hits the idle/life clock. Footprint:
 * ~66 KB of slots + one answer buffer per busy client; no threads. */
#define TCP_IDLE_MS 3000
#define TCP_LIFE_MS 10000
#ifndef DNSD_TCP_PER_IP
#define DNSD_TCP_PER_IP 2
#endif
#ifdef MSG_NOSIGNAL
#define TCP_SEND_FLAGS MSG_NOSIGNAL
#else
#define TCP_SEND_FLAGS 0
#endif

static int64_t core_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static int would_block(void) { return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR; }

static void tcp_close(DnsdTcpConn *t) {
    if (t->fd >= 0) close(t->fd);
    free(t->out);
    memset(t, 0, sizeof *t);
}

static void tcp_accept(DnsdCore *dc) {
    for (int k = 0; k < 8; k++) {                       /* drain a burst, bounded */
        struct sockaddr_in sa; socklen_t sl = sizeof sa;
        int c = accept(dc->tfd, (struct sockaddr *)&sa, &sl);
        if (c < 0) return;
        uint32_t ip = sl >= (socklen_t)sizeof sa ? sa.sin_addr.s_addr : 0;
        int slot = -1, same = 0;
        for (int i = 0; i < DNSD_TCP_MAX; i++) {
            if (!dc->tcp[i].used) { if (slot < 0) slot = i; }
            else if (dc->tcp[i].ip == ip) same++;
        }
        if (slot < 0 || same >= DNSD_TCP_PER_IP) { close(c); continue; }
        int fl = fcntl(c, F_GETFL, 0);
        if (fl < 0 || fcntl(c, F_SETFL, fl | O_NONBLOCK) != 0) { close(c); continue; }
        DnsdTcpConn *t = &dc->tcp[slot];
        memset(t, 0, sizeof *t);
        t->used = 1; t->fd = c; t->ip = ip;
        t->born_ms = t->last_ms = core_ms();
    }
}

/* write what the socket takes; 0 = keep, -1 = close */
static int tcp_flush(DnsdTcpConn *t) {
    while (t->out && t->out_off < t->out_len) {
        ssize_t w = send(t->fd, t->out + t->out_off, t->out_len - t->out_off, TCP_SEND_FLAGS);
        if (w < 0) return would_block() ? 0 : -1;
        if (w == 0) return -1;
        t->out_off += (size_t)w; t->last_ms = core_ms();
    }
    free(t->out); t->out = NULL; t->out_len = t->out_off = 0;
    return 0;
}

/* answer every complete buffered query, one at a time (each answer must drain
 * before the next is built); 0 = keep, -1 = close */
static int tcp_answer(DnsdCore *dc, DnsdTcpConn *t) {
    static uint8_t out[65536];
    while (!t->out && t->in_len >= 2) {
        size_t mlen = ((size_t)t->in[0] << 8) | t->in[1];
        if (mlen == 0 || mlen > DNSD_TCP_QMAX) return -1;
        if (t->in_len < 2 + mlen) break;
        dns_query q;
        if (dns_parse_query(t->in + 2, mlen, &q) != 0) return -1;
        size_t rn = dnsd_core_answer(dc, &q, out, sizeof out, 1);
        if (rn == 0 || rn > 65535) return -1;
        t->out = malloc(rn + 2);
        if (!t->out) return -1;
        t->out[0] = (uint8_t)(rn >> 8); t->out[1] = (uint8_t)rn;
        memcpy(t->out + 2, out, rn); t->out_len = rn + 2; t->out_off = 0;
        memmove(t->in, t->in + 2 + mlen, t->in_len - 2 - mlen); t->in_len -= 2 + mlen;
        if (tcp_flush(t) != 0) return -1;
    }
    return 0;
}

static void tcp_service(DnsdCore *dc, DnsdTcpConn *t, short rev) {
    if ((rev & POLLOUT) && tcp_flush(t) != 0) { tcp_close(t); return; }
    if (rev & (POLLIN | POLLHUP | POLLERR)) {
        if (t->in_len < sizeof t->in) {
            ssize_t r = recv(t->fd, t->in + t->in_len, sizeof t->in - t->in_len, 0);
            if (r == 0 || (r < 0 && !would_block())) { tcp_close(t); return; }
            if (r > 0) { t->in_len += (size_t)r; t->last_ms = core_ms(); }
        } else if (rev & (POLLHUP | POLLERR)) { tcp_close(t); return; }
    }
    if (tcp_answer(dc, t) != 0) tcp_close(t);
}

static void tcp_expire(DnsdCore *dc, int64_t now) {
    for (int i = 0; i < DNSD_TCP_MAX; i++) {
        DnsdTcpConn *t = &dc->tcp[i];
        if (t->used && (now - t->born_ms >= TCP_LIFE_MS || now - t->last_ms >= TCP_IDLE_MS))
            tcp_close(t);
    }
}

/* ── lifecycle ───────────────────────────────────────────────────────────────── */
int dnsd_core_bind(DnsdCore *dc, const char *addr, int port) {
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port);
    /* A malformed address must NOT fall through to the memset's 0.0.0.0: that
     * would silently turn an intended loopback bind into a wildcard one and
     * expose the resolver to the whole network. */
    if (inet_pton(AF_INET, addr ? addr : "", &sa.sin_addr) != 1) {
        fprintf(stderr, "dnsd: bad bind address '%s'\n", addr ? addr : "(null)");
        dc->ufd = dc->tfd = -1; return -1;
    }
    int one = 1;

    dc->ufd = socket(AF_INET, SOCK_DGRAM, 0);
    if (dc->ufd < 0) { perror("socket dns/udp"); dc->tfd = -1; return -1; }
    setsockopt(dc->ufd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(dc->ufd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        perror("bind dns/udp"); close(dc->ufd); dc->ufd = -1; dc->tfd = -1; return -1;
    }

    dc->tfd = socket(AF_INET, SOCK_STREAM, 0);
    if (dc->tfd < 0) { perror("socket dns/tcp"); return 0; }   /* UDP-only fallback */
    setsockopt(dc->tfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(dc->tfd, (struct sockaddr *)&sa, sizeof sa) < 0 || listen(dc->tfd, 16) < 0) {
        perror("bind dns/tcp"); close(dc->tfd); dc->tfd = -1;   /* UDP-only fallback */
    } else {
        int fl = fcntl(dc->tfd, F_GETFL, 0);                  /* accept must never block */
        if (fl < 0 || fcntl(dc->tfd, F_SETFL, fl | O_NONBLOCK) != 0) {
            perror("dns/tcp nonblock"); close(dc->tfd); dc->tfd = -1;
        }
    }
    for (int i = 0; i < DNSD_TCP_MAX; i++) dc->tcp[i].used = 0;
    return 0;
}

int dnsd_core_poll(DnsdCore *dc, int timeout_ms) {
    if (dc->ufd < 0) return 0;
    struct pollfd pfd[2 + DNSD_TCP_MAX]; int map[2 + DNSD_TCP_MAX]; int nf = 0;
    pfd[nf].fd = dc->ufd; pfd[nf].events = POLLIN; pfd[nf].revents = 0; map[nf++] = -1;
    if (dc->tfd >= 0) { pfd[nf].fd = dc->tfd; pfd[nf].events = POLLIN; pfd[nf].revents = 0; map[nf++] = -2; }
    int64_t now = core_ms(), next = -1;
    for (int i = 0; i < DNSD_TCP_MAX; i++) {
        DnsdTcpConn *t = &dc->tcp[i];
        if (!t->used) continue;
        short ev = 0;
        if (t->in_len < sizeof t->in) ev |= POLLIN;
        if (t->out) ev |= POLLOUT;
        pfd[nf].fd = t->fd; pfd[nf].events = ev; pfd[nf].revents = 0; map[nf++] = i;
        int64_t d1 = t->born_ms + TCP_LIFE_MS, d2 = t->last_ms + TCP_IDLE_MS;
        int64_t d = d1 < d2 ? d1 : d2;
        if (next < 0 || d < next) next = d;
    }
    int wait = timeout_ms;                               /* wake for the next expiry */
    if (next >= 0) { int64_t left = next - now; if (left < 0) left = 0; if (wait < 0 || left < wait) wait = (int)left; }
    int pr = poll(pfd, (nfds_t)nf, wait);
    int served = 0;
    if (pr > 0) {
        for (int k = 0; k < nf; k++) {
            if (!pfd[k].revents) continue;
            if (map[k] == -1) { if (pfd[k].revents & POLLIN) { serve_udp(dc); served++; } }
            else if (map[k] == -2) { if (pfd[k].revents & POLLIN) { tcp_accept(dc); served++; } }
            else if (dc->tcp[map[k]].used && dc->tcp[map[k]].fd == pfd[k].fd) {
                tcp_service(dc, &dc->tcp[map[k]], pfd[k].revents); served++;
            }
        }
    }
    tcp_expire(dc, core_ms());
    return served;
}

void dnsd_core_close(DnsdCore *dc) {
    for (int i = 0; i < DNSD_TCP_MAX; i++) if (dc->tcp[i].used) tcp_close(&dc->tcp[i]);
    if (dc->ufd >= 0) close(dc->ufd);
    if (dc->tfd >= 0) close(dc->tfd);
    dc->ufd = dc->tfd = -1;
}
