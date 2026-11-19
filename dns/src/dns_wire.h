/* dns_wire.h — minimal, zero-dep DNS message codec (RFC 1035 wire format).
 *
 * Scope: enough to parse a single-question query and build an authoritative
 * answer. Names are written uncompressed (fine for a small authoritative
 * responder); compression pointers are followed on read. */
#ifndef DNS_WIRE_H
#define DNS_WIRE_H

#include <stdint.h>
#include <stddef.h>

/* Record types we name explicitly; anything else rides the generic TYPE path. */
enum {
    DNS_A          = 1,
    DNS_NS         = 2,
    DNS_CNAME      = 5,
    DNS_SOA        = 6,
    DNS_PTR        = 12,
    DNS_MX         = 15,
    DNS_TXT        = 16,
    DNS_AAAA       = 28,
    DNS_SRV        = 33,
    DNS_SSHFP      = 44,
    DNS_TLSA       = 52,
    DNS_OPENPGPKEY = 61,
};

enum { DNS_CLASS_IN = 1 };

/* RFC 1035 §2.3.4: a domain name is at most 255 octets on the wire (label
 * length bytes and the root label included). Both the decoder and the encoder
 * enforce it — the 256-byte text buffers below are not the limit. */
#define DNS_NAME_MAX 255

/* RCODEs we use. */
enum {
    DNS_RCODE_NOERROR  = 0,
    DNS_RCODE_FORMERR  = 1,
    DNS_RCODE_SERVFAIL = 2,
    DNS_RCODE_NXDOMAIN = 3,
    DNS_RCODE_REFUSED  = 5,
};

/* A parsed query (first question only). qname is dotted, lowercased, no
 * trailing dot; the root is the empty string. qname_orig is the same name with
 * the query's own octets preserved: LOOKUPS use qname (DNS matching is case
 * blind), but the response must echo the question exactly as it was asked
 * (RFC 1035 §4.1.2) — case folding it would break DNS-0x20 case randomisation,
 * which clients rely on to detect off-path spoofing. */
typedef struct {
    uint16_t id;
    uint16_t flags;   /* raw header flags of the request (RD is echoed back) */
    char     qname[256];
    char     qname_orig[256];
    uint16_t qtype;
    uint16_t qclass;
    /* EDNS0 (RFC 6891), parsed from an OPT pseudo-RR in the additional section.
     * edns=1 means the client speaks EDNS0 and advertised udp_payload as the
     * largest UDP answer it will accept; without it the UDP budget is 512. */
    uint8_t  edns;
    uint8_t  edns_version;   /* 0 expected */
    uint16_t udp_payload;    /* requestor's advertised UDP payload size */
} dns_query;

/* Parse a request datagram. Returns 0 on success, -1 on malformed input. */
int dns_parse_query(const uint8_t *buf, size_t len, dns_query *q);

/* Response builder over a caller-owned buffer. */
typedef struct {
    uint8_t *buf;
    size_t   cap;        /* hard buffer size */
    size_t   limit;      /* soft byte budget (UDP payload); <= cap */
    size_t   len;
    int      ancount;
    int      arcount;    /* additional RRs (the echoed OPT) */
    int      truncated;  /* an RR didn't fit `limit` → TC bit set at finish */
    int      ok;         /* cleared if an append overflowed the hard buffer */
} dns_resp;

/* Start a response: writes the header (QR=1, AA=1, RD echoed, given rcode) and
 * re-emits the question section. `limit` starts at `cap`. */
void dns_resp_begin(dns_resp *r, uint8_t *buf, size_t cap,
                    const dns_query *q, int rcode);

/* Lower the soft byte budget (e.g. to the client's advertised UDP payload size,
 * minus any space reserved for a trailing OPT). Answers that would exceed it are
 * dropped and the response is marked truncated (TC). Clamped to [len, cap]. */
void dns_resp_set_limit(dns_resp *r, size_t limit);

/* Append one answer RR carrying raw rdata. `owner` is a dotted name. Returns -1
 * (without setting TC) once the response is already truncated. */
int dns_resp_add(dns_resp *r, const char *owner, uint16_t type,
                 uint32_t ttl, const uint8_t *rdata, uint16_t rdlen);

/* Append the response's EDNS0 OPT RR (additional section), advertising our own
 * max UDP payload. Call after all answers, before finish. */
int dns_resp_add_opt(dns_resp *r, uint16_t udp_payload);

/* Patch ANCOUNT/ARCOUNT (and TC if truncated) into the header. Returns the final
 * message length, or 0 if the build overflowed the hard buffer. */
size_t dns_resp_finish(dns_resp *r);

/* Encode a dotted name into wire label format. Returns bytes written, or -1. */
int dns_encode_name(uint8_t *out, size_t cap, const char *dotted);

#endif /* DNS_WIRE_H */
