/* zone.h — a signed record set for one pepenet apex name.
 *
 * The zone file is a simple whitespace-delimited text format (see
 * zones/pepenet.zone). Each record is parsed immediately into its final wire
 * rdata so the responder only copies bytes. The apex itself is the flat
 * pepenet name — a DNS label per namespace-protocol §3.1 ([a-z0-9-], 1..32);
 * callers validate with sp_name_valid (pepenet-mesh). Subdomain structure
 * lives in the `label` field (ordinary DNS labels, e.g. `_443._tcp`). */
#ifndef ZONE_H
#define ZONE_H

#include <stdint.h>
#include <stddef.h>

#define ZONE_MAX_RECS 512
#define ZONE_MAX_RDATA 512

typedef struct {
    char     label[64];   /* subdomain; "" is the apex (file uses "@") */
    uint16_t type;
    uint32_t ttl;
    uint16_t rdlen;
    uint8_t  rdata[ZONE_MAX_RDATA];
} zone_rec;

typedef struct {
    char     apex[64];    /* flat pepenet name this zone belongs to */
    uint64_t serial;
    int      n;
    zone_rec recs[ZONE_MAX_RECS];
} zone;

/* Load and parse a zone file. `apex` is stamped onto z->apex. Returns 0 on
 * success, -1 on I/O or parse error (with a message on stderr). */
int zone_load(zone *z, const char *path, const char *apex);

/* Build one record from text fields, the same way the zone file does: `label`
 * is "@" (apex) or a subdomain; `type_s` a mnemonic (A, TLSA, …) or "TYPEnnn";
 * `rdata_text` is the record's value (e.g. "192.0.2.9", or "3 1 1 <hex>"). An
 * empty/NULL `rdata_text` builds a delete (rdlen 0). 0 ok, -1 bad type/rdata. */
int zone_build_rec(const char *label, const char *type_s, uint32_t ttl,
                   const char *rdata_text, zone_rec *out);

/* Reverse of type_code: a mnemonic for a type, or "TYPEnnn" for the rest.
 * Writes into buf (caller sizes >= 12) and returns buf. */
const char *zone_type_name(uint16_t type, char *buf, size_t cap);

#endif /* ZONE_H */
