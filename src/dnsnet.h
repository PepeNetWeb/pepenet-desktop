// dnsnet.h — the embedded dns plane: zone gossip + resolver (meld §3).
//
// Two background threads over the shared dns store (dns-<coin>.db):
//   net thread      — pepenet-dns's chain-wire gossip (dnz* commands over
//                     idx_serve's connections): firehose mirror of the record
//                     store, bounded at 8 KB of HELD ops per name (edits
//                     replace, deletes tombstone; no store TTL — a lapsed
//                     lease sweeps its records). Drains the UI's publish
//                     queue (hot-zone-key-signed records under a §2.2 cert).
//   resolver thread — pepenet-dns's DnsdCore on 127.0.0.1:<port> (UDP+TCP,
//                     EDNS0, ownership-gated), --tls-redirect semantics on so
//                     DANE names steer the browser at the local proxy.
//
// The UI thread talks to this seam only: boot (conf), start/stop, status
// snapshots, and the publish queue. Config: ~/.pepenet/dns-<coin>.conf
// (dns_port=), env overrides PEPENET_DNS_{PEER,LISTEN,PORT,TEST}.
#ifndef DNET_DNSNET_H
#define DNET_DNSNET_H

#include <stdint.h>
#include "zone.h"           // zone_rec / zone (pepenet-dns)

typedef struct {
    int     running;            // net thread alive
    int     queued;             // publishes waiting for the net thread's drain
    char    phase[40];          // net-thread lifecycle ("mesh", "waiting for
                                // chain db", "store open FAILED", …) — the
                                // first thing to read when publishes sit
    int     peers;              // handshaken mesh peers
    int64_t zones_held;         // names in the store
    int64_t records_held;       // record rows held (incl. tombstones)
    int     resolver_running;   // resolver thread alive + bound
    int     resolver_port;
    char    last_err[128];      // last refused publish ("" = none)
    char    last_pub[160];      // last publish outcome line ("" = none)
} DnsStatus;

// read/create the conf next to the chain db. Returns 1 (the dns plane has no
// "off" mode — an empty view just answers NXDOMAIN and grows as sync folds).
int  dnsnet_boot(const char *coin, const char *chain_dbpath);

// append a mesh peer ("host:port") after boot, before start — the seam
// crawl-discovered pepenet candidates come in through. Dupes are dropped.
void dnsnet_add_peer(const char *hostport);

int  dnsnet_start(void);        // spin both threads (idempotent)
void dnsnet_stop(void);         // stop + join both

void dnsnet_status(DnsStatus *out);
int  dnsnet_test_view(void);    // offline harness (PEPENET_DNS_TEST) active?

// UI thread: queue ONE record publish on `name`'s zone — a PUT, or a DELETE
// when rec->rdlen == 0 (issues the signed `del` tombstone that outranks every
// replay of the old record). The net thread signs (hot zone key + §2.2 cert,
// wallet-key fallback), admits, and announces it next tick; the outcome lands
// in status.last_pub / last_err. Returns 1 queued, 0 queue full / not running.
int  dnsnet_publish(const char *name, const zone_rec *rec);

// Queue a whole-zone CLEAR: voids every record and tombstone anchored below
// it (the per-name floor) and reclaims their bytes. Same signing path.
int  dnsnet_publish_clear(const char *name);

// Publish the `_443._tcp[.sub] TLSA 3 1 1 <spki>` pin for an origin `host`
// (TLD-less: apex "gm" or dotted sub "shop.gm"). Derives the apex + TLSA label
// and queues the record via dnsnet_publish. The one place the DANE key pin is
// built — the SSL screen and the auto-refresh thread both go through here.
// Returns 1 queued, 0 otherwise. Thread-safe (dnsnet_publish is).
int  dnsnet_publish_tlsa(const char *host, const uint8_t spki[32]);

// The inverse: queue the signed DELETE tombstone for `host`'s TLSA pin (same
// label derivation). The name stops being DANE-servable once it gossips.
int  dnsnet_unpublish_tlsa(const char *host);

// UI-thread zone read: assemble `name`'s live zone from a dedicated read
// handle (cheap for one name). Returns live record count, -1 if unavailable.
int  dnsnet_zone(const char *name, zone *z);

// UI-thread usage read: bytes of held ops for `name` (records + tombstones +
// clear) against the 8 KB per-name budget (DNS_BUDGET). -1 if unavailable.
int64_t dnsnet_zone_bytes(const char *name);

const char *dnsnet_store_path(void);
const char *dnsnet_chain_path(void);

#endif
