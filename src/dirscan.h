// dirscan.h — the Discover directory (meld §6): the enumerable .pep website
// list. The chain IS the registry, so `SELECT name FROM names` lists every
// name — but a *website* is a name whose zone contains an A record, so the
// cheaper primary axis is the dns store's held zones (store_heads_iter), each
// folded and joined against the registry for its lease/owner.
//
// The join is far too slow per frame, so a background thread rebuilds a
// double-buffered snapshot on a timer / dirty kick; the UI takes a copy.
#ifndef DNET_DIRSCAN_H
#define DNET_DIRSCAN_H

#include <stdint.h>

typedef struct {
    char    name[40];       // apex (the TLD is implied)
    int64_t lease_expiry;   // 0 if the name isn't in the registry (lapsed)
    int     registered;     // present in names table (owned right now)
    int     has_a;          // zone has an apex A record → a website
    int     has_tlsa;       // _443._tcp TLSA present → visitable w/ green lock
    int     nrec;           // total live records in the zone
    char    a_ip[16];       // the apex A, dotted (for the row subtitle)
    char    site[112];      // owner's `_site` TXT — the Discover card blurb
} DirRow;

#define DIR_MAX 512

// Start/stop the rebuild thread. store_path = the dns carrier db;
// chain_db = the indexer projection. Idempotent.
int  dirscan_start(const char *store_path, const char *chain_db);
void dirscan_stop(void);

// Nudge a rebuild (e.g. right after our own publish) — coalesced with the timer.
void dirscan_kick(void);

// Copy the current snapshot into out[max]; returns the row count. Never blocks
// on the rebuild (reads the published buffer under a short lock). *built_at is
// the snapshot's wall-clock stamp (0 = never built).
int  dirscan_snapshot(DirRow *out, int max, int64_t *built_at, int *last_ms);

#endif
