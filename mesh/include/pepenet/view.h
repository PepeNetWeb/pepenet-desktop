// view.h — a read-only window onto namespace ownership, for any overlay.
//
// Chain mode reads the headless indexer's sqlite projection (names table + the
// epochs ownership-history + the proj_height sentinel) over WAL, so an overlay
// daemon runs safely alongside a live indexerd. Test mode loads a static
// name→owner table from a file so a mesh can be exercised with no chain at all.
//
// This is the identity root every pepenet overlay shares: the chain settles
// "name → owner @ height", overlays decide what to hang off that. Lifted from the
// vpost carrier's view.c (the two must stay behaviorally identical — §4.2).
//
// Names are the namespace-protocol §3.1 DNS-label set ([a-z0-9-], 1..32). Lookups
// of an invalid name return unowned (0) without hitting the DB — consensus can
// never mint them, so an overlay need not special-case junk labels.
#ifndef PEPENET_VIEW_H
#define PEPENET_VIEW_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SpView SpView;

SpView  *sp_view_open_chain(const char *indexer_db_path);        // read-only, WAL-friendly
SpView  *sp_view_open_test(const char *names_file, uint32_t tip); // lines: <name> <owner-h160-hex>
void     sp_view_close(SpView *v);

uint32_t sp_view_tip(SpView *v);                                 // projected chain height

// owner_of(name @ height) — EXACT §4.2 when the DB carries the epochs projection:
// the recorded owner at that height, including lapses. Heights the history does
// not cover fall back to the current owner. 1 owned (fills owner[20]) · 0 not.
// Invalid §3.1 names always return 0.
int      sp_view_owner_of(SpView *v, const uint8_t *name, int name_len,
                          uint32_t height, uint8_t owner[20]);

// convenience: current owner at the projected tip. 1 owned · 0 not.
int      sp_view_owner_now(SpView *v, const char *name, uint8_t owner[20]);

int      sp_view_addr_owns_name(SpView *v, const uint8_t addr[20]); // does addr own ANY name?

#ifdef __cplusplus
}
#endif

#endif
