// indexer.h — the chain-side public surface (everything the protocol-sm engine
// does NOT do: real block/tx decode, §4 attribution, persistence, P2P sync).
#ifndef IDX_INDEXER_H
#define IDX_INDEXER_H

#include <stdint.h>
#include <stddef.h>
#include <sqlite3.h>
#include "sm.h"
#include "oracle_feed.h"

#ifdef __cplusplus
extern "C" {
#endif

// The overlay discovery mark: a peer whose subver (user-agent) starts with
// this prefix speaks the dns-mesh overlay — the crawl's classifier, the
// serve loop's mesh gate, and the dial pool's bucket all match on it. One
// mark per NETWORK: every node on a deployment must agree or they can't
// find each other. Overridable at build time so a branded deployment flies
// its own flag (the PepeNet desktop builds with "/pepenet-"); the generic
// default stays "/pepenet-".
#ifndef IDX_DNET_MARK
#define IDX_DNET_MARK "/pepenet-"
#endif

// Peers-table bounds (idx_db_peers_prune): an addr unseen this long ages out,
// and the table is hard-capped to the freshest N regardless. A working peer
// re-stamps last_good on every good handshake, so only genuinely-dead addrs
// expire. Pruned at each sync pass end and periodically by idx_serve.
#define IDX_PEER_TTL_SECS ((int64_t)14 * 24 * 3600)   // 14 days
#define IDX_PEER_CAP      4096

// CLI dispatch for the chain-bound commands (sync / resolve / owned / digest /
// index). Defined in sync.c. Returns a process exit code.
int indexer_main(int argc, char **argv);

// idx-03 crash recovery (sync.c): rewind a cursor that is ahead of the committed
// projection and drop every height-keyed row above it. 1 = rewound.
// idx-04: apply a snapshot dir as a FRESH db only if state.db's whole-file
// SHA-256 equals the pin (flag_pin, else the compiled per-chain default —
// snapshot.h IDX_SNAPSHOT_PIN_*). 1 = applied; 0 = refused (why filled; nothing
// written at dbpath) — the caller falls back to a normal full sync.
int  idx_snapshot_import(const char *coin, const char *snapdir, const char *dbpath,
                         const char *flag_pin, char *why, size_t cap);
int  idx_sync_recover(sqlite3 *db, int64_t start, const uint8_t start_hash[32],
                      int64_t *height, uint8_t tip[32]);
// test-only: IDX_TEST_CRASH_AT=<h> → _exit(137) after block h's rows, pre-projection
void idx_test_crash_point(int64_t height);

// Active coin's name-carrier prefix (the two bytes after 0xFF). 1 if `name`
// is a known coin. Testnet and regtest return the pep prefix.
int idx_coin_onchain_magic(const char *name, uint8_t out[2]);

// Cooperative stop for an embedding host (the desktop client runs `sync` on a
// background thread). Set to 1 to make a running sync wind down at the next
// recv boundary (≤ one recv timeout); the host clears it before the next pass.
// The headless CLI never touches it.
extern volatile int idx_sync_stop;

// The peer's declared chain height (version.start_height), captured at the
// current pass's handshake; 0 = unknown / not yet handshaken (reset at each
// pass start). `projected height ≥ this` is the wire's only live at-tip
// signal — a caught-up getblocks is answered with silence — so embedding
// hosts use it to render truthful sync state. The headless CLI just logs it.
extern volatile int64_t idx_sync_peer_height;
// peer_height follows block announcements (inv / headers / pushed blocks we
// can place on our chain, and blocks folded from the sync peer), not only the
// handshake's start_height. Monotonic; the meta write is rate-limited to one
// per IDX_PH_WRITE_MIN_S (force = flush now, e.g. at pass end). Returns the
// best height noted so far. db may be NULL (memory only).
#define IDX_PH_WRITE_MIN_S 60
struct sqlite3;
void    idx_peer_height_load(struct sqlite3 *db);   /* seed g_ph_* from meta on db open */
int64_t idx_peer_height_note(struct sqlite3 *db, int64_t h, int64_t now, int force);
void    idx_peer_height_reset(void);   /* tests */

// The user-agent (subver) sent in our version message. A "/pepenet-…/" prefix
// is the mesh's discovery mark (peer-discovery design): crawlers classify a
// node as dns-aware by this string, so embedding hosts set their app identity
// here BEFORE the first sync pass (e.g. "/pepenet-desktop:0.1/").
extern const char *idx_sync_agent;

// The connected peer's subver and services, captured at the current pass's
// handshake (empty/0 = not yet handshaken; reset at each pass start). The
// crawl's classifier reads these after a probe handshake.
extern volatile char idx_sync_peer_agent[128];
extern volatile uint64_t idx_sync_peer_services;

// Set (never cleared) when a self-connect guard fires on a configured seed:
// the seed hostname resolved to this node's own address, i.e. this node IS
// the network's seed. Embedding hosts read it to skip seed-finding work that
// makes no sense on the seed itself (e.g. the discovery crawl — clients dial
// the seed, so marked peers arrive via inbound + dnaddr instead).
extern volatile int idx_self_seed;

// One bounded crawl pass over the chain graph (peer-discovery slice 2): dial
// up to max_dials candidates — `extra` targets (comma list, may be NULL)
// first, then the peers table's least-recently-tried — handshake, record
// services + agent + last_good, getaddr to grow the frontier. Classifier:
// the IDX_DNET_MARK subver prefix = dns-aware (query idx_db_peers_agent for
// the bucket); NODE_NETWORK services = block source. Probes run 8 at a time
// on one poll loop with tight budgets (~3 s connect / 5 s handshake), so a
// 64-dial sweep of a mostly-dead frontier costs ~30-60 s; still blocking —
// run on a background thread. Returns marked peers now known, -1 on db-open
// failure. `stop` may be NULL.
int idx_crawl(const char *coin, const char *dbpath, const char *extra,
              int max_dials, volatile int *stop);

// Live serve-loop connection snapshot (an embedding host's Peers page).
// idx_serve republishes its connection table ~1 Hz under a seqlock (single
// writer, lock-free readers — no pthread dependency for the headless CLI);
// idx_serve_conns copies the latest snapshot from any thread. Rows cover
// every slot in use: live inbound/outbound connections AND outbound slots
// between redials (connected == 0, redial_in counting down).
typedef struct {
    char     peer[80];      // remote ip:port ("" until connected)
    char     host[80];      // outbound: the dial target host
    uint16_t rport;         // outbound: the dial target port
    char     agent[128];    // peer subver ("/pepenet-" = a mesh peer)
    int      connected;     // socket open
    int      up;            // version handshake complete
    int      outbound;      // dialed by us (else accepted inbound)
    int      mesh_seat;     // slot seated by overlay discovery (dnet pool)
    int      mesh;          // handed to the mesh carrier (peer_up accepted)
    int64_t  redial_in;     // outbound + not connected: seconds to next dial
    int64_t  peer_height;   // peer's claimed chain height at handshake (0 unknown)
} IdxServeConn;
// → rows copied (0 = idx_serve not running / nothing seated)
int idx_serve_conns(IdxServeConn *out, int max);
// Highest chain height any live serve-plane peer claimed at its handshake
// (0 = none). Paired with the blockstage this is the sync pass's "am I at the
// network's tip without opening a socket" measure.
int64_t idx_serve_best_height(void);
// 1 iff the serve plane owns a relationship with this dial target (live conn
// by remote ip, or an outbound seat by dial-target text). The
// one-connection-per-peer rule: no other plane may open a socket to such a
// peer — chain data, reorgs and tx relay all ride the standing connection.
int idx_serve_peer_held(const char *target);
// Bumps once per block the serve plane newly parks in the blockstage (the
// sync-over-one-connection mailbox — see serve_store.h). Embedding hosts
// watch it to cut their inter-pass pause short: fold-on-inv latency instead
// of timer latency.
extern volatile int64_t idx_serve_stage_seq;

// Live crawl progress (the chain-graph walk that hunts "/pepenet-" peers —
// idx_crawl's per-pass counters, which otherwise only reach stderr). Updated
// as the pass dials; same seqlock scheme, readable from any thread.
typedef struct {
    int     running;        // a pass is on the wire right now
    int     dials;          // this pass: dial attempts so far
    int     max_dials;      // this pass: the bound
    int     up;             // this pass: completed handshakes
    int     hits;           // this pass: "/pepenet-" agents found
    int     known;          // "/pepenet-" peers known in the db at last pass end
    int64_t last_pass;      // wall time the last pass finished (0 = never ran)
    int64_t passes;         // completed passes since process start
    char    last_peer[80];  // most recent addr probed
    char    last_agent[128];// its subver ("" = down / no handshake)
} IdxCrawlStatus;
void idx_crawl_status(IdxCrawlStatus *out);

// Mesh hooks (peer-discovery slice 3, step 3): an embedder (the desktop / a
// pepenet daemon) drives a carrier over the pepenet peer connections idx_serve
// manages, so the DNS mesh rides the chain wire — no separate mesh port. A peer
// whose version subver starts "/pepenet-" is a mesh peer; on its handshake
// idx_serve calls peer_up with a `send` bound to that connection (send a dn*
// command) and routes inbound "dn<name>" commands to peer_msg. NULL = the node
// serves chain data only (no gossip), which is all the standalone indexer does
// (it links no carrier).
typedef struct {
    // A pepenet peer handshaked. send(peer, "dnheads", pay, n) emits a command
    // on ITS connection. Return an opaque handle (passed back to peer_msg /
    // peer_down), or NULL to ignore this peer.
    void *(*peer_up)(void *ud, void *peer,
                     void (*send)(void *peer, const char *cmd, const uint8_t *pay, size_t n));
    void  (*peer_msg)(void *ud, void *handle, const char *name, const uint8_t *pay, int n);
    void  (*peer_down)(void *ud, void *handle);
    void  (*tick)(void *ud);   // ~1 Hz on the serve thread (publish drain / housekeeping)
    void   *ud;
    /* optional: overlay reports local-policy strikes against this SConn */
    void  (*peer_misbehave)(void *peer, int score, const char *why);
} IdxMeshHooks;

// Transport hooks for a mesh carrier (local policy only, nothing on the wire);
// `peer` is the pointer idx_serve passed to peer_up. Serve thread only.
//   pending: bytes queued for that conn but not yet written to its socket
//   kick:    close that conn right after the mesh tick (logged; no ban/score)
//   exempt:  1 for loopback/unknown-address peers and outbound seats we dialed
size_t idx_serve_peer_pending(void *peer);
void   idx_serve_peer_kick(void *peer, const char *why);
int    idx_serve_peer_exempt(void *peer);

/* Overlay / serve local-policy strike: add `n` to this SConn's score; at 100
 * ban the IPv4 24 h and drop the conn. `peer` is the SConn* from peer_up. */
void serve_conn_misbehave(void *peer, int n, const char *why);

// The chain-wire presence (peer-discovery slice 3). Listen on `port` (0 =
// dial-only, no bind — for a NAT'd node), maintain outbound connections to
// `dial_peers` (comma host:port list, may be NULL), version-handshake
// advertising our "/pepenet-" agent, answer getaddr, harvest addr, serve
// getheaders/getdata and getblocks-within-the-window (a near-tip peer can
// sync wholly from us; a deep-behind one gets honest silence and its ladder's
// NODE_NETWORK gate routes it to an archive peer), and — when `mesh` is
// non-NULL — carry carrier gossip as
// dn* commands over every pepenet connection. Blocks until *stop; run on a
// thread. Returns 0, -1 on bind failure.
// Outcome of idx_serve's chain-port bind, for local status reporting only
// (never on the wire). PENDING until idx_serve reaches the bind; OFF when
// started with port 0 (dial-only by choice); FAILED = bind/listen refused and
// the node degraded to dial-only (err = errno, or WSAGetLastError on Windows).
enum { IDX_LISTEN_PENDING = 0, IDX_LISTEN_OK = 1, IDX_LISTEN_FAILED = 2,
       IDX_LISTEN_OFF = 3 };
void idx_serve_listen_status(int *state, int *port, int *err);
int idx_serve(const char *coin, const char *dbpath, uint16_t port,
              const char *dial_peers, volatile int *stop, const IdxMeshHooks *mesh);

// The coin's default chain P2P port (pep 33874, doge 22556, ...) — the port a
// node listens on to accept inbound pepenet peers. 0 if the coin is unknown.
uint16_t idx_coin_port(const char *coin);

// Reorg rollback to `to_height` (kept): prune the height-keyed projections above
// it, drop its oracle rows, rebuild the fold state by replaying the stored raw
// carrier blocks. Replaces *s. Returns 1, 0 on a replay failure.
int idx_sync_rollback(SmState **s, sqlite3 *db, OracleFeed *oracle,
                      int64_t activation, int64_t to_height);

#ifdef __cplusplus
}
#endif

#endif
