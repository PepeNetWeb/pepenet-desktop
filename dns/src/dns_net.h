/* dns_net.h — zone gossip over the chain-wire mesh (dn* commands).
 *
 * The sync unit is the NAME: a zone is ≤ DNS_BUDGET bytes of held ops, so a
 * full zone rides one frame. Three messages (payloads after the dn command):
 *
 *   dnzinv : var count ‖ [ nlen:u8 name ‖ digest32 ]*        (i hold this)
 *   dnzget : nlen:u8 name                                    (send me yours)
 *   dnzdat : nlen:u8 name ‖ var count ‖ [ oplen:var op ]*    (full dump;
 *            the clear op first when held, then rows in key order)
 *
 * Convergence: a peer whose digest differs pulls; after admitting a dump we
 * re-announce the name to everyone INCLUDING the source (if we held ops the
 * source lacked, its digest now mismatches ours and it pulls back). Ops that
 * anchor ahead of our sync (-2) sit in a small hold queue and retry on the
 * tick. Everything rides the IdxMeshHooks surface dnsd/desktop already own;
 * this module is single-instance (one store per process). */
#ifndef DNS_NET_H
#define DNS_NET_H

#include <stdint.h>
#include <stddef.h>
#include "dns_state.h"

typedef void (*dnsnet_send_fn)(void *peer, const char *cmd, const uint8_t *pay, size_t n);

/* Bind the module to its store + oracle (call once, before any peer). */
void  dnsnet_init(SpState *st, SpChainOracle oracle, int verbose);

/* Peer lifecycle — mirror of IdxMeshHooks up/msg/down/tick. */
void *dnsnet_up(void *peer, dnsnet_send_fn send);      /* → handle (NULL = full) */
void  dnsnet_msg(void *handle, const char *cmd, const uint8_t *pay, int n);
void  dnsnet_down(void *handle);
void  dnsnet_tick(void);                               /* hold-queue + anti-entropy */

/* A local publish changed `name` — announce it to every live peer. */
void  dnsnet_announce(const char *name);

/* Overlay → serve score hook. NULL-checked. `peer` is the SConn* from dnsnet_up. */
void  dnsnet_set_misbehave(void (*fn)(void *peer, int score, const char *why));

/* Former P10 hook, kept for API compatibility: L2's stale-first lanes
 * (quiet-for-longest names first, in blocks) replace ownership seniority. */
void  dnsnet_set_seniority(int (*fn)(const char *name));

/* live peer count (status surfaces) */
int   dnsnet_peers(void);

/* ── local P2P spam fixes (dns_net.c L1-L10); nothing here touches the wire ── */
/* L2: one relay credit per `blocks` blocks of new chain height per name
 * (default 10; burst 4). Survives dnsnet_init. */
void  dnsnet_set_credit_blocks(int blocks);
/* L2 stagger: the block phase (0..credit_blocks-1) on which `name` gains a
 * credit, from a per-process keyed hash */
int   dnsnet_credit_phase(const char *name);
/* L7: at most `cap` dn* peers (default 64 = MAX_PEERS); extra peers still get
 * chain service, just no zone gossip. */
void  dnsnet_set_peer_cap(int cap);
/* L7: the cap for an uplink of `mbit` Mbit/s = mbit / 0.52 (one saturated
 * link at P6), clamped to [2, 64]; mbit <= 0 -> 64. */
int   dnsnet_peer_cap_for_uplink(double mbit);
/* L6/L7: optional transport hooks. pending(peer) = bytes queued but not yet
 * written to the socket (P6 refill waits for it to drain); drop(peer, why) =
 * close that connection, no ban (L6 disconnect; called from dnsnet_tick only);
 * is_local(peer) = 1 for peers that are never disconnected (loopback, seats). */
void  dnsnet_set_transport(size_t (*pending)(void *peer), void (*drop)(void *peer, const char *why),
                           int (*is_local)(void *peer));
/* counters by name (tests, status); "blk" = the max-seen tip credit uses */
unsigned long dnsnet_counter(const char *name);

#endif /* DNS_NET_H */
