/* dns_state.h — the DNS overlay over pepenet-mesh's sp_state (anchor-ordered
 * per-key LWW; see pepenet/state.h for the replication model).
 *
 * A zone is WHAT THE STORE CURRENTLY HOLDS for a name: one row per
 * (label, type) — the sp_state key — whose op payload is ttl ‖ rdata. Editing
 * replaces the row and frees its bytes, deleting leaves the signed tombstone,
 * `clear` voids everything below its anchor. There is no log, no fold, no
 * store TTL: a record lives until superseded, cleared, or its NAME lapses on
 * chain (dns_state_sweep). The record's own `ttl` field survives as what it
 * always meant in DNS — the resolver-cache TTL served in answers.
 *
 * Budget: DNS_BUDGET bytes of held ops per name, enforced at admission. The
 * whole zone therefore also fits one gossip frame (dns_net's zdat).
 *
 * Two wire forms of one record:
 *   • gossip (off-chain): an sp_state op — key = label ‖ type_be16, payload =
 *     ttl:var ‖ rdata — signed by the owner key or a §2.2 DNS_SCOPE hot key.
 *   • on-chain (escape hatch): the bare 0xD8 carrier in an OP_RETURN,
 *     0xFF ‖ magic[2] ‖ 0xD8 ‖ labellen:var label ‖ type:var ‖ ttl:var ‖ rdata.
 *     magic is the active coin's on-chain prefix (two bytes; the caller passes
 *     the Coin row). A carrier wearing any other prefix is not a record.
 *     Authenticated by the spend from the owner's address; its ANCHOR is its
 *     inclusion height — the same ordering axis as the gossiped form. It must
 *     fit DNS_ONCHAIN_MAX to relay permissionlessly. */
#ifndef DNS_STATE_H
#define DNS_STATE_H

#include <stdint.h>
#include "zone.h"
#include "pepenet/state.h"

#define DNS_SCOPE       0x20    /* §2.2 delegation scope bit for zone ops */
#define DNS_BUDGET      8192    /* bytes of held ops per name */
#define ZONE_OP         0xD8    /* on-chain overlay opcode (band 0xD6..0xFF) */
#define DNS_ONCHAIN_MAX 80      /* relay limit for the bare on-chain carrier */

/* ── key / payload codecs (the sp_state packing) ────────────────────────────── */
/* key = lowercased label bytes ‖ type_be16. Returns klen, -1 if label too long. */
int  dns_key_pack(const char *label, uint16_t type, uint8_t *key, int keymax);
int  dns_key_unpack(const uint8_t *key, int klen, char label[64], uint16_t *type);
/* payload = ttl:var ‖ rdata. Returns length, -1 on overflow. */
int  dns_payload_pack(uint32_t ttl, const uint8_t *rdata, int rdlen,
                      uint8_t *out, int outmax);
int  dns_payload_unpack(const uint8_t *p, int plen, uint32_t *ttl,
                        const uint8_t **rdata, int *rdlen);

/* ── on-chain carrier (escape hatch) ────────────────────────────────────────── */
/* magic is the coin's two-byte prefix (NULL rejects: encode -1, decode 0). */
int  dns_rec_encode(const zone_rec *r, const uint8_t magic[2],
                    uint8_t *out, int outmax);
int  dns_rec_decode(const uint8_t *c, int clen, const uint8_t magic[2],
                    zone_rec *r);
int  dns_rec_escape_hatchable(const zone_rec *r, const uint8_t magic[2]);

/* ── publishing (build one op, admit it locally) ────────────────────────────── */
/* All three anchor at the oracle's tip − SP_STATE_REORG (reorg-safe), sign
 * with `priv`/`pub33`, and embed a §2.2 cert when cert_type != SP_CERT_NONE
 * (the hot-zone-key path; SP_CERT_NONE ⇒ priv IS the owner key). Return the
 * sp_state_admit rc (1 ok · 0 rejected+err · -1 dup · -2 hold), or -3 when the
 * op cannot be built (bad label/rdata, no usable anchor). A delete of a
 * (label,type) IS dns_state_del — it leaves the tombstone; dns_state_clear
 * voids the whole zone below its anchor (floor). */
int dns_state_put(SpState *st, const SpChainOracle *o, const char *name,
                  const zone_rec *rec,
                  const uint8_t priv[32], const uint8_t pub33[33],
                  int cert_type, const uint8_t *cert, int cert_len,
                  char *err, int errlen);
int dns_state_del(SpState *st, const SpChainOracle *o, const char *name,
                  const char *label, uint16_t type,
                  const uint8_t priv[32], const uint8_t pub33[33],
                  int cert_type, const uint8_t *cert, int cert_len,
                  char *err, int errlen);
int dns_state_clear(SpState *st, const SpChainOracle *o, const char *name,
                    const uint8_t priv[32], const uint8_t pub33[33],
                    int cert_type, const uint8_t *cert, int cert_len,
                    char *err, int errlen);

/* ── reads ──────────────────────────────────────────────────────────────────── */
/* Assemble the live zone (PUT rows only; tombstones skipped). Returns z->n. */
int  dns_state_zone(SpState *st, const char *name, zone *z);

/* Zone digest for gossip: sha256(floor_le32 ‖ clear_id|zero32 ‖ op_ids in key
 * order). Equal digests ⇒ equal held state for the name. */
void dns_state_digest(SpState *st, const char *name, uint8_t out[32]);
/* L10: cache digests of ONE store (the gossip store). Exact invalidation via
 * the sp_state change hook + PRAGMA data_version; attach again to switch
 * stores, detach to stop. Uncached stores compute as before. */
void dns_state_cache_attach(SpState *st);
void dns_state_cache_detach(void);
void dns_state_cache_stats(unsigned long *hit, unsigned long *miss, unsigned long *inval, unsigned long *flush);

/* The zone as served for the CURRENT owner `owner`: empty (returns 0) when the
 * held rows were admitted under a different owner (a transfer whose new owner
 * has not published yet — they are the previous owner's records). */
int  dns_state_zone_owned(SpState *st, const char *name, const uint8_t owner[20], zone *z);

/* Expiry sweep: drop every stored name the oracle no longer answers for
 * (lease lapsed / never owned). Returns how many names were dropped. Walks
 * the whole store. */
int  dns_state_sweep(SpState *st, const SpChainOracle *o);
/* One resumable step of the same sweep: up to `max` names after `cursor`
 * ("" = start; wraps back to "" at the end). Returns names dropped; *examined
 * (may be NULL) = names looked at. */
int  dns_state_sweep_step(SpState *st, const SpChainOracle *o, char *cursor /* >= 33 B */,
                          int max, int *examined);

#endif /* DNS_STATE_H */
