/* origin.h — pure name→origin resolution logic (no store, no network, no TLS).
 *
 * This is the testable heart of slice 4's resolver: turning an SNI name plus a
 * folded pepenet zone into the OriginInfo the proxy dials + DANE-verifies. It
 * deliberately holds NO I/O — the store/view plumbing lives in resolve.{h,c},
 * so this layer can be proven hermetically against a hand-built zone (see
 * origin_test.c). The byte-level TLSA extraction here is exactly what feeds
 * dane_connect, so it is security-critical and unit-pinned.
 */
#ifndef PEPENET_TLS_ORIGIN_H
#define PEPENET_TLS_ORIGIN_H

#include <stddef.h>
#include "proxy.h"   /* OriginInfo */
#include "zone.h"    /* zone / zone_rec — the fold, from pepenet-dns */

/* Split an SNI into (apex, sub) for a given TLD suffix, mirroring dnsd's
 * suffix-strip + last-dot split (a pepenet apex is one dotless label).
 *   ("www.pepenet.doge", "doge") -> apex="pepenet", sub="www"     , 1
 *   ("pepenet.doge",     "doge") -> apex="pepenet", sub=""        , 1  (apex itself)
 *   ("a.b.pepenet.doge", "doge") -> apex="pepenet", sub="a.b"     , 1
 * Returns 0 if the name is not under `.suffix` or the apex would be empty. */
int origin_split(const char *sni, const char *suffix,
                 char *apex, size_t apexcap, char *sub, size_t subcap);

/* Fill *out for subdomain `sub` from a folded zone. Requires BOTH:
 *   - an A record at `sub` — in-zone CNAMEs are chased (≤4 hops) for the
 *     ADDRESS only: `www CNAME <apex>.<suffix>` resolves to the apex A.
 *     Targets outside this zone (another apex, an ICANN name) refuse.
 *   - a TLSA record at `_443._tcp[.sub]`  → out->usage/selector/mtype/assoc.
 *     The pin lookup NEVER follows the CNAME — pins are per-SNI hostname.
 * `suffix` is the resolver's TLD (needed to recognize in-zone CNAME targets;
 * pass NULL to disable chasing). Returns 1 only if both are present. No TLSA
 * ⇒ the origin cannot be DANE-authenticated, so it is NOT servable (0) —
 * never fall back to an unverified connection. */
int origin_from_zone(const zone *z, const char *sub, const char *suffix,
                     OriginInfo *out);

/* 1 iff the zone has any TLSA at sub's _443._tcp label (GreatDANE). */
int origin_has_tlsa(const zone *z, const char *sub);

#endif
