/* sscert.h — the self-signed ORIGIN server certificate.
 *
 * The other half of the DANE story: ca.c mints what the *browser* sees, this
 * mints what the *origin server* serves — the cert whose SubjectPublicKeyInfo
 * hash the name's owner publishes as `_443._tcp TLSA 3 1 1`. Under DANE-EE
 * (usage 3) no CA signs it and no verifier walks a chain: the chain-published
 * SPKI hash IS the trust anchor, so self-signed + long-lived is exactly right.
 * Until now operators hand-rolled this with the openssl CLI (and LibreSSL vs
 * OpenSSL disagreements produced mismatched pins); this makes it one call.
 */
#ifndef PEPENET_TLS_SSCERT_H
#define PEPENET_TLS_SSCERT_H

#include <stdint.h>
#include <stddef.h>

/* Ensure the origin cert+key for `fqdn` (e.g. "pepenet.pepe") at the two paths:
 * load if the pair exists, else generate + persist (EC P-256, ~10 y, key
 * 0600). SAN = fqdn, plus *.fqdn when `wildcard` — one cert for the apex and
 * every subdomain; without it the cert names the fqdn alone (subs get their
 * own certs). `wildcard` only shapes a fresh generate; a loaded pair keeps
 * whatever SAN it was born with. Writes the SPKI SHA-256 — the exact
 * `TLSA 3 1 1` association data — into spki. `created` (optional) is set to
 * 1 when freshly generated, 0 when loaded. 1 on success, 0 on error. */
int sscert_ensure(const char *fqdn, const char *crt_path, const char *key_path,
                  int wildcard, uint8_t spki[32], int *created);

/* Probe-only: read an existing cert and return its SPKI SHA-256. Never
 * creates anything. 1 on success, 0 if absent/unparseable. */
int sscert_spki(const char *crt_path, uint8_t spki[32]);

/* Probe-only: 1 if the cert at crt_path carries a "*." SAN entry (covers
 * subdomains), 0 if not (or absent/unparseable). */
int sscert_wildcard(const char *crt_path);

/* Probe a LIVE TLS origin: connect to host:port (hostname or IP) sending
 * SNI=servername, read the leaf certificate it serves, and return its SPKI
 * SHA-256 — the exact `TLSA 3 1 1` association data. No chain verification:
 * DANE pins the KEY, so we accept whatever leaf is presented and pin it. This
 * is how an operator reuses an existing (e.g. Let's Encrypt) cert for a
 * chain name — we only ever read the public half, never the private key.
 *
 * Probe with the SAME SNI the proxy uses at runtime (the chain fqdn, e.g.
 * "pepenet.pepe"), so the pin matches exactly what proxy.c will see when it
 * dials the origin. If crt_path is non-NULL the leaf is saved there (PEM,
 * public cert only) so the SSL screen can list + re-pin it. subject/not_after
 * (optional) are filled for display. 1 on success, 0 on failure (err set). */
int sscert_probe(const char *host, int port, const char *servername,
                 const char *crt_path, uint8_t spki[32],
                 char *subject, size_t subjcap, int64_t *not_after,
                 char *err, size_t errcap);

#endif
