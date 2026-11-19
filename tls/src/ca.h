/* ca.h — the name-constrained local root CA + on-the-fly leaf minting.
 *
 * This instance serves exactly ONE TLD — a `.doge` network OR a `.pepe` network
 * (ca_set_tld), never both. The root is generated once into
 * <data-dir>/<name>-root-<tld>.{crt,key} (EC P-256, ~10y; default dir ~/.pepenet
 * and name "pepenet" — override with ca_set_dir / ca_set_name) and carries a
 * *critical* X.509 NameConstraints extension permitting only that one TLD. That
 * constraint is the security pillar (DESIGN.md §2): even if this hot key leaks,
 * a conforming verifier refuses any leaf it signs for a name outside the TLD —
 * a doge box's key cannot mint a `.pepe` leaf at all.
 *
 * Programmatic libcrypto (OpenSSL 3), not a shell-out to `openssl`, because the
 * proxy mints a fresh leaf per TLS connection in-process — same path exercised
 * here. Link Homebrew openssl@3 (system LibreSSL lacks the DANE API the proxy
 * needs, and EVP_EC_gen); see Makefile.
 */
#ifndef PEPENET_TLS_CA_H
#define PEPENET_TLS_CA_H

#include <openssl/x509.h>
#include <openssl/evp.h>

/* Select the TLD this instance serves: exactly one of "doge" or "pepe". Call
 * before ca_root_ensure. 1 if accepted, 0 if not a known TLD (state unchanged).
 * Defaults to "doge" if never called. */
int ca_set_tld(const char *tld);
const char *ca_tld(void);          /* the active TLD ("doge"/"pepe") */

/* Point the root CA at a directory (the embedding app's data dir) so the root
 * cert/key follow a relocated data dir. Call before ca_root_ensure; default is
 * ~/.pepenet when unset. */
void ca_set_dir(const char *dir);

/* Set the instance name — the cert-file prefix (<name>-root-<tld>.{crt,key}) and
 * the root CN. The embedding app passes its own identity (e.g. "pepenet");
 * default "pepenet". Call before ca_root_ensure. */
void ca_set_name(const char *name);

/* Load the root from <data-dir>/<name>-root-<tld>.{crt,key}, creating +
 * persisting it (name-constrained, EC P-256) if absent. 1 on success (cert/key
 * owned by caller — X509_free / EVP_PKEY_free), 0 on error. Idempotent. */
int ca_root_ensure(X509 **cert, EVP_PKEY **key);

/* Mint a short-lived server leaf for `name` (subject CN + SAN dNSName=name,
 * EKU serverAuth), signed by the root. 1 with leaf/leafkey set (caller frees),
 * 0 on error. `name` is the SNI, e.g. "www.pepenet.doge". */
int ca_leaf_mint(X509 *root, EVP_PKEY *rootkey, const char *name,
                 X509 **leaf, EVP_PKEY **leafkey);

/* Filesystem paths + the root's subject CN (static storage; do not free). All
 * reflect the active TLD. */
const char *ca_root_cert_path(void);
const char *ca_root_key_path(void);
const char *ca_root_cn(void);

#endif
