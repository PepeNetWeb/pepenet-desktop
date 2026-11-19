/* trust.h — install / remove the pepenet root in the OS *user* trust store.
 *
 * macOS: login keychain via `security`; the GUI auth prompt IS the operator's
 * deliberate consent to trust the `.doge`/`.pepe` root (DESIGN.md §2).
 * Linux: unprivileged NSS db (`certutil` → `~/.pki/nssdb`, Snap Chromium's
 * private db, Firefox profile cert9.db). The system store (`/usr/local/share
 * /ca-certificates` + `update-ca-certificates`) is the privileged helper's
 * job — there is no keychain GUI on Linux, so polkit plus the in-app consent
 * card is consent. `certutil` missing is not a hard failure for curl (p11-kit
 * system store), but Snap Chromium/Firefox will show CERT_AUTHORITY_INVALID.
 */
#ifndef PEPENET_TLS_TRUST_H
#define PEPENET_TLS_TRUST_H

/* Install `certpath` (PEM) as a trusted root in the user store. 1 on success. */
int trust_install(const char *certpath);

/* Remove the root's trust settings + the cert itself (matched by subject CN,
 * e.g. ca_root_cn()). Best-effort; 1 on success. */
int trust_uninstall(const char *certpath, const char *cn);

#endif
