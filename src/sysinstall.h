// sysinstall.h — the system-level web install (meld §4): the one-time,
// consented, privileged wiring that lets a stock browser reach .pep with a
// green lock. Three pieces, two privilege levels:
//   • root CA trusted in the login keychain — UNPRIVILEGED (trust_install;
//     the keychain GUI auth IS the consent), done in-process;
//   • /etc/resolver/pep + pf rdr :443→:8443 — PRIVILEGED, done by
//     packaging/install-helper.sh via `osascript … with administrator privileges`.
// Uninstall reverses all three. Quit leaves them planted but inert (dead ports).
#ifndef DNET_SYSINSTALL_H
#define DNET_SYSINSTALL_H

typedef struct {
    int ca_trusted;      // root CA present in the login keychain
    int resolver_file;   // /etc/resolver/pep exists
    int pf_anchor;       // pf rdr :443→:8443 loaded
} InstallState;

// Cheap probes (stat + `security`/`pfctl` shellouts). Cache the result ~5 s in
// the caller; this does real work. Safe on the UI thread.
void sysinstall_probe(InstallState *out);

// The buttons. install: trust_install(ca_root_cert_path()) in-process, then
// osascript→install-helper.sh for resolver+pf (one admin prompt). uninstall:
// the reverse. Both block on the auth dialog; call off a click, not per frame.
// Return 1 on success (best-effort for the privileged half).
int  sysinstall_install(void);
int  sysinstall_uninstall(void);

// Launch-at-login: a per-user LaunchAgent (~/Library/LaunchAgents/
// <bundle-id>.plist) pointing at the CURRENT executable. set(1) rewrites it
// (so a moved build heals on next enable), set(0) removes it. Takes effect
// at next login — no launchctl bootstrap, which would double-launch the
// running instance. state() = plist exists.
int  sysinstall_loginitem_state(void);
int  sysinstall_loginitem_set(int on);
void sysinstall_loginitem_default(void);   // first boot: default ON (once)

// Firefox ignores the macOS keychain unless security.enterprise_roots.enabled
// is set. Best-effort: append the pref to every Firefox profile's user.js
// (applied when Firefox next starts). Returns the number of profiles touched
// or already set; 0 = no Firefox profiles found.
int  sysinstall_firefox_roots(void);

// First-run consent marker (~/.pepenet/consent-<tld>): written when the user
// answers the 9h card either way, so it shows exactly once. Settings keeps the
// enable/uninstall pair for later visits.
int  sysinstall_consent_seen(void);
void sysinstall_consent_mark(void);

#endif
