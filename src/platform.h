// platform.h — the OS seam. Everything the app does that differs between
// operating systems lives behind these calls, so a port is a second
// implementation, not a fork. On macOS the implementation spans:
//   • platform_mac.m  — the stateless primitives below (paths, launch, reveal)
//   • sokol_impl.m     — platform_style_window (the drawn-titlebar window chrome)
//   • tray.m           — platform_window_visible (the tray-resident window state)
// A Windows port supplies platform_win.c + tray_win.c providing the same names;
// nothing above this header is meant to know which OS it is running on.
//
// The two HIGHER-LEVEL seams keep their own headers because they compose these
// primitives with a policy layer: sysinstall.h (the consented, privileged web
// install — CA trust + resolver + port redirect) and the tray/lifecycle C
// functions (tray_setup/update/…). Their macOS internals still route their OS
// primitives (data dir, executable path, resource lookup) through here.
#ifndef DNET_PLATFORM_H
#define DNET_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

// ── filesystem locations ──────────────────────────────────────────────────────
// The per-user data directory, created if missing. Default ~/.<APP_DATA_DIR>
// (this build: ~/.pepenet); a user-chosen absolute path stored under the
// "data_dir" config key (Settings › Change location) supersedes it. Written
// into `out` (never a trailing slash) and also returned. Falls back to "." if
// the OS gives us no home.
const char *platform_data_dir(char *out, size_t cap);

// A path INSIDE the data directory: <data_dir>/<name>. Same buffer contract as
// platform_data_dir. Convenience over data_dir + snprintf at every call site.
const char *platform_data_path(const char *name, char *out, size_t cap);

// ── persisted app config (macOS: NSUserDefaults · Windows: registry) ──────────
// A tiny string key/value store that lives OUTSIDE the data directory, so it can
// record WHERE the data directory is. get: 1 + value into `out` (0 = unset).
// set: pass "" / NULL to clear the key. Currently used for "data_dir".
int platform_config_get(const char *key, char *out, size_t cap);
int platform_config_set(const char *key, const char *val);

// Modal folder picker (Settings › Change location). Runs on the caller's run
// loop — call from the UI thread. 1 + chosen absolute path into `out`, 0 on
// cancel.
int platform_choose_directory(char *out, size_t cap);

// Absolute path of the running executable (for a login-item / autostart entry
// that survives the binary being moved). 1 on success, 0 on failure.
int platform_executable_path(char *out, size_t cap);

// A file bundled alongside the app (packaged: the app's resource directory;
// dev runs: the in-tree copy). 1 if resolved into `out`, 0 if not found.
int platform_resource_path(const char *name, char *out, size_t cap);

// ── launching ─────────────────────────────────────────────────────────────────
// Open a URL in the user's default browser. Fire-and-forget, best-effort.
void platform_open_url(const char *url);

// Reveal a file in the OS file manager (Finder / Explorer), selecting it.
// Best-effort.
void platform_reveal_file(const char *path);

// ── window chrome (implemented in the windowing TU: sokol_impl.m / tray.m) ────
// Apply the app's custom-titlebar window styling. `ui_scale` maps logical px to
// window points. Called once after the window exists.
void platform_style_window(float ui_scale);

// Is the main window visible? The frame loop skips rendering while hidden (the
// tray-resident app keeps its engines warm with the window ordered out). 1 if
// visible or unknown (render), 0 if hidden.
int  platform_window_visible(void);

// Launch-at-login through the OS's blessed channel (macOS 13+ SMAppService with
// the plist bundled at Contents/Library/LaunchAgents) — the Login Items UI and
// the "runs in the background" notification then carry the APP's name; a
// hand-written ~/Library/LaunchAgents plist is attributed to the signing
// identity's LEGAL name instead. state: 1 registered · 0 not · -1 unavailable
// (caller falls back to the legacy hand-written agent). set: same tri-state.
int  platform_loginitem_state(void);
int  platform_loginitem_set(int on);

// ── secret storage (OS keystore: macOS Keychain · Windows DPAPI/CredMan) ──────
// Store a small secret (e.g. a 32-byte private key) encrypted at rest under the
// user's login account, keyed by `account`. This is AT-REST protection, not
// hardware signing: the coin's secp256k1 keys cannot live in the Secure Enclave
// or a TPM (unsupported curve), so callers still retrieve the key to sign
// in-process — but it is no longer a plaintext file readable outside the login.
// The keystore "service" namespace defaults to the per-instance data-dir name
// (appconf APP_DATA_DIR — this build: "pepenet") and can be overridden with
// $PEPENET_KEYCHAIN_SERVICE — mainly for test isolation.
//   get: bytes read into `out`; 0 = no such item; -1 = the item may EXIST but
//        the keystore refused (access denied / user hit Deny / locked). The
//        caller MUST treat -1 as "hands off" — never as an invitation to mint
//        and store a replacement secret over a live one.
//   set: 1 on success, 0 on failure (keystore locked/denied).
//   del: 1 if removed or already absent, 0 on error.
int  platform_secret_get(const char *account, uint8_t *out, size_t cap);
int  platform_secret_set(const char *account, const uint8_t *secret, size_t len);
int  platform_secret_del(const char *account);

#endif
