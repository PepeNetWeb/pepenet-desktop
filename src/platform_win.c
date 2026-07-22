// platform_win.c — the Windows implementation of the stateless platform.h
// primitives (paths, config, executable location, bundled resources,
// launching, secret storage). The windowing halves live with the code that
// owns the HWND — sokol_impl_win.c (platform_style_window) and tray_win.c
// (platform_window_visible). Mirrors platform_mac.m; see platform.h.
//
// Path convention: every path this file RETURNS uses forward slashes — all
// Win32/CRT file APIs accept them, and the engine code above this seam parses
// directories with strrchr(p, '/') (zonekey.c, wallet.c, dnsnet.c's dirname).
// Native backslashes appear only where the shell demands them (Explorer's
// /select argument); the executable path keeps whatever GetModuleFileName
// returns for registry/shortcut fidelity.
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <wincred.h>
#include <direct.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "platform.h"
#include "appconf.h"     // APP_DATA_DIR (default data-folder name), APP_NAME

#define CONFIG_REG_KEY "Software\\" APP_NAME

static void fwd_slashes(char *p) {
    for (; *p; p++) if (*p == '\\') *p = '/';
}

// ── persisted app config (HKCU registry — Windows' NSUserDefaults) ────────────
int platform_config_get(const char *key, char *out, size_t cap) {
    if (!key || !out || !cap) return 0;
    out[0] = 0;
    HKEY h;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, CONFIG_REG_KEY, 0, KEY_READ, &h) != ERROR_SUCCESS)
        return 0;
    DWORD type = 0, len = (DWORD)cap - 1;
    LONG rc = RegQueryValueExA(h, key, NULL, &type, (BYTE *)out, &len);
    RegCloseKey(h);
    if (rc != ERROR_SUCCESS || type != REG_SZ || len == 0) { out[0] = 0; return 0; }
    out[len] = 0;                     // RegQueryValueEx may or may not include NUL
    return out[0] != 0;
}

int platform_config_set(const char *key, const char *val) {
    if (!key) return 0;
    HKEY h;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, CONFIG_REG_KEY, 0, NULL, 0,
                        KEY_WRITE, NULL, &h, NULL) != ERROR_SUCCESS)
        return 0;
    LONG rc;
    if (val && val[0])
        rc = RegSetValueExA(h, key, 0, REG_SZ, (const BYTE *)val,
                            (DWORD)strlen(val) + 1);
    else
        rc = RegDeleteValueA(h, key);   // empty = clear the override
    RegCloseKey(h);
    return rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND;
}

// ── filesystem locations ──────────────────────────────────────────────────────
static int is_abs_path(const char *p) {
    return p[0] == '/' ||
           (((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) &&
            p[1] == ':') ||
           (p[0] == '\\' && p[1] == '\\');
}

const char *platform_data_dir(char *out, size_t cap) {
    char over[600];
    if (platform_config_get("data_dir", over, sizeof over) && is_abs_path(over)) {
        snprintf(out, cap, "%s", over);
    } else {
        const char *home = getenv("USERPROFILE");
        if (!home || !home[0]) home = getenv("HOME");
        if (!home || !home[0]) home = ".";
        snprintf(out, cap, "%s/.%s", home, APP_DATA_DIR);   // ~/.pepenet, mac parity
    }
    fwd_slashes(out);
    _mkdir(out);                            // idempotent; ignore EEXIST
    return out;
}

const char *platform_data_path(const char *name, char *out, size_t cap) {
    char dir[600];
    platform_data_dir(dir, sizeof dir);
    snprintf(out, cap, "%s/%s", dir, name);
    return out;
}

// Modal folder picker (Settings › Change location) — SHBrowseForFolder; runs
// on the calling (UI) thread.
int platform_choose_directory(char *out, size_t cap) {
    if (!out || !cap) return 0;
    out[0] = 0;
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    BROWSEINFOA bi;
    memset(&bi, 0, sizeof bi);
    bi.lpszTitle = "Choose a data folder";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    PIDLIST_ABSOLUTE pidl = SHBrowseForFolderA(&bi);
    if (!pidl) return 0;
    char path[MAX_PATH] = {0};
    int ok = SHGetPathFromIDListA(pidl, path) && path[0];
    CoTaskMemFree(pidl);
    if (!ok) return 0;
    fwd_slashes(path);
    snprintf(out, cap, "%s", path);
    return 1;
}

int platform_executable_path(char *out, size_t cap) {
    if (!out || !cap) return 0;
    DWORD n = GetModuleFileNameA(NULL, out, (DWORD)cap);
    return n > 0 && n < cap;
}

// A file bundled alongside the app: packaged installs ship a resources\
// folder next to the exe (fonts, install-helper); dev runs return 0 so the
// caller falls back into the source tree.
int platform_resource_path(const char *name, char *out, size_t cap) {
    if (out && cap) out[0] = 0;
    if (!name || !out || !cap) return 0;
    char exe[1024];
    if (!platform_executable_path(exe, sizeof exe)) return 0;
    char *sep = strrchr(exe, '\\');
    char *sep2 = strrchr(exe, '/');
    if (sep2 > sep) sep = sep2;
    if (!sep) return 0;
    *sep = 0;
    snprintf(out, cap, "%s/resources/%s", exe, name);
    fwd_slashes(out);
    if (GetFileAttributesA(out) != INVALID_FILE_ATTRIBUTES) return 1;
    snprintf(out, cap, "%s/%s", exe, name);
    fwd_slashes(out);
    if (GetFileAttributesA(out) != INVALID_FILE_ATTRIBUTES) return 1;
    out[0] = 0;
    return 0;
}

// ── launching ─────────────────────────────────────────────────────────────────
void platform_open_url(const char *url) {
    if (!url || !url[0]) return;
    ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);
}

void platform_reveal_file(const char *path) {
    if (!path || !path[0]) return;
    char nat[1100];
    snprintf(nat, sizeof nat, "%s", path);
    for (char *p = nat; *p; p++) if (*p == '/') *p = '\\';   // explorer insists
    char args[1200];
    snprintf(args, sizeof args, "/select,\"%s\"", nat);
    ShellExecuteA(NULL, "open", "explorer.exe", args, NULL, SW_SHOWNORMAL);
}

// ── secret storage (Windows Credential Manager — DPAPI-backed at rest) ────────
// Target name "<service>/<account>"; service defaults to the per-instance
// data-dir name (APP_DATA_DIR: "pepenet"), overridable with
// $PEPENET_KEYCHAIN_SERVICE for test isolation — mirrors the mac Keychain.
static const char *cred_service(void) {
    const char *s = getenv("PEPENET_KEYCHAIN_SERVICE");
    return (s && s[0]) ? s : APP_DATA_DIR;
}

static void cred_target(const char *account, char *out, size_t cap) {
    snprintf(out, cap, "%s/%s", cred_service(), account);
}

int platform_secret_get(const char *account, uint8_t *out, size_t cap) {
    if (!account || !out || !cap) return 0;
    char target[256];
    cred_target(account, target, sizeof target);
    PCREDENTIALA c = NULL;
    if (!CredReadA(target, CRED_TYPE_GENERIC, 0, &c)) return 0;
    int n = 0;
    if (c->CredentialBlobSize > 0 && c->CredentialBlobSize <= cap) {
        memcpy(out, c->CredentialBlob, c->CredentialBlobSize);
        n = (int)c->CredentialBlobSize;
    }
    CredFree(c);
    return n;
}

int platform_secret_set(const char *account, const uint8_t *secret, size_t len) {
    if (!account || !secret || !len) return 0;
    char target[256];
    cred_target(account, target, sizeof target);
    CREDENTIALA c;
    memset(&c, 0, sizeof c);
    c.Type = CRED_TYPE_GENERIC;
    c.TargetName = target;
    c.CredentialBlob = (LPBYTE)secret;
    c.CredentialBlobSize = (DWORD)len;
    c.Persist = CRED_PERSIST_LOCAL_MACHINE;   // this user, this machine
    return CredWriteA(&c, 0) ? 1 : 0;
}

int platform_secret_del(const char *account) {
    if (!account) return 0;
    char target[256];
    cred_target(account, target, sizeof target);
    if (CredDeleteA(target, CRED_TYPE_GENERIC, 0)) return 1;
    return GetLastError() == ERROR_NOT_FOUND;   // already absent = success
}

// No SMAppService equivalent here — -1 sends sysinstall to its own autostart
// mechanism (Run-key / Startup shortcut when the Windows port lands).
int platform_loginitem_state(void) { return -1; }
int platform_loginitem_set(int on) { (void)on; return -1; }

#endif /* _WIN32 */
