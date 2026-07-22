// tray_win.c — the notification-area icon + the tray-resident lifecycle on
// Windows (mirrors tray.m; see that file for the design story).
//
// The app is a regular window, but closing (or minimizing) it HIDES it and
// keeps every engine warm. The tray icon carries the live state and the only
// real Quit. Wiring: sokol's WM_CLOSE sends SAPP_EVENTTYPE_QUIT_REQUESTED;
// main.c calls tray_quit_requested() to decide veto-and-hide vs. really quit
// (the tray Quit sets g_really_quit, then requests the same quit path — one
// exit road, cleanup_cb included). The frame loop calls
// platform_window_visible() to skip rendering while hidden.
//
// The status menu is built FRESH each time it opens (like tray.m's dock menu)
// — no 1 Hz retitling of a live HMENU needed; tray_update() only refreshes
// the icon tooltip. All text goes through the wide APIs (the strings carry
// UTF-8: "…", "·", the coin glyph).
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>

#include "appconf.h"
#include "webproxy.h"
#include "dnsnet.h"
#include "model.h"
#include "ui/strings.h"

#include <stdint.h>
#include <stdio.h>

extern const void *sapp_win32_get_hwnd(void);
void sapp_request_quit(void);
void tray_update(void);
// plain-C formatters from ui/draw.c (no nuklear deps) — keep the menu rows
// byte-identical to the balance dropdown's health rows
void fmt_thousands(char *out, size_t cap, int64_t n);
void fmt_amount(char *out, size_t cap, int64_t koinu);

#define WM_TRAYICON   (WM_APP + 1)
#define TRAY_UID      1
#define CMD_OPEN      1
#define CMD_QUIT      2
#define TRAY_ROWS     5

static int  g_installed;
static int  g_really_quit;

// ── the status rows (same sources as the dropdown's health rows) ──────────────
static void status_lines(char out[TRAY_ROWS][64]) {
    if (M.web.running && M.dns.resolver_running)
        snprintf(out[0], 64, "%s", TR(S_TRAY_WEB_ON));
    else
        snprintf(out[0], 64, "%s", TR(S_TRAY_WEB_OFF));
    if (M.unreachable)
        snprintf(out[1], 64, "%s", TR(S_TRAY_CHAIN_UNREACH));
    else if (!M.running)
        snprintf(out[1], 64, "%s", TR(S_TRAY_CHAIN_STARTING));
    else {
        char hb[32];
        fmt_thousands(hb, sizeof hb, M.height);
        snprintf(out[1], 64, TR(S_TRAY_CHAIN_FMT),
                 M.synced ? TR(S_SYNC_SYNCED) : TR(S_SYNC_SYNCING), hb);
    }
    char a[32];
    fmt_amount(a, sizeof a, model_fee_k());
    snprintf(out[2], 64, TR(S_TRAY_FEE_FMT), a);
    fmt_amount(a, sizeof a, M.year_cost);
    snprintf(out[3], 64, TR(S_TRAY_RENT_FMT), a);
    if (M.dns.running)
        snprintf(out[4], 64, TR(S_TRAY_MESH_FMT), M.dns.peers,
                 M.dns.peers == 1 ? "" : "s");
    else
        snprintf(out[4], 64, "%s", TR(S_TRAY_MESH_STARTING));
}

static void to_wide(const char *utf8, wchar_t *out, int cap) {
    if (!MultiByteToWideChar(CP_UTF8, 0, utf8, -1, out, cap)) out[0] = 0;
}

// ── window show/hide ──────────────────────────────────────────────────────────
static void show_window(void) {
    HWND w = (HWND)sapp_win32_get_hwnd();
    if (!w) return;
    ShowWindow(w, IsIconic(w) ? SW_RESTORE : SW_SHOW);
    SetForegroundWindow(w);
}

void tray_hide_window(void) {
    HWND w = (HWND)sapp_win32_get_hwnd();
    if (w) ShowWindow(w, SW_HIDE);
}

// --background (autostart entry): start hidden — the tray icon is the app
// until Open shows the window. No Dock-tile equivalent to suppress here.
void tray_background_start(void) {
    tray_hide_window();
}

// ── the popup menu (built fresh per open, like tray.m's dock menu) ────────────
static void tray_menu(HWND w) {
    char l[TRAY_ROWS][64];
    status_lines(l);
    wchar_t wl[96];
    HMENU m = CreatePopupMenu();
    to_wide(TR(S_TRAY_OPEN), wl, 96);
    AppendMenuW(m, MF_STRING, CMD_OPEN, wl);
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    for (int i = 0; i < TRAY_ROWS; i++) {
        to_wide(l[i], wl, 96);
        AppendMenuW(m, MF_STRING | MF_GRAYED, 0, wl);
    }
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    to_wide(TR(S_TRAY_QUIT), wl, 96);
    AppendMenuW(m, MF_STRING, CMD_QUIT, wl);

    // TrackPopupMenu needs the window foregrounded or the menu won't dismiss
    SetForegroundWindow(w);
    POINT pt;
    GetCursorPos(&pt);
    int cmd = TrackPopupMenu(m, TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
                             pt.x, pt.y, 0, w, NULL);
    PostMessageW(w, WM_NULL, 0, 0);
    DestroyMenu(m);
    if (cmd == CMD_OPEN) show_window();
    else if (cmd == CMD_QUIT) {
        // one quit road: flag it, then drive sokol's QUIT_REQUESTED — main.c's
        // handler sees tray_quit_requested()==1, lets it through, cleanup runs
        g_really_quit = 1;
        sapp_request_quit();
    }
}

// ── subclass proc: tray callbacks + icon removal on destroy ───────────────────
static LRESULT CALLBACK tray_subclass(HWND w, UINT msg, WPARAM wp, LPARAM lp,
                                      UINT_PTR id, DWORD_PTR data) {
    (void)id; (void)data;
    if (msg == WM_TRAYICON) {
        UINT ev = LOWORD(lp);
        if (ev == WM_LBUTTONUP) show_window();
        else if (ev == WM_RBUTTONUP || ev == WM_CONTEXTMENU) tray_menu(w);
        return 0;
    }
    if (msg == WM_DESTROY && g_installed) {
        NOTIFYICONDATAW nid;
        memset(&nid, 0, sizeof nid);
        nid.cbSize = sizeof nid;
        nid.hWnd = w;
        nid.uID = TRAY_UID;
        Shell_NotifyIconW(NIM_DELETE, &nid);
        g_installed = 0;
    }
    return DefSubclassProc(w, msg, wp, lp);
}

// ── setup (called once, after the window exists; live mode only) ──────────────
void tray_setup(void) {
    HWND w = (HWND)sapp_win32_get_hwnd();
    if (!w || g_installed) return;
    SetWindowSubclass(w, tray_subclass, 0xD06E, 0);

    NOTIFYICONDATAW nid;
    memset(&nid, 0, sizeof nid);
    nid.cbSize = sizeof nid;
    nid.hWnd = w;
    nid.uID = TRAY_UID;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = LoadIconW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(1));
    if (!nid.hIcon) nid.hIcon = LoadIconW(NULL, MAKEINTRESOURCEW(32512) /* IDI_APPLICATION */);
    to_wide(APP_NAME, nid.szTip, 128);
    g_installed = Shell_NotifyIconW(NIM_ADD, &nid) ? 1 : 0;
    tray_update();
}

// ── live status (~1 Hz from the frame loop): refresh the tooltip ──────────────
void tray_update(void) {
    if (!g_installed) return;
    HWND w = (HWND)sapp_win32_get_hwnd();
    char l[TRAY_ROWS][64], tip[128];
    status_lines(l);
    snprintf(tip, sizeof tip, "%s \xE2\x80\x94 %s", APP_NAME, l[1]);
    NOTIFYICONDATAW nid;
    memset(&nid, 0, sizeof nid);
    nid.cbSize = sizeof nid;
    nid.hWnd = w;
    nid.uID = TRAY_UID;
    nid.uFlags = NIF_TIP;
    to_wide(tip, nid.szTip, 128);
    Shell_NotifyIconW(NIM_MODIFY, &nid);
}

// ── test seams: drive the exact user paths headlessly ─────────────────────────
void tray_test_close(void) {              // the titlebar ✕ (goes through WM_CLOSE)
    HWND w = (HWND)sapp_win32_get_hwnd();
    if (w) PostMessageW(w, WM_CLOSE, 0, 0);
}
void tray_test_quit(void) {               // the tray's Quit item
    g_really_quit = 1;
    sapp_request_quit();
}
void tray_test_dump(void) {               // the menu's live status rows
    char l[TRAY_ROWS][64];
    status_lines(l);
    for (int i = 0; i < TRAY_ROWS; i++) fprintf(stderr, "TRAYROW %s\n", l[i]);
}

// ── quit decision (from SAPP_EVENTTYPE_QUIT_REQUESTED) ────────────────────────
// 1 = allow the quit (only the tray's real Quit); 0 = veto + hide warm.
int tray_quit_requested(void) {
    if (g_really_quit) return 1;
    tray_hide_window();                   // hide; engines keep running
    return 0;
}

// ── visibility (frame loop skips rendering while hidden) ──────────────────────
int platform_window_visible(void) {
    HWND w = (HWND)sapp_win32_get_hwnd();
    return w ? (IsWindowVisible(w) ? 1 : 0) : 1;
}

#endif /* _WIN32 */
