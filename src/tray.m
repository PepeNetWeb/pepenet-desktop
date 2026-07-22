// tray.m — the menu-bar status item + the tray-resident lifecycle (meld §4).
//
// The app is a regular app (Dock icon), but closing its window HIDES it and
// keeps every engine warm — the chain stays synced, the resolver + proxy keep
// serving the TLD. The menu bar carries the live state and the only real Quit.
// Quit stops the engines; the installed system config (root + resolver + pf)
// stays planted but inert — a dead proxy port is the legible "app is off"
// state (Uninstall in Settings is the only thing that reverses it).
//
// Wiring: sokol's window-close sends SAPP_EVENTTYPE_QUIT_REQUESTED; the app's
// event handler calls tray_quit_requested() to decide veto-and-hide vs. really
// quit. The frame loop calls platform_window_visible() to skip rendering
// while hidden (engines still tick).
#import <Cocoa/Cocoa.h>
#import <objc/runtime.h>

#include "appconf.h"
#include "platform.h"
#include "webproxy.h"
#include "dnsnet.h"
#include "model.h"
#include "ui/strings.h"

#include <stdint.h>
#include <stdio.h>

extern const void *sapp_macos_get_window(void);
// plain-C formatters from ui/draw.c (no nuklear deps) — keep the menu rows
// byte-identical to the balance dropdown's health rows
void fmt_thousands(char *out, size_t cap, int64_t n);
void fmt_amount(char *out, size_t cap, int64_t koinu);

static NSStatusItem   *g_item;

// ── the status rows (shared by the tray menu + the Dock menu) ─────────────────
// Same sources as the dropdown's health rows: the 1 Hz model snapshot.
#define TRAY_ROWS 5
static NSMenuItem *g_rows[TRAY_ROWS];   // tray copies, retitled at 1 Hz

static void status_lines(char out[TRAY_ROWS][64]) {
    // web plane (resolver + proxy folded into one legible line)
    if (M.web.running && M.dns.resolver_running)
        snprintf(out[0], 64, "%s", TR(S_TRAY_WEB_ON));
    else
        snprintf(out[0], 64, "%s", TR(S_TRAY_WEB_OFF));
    // chain: block # + sync state (sync is one pinned peer; its health IS
    // the connectivity signal — there is no chain peer count to show)
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

// ── menu actions ──────────────────────────────────────────────────────────────
// Bring the hidden-warm app back: Dock tile + window + focus. The policy
// restore undoes a --background start (Accessory = no Dock tile); a no-op
// when the app came up normally.
static void show_app(void) {
    if ([NSApp activationPolicy] != NSApplicationActivationPolicyRegular)
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    NSWindow *win = (NSWindow *)(uintptr_t)sapp_macos_get_window();
    [NSApp activateIgnoringOtherApps:YES];
    [win makeKeyAndOrderFront:nil];
}

@interface TrayTarget : NSObject
- (void)openApp:(id)sender;
- (void)quitApp:(id)sender;
@end

@implementation TrayTarget
- (void)openApp:(id)sender {
    (void)sender;
    show_app();
}
- (void)quitApp:(id)sender {
    (void)sender;
    // straight through AppKit: applicationWillTerminate → sokol cleanup_cb →
    // engines stop. (The old sapp_request_quit → performClose route needed
    // terminate-after-last-window-closed, which tray_setup turns off.)
    [NSApp terminate:nil];
}
@end

static TrayTarget *g_target;

void tray_update(void);

// tray-resident means a hidden window must NOT end the app — but AppKit's
// deferred "_scheduleCheckForTerminateAfterLastWindowClosed" counts VISIBLE
// windows, so after a vetoed close it still saw zero and terminated us
// through sokol's applicationShouldTerminateAfterLastWindowClosed: YES.
// Answer NO instead (patched at runtime; the vendored sokol stays pristine).
// Real exits don't rely on it: Quit calls [NSApp terminate:] directly.
static BOOL no_term_after_last_close(id self, SEL _cmd, NSApplication *app) {
    (void)self; (void)_cmd; (void)app;
    return NO;
}

// Dock-icon click while the window is hidden-warm should bring it back —
// sokol's delegate doesn't implement reopen, so add it (class_addMethod: the
// selector doesn't exist there, this is an add, not a replace).
static BOOL reopen_shows_window(id self, SEL _cmd, NSApplication *app, BOOL has_visible) {
    (void)self; (void)_cmd; (void)app;
    if (!has_visible) show_app();      // also restores the Dock tile after a
    return YES;                        // --background (Accessory) start
}

// Right-clicking the Dock icon asks the app delegate for extra menu items —
// serve the same live status rows. Built fresh per click, so no retitling.
static NSMenu *dock_menu(id self, SEL _cmd, NSApplication *app) {
    (void)self; (void)_cmd; (void)app;
    char l[TRAY_ROWS][64];
    status_lines(l);
    NSMenu *m = [[[NSMenu alloc] init] autorelease];
    for (int i = 0; i < TRAY_ROWS; i++) {
        NSMenuItem *it = [m addItemWithTitle:[NSString stringWithUTF8String:l[i]]
                                      action:nil keyEquivalent:@""];
        [it setEnabled:NO];
    }
    return m;
}

// The menu-bar face as art: the logo, staged into Resources at 36px. Returns
// nil when the resource isn't there (an unbundled dev run without the staged
// copy) so the caller can fall back to the emoji title.
static NSImage *tray_face_image(void) {
    char p[1024];
    if (!platform_resource_path(APP_TRAY_ICON, p, sizeof p)) {
#ifdef SHIB_DEV_TRAY_ICON
        snprintf(p, sizeof p, "%s", SHIB_DEV_TRAY_ICON);
#else
        return nil;
#endif
    }
    NSImage *img = [[[NSImage alloc] initWithContentsOfFile:
                        [NSString stringWithUTF8String:p]] autorelease];
    if (!img) return nil;
    // 18pt is the menu-bar art box; the 36px source lands 1:1 on retina. NOT a
    // template image — the logo is colored, and templates get flattened to a
    // monochrome silhouette.
    img.size = NSMakeSize(18, 18);
    return img;
}

// ── setup (called once, after the window exists; live mode only — demo keeps
//    stock close-quits behavior) ────────────────────────────────────────────────
void tray_setup(void) {
    Method m = class_getInstanceMethod([NSApp.delegate class],
                  @selector(applicationShouldTerminateAfterLastWindowClosed:));
    if (m) method_setImplementation(m, (IMP)no_term_after_last_close);
    class_addMethod([NSApp.delegate class],
                    @selector(applicationShouldHandleReopen:hasVisibleWindows:),
                    (IMP)reopen_shows_window, "c@:@c");
    class_addMethod([NSApp.delegate class],
                    @selector(applicationDockMenu:),
                    (IMP)dock_menu, "@@:@");

    g_target = [[TrayTarget alloc] init];
    // MRC file (no -fobjc-arc): the item comes back autoreleased, and an
    // NSStatusItem REMOVES ITSELF from the menu bar when deallocated — without
    // this retain the 🐸 vanished as soon as the first autorelease pool
    // drained, and every later tray_update poked a dead object.
    g_item = [[[NSStatusBar systemStatusBar]
                  statusItemWithLength:NSVariableStatusItemLength] retain];
    NSImage *face = tray_face_image();
    if (face) {
        g_item.button.image = face;
        g_item.button.imagePosition = NSImageOnly;
    } else {
        g_item.button.title = @APP_TRAY_FACE;   // emoji fallback, no asset
    }

    NSMenu *menu = [[NSMenu alloc] init];
    [[menu addItemWithTitle:[NSString stringWithUTF8String:TR(S_TRAY_OPEN)]
                     action:@selector(openApp:)
              keyEquivalent:@""] setTarget:g_target];
    [menu addItem:[NSMenuItem separatorItem]];
    for (int i = 0; i < TRAY_ROWS; i++) {
        g_rows[i] = [menu addItemWithTitle:@"…" action:nil keyEquivalent:@""];
        [g_rows[i] setEnabled:NO];
    }
    [menu addItem:[NSMenuItem separatorItem]];
    [[menu addItemWithTitle:[NSString stringWithUTF8String:TR(S_TRAY_QUIT)]
                     action:@selector(quitApp:)
              keyEquivalent:@"q"] setTarget:g_target];
    g_item.menu = menu;
    tray_update();                  // first titles now, not a second from now
}

// ── live status (called ~1 Hz from the frame loop, hidden or not) ─────────────
void tray_update(void) {
    if (!g_rows[0]) return;
    char l[TRAY_ROWS][64];
    status_lines(l);
    for (int i = 0; i < TRAY_ROWS; i++)
        g_rows[i].title = [NSString stringWithUTF8String:l[i]];
}

// ── minimize → tray: deminiaturize (kill the Dock tile) and hide warm ─────────
void tray_hide_window(void) {
    NSWindow *win = (NSWindow *)(uintptr_t)sapp_macos_get_window();
    if (!win) return;
    if (win.miniaturized) [win deminiaturize:nil];
    [win orderOut:nil];
}

// ── background start (--background, the login agent's flag): tray only ────────
// No window, no Dock tile — the menu-bar item is the whole app until Open /
// reopen restores it (show_app flips the policy back to Regular).
void tray_background_start(void) {
    tray_hide_window();
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
}

// ── test seams: drive the exact user paths headlessly ─────────────────────────
void tray_test_close(void) {              // the red button (performClose:)
    NSWindow *win = (NSWindow *)(uintptr_t)sapp_macos_get_window();
    [win performClose:nil];
}
void tray_test_quit(void) {               // the tray's Quit item
    [g_target quitApp:nil];
}
void tray_test_dump(void) {               // the menus' live status rows
    char l[TRAY_ROWS][64];
    status_lines(l);
    for (int i = 0; i < TRAY_ROWS; i++) fprintf(stderr, "TRAYROW %s\n", l[i]);
}

// ── quit decision (called from SAPP_EVENTTYPE_QUIT_REQUESTED) ──────────────────
// 1 = allow the quit; 0 = veto + hide the window warm. Always the latter now:
// real Quit goes through [NSApp terminate:], never through window close.
int tray_quit_requested(void) {
    NSWindow *win = (NSWindow *)(uintptr_t)sapp_macos_get_window();
    [win orderOut:nil];              // hide; engines keep running
    return 0;
}

// ── visibility (frame loop skips rendering while hidden) ───────────────────────
int platform_window_visible(void) {
    NSWindow *win = (NSWindow *)(uintptr_t)sapp_macos_get_window();
    return win ? (win.isVisible ? 1 : 0) : 1;
}
