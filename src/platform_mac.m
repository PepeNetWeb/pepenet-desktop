// platform_mac.m — the macOS implementation of the stateless platform.h
// primitives (paths, executable location, bundled resources, launching a URL,
// revealing a file). The windowing halves (platform_style_window,
// platform_window_visible) live with the code that owns the NSWindow —
// sokol_impl.m and tray.m respectively. See platform.h.
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <Security/Security.h>
#import <ServiceManagement/ServiceManagement.h>

#include "platform.h"
#include "appconf.h"     // APP_DATA_DIR (the default data-folder name)

#include <mach-o/dyld.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

extern char **environ;

// ── persisted app config (NSUserDefaults) ─────────────────────────────────────
// A tiny key/value store that lives OUTSIDE the data directory (so it survives a
// relocation of the data dir itself). Used for the user-chosen data-dir path.
int platform_config_get(const char *key, char *out, size_t cap) {
    if (!key || !out || !cap) return 0;
    out[0] = 0;
    NSString *k = [NSString stringWithUTF8String:key];
    NSString *v = [[NSUserDefaults standardUserDefaults] stringForKey:k];
    if (!v || v.length == 0) return 0;
    snprintf(out, cap, "%s", v.UTF8String);
    return 1;
}
int platform_config_set(const char *key, const char *val) {
    if (!key) return 0;
    NSString *k = [NSString stringWithUTF8String:key];
    NSUserDefaults *d = [NSUserDefaults standardUserDefaults];
    if (val && val[0]) [d setObject:[NSString stringWithUTF8String:val] forKey:k];
    else               [d removeObjectForKey:k];   // empty = clear the override
    [d synchronize];
    return 1;
}

// ── filesystem locations ──────────────────────────────────────────────────────
const char *platform_data_dir(char *out, size_t cap) {
    // a user-chosen absolute path (Settings › Change location) wins; otherwise
    // the per-instance default folder ~/.<APP_DATA_DIR>.
    char over[600];
    if (platform_config_get("data_dir", over, sizeof over) && over[0] == '/') {
        snprintf(out, cap, "%s", over);
    } else {
        const char *home = getenv("HOME");
        if (!home || !home[0]) home = ".";
        snprintf(out, cap, "%s/.%s", home, APP_DATA_DIR);
    }
    mkdir(out, 0755);                       // idempotent; ignore EEXIST
    return out;
}

// Modal folder chooser (Settings › Change location). Runs on the calling
// thread's run loop — invoked from the UI thread. 1 + absolute path on OK.
int platform_choose_directory(char *out, size_t cap) {
    if (!out || !cap) return 0;
    out[0] = 0;
    NSOpenPanel *p = [NSOpenPanel openPanel];
    p.canChooseDirectories = YES;
    p.canChooseFiles = NO;
    p.allowsMultipleSelection = NO;
    p.canCreateDirectories = YES;
    p.prompt = @"Choose";
    if ([p runModal] != NSModalResponseOK || p.URLs.count == 0) return 0;
    NSString *path = p.URLs.firstObject.path;
    if (!path || path.length == 0) return 0;
    snprintf(out, cap, "%s", path.UTF8String);
    return 1;
}

const char *platform_data_path(const char *name, char *out, size_t cap) {
    char dir[600];
    platform_data_dir(dir, sizeof dir);
    snprintf(out, cap, "%s/%s", dir, name);
    return out;
}

int platform_executable_path(char *out, size_t cap) {
    if (!out || !cap) return 0;
    uint32_t sz = (uint32_t)cap;
    return _NSGetExecutablePath(out, &sz) == 0;
}

// Packaged app: the bundle's Resources directory. Dev runs (no bundle path
// match): the caller's fallback into the source tree handles it.
int platform_resource_path(const char *name, char *out, size_t cap) {
    if (out && cap) out[0] = '\0';
    if (!name || !out || !cap) return 0;
    NSString *n = [NSString stringWithUTF8String:name];
    NSString *res = [[NSBundle mainBundle] resourcePath];
    if (!res) return 0;
    NSString *p = [res stringByAppendingPathComponent:n];
    if (![[NSFileManager defaultManager] fileExistsAtPath:p]) return 0;
    snprintf(out, cap, "%s", p.UTF8String);
    return 1;
}

// ── launching ─────────────────────────────────────────────────────────────────
void platform_open_url(const char *url) {
    if (!url || !url[0]) return;
    char *argv[] = { "/usr/bin/open", (char *)url, NULL };
    pid_t pid;
    posix_spawn(&pid, "/usr/bin/open", NULL, NULL, argv, environ);
}

void platform_reveal_file(const char *path) {
    if (!path || !path[0]) return;
    char *argv[] = { "/usr/bin/open", "-R", (char *)path, NULL };
    pid_t pid;
    posix_spawn(&pid, "/usr/bin/open", NULL, NULL, argv, environ);
}

// ── secret storage (Keychain generic-password items) ──────────────────────────
// The keychain "service" is the PER-INSTANCE namespace, keyed off appconf's data
// dir name (this build: "pepenet") — NOT the base protocol name — so PepeNet and
// any sibling build keep separate keys. $PEPENET_KEYCHAIN_SERVICE overrides it
// (test isolation).
static CFStringRef kc_service(void) {
    const char *s = getenv("PEPENET_KEYCHAIN_SERVICE");
    return CFStringCreateWithCString(NULL, (s && s[0]) ? s : APP_DATA_DIR,
                                     kCFStringEncodingUTF8);
}

// ── launch-at-login (SMAppService, macOS 13+) ─────────────────────────────────
// The agent plist ships INSIDE the bundle (Contents/Library/LaunchAgents) and
// is registered by name — that is what makes the Login Items UI and the "runs
// in the background" notification say the app's name instead of the signing
// identity's legal name. -1 = API unavailable (pre-13); sysinstall.c then
// falls back to its legacy hand-written ~/Library/LaunchAgents plist.
static SMAppService *loginitem_svc(void) API_AVAILABLE(macos(13.0)) {
    return [SMAppService agentServiceWithPlistName:@"com.pepenet.app.plist"];
}

int platform_loginitem_state(void) {
    if (@available(macOS 13.0, *))
        return loginitem_svc().status == SMAppServiceStatusEnabled ? 1 : 0;
    return -1;
}

int platform_loginitem_set(int on) {
    if (@available(macOS 13.0, *)) {
        NSError *err = nil;
        if (on) {
            // an already-registered agent errors — the status check below is
            // the truth either way
            [loginitem_svc() registerAndReturnError:&err];
            int ok = loginitem_svc().status == SMAppServiceStatusEnabled;
            if (!ok && err)
                fprintf(stderr, "loginitem: register failed: %s\n",
                        err.localizedDescription.UTF8String);
            return ok;
        }
        [loginitem_svc() unregisterAndReturnError:&err];
        return 1;
    }
    return -1;
}

int platform_secret_get(const char *account, uint8_t *out, size_t cap) {
    if (!account || !out || !cap) return 0;
    CFStringRef svc = kc_service();
    CFStringRef acct = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    const void *k[] = { kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecMatchLimit };
    const void *v[] = { kSecClassGenericPassword, svc, acct, kCFBooleanTrue, kSecMatchLimitOne };
    CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, 5,
                          &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFTypeRef data = NULL;
    OSStatus st = SecItemCopyMatching(q, &data);
    CFRelease(q); CFRelease(svc); CFRelease(acct);
    // Only errSecItemNotFound means "no item". Everything else (errSecAuthFailed,
    // errSecUserCanceled, errSecInteractionNotAllowed, …) means an item may exist
    // that we were not allowed to read — report -1 so the caller never mistakes a
    // denied wallet key for an absent one and mints a replacement over it.
    int n = st == errSecItemNotFound ? 0 : -1;
    if (st == errSecSuccess && data) {
        CFDataRef d = (CFDataRef)data;
        CFIndex len = CFDataGetLength(d);
        if (len > 0 && (size_t)len <= cap) { memcpy(out, CFDataGetBytePtr(d), (size_t)len); n = (int)len; }
    }
    if (data) CFRelease(data);
    return n;
}

int platform_secret_set(const char *account, const uint8_t *secret, size_t len) {
    if (!account || !secret || !len) return 0;
    CFStringRef svc = kc_service();
    CFStringRef acct = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    CFDataRef payload = CFDataCreate(NULL, secret, (CFIndex)len);
    // update the item if present, else add it (this-device-only, unlocked)
    const void *qk[] = { kSecClass, kSecAttrService, kSecAttrAccount };
    const void *qv[] = { kSecClassGenericPassword, svc, acct };
    CFDictionaryRef query = CFDictionaryCreate(NULL, qk, qv, 3,
                              &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    const void *uk[] = { kSecValueData };
    const void *uv[] = { payload };
    CFDictionaryRef upd = CFDictionaryCreate(NULL, uk, uv, 1,
                            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    OSStatus st = SecItemUpdate(query, upd);
    if (st == errSecItemNotFound) {
        const void *ak[] = { kSecClass, kSecAttrService, kSecAttrAccount, kSecValueData, kSecAttrAccessible };
        const void *av[] = { kSecClassGenericPassword, svc, acct, payload,
                             kSecAttrAccessibleWhenUnlockedThisDeviceOnly };
        CFDictionaryRef add = CFDictionaryCreate(NULL, ak, av, 5,
                                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        st = SecItemAdd(add, NULL);
        CFRelease(add);
    }
    CFRelease(query); CFRelease(upd); CFRelease(payload); CFRelease(svc); CFRelease(acct);
    return st == errSecSuccess;
}

int platform_secret_del(const char *account) {
    if (!account) return 0;
    CFStringRef svc = kc_service();
    CFStringRef acct = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    const void *qk[] = { kSecClass, kSecAttrService, kSecAttrAccount };
    const void *qv[] = { kSecClassGenericPassword, svc, acct };
    CFDictionaryRef q = CFDictionaryCreate(NULL, qk, qv, 3,
                          &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    OSStatus st = SecItemDelete(q);
    CFRelease(q); CFRelease(svc); CFRelease(acct);
    return st == errSecSuccess || st == errSecItemNotFound;
}
