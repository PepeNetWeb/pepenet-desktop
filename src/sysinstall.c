// sysinstall.c — see sysinstall.h.
#include "sysinstall.h"
#include "appconf.h"
#include "platform.h"
#include "ca.h"
#include "trust.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// resolve packaging/install-helper.sh: bundled Resources first (packaged app),
// else the in-tree copy (dev runs). Mirrors the font-path fallback.
static const char *helper_path(char *buf, size_t cap) {
    if (platform_resource_path("install-helper.sh", buf, cap) && buf[0]) return buf;
    snprintf(buf, cap, "%s/packaging/install-helper.sh",
             getenv("PEPENET_SRC") ? getenv("PEPENET_SRC")
                                   : "/Volumes/Storage/source/pepenet/pepenet-desktop");
    return buf;
}

static int cmd_ok(const char *cmd) {          // 1 if the command exits 0
    FILE *p = popen(cmd, "r");
    if (!p) return 0;
    char buf[256];
    while (fgets(buf, sizeof buf, p)) { /* drain */ }
    return pclose(p) == 0;
}

void sysinstall_probe(InstallState *out) {
    memset(out, 0, sizeof *out);

    char cmd[512];
    // CA: `security find-certificate -c <cn>` in the login keychain
    snprintf(cmd, sizeof cmd,
             "security find-certificate -c '%s' >/dev/null 2>&1", ca_root_cn());
    out->ca_trusted = cmd_ok(cmd);

    // resolver file
    struct stat st;
    out->resolver_file = (stat("/etc/resolver/" APP_TLD, &st) == 0);

    // pf rdr: `pfctl -sn` needs root (/dev/pf) — as the user it prints
    // "Permission denied" forever and the old probe lied "not loaded" while
    // the redirect was in fact installed (and Discover's web_ready gate went
    // false with it). Probe the two world-readable files the helper plants
    // instead: the anchor and its /etc/pf.conf hook.
    out->pf_anchor = 0;
    if (stat("/etc/pf.anchors/" APP_PF_ANCHOR, &st) == 0) {
        FILE *f = fopen("/etc/pf.conf", "r");
        if (f) {
            char line[512];
            while (fgets(line, sizeof line, f))
                if (strstr(line, "\"" APP_PF_ANCHOR "\"")) { out->pf_anchor = 1; break; }
            fclose(f);
        }
    }
}

int sysinstall_install(void) {
    ca_set_tld(APP_TLD);
    // 1) CA trust — unprivileged login-keychain op (its own GUI auth prompt)
    int ca = trust_install(ca_root_cert_path());
    // 2) resolver + pf — one admin prompt via osascript wrapping the helper
    char helper[512], script[1024];
    helper_path(helper, sizeof helper);
    snprintf(script, sizeof script,
             "osascript -e 'do shell script \"/bin/sh \\\"%s\\\" install " APP_TLD " "
             "--dns-port " APP_DNS_PORT_S " --proxy-port " APP_PROXY_PORT_S "\" "
             "with administrator privileges' >/dev/null 2>&1",
             helper);
    int sys = cmd_ok(script);
    // 3) Firefox trusts the keychain only with enterprise_roots — flip it in
    //    every profile's user.js (applies at Firefox's next start)
    sysinstall_firefox_roots();
    // 4) launch at login — the resolver/proxy live in-process, so "web access
    //    enabled" implies the app should come up with the machine
    sysinstall_loginitem_set(1);
    return ca && sys;
}

// ── launch at login (LaunchAgent) ────────────────────────────────────────────
static const char *agent_path(char *buf, size_t cap) {
    const char *home = getenv("HOME");
    snprintf(buf, cap, "%s/Library/LaunchAgents/" APP_BUNDLE_ID ".plist",
             home && home[0] ? home : ".");
    return buf;
}

int sysinstall_loginitem_state(void) {
    char p[512];
    struct stat st;
    int legacy = stat(agent_path(p, sizeof p), &st) == 0;
    int r = platform_loginitem_state();
    if (r < 0) return legacy;
    return r || legacy;     // an unmigrated legacy agent still counts as ON
}

int sysinstall_loginitem_set(int on) {
    char p[512];
    agent_path(p, sizeof p);
    int r = platform_loginitem_set(on);
    if (r >= 0) {
        // SMAppService took the registration (attributed to the APP in Login
        // Items). Retire any legacy hand-written agent — it surfaced the
        // signing identity's LEGAL NAME in the background-items UI: silence
        // the live registration, then remove the file.
        struct stat st;
        if (stat(p, &st) == 0) {
            char cmd[600];
            snprintf(cmd, sizeof cmd,
                     "launchctl bootout gui/%ld/" APP_BUNDLE_ID " >/dev/null 2>&1",
                     (long)getuid());
            cmd_ok(cmd);
            unlink(p);
        }
        return r;
    }
    // legacy fallback (macOS < 13): the hand-written ~/Library/LaunchAgents plist
    if (!on) return unlink(p) == 0 || 1;
    char exe[1024];
    if (!platform_executable_path(exe, sizeof exe)) return 0;
    char dir[512];
    const char *home = getenv("HOME");
    snprintf(dir, sizeof dir, "%s/Library/LaunchAgents", home && home[0] ? home : ".");
    mkdir(dir, 0755);
    FILE *f = fopen(p, "w");
    if (!f) return 0;
    fprintf(f,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\"><dict>\n"
        "  <key>Label</key><string>" APP_BUNDLE_ID "</string>\n"
        // --background: a login launch starts hidden (tray only, no window)
        "  <key>ProgramArguments</key><array><string>%s</string>"
        "<string>--background</string></array>\n"
        "  <key>RunAtLoad</key><true/>\n"
        "</dict></plist>\n", exe);
    fclose(f);
    return 1;
}

// Launch-at-login defaults ON: the first boot plants the agent and drops a
// marker; from then on the Settings toggle is the only writer (so a user's
// OFF stays off). While the agent exists it is rewritten each boot, keeping
// the executable path and arguments current across app moves and updates.
void sysinstall_loginitem_default(void) {
    char p[512];
    struct stat st;
    platform_data_path("autostart-" APP_TLD, p, sizeof p);
    if (stat(p, &st) != 0) {
        sysinstall_loginitem_set(1);
        FILE *f = fopen(p, "w");
        if (f) { fputs("applied\n", f); fclose(f); }
    } else if (sysinstall_loginitem_state()) {
        sysinstall_loginitem_set(1);
    }
}

// ── Firefox enterprise-roots pref ────────────────────────────────────────────
static int userjs_flip(const char *profile_dir) {
    char uj[700];
    snprintf(uj, sizeof uj, "%s/user.js", profile_dir);
    FILE *f = fopen(uj, "r");
    if (f) {                                     // already set?
        char line[512];
        while (fgets(line, sizeof line, f))
            if (strstr(line, "security.enterprise_roots.enabled")) {
                fclose(f);
                return 1;
            }
        fclose(f);
    }
    f = fopen(uj, "a");
    if (!f) return 0;
    fputs("user_pref(\"security.enterprise_roots.enabled\", true);\n", f);
    fclose(f);
    return 1;
}

int sysinstall_firefox_roots(void) {
    char base[600];
    const char *home = getenv("HOME");
    snprintf(base, sizeof base, "%s/Library/Application Support/Firefox/Profiles",
             home && home[0] ? home : ".");
    DIR *d = opendir(base);
    if (!d) return 0;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char pd[700];
        snprintf(pd, sizeof pd, "%s/%s", base, e->d_name);
        struct stat st;
        if (stat(pd, &st) == 0 && S_ISDIR(st.st_mode) && userjs_flip(pd)) n++;
    }
    closedir(d);
    return n;
}

static const char *consent_path(char *buf, size_t cap) {
    return platform_data_path("consent-" APP_TLD, buf, cap);
}

int sysinstall_consent_seen(void) {
    char p[512];
    struct stat st;
    return stat(consent_path(p, sizeof p), &st) == 0;
}

void sysinstall_consent_mark(void) {
    char p[512];
    FILE *f = fopen(consent_path(p, sizeof p), "w");
    if (f) { fputs("answered\n", f); fclose(f); }
}

int sysinstall_uninstall(void) {
    ca_set_tld(APP_TLD);
    trust_uninstall(ca_root_cert_path(), ca_root_cn());
    char helper[512], script[1024];
    helper_path(helper, sizeof helper);
    snprintf(script, sizeof script,
             "osascript -e 'do shell script \"/bin/sh \\\"%s\\\" uninstall " APP_TLD "\" "
             "with administrator privileges' >/dev/null 2>&1",
             helper);
    return cmd_ok(script);
}
