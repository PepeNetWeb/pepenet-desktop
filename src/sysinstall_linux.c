// sysinstall_linux.c — Linux system-level web install (see sysinstall.h).
// Transposed from sysinstall.c / sysinstall_win.c:
//   • root CA in the user NSS db — UNPRIVILEGED, in-process (tls/src/trust.c);
//     certutil missing is a no-op, the helper plants the system store;
//   • system CA + systemd-resolved split-DNS + nft :443 rdr — PRIVILEGED,
//     packaging/install-helper-linux.sh via pkexec, or sudo if pkexec is
//     missing (Ubuntu server images, passwordless-sudo VMs);
//   • PAC autoconfig — UNPRIVILEGED (GNOME gsettings / KDE kwriteconfig),
//     the PRIMARY browser route (DoH skips OS DNS; nft is best-effort).
#if defined(__linux__) || defined(__unix__)
#ifndef _WIN32
#ifndef __APPLE__

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

#define PAC_URL "http://127.0.0.1:" APP_PAC_PORT_S "/proxy.pac"

static void ca_ident(void) {
    static int done;
    if (done) return;
    char ddir[600];
    ca_set_dir((char *)platform_data_dir(ddir, sizeof ddir));
    ca_set_name(APP_DATA_DIR);
    ca_set_tld(APP_TLD);
    done = 1;
}

static const char *helper_path(char *buf, size_t cap) {
    if (platform_resource_path("install-helper-linux.sh", buf, cap) && buf[0])
        return buf;
    const char *src = getenv("PEPENET_SRC");
    snprintf(buf, cap, "%s/packaging/install-helper-linux.sh",
             src && src[0] ? src : ".");
    return buf;
}

static int cmd_ok(const char *cmd) {
    FILE *p = popen(cmd, "r");
    if (!p) return 0;
    char buf[256];
    while (fgets(buf, sizeof buf, p)) { }
    return pclose(p) == 0;
}

// ── PAC (GNOME gsettings / KDE kioslaverc). Never clobber a foreign URL. ─────
static int gnome_pac_current(char *out, size_t cap) {
    if (out && cap) out[0] = 0;
    FILE *p = popen("gsettings get org.gnome.system.proxy autoconfig-url 2>/dev/null", "r");
    if (!p) return 0;
    char buf[512];
    if (!fgets(buf, sizeof buf, p)) { pclose(p); return 0; }
    pclose(p);
    // gsettings prints 'http://…' with single quotes; empty is ''
    char *s = buf;
    if (*s == '\'') s++;
    s[strcspn(s, "'\r\n")] = 0;
    if (!s[0]) return 0;
    if (out && cap) snprintf(out, cap, "%s", s);
    return 1;
}

static int gnome_mode_auto(void) {
    FILE *p = popen("gsettings get org.gnome.system.proxy mode 2>/dev/null", "r");
    if (!p) return 0;
    char buf[64];
    int ok = fgets(buf, sizeof buf, p) && strstr(buf, "auto") != NULL;
    pclose(p);
    return ok;
}

static int kde_pac_current(char *out, size_t cap) {
    if (out && cap) out[0] = 0;
    FILE *p = popen("kreadconfig5 --file kioslaverc --group 'Proxy Settings' "
                    "--key 'Proxy Config Script' 2>/dev/null", "r");
    if (!p) p = popen("kreadconfig6 --file kioslaverc --group 'Proxy Settings' "
                      "--key 'Proxy Config Script' 2>/dev/null", "r");
    if (!p) return 0;
    char buf[512];
    if (!fgets(buf, sizeof buf, p)) { pclose(p); return 0; }
    pclose(p);
    buf[strcspn(buf, "\r\n")] = 0;
    if (!buf[0]) return 0;
    if (out && cap) snprintf(out, cap, "%s", buf);
    return 1;
}

static int pac_ours(void) {
    char cur[512];
    if (gnome_pac_current(cur, sizeof cur) && gnome_mode_auto() &&
        !strcmp(cur, PAC_URL))
        return 1;
    if (kde_pac_current(cur, sizeof cur) && !strcmp(cur, PAC_URL))
        return 1;
    return 0;
}

static int pac_install(void) {
    char cur[512];
    if (gnome_pac_current(cur, sizeof cur) && gnome_mode_auto() &&
        strcmp(cur, PAC_URL) != 0) {
        fprintf(stderr, "sysinstall: GNOME PAC is foreign (%s) — leaving it\n", cur);
    } else if (cmd_ok("command -v gsettings >/dev/null")) {
        char cmd[400];
        snprintf(cmd, sizeof cmd,
                 "gsettings set org.gnome.system.proxy autoconfig-url '%s' && "
                 "gsettings set org.gnome.system.proxy mode auto", PAC_URL);
        cmd_ok(cmd);
    }
    if (kde_pac_current(cur, sizeof cur) && cur[0] && strcmp(cur, PAC_URL) != 0) {
        fprintf(stderr, "sysinstall: KDE PAC is foreign (%s) — leaving it\n", cur);
    } else if (cmd_ok("command -v kwriteconfig5 >/dev/null") ||
               cmd_ok("command -v kwriteconfig6 >/dev/null")) {
        const char *kw = cmd_ok("command -v kwriteconfig6 >/dev/null")
                       ? "kwriteconfig6" : "kwriteconfig5";
        char cmd[500];
        snprintf(cmd, sizeof cmd,
                 "%s --file kioslaverc --group 'Proxy Settings' --key ProxyType 2 && "
                 "%s --file kioslaverc --group 'Proxy Settings' "
                 "--key 'Proxy Config Script' '%s'", kw, kw, PAC_URL);
        cmd_ok(cmd);
    }
    return pac_ours();
}

static void pac_uninstall(void) {
    char cur[512];
    if (gnome_pac_current(cur, sizeof cur) && !strcmp(cur, PAC_URL)) {
        cmd_ok("gsettings set org.gnome.system.proxy mode none");
        cmd_ok("gsettings reset org.gnome.system.proxy autoconfig-url");
    }
    if (kde_pac_current(cur, sizeof cur) && !strcmp(cur, PAC_URL)) {
        const char *kw = cmd_ok("command -v kwriteconfig6 >/dev/null")
                       ? "kwriteconfig6" : "kwriteconfig5";
        char cmd[400];
        snprintf(cmd, sizeof cmd,
                 "%s --file kioslaverc --group 'Proxy Settings' --key ProxyType 0 && "
                 "%s --file kioslaverc --group 'Proxy Settings' "
                 "--key 'Proxy Config Script' ''", kw, kw);
        cmd_ok(cmd);
    }
}

static int probe_ca(void) {
    struct stat st;
    if (stat("/usr/local/share/ca-certificates/pepenet-" APP_TLD ".crt", &st) == 0)
        return 1;
    if (stat("/etc/pki/ca-trust/source/anchors/pepenet-" APP_TLD ".crt", &st) == 0)
        return 1;
    return 0;
}

static int probe_resolver(void) {
    return cmd_ok("resolvectl domain lo 2>/dev/null | grep -q '" APP_TLD "'");
}

static int probe_nft(void) {
    return cmd_ok("nft list table ip pepenet-" APP_TLD " >/dev/null 2>&1");
}

static int have_bin(const char *name) {
    char cmd[160];
    snprintf(cmd, sizeof cmd, "command -v %s >/dev/null 2>&1", name);
    return cmd_ok(cmd);
}

static int run_helper(const char *verb) {
    char helper[512], args[1200], cmd[1600];
    helper_path(helper, sizeof helper);
    ca_ident();
    if (!strcmp(verb, "install")) {
        snprintf(args, sizeof args,
                 "/bin/sh \"%s\" install " APP_TLD
                 " --dns-port " APP_DNS_PORT_S
                 " --proxy-port " APP_PROXY_PF_PORT_S
                 " --pac-port " APP_PAC_PORT_S
                 " --cert \"%s\"",
                 helper, ca_root_cert_path());
    } else {
        snprintf(args, sizeof args, "/bin/sh \"%s\" uninstall " APP_TLD, helper);
    }
    // Already root: no elevator. Else pkexec (polkit GUI) if present —
    // Ubuntu desktop. Else sudo, for passwordless-sudo boxes that do not
    // ship pkexec (this VM, Ubuntu server).
    if (geteuid() == 0) {
        snprintf(cmd, sizeof cmd, "%s", args);
        return cmd_ok(cmd);
    }
    if (have_bin("pkexec")) {
        snprintf(cmd, sizeof cmd, "pkexec %s", args);
        return cmd_ok(cmd);
    }
    if (have_bin("sudo")) {
        snprintf(cmd, sizeof cmd, "sudo %s", args);
        return cmd_ok(cmd);
    }
    fprintf(stderr, "sysinstall: neither pkexec nor sudo found\n");
    return 0;
}

void sysinstall_probe(InstallState *out) {
    memset(out, 0, sizeof *out);
    ca_ident();
    out->ca_trusted    = probe_ca();
    out->resolver_file = probe_resolver();
    out->pf_anchor     = probe_nft();
    out->pac_on        = pac_ours();
}

int sysinstall_install(void) {
    ca_ident();
    trust_install(ca_root_cert_path());          // nssdb; best-effort
    int sys = run_helper("install");
    pac_install();
    sysinstall_firefox_roots();
    sysinstall_loginitem_set(1);
    return sys;
}

int sysinstall_uninstall(void) {
    ca_ident();
    trust_uninstall(ca_root_cert_path(), ca_root_cn());
    pac_uninstall();
    return run_helper("uninstall");
}

int sysinstall_loginitem_state(void) { return platform_loginitem_state(); }
int sysinstall_loginitem_set(int on) { return platform_loginitem_set(on); }

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

static int userjs_flip(const char *profile_dir) {
    char uj[700];
    snprintf(uj, sizeof uj, "%s/user.js", profile_dir);
    FILE *f = fopen(uj, "r");
    if (f) {
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
    snprintf(base, sizeof base, "%s/.mozilla/firefox",
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
    char p[512]; struct stat st;
    return stat(consent_path(p, sizeof p), &st) == 0;
}
void sysinstall_consent_mark(void) {
    char p[512];
    FILE *f = fopen(consent_path(p, sizeof p), "w");
    if (f) { fputs("answered\n", f); fclose(f); }
}

static const char *webpref_path(char *buf, size_t cap) {
    return platform_data_path("webaccess-" APP_TLD, buf, cap);
}
int sysinstall_web_wanted(void) {
    char p[512];
    FILE *f = fopen(webpref_path(p, sizeof p), "r");
    if (!f) return -1;
    int c = fgetc(f);
    fclose(f);
    return c == '1';
}
void sysinstall_web_set(int on) {
    char p[512];
    FILE *f = fopen(webpref_path(p, sizeof p), "w");
    if (f) { fputc(on ? '1' : '0', f); fclose(f); }
}

static const char *fgstart_path(char *buf, size_t cap) {
    return platform_data_path("fgstart-" APP_TLD, buf, cap);
}
static const char *bgstart_legacy(char *buf, size_t cap) {
    return platform_data_path("bgstart-" APP_TLD, buf, cap);
}
int sysinstall_bgstart_state(void) {
    char p[512]; struct stat st;
    return stat(fgstart_path(p, sizeof p), &st) != 0;   // default ON
}
void sysinstall_bgstart_set(int on) {
    char p[512];
    remove(bgstart_legacy(p, sizeof p));
    if (on) {
        remove(fgstart_path(p, sizeof p));
    } else {
        FILE *f = fopen(fgstart_path(p, sizeof p), "w");
        if (f) { fputs("1\n", f); fclose(f); }
    }
}

#endif
#endif
#endif
