// sysinstall_win.c — the Windows system-level web install (see sysinstall.h).
// Three pieces, two privilege levels — the mac layout, transposed:
//   • root CA trusted in the CURRENT USER Root store — UNPRIVILEGED, done
//     in-process (trust_win.c); Windows' own root-trust warning dialog IS the
//     consent (the keychain-auth analogue);
//   • the ".<tld>" DNS route — an NRPT rule (Namespace .pepe → 127.0.0.1),
//     PRIVILEGED, done by packaging/install-helper.ps1 behind ONE UAC prompt;
//   • the :443 path — nothing to install: Windows has no privileged ports, so
//     webproxy binds 127.0.0.1:443 directly whenever the app runs. A marker
//     file in the data dir records the consented install (the "planted"
//     state that survives quit — mac's pf-anchor analogue).
// Uninstall reverses cert + NRPT + marker. Quit leaves them planted but inert
// (dead :53/:443 = the legible "PepeNet is off" state).
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#include <wincrypt.h>
#include <wininet.h>

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

#define RUN_REG_KEY "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define NRPT_REG_KEY \
    "SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig"
#define INET_REG_KEY "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
#define PAC_URL "http://127.0.0.1:" APP_PAC_PORT_S "/proxy.pac"

// keep the CA identity deterministic no matter when the probe runs relative
// to webproxy_start (which sets the same three)
static void ca_ident(void) {
    static int done;
    if (done) return;
    char ddir[600];
    ca_set_dir((char *)platform_data_dir(ddir, sizeof ddir));
    ca_set_name(APP_DATA_DIR);
    ca_set_tld(APP_TLD);
    done = 1;
}

// resolve packaging/install-helper.ps1: bundled resources first (packaged
// installs), else the in-tree copy (dev runs; PEPENET_SRC overrides the root)
static const char *helper_path(char *buf, size_t cap) {
    if (platform_resource_path("install-helper.ps1", buf, cap) && buf[0]) return buf;
    const char *src = getenv("PEPENET_SRC");
    snprintf(buf, cap, "%s\\packaging\\install-helper.ps1", src ? src : ".");
    return buf;
}

// run the helper elevated (ONE UAC prompt) and wait; 1 = exit code 0
static int run_helper_elevated(const char *verb) {
    char helper[512], params[700];
    helper_path(helper, sizeof helper);
    snprintf(params, sizeof params,
             "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"%s\" %s " APP_TLD,
             helper, verb);
    SHELLEXECUTEINFOA sei;
    memset(&sei, 0, sizeof sei);
    sei.cbSize = sizeof sei;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    sei.lpVerb = "runas";                       // the UAC prompt = admin consent
    sei.lpFile = "powershell.exe";
    sei.lpParameters = params;
    sei.nShow = SW_HIDE;
    if (!ShellExecuteExA(&sei) || !sei.hProcess) return 0;   // declined / failed
    WaitForSingleObject(sei.hProcess, 120000);
    DWORD code = 1;
    GetExitCodeProcess(sei.hProcess, &code);
    CloseHandle(sei.hProcess);
    return code == 0;
}

// ── the PAC route (HKCU AutoConfigURL — unprivileged) ─────────────────────────
// The fourth piece of the web install, Windows-only: the NRPT rule dies under
// DNS-leak-blocking VPNs (their WFP filters drop every port-53 packet, loopback
// included), so browsers also get a proxy autoconfig URL at webproxy's front
// door. The PAC steers only *.<tld>; everything else stays DIRECT, and a dead
// front door (app off) makes browsers fall back to DIRECT — same "planted but
// inert" quit state as NRPT's dead :53. Never clobbers a foreign AutoConfigURL
// (a corporate PAC outranks us — the NRPT path still covers non-VPN use).

static void proxy_settings_refresh(void) {      // WinINET pickup + broadcast
    InternetSetOptionA(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    InternetSetOptionA(NULL, INTERNET_OPTION_REFRESH, NULL, 0);
}

static int pac_current(char *buf, DWORD cap) {
    HKEY h;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, INET_REG_KEY, 0, KEY_READ, &h) != ERROR_SUCCESS)
        return 0;
    DWORD type = 0, len = cap;
    int ok = RegQueryValueExA(h, "AutoConfigURL", NULL, &type,
                              (BYTE *)buf, &len) == ERROR_SUCCESS &&
             type == REG_SZ && len > 1;
    RegCloseKey(h);
    return ok;
}

static int pac_install(void) {
    char cur[1024];
    if (pac_current(cur, sizeof cur)) {
        if (!strcmp(cur, PAC_URL)) return 1;    // already ours
        fprintf(stderr, "sysinstall: AutoConfigURL is foreign (%s) — leaving it\n", cur);
        return 0;
    }
    HKEY h;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, INET_REG_KEY, 0, KEY_SET_VALUE, &h) != ERROR_SUCCESS)
        return 0;
    int ok = RegSetValueExA(h, "AutoConfigURL", 0, REG_SZ, (const BYTE *)PAC_URL,
                            (DWORD)strlen(PAC_URL) + 1) == ERROR_SUCCESS;
    RegCloseKey(h);
    if (ok) proxy_settings_refresh();
    return ok;
}

static void pac_uninstall(void) {
    char cur[1024];
    if (!pac_current(cur, sizeof cur) || strcmp(cur, PAC_URL) != 0) return;  // not ours
    HKEY h;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, INET_REG_KEY, 0, KEY_SET_VALUE, &h) != ERROR_SUCCESS)
        return;
    RegDeleteValueA(h, "AutoConfigURL");
    RegCloseKey(h);
    proxy_settings_refresh();
}

// ── probes ────────────────────────────────────────────────────────────────────
static int probe_ca(void) {
    ca_ident();
    wchar_t wcn[256];
    if (!MultiByteToWideChar(CP_UTF8, 0, ca_root_cn(), -1, wcn, 256)) return 0;
    HCERTSTORE st = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                                  CERT_SYSTEM_STORE_CURRENT_USER |
                                  CERT_STORE_READONLY_FLAG, "Root");
    if (!st) return 0;
    PCCERT_CONTEXT c = CertFindCertificateInStore(st, X509_ASN_ENCODING, 0,
                                                  CERT_FIND_SUBJECT_STR_W, wcn, NULL);
    int found = c != NULL;
    if (c) CertFreeCertificateContext(c);
    CertCloseStore(st, 0);
    return found;
}

// NRPT rules live as GUID subkeys under DnsPolicyConfig; ours carries
// Name = ".<tld>". Reading HKLM needs no privilege.
static int probe_nrpt(void) {
    HKEY root;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, NRPT_REG_KEY, 0,
                      KEY_READ, &root) != ERROR_SUCCESS)
        return 0;
    int found = 0;
    char sub[256];
    for (DWORD i = 0; !found; i++) {
        DWORD cap = sizeof sub;
        if (RegEnumKeyExA(root, i, sub, &cap, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        HKEY k;
        if (RegOpenKeyExA(root, sub, 0, KEY_READ, &k) != ERROR_SUCCESS) continue;
        char name[512];
        DWORD len = sizeof name, type = 0;
        if (RegQueryValueExA(k, "Name", NULL, &type, (BYTE *)name, &len) == ERROR_SUCCESS &&
            (type == REG_MULTI_SZ || type == REG_SZ)) {
            // REG_MULTI_SZ: first string suffices — we write exactly one
            if (!strcmp(name, "." APP_TLD)) found = 1;
        }
        RegCloseKey(k);
    }
    RegCloseKey(root);
    return found;
}

static const char *marker_path(char *buf, size_t cap) {
    return platform_data_path("webinstall-" APP_TLD, buf, cap);
}

void sysinstall_probe(InstallState *out) {
    memset(out, 0, sizeof *out);
    out->ca_trusted = probe_ca();
    out->resolver_file = probe_nrpt();
    struct stat st;
    char p[600];
    out->pf_anchor = stat(marker_path(p, sizeof p), &st) == 0;
    // self-heal the PAC route on consented installs (the marker IS the consent):
    // upgrades from pre-PAC builds and registry-scrubbing VPN clients both land
    // here. A cheap RegQuery per probe; the write fires only when it is missing.
    if (out->pf_anchor) {
        char cur[1024];
        if (!pac_current(cur, sizeof cur)) pac_install();
    }
}

// ── install / uninstall ───────────────────────────────────────────────────────
int sysinstall_install(void) {
    ca_ident();
    // 1) CA trust — unprivileged user-store op (Windows' own warning dialog)
    int ca = trust_install(ca_root_cert_path());
    // 2) the ".<tld>" DNS route — one UAC prompt via the helper (NRPT rule)
    int sys = run_helper_elevated("install");
    // 2b) the VPN-proof PAC route — unprivileged HKCU, best-effort like :443
    pac_install();
    // 3) Firefox trusts the OS store only with enterprise_roots — flip it in
    //    every profile's user.js (applies at Firefox's next start)
    sysinstall_firefox_roots();
    // 4) launch at login — the resolver/proxy live in-process, so "web access
    //    enabled" implies the app should come up with the machine
    sysinstall_loginitem_set(1);
    // 5) the consent marker (the "planted" state the probe reports)
    if (ca && sys) {
        char p[600];
        FILE *f = fopen(marker_path(p, sizeof p), "w");
        if (f) { fputs("installed\n", f); fclose(f); }
    }
    return ca && sys;
}

int sysinstall_uninstall(void) {
    ca_ident();
    trust_uninstall(ca_root_cert_path(), ca_root_cn());
    pac_uninstall();
    int sys = run_helper_elevated("uninstall");
    char p[600];
    remove(marker_path(p, sizeof p));
    return sys;
}

// ── launch at login (HKCU Run key) ────────────────────────────────────────────
int sysinstall_loginitem_state(void) {
    HKEY h;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, RUN_REG_KEY, 0, KEY_READ, &h) != ERROR_SUCCESS)
        return 0;
    DWORD len = 0;
    LONG rc = RegQueryValueExA(h, APP_NAME, NULL, NULL, NULL, &len);
    RegCloseKey(h);
    return rc == ERROR_SUCCESS && len > 0;
}

int sysinstall_loginitem_set(int on) {
    HKEY h;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, RUN_REG_KEY, 0, KEY_SET_VALUE, &h) != ERROR_SUCCESS)
        return 0;
    int ok;
    if (!on) {
        LONG rc = RegDeleteValueA(h, APP_NAME);
        ok = rc == ERROR_SUCCESS || rc == ERROR_FILE_NOT_FOUND;
    } else {
        char exe[1024], val[1060];
        ok = platform_executable_path(exe, sizeof exe);
        if (ok) {
            snprintf(val, sizeof val, "\"%s\"", exe);
            ok = RegSetValueExA(h, APP_NAME, 0, REG_SZ, (const BYTE *)val,
                                (DWORD)strlen(val) + 1) == ERROR_SUCCESS;
        }
    }
    RegCloseKey(h);
    return ok;
}

// Launch-at-login defaults ON: the first boot writes the Run-key value and
// drops a marker; from then on the Settings toggle is the only writer (so a
// user's OFF stays off). While the value exists it is rewritten each boot,
// keeping the executable path current across app moves and updates.
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
    snprintf(uj, sizeof uj, "%s\\user.js", profile_dir);
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
    const char *appdata = getenv("APPDATA");
    if (!appdata || !appdata[0]) return 0;
    snprintf(base, sizeof base, "%s\\Mozilla\\Firefox\\Profiles", appdata);
    DIR *d = opendir(base);
    if (!d) return 0;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char pd[700];
        snprintf(pd, sizeof pd, "%s\\%s", base, e->d_name);
        struct stat st;
        if (stat(pd, &st) == 0 && (st.st_mode & S_IFDIR) && userjs_flip(pd)) n++;
    }
    closedir(d);
    return n;
}

// ── first-run consent marker (identical to the mac path) ─────────────────────
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

#endif /* _WIN32 */
