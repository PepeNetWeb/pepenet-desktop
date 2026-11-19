/* trust.c — see trust.h. */
#include "trust.h"
#include "ca.h"

#include <openssl/pem.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Only the in-process name-constrained root may enter a trust store. The PEM
 * on disk is user-writable; we refuse a swapped unconstrained CA, then plant
 * a temp copy of the in-memory cert so the install isn't a TOCTOU on the path. */
static int file_is_our_root(const char *certpath) {
    X509 *want = NULL; EVP_PKEY *k = NULL;
    if (!ca_root_ensure(&want, &k)) return 0;
    FILE *f = fopen(certpath, "rb");
    X509 *got = f ? PEM_read_X509(f, NULL, NULL, NULL) : NULL;
    if (f) fclose(f);
    int ok = got && X509_cmp(want, got) == 0;
    if (got) X509_free(got);
    X509_free(want); EVP_PKEY_free(k);
    return ok;
}
static int seal_root_tmp(char *path, size_t cap) {
    X509 *want = NULL; EVP_PKEY *k = NULL;
    if (!ca_root_ensure(&want, &k)) return 0;
    snprintf(path, cap, "/tmp/pepenet-root-XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) { X509_free(want); EVP_PKEY_free(k); return 0; }
    fchmod(fd, 0600);
    FILE *f = fdopen(fd, "w");
    int ok = f && PEM_write_X509(f, want);
    if (f) fclose(f); else close(fd);
    X509_free(want); EVP_PKEY_free(k);
    if (!ok) { unlink(path); return 0; }
    return 1;
}

#ifdef __APPLE__
/* -r trustRoot marks it a trusted anchor; no -d ⇒ the user login keychain
 * (unprivileged). macOS pops a GUI auth dialog to change trust settings —
 * expected: the operator is consenting to install this root. */
int trust_install(const char *certpath) {
    if (!file_is_our_root(certpath)) {
        fprintf(stderr, "trust_install: refusing PEM that is not this process's "
                        "name-constrained root\n");
        return 0;
    }
    char tmp[256];
    if (!seal_root_tmp(tmp, sizeof tmp)) return 0;
    char cmd[1400];
    snprintf(cmd, sizeof cmd,
        "security add-trusted-cert -r trustRoot "
        "-k \"$HOME/Library/Keychains/login.keychain-db\" \"%s\"",
        tmp);
    int ok = system(cmd) == 0;
    unlink(tmp);
    return ok;
}

int trust_uninstall(const char *certpath, const char *cn) {
    char cmd[1400];
    /* Drop trust settings, then delete the cert by CN (the active TLD's root,
     * e.g. "pepenet .doge root CA"). Both best-effort so an already-partly-
     * removed state still returns cleanly. */
    snprintf(cmd, sizeof cmd,
        "security remove-trusted-cert \"%s\" 2>/dev/null; "
        "security delete-certificate -c \"%s\" "
        "\"$HOME/Library/Keychains/login.keychain-db\" 2>/dev/null; true",
        certpath, cn);
    return system(cmd) == 0;
}

#elif defined(__linux__)

/* Nickname in the NSS db: the cert file's basename without .crt
 * (e.g. ~/.pepenet/pepenet-root-pepe.crt → "pepenet-root-pepe"). Stable
 * across install/uninstall without needing the CN at install time. */
static void nss_nick(const char *certpath, char *out, size_t cap) {
    const char *b = certpath ? strrchr(certpath, '/') : NULL;
    b = b ? b + 1 : (certpath ? certpath : "pepenet-root");
    snprintf(out, cap, "%s", b);
    size_t n = strlen(out);
    if (n > 4 && strcmp(out + n - 4, ".crt") == 0) out[n - 4] = 0;
}

static int have_certutil(void) {
    return system("command -v certutil >/dev/null 2>&1") == 0;
}

static int nssdb_path(char *out, size_t cap) {
    const char *home = getenv("HOME");
    if (!home || !home[0]) return 0;
    snprintf(out, cap, "%s/.pki/nssdb", home);
    return 1;
}

static int is_dir(const char *p) {
    struct stat st;
    return p && stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

static int nssdb_ensure(const char *dir) {
    char cmd[700];
    snprintf(cmd, sizeof cmd, "mkdir -p \"%s\"", dir);
    if (system(cmd) != 0) return 0;
    char db[600];
    snprintf(db, sizeof db, "%s/cert9.db", dir);
    struct stat st;
    if (stat(db, &st) == 0) return 1;
    /* empty-password: this is a per-user TLS trust db, not a login keyring.
     * Chromium creates the same db the same way. */
    snprintf(cmd, sizeof cmd,
             "certutil -N -d sql:\"%s\" --empty-password >/dev/null 2>&1", dir);
    return system(cmd) == 0;
}

static int nss_add(const char *dir, const char *nick, const char *certpath) {
    char cmd[1800];
    if (!dir || !dir[0] || !nssdb_ensure(dir)) return 0;
    snprintf(cmd, sizeof cmd,
        "certutil -D -d sql:\"%s\" -n \"%s\" >/dev/null 2>&1; "
        "certutil -A -d sql:\"%s\" -t \"C,,\" -n \"%s\" -i \"%s\"",
        dir, nick, dir, nick, certpath);
    return system(cmd) == 0;
}

static int nss_del(const char *dir, const char *nick) {
    char cmd[900], db[600];
    struct stat st;
    if (!dir || !dir[0]) return 1;
    snprintf(db, sizeof db, "%s/cert9.db", dir);
    if (stat(db, &st) != 0) return 1;
    snprintf(cmd, sizeof cmd,
             "certutil -D -d sql:\"%s\" -n \"%s\" >/dev/null 2>&1; true",
             dir, nick);
    return system(cmd) == 0;
}

static void nss_add_under(const char *parent, const char *nick, const char *certpath) {
    char a[700], b[700];
    if (!is_dir(parent)) return;
    snprintf(a, sizeof a, "%s/.pki/nssdb", parent);
    snprintf(b, sizeof b, "%s/.local/share/pki/nssdb", parent);
    nss_add(a, nick, certpath);
    nss_add(b, nick, certpath);
}

static void nss_del_under(const char *parent, const char *nick) {
    char a[700], b[700];
    if (!is_dir(parent)) return;
    snprintf(a, sizeof a, "%s/.pki/nssdb", parent);
    snprintf(b, sizeof b, "%s/.local/share/pki/nssdb", parent);
    nss_del(a, nick);
    nss_del(b, nick);
}

/* Snap Chromium (and some Chromium builds) ignore the host p11-kit store and
 * keep a private NSS db under ~/snap/chromium/<rev>/. Plant every revision
 * we can see, plus current/ and common/. */
static void nss_chromium_snaps(const char *home, const char *nick, const char *certpath, int add) {
    char root[600];
    snprintf(root, sizeof root, "%s/snap/chromium", home);
    if (!is_dir(root)) return;
    DIR *d = opendir(root);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char rev[700];
        snprintf(rev, sizeof rev, "%s/%s", root, e->d_name);
        if (!is_dir(rev)) continue;
        if (add) nss_add_under(rev, nick, certpath);
        else     nss_del_under(rev, nick);
    }
    closedir(d);
}

/* Firefox NSS lives in the profile (cert9.db), not ~/.pki/nssdb. Snap Firefox
 * keeps profiles under ~/snap/firefox/common/.mozilla/firefox/. */
static void nss_firefox_profiles(const char *base, const char *nick, const char *certpath, int add) {
    DIR *d = opendir(base);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char pd[800], prefs[820], certdb[820];
        snprintf(pd, sizeof pd, "%s/%s", base, e->d_name);
        struct stat st;
        if (stat(pd, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        snprintf(prefs, sizeof prefs, "%s/prefs.js", pd);
        snprintf(certdb, sizeof certdb, "%s/cert9.db", pd);
        if (stat(prefs, &st) != 0 && stat(certdb, &st) != 0) continue;
        if (add) nss_add(pd, nick, certpath);
        else     nss_del(pd, nick);
    }
    closedir(d);
}

int trust_install(const char *certpath) {
    if (!certpath || !certpath[0]) return 0;
    if (!file_is_our_root(certpath)) {
        fprintf(stderr, "trust_install: refusing PEM that is not this process's "
                        "name-constrained root\n");
        return 0;
    }
    /* No certutil → cannot write NSS. Deb Chromium/curl still pick the root
     * up from the system store; Snap Chromium/Firefox will not. */
    if (!have_certutil()) {
        fprintf(stderr, "trust_install: certutil missing (apt install libnss3-tools); "
                        "Snap Chromium/Firefox will reject the .pepe root\n");
        return 1;
    }
    const char *home = getenv("HOME");
    if (!home || !home[0]) return 0;
    char tmp[256];
    if (!seal_root_tmp(tmp, sizeof tmp)) return 0;
    char dir[512], nick[128], ff[700];
    nss_nick(certpath, nick, sizeof nick);
    int ok = nssdb_path(dir, sizeof dir) && nss_add(dir, nick, tmp);
    if (ok) {
        nss_chromium_snaps(home, nick, tmp, 1);
        snprintf(ff, sizeof ff, "%s/.mozilla/firefox", home);
        nss_firefox_profiles(ff, nick, tmp, 1);
        snprintf(ff, sizeof ff, "%s/snap/firefox/common/.mozilla/firefox", home);
        nss_firefox_profiles(ff, nick, tmp, 1);
        snprintf(ff, sizeof ff, "%s/snap/firefox/current/.mozilla/firefox", home);
        nss_firefox_profiles(ff, nick, tmp, 1);
    }
    unlink(tmp);
    return ok;
}

int trust_uninstall(const char *certpath, const char *cn) {
    (void)cn;
    if (!have_certutil()) return 1;
    const char *home = getenv("HOME");
    if (!home || !home[0]) return 1;
    char dir[512], nick[128], ff[700];
    nss_nick(certpath, nick, sizeof nick);
    if (nssdb_path(dir, sizeof dir)) nss_del(dir, nick);
    nss_chromium_snaps(home, nick, NULL, 0);
    snprintf(ff, sizeof ff, "%s/.mozilla/firefox", home);
    nss_firefox_profiles(ff, nick, NULL, 0);
    snprintf(ff, sizeof ff, "%s/snap/firefox/common/.mozilla/firefox", home);
    nss_firefox_profiles(ff, nick, NULL, 0);
    snprintf(ff, sizeof ff, "%s/snap/firefox/current/.mozilla/firefox", home);
    nss_firefox_profiles(ff, nick, NULL, 0);
    return 1;
}

#else
int trust_install(const char *certpath) {
    (void)certpath;
    fprintf(stderr, "trust_install: no user trust-store backend on this OS\n");
    return 0;
}
int trust_uninstall(const char *certpath, const char *cn) {
    (void)certpath; (void)cn;
    return 0;
}
#endif
