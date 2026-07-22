// trust_win.c — Windows implementation of tls/src/trust.h: install/remove the
// name-constrained root in the CURRENT USER "Root" certificate store. Adding
// a root to the user store makes Windows itself raise the security-warning
// dialog — that GUI confirmation IS the operator's deliberate consent, the
// exact analogue of the mac keychain auth prompt (DESIGN.md §2). No admin,
// no shell-outs. Chrome/Edge read this store directly; Firefox needs the
// enterprise-roots pref (sysinstall_firefox_roots flips it).
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trust.h"

// PEM file → DER bytes (caller frees). 0 on any parse trouble.
static BYTE *pem_to_der(const char *path, DWORD *outlen) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 1 << 20) { fclose(f); return NULL; }
    char *pem = (char *)malloc((size_t)sz + 1);
    if (!pem) { fclose(f); return NULL; }
    size_t n = fread(pem, 1, (size_t)sz, f);
    fclose(f);
    pem[n] = 0;
    DWORD der_len = 0;
    if (!CryptStringToBinaryA(pem, (DWORD)n, CRYPT_STRING_BASE64HEADER,
                              NULL, &der_len, NULL, NULL) || !der_len) {
        free(pem);
        return NULL;
    }
    BYTE *der = (BYTE *)malloc(der_len);
    if (!der || !CryptStringToBinaryA(pem, (DWORD)n, CRYPT_STRING_BASE64HEADER,
                                      der, &der_len, NULL, NULL)) {
        free(pem); free(der);
        return NULL;
    }
    free(pem);
    *outlen = der_len;
    return der;
}

static HCERTSTORE open_user_root(void) {
    return CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0,
                         CERT_SYSTEM_STORE_CURRENT_USER, "Root");
}

int trust_install(const char *certpath) {
    DWORD der_len = 0;
    BYTE *der = pem_to_der(certpath, &der_len);
    if (!der) return 0;
    HCERTSTORE st = open_user_root();
    if (!st) { free(der); return 0; }
    // REPLACE_EXISTING keeps reinstall idempotent; Windows shows its
    // root-trust warning dialog here — user consent, or the add fails
    int ok = CertAddEncodedCertificateToStore(st, X509_ASN_ENCODING, der, der_len,
                                              CERT_STORE_ADD_REPLACE_EXISTING,
                                              NULL) ? 1 : 0;
    CertCloseStore(st, 0);
    free(der);
    return ok;
}

int trust_uninstall(const char *certpath, const char *cn) {
    (void)certpath;                       // matched by subject CN, like the mac path
    if (!cn || !cn[0]) return 0;
    wchar_t wcn[256];
    if (!MultiByteToWideChar(CP_UTF8, 0, cn, -1, wcn, 256)) return 0;
    HCERTSTORE st = open_user_root();
    if (!st) return 0;
    int removed = 0;
    PCCERT_CONTEXT c = NULL;
    // delete EVERY match (stale reinstalls included); deletion invalidates the
    // context, so restart the find from scratch each round
    for (;;) {
        c = CertFindCertificateInStore(st, X509_ASN_ENCODING, 0,
                                       CERT_FIND_SUBJECT_STR_W, wcn, NULL);
        if (!c) break;
        PCCERT_CONTEXT dup = CertDuplicateCertificateContext(c);
        CertFreeCertificateContext(c);
        if (!CertDeleteCertificateFromStore(dup)) break;
        removed++;
    }
    CertCloseStore(st, 0);
    return removed > 0;
}

#endif /* _WIN32 */
