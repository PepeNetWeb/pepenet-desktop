// signer.c — key-scoping backend. Key material source: the DeskWallet that
// wallet_boot loaded from the OS keystore (macOS Keychain) at launch — this
// file just scopes short-lived copies of the in-memory seckey for signing
// (secp256k1 can't sign inside the Secure Enclave, so the key is retrieved).
#include "signer.h"
#include "wallet.h"

#include <stdio.h>
#include <string.h>

int signer_ready(void) { return WLT.ok; }

int signer_acquire(SignerKey *out) {
    if (!WLT.ok) return 0;
    memset(out, 0, sizeof *out);
    memcpy(out->seckey, WLT.seckey, 32);
    snprintf(out->coin, sizeof out->coin, "%s", WLT.coin);
    snprintf(out->keypath, sizeof out->keypath, "%s", WLT.path);
    return 1;
}

void signer_release(SignerKey *k) {
    volatile uint8_t *p = k->seckey;            // don't let the wipe optimize out
    for (int i = 0; i < 32; i++) p[i] = 0;
}

const char *signer_backend(void) { return "macOS Keychain (encrypted at rest)"; }
