// signer.h — WHERE the secret key comes from, behind one seam.
//
// Everything that signs (src/ops.c → src/wallet.c) acquires key material
// through this interface and never touches the key file or WLT directly, so
// swapping the backend is a signer.c-only change:
//
//   today   dev key file — the plaintext 0600 wallet-<coin>.key WLT booted
//           (agreed testing posture; same file `wallet` uses)
//   later   macOS Keychain / BIP39 seed ceremony — acquire() reads the item
//           instead; callers are unchanged
//   note    a NON-extractable key (Secure Enclave/TPM) additionally needs the
//           build path to take a sign-callback instead of raw bytes — that
//           refactor rides the Keychain milestone, not this seam
#ifndef DESKTOP_SIGNER_H
#define DESKTOP_SIGNER_H

#include <stdint.h>

typedef struct {
    uint8_t seckey[32];
    char    coin[16];
    char    keypath[600];   // the key file — wallet's .commits sidecar
                            // (claim salts) lives next to it
} SignerKey;

// Key material present and usable this session?
int signer_ready(void);

// Copy the key into *out for ONE operation. Returns 0 if unavailable.
// Callers must signer_release() as soon as the op is built.
int signer_acquire(SignerKey *out);

// Wipe the copy.
void signer_release(SignerKey *k);

// Human label for Settings/logs ("dev key file", later "macOS Keychain").
const char *signer_backend(void);

#endif
