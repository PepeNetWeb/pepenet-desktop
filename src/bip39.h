// bip39.h — BIP39 mnemonic ⇄ entropy ⇄ seed (12 words, 128-bit entropy).
//
// The wallet's recovery phrase. 16 bytes of entropy encode as 12 words (11 bits
// each) with a 4-bit SHA-256 checksum; the phrase stretches to a 64-byte BIP32
// seed via PBKDF2-HMAC-SHA512. Empty passphrase (no BIP39 25th word) — standard.
#ifndef DNET_BIP39_H
#define DNET_BIP39_H

#include <stddef.h>
#include <stdint.h>

// the canonical 2048-word English wordlist (bip39_wordlist.c); index = 11-bit value
extern const char *const BIP39_WORDS[2048];

// 16-byte entropy → NUL-terminated 12-word mnemonic. `out` must hold ≥ 128 bytes.
void bip39_mnemonic_from_entropy(const uint8_t entropy[16], char *out, size_t cap);

// mnemonic → 16-byte entropy, validating every word against the list AND the
// 4-bit checksum. 1 ok, 0 on any unknown word / wrong count / bad checksum.
// Case- and whitespace-tolerant (folds to lowercase, collapses runs of spaces).
int  bip39_entropy_from_mnemonic(const char *mnemonic, uint8_t entropy[16]);

// BIP39 seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048). `seed_out` ≥ 64.
void bip39_seed_from_mnemonic(const char *mnemonic, uint8_t seed_out[64]);

#endif
