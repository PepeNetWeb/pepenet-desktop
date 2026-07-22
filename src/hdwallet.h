// hdwallet.h — BIP32/BIP44 key derivation from a BIP39 seed.
//
// Derives the private key at m/44'/3'/0'/0/<index>. All coins in this family
// share that path (the reference GUI wallet does too); the address version byte
// differentiates them, so the wallet derives pubkey/address from the privkey.
#ifndef DNET_HDWALLET_H
#define DNET_HDWALLET_H

#include <stdint.h>

// 64-byte BIP32 seed → 32-byte private key at m/44'/3'/0'/0/<index>.
// 1 ok, 0 on the astronomically-rare invalid intermediate scalar.
int hd_privkey_from_seed(const uint8_t seed[64], uint32_t index, uint8_t out_priv[32]);

#endif
