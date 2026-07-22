// hdwallet.c — see hdwallet.h. Ports the reference GUI wallet's BIP32 CKD
// (PepeNet/clients/gui/crypto/hd_wallet.c) but returns just the private key and
// uses OpenSSL's HMAC-SHA512 (libcrypto is already linked) + the vendored
// libsecp256k1's scalar tweak-add for each child step.
#include "hdwallet.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <secp256k1.h>

#include <string.h>

static void hmac512(const uint8_t *key, int keylen,
                    const uint8_t *data, int datalen, uint8_t out[64]) {
    unsigned int outlen = 64;
    HMAC(EVP_sha512(), key, keylen, data, (size_t)datalen, out, &outlen);
}

int hd_privkey_from_seed(const uint8_t seed[64], uint32_t index, uint8_t out_priv[32]) {
    // m/44'/3'/0'/0/<index>  (' = hardened, top bit set)
    const uint32_t path[5] = { 0x8000002Cu, 0x80000003u, 0x80000000u, 0u, index };
    uint8_t I[64], privkey[32], chaincode[32], data[37], pub[33];

    hmac512((const uint8_t *)"Bitcoin seed", 12, seed, 64, I);   // master
    memcpy(privkey,   I,      32);
    memcpy(chaincode, I + 32, 32);

    secp256k1_context *cx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!cx) return 0;

    int ok = 1;
    for (int level = 0; level < 5 && ok; level++) {
        if (path[level] & 0x80000000u) {            // hardened: 0x00 || priv
            data[0] = 0x00;
            memcpy(data + 1, privkey, 32);
        } else {                                     // normal: compressed pub
            secp256k1_pubkey pk;
            if (!secp256k1_ec_pubkey_create(cx, &pk, privkey)) { ok = 0; break; }
            size_t plen = sizeof pub;
            secp256k1_ec_pubkey_serialize(cx, pub, &plen, &pk, SECP256K1_EC_COMPRESSED);
            memcpy(data, pub, 33);
        }
        data[33] = (uint8_t)(path[level] >> 24);
        data[34] = (uint8_t)(path[level] >> 16);
        data[35] = (uint8_t)(path[level] >> 8);
        data[36] = (uint8_t)(path[level]);

        hmac512(chaincode, 32, data, 37, I);
        // child = (IL + parent) mod n; tweak_add returns 0 exactly when BIP32
        // says to skip (IL >= n or zero result) — conformant.
        if (!secp256k1_ec_seckey_tweak_add(cx, privkey, I)) { ok = 0; break; }
        memcpy(chaincode, I + 32, 32);
    }
    secp256k1_context_destroy(cx);

    if (ok) memcpy(out_priv, privkey, 32);
    // scrub intermediates
    memset(privkey, 0, sizeof privkey);
    memset(chaincode, 0, sizeof chaincode);
    memset(I, 0, sizeof I);
    memset(data, 0, sizeof data);
    return ok;
}
