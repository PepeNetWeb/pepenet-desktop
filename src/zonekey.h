// zonekey.h — the per-device hot zone-signing key + its delegation-cert cache.
//
// The wallet key (WLT) is the money key AND the on-chain name owner. We do not
// want it signing every DNS record inside the always-on mesh/resolver process —
// a compromise of that process would then be a compromise of the money key.
//
// Instead: a separate hot keypair (zonekey-<coin>.key, 0600, next to the db)
// signs the zone records, and the wallet key mints a §2.2 P2PKH delegation cert
// (scope DNS_SCOPE) that authorizes the hot key to sign for a name it owns. The
// wallet key is touched ONLY at mint time (once per name, re-minted ~yearly);
// the net thread that signs records holds only the hot key. This is also the
// seam a future Keychain/hardware wallet plugs into: summon the cold key rarely
// to mint a cert, never to sign a record. Per device the hot key differs, so a
// lost device is revoked by letting its cert lapse — the money key is untouched.
#ifndef DNET_ZONEKEY_H
#define DNET_ZONEKEY_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    int     ok;
    int     created;            // fresh hot key generated this launch
    uint8_t seckey[32];
    uint8_t pub[33];            // compressed — the cert's posting_key
    char    path[600];          // the hot-key file
} ZoneKey;

extern ZoneKey ZK;

// Load-or-create <dbdir>/zonekey-<coin>.key (mirrors wallet_boot's layout).
// Independent of the wallet: a fresh hot key is fine on its own — only a cert
// binds it to an owner. Returns ZK.ok.
int zonekey_boot(const char *coin, const char *dbpath);

// Fill `cert` with a delegation cert authorizing ZK.pub to sign `name`'s zone,
// valid comfortably past `tip` (the current chain height). Reuses a cached cert
// (memory, then disk: zonecert-<coin>-<name>.bin) when still valid, else mints a
// fresh one with the wallet key and caches it. Returns the cert length, or 0 if
// the wallet key is unavailable / mint failed (caller falls back to owner-sign).
// Thread-safe. The one place WLT.seckey is used after boot.
int zonekey_cert(const char *name, uint32_t tip, uint8_t *cert, size_t cap);

#endif
