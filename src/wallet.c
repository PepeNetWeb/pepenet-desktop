// wallet.c — the desktop wallet, one module. Three former pieces, merged:
//   1. identity: the HD/BIP39/Keychain keypair (WLT) + address helpers.
//   2. the transaction engine: fund → sign → self-check → broadcast, and every
//      §3 namespace-op byte layout. This used to live in the headless indexer
//      (indexer/src/wallet.c) and be #included through a rename trick — it never
//      belonged there; it is vendored in here now.
//   3. the typed GUI seam (SwlReq/SwlRes → swl_run), formerly wallet.c.
// See wallet.h. Engine internals are static; ops.c drives only swl_run/swl_selftest.
#include "wallet.h"
#include "appconf.h"
#include "platform.h"     // platform_secret_* (the OS keystore)
#include "bip39.h"        // recovery-phrase ⇄ entropy ⇄ seed
#include "hdwallet.h"     // BIP32 m/44'/3'/0'/0/0 → privkey
#include "chain.h"
#include "attrib.h"
#include "adapter.h"
#include "base58.h"
#include "db.h"
#include "indexer.h"      // idx_serve_peer_held — the one-connection-per-peer rule
#include "sm.h"
#include "sha256.h"
#include "ripemd160.h"

#include <secp256k1.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <time.h>

// ══════════════════════ 1. identity: keys / HD / recovery phrase ══════════════
DeskWallet WLT;

// host-profile display facts (mirrors wallet's WCOINS)
static const struct { const char *name; uint8_t p2pkh_ver; } VERS[] = {
    { "doge", 30 }, { "pep", 56 }, { "testnet", 113 }, { "regtest", 111 },
};

const char *wallet_coin(void) { return WLT.coin[0] ? WLT.coin : APP_COIN; }

int wallet_addr_valid(const char *addr) {
    if (!addr || !addr[0]) return 0;
    uint8_t ver, payload[24];
    size_t n;
    if (!idx_b58check_decode(addr, &ver, payload, sizeof payload, &n) || n != 20)
        return 0;
    const char *coin = wallet_coin();
    for (size_t i = 0; i < sizeof VERS / sizeof VERS[0]; i++)
        if (!strcmp(VERS[i].name, coin)) return ver == VERS[i].p2pkh_ver;
    return 0;
}

int wallet_addr_decode(const char *addr, uint8_t out160[20]) {
    if (!wallet_addr_valid(addr)) return 0;
    uint8_t ver, payload[24];
    size_t n;
    if (!idx_b58check_decode(addr, &ver, payload, sizeof payload, &n) || n != 20)
        return 0;
    memcpy(out160, payload, 20);
    return 1;
}

int wallet_h160_addr(const uint8_t h160[20], char *out, size_t cap) {
    const char *coin = wallet_coin();
    for (size_t i = 0; i < sizeof VERS / sizeof VERS[0]; i++)
        if (!strcmp(VERS[i].name, coin))
            return idx_b58check_encode(VERS[i].p2pkh_ver, h160, 20, out, cap);
    return 0;
}

static void hash160(const uint8_t *d, size_t n, uint8_t out[20]) {
    uint8_t t[32];
    SHA256_CTX c;
    sha256_init(&c);
    sha256_update(&c, d, (unsigned)n);
    sha256_final(&c, t);
    ripemd160(t, 32, out);
}

static int derive(uint8_t ver) {
    secp256k1_context *cx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!cx) return 0;
    int ok = 0;
    secp256k1_pubkey pk;
    if (secp256k1_ec_seckey_verify(cx, WLT.seckey) &&
        secp256k1_ec_pubkey_create(cx, &pk, WLT.seckey)) {
        size_t plen = sizeof WLT.pub;
        secp256k1_ec_pubkey_serialize(cx, WLT.pub, &plen, &pk, SECP256K1_EC_COMPRESSED);
        hash160(WLT.pub, 33, WLT.h160);
        ok = idx_b58check_encode(ver, WLT.h160, 20, WLT.address, sizeof WLT.address);
    }
    secp256k1_context_destroy(cx);
    return ok;
}

// derive the wallet key from WLT.entropy via BIP39→BIP32 (m/44'/3'/0'/0/0),
// then fill pub/h160/address. 1 ok. Scrubs the intermediate seed.
static int apply_hd(void) {
    char mnem[128];
    uint8_t seed[64];
    bip39_mnemonic_from_entropy(WLT.entropy, mnem, sizeof mnem);
    bip39_seed_from_mnemonic(mnem, seed);
    int ok = hd_privkey_from_seed(seed, 0, WLT.seckey) && derive(WLT.ver);
    memset(seed, 0, sizeof seed);
    memset(mnem, 0, sizeof mnem);
    return ok;
}

static const char *wallet_acct(char *buf, size_t cap) {
    snprintf(buf, cap, "wallet-%s", WLT.coin);
    return buf;
}

int wallet_boot(const char *coin, const char *dbpath) {
    memset(&WLT, 0, sizeof WLT);
    snprintf(WLT.coin, sizeof WLT.coin, "%s", coin);
    uint8_t ver = 0;
    int known = 0;
    for (size_t i = 0; i < sizeof VERS / sizeof VERS[0]; i++)
        if (!strcmp(VERS[i].name, coin)) { ver = VERS[i].p2pkh_ver; known = 1; }
    if (!known) { fprintf(stderr, "wallet: unknown coin %s\n", coin); return 0; }
    WLT.ver = ver;

    // the key-file path next to the db — the signer's keypath (wallet.c never
    // writes it; the keystore is the sole store of record).
    char dir[512];
    snprintf(dir, sizeof dir, "%s", dbpath);
    char *sl = strrchr(dir, '/');
    if (sl) *sl = 0;
    else snprintf(dir, sizeof dir, ".");
    snprintf(WLT.path, sizeof WLT.path, "%s/wallet-%s.key", dir, coin);

    char acct[32];
    wallet_acct(acct, sizeof acct);

    // 1) the OS keystore is the source of record: a stored 16-byte BIP39 entropy
    //    derives the HD key (m/44'/3'/0'/0/0).
    uint8_t kbuf[64];
    int n = platform_secret_get(acct, kbuf, sizeof kbuf);
    if (n == 16) {
        memcpy(WLT.entropy, kbuf, 16);
        if (apply_hd()) { WLT.ok = 1; return 1; }
    }
    if (n < 0) {
        // the keystore REFUSED the read (Deny click / locked / ACL gate) — the
        // key most likely still exists, so generating a replacement here would
        // orphan or overwrite the real wallet. Boot walletless and say why.
        WLT.denied = 1;
        fprintf(stderr, "wallet: keychain refused the key read — allow '%s' access to the "
                        "'%s' keychain item, then relaunch\n", APP_NAME, acct);
        return 0;
    }

    // 2) fresh wallet → a new BIP39 phrase, entropy stored in the keystore
    int good = 0;
    for (int tries = 0; tries < 4 && !good; tries++) {
        if (getentropy(WLT.entropy, 16) != 0) {
            fprintf(stderr, "wallet: getentropy: %s\n", strerror(errno));
            return 0;
        }
        good = apply_hd();
    }
    if (!good) return 0;
    if (!platform_secret_set(acct, WLT.entropy, 16)) {          // an unsaved key is never shown
        fprintf(stderr, "wallet: keychain store failed — key not persisted\n");
        return 0;
    }
    WLT.ok = 1;
    WLT.created = 1;
    fprintf(stderr, "wallet: created HD wallet '%s' (%s)\n", acct, WLT.address);
    return 1;
}

// ── recovery-phrase surface (UI thread) ───────────────────────────────────────
int wallet_has_phrase(void) { return WLT.ok; }

const char *wallet_mnemonic(void) {
    static char mnem[128];
    mnem[0] = 0;
    if (WLT.ok) bip39_mnemonic_from_entropy(WLT.entropy, mnem, sizeof mnem);
    return mnem;
}

// Replace the wallet from a typed recovery phrase. Validates the phrase, derives
// the new key, and persists the entropy. On success WLT reflects the new wallet
// immediately (address updates), but the chain watch/ops still track the old
// address until relaunch — the caller should prompt a restart. 1 ok, 0 invalid
// phrase / keystore failure (WLT is rolled back).
int wallet_restore(const char *mnemonic) {
    if (!WLT.ver) return 0;
    uint8_t ent[16];
    if (!bip39_entropy_from_mnemonic(mnemonic, ent)) return 0;

    uint8_t save_ent[16], save_sk[32];
    memcpy(save_ent, WLT.entropy, 16);
    memcpy(save_sk, WLT.seckey, 32);

    char acct[32]; wallet_acct(acct, sizeof acct);
    memcpy(WLT.entropy, ent, 16);
    if (apply_hd() && platform_secret_set(acct, ent, 16)) {
        WLT.ok = 1;
        fprintf(stderr, "wallet: restored from phrase (%s) — restart to reload balances\n",
                WLT.address);
        return 1;
    }
    memcpy(WLT.entropy, save_ent, 16);      // rollback
    memcpy(WLT.seckey, save_sk, 32);
    derive(WLT.ver);
    return 0;
}

// ══════════════════════ 2. transaction engine (vendored from the indexer) ═════
// (was indexer/src/wallet.c — its own `hash160` is dropped in favor of the
//  identity copy above; the CLI `main` is dropped; the rest is unchanged.)

#define COIN_UNIT   100000000LL          // koinu per host coin (Doge-family)
#define DUST        1000000LL            // 0.01 — Dogecoin-1.14 dust threshold
#define FEE_DEFAULT (COIN_UNIT / 10)     // 0.1/tx — ~100× the 1.14 relay floor
#define FEE_MIN     100000LL             // 0.001 — the relay floor itself
#define MAX_INS     16

// host-profile transport + display facts (docs/notes/host-profiles.md)
typedef struct { const char *name; uint8_t magic[4]; uint16_t port; uint8_t p2pkh_ver, wif_ver; } WCoin;
static const WCoin WCOINS[] = {
    { "doge",    { 0xC0, 0xC0, 0xC0, 0xC0 }, 22556,  30, 158 },
    { "pep",     { 0xC0, 0xA0, 0xF0, 0xE0 }, 33874,  56, 158 },
    { "testnet", { 0xFC, 0xC1, 0xB7, 0xDC }, 44556, 113, 241 },
    { "regtest", { 0xFA, 0xBF, 0xB5, 0xDA }, 18444, 111, 239 },
};
static const WCoin *wcoin(const char *n) {
    for (unsigned i = 0; i < sizeof WCOINS / sizeof WCOINS[0]; i++) if (!strcmp(WCOINS[i].name, n)) return &WCOINS[i];
    return NULL;
}

static void tohex(const uint8_t *b, int n, char *out) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 15]; }
    out[2*n] = 0;
}

// ── wallet file: coin= + seckey= lines, 0600 ─────────────────────────────────
typedef struct {
    const WCoin *coin;
    uint8_t seckey[32], pub[33], h160[20];
    char addr[64];
    secp256k1_context *ctx;
} Wallet;

static int wallet_derive(Wallet *w) {
    w->ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    if (!secp256k1_ec_seckey_verify(w->ctx, w->seckey)) return 0;
    secp256k1_pubkey pk;
    if (!secp256k1_ec_pubkey_create(w->ctx, &pk, w->seckey)) return 0;
    size_t plen = 33;
    secp256k1_ec_pubkey_serialize(w->ctx, w->pub, &plen, &pk, SECP256K1_EC_COMPRESSED);
    hash160(w->pub, 33, w->h160);
    return idx_b58check_encode(w->coin->p2pkh_ver, w->h160, 20, w->addr, sizeof w->addr);
}

static int wallet_load(const char *path, Wallet *w) {
    memset(w, 0, sizeof *w);
    FILE *f = fopen(path, "r"); if (!f) { fprintf(stderr, "cannot open wallet %s\n", path); return 0; }
    char line[256]; int have_key = 0;
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!strncmp(line, "coin=", 5)) w->coin = wcoin(line + 5);
        else if (!strncmp(line, "seckey=", 7)) {
            size_t n; have_key = idx_hex_to_bytes(line + 7, w->seckey, 32, &n) && n == 32;
        }
    }
    fclose(f);
    if (!w->coin || !have_key) { fprintf(stderr, "wallet file malformed (need coin= and seckey=)\n"); return 0; }
    if (!wallet_derive(w)) { fprintf(stderr, "invalid secret key in wallet\n"); return 0; }
    return 1;
}




// ── utxos ─────────────────────────────────────────────────────────────────────
typedef struct { uint8_t txid[32]; uint32_t vout; int64_t value; } Utxo;
typedef struct { Utxo u[64]; int n; int64_t total; } UtxoSet;
static void utxo_cb(void *p, const uint8_t txid[32], uint32_t vout, int64_t value, int64_t height) {
    (void)height;
    UtxoSet *s = (UtxoSet *)p;
    if (s->n < 64) { memcpy(s->u[s->n].txid, txid, 32); s->u[s->n].vout = vout; s->u[s->n].value = value; s->n++; }
    s->total += value;
}
static int load_utxos(const char *dbpath, const uint8_t h160[20], UtxoSet *s) {
    memset(s, 0, sizeof *s);
    sqlite3 *db = idx_db_open(dbpath); if (!db) { fprintf(stderr, "cannot open db %s\n", dbpath); return 0; }
    idx_db_utxos(db, h160, utxo_cb, s);
    idx_db_close(db); return 1;
}


// ── amounts: "1", "0.5", "1650.25" (≤ 8 frac digits) → koinu ─────────────────
static int parse_amt(const char *s, int64_t *out) {
    int64_t whole = 0, frac = 0; int fd = 0; const char *p = s;
    if (!*p) return 0;
    for (; *p && *p != '.'; p++) { if (*p < '0' || *p > '9') return 0; whole = whole * 10 + (*p - '0'); if (whole > 100000000000LL) return 0; }
    if (*p == '.') { p++; for (; *p; p++) { if (*p < '0' || *p > '9' || fd >= 8) return 0; frac = frac * 10 + (*p - '0'); fd++; } }
    while (fd++ < 8) frac *= 10;
    *out = whole * COIN_UNIT + frac;
    return 1;
}

// ── tx construction (legacy Doge-family, SIGHASH_ALL P2PKH) ───────────────────
typedef struct { uint8_t b[8192]; size_t n; } Buf;
static void put8 (Buf *b, uint8_t v)  { b->b[b->n++] = v; }
static void put32(Buf *b, uint32_t v) { for (int i = 0; i < 4; i++) put8(b, (uint8_t)(v >> (8*i))); }
static void put64(Buf *b, uint64_t v) { for (int i = 0; i < 8; i++) put8(b, (uint8_t)(v >> (8*i))); }
static void putbytes(Buf *b, const uint8_t *p, size_t n) { memcpy(b->b + b->n, p, n); b->n += n; }
static void putvar(Buf *b, uint64_t v) {
    if (v < 0xFD) put8(b, (uint8_t)v);
    else { put8(b, 0xFD); put8(b, (uint8_t)v); put8(b, (uint8_t)(v >> 8)); }   // (all our counts < 65536)
}
// §1 carrier: OP_RETURN + ONE minimal push of the UTF-8 body (mirror image of
// chain.c idx_op_return_payload — direct push ≤75, OP_PUSHDATA1 for 76..80).
static size_t or_script(uint8_t *out, const uint8_t *body, size_t blen) {
    size_t n = 0;
    out[n++] = 0x6A;
    if (blen <= 75) out[n++] = (uint8_t)blen;
    else { out[n++] = 0x4C; out[n++] = (uint8_t)blen; }
    memcpy(out + n, body, blen); n += blen;
    return n;
}

// Generic outputs: value + raw scriptPubKey (P2PKH or OP_RETURN carrier).
typedef struct { int64_t value; uint8_t spk[96]; size_t spklen; } WOut;
static void wout_p2pkh(WOut *o, const uint8_t h160[20], int64_t value) {
    o->value = value; o->spklen = 25;
    o->spk[0] = 0x76; o->spk[1] = 0xA9; o->spk[2] = 0x14; memcpy(o->spk + 3, h160, 20);
    o->spk[23] = 0x88; o->spk[24] = 0xAC;
}
static void wout_carrier(WOut *o, const uint8_t *payload, size_t plen, int64_t value) {
    o->value = value; o->spklen = or_script(o->spk, payload, plen);
}

// Serialize a tx. scriptsigs[i]/sslens[i] = per-input scriptSig (empty or the
// signing scriptCode for the sighash variant, or the final sig+pubkey).
static void tx_serialize(Buf *b, const Utxo *ins, int nin,
                         const uint8_t *const scriptsigs[], const size_t sslens[],
                         const WOut *outs, int nout) {
    b->n = 0;
    put32(b, 1);                                             // version
    putvar(b, (uint64_t)nin);
    for (int i = 0; i < nin; i++) {
        putbytes(b, ins[i].txid, 32);
        put32(b, ins[i].vout);
        putvar(b, sslens[i]); if (sslens[i]) putbytes(b, scriptsigs[i], sslens[i]);
        put32(b, 0xFFFFFFFF);                                // sequence: final
    }
    putvar(b, (uint64_t)nout);
    for (int i = 0; i < nout; i++) {
        put64(b, (uint64_t)outs[i].value);
        putvar(b, outs[i].spklen); putbytes(b, outs[i].spk, outs[i].spklen);
    }
    put32(b, 0);                                             // locktime
}

// Build + sign (SIGHASH_ALL, every input ours). Returns tx length (0 on failure).
static size_t build_signed_tx(const Wallet *w, const Utxo *ins, int nin,
                              const WOut *outs, int nout, uint8_t *out, uint8_t txid[32]) {
    // our P2PKH scriptPubKey doubles as the legacy-sighash scriptCode for every
    // input (all inputs are ours; no embedded sigs, so FindAndDelete is a no-op)
    uint8_t spk[25] = { 0x76, 0xA9, 0x14 }; memcpy(spk + 3, w->h160, 20); spk[23] = 0x88; spk[24] = 0xAC;
    uint8_t sigs[MAX_INS][108]; size_t siglens[MAX_INS];
    const uint8_t *ssp[MAX_INS]; size_t ssl[MAX_INS];
    Buf b;
    for (int i = 0; i < nin; i++) {
        for (int k = 0; k < nin; k++) { ssp[k] = spk; ssl[k] = (k == i) ? 25 : 0; }
        tx_serialize(&b, ins, nin, ssp, ssl, outs, nout);
        put32(&b, 1);                                        // SIGHASH_ALL
        uint8_t h[32]; idx_sha256d(b.b, b.n, h);
        secp256k1_ecdsa_signature sig;
        if (!secp256k1_ecdsa_sign(w->ctx, &sig, h, w->seckey, NULL, NULL)) return 0;
        uint8_t der[72]; size_t dlen = sizeof der;
        secp256k1_ecdsa_signature_serialize_der(w->ctx, der, &dlen, &sig);
        uint8_t *ss = sigs[i]; size_t n = 0;                 // <sig||0x01> <pubkey33>
        ss[n++] = (uint8_t)(dlen + 1); memcpy(ss + n, der, dlen); n += dlen; ss[n++] = 0x01;
        ss[n++] = 33; memcpy(ss + n, w->pub, 33); n += 33;
        siglens[i] = n;
    }
    for (int i = 0; i < nin; i++) { ssp[i] = sigs[i]; ssl[i] = siglens[i]; }
    tx_serialize(&b, ins, nin, ssp, ssl, outs, nout);
    memcpy(out, b.b, b.n);
    idx_sha256d(b.b, b.n, txid);
    return b.n;
}

// Greedy largest-first coin selection for `need` koinu. Returns input count, 0
// if the balance can't cover it. *in_sum = selected total.
static int select_coins(const UtxoSet *s, int64_t need, int64_t *in_sum) {
    int nin = 0; *in_sum = 0;
    for (int i = 0; i < s->n && nin < MAX_INS && *in_sum < need; i++) { *in_sum += s->u[i].value; nin++; }
    return (*in_sum >= need) ? nin : 0;
}

// Action variant: the carrier must decode as SM_CAR_ACTION with the expected
// opcode, and vin[0] must §4-attribute to the wallet — the engine's exact view.
typedef struct { int expect_op; int ok; } ActVerifyCtx;
static void act_verify_tx_cb(void *u, const IdxTx *tx, uint32_t txindex) {
    (void)txindex;
    ActVerifyCtx *v = (ActVerifyCtx *)u;
    for (int o = 0; o < tx->n_out; o++) {
        const uint8_t *pd; size_t pdn;
        if (!idx_op_return_payload(tx->outs[o].spk, tx->outs[o].spklen, &pd, &pdn)) continue;
        SmCarrier car; memset(&car, 0, sizeof car);
        sm_decode_payload(pd, pdn, (uint64_t)tx->outs[o].value, &car);
        if (car.kind == SM_CAR_ACTION && car.act.op == v->expect_op) v->ok = 1;
    }
}
static int verify_action(const Wallet *w, const uint8_t *tx, size_t txlen, int expect_op) {
    uint8_t blk[9000]; size_t n = 0;
    memset(blk, 0, 80); blk[0] = 1;
    n = 80; blk[n++] = 1;
    memcpy(blk + n, tx, txlen); n += txlen;
    IdxBlockMeta meta; ActVerifyCtx v = { expect_op, 0 };
    if (!idx_parse_block(blk, n, &meta, act_verify_tx_cb, &v)) return 0;
    IdxAttr a;
    if (idx_attribute(tx, txlen, 0, &a) != IDX_ATTR_FOUND || memcmp(a.identity, w->h160, 20)) return 0;
    return v.ok;
}

// ── P2P broadcast (self-contained; same framing as sync.c) ────────────────────
static int net_send(int fd, const uint8_t magic[4], const char *cmd, const uint8_t *payload, uint32_t len) {
    uint8_t hdr[24]; memset(hdr, 0, 24); memcpy(hdr, magic, 4);
    strncpy((char *)hdr + 4, cmd, 12);
    hdr[16] = (uint8_t)len; hdr[17] = (uint8_t)(len >> 8); hdr[18] = (uint8_t)(len >> 16); hdr[19] = (uint8_t)(len >> 24);
    uint8_t ck[32]; idx_sha256d(payload ? payload : (const uint8_t *)"", len, ck); memcpy(hdr + 20, ck, 4);
    if (write(fd, hdr, 24) != 24) return 0;
    if (len && write(fd, payload, len) != (ssize_t)len) return 0;
    return 1;
}
static int read_n(int fd, uint8_t *buf, size_t n, int timeout_ms) {
    size_t got = 0;
    while (got < n) {
        struct pollfd p = { fd, POLLIN, 0 };
        int pr = poll(&p, 1, timeout_ms); if (pr <= 0) return 0;
        ssize_t r = read(fd, buf + got, n - got); if (r <= 0) return 0; got += (size_t)r;
    }
    return 1;
}
static int net_recv(int fd, const uint8_t magic[4], char cmd_out[13], uint8_t **payload, uint32_t *len, int timeout_ms) {
    uint8_t hdr[24]; if (!read_n(fd, hdr, 24, timeout_ms)) return 0;
    if (memcmp(hdr, magic, 4) != 0) return -1;
    memcpy(cmd_out, hdr + 4, 12); cmd_out[12] = 0;
    uint32_t l = (uint32_t)hdr[16] | (uint32_t)hdr[17] << 8 | (uint32_t)hdr[18] << 16 | (uint32_t)hdr[19] << 24;
    if (l > 32 * 1024 * 1024) return -1;
    uint8_t *buf = malloc(l ? l : 1);
    if (l && !read_n(fd, buf, l, timeout_ms)) { free(buf); return 0; }
    *payload = buf; *len = l; return 1;
}
static int p2p_handshake(int fd, const uint8_t magic[4]) {
    uint8_t v[256]; int o = 0;
    for (int i = 0; i < 4; i++) v[o++] = (70015 >> (8*i)) & 0xff;
    for (int i = 0; i < 8; i++) v[o++] = 0;
    int64_t now = (int64_t)time(NULL); for (int i = 0; i < 8; i++) v[o++] = (now >> (8*i)) & 0xff;
    memset(v + o, 0, 26); o += 26;
    memset(v + o, 0, 26); o += 26;
    for (int i = 0; i < 8; i++) v[o++] = (uint8_t)(i * 31 + 7);
    v[o++] = 0;                                              // user-agent len 0
    for (int i = 0; i < 4; i++) v[o++] = 0;                  // start_height 0
    v[o++] = 1;                                              // relay: yes (we're here to send a tx)
    if (!net_send(fd, magic, "version", v, (uint32_t)o)) return 0;
    int got_verack = 0, sent_verack = 0;
    for (int i = 0; i < 10; i++) {
        char cmd[13]; uint8_t *pl; uint32_t pl_len;
        int r = net_recv(fd, magic, cmd, &pl, &pl_len, 8000); if (r != 1) { if (r == -1) continue; return got_verack && sent_verack; }
        if (!strcmp(cmd, "version")) { net_send(fd, magic, "verack", NULL, 0); sent_verack = 1; }
        else if (!strcmp(cmd, "verack")) got_verack = 1;
        else if (!strcmp(cmd, "ping")) net_send(fd, magic, "pong", pl, pl_len);
        free(pl);
        if (got_verack && sent_verack) return 1;
    }
    return got_verack && sent_verack;
}
static void print_reject(const uint8_t *pl, uint32_t n) {
    // reject: varstr message, u8 ccode, varstr reason [, data]
    uint32_t o = 0; if (o >= n) return;
    uint8_t ml = pl[o++]; if (o + ml + 1 > n) return;
    o += ml;
    uint8_t code = pl[o++];
    uint8_t rl = (o < n) ? pl[o++] : 0; if (o + rl > n) rl = (uint8_t)(n - o);
    fprintf(stderr, "peer REJECTED tx: code 0x%02x reason \"%.*s\"\n", code, (int)rl, (const char *)pl + o);
}
// Resolve `host` (name or literal; "host:port" overrides dflt) and connect,
// bounded to 5 s per address — the same dial sync.c uses, duplicated here
// because this TU is self-contained by policy (wallet links no sync.c).
static int resolve_connect(const char *hostport, uint16_t dflt_port) {
    char host[80]; uint16_t port = dflt_port;
    snprintf(host, sizeof host, "%s", hostport);
    char *c = strrchr(host, ':');
    if (c && c[1] && strspn(c + 1, "0123456789") == strlen(c + 1)) { *c = 0; port = (uint16_t)atoi(c + 1); }
    char ps[8]; snprintf(ps, sizeof ps, "%u", port);
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, ps, &hints, &res) != 0 || !res) return -1;
    int fd = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        int r = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (r != 0 && errno == EINPROGRESS) {
            struct pollfd p = { fd, POLLOUT, 0 };
            int err = 0; socklen_t el = sizeof err;
            if (poll(&p, 1, 5000) == 1 &&
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0) r = 0;
        }
        if (r == 0) { fcntl(fd, F_SETFL, fl); break; }
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

// inv → (getdata → tx) → probe with our own getdata: peer returning the tx from
// its relay pool = accepted. Returns 1 accepted, 0 unknown/failed.
// Dials the explicit peer first, then falls through to the db's proven/harvested
// peer pool (the same ladder sync walks) — a dead pinned peer must not strand a
// signed tx. Failover happens only BEFORE the inv is sent; once a peer has seen
// the tx the verdict (echo / reject / silence) is that peer's.
static int broadcast_tx(const WCoin *coin, const char *ip, const char *dbpath,
                        const uint8_t *tx, size_t txlen, const uint8_t txid[32]) {
    char cand[10][80]; int nc = 0;
    if (ip && *ip && strcmp(ip, "auto") != 0) snprintf(cand[nc++], 80, "%s", ip);
    if (dbpath) {
        sqlite3 *pdb = idx_db_open(dbpath);
        if (pdb) {
            char pool[8][80]; int n = idx_db_peers_best(pdb, pool, 8);
            for (int i = 0; i < n && nc < 10; i++) {
                int dup = 0;
                for (int j = 0; j < nc; j++) if (!strcmp(cand[j], pool[i])) { dup = 1; break; }
                if (!dup) snprintf(cand[nc++], 80, "%s", pool[i]);
            }
            idx_db_close(pdb);
        }
    }
    int fd = -1;
    // ONE CONNECTION PER PEER: never open a broadcast socket to a peer the
    // serve plane holds — an archive node we hold no conn to relays a tx just
    // as well, without doubling up on the mesh line. Round 2 (held peers
    // allowed) exists only for an isolated mesh where every candidate is held:
    // a signed tx leaving the machine outranks topology hygiene, loudly.
    for (int round = 0; round < 2 && fd < 0; round++)
        for (int i = 0; i < nc && fd < 0; i++) {
            if (round == 0 && idx_serve_peer_held(cand[i])) continue;
            if (round == 1 && !idx_serve_peer_held(cand[i])) continue;   // round 1 tried these
            if (round == 1)
                fprintf(stderr, "  every candidate is held by the serve plane — dialing %s anyway (tx must leave)\n", cand[i]);
            fd = resolve_connect(cand[i], coin->port);
            if (fd < 0) { fprintf(stderr, "  %s unreachable\n", cand[i]); continue; }
            if (!p2p_handshake(fd, coin->magic)) {
                fprintf(stderr, "  %s handshake failed\n", cand[i]);
                close(fd); fd = -1;
            }
        }
    if (fd < 0) { fprintf(stderr, "no peer reachable for broadcast (%d candidates)\n", nc); return 0; }
    uint8_t inv[37]; inv[0] = 1; inv[1] = 1; inv[2] = inv[3] = inv[4] = 0; memcpy(inv + 5, txid, 32);
    net_send(fd, coin->magic, "inv", inv, 37);
    int sent = 0, accepted = 0, rejected = 0, probed = 0;
    time_t deadline = time(NULL) + 20;
    while (time(NULL) < deadline && !rejected && !accepted) {
        char cmd[13]; uint8_t *pl; uint32_t pl_len;
        int r = net_recv(fd, coin->magic, cmd, &pl, &pl_len, 4000);
        if (r == 0) {                                        // quiet: push, then probe
            if (!sent) { net_send(fd, coin->magic, "tx", tx, (uint32_t)txlen); sent = 1; fprintf(stderr, "  (no getdata — pushed tx unsolicited)\n"); }
            else if (!probed) { net_send(fd, coin->magic, "getdata", inv, 37); probed = 1; }
            continue;
        }
        if (r == -1) continue;
        if (!strcmp(cmd, "ping")) net_send(fd, coin->magic, "pong", pl, pl_len);
        else if (!strcmp(cmd, "getdata") && pl_len >= 37 && !memcmp(pl + 5, txid, 32)) {
            net_send(fd, coin->magic, "tx", tx, (uint32_t)txlen); sent = 1;
            net_send(fd, coin->magic, "getdata", inv, 37); probed = 1;   // immediately ask for it back
        }
        else if (!strcmp(cmd, "tx") && pl_len == txlen && !memcmp(pl, tx, txlen)) accepted = 1;
        else if (!strcmp(cmd, "reject")) { print_reject(pl, pl_len); rejected = 1; }
        else if (!strcmp(cmd, "notfound") && probed && sent) {
            fprintf(stderr, "  peer answered notfound to the echo probe (relay pool miss — not proof of rejection)\n");
            accepted = -1;                                   // sent, unconfirmed
        }
        free(pl);
    }
    close(fd);
    if (rejected) return 0;
    if (!sent) { fprintf(stderr, "peer never took the tx\n"); return 0; }
    return accepted == 1 ? 1 : -1;                           // -1 = sent, echo unconfirmed
}

// Re-announce an already-signed tx (wallet.h) — broadcast_tx verbatim, no keys.
int swl_rebroadcast(const char *coinname, const char *ip, const char *dbpath,
                    const uint8_t *tx, size_t txlen, const uint8_t txid32[32]) {
    const WCoin *coin = wcoin(coinname);
    if (!coin || !tx || !txlen) return 0;
    return broadcast_tx(coin, ip, dbpath, tx, txlen, txid32);
}

// ── shared tail: fund → sign → self-check → broadcast ────────────────────────
// outs[0..nout-1] = the fixed outputs (out_total = their value sum); change is
// appended automatically. expect_op ≥ 0 self-checks an SM_OP_* action carrier;
// -1 = plain payment (attribution-only check). Returns 1 sent, 0 failed.


// ── send: plain P2PKH payment ─────────────────────────────────────────────────

// ── commit/claim: §3.2 front-run-protected name mint ─────────────────────────
// The salt is secret until the claim reveals it — kept in a 0600 sidecar file.
static void sidecar_path(const char *wallet_path, char out[512]) {
    snprintf(out, 512, "%s.commits", wallet_path);
}

static int sidecar_find_salt(const char *wallet_path, const char *name, uint8_t salt[32]) {
    char scp[512]; sidecar_path(wallet_path, scp);
    FILE *f = fopen(scp, "r"); if (!f) return 0;
    char line[512], want[64]; int found = 0;
    snprintf(want, sizeof want, "name=%s salt=", name);
    size_t wl = strlen(want);
    while (fgets(line, sizeof line, f)) {                    // last match wins
        if (strncmp(line, want, wl) != 0 || strlen(line) < wl + 64) continue;
        char hex[65]; memcpy(hex, line + wl, 64); hex[64] = 0;
        size_t n; if (idx_hex_to_bytes(hex, salt, 32, &n) && n == 32) found = 1;
    }
    fclose(f); return found;
}
// Pre-claim safety (one db open over the indexer projection). Returns 0 if the
// commit is not yet indexed (the claim would be dropped — same-block). Sets
// *owned if the name is currently owned (a claim would burn the whole rent for
// nothing) and *expired if the commit's ~5 h COMMIT_EXPIRY window has passed
// (MTP-approximated by the tip block time; a pruned commit no longer backs a
// claim). All three are money-loss traps the fold punishes silently.
static int claim_precheck(const char *dbpath, const uint8_t commitment[32],
                          const char *name, int *owned, int *expired) {
    *owned = 0; *expired = 0;
    sqlite3 *db = idx_db_open(dbpath); if (!db) return 0;
    sqlite3_stmt *st; int found = 0; int64_t commit_time = 0, tip_time = 0;
    sqlite3_prepare_v2(db, "SELECT commit_time FROM commits WHERE commitment=?", -1, &st, NULL);
    sqlite3_bind_blob(st, 1, commitment, 32, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) { commit_time = sqlite3_column_int64(st, 0); found = 1; }
    sqlite3_finalize(st);
    sqlite3_prepare_v2(db, "SELECT time FROM blocks ORDER BY height DESC LIMIT 1", -1, &st, NULL);
    if (sqlite3_step(st) == SQLITE_ROW) tip_time = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    IdxNameRow r;
    if (idx_db_name_row(db, name, &r)) *owned = 1;
    idx_db_close(db);
    if (found && tip_time > 0 && tip_time > commit_time + SM_COMMIT_EXPIRY) *expired = 1;
    return found;
}

// The fold's own time gate: MTP = median of the last 11 synced block times. A
// market op that lands with MTP ≥ its expiry is dropped (settle/pay pay the seller
// for nothing), so the wallet refuses using the SAME condition rather than a
// skewed local clock. Returns 0 if the db has no blocks (can't judge → caller warns).
static int64_t db_tip_mtp(const char *dbpath) {
    sqlite3 *db = idx_db_open(dbpath); if (!db) return 0;
    sqlite3_stmt *st; int64_t ts[11]; int n = 0;
    sqlite3_prepare_v2(db, "SELECT time FROM blocks ORDER BY height DESC LIMIT 11", -1, &st, NULL);
    while (sqlite3_step(st) == SQLITE_ROW && n < 11) ts[n++] = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st); idx_db_close(db);
    if (n == 0) return 0;
    for (int i = 0; i < n; i++) for (int j = i + 1; j < n; j++)
        if (ts[j] < ts[i]) { int64_t t = ts[i]; ts[i] = ts[j]; ts[j] = t; }
    return ts[n / 2];
}
// Warn if the projection is stale enough that ownership/market state may have moved
// since the last sync (real time minus the tip block time). Advisory only.

// ── transfer: §3.6 gift a name (bare form = ALL unlocked owned names) ─────────

// ── §3.7 market: open (SELL·RESERVE·SETTLE) + directed (SELL_TO·PAY) ─────────
// The wallet reads price/seller/legs from the indexer's OWN projection (the
// names table) — never hand-typed — so every payment output is computed from
// the same view the fold will match it against.
static int load_name_row(const char *dbpath, const char *name, IdxNameRow *r) {
    sqlite3 *db = idx_db_open(dbpath); if (!db) { fprintf(stderr, "cannot open db %s\n", dbpath); return 0; }
    int ok = idx_db_name_row(db, name, r);
    idx_db_close(db);
    if (!ok) fprintf(stderr, "'%s' not in the names projection (unowned, or re-run `indexerd sync`)\n", name);
    return ok;
}
// Deposit leg — byte-identical mirror of market.c: max(DUST_FLOOR, ⌊price·bps/10000⌋)
// in 128-bit (price·bps overflows int64 for a near-2⁶⁴ price).
static uint64_t deposit_leg(uint64_t price, unsigned bps) {
    unsigned __int128 v = (unsigned __int128)price * bps / 10000u;
    uint64_t leg = (uint64_t)v;
    return leg < (uint64_t)SM_DUST_FLOOR ? (uint64_t)SM_DUST_FLOOR : leg;
}






// ── §3.5 RENEW (bare all-form) · §3.6 RELEASE (selective bitmap) ──

// Owned-set bitmap position of `name` for this owner: lexicographic (unsigned
// bytewise — SQLite BINARY collation) over ALL owned names, listed/offered
// included (a listing keeps its position, §3.5). Returns bit index, -1 if absent.
typedef struct { const char *want; int idx, found, count; } BitFindCtx;
static void bitfind_cb(void *u, const char *nm, int64_t lease, int st) {
    (void)lease; (void)st;
    BitFindCtx *c = (BitFindCtx *)u;
    if (!c->found && !strcmp(nm, c->want)) { c->idx = c->count; c->found = 1; }
    c->count++;
}


// ── selftest ──────────────────────────────────────────────────────────────────
static int cmd_selftest(void) {
    int fail = 0;
    #define EXPECT(cond, msg) do { if (cond) { printf("  ok   %s\n", msg); } \
        else { printf("  FAIL %s\n", msg); fail++; } } while (0)

    // base58check: the canonical version-0 zero-hash160 vector + roundtrip
    uint8_t z20[20] = { 0 }; char a58[64];
    idx_b58check_encode(0, z20, 20, a58, sizeof a58);
    EXPECT(!strcmp(a58, "1111111111111111111114oLvT2"), "b58check encode matches known vector");
    uint8_t ver, pay[32]; size_t plen;
    uint8_t h20[20]; for (int i = 0; i < 20; i++) h20[i] = (uint8_t)(i * 7 + 3);
    idx_b58check_encode(56, h20, 20, a58, sizeof a58);
    EXPECT(idx_b58check_decode(a58, &ver, pay, sizeof pay, &plen) && ver == 56 && plen == 20 && !memcmp(pay, h20, 20),
           "b58check pep-address roundtrip");
    EXPECT(a58[0] == 'P', "pep version 56 renders a P… address");

    // key derivation: seckey=1 → the canonical compressed-G hash160
    Wallet w; memset(&w, 0, sizeof w);
    w.coin = wcoin("pep"); w.seckey[31] = 1;
    EXPECT(wallet_derive(&w), "derive seckey=1");
    char hh[41]; tohex(w.h160, 20, hh);
    EXPECT(!strcmp(hh, "751e76e8199196d454941c45d1b3a323f1433bd6"), "hash160(compressed G) matches known vector");

    // build + sign a COMMIT spending two fake utxos; §4 attributes both inputs
    Utxo u[2]; memset(u, 0, sizeof u);
    for (int i = 0; i < 32; i++) { u[0].txid[i] = 0x11; u[1].txid[i] = 0x22; }
    u[0].vout = 1; u[0].value = 5 * COIN_UNIT;
    u[1].vout = 0; u[1].value = 3 * COIN_UNIT;
    int64_t fee = FEE_DEFAULT, change = 8 * COIN_UNIT - fee;
    WOut outs[2];
    uint8_t c0[36] = { 0xFF, 0x50, 0x4E, SM_OP_COMMIT }; memset(c0 + 4, 0x5A, 32);
    wout_carrier(&outs[0], c0, 36, 0);
    wout_p2pkh(&outs[1], w.h160, change);
    uint8_t tx[8192], txid[32];
    size_t txlen = build_signed_tx(&w, u, 2, outs, 2, tx, txid);
    EXPECT(txlen > 0, "build+sign 2-input COMMIT tx");
    EXPECT(verify_action(&w, tx, txlen, SM_OP_COMMIT),
           "indexer pipeline attributes + decodes our own COMMIT");
    IdxAttr a;                                    // second input verifies too
    EXPECT(idx_attribute(tx, txlen, 1, &a) == IDX_ATTR_FOUND && !memcmp(a.identity, w.h160, 20),
           "§4 attribution FOUND on vin[1] as well");

    // action carriers: COMMIT / CLAIM / TRANSFER decode through the engine and
    // attribute to the wallet (the exact pre-broadcast self-check gate)
    const char *nm = "pepenet"; size_t nl = strlen(nm);
    uint8_t salt[32]; memset(salt, 0x5A, 32);
    uint8_t pre80[80]; size_t pn = 0;
    memcpy(pre80 + pn, salt, 32); pn += 32; memcpy(pre80 + pn, nm, nl); pn += nl; memcpy(pre80 + pn, w.h160, 20); pn += 20;
    uint8_t cmt[32]; SHA256_CTX cc; sha256_init(&cc); sha256_update(&cc, pre80, pn); sha256_final(&cc, cmt);
    uint8_t apay[80] = { 0xFF, 0x50, 0x4E, SM_OP_COMMIT }; memcpy(apay + 4, cmt, 32);
    wout_carrier(&outs[0], apay, 36, 0); wout_p2pkh(&outs[1], w.h160, change);
    txlen = build_signed_tx(&w, u, 1, outs, 2, tx, txid);
    EXPECT(txlen && verify_action(&w, tx, txlen, SM_OP_COMMIT), "COMMIT carrier decodes + attributes");
    apay[3] = SM_OP_CLAIM; memcpy(apay + 4, salt, 32); memcpy(apay + 36, nm, nl);
    wout_carrier(&outs[0], apay, 36 + nl, 13);
    txlen = build_signed_tx(&w, u, 1, outs, 2, tx, txid);
    EXPECT(txlen && verify_action(&w, tx, txlen, SM_OP_CLAIM), "CLAIM carrier decodes + attributes");
    apay[3] = SM_OP_TRANSFER; memcpy(apay + 4, w.h160, 20);
    wout_carrier(&outs[0], apay, 24, 0);
    txlen = build_signed_tx(&w, u, 1, outs, 2, tx, txid);
    EXPECT(txlen && verify_action(&w, tx, txlen, SM_OP_TRANSFER), "TRANSFER carrier decodes + attributes");

    // §3.7 market carriers, through the same gate
    uint64_t price = 500000000ULL;                                 // 5 PEP
    apay[3] = SM_OP_SELL;
    for (int i = 0; i < 8; i++) apay[4 + i] = (uint8_t)(price >> (8*i));
    memset(apay + 12, 0, 4); memcpy(apay + 16, nm, nl);
    wout_carrier(&outs[0], apay, 16 + nl, 0);
    txlen = build_signed_tx(&w, u, 1, outs, 2, tx, txid);
    EXPECT(txlen && verify_action(&w, tx, txlen, SM_OP_SELL), "SELL carrier decodes + attributes");
    apay[3] = SM_OP_RESERVE; memcpy(apay + 4, nm, nl);
    wout_carrier(&outs[0], apay, 4 + nl, (int64_t)deposit_leg(price, SM_RESERVE_BURN_BPS));
    WOut outs3[3]; outs3[0] = outs[0];
    wout_p2pkh(&outs3[1], h20, (int64_t)deposit_leg(price, SM_RESERVE_PAY_BPS));   // pay-leg to a fake seller
    wout_p2pkh(&outs3[2], w.h160, COIN_UNIT);
    txlen = build_signed_tx(&w, u, 1, outs3, 3, tx, txid);
    EXPECT(txlen && verify_action(&w, tx, txlen, SM_OP_RESERVE), "RESERVE carrier (burn-leg value + pay-leg output) decodes + attributes");
    apay[3] = SM_OP_SETTLE;
    wout_carrier(&outs3[0], apay, 4 + nl, 0);
    wout_p2pkh(&outs3[1], h20, (int64_t)(price - 2 * deposit_leg(price, SM_RESERVE_BURN_BPS)));
    txlen = build_signed_tx(&w, u, 1, outs3, 3, tx, txid);
    EXPECT(txlen && verify_action(&w, tx, txlen, SM_OP_SETTLE), "SETTLE carrier decodes + attributes");
    apay[3] = SM_OP_SELL_TO;
    for (int i = 0; i < 8; i++) apay[4 + i] = (uint8_t)(price >> (8*i));
    memcpy(apay + 12, h20, 20); memcpy(apay + 32, nm, nl);
    wout_carrier(&outs[0], apay, 32 + nl, 0);
    txlen = build_signed_tx(&w, u, 1, outs, 2, tx, txid);
    EXPECT(txlen && verify_action(&w, tx, txlen, SM_OP_SELL_TO), "SELL_TO carrier decodes + attributes");
    apay[3] = SM_OP_PAY; memcpy(apay + 4, nm, nl);
    wout_carrier(&outs3[0], apay, 4 + nl, 0);
    wout_p2pkh(&outs3[1], h20, (int64_t)price);
    txlen = build_signed_tx(&w, u, 1, outs3, 3, tx, txid);
    EXPECT(txlen && verify_action(&w, tx, txlen, SM_OP_PAY), "PAY carrier decodes + attributes");

    // deposit-leg math mirrors market.c: bps floor + the near-2⁶⁴ 128-bit case
    EXPECT(deposit_leg(500000000ULL, SM_RESERVE_BURN_BPS) == 2500000ULL, "deposit leg: 0.5% of 5 PEP = 2,500,000 koinu");
    EXPECT(deposit_leg(1, SM_RESERVE_BURN_BPS) == 1, "deposit leg floors at DUST_FLOOR");
    EXPECT(deposit_leg(UINT64_MAX, SM_RESERVE_BURN_BPS) == UINT64_MAX / 10000 * 50 + (UINT64_MAX % 10000) * 50 / 10000,
           "deposit leg: near-2⁶⁴ price computed in 128-bit (no wrap)");

    // RENEW (bare) / RELEASE (anchor+bitmap)
    apay[3] = SM_OP_RENEW;
    wout_carrier(&outs[0], apay, 4, 1000);
    txlen = build_signed_tx(&w, u, 1, outs, 2, tx, txid);
    EXPECT(txlen && verify_action(&w, tx, txlen, SM_OP_RENEW), "RENEW bare-all carrier decodes + attributes");
    apay[3] = SM_OP_RELEASE;
    memset(apay + 4, 0, 5); apay[4] = 0x40; apay[9] = 0x01;        // anchor h64, bit 0 (LSB-first)
    wout_carrier(&outs[0], apay, 10, 0);
    txlen = build_signed_tx(&w, u, 1, outs, 2, tx, txid);
    EXPECT(txlen && verify_action(&w, tx, txlen, SM_OP_RELEASE), "RELEASE anchor+bitmap carrier decodes + attributes");

    // §1 push-encoding boundaries survive the decoder's minimality rules
    uint8_t body80[80]; memset(body80, 'x', 80);
    uint8_t ors[96]; const uint8_t *pd; size_t pdn;
    size_t n = or_script(ors, body80, 75);
    EXPECT(ors[1] == 75 && idx_op_return_payload(ors, n, &pd, &pdn) && pdn == 75, "75-byte body → direct push, decoder accepts");
    n = or_script(ors, body80, 80);
    EXPECT(ors[1] == 0x4C && idx_op_return_payload(ors, n, &pd, &pdn) && pdn == 80, "80-byte body → PUSHDATA1, decoder accepts");

    // amount parser
    int64_t v;
    EXPECT(parse_amt("1", &v) && v == COIN_UNIT, "parse_amt 1");
    EXPECT(parse_amt("0.01", &v) && v == DUST, "parse_amt 0.01");
    EXPECT(parse_amt("1650.00000001", &v) && v == 1650 * COIN_UNIT + 1, "parse_amt 1650.00000001");
    EXPECT(!parse_amt("1.234567890", &v) && !parse_amt("x", &v), "parse_amt rejects junk");

    printf(fail ? "\nwallet selftest: %d FAILED\n" : "\nwallet selftest: ALL PASSED\n", fail);
    return fail ? 1 : 0;
}



// ══════════════════════ 3. the typed GUI seam (SwlReq/SwlRes) ═════════════════
_Static_assert(SWL_MAX_INS == MAX_INS, "wallet.h mirrors wallet.c's input cap");

static int swl_fail(SwlRes *res, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(res->err, sizeof res->err, fmt, ap);
    va_end(ap);
    res->code = SWL_R_ERR;
    return 0;
}

static void swl_amt(char *out, size_t cap, int64_t koinu) {
    snprintf(out, cap, "%lld.%08lld",
             (long long)(koinu / COIN_UNIT), (long long)(koinu % COIN_UNIT));
}

// SignerKey → the stack Wallet wallet's builders take. Wipe after use —
// and unlike wallet_load's CLI path, destroy the secp context (a GUI signs
// many times per process).
static int wallet_from_key(const SignerKey *k, Wallet *w, SwlRes *res) {
    memset(w, 0, sizeof *w);
    w->coin = wcoin(k->coin);
    if (!w->coin) return swl_fail(res, "unknown coin '%s'", k->coin);
    memcpy(w->seckey, k->seckey, 32);
    if (!wallet_derive(w)) return swl_fail(res, "the wallet's secret key is invalid");
    return 1;
}
static void wallet_wipe(Wallet *w) {
    if (w->ctx) secp256k1_context_destroy(w->ctx);
    volatile uint8_t *p = w->seckey;
    for (int i = 0; i < 32; i++) p[i] = 0;
    memset(w, 0, sizeof *w);
}

// The shared tail — fund → sign → self-check → (broadcast | dry stop).
// expect_op ≥ 0: §3 action carrier; -1: plain payment; -2: §1 post.
static int swl_tail(const Wallet *w, const SwlReq *req, SwlRes *res,
                    WOut *outs, int nout, int64_t out_total, int expect_op) {
    UtxoSet s;
    if (!load_utxos(req->dbpath, w->h160, &s))
        return swl_fail(res, "cannot open the chain db");
    // the queue's coin view: drop confirmed outpoints in-flight links already
    // spend, then front-load in-flight change so selection (in-order greedy)
    // chains off the newest link instead of forking the wallet
    if (req->nlocked) {
        int k = 0;
        for (int i = 0; i < s.n; i++) {
            int locked = 0;
            for (int j = 0; j < req->nlocked && !locked; j++)
                if (s.u[i].vout == req->locked[j].vout &&
                    !memcmp(s.u[i].txid, req->locked[j].txid, 32)) locked = 1;
            if (locked) s.total -= s.u[i].value;
            else s.u[k++] = s.u[i];
        }
        s.n = k;
    }
    for (int i = req->nvirt - 1; i >= 0; i--) {
        if (s.n >= (int)(sizeof s.u / sizeof s.u[0])) { s.n--; s.total -= s.u[s.n].value; }
        memmove(s.u + 1, s.u, (size_t)s.n * sizeof s.u[0]);
        memcpy(s.u[0].txid, req->virt[i].txid, 32);
        s.u[0].vout  = req->virt[i].vout;
        s.u[0].value = req->virt[i].value;
        s.n++;
        s.total += req->virt[i].value;
    }
    int64_t fee = req->fee, in_sum;
    // want_change: pad by one dust unit so a ≥dust change output ALWAYS
    // exists. The queue needs that unconditionally — the next link chains off
    // it, and the sweep proves "confirmed as built" by that outpoint alone; a
    // changeless link would let a benign chain reach the malleation forensics,
    // where a value collision could replay a folded op. No fallback.
    int64_t pad = req->want_change ? DUST : 0;
    int nin = select_coins(&s, out_total + fee + pad, &in_sum);
    if (!nin) {
        char need[32], have[32];
        swl_amt(need, sizeof need, out_total + fee + pad);
        swl_amt(have, sizeof have, s.total);
        return swl_fail(res, "insufficient spendable balance — need %s%s, have %s",
                        need, pad ? " (incl. the 0.01 change buffer)" : "", have);
    }
    int64_t change = in_sum - out_total - fee;
    if (change > 0 && change < DUST) { fee += change; change = 0; }   // sub-dust → fee
    if (change > 0) {
        res->has_change   = 1;
        res->change_vout  = (uint32_t)nout;
        res->change_value = change;
        wout_p2pkh(&outs[nout++], w->h160, change);
    }

    uint8_t tx[8192], txid[32];
    size_t txlen = build_signed_tx(w, s.u, nin, outs, nout, tx, txid);
    if (!txlen) return swl_fail(res, "signing failed");

    // the same gate wallet runs: would the indexer pipeline fold this tx?
    if (expect_op >= 0) {
        if (!verify_action(w, tx, txlen, expect_op))
            return swl_fail(res, "self-check refused the tx — the fold would not decode op 0x%02x", expect_op);
    } else {
        IdxAttr a;
        if (idx_attribute(tx, txlen, 0, &a) != IDX_ATTR_FOUND || memcmp(a.identity, w->h160, 20))
            return swl_fail(res, "self-check refused the tx (§4 attribution)");
    }

    idx_hash_to_hex(txid, res->txid);
    memcpy(res->txid32, txid, 32);
    if (txlen <= SWL_RAW_MAX) {         // keep the signed bytes with the link:
        memcpy(res->raw, tx, txlen);    // a tx no mempool took can be re-announced
        res->rawlen = (uint32_t)txlen;
    }
    res->spent_inputs = in_sum;
    res->change = change;
    memcpy(res->in0_txid, s.u[0].txid, 32);
    res->in0_vout = s.u[0].vout;
    res->nins = nin;
    for (int i = 0; i < nin; i++) {
        memcpy(res->ins[i].txid, s.u[i].txid, 32);
        res->ins[i].vout = s.u[i].vout;
    }

    if (req->dry_run) { res->dry = 1; res->code = SWL_R_OK; return 1; }

    int r = broadcast_tx(w->coin, req->ip, req->dbpath, tx, txlen, txid);
    if (r == 0) {
        res->net_fail = 1;      // rejected or unreachable: not in any mempool — retryable
        return swl_fail(res, "broadcast failed — peer rejected the tx or is unreachable");
    }
    res->accepted = r;
    res->code = SWL_R_OK;
    return 1;
}

// CLAIM phase 1: fresh salt → sidecar (BEFORE broadcast — a committed name is
// unclaimable without it) → commit carrier. The salt sidecar is the durable
// record that lets a restarted claim complete the existing on-chain commit.
static int swl_do_commit(const Wallet *w, const SwlReq *req, SwlRes *res) {
    size_t nlen = strlen(req->name);
    uint8_t salt[32];
    if (getentropy(salt, 32) != 0)
        return swl_fail(res, "getentropy failed");
    uint8_t pre[32 + 20 + 20];
    size_t pn = 0;
    memcpy(pre + pn, salt, 32); pn += 32;
    memcpy(pre + pn, req->name, nlen); pn += nlen;
    memcpy(pre + pn, w->h160, 20); pn += 20;
    uint8_t commitment[32];
    SHA256_CTX c;
    sha256_init(&c); sha256_update(&c, pre, pn); sha256_final(&c, commitment);

    if (!req->dry_run) {
        char scp[512];
        sidecar_path(req->key.keypath, scp);
        int fd = open(scp, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (fd < 0) return swl_fail(res, "cannot write the commit sidecar %s", scp);
        FILE *f = fdopen(fd, "a");
        char sh[65], ch[65];
        tohex(salt, 32, sh); tohex(commitment, 32, ch);
        fprintf(f, "name=%s salt=%s commitment=%s\n", req->name, sh, ch);
        fclose(f);
    }

    uint8_t payload[36] = { 0xFF, 0x50, 0x4E, SM_OP_COMMIT };
    memcpy(payload + 4, commitment, 32);
    WOut outs[4];
    wout_carrier(&outs[0], payload, 36, 0);                  // commit burns nothing
    if (!swl_tail(w, req, res, outs, 1, 0, SM_OP_COMMIT)) return 0;
    res->code = SWL_R_COMMITTED;
    return 1;
}

// §3.5 bitmap plumbing shared by RELEASE, selective RENEW and selective
// TRANSFER: the lex bit position of every req->names entry, the packed flags,
// and the height anchor (tip−6, clamped up to last_set_mutation_height so the
// guard passes). need_unlocked: RELEASE/TRANSFER move names, so each must be
// plain OWNED; renew tops up movement-locked ones too. max_flags is the op's
// flag budget in BYTES (71 for renew/release; 51 for transfer — the 20-byte
// target eats flag space).
typedef struct { const SwlReq *req; int idx[16]; int found, count; } MultiFind;
static void multifind_cb(void *u, const char *nm, int64_t lease, int st) {
    (void)lease; (void)st;
    MultiFind *m = (MultiFind *)u;
    for (int i = 0; i < m->req->nnames; i++)
        if (m->idx[i] < 0 && !strcmp(nm, m->req->names[i])) { m->idx[i] = m->count; m->found++; }
    m->count++;
}
static int bits_and_anchor(const Wallet *w, const SwlReq *req, SwlRes *res,
                           int need_unlocked, int max_flags, uint8_t flags[71],
                           int *nflags, int64_t *anchor_out) {
    if (req->nnames < 1 || req->nnames > 16)
        return swl_fail(res, "1..16 names per batch");
    for (int i = 0; i < req->nnames; i++) {
        IdxNameRow r;
        if (!load_name_row(req->dbpath, req->names[i], &r))
            return swl_fail(res, "'%s' is not in the names projection — sync first", req->names[i]);
        if (memcmp(r.owner, w->h160, 20) || r.owner_type != 0)
            return swl_fail(res, "this wallet does not own '%s'", req->names[i]);
        if (need_unlocked && r.st != SM_OWNED)
            return swl_fail(res, "'%s' is movement-locked — only renew works right now", req->names[i]);
    }
    sqlite3 *db = idx_db_open(req->dbpath);
    if (!db) return swl_fail(res, "cannot open the chain db");
    char hh[41];
    tohex(w->h160, 20, hh);
    MultiFind mf = { req, {0}, 0, 0 };
    for (int i = 0; i < 16; i++) mf.idx[i] = -1;
    idx_db_owned(db, hh, multifind_cb, &mf);
    int64_t tip = 0;
    uint8_t tiph[32];
    int have_tip = idx_db_load_sync(db, &tip, tiph);
    int64_t last_mut = 0;                    // anchor guard: last_mut ≤ H ≤ confirm
    sqlite3_stmt *st;
    sqlite3_prepare_v2(db, "SELECT height FROM muts WHERE owner=?", -1, &st, NULL);
    sqlite3_bind_blob(st, 1, w->h160, 20, SQLITE_STATIC);
    if (sqlite3_step(st) == SQLITE_ROW) last_mut = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    idx_db_close(db);
    if (mf.found != req->nnames || !have_tip)
        return swl_fail(res, "cannot build the name bitmap — sync first");
    memset(flags, 0, 71);
    int maxbit = 0;
    for (int i = 0; i < req->nnames; i++) {
        if (mf.idx[i] >= max_flags * 8)
            return swl_fail(res, "'%s' is past bit %d — this op's selective bitmap cannot address it",
                            req->names[i], max_flags * 8 - 1);
        flags[mf.idx[i] >> 3] |= (uint8_t)(1u << (mf.idx[i] & 7));   // LSB-first
        if (mf.idx[i] > maxbit) maxbit = mf.idx[i];
    }
    *nflags = maxbit / 8 + 1;
    int64_t anchor = tip > 6 ? tip - 6 : tip;
    if (anchor < last_mut) anchor = last_mut;
    *anchor_out = anchor;
    return 1;
}

static int swl_dispatch(const Wallet *w, const SwlReq *req, SwlRes *res) {
    WOut outs[4];
    size_t nlen = strlen(req->name);

    switch (req->op) {

    case SWL_SEND: {
        if (req->amount < DUST)
            return swl_fail(res, "amount below the 0.01 dust minimum");
        wout_p2pkh(&outs[0], req->to160, req->amount);
        return swl_tail(w, req, res, outs, 1, req->amount, -1);
    }
    case SWL_CLAIM: {
        if (!sm_name_valid(req->name, nlen))
            return swl_fail(res, "names are a-z 0-9 _ . and at most 20 bytes");
        if (req->amount < 1)
            return swl_fail(res, "rent must be at least 1 koinu");
        uint8_t salt[32];
        if (!sidecar_find_salt(req->key.keypath, req->name, salt))
            return swl_do_commit(w, req, res);
        uint8_t pre[32 + 20 + 20];
        size_t pn = 0;
        memcpy(pre + pn, salt, 32); pn += 32;
        memcpy(pre + pn, req->name, nlen); pn += nlen;
        memcpy(pre + pn, w->h160, 20); pn += 20;
        uint8_t commitment[32];
        SHA256_CTX c;
        sha256_init(&c); sha256_update(&c, pre, pn); sha256_final(&c, commitment);
        int owned = 0, expired = 0;
        if (!claim_precheck(req->dbpath, commitment, req->name, &owned, &expired)) {
            // force_recommit = a retry after the commit never appeared; if it
            // HAD indexed by now we'd claim it below instead of paying again
            if (req->force_recommit) return swl_do_commit(w, req, res);
            res->code = SWL_R_WAIT_COMMIT;      // not indexed yet — sync, retry
            return 1;
        }
        if (owned)
            return swl_fail(res, "'%s' is owned right now — a claim would burn the rent for nothing", req->name);
        if (expired)                             // pruned commit: fresh salt, start over
            return swl_do_commit(w, req, res);
        uint8_t payload[4 + 32 + 20] = { 0xFF, 0x50, 0x4E, SM_OP_CLAIM };
        memcpy(payload + 4, salt, 32);
        memcpy(payload + 36, req->name, nlen);
        wout_carrier(&outs[0], payload, 36 + nlen, req->amount);   // rent rides the carrier
        return swl_tail(w, req, res, outs, 1, req->amount, SM_OP_CLAIM);
    }

    case SWL_RENEW: {
        if (req->amount < 1)
            return swl_fail(res, "rent must be at least 1 koinu");
        if (req->nnames == 0) {                                    // bare all-form
            uint8_t payload[4] = { 0xFF, 0x50, 0x4E, SM_OP_RENEW };
            wout_carrier(&outs[0], payload, 4, req->amount);
            return swl_tail(w, req, res, outs, 1, req->amount, SM_OP_RENEW);
        }
        uint8_t flags[71];                       // selective: the rent water-fills
        int nflags;                              // only the flagged names
        int64_t anchor;
        if (!bits_and_anchor(w, req, res, 0, 71, flags, &nflags, &anchor)) return 0;
        uint8_t payload[4 + 5 + 71] = { 0xFF, 0x50, 0x4E, SM_OP_RENEW };
        for (int i = 0; i < 5; i++) payload[4 + i] = (uint8_t)((uint64_t)anchor >> (8 * i));
        memcpy(payload + 9, flags, (size_t)nflags);
        wout_carrier(&outs[0], payload, 9 + (size_t)nflags, req->amount);
        return swl_tail(w, req, res, outs, 1, req->amount, SM_OP_RENEW);
    }

    case SWL_TRANSFER: {
        if (req->nnames == 0) {                  // bare §3.6 all-form: EVERY unlocked name
            uint8_t payload[24] = { 0xFF, 0x50, 0x4E, SM_OP_TRANSFER };
            memcpy(payload + 4, req->to160, 20);
            wout_carrier(&outs[0], payload, 24, 0);                // fee-only, gift
            return swl_tail(w, req, res, outs, 1, 0, SM_OP_TRANSFER);
        }
        uint8_t flags[71];                       // selective: [target][anchor][flags]
        int nflags;                              // — only the flagged names move
        int64_t anchor;
        if (!bits_and_anchor(w, req, res, 1, 51, flags, &nflags, &anchor)) return 0;
        uint8_t payload[4 + 20 + 5 + 51] = { 0xFF, 0x50, 0x4E, SM_OP_TRANSFER };
        memcpy(payload + 4, req->to160, 20);
        for (int i = 0; i < 5; i++) payload[24 + i] = (uint8_t)((uint64_t)anchor >> (8 * i));
        memcpy(payload + 29, flags, (size_t)nflags);
        wout_carrier(&outs[0], payload, 29 + (size_t)nflags, 0);   // fee-only, gift
        return swl_tail(w, req, res, outs, 1, 0, SM_OP_TRANSFER);
    }

    case SWL_SELL: {
        if (!sm_name_valid(req->name, nlen))
            return swl_fail(res, "names are a-z 0-9 _ . and at most 20 bytes");
        if (req->price < (uint64_t)SM_SELL_PRICE_FLOOR)
            return swl_fail(res, "price below the 3-koinu SELL floor");
        if (req->window_s != 0 && req->window_s < (uint32_t)SM_RESERVE_WINDOW)
            return swl_fail(res, "a nonzero window must be at least 5 hours (18000 s)");
        IdxNameRow r;
        if (!load_name_row(req->dbpath, req->name, &r))
            return swl_fail(res, "'%s' is not in the names projection — sync first", req->name);
        if (memcmp(r.owner, w->h160, 20) || r.owner_type != 0)
            return swl_fail(res, "this wallet does not own '%s'", req->name);
        if (r.st != SM_OWNED)
            return swl_fail(res, "'%s' is movement-locked — only renew works right now", req->name);
        // §5 executability: the 0.5% pay-leg must clear the NETWORK dust floor
        // (the fold would honor less, but the reserve/reclaim tx could never
        // relay — it would broadcast and sit unmined forever)
        if (deposit_leg(req->price, SM_RESERVE_PAY_BPS) < (uint64_t)DUST)
            return swl_fail(res, "price below 2.0 — the 0.5%% pay-leg would be dust; "
                                 "nobody (you included) could ever reserve or reclaim it");
        int64_t eff = req->window_s ? (int64_t)req->window_s : SM_RESERVE_WINDOW;
        int64_t mtp = db_tip_mtp(req->dbpath);
        if (mtp && mtp + eff + SM_REORG_BUFFER > r.lease_expiry)
            return swl_fail(res, "lease shorter than the window — renew first");
        uint8_t payload[4 + 8 + 4 + 20] = { 0xFF, 0x50, 0x4E, SM_OP_SELL };
        for (int i = 0; i < 8; i++) payload[4 + i]  = (uint8_t)(req->price   >> (8 * i));
        for (int i = 0; i < 4; i++) payload[12 + i] = (uint8_t)(req->window_s >> (8 * i));
        memcpy(payload + 16, req->name, nlen);
        wout_carrier(&outs[0], payload, 16 + nlen, 0);             // fee-only
        return swl_tail(w, req, res, outs, 1, 0, SM_OP_SELL);
    }

    case SWL_RELEASE: {                          // 1..16 names, ONE bitmap tx
        uint8_t flags[71];
        int nflags;
        int64_t anchor;
        if (!bits_and_anchor(w, req, res, 1, 71, flags, &nflags, &anchor)) return 0;
        uint8_t payload[4 + 5 + 71] = { 0xFF, 0x50, 0x4E, SM_OP_RELEASE };
        for (int i = 0; i < 5; i++) payload[4 + i] = (uint8_t)((uint64_t)anchor >> (8 * i));
        memcpy(payload + 9, flags, (size_t)nflags);
        wout_carrier(&outs[0], payload, 9 + (size_t)nflags, 0);
        return swl_tail(w, req, res, outs, 1, 0, SM_OP_RELEASE);
    }

    case SWL_RESERVE: {
        IdxNameRow r;
        if (!load_name_row(req->dbpath, req->name, &r))
            return swl_fail(res, "'%s' is not in the names projection — sync first", req->name);
        if (r.st == SM_RESERVED)
            return swl_fail(res, "someone already reserved this name — a second reserve loses its whole deposit");
        if (r.st != SM_LISTED)
            return swl_fail(res, "'%s' is not an open listing", req->name);
        if (r.seller_type != 0)
            return swl_fail(res, "seller is not P2PKH — this wallet only builds P2PKH pay-legs");
        int64_t mtp = db_tip_mtp(req->dbpath);
        if (mtp && mtp >= r.offer_expiry)
            return swl_fail(res, "the listing window closed — a late reserve forfeits its deposit");
        uint64_t burn_leg = deposit_leg(r.price, SM_RESERVE_BURN_BPS);
        uint64_t pay_leg  = deposit_leg(r.price, SM_RESERVE_PAY_BPS);
        if (pay_leg < (uint64_t)DUST)                  // §5: sub-dust can't relay
            return swl_fail(res, "un-executable listing — its 0.5%% pay-leg is below "
                                 "the 0.01 dust floor; it unlists when the window closes");
        uint8_t payload[4 + 20] = { 0xFF, 0x50, 0x4E, SM_OP_RESERVE };
        memcpy(payload + 4, req->name, nlen);
        wout_carrier(&outs[0], payload, 4 + nlen, (int64_t)burn_leg);  // burn-leg on the carrier
        wout_p2pkh(&outs[1], r.seller, (int64_t)pay_leg);              // pay-leg to the seller
        return swl_tail(w, req, res, outs, 2, (int64_t)(burn_leg + pay_leg), SM_OP_RESERVE);
    }

    case SWL_SETTLE: {
        IdxNameRow r;
        if (!load_name_row(req->dbpath, req->name, &r))
            return swl_fail(res, "'%s' is not in the names projection — sync first", req->name);
        if (r.st != SM_RESERVED)
            return swl_fail(res, "'%s' is not reserved", req->name);
        if (memcmp(r.buyer, w->h160, 20))
            return swl_fail(res, "this wallet is not the reserver — a settle would pay the seller for nothing");
        if (r.seller_type != 0)
            return swl_fail(res, "seller is not P2PKH");
        int64_t mtp = db_tip_mtp(req->dbpath);
        if (mtp && mtp >= r.reserve_expiry)
            return swl_fail(res, "the settle window expired — the deposit is forfeit");
        if (r.price < r.burn_leg + r.pay_leg)
            return swl_fail(res, "projection row looks corrupt (legs exceed price)");
        uint64_t remainder = r.price - r.burn_leg - r.pay_leg;   // legs as the fold recorded
        if (remainder < (uint64_t)DUST)                // §5: sub-dust can't relay
            return swl_fail(res, "un-executable — the settle remainder is below the 0.01 dust floor");
        uint8_t payload[4 + 20] = { 0xFF, 0x50, 0x4E, SM_OP_SETTLE };
        memcpy(payload + 4, req->name, nlen);
        wout_carrier(&outs[0], payload, 4 + nlen, 0);
        wout_p2pkh(&outs[1], r.seller, (int64_t)remainder);
        return swl_tail(w, req, res, outs, 2, (int64_t)remainder, SM_OP_SETTLE);
    }

    case SWL_PAY: {
        IdxNameRow r;
        if (!load_name_row(req->dbpath, req->name, &r))
            return swl_fail(res, "'%s' is not in the names projection — sync first", req->name);
        if (r.st != SM_OFFERED)
            return swl_fail(res, "'%s' has no live directed offer", req->name);
        if (memcmp(r.buyer, w->h160, 20))
            return swl_fail(res, "this offer is directed at a different wallet");
        if (r.seller_type != 0)
            return swl_fail(res, "seller is not P2PKH");
        int64_t mtp = db_tip_mtp(req->dbpath);
        if (mtp && mtp >= r.offer_expiry)
            return swl_fail(res, "the offer window closed");
        if (r.price < (uint64_t)DUST)                  // §5: sub-dust can't relay
            return swl_fail(res, "un-executable offer — its price is below the 0.01 dust floor");
        uint8_t payload[4 + 20] = { 0xFF, 0x50, 0x4E, SM_OP_PAY };
        memcpy(payload + 4, req->name, nlen);
        wout_carrier(&outs[0], payload, 4 + nlen, 0);
        wout_p2pkh(&outs[1], r.seller, (int64_t)r.price);          // full price
        return swl_tail(w, req, res, outs, 2, (int64_t)r.price, SM_OP_PAY);
    }

    case SWL_OFFER: {                            // §3.7 SELL_TO — directed, 2 h fixed
        if (!sm_name_valid(req->name, nlen))
            return swl_fail(res, "names are a-z 0-9 _ . and at most 20 bytes");
        if (req->price < (uint64_t)SM_DUST_FLOOR)
            return swl_fail(res, "price must be at least 1 koinu");
        if (req->price < (uint64_t)DUST)               // §5: PAY sends the full
            return swl_fail(res, "price below the 0.01 dust floor — the buyer's "
                                 "payment output could never relay");
        if (!memcmp(req->to160, w->h160, 20))
            return swl_fail(res, "that's this wallet's own address");
        IdxNameRow r;
        if (!load_name_row(req->dbpath, req->name, &r))
            return swl_fail(res, "'%s' is not in the names projection — sync first", req->name);
        if (memcmp(r.owner, w->h160, 20) || r.owner_type != 0)
            return swl_fail(res, "this wallet does not own '%s'", req->name);
        if (r.st != SM_OWNED)
            return swl_fail(res, "'%s' is movement-locked — only renew works right now", req->name);
        int64_t mtp = db_tip_mtp(req->dbpath);   // the fold wants window+buffer of lease
        if (mtp && mtp + SM_DIRECT_WINDOW + SM_REORG_BUFFER > r.lease_expiry)
            return swl_fail(res, "lease shorter than the offer window — renew first");
        uint8_t payload[4 + 8 + 20 + 20] = { 0xFF, 0x50, 0x4E, SM_OP_SELL_TO };
        for (int i = 0; i < 8; i++) payload[4 + i] = (uint8_t)(req->price >> (8 * i));
        memcpy(payload + 12, req->to160, 20);
        memcpy(payload + 32, req->name, nlen);
        wout_carrier(&outs[0], payload, 32 + nlen, 0);             // fee-only
        return swl_tail(w, req, res, outs, 1, 0, SM_OP_SELL_TO);
    }
    }
    return swl_fail(res, "unknown wallet op");
}

int swl_run(const SwlReq *req, SwlRes *res) {
    memset(res, 0, sizeof *res);
    if (req->fee < FEE_MIN)
        return swl_fail(res, "fee below the 0.001 relay floor");
    Wallet w;
    if (!wallet_from_key(&req->key, &w, res)) { wallet_wipe(&w); return 0; }
    int ok = swl_dispatch(&w, req, res);
    wallet_wipe(&w);
    return ok;
}

int swl_selftest(void) { return cmd_selftest(); }
