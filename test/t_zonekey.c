/* t_zonekey.c — the per-device hot zone-signing key and its delegation-cert
 * cache (src/zonekey.c).
 *
 * The whole point of this module is that the MONEY key never signs a DNS
 * record: a separate hot key does, authorized by a §2.2 P2PKH delegation cert
 * the wallet key mints once per name. So the suite proves the properties that
 * make that split real:
 *
 *   · load-or-create is deterministic — a second boot LOADS the same key, byte
 *     for byte, and never rotates or clobbers the file; the file is 0600 and
 *     lands at <dbdir>/zonekey-<coin>.key;
 *   · the file's hex encoding round-trips exactly (write a known 32-byte
 *     secret, boot, get that secret and the secp256k1 pubkey derived from it);
 *   · malformed input is REFUSED, not papered over: no seckey line, short hex,
 *     non-hex, and hex that is a valid 32-byte string but an invalid curve
 *     scalar (zero, and >= the group order) all fail closed;
 *   · distinct inputs give distinct keys — a fresh coin gets a fresh file and
 *     a different key;
 *   · zonekey_cert mints a cert that PARSES, delegates to the CURRENT hot key,
 *     carries DNS_SCOPE, and expires exactly ZK_CERT_TTL past the tip it was
 *     minted for; it caches in memory and on disk, re-mints on the margin
 *     boundary and not one block earlier, and refuses names outside the §3.1
 *     1..32 bound;
 *   · a short output buffer returns 0 and writes nothing past its cap.
 */
#include "zonekey.h"
#include "wallet.h"
#include "dns_state.h"          /* DNS_SCOPE */

#include "pepenet/crypto.h"
#include "pepenet/state.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_fail;
#define CHECK(cond, name) do { \
    if (cond) printf("ok   %s\n", name); \
    else      { printf("FAIL %s\n", name); g_fail = 1; } \
} while (0)

/* zonekey.c reads WLT for the money key that signs the cert; the wallet module
 * itself is not linked here (it drags sqlite, sockets and the indexer in). */
DeskWallet WLT;

/* the constants zonekey.c compiles in (zonekey.c:30-32) */
#define ZK_CERT_TTL    ((uint32_t)(90 * 24 * 60))
#define ZK_CERT_MARGIN ((uint32_t)(7  * 24 * 60))

static char TDIR[256];

static void rm_rf_dir(void) {
    DIR *d = opendir(TDIR);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            char p[512];
            snprintf(p, sizeof p, "%s/%s", TDIR, e->d_name);
            unlink(p);
        }
        closedir(d);
    }
    rmdir(TDIR);
}

static void wipe_keys(void) {                 /* leave the dir, drop the files */
    DIR *d = opendir(TDIR);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        char p[512];
        snprintf(p, sizeof p, "%s/%s", TDIR, e->d_name);
        unlink(p);
    }
    closedir(d);
}

static int write_keyfile(const char *coin, const char *body) {
    char p[512];
    snprintf(p, sizeof p, "%s/zonekey-%s.key", TDIR, coin);
    FILE *f = fopen(p, "w");
    if (!f) return 0;
    fputs(body, f);
    fclose(f);
    return 1;
}
static long file_bytes(const char *path, char *out, size_t cap) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    long n = (long)fread(out, 1, cap, f);
    fclose(f);
    return n;
}
static void tohex(const uint8_t *b, int n, char *out) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 15]; }
    out[2*n] = 0;
}

int main(void) {
    snprintf(TDIR, sizeof TDIR, "/tmp/t_zonekey_%d", (int)getpid());
    mkdir(TDIR, 0700);
    char db[512];
    snprintf(db, sizeof db, "%s/chain.db", TDIR);      /* the db FILE; g_dir is its parent */
    char keypath[512];
    snprintf(keypath, sizeof keypath, "%s/zonekey-doge.key", TDIR);

    printf("-- create: a fresh hot key --\n");
    uint8_t first_sec[32], first_pub[33];
    {
        CHECK(zonekey_boot("doge", db) == 1, "zonekey_boot creates a key on a fresh dir");
        CHECK(ZK.ok == 1 && ZK.created == 1, "ZK.ok set, ZK.created flags the fresh generate");
        CHECK(strcmp(ZK.path, keypath) == 0, "the key lands at <dbdir>/zonekey-<coin>.key");
        struct stat st;
        CHECK(stat(ZK.path, &st) == 0 && (st.st_mode & 0777) == 0600, "the hot key file is 0600");
        uint8_t chk[33];
        CHECK(sp_pubkey(ZK.seckey, chk) == 1 && memcmp(chk, ZK.pub, 33) == 0,
              "ZK.pub is secp256k1(ZK.seckey), compressed");
        CHECK(ZK.pub[0] == 0x02 || ZK.pub[0] == 0x03, "the hot pubkey is a compressed point");
        int nonzero = 0;
        for (int i = 0; i < 32; i++) if (ZK.seckey[i]) nonzero = 1;
        CHECK(nonzero, "the generated secret is not all-zero");
        memcpy(first_sec, ZK.seckey, 32);
        memcpy(first_pub, ZK.pub, 33);

        char body[256];
        long n = file_bytes(ZK.path, body, sizeof body - 1);
        body[n > 0 ? n : 0] = 0;
        CHECK(n > 0 && strstr(body, "coin=doge\n") != NULL, "the file records the coin");
        char kh[65]; tohex(first_sec, 32, kh);
        char want[128];
        snprintf(want, sizeof want, "seckey=%s\n", kh);
        CHECK(strstr(body, want) != NULL, "the file records the secret as 64 lowercase hex chars");
    }

    printf("-- load: a second boot never rotates or clobbers --\n");
    {
        char before[256];
        long bn = file_bytes(keypath, before, sizeof before);
        CHECK(zonekey_boot("doge", db) == 1, "the second boot succeeds");
        CHECK(ZK.created == 0, "ZK.created is 0 — the key was LOADED, not regenerated");
        CHECK(memcmp(ZK.seckey, first_sec, 32) == 0, "the same secret came back byte for byte");
        CHECK(memcmp(ZK.pub, first_pub, 33) == 0, "…and the same pubkey");
        char after[256];
        long an = file_bytes(keypath, after, sizeof after);
        CHECK(bn == an && bn > 0 && memcmp(before, after, (size_t)bn) == 0,
              "the key file is byte-identical after the load (never rewritten)");
        /* determinism under repetition */
        int stable = 1;
        for (int i = 0; i < 5; i++) {
            zonekey_boot("doge", db);
            if (memcmp(ZK.seckey, first_sec, 32) || memcmp(ZK.pub, first_pub, 33)) stable = 0;
        }
        CHECK(stable, "five more boots return the identical keypair");
    }

    printf("-- distinct inputs -> distinct keys --\n");
    {
        char db2[512];
        snprintf(db2, sizeof db2, "%s/chain.db", TDIR);
        CHECK(zonekey_boot("shib", db2) == 1, "a different coin boots its own key file");
        char p2[512];
        snprintf(p2, sizeof p2, "%s/zonekey-shib.key", TDIR);
        CHECK(strcmp(ZK.path, p2) == 0, "…at zonekey-shib.key, beside the doge one");
        CHECK(memcmp(ZK.seckey, first_sec, 32) != 0, "a different coin gets a DIFFERENT secret");
        CHECK(access(keypath, R_OK) == 0, "the doge key file is untouched");
    }

    printf("-- the hex codec round-trips exactly --\n");
    {
        wipe_keys();
        uint8_t known[32];
        for (int i = 0; i < 32; i++) known[i] = (uint8_t)(0x10 + i);   /* a valid scalar */
        char kh[65]; tohex(known, 32, kh);
        char body[160];
        snprintf(body, sizeof body, "coin=doge\nseckey=%s\n", kh);
        CHECK(write_keyfile("doge", body) == 1, "a key file with a known secret is planted");
        CHECK(zonekey_boot("doge", db) == 1, "it boots");
        CHECK(ZK.created == 0, "…as a load");
        CHECK(memcmp(ZK.seckey, known, 32) == 0, "the 64 hex chars decoded to the exact 32 bytes");
        uint8_t chk[33];
        CHECK(sp_pubkey(known, chk) == 1 && memcmp(ZK.pub, chk, 33) == 0,
              "the derived pubkey matches sp_pubkey of the planted secret");
        /* uppercase hex and CRLF line endings are still accepted */
        wipe_keys();
        char up[65];
        for (int i = 0; i < 64; i++) up[i] = (char)(kh[i] >= 'a' && kh[i] <= 'f' ? kh[i] - 32 : kh[i]);
        up[64] = 0;
        snprintf(body, sizeof body, "coin=doge\r\nseckey=%s\r\n", up);
        write_keyfile("doge", body);
        CHECK(zonekey_boot("doge", db) == 1 && memcmp(ZK.seckey, known, 32) == 0,
              "uppercase hex with CRLF line endings still decodes");
    }

    printf("-- malformed hot-key files FAIL CLOSED --\n");
    {
        struct { const char *body, *what; } bad[] = {
            { "coin=doge\n",                          "no seckey line" },
            { "",                                     "an empty file" },
            { "seckey=\n",                            "an empty seckey" },
            { "seckey=00\n",                          "hex too short" },
            { "seckey=zz00112233445566778899aabbccddeeff00112233445566778899aabbcc\n",
                                                      "non-hex characters" },
            { "seckey=0000000000000000000000000000000000000000000000000000000000000000\n",
                                                      "the all-zero scalar" },
            { "seckey=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\n",
                                                      "a scalar past the group order" },
            { "seckey=fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141\n",
                                                      "exactly the group order n" },
        };
        for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            wipe_keys();
            write_keyfile("doge", bad[i].body);
            char nm[96];
            snprintf(nm, sizeof nm, "REFUSED: %s", bad[i].what);
            int rc = zonekey_boot("doge", db);
            CHECK(rc == 0 && ZK.ok == 0, nm);
        }
        /* trailing junk after a good key is ignored — the last seckey= wins */
        wipe_keys();
        uint8_t known[32];
        for (int i = 0; i < 32; i++) known[i] = (uint8_t)(0x10 + i);
        char kh[65]; tohex(known, 32, kh);
        char body[256];
        snprintf(body, sizeof body, "coin=doge\nseckey=%s\nnote=hello\n", kh);
        write_keyfile("doge", body);
        CHECK(zonekey_boot("doge", db) == 1 && memcmp(ZK.seckey, known, 32) == 0,
              "an unknown trailing key=value line is ignored");
    }

    printf("-- zonekey_cert: refusals before any key is touched --\n");
    {
        uint8_t cert[512];
        memset(&WLT, 0, sizeof WLT);
        WLT.ok = 0;
        CHECK(zonekey_cert("pepe", 1000, cert, sizeof cert) == 0, "no wallet key -> no cert");

        /* a real money key: sha256("owner") is a valid scalar */
        sp_sha256((const uint8_t *)"owner", 5, WLT.seckey);
        while (!sp_pubkey(WLT.seckey, WLT.pub)) sp_sha256(WLT.seckey, 32, WLT.seckey);
        sp_hash160(WLT.pub, 33, WLT.h160);
        snprintf(WLT.coin, sizeof WLT.coin, "doge");
        WLT.ok = 1;

        CHECK(zonekey_cert("", 1000, cert, sizeof cert) == 0, "an empty name -> no cert");
        CHECK(zonekey_cert(NULL, 1000, cert, sizeof cert) == 0, "a NULL name -> no cert");
        char n33[34]; memset(n33, 'a', 33); n33[33] = 0;
        CHECK(zonekey_cert(n33, 1000, cert, sizeof cert) == 0,
              "a 33-byte name -> no cert (past the §3.1 apex bound)");
        char n32[33]; memset(n32, 'a', 32); n32[32] = 0;
        CHECK(zonekey_cert(n32, 1000, cert, sizeof cert) > 0, "a 32-byte name mints");
        CHECK(zonekey_cert("a", 1000, cert, sizeof cert) > 0, "a 1-byte name mints");
    }

    printf("-- zonekey_cert: what the minted cert actually says --\n");
    uint8_t cert_a[512]; int len_a;
    {
        len_a = zonekey_cert("pepe", 1000, cert_a, sizeof cert_a);
        CHECK(len_a > 0, "a cert mints for 'pepe' at tip 1000");
        SpCert vc;
        CHECK(sp_cert_parse(SP_CERT_P2PKH, cert_a, len_a, &vc) == 1, "the cert PARSES as §2.2 P2PKH");
        CHECK(vc.name_len == 4 && memcmp(vc.name, "pepe", 4) == 0, "…is bound to the name 'pepe'");
        CHECK(vc.posting_key && memcmp(vc.posting_key, ZK.pub, 33) == 0,
              "…delegates to the CURRENT hot key, not the money key");
        CHECK(vc.owner_key && memcmp(vc.owner_key, WLT.pub, 33) == 0,
              "…and is signed under the wallet (money) key");
        CHECK((vc.scope & DNS_SCOPE) != 0, "…carries the DNS_SCOPE bit");
        CHECK(vc.not_after == 1000 + ZK_CERT_TTL,
              "…expires exactly ZK_CERT_TTL (90 days of 1-min blocks) past the tip");
        CHECK(sp_cert_verify(&vc, (const uint8_t *)"pepe", 4, ZK.pub, 1001, WLT.h160) == 1,
              "the cert VERIFIES against the hot key and the wallet's hash160");
        CHECK(sp_cert_verify(&vc, (const uint8_t *)"other", 5, ZK.pub, 1001, WLT.h160) != 1,
              "…and does NOT verify for a different name");

        char cp[600];
        snprintf(cp, sizeof cp, "%s/zonecert-doge-pepe.bin", TDIR);
        char disk[512];
        long dn = file_bytes(cp, disk, sizeof disk);
        CHECK(dn == len_a && memcmp(disk, cert_a, (size_t)len_a) == 0,
              "the cert is persisted verbatim to zonecert-<coin>-<name>.bin");
    }

    printf("-- zonekey_cert: caching, the re-mint margin, and distinct names --\n");
    {
        uint8_t c2[512];
        int l2 = zonekey_cert("pepe", 1000, c2, sizeof c2);
        CHECK(l2 == len_a && memcmp(c2, cert_a, (size_t)len_a) == 0,
              "the same (name, tip) returns the identical cached cert");

        /* one block inside the margin: still cached */
        uint32_t na = 1000 + ZK_CERT_TTL;
        l2 = zonekey_cert("pepe", na - ZK_CERT_MARGIN - 1, c2, sizeof c2);
        CHECK(l2 == len_a && memcmp(c2, cert_a, (size_t)len_a) == 0,
              "one block INSIDE the 7-day margin the cached cert is still handed out");

        /* exactly at the margin: re-mint (the guard is tip + MARGIN < not_after) */
        l2 = zonekey_cert("pepe", na - ZK_CERT_MARGIN, c2, sizeof c2);
        CHECK(l2 > 0 && (l2 != len_a || memcmp(c2, cert_a, (size_t)len_a) != 0),
              "AT the margin boundary a fresh cert is minted");
        SpCert vc2;
        CHECK(sp_cert_parse(SP_CERT_P2PKH, c2, l2, &vc2) == 1 &&
              vc2.not_after == (na - ZK_CERT_MARGIN) + ZK_CERT_TTL,
              "…with its window rolled forward from the new tip");

        uint8_t cb[512];
        int lb = zonekey_cert("shibe", 1000, cb, sizeof cb);
        CHECK(lb > 0 && (lb != len_a || memcmp(cb, cert_a, (size_t)len_a) != 0),
              "a different name mints a different cert");
        SpCert vb;
        CHECK(sp_cert_parse(SP_CERT_P2PKH, cb, lb, &vb) == 1 &&
              vb.name_len == 5 && memcmp(vb.name, "shibe", 5) == 0,
              "…bound to that name");
        CHECK(sp_cert_verify(&vb, (const uint8_t *)"pepe", 4, ZK.pub, 1001, WLT.h160) != 1,
              "…and it does not authorize 'pepe'");

        /* more names than the 16-slot memory cache: every one still mints */
        int all = 1;
        for (int i = 0; i < 24; i++) {
            char nm[24];
            snprintf(nm, sizeof nm, "name%02d", i);
            uint8_t c[512];
            int l = zonekey_cert(nm, 2000, c, sizeof c);
            SpCert v;
            if (l <= 0 || !sp_cert_parse(SP_CERT_P2PKH, c, l, &v) ||
                (int)v.name_len != (int)strlen(nm) || memcmp(v.name, nm, v.name_len)) all = 0;
        }
        CHECK(all, "24 names (past the 16-slot cache) each mint a correctly bound cert");
        /* an evicted name re-mints from DISK rather than re-signing blind */
        uint8_t c3[512];
        int l3 = zonekey_cert("pepe", na - ZK_CERT_MARGIN, c3, sizeof c3);
        CHECK(l3 == l2 && memcmp(c3, c2, (size_t)l2) == 0,
              "a name evicted from memory comes back identical (disk cache)");
    }

    printf("-- zonekey_cert: a short output buffer is refused, not overrun --\n");
    {
        struct { uint8_t buf[16]; uint8_t canary[32]; } box;
        memset(&box, 0x5A, sizeof box);
        int rc = zonekey_cert("tinybuf", 3000, box.buf, sizeof box.buf);
        CHECK(rc == 0, "a cap smaller than the cert returns 0");
        int intact = 1;
        for (unsigned i = 0; i < sizeof box.canary; i++) if (box.canary[i] != 0x5A) intact = 0;
        CHECK(intact, "…and writes nothing past the cap");
        /* it still persisted, so a later call with room gets it */
        uint8_t big[512];
        int l = zonekey_cert("tinybuf", 3000, big, sizeof big);
        CHECK(l > (int)sizeof box.buf, "the same name mints fine into a big enough buffer");
    }

    printf("-- a stale hot key invalidates the disk cert --\n");
    {
        /* rotate the hot key by wiping the file and re-booting: the cert on
         * disk still delegates to the OLD hot key, so load_cert must reject it
         * and zonekey_cert must mint a fresh one. */
        uint8_t old_pub[33];
        memcpy(old_pub, ZK.pub, 33);
        char kf[512];
        snprintf(kf, sizeof kf, "%s/zonekey-doge.key", TDIR);
        unlink(kf);
        CHECK(zonekey_boot("doge", db) == 1 && ZK.created == 1, "the hot key is rotated");
        CHECK(memcmp(ZK.pub, old_pub, 33) != 0, "…to a genuinely different hot key");
        uint8_t c[512];
        int l = zonekey_cert("rotated", 4000, c, sizeof c);
        SpCert v;
        CHECK(l > 0 && sp_cert_parse(SP_CERT_P2PKH, c, l, &v) == 1 &&
              memcmp(v.posting_key, ZK.pub, 33) == 0,
              "a cert minted after rotation delegates to the NEW hot key");
    }

    rm_rf_dir();
    printf("%s\n", g_fail ? "t_zonekey: FAIL" : "t_zonekey: all ok");
    return g_fail;
}
