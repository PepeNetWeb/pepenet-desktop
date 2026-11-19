// net_test.c — self-test battery for pepenet-mesh.
//
// Proves the shared substrate end-to-end with REAL data: the dev key
// e32056… derives to the pubkey whose hash160 is both the payload of the
// wallet address PtvGit8g… AND the on-chain owner of `pepenet` in pep.db.
// That single chain is the entire trust model an overlay relies on.
//
// Also pins §3.1 name rules (sp_name_valid) so overlays refuse the same labels
// consensus refuses, and a chainless test-mode view for mesh bootstraps.
#include "pepenet/wire.h"
#include "pepenet/crypto.h"
#include "pepenet/view.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fails = 0;
#define OK(cond, msg) do { \
    if (cond) printf("  ok   %s\n", msg); \
    else { printf("  FAIL %s\n", msg); fails++; } } while (0)

static void hex(const uint8_t *b, int n, char *out) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 15]; }
    out[2*n] = 0;
}

static int hexbytes(const char *h, uint8_t *out, int n) {
    for (int i = 0; i < n; i++) { unsigned v; if (sscanf(h + 2*i, "%2x", &v) != 1) return 0; out[i] = (uint8_t)v; }
    return 1;
}

// the key that actually owns `pepenet` on pepecoin (~/.pepenet/pep-test2.key →
// address PqoGtDz…, hash160 c406ee39… == names.owner for `pepenet`).
static const char *DEV_PRIV = "1f2d2cd99384a259508dfe82a1b28877e64f8e1dc4561bbf4641f4a4247dfd4e";
static const char *DEV_ADDR = "PqoGtDzCCSbR6yiwG8Ch9VeyXw7uTNUYTi";

static void test_name_valid(void) {
    printf("name: §3.1 DNS-label rules (sp_name_valid)\n");
    OK(sp_name_valid("a", 1), "single letter");
    OK(sp_name_valid("0", 1), "single digit");
    OK(sp_name_valid("pepenet", 7), "pepenet");
    OK(sp_name_valid("wallet-pepenet", 14), "hyphen mid-label");
    OK(sp_name_valid("a1b2c3", 6), "alnum mix");

    char max32[33];
    memset(max32, 'a', 32); max32[32] = 0;
    OK(sp_name_valid(max32, 32), "32-byte name (SP_NAME_MAX)");
    OK(!sp_name_valid(max32, 33), "33-byte name rejected");
    OK(!sp_name_valid("", 0), "empty rejected");
    OK(!sp_name_valid(NULL, 1), "NULL rejected");

    OK(!sp_name_valid("Alice", 5), "uppercase rejected (no fold)");
    OK(!sp_name_valid("foo.bar", 7), "dot rejected (no FQDN look-alike)");
    OK(!sp_name_valid("foo_bar", 7), "underscore rejected");
    OK(!sp_name_valid("-lead", 5), "leading hyphen rejected");
    OK(!sp_name_valid("trail-", 6), "trailing hyphen rejected");
    OK(!sp_name_valid("xn--foo", 7), "xn-- (ACE) rejected via -- at 3–4");
    OK(!sp_name_valid("ab--cd", 6), "-- at positions 3–4 rejected");
    OK(sp_name_valid("a-b", 3), "hyphen not at 3–4 still ok (len 3)");
    OK(sp_name_valid("ab-cd", 5), "hyphen at position 3 alone ok");
    OK(sp_name_valid("a--b", 4), "-- at positions 2–3 ok (only 3–4 banned)");
}

static void test_view_testmode(const uint8_t owner[20]) {
    printf("view: chainless test mode\n");
    char path[] = "/tmp/spnet-names.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { OK(0, "mkstemp for names file"); return; }
    char h[41];
    hex(owner, 20, h);
    // valid rows + junk rows the loader must skip (write line-by-line; a single
    // 128-byte snprintf would truncate the multi-row fixture).
    FILE *wf = fdopen(fd, "w");
    if (!wf) { close(fd); unlink(path); OK(0, "fdopen names file"); return; }
    fprintf(wf, "pepenet %s\n", h);
    fprintf(wf, "Alice %s\n", h);       /* uppercase — skip */
    fprintf(wf, "foo.bar %s\n", h);     /* dot — skip */
    fprintf(wf, "xn--bad %s\n", h);     /* ACE — skip */
    fprintf(wf, "also-mine %s\n", h);
    fclose(wf);

    SpView *v = sp_view_open_test(path, 1000);
    OK(v != NULL, "open test names file");
    if (v) {
        OK(sp_view_tip(v) == 1000, "test tip = 1000");
        uint8_t got[20];
        OK(sp_view_owner_now(v, "pepenet", got) && memcmp(got, owner, 20) == 0,
           "pepenet owned in test table");
        OK(sp_view_owner_now(v, "also-mine", got) && memcmp(got, owner, 20) == 0,
           "also-mine owned in test table");
        OK(!sp_view_owner_now(v, "Alice", got), "invalid uppercase not loaded");
        OK(!sp_view_owner_now(v, "no-such-name", got), "missing name → 0");
        OK(!sp_view_owner_of(v, (const uint8_t *)"foo_bar", 7, 1000, got),
           "invalid name short-circuits to unowned");
        OK(sp_view_addr_owns_name(v, owner), "addr owns at least one name");
        uint8_t nobody[20]; memset(nobody, 0, 20);
        OK(!sp_view_addr_owns_name(v, nobody), "zero addr owns nothing");
        sp_view_close(v);
    }
    unlink(path);
}

int main(int argc, char **argv) {
    char buf[128];

    printf("wire: CompactSize roundtrip across boundaries\n");
    uint64_t vals[] = { 0, 1, 0xFC, 0xFD, 0xFFFF, 0x10000, 0xFFFFFFFFULL, 0x100000000ULL };
    for (unsigned i = 0; i < sizeof vals / sizeof *vals; i++) {
        uint8_t w[9]; int n = sp_wvar(w, vals[i]);
        int off = 0; uint64_t got = 0;
        int ok = sp_rvar(w, n, &off, &got) && got == vals[i] && off == n;
        snprintf(buf, sizeof buf, "varint %llu (%d bytes)", (unsigned long long)vals[i], n);
        OK(ok, buf);
    }
    { int off = 0; uint64_t v; OK(!sp_rvar((const uint8_t *)"\xFD\x01", 2, &off, &v), "truncated varint rejected"); }

    printf("crypto: key → pubkey → hash160 → address\n");
    uint8_t priv[32], pub[33], h160[20];
    OK(hexbytes(DEV_PRIV, priv, 32), "dev priv parsed");
    OK(sp_pubkey(priv, pub), "pubkey derived");
    sp_hash160(pub, 33, h160);
    hex(h160, 20, buf);
    printf("       hash160(pub) = %s\n", buf);

    // decode the known wallet address → version + payload; payload must equal hash160(pub)
    uint8_t ver, pay[64]; size_t paylen = 0;
    OK(sp_addr_decode(DEV_ADDR, &ver, pay, sizeof pay, &paylen), "wallet address decodes (checksum ok)");
    OK(paylen == 20 && memcmp(pay, h160, 20) == 0, "address payload == hash160(pub)");
    printf("       address version byte = 0x%02x\n", ver);

    // re-encode with the discovered version → must reproduce the address
    char addr[64];
    OK(sp_addr_encode(ver, h160, 20, addr, sizeof addr) && strcmp(addr, DEV_ADDR) == 0,
       "re-encode reproduces the wallet address");

    printf("crypto: ECDSA sign / verify\n");
    uint8_t digest[32]; sp_sha256((const uint8_t *)"pepenet zone v1", 15, digest);
    uint8_t sig[64];
    OK(sp_ecdsa_sign(priv, digest, sig), "sign digest");
    OK(sp_ecdsa_verify(digest, sig, pub, 33), "verify good signature");
    sig[0] ^= 0x01;
    OK(!sp_ecdsa_verify(digest, sig, pub, 33), "tampered signature rejected");
    sig[0] ^= 0x01;
    digest[0] ^= 0x01;
    OK(!sp_ecdsa_verify(digest, sig, pub, 33), "wrong digest rejected");

    OK(sp_key_is_owner(pub, 33, h160), "sp_key_is_owner true for matching hash160");
    uint8_t other[20]; memcpy(other, h160, 20); other[0] ^= 0xFF;
    OK(!sp_key_is_owner(pub, 33, other), "sp_key_is_owner false for other owner");

    test_name_valid();
    test_view_testmode(h160);

    if (argc > 1) {
        printf("view: ownership of `pepenet` from %s\n", argv[1]);
        SpView *v = sp_view_open_chain(argv[1]);
        OK(v != NULL, "open indexer db");
        if (v) {
            printf("       tip height = %u\n", sp_view_tip(v));
            uint8_t owner[20];
            int owned = sp_view_owner_now(v, "pepenet", owner);
            OK(owned, "pepenet is owned on-chain");
            if (owned) {
                hex(owner, 20, buf);
                printf("       on-chain owner = %s\n", buf);
                OK(memcmp(owner, h160, 20) == 0,
                   "on-chain owner == hash160(dev pubkey)  ← the dev key owns pepenet");
            }
            uint8_t none[20];
            OK(!sp_view_owner_now(v, "no-such-name-xyz", none), "unowned valid name → 0");
            OK(!sp_view_owner_now(v, "Alice", none), "invalid name → 0 without lookup");
            sp_view_close(v);
        }
    } else {
        printf("view: (pass an indexer db path as argv[1] to test chain ownership)\n");
    }

    printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "PASSED", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
