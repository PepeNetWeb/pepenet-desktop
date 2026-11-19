// PepeNet headless indexer — CLI entry.
//
// The state machine is the protocol-sm fold (../../protocol-sm/impls/c), linked
// as the consensus engine. This binary adds the chain side the reference omits:
// real Dogecoin block/tx decode + §4 attribution (the adapter), a sqlite
// projection of the fold state, and a P2P sync loop.
#include "sm.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "indexer.h"
#include "pow.h"

int chain_selftest(void);                 // test_chain.c
int mempool_selftest(void);               // test_chain.c (relay mempool + txcheck)
int chain_mkblocks(const char *dir);      // test_chain.c (offline `index` test fixtures)

static void hex32(const uint8_t b[32], char out[65]) {
    static const char *H = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 15]; }
    out[64] = 0;
}
static int eqhex(const uint8_t b[32], const char *want) {
    char got[65]; hex32(b, got); return strcmp(got, want) == 0;
}

// ── engine-link + shim conformance against the reference goldens ──────────────
static int cmd_selftest(void) {
    int fail = 0;
    #define EXPECT(cond, msg) do { if (cond) { printf("  ok   %s\n", msg); } \
        else { printf("  FAIL %s\n", msg); fail++; } } while (0)

    // 1. The fold + canonical SHA-256 digest reproduce the reference action stream
    //    (proves the engine is linked & folding byte-identically in this build).
    uint8_t in[32], st[32];
    sm_generate(42, 2000, 0, in, st, NULL, NULL, NULL);
    // Goldens = protocol/impls/c `./sm random 42 2000` (the stream embeds the
    // 0xFF 'P' 'N' universal prefix, so any prefix skew between this link and
    // the reference forks input_digest immediately).
    EXPECT(eqhex(in, "1b8e794802636a0bf6da528755eabe566ae20ef04eba7dcd2b71db3ce9b738d0"),
           "sm_generate(42,2000) input_digest matches reference");
    EXPECT(eqhex(st, "0bba34a7ab905a6bc403ce33fe28b1054bd6182ae14e0f7bcd7ff957756ea2ad"),
           "sm_generate(42,2000) state_digest matches reference");

    // 2. Empty-state digests (canonical + ECMH). The ECMH anchor exercises the
    //    libsecp shim (identity/hash-to-curve/add) and pins it to the §13.2 golden.
    SmState *s = sm_new(1);
    uint8_t d[32], e[32];
    sm_state_digest(s, d);
    sm_state_ecmh(s, e);
    // (Empty-state goldens are prefix-independent; = the impls/c selftest prints.)
    EXPECT(eqhex(d, "0967073bc100b3e1e16833c03f3277dcd7d5076c77a98d6b3ce9ce4aae8ec298"),
           "empty_state_digest matches reference");
    EXPECT(eqhex(e, "3ecfc3d7fa5be56fc513dde926bdf105c92accbf07088e702f85856fa69d10e0"),
           "empty_state_ecmh matches reference (libsecp shim)");
    sm_free(s);

    printf("\n-- end-to-end chain pipeline (parse → §4 attribute → fold) --\n");
    fail += chain_selftest();

    printf("\n-- relay mempool (context-free tx validation + pool) --\n");
    fail += mempool_selftest();

    printf("\n-- proof-of-work primitives (scrypt / compact / Digishield) --\n");
    { int pf = idx_pow_selftest();
      if (pf) fail += pf; else printf("  ok   RFC 7914 scrypt vector + compact round-trips + Digishield\n"); }

    printf(fail ? "\nselftest: %d FAILED\n" : "\nselftest: ALL PASSED\n", fail);
    return fail ? 1 : 0;
}

static int usage(const char *p) {
    fprintf(stderr,
      "usage: %s <command> [args]\n"
      "  selftest                 engine-link + shim conformance vs reference goldens\n"
      "  ecmh                     print the §13.2 ECMH primitive vectors (combined golden)\n"
      "  sync   <coin> <db> [peers|auto] [activation]  connect over P2P and index the chain (confirmed-only)\n"
      "  crawl  <coin> <db> [max_dials] [host:port,...]  explore the chain graph, classify peers by agent\n"
      "  serve  <coin> <db> [port] [host:port,...]  run as a pepenet chain peer (serve headers/blocks, gossip)\n"
      "  resolve <db> <name>      print the current owner (hash160) of a name\n"
      "  owned  <db> <hash160hex> list names owned by an address\n"
      "  digest <db> [--coin C]   print height, live §3.4 rate, and the state digest\n"
      "  refold <db> [--coin C] [--force]  rebuild the fold from local blocks under current rules\n"
      "                           (refuses if referenced heights are missing from raw_blocks)\n"
      "  watch  <db> <addr|h160>  register a wallet address for UTXO tracking (before funding!)\n"
      "  index  <blockfile>       fold a raw block file (hex or binary) — offline\n"
      "  check  <db> [serve-db]   read-only integrity/consistency check (exit 1 on errors)\n"
      "  snapshot-export <coin> <db> <outdir>         offline: state.db copy + MANIFEST (digest/ECMH at H)\n"
      "  snapshot-verify <coin> <snapdir> [headers] (--sha256 <hex> | --allow-unpinned)   pin gate (no pin = refuse), then recheck digests + header PoW\n"
      "  snapshot-import <coin> <snapdir> <db> [--sha256 <hex>]   apply a PINNED snapshot as a fresh db (fail closed)\n",
      p);
    return 2;
}

int main(int argc, char **argv) {
    if (argc < 2) return usage(argv[0]);
    const char *cmd = argv[1];
    if (!strcmp(cmd, "selftest")) return cmd_selftest();
    if (!strcmp(cmd, "ecmh"))     return ecmh_cmd();
    if (!strcmp(cmd, "mkblocks")) return argc > 2 ? chain_mkblocks(argv[2]) : usage(argv[0]);
    if (!strcmp(cmd, "sync") || !strcmp(cmd, "resolve") || !strcmp(cmd, "owned") ||
        !strcmp(cmd, "digest") || !strcmp(cmd, "index") ||
        !strcmp(cmd, "watch") || !strcmp(cmd, "refold") || !strcmp(cmd, "crawl") ||
        !strcmp(cmd, "serve") || !strcmp(cmd, "weigh") ||
        !strcmp(cmd, "snapshot-export") || !strcmp(cmd, "snapshot-verify") || !strcmp(cmd, "snapshot-import") ||
        !strcmp(cmd, "check"))
        return indexer_main(argc, argv);
    return usage(argv[0]);
}
