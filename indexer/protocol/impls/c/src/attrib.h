// §4 Stateless Identity & Attribution — cross-language conformance shell.
//
// The byte-logic of attribution (strict-DER, low-S, canonical pubkey ENCODING,
// P2SH-multisig template + in-order scan, the legacy sighash incl. FindAndDelete,
// SIGHASH_ALL, Identity = RIPEMD160(SHA256(x))) computed FOR REAL over generated
// raw transactions. The only curve ops — `on_curve(pubkey)` and `verify(hash,sig,
// pubkey)` — are INJECTED as pinned pseudo-functions of the bytes (no secp256k1),
// exactly as §6 injects identity. Pinned in SPEC-conformance.md §13.
#ifndef SM_ATTRIB_H
#define SM_ATTRIB_H

int attrib_cmd_fuzz(int argc, char **argv);      // `attrib <seed> <count> [--cov]` (injected curve oracle)
int attrib_cmd_scenario(int argc, char **argv);  // `attrib-scenario` (injected curve oracle)
int attrib_cmd_curve(void);                      // `attrib-curve` — REAL secp256k1 vector set (§4 Strategy B)
// end-to-end real-pipeline vectors: sign the actual legacy sighash with RFC-6979,
// embed, run attribute() with the REAL curve. comb is a SHA256_CTX* (folded into
// the attrib-curve combined digest). Defined in attrib.c (needs static attribute()).
void attrib_real_endtoend(void *comb_sha256_ctx);
int attrib_selftest(void);                       // RIPEMD160 / DER / FindAndDelete + secp256k1 KATs (C only)

#endif
