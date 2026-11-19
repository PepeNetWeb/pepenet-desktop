#!/usr/bin/env node
// PepeNet namespace reference state machine — clean-room TypeScript implementation (CLI entry).
// Run with Node ≥ 23.6 (native TS type-stripping):  node sm.ts <mode> [args]
//
// Modes:
//   selftest                 run the hand-authored conformance battery (the validation gate)
//   digest                   dump the canonical state digest for a fixed hand-built scenario
//   prng <seed> <count>      print SplitMix64 outputs (and the pinned seed=0 check)
//   random <seed> <blocks>   run MY OWN generator (NON-GOLDEN — see note) → input+state digests
//   forkvectors              consensus-fork differential vectors (spec-outcome check; cf. impls/c forkvectors)
//   help
import { runSelftest } from "./src/selftest.ts";
import { runGenerator } from "./src/gen.ts";
import { SplitMix64 } from "./src/prng.ts";
import { Fold } from "./src/fold.ts";
import { hex } from "./src/bytes.ts";
import * as B from "./src/builders.ts";
import { ST, COMMIT_EXPIRY } from "./src/constants.ts";
import * as Modes from "./src/modes.ts";
import { cmdAttribCurve } from "./src/attrib_curve.ts";
import { cmdEcmh } from "./src/ecmh.ts";
import { cmdScenario } from "./src/scenario.ts";

const args = process.argv.slice(2);
const mode = args[0] ?? "help";

function digestDump(): void {
  // A small, fully-deterministic hand scenario that exercises names/commits/muts,
  // then dumps the §4-canonical digest. This is the required "state-digest dump".
  const f = new Fold(0n);
  const id1 = B.genId(1), id2 = B.genId(2);
  const salt1 = new Uint8Array(32).fill(11), salt2 = new Uint8Array(32).fill(22);
  // block 1: two commits
  f.beginBlock(1n, 1000n, 28n);
  f.applyTx(B.tx([B.input(id1)], [B.commit(B.commitmentOf(salt1, "alpha", id1))]), 0);
  f.applyTx(B.tx([B.input(id2)], [B.commit(B.commitmentOf(salt2, "beta", id2))]), 1);
  console.log("after block1 (2 commits):", hex(f.digest()));
  // block 2: two claims
  f.beginBlock(2n, 1100n, 28n);
  f.applyTx(B.tx([B.input(id1)], [B.claim(salt1, "alpha", 30n)]), 0);
  f.applyTx(B.tx([B.input(id2)], [B.claim(salt2, "beta", 60n)]), 1);
  console.log("after block2 (alpha→id1, beta→id2):", hex(f.digest()));
  // block 3: SELL + TRANSFER (names-only surface)
  f.beginBlock(3n, 1200n, 28n);
  f.applyTx(B.tx([B.input(id2)], [B.sell(1000n, 18000n, "beta")]), 0);
  f.applyTx(B.tx([B.input(id1)], [B.transferAll(id2)]), 1);
  console.log("after block3 (sell/transfer):", hex(f.digest()));
  console.log("\nlive names:", f.names.size, "commits:", f.commits.length, "muts:", f.muts.size);
}

// ── consensus-fork differential vectors (TV-N from SPEC-RATIONALE.md + M9) ───────────────
// Each runs a TV-N construction against THIS impl and asserts the SPEC-pinned (2026-06-29) outcome,
// mirroring impls/c `forkvectors` so C / Java / TS are directly comparable. A "DIVERGE" line is a
// real divergence from the hardened prose. Independent impls can't share the gen.c seed-soak, but
// they MUST each produce the spec outcome for every consensus-critical vector.
function cmdForkvectors(): number {
  const dec = new TextDecoder();
  const salt = (b: number): Uint8Array => new Uint8Array(32).fill(b);
  let pass = 0, fail = 0;
  const rowOf = (f: Fold, name: string) => {
    for (const r of f.names.values()) if (dec.decode(r.name) === name) return r;
    return undefined;
  };
  const owns = (f: Fold, id: Uint8Array, name: string): boolean => {
    const r = rowOf(f, name);
    return !!r && r.st === ST.OWNED && hex(r.owner) === hex(id);
  };
  const lease = (f: Fold, name: string): bigint => { const r = rowOf(f, name); return r ? r.leaseExpiry : -1n; };
  const fv = (tv: string, desc: string, got: string, want: string): void => {
    const ok = got === want;
    if (ok) pass++; else fail++;
    console.log(`  ${tv.padEnd(6)} ${desc.padEnd(44)} ts=${got.padEnd(7)} spec=${want.padEnd(7)} ${ok ? "MATCH" : "*** DIVERGE ***"}`);
  };

  // TV-1: COMMIT_EXPIRY inclusive — a claim at MTP == commit_time + COMMIT_EXPIRY mints.
  {
    const f = new Fold(0n), A = B.genId(0xaa), ct = 1000n;
    f.beginBlock(5n, ct, 28n);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x11), "edge", A))]), 0);
    f.beginBlock(6n, ct + COMMIT_EXPIRY, 28n);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x11), "edge", 10n)]), 0);
    fv("TV-1", "COMMIT_EXPIRY inclusive boundary", owns(f, A, "edge") ? "mint" : "drop", "mint");
  }
  // TV-5b: one author, two matching commits (tx0,tx2) + rival (tx1) — author (min tx_index) wins both orders.
  {
    const f = new Fold(0n), A = B.genId(0xaa), Bb = B.genId(0xbb);
    f.beginBlock(5n, 1000n, 28n);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x11), "dup", A))]), 0);
    f.applyTx(B.tx([B.input(Bb)], [B.commit(B.commitmentOf(salt(0x22), "dup", Bb))]), 1);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x11), "dup", A))]), 2);
    f.beginBlock(6n, 1500n, 28n);
    f.applyTx(B.tx([B.input(Bb)], [B.claim(salt(0x22), "dup", 10n)]), 0); // rival claims first
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x11), "dup", 10n)]), 1);  // author claims second
    fv("TV-5b", "claim multiplicity (author min-tuple wins)", owns(f, A, "dup") ? "A wins" : owns(f, Bb, "dup") ? "B wins" : "none", "A wins");
  }
  // TV-6: bitmap LSB-first — flag 0x01 selects lexicographic name 0 (aa).
  {
    const f = new Fold(0n), A = B.genId(0xaa);
    f.beginBlock(5n, 1000n, 28n);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(1), "aa", A), 0), B.commit(B.commitmentOf(salt(2), "bb", A), 1), B.commit(B.commitmentOf(salt(3), "cc", A), 2)]), 0);
    f.beginBlock(6n, 1500n, 28n);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(1), "aa", 1n, 0), B.claim(salt(2), "bb", 1n, 1), B.claim(salt(3), "cc", 1n, 2)]), 0);
    const aa0 = lease(f, "aa"), bb0 = lease(f, "bb");
    f.beginBlock(7n, 1600n, 28n);
    f.applyTx(B.tx([B.input(A)], [B.renewSel(6n, new Uint8Array([0x01]), 10n)]), 0);
    fv("TV-6", "bitmap LSB-first (0x01 -> aa)", lease(f, "aa") > aa0 && lease(f, "bb") === bb0 ? "aa" : "other", "aa");
  }
  // TV-7: a pre-block LAPSE bumps last_set_mutation_height (§3.5), so a selective RENEW anchored at
  // H-1 (before the lapse) is REJECTED — not silently applied against a now-stale ordering.
  {
    const f = new Fold(0n), A = B.genId(0xaa), M = 1_000_000n;
    f.beginBlock(5n, M, 28n);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x11), "aa", A), 0), B.commit(B.commitmentOf(salt(0x22), "keep", A), 1)]), 0);
    f.beginBlock(6n, M, 28n);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x11), "aa", 1n, 0), B.claim(salt(0x22), "keep", 100n, 1)]), 0);
    const aaExp = lease(f, "aa"), keep0 = lease(f, "keep");
    f.beginBlock(7n, aaExp, 28n); // "aa" lapses pre-block at its expiry
    f.applyTx(B.tx([B.input(A)], [B.renewSel(6n, new Uint8Array([0x01]), 10n)]), 0);
    fv("TV-7", "lapse bumps mut height (stale RENEW)", lease(f, "keep") > keep0 ? "ACCEPT" : "REJECT", "REJECT");
  }
  // TV-8: a selective TRANSFER selecting a LOCKED (listed) name skips it, moves the rest.
  {
    const f = new Fold(0n), A = B.genId(0xaa), T = B.genId(0x77);
    f.beginBlock(5n, 1000n, 28n);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(1), "aa", A), 0), B.commit(B.commitmentOf(salt(2), "bb", A), 1), B.commit(B.commitmentOf(salt(3), "cc", A), 2)]), 0);
    f.beginBlock(6n, 1500n, 28n);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(1), "aa", 200n, 0), B.claim(salt(2), "bb", 200n, 1), B.claim(salt(3), "cc", 200n, 2)]), 0);
    f.beginBlock(7n, 1600n, 28n);
    f.applyTx(B.tx([B.input(A)], [B.sell(300n, 20000n, "bb")]), 0); // bb LISTED (movement-locked)
    f.beginBlock(8n, 1700n, 28n);
    f.applyTx(B.tx([B.input(A)], [B.transferSel(T, 7n, new Uint8Array([0x03]))]), 0); // bits 0,1 → aa,bb
    const bb = rowOf(f, "bb");
    const ok = owns(f, T, "aa") && !!bb && bb.st === ST.LISTED && owns(f, A, "cc");
    fv("TV-8", "locked-name selective skip", ok ? "skip" : "other", "skip");
  }
  // M9: TRADE is attributed to its named parties (idxA/idxB), NOT the acting identity. A TRADE
  // whose vin[0] is ⊥ (didn't sign SIGHASH_ALL) still settles if both parties are valid.
  {
    const f = new Fold(0n), A = B.genId(1), Bb = B.genId(2);
    f.beginBlock(5n, 1000n, 28n);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x11), "na", A))]), 0);
    f.applyTx(B.tx([B.input(Bb)], [B.commit(B.commitmentOf(salt(0x22), "nb", Bb))]), 1);
    f.beginBlock(6n, 1100n, 28n);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x11), "na", 50n)]), 0);
    f.applyTx(B.tx([B.input(Bb)], [B.claim(salt(0x22), "nb", 50n)]), 1);
    f.beginBlock(7n, 1200n, 28n);
    const bottom = B.input(B.genId(9), 0, false); // vin[0] = ⊥ (no SIGHASH_ALL)
    f.applyTx(B.tx([bottom, B.input(A), B.input(Bb)], [B.trade(1, 2, "na", "nb")]), 0);
    fv("M9", "TRADE bypasses ⊥ acting identity", owns(f, Bb, "na") && owns(f, A, "nb") ? "swap" : "drop", "swap");
  }
  // H8: a used COMMIT lingers (NOT consumed) until its time-prune (§3.2; digest-affecting).
  {
    const f = new Fold(0n), A = B.genId(0xaa), ct = 1000n;
    f.beginBlock(5n, ct, 28n);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x11), "edge", A))]), 0);
    f.beginBlock(6n, 1100n, 28n);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x11), "edge", 10n)]), 0);
    const lingers = f.commits.length === 1; // claim did NOT remove the backing commit
    f.beginBlock(7n, ct + COMMIT_EXPIRY + 1n, 28n); // past the prune window
    fv("H8", "used commit lingers then time-prunes", lingers && f.commits.length === 0 ? "linger" : "other", "linger");
  }
  // H3: a per-owner mutation height persists after the owner's set empties (§3.5/§3.9; digest-affecting).
  {
    const f = new Fold(0n), A = B.genId(0xaa);
    f.beginBlock(5n, 1000n, 28n);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x11), "solo", A))]), 0);
    f.beginBlock(6n, 1100n, 28n);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x11), "solo", 10n)]), 0);
    f.beginBlock(7n, 1200n, 28n);
    f.applyTx(B.tx([B.input(A)], [B.release(6n, new Uint8Array([0x01]))]), 0); // releases solo → set empties
    const empty = rowOf(f, "solo") === undefined;
    const mutKept = [...f.muts.values()].some((m) => hex(m.owner) === hex(A));
    fv("H3", "mut row persists after set empties", empty && mutKept ? "kept" : "other", "kept");
  }

  console.log("────");
  console.log(`forkvectors: ${pass} match, ${fail} diverge (fold layer; spec-pinned 2026-06-29 reading)`);
  return fail ? 1 : 0;
}

switch (mode) {
  case "selftest": {
    const r = runSelftest();
    process.exit(r.fail ? 1 : 0);
    break;
  }
  case "digest":
    digestDump();
    break;
  case "prng": {
    const seed = BigInt(args[1] ?? "0");
    const count = Number(args[2] ?? "5");
    const r = new SplitMix64(seed);
    console.log(`SplitMix64 seed=${seed} (pinned check: seed=0 first = 0xE220A8397B1DCDAF)`);
    for (let i = 0; i < count; i++) console.log(`  ${i}: 0x${r.next().toString(16).padStart(16, "0")}`);
    break;
  }
  case "random": {
    const seed = BigInt(args[1] ?? "42");
    const blocks = Number(args[2] ?? "1000");
    console.log(`MY OWN generator (NON-GOLDEN — own draw order; does NOT reproduce the doc's frozen`);
    console.log(`seed-goldens, which depend on the forbidden impls/c/src/gen.c). seed=${seed} blocks=${blocks}`);
    const r = runGenerator(seed, blocks);
    console.log("input_digest:", r.inputDigest);
    console.log("state_digest:", r.stateDigest);
    break;
  }
  case "forkvectors":
    process.exit(cmdForkvectors());
    break;
  case "attrib-curve":
    process.exit(cmdAttribCurve());
    break;
  case "ecmh":
    process.exit(cmdEcmh());
    break;
  case "scenario":
    process.exit(cmdScenario());
    break;
  case "properties":
    process.exit(Modes.properties(BigInt(args[1] ?? "42"), Number(args[2] ?? "30000")));
    break;
  case "meta":
    process.exit(Modes.meta(BigInt(args[1] ?? "42"), Number(args[2] ?? "15000")));
    break;
  case "reorg":
    process.exit(Modes.reorg(BigInt(args[1] ?? "42"), Number(args[2] ?? "6000")));
    break;
  case "reorgfuzz":
    process.exit(Modes.reorgfuzz(BigInt(args[1] ?? "42"), Number(args[2] ?? "6000")));
    break;
  case "fuzz":
    process.exit(Modes.fuzz(BigInt(args[1] ?? "42"), Number(args[2] ?? "30000")));
    break;
  default:
    console.log(`PepeNet clean-room SM. Usage: node sm.ts <mode>
  selftest                 hand-authored conformance battery (validation gate)
  digest                   canonical state-digest dump (fixed scenario)
  prng <seed> <count>      SplitMix64 outputs
  random <seed> <blocks>   own generator (NON-GOLDEN) → input+state digests
  forkvectors              consensus-fork differential vectors (spec-outcome check)
  properties <seed> <n>    §8 invariant battery (violations==0)
  meta <seed> <n>          §11 inert-tx no-op (failures==0)
  reorg <seed> <n>         §10 reorg confluence (failures==0)
  reorgfuzz <seed> <n>     §11 K=64 fork/divergence trials (failures==0)
  fuzz <seed> <n>          §9 decoder fuzz (parser_crashes==0)
  help`);
}
