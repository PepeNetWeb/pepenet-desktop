// Exhaustive hand-authored conformance battery. Each case asserts an outcome DERIVED FROM THE PROSE
// (protocol-spec.md / SPEC-conformance.md) — hitting every rule and every boundary, especially the
// under-specified ones flagged in SPEC-RATIONALE.md. This is the self-validation the brief requires.
import { sha256 } from "./sha256.ts";
import { ripemd160, hash160 } from "./ripemd160.ts";
import { SplitMix64 } from "./prng.ts";
import { validUtf8 } from "./utf8.ts";
import { hex, fromHex, concat, u8, u32le, u64le, type Bytes } from "./bytes.ts";
import { decodePayload, singleMinimalPush, validName } from "./decode.ts";
import { Fold } from "./fold.ts";
import type { FoldTx } from "./fold.ts";
import { oracleRate, computeMTP } from "./oracle.ts";
import { OP, PREFIX0, PREFIX1, PREFIX2, RESERVE_WINDOW, DIRECT_WINDOW, REORG_BUFFER, BILLING_UNIT, MAX_LEASE, BODY_MAX } from "./constants.ts";
import * as B from "./builders.ts";
import { attribute, parseTx } from "./attribution.ts";
import {
  P as SECP_PP, N as SECP_NN, N_HALF as SECP_NH, GX as SECP_GX, GY as SECP_GY,
  be32, pubkey, ecdsaSign, ecdsaVerify, onCurve, secpSelftest,
} from "./secp256k1.ts";

let pass = 0, fail = 0;
const fails: string[] = [];
function ok(label: string, cond: boolean): void {
  if (cond) pass++; else { fail++; fails.push(label); }
}
function eq<T>(label: string, got: T, want: T): void {
  const g = typeof got === "bigint" ? got.toString() : JSON.stringify(got);
  const w = typeof want === "bigint" ? want.toString() : JSON.stringify(want);
  if (g === w) pass++; else { fail++; fails.push(`${label}: got ${g} want ${w}`); }
}
const enc = (s: string) => new TextEncoder().encode(s);
const DAY = BILLING_UNIT;
const owner = (f: Fold, name: string): string => {
  const r = f.names.get(hex(enc(name)));
  return r ? hex(r.owner) : "<none>";
};
const lease = (f: Fold, name: string): bigint => f.names.get(hex(enc(name)))!.leaseExpiry;
const st = (f: Fold, name: string): number | string => f.names.get(hex(enc(name)))?.st ?? "<none>";
const has = (f: Fold, name: string): boolean => f.names.has(hex(enc(name)));

// helper: stand up a freshly-claimed name owned by `idn` with `days` of lease at mtp `base`.
function claimName(f: Fold, idn: number, name: string, days: bigint, atHeight: bigint, mtp: bigint): void {
  const id = B.genId(idn);
  const salt = new Uint8Array(32).fill(idn + 100);
  const commitment = B.commitmentOf(salt, name, id);
  f.beginBlock(atHeight - 1n, mtp - 1n, 28n);
  f.applyTx(B.tx([B.input(id, B.genType(idn))], [B.commit(commitment)]), 0);
  f.beginBlock(atHeight, mtp, 28n); // rate 28 ⇒ T(days) = burn
  f.applyTx(B.tx([B.input(id, B.genType(idn))], [B.claim(salt, name, days)]), 0);
}

// ───────────────────────────── primitives ─────────────────────────────
function tPrimitives(): void {
  eq("sha256('')", hex(sha256(enc(""))), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  eq("ripemd160('abc')", hex(ripemd160(enc("abc"))), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
  eq("hash160('abc')", hex(hash160(enc("abc"))), "bb1be98c142444d7a56aa3981c3942a978e4dc33");
  eq("splitmix64(0)", new SplitMix64(0n).next().toString(16).padStart(16, "0"), "e220a8397b1dcdaf");
  ok("utf8 valid", validUtf8(enc("héllo ✓")));
  ok("utf8 reject 0xFF", !validUtf8(fromHex("ff")));
  ok("utf8 reject overlong", !validUtf8(fromHex("c080")));
  ok("utf8 reject surrogate", !validUtf8(fromHex("eda080")));
  ok("utf8 reject >10FFFF (f4908080)", !validUtf8(fromHex("f4908080")));
  ok("utf8 reject late-bad", !validUtf8(fromHex("61ff")));
  ok("utf8 accept 4-byte 😀", validUtf8(fromHex("f09f9880")));
}

// ───────────────────────────── charset + structural (§3.1) ─────────────────────────────
// [a-z0-9-], 1..32; no leading/trailing hyphen; no `--` at positions 3–4.
// Pins the OUTCOME behind scenario 52 / 52b.
function tDottedNames(): void {
  ok("hyphen name valid", validName(enc("shib-p2p")));
  ok("32-byte name valid", validName(enc("abcdefghijklmnopqrstuvwxyz0123ab")));
  ok("33-byte name invalid (max 32)", !validName(enc("abcdefghijklmnopqrstuvwxyz0123abc")));
  ok("dot now invalid", !validName(enc("shib.p2p")));
  ok("underscore now invalid", !validName(enc("shib_p2p")));
  ok("uppercase still invalid", !validName(enc("Shib-p2p")));
  ok("comma still invalid (TRADE pair split relies on it)", !validName(enc("a,b")));
  ok("leading hyphen invalid", !validName(enc("-a")));
  ok("trailing hyphen invalid", !validName(enc("a-")));
  ok("ACE prefix (xn--) invalid", !validName(enc("xn--x")));

  const A = B.genId(0xaa);
  const salt = (b: number): Bytes => new Uint8Array(32).fill(b);
  const f = new Fold(0n);
  f.beginBlock(10n, 1000n, 28n);
  f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x71), "shib-p2p", A))]), 0);
  f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x74), "shib.p2p", A))]), 1);
  f.beginBlock(11n, 1500n, 28n);
  f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x71), "shib-p2p", 10n)]), 0);
  f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x74), "shib.p2p", 10n)]), 1);
  eq("hyphen claim mints", owner(f, "shib-p2p"), hex(A));
  ok("dotted claim drops", !has(f, "shib.p2p") && f.names.size === 1);
}

// ───────────────────────────── decoder ─────────────────────────────
function frame(op: number, body: Bytes): Bytes {
  return concat(u8(PREFIX0), u8(PREFIX1), u8(PREFIX2), u8(op), body);
}
function dk(payload: Bytes, value = 0n): string {
  const r = decodePayload(payload, value);
  return r.kind;
}
function tDecoder(): void {
  // name validation
  ok("name lowercase ok", validName(enc("alice-99")));
  ok("name reject uppercase", !validName(enc("Alice"))); // charset is strict [a-z0-9-]
  ok("name reject underscore", !validName(enc("a_b")));
  ok("name reject empty", !validName(enc("")));
  ok("name reject 33", !validName(enc("a".repeat(33))));
  ok("name accept 32", validName(enc("a".repeat(32))));
  ok("name reject space", !validName(enc("a b")));
  ok("name reject comma", !validName(enc("a,b")));
  ok("name reject leading hyphen", !validName(enc("-a")));
  ok("name reject trailing hyphen", !validName(enc("a-")));
  ok("name reject xn--", !validName(enc("xn--x")));

  // COMMIT bl==32
  eq("COMMIT good", dk(frame(OP.COMMIT, new Uint8Array(32))), "ACTION");
  eq("COMMIT bad 31", dk(frame(OP.COMMIT, new Uint8Array(31))), "IGNORE");
  // CLAIM bl 33..64
  eq("CLAIM 33 (name1)", dk(frame(OP.CLAIM, concat(new Uint8Array(32), enc("a")))), "ACTION");
  eq("CLAIM 32 (no name)", dk(frame(OP.CLAIM, new Uint8Array(32))), "IGNORE");
  eq("CLAIM 64 (name32)", dk(frame(OP.CLAIM, concat(new Uint8Array(32), enc("a".repeat(32))))), "ACTION");
  eq("CLAIM 65 (name33)", dk(frame(OP.CLAIM, concat(new Uint8Array(32), enc("a".repeat(33))))), "IGNORE");
  eq("CLAIM bad name byte", dk(frame(OP.CLAIM, concat(new Uint8Array(32), enc("A")))), "IGNORE");
  eq("CLAIM leading hyphen → ignore", dk(frame(OP.CLAIM, concat(new Uint8Array(32), enc("-a")))), "IGNORE");
  // RENEW modes 0/5/6..BODY_MAX (§6 pinned ceiling), invalid 1..4
  eq("RENEW all bl0", dk(frame(OP.RENEW, new Uint8Array(0)), 1n), "ACTION");
  eq("RENEW all-safe bl5", dk(frame(OP.RENEW, new Uint8Array(5)), 1n), "ACTION");
  eq("RENEW sel bl6", dk(frame(OP.RENEW, new Uint8Array(6)), 1n), "ACTION");
  eq("RENEW bl1 invalid", dk(frame(OP.RENEW, new Uint8Array(1)), 1n), "IGNORE");
  eq("RENEW bl4 invalid", dk(frame(OP.RENEW, new Uint8Array(4)), 1n), "IGNORE");
  eq("RENEW bl77 valid (past the old 80-byte carrier)", dk(frame(OP.RENEW, new Uint8Array(77)), 1n), "ACTION");
  eq("RENEW bl at BODY_MAX (9992)", dk(frame(OP.RENEW, new Uint8Array(BODY_MAX)), 1n), "ACTION");
  eq("RENEW bl past BODY_MAX", dk(frame(OP.RENEW, new Uint8Array(BODY_MAX + 1)), 1n), "IGNORE");
  eq("TRANSFER sel at BODY_MAX", dk(frame(OP.TRANSFER, new Uint8Array(BODY_MAX))), "ACTION");
  eq("TRANSFER sel past BODY_MAX", dk(frame(OP.TRANSFER, new Uint8Array(BODY_MAX + 1))), "IGNORE");
  eq("RELEASE at BODY_MAX", dk(frame(OP.RELEASE, new Uint8Array(BODY_MAX)), 1n), "ACTION");
  eq("RELEASE past BODY_MAX", dk(frame(OP.RELEASE, new Uint8Array(BODY_MAX + 1)), 1n), "IGNORE");
  // TRANSFER 20, 26..76, invalid 21..25
  eq("TRANSFER all bl20", dk(frame(OP.TRANSFER, new Uint8Array(20))), "ACTION");
  eq("TRANSFER bl21 invalid", dk(frame(OP.TRANSFER, new Uint8Array(21))), "IGNORE");
  eq("TRANSFER bl25 invalid", dk(frame(OP.TRANSFER, new Uint8Array(25))), "IGNORE");
  eq("TRANSFER sel bl26", dk(frame(OP.TRANSFER, new Uint8Array(26))), "ACTION");
  // SELL bl 13..44
  eq("SELL bl13", dk(frame(OP.SELL, concat(u64le(3n), u32le(18000), enc("a")))), "ACTION");
  eq("SELL bl12 (no name)", dk(frame(OP.SELL, concat(u64le(3n), u32le(18000)))), "IGNORE");
  // RESERVE/SETTLE/PAY bl 1..32
  eq("RESERVE bl1", dk(frame(OP.RESERVE, enc("a"))), "ACTION");
  eq("RESERVE bl0", dk(frame(OP.RESERVE, new Uint8Array(0))), "IGNORE");
  eq("RESERVE bl33", dk(frame(OP.RESERVE, enc("a".repeat(33)))), "IGNORE");
  // RELEASE bl 6..76
  eq("RELEASE bl6", dk(frame(OP.RELEASE, new Uint8Array(6))), "ACTION");
  eq("RELEASE bl5 invalid", dk(frame(OP.RELEASE, new Uint8Array(5))), "IGNORE");
  // SELL_TO bl 29..60
  eq("SELL_TO bl29", dk(frame(OP.SELL_TO, concat(u64le(1n), new Uint8Array(20), enc("a")))), "ACTION");
  eq("SELL_TO bl28 (no name)", dk(frame(OP.SELL_TO, concat(u64le(1n), new Uint8Array(20)))), "IGNORE");
  // AS bl==1
  eq("AS bl1", dk(frame(OP.AS, u8(0))), "ACTION");
  eq("AS bl2", dk(frame(OP.AS, new Uint8Array(2))), "IGNORE");
  // TRADE bl≥5, exactly one comma
  eq("TRADE good a,b", dk(frame(OP.TRADE, concat(u8(0), u8(1), enc("a,b")))), "ACTION");
  eq("TRADE no comma", dk(frame(OP.TRADE, concat(u8(0), u8(1), enc("ab")))), "IGNORE");
  eq("TRADE two commas", dk(frame(OP.TRADE, concat(u8(0), u8(1), enc("a,b,c")))), "IGNORE");
  eq("TRADE empty side", dk(frame(OP.TRADE, concat(u8(0), u8(1), enc("a,")))), "IGNORE");
  eq("TRADE idx byte = comma value (44) ok", dk(frame(OP.TRADE, concat(u8(44), u8(1), enc("a,b")))), "ACTION");

  // demux: only ACTION or IGNORE (bare UTF-8 / overlay → IGNORE)
  eq("IGNORE bare utf8 value>0", dk(enc("hello"), 1n), "IGNORE");
  eq("IGNORE bare utf8 value=0", dk(enc("hello"), 0n), "IGNORE");
  eq("IGNORE bad-prefix non-utf8", dk(fromHex("ff414243"), 1n), "IGNORE");
  eq("IGNORE FFSP bad opcode 0x10", dk(frame(0x10, new Uint8Array(0)), 1n), "IGNORE");
  eq("IGNORE overlay 0xD6", dk(frame(0xd6, u8(0)), 0n), "IGNORE");
  eq("IGNORE lone S", dk(enc("S"), 1n), "IGNORE");

  // single minimal push carrier (§1)
  ok("carrier OP_RETURN+push20", singleMinimalPush(concat(u8(0x6a), u8(20), new Uint8Array(20))) !== null);
  ok("carrier multi-push ⊥", singleMinimalPush(concat(u8(0x6a), u8(1), u8(1), u8(1), u8(2))) === null);
  ok("carrier trailing-opcode ⊥", singleMinimalPush(concat(u8(0x6a), u8(1), u8(1), u8(0x51))) === null);
  ok("carrier non-minimal PUSHDATA1 ⊥", singleMinimalPush(concat(u8(0x6a), u8(0x4c), u8(1), u8(1))) === null);
  ok("carrier >80 ⊥", singleMinimalPush(concat(u8(0x6a), u8(81), new Uint8Array(81))) === null);
  ok("carrier bare OP_RETURN ⊥", singleMinimalPush(u8(0x6a)) === null);
}

// ───────────────────────────── commit→claim (§3.2) ─────────────────────────────
function tCommitClaim(): void {
  // naked claim (no commit) → drop
  {
    const f = new Fold(0n);
    const id = B.genId(1), salt = new Uint8Array(32).fill(5);
    f.beginBlock(2n, 1000n, 28n);
    f.applyTx(B.tx([B.input(id)], [B.claim(salt, "naked", 30n)]), 0);
    ok("naked claim drops", !has(f, "naked"));
  }
  // same-block commit+claim too shallow → drop
  {
    const f = new Fold(0n);
    const id = B.genId(1), salt = new Uint8Array(32).fill(5);
    const c = B.commitmentOf(salt, "shallow", id);
    f.beginBlock(2n, 1000n, 28n);
    f.applyTx(B.tx([B.input(id)], [B.commit(c)]), 0);
    f.applyTx(B.tx([B.input(id)], [B.claim(salt, "shallow", 30n)]), 1);
    ok("same-block claim too shallow drops", !has(f, "shallow"));
  }
  // happy path mints; lease exact
  {
    const f = new Fold(0n);
    claimName(f, 1, "alice", 30n, 5n, 1000n);
    eq("happy claim owner", owner(f, "alice"), hex(B.genId(1)));
    eq("happy claim lease", lease(f, "alice"), 1000n + 30n * DAY);
  }
  // commitment-copy author binding: attacker copies victim's commitment, only victim can claim
  {
    const f = new Fold(0n);
    const V = B.genId(1), X = B.genId(2), salt = new Uint8Array(32).fill(7);
    const cV = B.commitmentOf(salt, "prize", V); // victim's commitment
    f.beginBlock(1n, 1000n, 28n);
    f.applyTx(B.tx([B.input(V)], [B.commit(cV)]), 0); // victim commits
    f.applyTx(B.tx([B.input(X)], [B.commit(cV)]), 1); // attacker copies the same 32 bytes
    f.beginBlock(2n, 1100n, 28n);
    f.applyTx(B.tx([B.input(X)], [B.claim(salt, "prize", 30n)]), 0); // attacker claim: SHA256(salt‖prize‖X) ≠ cV
    ok("commitment-copy: attacker claim drops", !has(f, "prize"));
    f.applyTx(B.tx([B.input(V)], [B.claim(salt, "prize", 30n)]), 1); // victim claim matches
    eq("commitment-copy: victim claim mints", owner(f, "prize"), hex(V));
  }
  // priority tuple — equal commit_height, commit tx_index decides (BOTH claim orderings). VEC 42.
  for (const claimBFirst of [true, false]) {
    const f = new Fold(0n);
    const A = B.genId(1), Bb = B.genId(2);
    const sA = new Uint8Array(32).fill(11), sB = new Uint8Array(32).fill(22);
    const cA = B.commitmentOf(sA, "hot", A), cB = B.commitmentOf(sB, "hot", Bb);
    f.beginBlock(1n, 1000n, 28n);
    f.applyTx(B.tx([B.input(A)], [B.commit(cA)]), 0); // A commits at tx_index 0 (LOWER)
    f.applyTx(B.tx([B.input(Bb)], [B.commit(cB)]), 1); // B commits at tx_index 1
    f.beginBlock(2n, 1100n, 28n);
    const claimA = B.tx([B.input(A)], [B.claim(sA, "hot", 30n)]);
    const claimB = B.tx([B.input(Bb)], [B.claim(sB, "hot", 30n)]);
    if (claimBFirst) { f.applyTx(claimB, 0); f.applyTx(claimA, 1); }
    else { f.applyTx(claimA, 0); f.applyTx(claimB, 1); }
    eq(`priority tuple A wins (claimBFirst=${claimBFirst})`, owner(f, "hot"), hex(A));
  }
  // lower commit_height wins across blocks within same claim block
  {
    const f = new Fold(0n);
    const A = B.genId(1), Bb = B.genId(2);
    const sA = new Uint8Array(32).fill(11), sB = new Uint8Array(32).fill(22);
    f.beginBlock(1n, 1000n, 28n);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(sA, "hot2", A))]), 0); // A commit block 1
    f.beginBlock(2n, 1100n, 28n);
    f.applyTx(B.tx([B.input(Bb)], [B.commit(B.commitmentOf(sB, "hot2", Bb))]), 0); // B commit block 2
    f.beginBlock(3n, 1200n, 28n);
    f.applyTx(B.tx([B.input(Bb)], [B.claim(sB, "hot2", 30n)]), 0); // B claims first
    f.applyTx(B.tx([B.input(A)], [B.claim(sA, "hot2", 30n)]), 1); // A displaces (lower commit_height)
    eq("lower commit_height wins", owner(f, "hot2"), hex(A));
  }
  // already-owned claim drops
  {
    const f = new Fold(0n);
    claimName(f, 1, "dup", 30n, 5n, 1000n);
    const X = B.genId(2), salt = new Uint8Array(32).fill(9);
    f.beginBlock(6n, 1100n, 28n);
    f.applyTx(B.tx([B.input(X)], [B.commit(B.commitmentOf(salt, "dup", X))]), 0);
    f.beginBlock(7n, 1200n, 28n);
    f.applyTx(B.tx([B.input(X)], [B.claim(salt, "dup", 30n)]), 0);
    eq("claim already-owned drops (owner unchanged)", owner(f, "dup"), hex(B.genId(1)));
  }
  // H8: a successfully-used commit LINGERS until COMMIT_EXPIRY (no consume-on-use rule in the prose)
  {
    const f = new Fold(0n);
    const id = B.genId(1), salt = new Uint8Array(32).fill(5);
    f.beginBlock(1n, 1000n, 28n);
    f.applyTx(B.tx([B.input(id)], [B.commit(B.commitmentOf(salt, "x", id))]), 0);
    f.beginBlock(2n, 1100n, 28n);
    f.applyTx(B.tx([B.input(id)], [B.claim(salt, "x", 30n)]), 0);
    eq("H8: used commit lingers (not consumed)", f.commits.length, 1);
    f.beginBlock(3n, 1100n + 18001n, 28n); // MTP > commit_time + COMMIT_EXPIRY
    eq("H8: commit self-prunes at COMMIT_EXPIRY", f.commits.length, 0);
  }
  // COMMIT_EXPIRY inclusive boundary
  for (const [mtp2, expectMint] of [[1000n + 18000n, true], [1000n + 18001n, false]] as const) {
    const f = new Fold(0n);
    const id = B.genId(1), salt = new Uint8Array(32).fill(3);
    f.beginBlock(1n, 1000n, 28n);
    f.applyTx(B.tx([B.input(id)], [B.commit(B.commitmentOf(salt, "exp", id))]), 0);
    f.beginBlock(2n, mtp2, 28n);
    f.applyTx(B.tx([B.input(id)], [B.claim(salt, "exp", 30n)]), 0);
    eq(`COMMIT_EXPIRY inclusive @+${mtp2 - 1000n}`, has(f, "exp"), expectMint);
  }
}

// ───────────────────────────── water-fill (§3.5) ─────────────────────────────
function tWaterfill(): void {
  // even split with remainder to first lex
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 100n, 5n, 1000n);
    claimName(f, 1, "b", 100n, 6n, 1100n);
    claimName(f, 1, "c", 100n, 7n, 1200n);
    const baseA = lease(f, "a"), baseB = lease(f, "b"), baseC = lease(f, "c");
    f.beginBlock(8n, 1300n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1))], [B.renewAll(10n)]), 0); // T=10 over 3 names
    eq("waterfill even a (+4)", lease(f, "a") - baseA, 4n * DAY);
    eq("waterfill even b (+3)", lease(f, "b") - baseB, 3n * DAY);
    eq("waterfill even c (+3)", lease(f, "c") - baseC, 3n * DAY);
  }
  // T < count floor: first T names (lex) get +1, rest none
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 100n, 5n, 1000n);
    claimName(f, 1, "b", 100n, 6n, 1100n);
    claimName(f, 1, "c", 100n, 7n, 1200n);
    const baseA = lease(f, "a"), baseB = lease(f, "b"), baseC = lease(f, "c");
    f.beginBlock(8n, 1300n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1))], [B.renewAll(2n)]), 0); // T=2 < 3 names
    eq("T<count: a +1 (first lex)", lease(f, "a") - baseA, 1n * DAY);
    eq("T<count: b +1 (second lex)", lease(f, "b") - baseB, 1n * DAY);
    eq("T<count: c unchanged (none left)", lease(f, "c") - baseC, 0n);
  }
  // MAX_LEASE redistribution: near-cap name redirects its share
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 364n, 5n, 1000n); // headroom 1 day
    claimName(f, 1, "b", 100n, 6n, 1100n); // headroom 265
    const baseA = lease(f, "a"), baseB = lease(f, "b");
    f.beginBlock(8n, 1300n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1))], [B.renewAll(10n)]), 0); // T=10
    eq("redistribute: a capped +1", lease(f, "a") - baseA, 1n * DAY);
    eq("redistribute: b absorbs +9", lease(f, "b") - baseB, 9n * DAY);
  }
  // all-capped forfeit (T>0 but every name at MAX_LEASE)
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 365n, 5n, 1000n); // exactly MAX_LEASE ⇒ headroom 0
    const baseA = lease(f, "a");
    eq("a at MAX_LEASE", baseA - 1000n, MAX_LEASE);
    f.beginBlock(8n, 1000n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1))], [B.renewAll(10n)]), 0);
    eq("all-capped forfeit: no change", lease(f, "a") - baseA, 0n);
  }
  // RENEW T=0 fail-closed
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 100n, 5n, 1000n);
    const baseA = lease(f, "a");
    f.beginBlock(8n, 1100n, 56n); // rate 56 ⇒ T = burn/2; burn=1 ⇒ T=0
    f.applyTx(B.tx([B.input(B.genId(1))], [B.renewAll(1n)]), 0);
    eq("RENEW T=0 fail-closed", lease(f, "a") - baseA, 0n);
  }
  // fresh CLAIM cap at 365
  {
    const f = new Fold(0n);
    claimName(f, 1, "big", 100000n, 5n, 1000n); // huge burn capped to 365 days
    eq("CLAIM cap 365", lease(f, "big") - 1000n, MAX_LEASE);
  }
}

// ───────────────────────────── renew modes & anchor (§3.5) ─────────────────────────────
function tRenewAnchor(): void {
  // selective bitmap LSB-first: owned {a,b,c} lex, flag 0b101 = bits 0,2 ⇒ a,c renew, b not
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 100n, 5n, 1000n);
    claimName(f, 1, "b", 100n, 6n, 1100n);
    claimName(f, 1, "c", 100n, 7n, 1200n);
    const lb = lease(f, "b");
    f.beginBlock(8n, 1300n, 28n);
    // anchor must be ≥ last_mutation. last claim bumped mut to height 7. Use H=7.
    f.applyTx(B.tx([B.input(B.genId(1))], [B.renewSel(7n, u8(0b101), 100n)]), 0);
    ok("selective: a renewed", lease(f, "a") > 1000n + 100n * DAY - DAY);
    eq("selective: b NOT renewed", lease(f, "b"), lb);
  }
  // anchor guard: H predates last mutation → drop (reject-and-resend)
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 100n, 5n, 1000n); // mut bumped to 5
    const la = lease(f, "a");
    f.beginBlock(8n, 1300n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1))], [B.renewSel(4n, u8(1), 100n)]), 0); // anchor 4 < lastMut 5
    eq("anchor stale rejects", lease(f, "a"), la);
  }
  // anchor guard: H > confirm height → drop
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 100n, 5n, 1000n);
    const la = lease(f, "a");
    f.beginBlock(8n, 1300n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1))], [B.renewSel(9n, u8(1), 100n)]), 0); // H=9 > confirm 8
    eq("anchor future rejects", lease(f, "a"), la);
  }
  // OOB bit ignored (not fatal): flag selects bit 5 with only 1 owned name ⇒ no-op, no drop
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 100n, 5n, 1000n);
    const la = lease(f, "a");
    f.beginBlock(8n, 1300n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1))], [B.renewSel(5n, u8(0b100000), 100n)]), 0); // bit5 OOB
    eq("OOB bit ignored", lease(f, "a"), la); // bit0 not set ⇒ a not renewed; bit5 ignored, no crash
  }
}

// ───────────────────────────── transfer / release (§3.5/3.6) ─────────────────────────────
function tTransferRelease(): void {
  // transfer-all moves all unlocked; lease conveys; bump both
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 100n, 5n, 1000n);
    const target = B.genId(2);
    const la = lease(f, "a");
    f.beginBlock(8n, 1300n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1))], [B.transferAll(target)]), 0);
    eq("transfer owner", owner(f, "a"), hex(target));
    eq("transfer lease conveys", lease(f, "a"), la);
    ok("transfer bumps sender mut", f.muts.get(hex(B.genId(1)))!.height === 8n);
    ok("transfer bumps target mut", f.muts.get(hex(target))!.height === 8n);
  }
  // listed name is SKIPPED by transfer (escrow movement-lock), rest proceeds
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 365n, 5n, 1000n);
    claimName(f, 1, "b", 365n, 6n, 1000n);
    f.beginBlock(8n, 1300n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1))], [B.sell(100n, 18000n, "a")]), 0); // list a
    const target = B.genId(2);
    f.applyTx(B.tx([B.input(B.genId(1))], [B.transferAll(target)]), 1);
    eq("listed a skipped (stays seller)", owner(f, "a"), hex(B.genId(1)));
    eq("unlocked b moved", owner(f, "b"), hex(target));
  }
  // release removes name; bump owner
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 100n, 5n, 1000n);
    f.beginBlock(8n, 1300n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1))], [B.release(5n, u8(1))]), 0);
    ok("release removes name", !has(f, "a"));
    ok("release bumps mut", f.muts.get(hex(B.genId(1)))!.height === 8n);
  }
  // all-skipped transfer/release does NOT bump
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 365n, 5n, 1000n);
    f.beginBlock(8n, 1300n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1))], [B.sell(100n, 18000n, "a")]), 0); // list a (no bump)
    const mutBefore = f.muts.get(hex(B.genId(1)))!.height;
    f.applyTx(B.tx([B.input(B.genId(1))], [B.release(5n, u8(1))]), 1); // tries to release listed a → skip
    eq("all-skipped release no bump", f.muts.get(hex(B.genId(1)))!.height, mutBefore);
  }
}

// ───────────────────────────── open market (§3.7) ─────────────────────────────
function tOpenMarket(): void {
  // SELL price floor 3×DUST
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 365n, 5n, 1000n);
    f.beginBlock(8n, 1300n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1))], [B.sell(2n, 18000n, "a")]), 0); // below floor 3
    eq("SELL below floor ignored", st(f, "a"), 0); // still OWNED
    f.applyTx(B.tx([B.input(B.genId(1))], [B.sell(3n, 18000n, "a")]), 1); // at floor
    eq("SELL at floor lists", st(f, "a"), 1);
  }
  // SELL window: 0 defaults to RESERVE_WINDOW; below floor (nonzero) rejected; lease-tail add-form
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 365n, 5n, 1000n);
    f.beginBlock(8n, 1300n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1))], [B.sell(100n, 0n, "a")]), 0); // window 0 → default
    eq("SELL window default offer_expiry", f.names.get(hex(enc("a")))!.offerExpiry, 1300n + RESERVE_WINDOW);
  }
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 365n, 5n, 1000n);
    f.beginBlock(8n, 1300n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1))], [B.sell(100n, 5n, "a")]), 0); // window 5 (<RESERVE_WINDOW) nonzero
    eq("SELL window below floor rejected", st(f, "a"), 0);
  }
  // RESERVE → SETTLE happy; deposit legs; reserve_expiry clamp; bump both
  {
    const f = new Fold(0n);
    claimName(f, 1, "n", 365n, 5n, 1000n); // seller id1 (P2PKH)
    const seller = B.genId(1), buyer = B.genId(2);
    f.beginBlock(8n, 2000n, 28n);
    f.applyTx(B.tx([B.input(seller)], [B.sell(1000n, 18000n, "n")]), 0); // offer_expiry 2000+18000=20000
    // deposit: burn=max(1,1000*50/10000)=5, pay=5, remainder=990
    f.beginBlock(9n, 2100n, 28n);
    f.applyTx(B.tx([B.input(buyer)], [B.reserve("n", 5n)], [B.output(0, seller, 5n)]), 0); // pay_leg out
    eq("RESERVE → RESERVED", st(f, "n"), 3);
    eq("reserve_expiry clamp", f.names.get(hex(enc("n")))!.reserveExpiry,
       (2100n + RESERVE_WINDOW) < 20000n ? 2100n + RESERVE_WINDOW : 20000n);
    eq("burn_leg", f.names.get(hex(enc("n")))!.burnLeg, 5n);
    eq("pay_leg", f.names.get(hex(enc("n")))!.payLeg, 5n);
    f.applyTx(B.tx([B.input(buyer)], [B.settle("n")], [B.output(0, seller, 990n)]), 1); // remainder out
    eq("SETTLE → buyer owns", owner(f, "n"), hex(buyer));
    eq("SETTLE → OWNED", st(f, "n"), 0);
    ok("SETTLE bumps buyer", f.muts.get(hex(buyer))!.height === 9n);
    ok("SETTLE bumps seller", f.muts.get(hex(seller))!.height === 9n);
  }
  // second reserve on RESERVED row drops (option theft prevented); loser's SETTLE fails
  {
    const f = new Fold(0n);
    claimName(f, 1, "n", 365n, 5n, 1000n);
    const seller = B.genId(1), b1 = B.genId(2), b2 = B.genId(6);
    f.beginBlock(8n, 2000n, 28n);
    f.applyTx(B.tx([B.input(seller)], [B.sell(1000n, 18000n, "n")]), 0);
    f.beginBlock(9n, 2100n, 28n);
    f.applyTx(B.tx([B.input(b1)], [B.reserve("n", 5n)], [B.output(0, seller, 5n)]), 0); // b1 wins
    f.applyTx(B.tx([B.input(b2)], [B.reserve("n", 5n)], [B.output(0, seller, 5n)]), 1); // b2 loses (no overwrite)
    eq("second reserve does not overwrite reserver", hex(f.names.get(hex(enc("n")))!.buyer), hex(b1));
    f.applyTx(B.tx([B.input(b2)], [B.settle("n")], [B.output(0, seller, 990n)]), 2); // b2 settle fails
    eq("loser settle drops (still RESERVED to b1)", st(f, "n"), 3);
  }
  // value-collision output matching (vector-41 style): RESERVE+SETTLE one tx, outputs [990,5]
  {
    const f = new Fold(0n);
    claimName(f, 1, "n", 365n, 5n, 1000n);
    const seller = B.genId(1), buyer = B.genId(2);
    f.beginBlock(8n, 2000n, 28n);
    f.applyTx(B.tx([B.input(seller)], [B.sell(1000n, 18000n, "n")]), 0);
    f.beginBlock(9n, 2100n, 28n);
    // outputs: vout0=990 (remainder), vout1=5 (pay_leg) — RESERVE must skip 990 take 5, SETTLE take 990
    const tx: FoldTx = {
      inputs: [B.input(buyer)],
      carriers: [B.reserve("n", 5n, 0), B.settle("n", 1)],
      outputs: [B.output(0, seller, 990n), B.output(0, seller, 5n)],
    };
    f.applyTx(tx, 0);
    eq("value-collision: buyer owns after reserve+settle", owner(f, "n"), hex(buyer));
  }
  // 128-bit deposit at price 2^64-1
  {
    const f = new Fold(0n);
    claimName(f, 1, "n", 365n, 5n, 1000n);
    const seller = B.genId(1);
    const price = (1n << 64n) - 1n;
    const expBurn = (price * 50n) / 10000n; // bigint exact (a 64-bit impl wraps)
    f.beginBlock(8n, 2000n, 28n);
    f.applyTx(B.tx([B.input(seller)], [B.sell(price, 18000n, "n")]), 0);
    f.beginBlock(9n, 2100n, 28n);
    f.applyTx(B.tx([B.input(B.genId(2))], [B.reserve("n", expBurn)], [B.output(0, seller, expBurn)]), 0);
    eq("128-bit burn_leg", f.names.get(hex(enc("n")))!.burnLeg, expBurn);
    eq("128-bit burn_leg value", expBurn, 92233720368547758n);
  }
  // over-funded RESERVE burn still wins (≥ not exact) — vec 46
  {
    const f = new Fold(0n);
    claimName(f, 1, "n", 365n, 5n, 1000n);
    const seller = B.genId(1), buyer = B.genId(2);
    f.beginBlock(8n, 2000n, 28n);
    f.applyTx(B.tx([B.input(seller)], [B.sell(1000n, 18000n, "n")]), 0);
    f.beginBlock(9n, 2100n, 28n);
    f.applyTx(B.tx([B.input(buyer)], [B.reserve("n", 999n)], [B.output(0, seller, 5n)]), 0); // burn over-funded
    eq("over-funded burn wins", st(f, "n"), 3);
  }
}

// ───────────────────────────── directed market (§3.7) ─────────────────────────────
function tDirected(): void {
  // SELL_TO → PAY happy; bump both
  {
    const f = new Fold(0n);
    claimName(f, 1, "n", 365n, 5n, 1000n);
    const seller = B.genId(1), buyer = B.genId(2);
    f.beginBlock(8n, 2000n, 28n);
    f.applyTx(B.tx([B.input(seller)], [B.sellTo(500n, buyer, "n")]), 0);
    eq("SELL_TO → OFFERED", st(f, "n"), 2);
    eq("offer_expiry", f.names.get(hex(enc("n")))!.offerExpiry, 2000n + DIRECT_WINDOW);
    f.beginBlock(9n, 2100n, 28n);
    f.applyTx(B.tx([B.input(buyer)], [B.pay("n")], [B.output(0, seller, 500n)]), 0);
    eq("PAY → buyer owns", owner(f, "n"), hex(buyer));
    eq("PAY → OWNED", st(f, "n"), 0);
    ok("PAY bumps both", f.muts.get(hex(buyer))!.height === 9n && f.muts.get(hex(seller))!.height === 9n);
  }
  // PAY from stranger drops (only named buyer's vin[0] may PAY)
  {
    const f = new Fold(0n);
    claimName(f, 1, "n", 365n, 5n, 1000n);
    const seller = B.genId(1), buyer = B.genId(2), stranger = B.genId(6);
    f.beginBlock(8n, 2000n, 28n);
    f.applyTx(B.tx([B.input(seller)], [B.sellTo(500n, buyer, "n")]), 0);
    f.beginBlock(9n, 2100n, 28n);
    f.applyTx(B.tx([B.input(stranger)], [B.pay("n")], [B.output(0, seller, 500n)]), 0);
    eq("stranger PAY drops (still OFFERED)", st(f, "n"), 2);
  }
  // SELL_TO lease-tail bound: name with short lease rejected
  {
    const f = new Fold(0n);
    claimName(f, 1, "n", 1n, 5n, 1000n); // ~1 day lease only
    const seller = B.genId(1), buyer = B.genId(2);
    f.beginBlock(8n, lease(f, "n") - 100n, 28n); // mtp near lease end, tail < DIRECT_WINDOW+REORG
    f.applyTx(B.tx([B.input(seller)], [B.sellTo(500n, buyer, "n")]), 0);
    eq("SELL_TO short-tail rejected", st(f, "n"), 0);
  }
}

// ───────────────────────────── AS (§3.10) ─────────────────────────────
function tAS(): void {
  // AS re-points actor: CLAIM attributes to vin[1]
  {
    const f = new Fold(0n);
    const A = B.genId(1), Bb = B.genId(2), salt = new Uint8Array(32).fill(8);
    const c = B.commitmentOf(salt, "asn", Bb); // commitment for B
    f.beginBlock(1n, 1000n, 28n);
    f.applyTx(B.tx([B.input(Bb)], [B.commit(c)]), 0);
    f.beginBlock(2n, 1100n, 28n);
    f.applyTx(B.tx([B.input(A), B.input(Bb)], [B.asMarker(1, 0), B.claim(salt, "asn", 30n, 1)]), 0);
    eq("AS → CLAIM attributes to vin[1]", owner(f, "asn"), hex(Bb));
  }
  // without AS, same claim attributes to vin[0]=A and mismatches B's commitment → drop
  {
    const f = new Fold(0n);
    const A = B.genId(1), Bb = B.genId(2), salt = new Uint8Array(32).fill(8);
    f.beginBlock(1n, 1000n, 28n);
    f.applyTx(B.tx([B.input(Bb)], [B.commit(B.commitmentOf(salt, "asn2", Bb))]), 0);
    f.beginBlock(2n, 1100n, 28n);
    f.applyTx(B.tx([B.input(A), B.input(Bb)], [B.claim(salt, "asn2", 30n)]), 0); // actor=A
    ok("no AS → claim by A mismatches B commit → drop", !has(f, "asn2"));
  }
  // AS out of range → segment drops
  {
    const f = new Fold(0n);
    const A = B.genId(1), Bb = B.genId(2), salt = new Uint8Array(32).fill(8);
    f.beginBlock(1n, 1000n, 28n);
    f.applyTx(B.tx([B.input(Bb)], [B.commit(B.commitmentOf(salt, "asn3", Bb))]), 0);
    f.beginBlock(2n, 1100n, 28n);
    f.applyTx(B.tx([B.input(A), B.input(Bb)], [B.asMarker(9, 0), B.claim(salt, "asn3", 30n, 1)]), 0);
    ok("AS OOB → segment drops", !has(f, "asn3"));
  }
  // AS to a non-SIGHASH_ALL input → drops
  {
    const f = new Fold(0n);
    const A = B.genId(1), Bb = B.genId(2), salt = new Uint8Array(32).fill(8);
    f.beginBlock(1n, 1000n, 28n);
    f.applyTx(B.tx([B.input(Bb)], [B.commit(B.commitmentOf(salt, "asn4", Bb))]), 0);
    f.beginBlock(2n, 1100n, 28n);
    f.applyTx(B.tx([B.input(A), B.input(Bb, B.genType(2), false)], [B.asMarker(1, 0), B.claim(salt, "asn4", 30n, 1)]), 0);
    ok("AS to non-SIGHASH_ALL input drops", !has(f, "asn4"));
  }
}

// ───────────────────────────── TRADE (§3.10) ─────────────────────────────
function tTrade(): void {
  // happy swap + lease convey + bump both
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 100n, 5n, 1000n);
    claimName(f, 2, "b", 200n, 6n, 1000n);
    const la = lease(f, "a"), lb = lease(f, "b");
    f.beginBlock(8n, 1300n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1)), B.input(B.genId(2))], [B.trade(0, 1, "a", "b")]), 0);
    eq("trade a→B", owner(f, "a"), hex(B.genId(2)));
    eq("trade b→A", owner(f, "b"), hex(B.genId(1)));
    eq("trade lease a conveys", lease(f, "a"), la);
    eq("trade lease b conveys", lease(f, "b"), lb);
    ok("trade bumps both", f.muts.get(hex(B.genId(1)))!.height === 8n && f.muts.get(hex(B.genId(2)))!.height === 8n);
  }
  // anti-rug: transfer pledged name BEFORE trade in same block → trade drops
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 100n, 5n, 1000n);
    claimName(f, 2, "b", 200n, 6n, 1000n);
    f.beginBlock(8n, 1300n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1))], [B.transferAll(B.genId(6))]), 0); // A moves "a" away
    f.applyTx(B.tx([B.input(B.genId(1)), B.input(B.genId(2))], [B.trade(0, 1, "a", "b")]), 1);
    eq("anti-rug before: a stays at C", owner(f, "a"), hex(B.genId(6)));
    eq("anti-rug before: b stays at B (trade dropped)", owner(f, "b"), hex(B.genId(2)));
  }
  // anti-rug: trade FIRST then transfer → trade stands, later transfer no-ops
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 100n, 5n, 1000n);
    claimName(f, 2, "b", 200n, 6n, 1000n);
    f.beginBlock(8n, 1300n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1)), B.input(B.genId(2))], [B.trade(0, 1, "a", "b")]), 0); // swap
    f.applyTx(B.tx([B.input(B.genId(1))], [B.transferAll(B.genId(6))]), 1); // A no longer owns "a"
    eq("anti-rug after: a stays at B (swap stood)", owner(f, "a"), hex(B.genId(2)));
  }
  // fail-closed edges
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 100n, 5n, 1000n);
    claimName(f, 2, "b", 200n, 6n, 1000n);
    f.beginBlock(8n, 1300n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1)), B.input(B.genId(2))], [B.trade(0, 0, "a", "b")]), 0); // idxA==idxB
    eq("trade idxA==idxB drops", owner(f, "a"), hex(B.genId(1)));
    f.applyTx(B.tx([B.input(B.genId(1)), B.input(B.genId(2))], [B.trade(0, 9, "a", "b")]), 1); // idx OOB
    eq("trade idx OOB drops", owner(f, "a"), hex(B.genId(1)));
    f.applyTx(B.tx([B.input(B.genId(1)), B.input(B.genId(2))], [B.trade(0, 1, "a", "a")]), 2); // nameA==nameB
    eq("trade nameA==nameB drops", owner(f, "a"), hex(B.genId(1)));
  }
  // locked name cannot trade
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 365n, 5n, 1000n);
    claimName(f, 2, "b", 365n, 6n, 1000n);
    f.beginBlock(8n, 2000n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1))], [B.sell(100n, 18000n, "a")]), 0); // lock a
    f.applyTx(B.tx([B.input(B.genId(1)), B.input(B.genId(2))], [B.trade(0, 1, "a", "b")]), 1);
    eq("trade locked name drops", owner(f, "b"), hex(B.genId(2)));
  }
}

// ───────────────────────────── no per-tx count cap (§0) ─────────────────────────────
function tTxBounds(): void {
  // 17 COMMIT carriers (past the historical 16) all fold.
  const f = new Fold(0n);
  f.beginBlock(10n, 1000n, 28n);
  const cs = [];
  for (let i = 0; i < 17; i++) {
    const c = new Uint8Array(32); c[0] = i & 0xff;
    cs.push(B.commit(c, i));
  }
  f.applyTx(B.tx([B.input(B.genId(0xaa))], cs), 0);
  eq("no per-tx count cap: 17 COMMITs all record", f.commits.length, 17);
}

// ───────────────────────────── pre-block transitions (§5) ─────────────────────────────
function tPreBlock(): void {
  // lease lapse exclusive boundary: owned iff MTP < lease_expiry
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 30n, 5n, 1000n);
    const E = lease(f, "a"); // 1000 + 30*86400
    f.beginBlock(6n, E - 1n, 28n);
    ok("MTP=E-1 still owned", has(f, "a"));
    f.beginBlock(7n, E, 28n); // MTP == lease_expiry → lapse
    ok("MTP=E lapses (exclusive)", !has(f, "a"));
    ok("lapse stamps mut to H", f.muts.get(hex(B.genId(1)))!.height === 7n);
  }
  // same-block lapse-and-reclaim: lapse before reclaiming tx
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 30n, 5n, 1000n);
    const E = lease(f, "a");
    const B2 = B.genId(2), salt = new Uint8Array(32).fill(4);
    f.beginBlock(6n, E - 100n, 28n); // commit by B2 just before lapse block
    f.applyTx(B.tx([B.input(B2)], [B.commit(B.commitmentOf(salt, "a", B2))]), 0);
    f.beginBlock(7n, E, 28n); // pre-block lapses "a"; B2 reclaims in this block
    f.applyTx(B.tx([B.input(B2)], [B.claim(salt, "a", 30n)]), 0);
    eq("same-block lapse-and-reclaim → B2 owns", owner(f, "a"), hex(B2));
  }
  // offer close at offer_expiry (exclusive)
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 365n, 5n, 1000n);
    f.beginBlock(8n, 2000n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1))], [B.sell(100n, 18000n, "a")]), 0);
    const oe = f.names.get(hex(enc("a")))!.offerExpiry;
    f.beginBlock(9n, oe, 28n); // MTP == offer_expiry → close
    eq("offer close → OWNED", st(f, "a"), 0);
  }
  // reserve revert then full cascade lapse in one MTP advance
  {
    const f = new Fold(0n);
    claimName(f, 1, "a", 365n, 5n, 1000n);
    const seller = B.genId(1), buyer = B.genId(2);
    f.beginBlock(8n, 2000n, 28n);
    f.applyTx(B.tx([B.input(seller)], [B.sell(1000n, 18000n, "a")]), 0);
    f.beginBlock(9n, 2100n, 28n);
    f.applyTx(B.tx([B.input(buyer)], [B.reserve("a", 5n)], [B.output(0, seller, 5n)]), 0);
    // jump MTP past lease_expiry: cascades RESERVED→LISTED→OWNED→lapse, name removed
    const E = lease(f, "a");
    f.beginBlock(10n, E, 28n);
    ok("full cascade lapse removes name", !has(f, "a"));
    ok("cascade lapse stamps seller mut", f.muts.get(hex(seller))!.height === 10n);
  }
}

// ───────────────────────────── gating (§3.0) ─────────────────────────────
// All ops gate at one ACTIVATION_HEIGHT (no genesis-vs-gated split after VOTE removal).
function tGating(): void {
  const f = new Fold(100n); // activation height 100
  const id = B.genId(1), salt = new Uint8Array(32).fill(2);
  f.beginBlock(50n, 1000n, 28n); // below activation
  f.applyTx(B.tx([B.input(id)], [B.commit(B.commitmentOf(salt, "early", id))]), 0);
  eq("gated COMMIT below activation dropped", f.commits.length, 0);
  f.beginBlock(100n, 1100n, 28n); // at activation
  f.applyTx(B.tx([B.input(id)], [B.commit(B.commitmentOf(salt, "late", id))]), 0);
  eq("COMMIT at activation records", f.commits.length, 1);
}

// ───────────────────────────── fee oracle + MTP ─────────────────────────────
function tOracleMTP(): void {
  // under-claim clamp: coinbase < subsidy → 0 fees → non-participant; all-zero window → DUST_FLOOR
  const subsidy = 10_000n * 100_000_000n;
  const win0 = Array.from({ length: 1500 }, () => ({ coinbaseTotal: subsidy - 1n, blockBytes: 1000n }));
  eq("oracle all-under-claim (|P|=0) → DUST_FLOOR", oracleRate(win0), 1n);
  // RATE_CAP clamp with a trusted (≥MIN_FEE_SAMPLE) participant window
  const win2 = Array.from({ length: 1000 }, () => ({ coinbaseTotal: subsidy + 10n ** 12n, blockBytes: 1n }));
  eq("oracle RATE_CAP (|P|=1000)", oracleRate(win2), 100_000_000n);
  // inclusive MIN_FEE_SAMPLE boundary: |P| = 1000 exactly (even), 499 zero-fee + 1 under-claim
  // non-participants, fpb 100..1099 → LOWER median index (1000−1)/2 = 499 → 599 × 200 = 119800
  const win3 = Array.from({ length: 1500 }, (_, i) => ({
    coinbaseTotal:
      i < 499 ? subsidy : i === 499 ? subsidy - 50n : subsidy + (100n + BigInt(i - 500)) * 1000n,
    blockBytes: 1000n,
  }));
  eq("oracle inclusive-1000 even lower-median", oracleRate(win3), 119_800n);
  // one participant short (|P| = 999) → degrade to DUST_FLOOR exactly
  const win4 = Array.from({ length: 1500 }, (_, i) => ({
    coinbaseTotal: i < 501 ? subsidy : subsidy + (100n + BigInt(i - 501)) * 1000n,
    blockBytes: 1000n,
  }));
  eq("oracle 999-participant degrade", oracleRate(win4), 1n);
  // odd |P| = 1101 through the participant filter: fpb 100..1200 → index (1101−1)/2 = 550
  // → 650 × 200 = 130000 (the historical middle rule, unchanged by the rewrite)
  const win5 = Array.from({ length: 2000 }, (_, i) => ({
    coinbaseTotal: i < 899 ? subsidy : subsidy + (100n + BigInt(i - 899)) * 1000n,
    blockBytes: 1000n,
  }));
  eq("oracle odd-|P| median", oracleRate(win5), 130_000n);
  // MTP median, middle element index k//2
  const ts = [100n, 50n, 75n, 200n, 25n].map((x) => x); // block timestamps 0..4
  // H=5: predecessors = all 5; sorted [25,50,75,100,200], index 5//2=2 → 75
  eq("MTP median (k=5)", computeMTP([100n, 50n, 75n, 200n, 25n], 5), 75n);
  // H=4: predecessors blocks 0..3 = [100,50,75,200], sorted [50,75,100,200], index 4//2=2 → 100
  eq("MTP median (k=4 upper-middle)", computeMTP([100n, 50n, 75n, 200n, 25n], 4), 100n);
  eq("MTP H=0 → 0", computeMTP([100n], 0), 0n);
}

// ───────────────────────────── attribution byte-logic (§4) ─────────────────────────────
function tAttribution(): void {
  // Build a minimal P2PKH spend and check classification + identity. Use injected curve stubs.
  // pubkey: 33-byte compressed; sig: a strict-DER low-S sig with 0x01 hashtype.
  const pubkey = concat(u8(0x02), new Uint8Array(32).fill(0x11));
  // craft a strict-DER sig: 30 len 02 lenR R 02 lenS S 01 ; small R,S (low-S guaranteed)
  const R = u8(0x05), S = u8(0x06);
  const der = concat(u8(0x30), u8(4 + R.length + S.length), u8(0x02), u8(R.length), R, u8(0x02), u8(S.length), S);
  const sig = concat(der, u8(0x01));
  const scriptSig = concat(u8(sig.length), sig, u8(pubkey.length), pubkey);
  // a minimal raw tx: version, 1 vin (prevout 36, scriptlen, scriptSig, seq), 1 vout (0 value, empty spk), locktime
  const prevout = new Uint8Array(36);
  const vin = concat(prevout, u8(scriptSig.length), scriptSig, u32le(0xffffffff));
  const vout = concat(u64le(0n), u8(0));
  const raw = concat(u32le(1), u8(1), vin, u8(1), vout, u32le(0));
  const tx = parseTx(raw);
  ok("attrib: tx parses", tx !== null);
  if (tx) {
    const r = attribute(tx, 0);
    eq("attrib: P2PKH identity = hash160(pubkey)", hex(r.identity), hex(hash160(pubkey)));
    ok("attrib: status ≥1 (classified)", r.status >= 1);
    ok("attrib: sighash nonzero", hex(r.sighash) !== hex(new Uint8Array(32)));
  }
  // malformed scriptSig (single push, not P2PKH) → status 0 drop
  {
    const ss = concat(u8(1), u8(0xab));
    const vin2 = concat(prevout, u8(ss.length), ss, u32le(0xffffffff));
    const raw2 = concat(u32le(1), u8(1), vin2, u8(1), vout, u32le(0));
    const tx2 = parseTx(raw2)!;
    eq("attrib: nonstandard → status 0", attribute(tx2, 0).status, 0);
  }
  // sig with wrong hashtype (0x02 NONE) → classify drop
  {
    const sig2 = concat(der, u8(0x02));
    const ss = concat(u8(sig2.length), sig2, u8(pubkey.length), pubkey);
    const vin3 = concat(prevout, u8(ss.length), ss, u32le(0xffffffff));
    const raw3 = concat(u32le(1), u8(1), vin3, u8(1), vout, u32le(0));
    eq("attrib: wrong hashtype → status 0", attribute(parseTx(raw3)!, 0).status, 0);
  }
}

// ───────────────────────────── §4 Strategy B real secp256k1 KAT ─────────────────────────────
function tSecp256k1(): void {
  // pinned constants
  eq("secp: P", "0x" + SECP_PP.toString(16),
    "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
  eq("secp: N", "0x" + SECP_NN.toString(16),
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
  eq("secp: N_HALF = N>>1", SECP_NH, SECP_NN >> 1n);
  // G satisfies the curve equation y^2 = x^3 + 7 (mod p)
  const fmod = (a: bigint) => { const r = a % SECP_PP; return r < 0n ? r + SECP_PP : r; };
  ok("secp: G on curve (y^2=x^3+7)", fmod(SECP_GY * SECP_GY) === fmod(SECP_GX * SECP_GX * SECP_GX + 7n));
  // decompress G (even Y) round-trips
  { const gc = new Uint8Array(33); gc[0] = 0x02; gc.set(be32(SECP_GX), 1);
    ok("secp: decompress G is on curve", onCurve(gc)); }
  // 2G known-answer (priv=2 ⇒ pub = compressed 2G)
  { const p2 = new Uint8Array(32); p2[31] = 2;
    eq("secp: priv2 = 2G compressed", hex(pubkey(p2)!),
      "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"); }
  // priv1 = G compressed
  { const p1 = new Uint8Array(32); p1[31] = 1;
    eq("secp: priv1 = G compressed", hex(pubkey(p1)!),
      "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"); }
  // n·G == ∞ ⇒ pubkey rejects priv == n is out of range; but verify the order via a known reject:
  //   sign/verify round-trip + tamper rejection over a deterministic key.
  { const priv = new Uint8Array(32); priv[31] = 0x2a;
    const pub = pubkey(priv)!;
    const mh = sha256(enc("secp KAT message"));
    const sig = ecdsaSign(priv, mh)!;
    ok("secp: sign/verify round-trip", ecdsaVerify(mh, sig.r, sig.s, pub));
    const mh2 = Uint8Array.from(mh); mh2[0] ^= 0x01;
    ok("secp: tampered hash rejected", !ecdsaVerify(mh2, sig.r, sig.s, pub));
    // low-S normalized: s ≤ n/2
    ok("secp: low-S normalized", (function () { let v = 0n; for (const b of sig.s) v = (v << 8n) | BigInt(b); return v <= SECP_NH; })()); }
  // bundled internal KAT (constants + 2G + n·G=∞ + decompress + 4 sign/verify rounds)
  eq("secp: bundled selftest", secpSelftest(), 0);
}

// ───────────────────────────── determinism: same input → same digest ─────────────────────────────
function tDeterminism(): void {
  function build(): string {
    const f = new Fold(0n);
    claimName(f, 1, "alpha", 100n, 5n, 1000n);
    claimName(f, 2, "beta", 50n, 6n, 1000n);
    f.beginBlock(8n, 1300n, 28n);
    f.applyTx(B.tx([B.input(B.genId(1)), B.input(B.genId(2))], [B.trade(0, 1, "alpha", "beta")]), 0);
    f.applyTx(B.tx([B.input(B.genId(2))], [B.sell(1000n, 18000n, "alpha")]), 1);
    return hex(f.digest());
  }
  eq("digest deterministic across two runs", build(), build());
}

// ───────────────────────────── §13.2 ECMH state binding ─────────────────────────────
function tEcmh(): void {
  // 1. Empty-state ECMH is stable + matches the cross-impl anchor.
  const empty = new Fold(0n).stateEcmh();
  ok("ECMH empty-state stable", hex(new Fold(0n).stateEcmh()) === hex(empty));
  eq("ECMH empty-state anchor", hex(empty),
    "3ecfc3d7fa5be56fc513dde926bdf105c92accbf07088e702f85856fa69d10e0");

  // 2. ECMH induces the SAME equality relation as the canonical digest. Build the same logical
  //    rows in two different insertion orders (commits in the same order so the tx_index-bearing
  //    commit rows match; CLAIM reversed ⇒ the names map is permuted with identical content) and a
  //    third, smaller state. Mirrors C test_ecmh.
  const A = B.genId(0xaa);
  const salt = (b: number) => new Uint8Array(32).fill(b);
  const ca = B.commitmentOf(salt(0xa1), "a", A), cb = B.commitmentOf(salt(0xa2), "b", A);

  const s1 = new Fold(0n);
  s1.beginBlock(10n, 1000n, 28n);
  s1.applyTx(B.tx([B.input(A)], [B.commit(ca)]), 0);
  s1.applyTx(B.tx([B.input(A)], [B.commit(cb)]), 1);
  s1.beginBlock(11n, 1500n, 28n);
  s1.applyTx(B.tx([B.input(A)], [B.claim(salt(0xa1), "a", 30n)]), 0);
  s1.applyTx(B.tx([B.input(A)], [B.claim(salt(0xa2), "b", 30n)]), 1);

  const s2 = new Fold(0n);
  s2.beginBlock(10n, 1000n, 28n);
  s2.applyTx(B.tx([B.input(A)], [B.commit(ca)]), 0);
  s2.applyTx(B.tx([B.input(A)], [B.commit(cb)]), 1);
  s2.beginBlock(11n, 1500n, 28n);
  s2.applyTx(B.tx([B.input(A)], [B.claim(salt(0xa2), "b", 30n)]), 1); // reversed claim order
  s2.applyTx(B.tx([B.input(A)], [B.claim(salt(0xa1), "a", 30n)]), 0);

  const s3 = new Fold(0n);
  s3.beginBlock(10n, 1000n, 28n);
  s3.applyTx(B.tx([B.input(A)], [B.commit(ca)]), 0);
  s3.beginBlock(11n, 1500n, 28n);
  s3.applyTx(B.tx([B.input(A)], [B.claim(salt(0xa1), "a", 30n)]), 0);

  const d1 = hex(s1.digest()), d2 = hex(s2.digest()), d3 = hex(s3.digest());
  const e1 = hex(s1.stateEcmh()), e2 = hex(s2.stateEcmh()), e3 = hex(s3.stateEcmh());
  ok("ECMH test setup: reordered builds give equal digest", d1 === d2);
  ok("ECMH equality tracks digest (equal states)", (d1 === d2) === (e1 === e2));
  ok("ECMH equality tracks digest (differing states)", (d1 === d3) === (e1 === e3));
}

export function runSelftest(): { pass: number; fail: number } {
  tPrimitives();
  tDecoder();
  tDottedNames();
  tCommitClaim();
  tWaterfill();
  tRenewAnchor();
  tTransferRelease();
  tOpenMarket();
  tDirected();
  tAS();
  tTrade();
  tTxBounds();
  tPreBlock();
  tGating();
  tOracleMTP();
  tAttribution();
  tSecp256k1();
  tEcmh();
  tDeterminism();
  if (fails.length) {
    console.log("\n── FAILURES ──");
    for (const m of fails) console.log("  ✗ " + m);
  }
  console.log(`empty_state_digest=${hex(new Fold(0n).digest())}`);
  console.log(`empty_state_ecmh=${hex(new Fold(0n).stateEcmh())}`);
  console.log(`selftest: ${pass} passed, ${fail} failed`);
  return { pass, fail };
}
