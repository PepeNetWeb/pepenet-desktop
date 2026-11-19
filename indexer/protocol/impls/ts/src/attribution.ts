// §4 Stateless Identity & Attribution (SPEC-conformance.md §13). raw tx → per-input
// {status, sighash, identity}. Everything that forks between languages is real byte logic; only the
// two curve ops (on_curve / verify) are INJECTED stubs, exactly as §13 prescribes (NOT real
// secp256k1). This is a separate surface from the §5 fold (which is fed already-resolved identity).
//
// status (§13): 0 classify-drop · 1 on-curve-drop · 2 verify-drop · 3 found.
// The sighash+identity are emitted for status ≥ 1 (formed right after classification, before the
// on-curve gate); status 0 emits ZERO32 / ZERO20.
import type { Bytes } from "./bytes.ts";
import { concat, u8, leBytes, varint, rdLE, rdU32 } from "./bytes.ts";
import { sha256, sha256d } from "./sha256.ts";
import { hash160 } from "./ripemd160.ts";
import { SECP_N_HALF, SECP_P } from "./constants.ts";
import { onCurve as realOnCurve, ecdsaVerify as realEcdsaVerify } from "./secp256k1.ts";

export const ZERO32 = new Uint8Array(32);
export const ZERO20 = new Uint8Array(20);

// ─── Curve oracle selector (mirrors C `g_real_curve`) ───────────────────────────────────────────
// false = injected pseudo-functions (Tier-1 self-regression; the `attrib`/`attrib-scenario`/
// `selftest` frozen byte-logic). true = REAL secp256k1 (the §4 Strategy B end-to-end vectors in
// `attrib-curve`). attrib/attrib-scenario/selftest never flip this, so they stay byte-identical.
let gRealCurve = false;
export function setRealCurve(on: boolean): void { gRealCurve = on; }

// ─── Injected curve oracle (§13) — the ONLY abstracted part. Pinned pseudo-functions of bytes. ──
function injOnCurve(pubkey: Bytes): boolean {
  return sha256(concat(u8(0x4f), pubkey))[0] !== 0x00;
}
function injEcdsaVerify(hash32: Bytes, r32: Bytes, s32: Bytes, pubkey: Bytes): boolean {
  return sha256(concat(u8(0x56), hash32, r32, s32, pubkey))[0] >= 0x20;
}
export function onCurve(pubkey: Bytes): boolean {
  return gRealCurve ? realOnCurve(pubkey) : injOnCurve(pubkey);
}
export function ecdsaVerify(hash32: Bytes, r32: Bytes, s32: Bytes, pubkey: Bytes): boolean {
  return gRealCurve ? realEcdsaVerify(hash32, r32, s32, pubkey) : injEcdsaVerify(hash32, r32, s32, pubkey);
}

// ─── Raw legacy tx (de)serialization ─────────────────────────────────────────────────────────
export type TxIn = { prevout: Bytes; scriptSig: Bytes; sequence: number };
export type TxOut = { value: bigint; spk: Bytes };
export type RawTx = { version: number; vins: TxIn[]; vouts: TxOut[]; locktime: number };

function readVarint(b: Bytes, o: number): [bigint, number] {
  const x = b[o];
  if (x < 0xfd) return [BigInt(x), o + 1];
  if (x === 0xfd) return [rdLE(b, o + 1, 2), o + 3];
  if (x === 0xfe) return [rdLE(b, o + 1, 4), o + 5];
  return [rdLE(b, o + 1, 8), o + 9];
}

export function parseTx(b: Bytes): RawTx | null {
  try {
    let o = 0;
    const version = rdU32(b, o); o += 4;
    let nin: bigint; [nin, o] = readVarint(b, o);
    const vins: TxIn[] = [];
    for (let i = 0n; i < nin; i++) {
      const prevout = b.subarray(o, o + 36); o += 36;
      let sl: bigint; [sl, o] = readVarint(b, o);
      const scriptSig = b.subarray(o, o + Number(sl)); o += Number(sl);
      const sequence = rdU32(b, o); o += 4;
      vins.push({ prevout, scriptSig, sequence });
    }
    let nout: bigint; [nout, o] = readVarint(b, o);
    const vouts: TxOut[] = [];
    for (let i = 0n; i < nout; i++) {
      const value = rdLE(b, o, 8); o += 8;
      let sl: bigint; [sl, o] = readVarint(b, o);
      const spk = b.subarray(o, o + Number(sl)); o += Number(sl);
      vouts.push({ value, spk });
    }
    const locktime = rdU32(b, o); o += 4;
    if (o !== b.length) return null; // trailing bytes ⇒ malformed
    return { version, vins, vouts, locktime };
  } catch {
    return null;
  }
}

function serializeForSighash(tx: RawTx, k: number, scriptCode: Bytes): Bytes {
  const parts: Bytes[] = [];
  parts.push(leBytes(BigInt(tx.version), 4));
  parts.push(varint(BigInt(tx.vins.length)));
  for (let i = 0; i < tx.vins.length; i++) {
    parts.push(tx.vins[i].prevout);
    if (i === k) {
      parts.push(varint(BigInt(scriptCode.length)));
      parts.push(scriptCode);
    } else {
      parts.push(varint(0n)); // empty script for non-signing inputs (legacy SIGHASH_ALL)
    }
    parts.push(leBytes(BigInt(tx.vins[i].sequence), 4));
  }
  parts.push(varint(BigInt(tx.vouts.length)));
  for (const o of tx.vouts) {
    parts.push(leBytes(o.value, 8));
    parts.push(varint(BigInt(o.spk.length)));
    parts.push(o.spk);
  }
  parts.push(leBytes(BigInt(tx.locktime), 4));
  parts.push(leBytes(1n, 4)); // hashtype SIGHASH_ALL appended as 4-byte LE int32 (§4 step 4)
  return concat(...parts);
}

// ─── Minimal-push script iterator ────────────────────────────────────────────────────────────
type Op = { op: number; data: Bytes | null; minimal: boolean };
function getOps(script: Bytes): Op[] | null {
  const ops: Op[] = [];
  let i = 0;
  while (i < script.length) {
    const op = script[i++];
    if (op > 0x4e) {
      ops.push({ op, data: null, minimal: true }); // a non-push opcode (OP_x)
      continue;
    }
    let len: number;
    let minimal = true;
    if (op < 0x4c) {
      len = op;
    } else if (op === 0x4c) {
      if (i + 1 > script.length) return null;
      len = script[i++];
      if (len < 0x4c) minimal = false; // <76 must use direct push
    } else if (op === 0x4d) {
      if (i + 2 > script.length) return null;
      len = script[i] | (script[i + 1] << 8); i += 2;
      if (len <= 0xff) minimal = false;
    } else {
      // 0x4e OP_PUSHDATA4
      if (i + 4 > script.length) return null;
      len = script[i] | (script[i + 1] << 8) | (script[i + 2] << 16) | script[i + 3] * 0x1000000;
      i += 4;
      if (len <= 0xffff) minimal = false;
    }
    if (i + len > script.length) return null;
    const data = script.subarray(i, i + len); i += len;
    // direct-push minimality for single-byte values is enforced where it matters (sig/pubkey shape)
    ops.push({ op, data, minimal });
  }
  return ops;
}

// minimal push encoding of arbitrary bytes (for FindAndDelete pattern construction)
export function minimalPush(data: Bytes): Bytes {
  const n = data.length;
  if (n < 0x4c) return concat(u8(n), data);
  if (n <= 0xff) return concat(u8(0x4c), u8(n), data);
  if (n <= 0xffff) return concat(u8(0x4d), leBytes(BigInt(n), 2), data);
  return concat(u8(0x4e), leBytes(BigInt(n), 4), data);
}

// Bitcoin Core CScript::FindAndDelete — remove every boundary-aligned occurrence of `pattern`
// (itself a serialized script element) from `script`, iterating opcode-by-opcode (§4 step 4 / §13).
export function findAndDelete(script: Bytes, pattern: Bytes): Bytes {
  if (pattern.length === 0) return script;
  const out: number[] = [];
  let i = 0;
  while (i < script.length) {
    // does `pattern` occur exactly at i, aligned to this opcode boundary?
    if (
      i + pattern.length <= script.length &&
      eqRange(script, i, pattern)
    ) {
      i += pattern.length; // delete it (skip)
      continue;
    }
    // otherwise copy this whole opcode (advance by its full length so removal stays boundary-aligned)
    const adv = opLen(script, i);
    if (adv < 0) {
      // unparseable tail — copy the rest verbatim (Core stops scanning on a bad GetOp)
      for (let j = i; j < script.length; j++) out.push(script[j]);
      break;
    }
    for (let j = i; j < i + adv; j++) out.push(script[j]);
    i += adv;
  }
  return Uint8Array.from(out);
}
function eqRange(s: Bytes, off: number, pat: Bytes): boolean {
  for (let j = 0; j < pat.length; j++) if (s[off + j] !== pat[j]) return false;
  return true;
}
function opLen(script: Bytes, i: number): number {
  const op = script[i];
  if (op > 0x4e) return 1;
  if (op < 0x4c) return 1 + op;
  if (op === 0x4c) return i + 1 < script.length ? 2 + script[i + 1] : -1;
  if (op === 0x4d) return i + 2 < script.length ? 3 + (script[i + 1] | (script[i + 2] << 8)) : -1;
  return i + 4 < script.length
    ? 5 + (script[i + 1] | (script[i + 2] << 8) | (script[i + 3] << 16) | script[i + 4] * 0x1000000)
    : -1;
}

// ─── strict-DER + low-S signature parse (§4 Rule 4, §13) ─────────────────────────────────────
// input = signature push (DER + 1-byte sighash type). Returns {r32,s32} or null.
export function parseSig(sig: Bytes): { r: Bytes; s: Bytes } | null {
  const n = sig.length;
  if (n < 9 || n > 73) return null;
  if (sig[0] !== 0x30) return null;
  if (sig[1] !== n - 3) return null; // DER body length == total − (0x30,len,hashtype)
  if (sig[2] !== 0x02) return null;
  const lenR = sig[3];
  if (lenR === 0) return null;
  if (5 + lenR >= n) return null;
  if (sig[4] & 0x80) return null; // R negative
  if (sig[4] === 0x00 && !(sig[5] & 0x80)) return null; // R non-minimal leading zero
  const rOff = 4;
  const sTypeOff = 4 + lenR;
  if (sig[sTypeOff] !== 0x02) return null;
  const lenS = sig[sTypeOff + 1];
  if (lenS === 0) return null;
  if (sTypeOff + 2 + lenS !== n - 1) return null; // S must end exactly before the 1-byte hashtype
  const sOff = sTypeOff + 2;
  if (sig[sOff] & 0x80) return null; // S negative
  if (sig[sOff] === 0x00 && !(sig[sOff + 1] & 0x80)) return null; // S non-minimal
  // hashtype byte MUST be exactly 0x01 SIGHASH_ALL (Rule 3 / §13)
  if (sig[n - 1] !== 0x01) return null;
  // low-S: S ≤ N/2
  const sBig = beToBig(sig.subarray(sOff, sOff + lenS));
  if (sBig > SECP_N_HALF) return null;
  const r32 = beToFixed32(sig.subarray(rOff, rOff + lenR));
  const s32 = beToFixed32(sig.subarray(sOff, sOff + lenS));
  if (r32 === null || s32 === null) return null; // R or S ≥ 2^256 → invalid
  return { r: r32, s: s32 };
}
function beToBig(b: Bytes): bigint {
  let v = 0n;
  for (let i = 0; i < b.length; i++) v = (v << 8n) | BigInt(b[i]);
  return v;
}
function beToFixed32(b: Bytes): Bytes | null {
  // strip minimal DER sign-pad zeros, then left-pad to 32 bytes BE. An integer that
  // does NOT fit in 32 bytes is rejected (null), NOT truncated to the low 32 bytes —
  // truncation would forge a different scalar and diverges from C/Go (which reject).
  let start = 0;
  while (start < b.length - 1 && b[start] === 0x00) start++;
  const trimmed = b.subarray(start);
  if (trimmed.length > 32) return null;
  const out = new Uint8Array(32);
  out.set(trimmed, 32 - trimmed.length);
  return out;
}

// ─── pubkey canonical encoding (§4 Rule 4) ───────────────────────────────────────────────────
// Returns true iff a canonical 33B compressed (0x02/0x03) or 65B uncompressed (0x04) key with
// coordinates < p. on_curve is the INJECTED part, checked separately as the status-1 stage.
export function pubkeyCanonical(pk: Bytes): boolean {
  if (pk.length === 33) {
    if (pk[0] !== 0x02 && pk[0] !== 0x03) return false;
    return beToBig(pk.subarray(1, 33)) < SECP_P;
  }
  if (pk.length === 65) {
    if (pk[0] !== 0x04) return false; // reject hybrid 0x06/0x07
    return beToBig(pk.subarray(1, 33)) < SECP_P && beToBig(pk.subarray(33, 65)) < SECP_P;
  }
  return false;
}

// ─── classification ──────────────────────────────────────────────────────────────────────────
type P2pkh = { kind: "p2pkh"; sig: Bytes; r: Bytes; s: Bytes; pubkey: Bytes };
type P2sh = { kind: "p2sh"; sigs: { r: Bytes; s: Bytes }[]; redeem: Bytes; keys: Bytes[]; m: number };
type Classified = P2pkh | P2sh | null;

function classify(scriptSig: Bytes): Classified {
  const ops = getOps(scriptSig);
  if (!ops) return null;
  // P2PKH: exactly two pushes [sig][pubkey]
  if (ops.length === 2 && ops[0].data && ops[1].data && ops[0].minimal && ops[1].minimal &&
      ops[0].op < 0x4c && ops[1].op < 0x4c) {
    const parsed = parseSig(ops[0].data);
    const pk = ops[1].data;
    if (parsed && pubkeyCanonical(pk)) {
      return { kind: "p2pkh", sig: ops[0].data, r: parsed.r, s: parsed.s, pubkey: pk };
    }
    return null;
  }
  // P2SH multisig: OP_0 [sig]×m [redeemScript]. OP_0 (0x00) is a zero-length push,
  // so its data is an empty array (matches C `op[0]==0x00 && dl[0]==0`, not data===null).
  if (ops.length >= 3 && ops[0].op === 0x00 && ops[0].data !== null && ops[0].data.length === 0) {
    const redeemOp = ops[ops.length - 1];
    if (!redeemOp.data || !redeemOp.minimal) return null;
    const tmpl = parseMultisigRedeem(redeemOp.data);
    if (!tmpl) return null;
    const sigOps = ops.slice(1, ops.length - 1);
    if (sigOps.length !== tmpl.m) return null; // exactly m sig pushes (the threshold)
    const sigs: { r: Bytes; s: Bytes }[] = [];
    for (const so of sigOps) {
      if (!so.data || !so.minimal) return null;
      const p = parseSig(so.data);
      if (!p) return null; // strict-DER + low-S + 0x01 on each sig
      sigs.push(p);
    }
    return { kind: "p2sh", sigs, redeem: redeemOp.data, keys: tmpl.keys, m: tmpl.m };
  }
  return null;
}

// redeemScript = OP_m <33B key>×n OP_n OP_CHECKMULTISIG, 1≤m≤n≤15, compressed keys only.
function parseMultisigRedeem(rs: Bytes): { m: number; n: number; keys: Bytes[] } | null {
  const ops = getOps(rs);
  if (!ops || ops.length < 4) return null;
  if (ops[ops.length - 1].op !== 0xae) return null; // OP_CHECKMULTISIG
  const mOp = ops[0].op;
  const nOp = ops[ops.length - 2].op;
  if (mOp < 0x51 || mOp > 0x60) return null; // OP_1..OP_16 minimal
  if (nOp < 0x51 || nOp > 0x60) return null;
  const m = mOp - 0x50;
  const n = nOp - 0x50;
  if (m < 1 || n < 1 || m > n || n > 15) return null;
  const keyOps = ops.slice(1, ops.length - 2);
  if (keyOps.length !== n) return null;
  const keys: Bytes[] = [];
  for (const ko of keyOps) {
    if (!ko.data || ko.data.length !== 33) return null; // compressed only
    if (ko.op !== 0x21 || !ko.minimal) return null; // exact 0x21 push
    if (ko.data[0] !== 0x02 && ko.data[0] !== 0x03) return null;
    if (beToBig(ko.data.subarray(1, 33)) >= SECP_P) return null; // X < p
    keys.push(ko.data);
  }
  return { m, n, keys };
}

// ─── attribute one input ─────────────────────────────────────────────────────────────────────
export type AttribResult = { status: 0 | 1 | 2 | 3; sighash: Bytes; identity: Bytes };

export function attribute(tx: RawTx, k: number): AttribResult {
  if (k < 0 || k >= tx.vins.length) return { status: 0, sighash: ZERO32, identity: ZERO20 };
  const c = classify(tx.vins[k].scriptSig);
  if (!c) return { status: 0, sighash: ZERO32, identity: ZERO20 };

  if (c.kind === "p2pkh") {
    const identity = hash160(c.pubkey);
    // scriptCode = OP_DUP OP_HASH160 <id> OP_EQUALVERIFY OP_CHECKSIG; FindAndDelete the sig push.
    let scriptCode = concat(u8(0x76), u8(0xa9), minimalPush(identity), u8(0x88), u8(0xac));
    scriptCode = findAndDelete(scriptCode, minimalPush(c.sig));
    const sighash = sha256d(serializeForSighash(tx, k, scriptCode));
    if (!onCurve(c.pubkey)) return { status: 1, sighash, identity };
    if (!ecdsaVerify(sighash, c.r, c.s, c.pubkey)) return { status: 2, sighash, identity };
    return { status: 3, sighash, identity };
  }

  // P2SH multisig
  const identity = hash160(c.redeem);
  // scriptCode = redeemScript; FindAndDelete each checked sig push (inert on the rigid template,
  // but implemented for real per §4 step 4 — "Implement FindAndDelete; do not assert it away").
  let scriptCode = c.redeem;
  const rawSigs = extractRawSigs(tx.vins[k].scriptSig, c.m);
  for (const rs of rawSigs) scriptCode = findAndDelete(scriptCode, minimalPush(rs));
  const sighash = sha256d(serializeForSighash(tx, k, scriptCode));
  // on_curve checked on ALL n redeemScript keys up front (§4 step 4)
  for (const key of c.keys) if (!onCurve(key)) return { status: 1, sighash, identity };
  // in-order signature scan: m sigs must match a subsequence of n keys in order
  let ki = 0;
  let verified = 0;
  for (const sg of c.sigs) {
    while (ki < c.keys.length && !ecdsaVerify(sighash, sg.r, sg.s, c.keys[ki])) ki++;
    if (ki < c.keys.length) { verified++; ki++; } else break;
  }
  if (verified < c.m) return { status: 2, sighash, identity };
  return { status: 3, sighash, identity };
}

function extractRawSigs(scriptSig: Bytes, m: number): Bytes[] {
  const ops = getOps(scriptSig);
  if (!ops) return [];
  // OP_0 [sig]×m [redeem]
  const out: Bytes[] = [];
  for (let i = 1; i <= m && i < ops.length - 1; i++) if (ops[i].data) out.push(ops[i].data as Bytes);
  return out;
}
