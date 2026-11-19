// §4 Strategy B — the pinned ECDSA curve-vector set (`sm attrib-curve`).
//
// Clean-room TS port of impls/c/src/attrib_curve.c + attrib.c `attrib_real_endtoend`. Runs the
// exact vector script against THIS impl's secp256k1 and must print BYTE-IDENTICAL output to the C
// reference (RFC-6979 + DER + field math are deterministic). Covers pinned P/N/N_HALF constants,
// on-curve membership at the edges, ECDSA verify accept/reject at the scalar boundaries, RFC-6979
// (r,s) + canonical-DER KAT, tiny-key KAT, the PRIMARY `combined` digest, and an end-to-end section
// that signs the real legacy sighash and feeds the existing §4 attribution byte-logic with the real
// curve. See SPEC-conformance.md §13 + SPEC-RATIONALE.md §11.
import type { Bytes } from "./bytes.ts";
import { hex, concat, u8 } from "./bytes.ts";
import { sha256 } from "./sha256.ts";
import { hash160 } from "./ripemd160.ts";
import {
  P, N, N_HALF, GX, GY, be32, pubkey, ecdsaSign, ecdsaVerify, onCurve,
} from "./secp256k1.ts";
import { parseTx, attribute, setRealCurve, type RawTx } from "./attribution.ts";

const CV_P = be32(P);
const CV_N = be32(N);
const CV_NHALF = be32(N_HALF);
const CV_GX = be32(GX);
const CV_GY = be32(GY);

// canonical strict-DER (r,s) ‖ SIGHASH_ALL — mirrors C der_int/der_sig (== der_int_e/der_sig_e).
function derInt(v: Bytes): Bytes {
  let i = 0;
  while (i < 31 && v[i] === 0) i++;
  const len = 32 - i;
  const pad = (v[i] & 0x80) ? 1 : 0;
  const out = new Uint8Array(2 + pad + len);
  out[0] = 0x02; out[1] = len + pad;
  let n = 2;
  if (pad) out[n++] = 0x00;
  out.set(v.subarray(i), n);
  return out;
}
function derSig(r: Bytes, s: Bytes): Bytes {
  const body = concat(derInt(r), derInt(s));
  return concat(u8(0x30), u8(body.length), body, u8(0x01)); // SIGHASH_ALL
}

// minimal-push helpers (mirror C emit_push / put_*) for the e2e raw-tx assembly.
function emitPush(d: Bytes): Bytes {
  if (d.length < 76) return concat(u8(d.length), d);
  if (d.length <= 255) return concat(u8(0x4c), u8(d.length), d);
  return concat(u8(0x4d), u8(d.length & 0xff), u8((d.length >> 8) & 0xff), d);
}
function u32le(v: number): Bytes {
  return Uint8Array.of(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff);
}
function u64le(v: bigint): Bytes {
  const out = new Uint8Array(8); let x = v;
  for (let i = 0; i < 8; i++) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}
function varint(v: number): Bytes {
  if (v < 0xfd) return u8(v);
  if (v <= 0xffff) return concat(u8(0xfd), u8(v & 0xff), u8((v >> 8) & 0xff));
  return concat(u8(0xfe), u32le(v));
}

// shared tx skeleton bytes for the legacy sighash (1 input scriptCode-filled, 1 OP_RETURN output).
// Mirrors C e2e_skeleton + legacy_sighash: version=1, outpoint 0x11×36, seq=FFFFFFFF, value=100000,
// spk=OP_RETURN(0x6a), locktime=0, SIGHASH_ALL trailer.
function legacySighash(scriptCode: Bytes): Bytes {
  const parts: Bytes[] = [];
  parts.push(u32le(1));               // version
  parts.push(varint(1));              // n_in
  // input 0 (the signing input): outpoint, scriptCode, seq
  const outpoint = new Uint8Array(36).fill(0x11);
  parts.push(outpoint);
  parts.push(varint(scriptCode.length));
  parts.push(scriptCode);
  parts.push(u32le(0xffffffff));      // seq
  parts.push(varint(1));              // n_out
  parts.push(u64le(100000n));         // value
  parts.push(varint(1));              // spklen
  parts.push(u8(0x6a));               // OP_RETURN
  parts.push(u32le(0));               // locktime
  parts.push(u32le(1));               // SIGHASH_ALL
  return sha256(sha256(concat(...parts)));
}

// assemble the raw tx carrying a given scriptSig (mirrors C e2e_rawtx).
function e2eRawtx(ss: Bytes): Bytes {
  const parts: Bytes[] = [];
  parts.push(u32le(1));
  parts.push(varint(1));
  parts.push(new Uint8Array(36).fill(0x11));
  parts.push(varint(ss.length));
  parts.push(ss);
  parts.push(u32le(0xffffffff));
  parts.push(varint(1));
  parts.push(u64le(100000n));
  parts.push(varint(1));
  parts.push(u8(0x6a));
  parts.push(u32le(0));
  return concat(...parts);
}

export function cmdAttribCurve(): number {
  const feeds: Bytes[] = [];
  const FEED = (b: Bytes): void => { feeds.push(b); };
  const out: string[] = [];

  // ── 1. pinned constants ────────────────────────────────────────────────────
  out.push(`p ${hex(CV_P)}`); FEED(CV_P);
  out.push(`n ${hex(CV_N)}`); FEED(CV_N);
  out.push(`nhalf ${hex(CV_NHALF)}`); FEED(CV_NHALF);

  // ── 2. on-curve membership at the edges ────────────────────────────────────
  type OC = { name: string; key: Bytes };
  const oc: OC[] = [];
  // G uncompressed (on)
  { const b = new Uint8Array(65); b[0] = 0x04; b.set(CV_GX, 1); b.set(CV_GY, 33);
    oc.push({ name: "oc_G_uncomp", key: b }); }
  // G compressed even (on)
  { const b = new Uint8Array(33); b[0] = 0x02; b.set(CV_GX, 1);
    oc.push({ name: "oc_G_comp02", key: b }); }
  // G compressed odd-prefix (still on curve)
  { const b = new Uint8Array(33); b[0] = 0x03; b.set(CV_GX, 1);
    oc.push({ name: "oc_G_comp03", key: b }); }
  // (Gx, Gy^lsb) uncompressed (off curve)
  { const b = new Uint8Array(65); b[0] = 0x04; b.set(CV_GX, 1); b.set(CV_GY, 33); b[64] ^= 0x01;
    oc.push({ name: "oc_G_badY", key: b }); }
  // compressed X=0
  { const b = new Uint8Array(33); b[0] = 0x02;
    oc.push({ name: "oc_X0", key: b }); }
  // compressed X=1
  { const b = new Uint8Array(33); b[0] = 0x02; b[32] = 1;
    oc.push({ name: "oc_X1", key: b }); }
  // uncompressed X>=p (X=p) ⇒ decode-reject
  { const b = new Uint8Array(65); b[0] = 0x04; b.set(CV_P, 1); b.set(CV_GY, 33);
    oc.push({ name: "oc_Xeqp", key: b }); }
  // compressed X>=p ⇒ decode-reject
  { const b = new Uint8Array(33); b[0] = 0x02; b.set(CV_P, 1);
    oc.push({ name: "oc_comp_Xeqp", key: b }); }
  // bad prefix 0x05 ⇒ reject
  { const b = new Uint8Array(33); b[0] = 0x05; b.set(CV_GX, 1);
    oc.push({ name: "oc_badprefix", key: b }); }
  for (const e of oc) {
    const v = onCurve(e.key) ? 1 : 0;
    out.push(`${e.name} ${v}`);
    FEED(u8(v)); FEED(e.key);
  }

  // ── 3 & 4. RFC-6979 deterministic sign + ECDSA verify at the boundaries ─────
  for (let i = 0; i < 4; i++) {
    const priv = new Uint8Array(32);
    priv[28] = 0xc0; priv[29] = 0xff; priv[30] = 0xee; priv[31] = (0x10 + i) & 0xff;
    const pub = pubkey(priv);
    if (!pub) { out.push(`sig${i} PUBFAIL`); continue; }
    const m = new TextEncoder().encode(`strategy-b curve vector ${i}`);
    const h = sha256(m);
    const sig = ecdsaSign(priv, h);
    if (!sig) { out.push(`sig${i} SIGNFAIL`); continue; }
    const der = derSig(sig.r, sig.s);
    out.push(`sig${i} pub=${hex(pub)} r=${hex(sig.r)} s=${hex(sig.s)} der=${hex(der)}`);
    FEED(pub); FEED(sig.r); FEED(sig.s); FEED(der);

    // verify boundary battery (accept/reject bit each).
    const zero = new Uint8Array(32);
    const hbad = Uint8Array.from(h); hbad[0] ^= 0x01;
    const hiS = new Uint8Array(32);   // high-S = n - s (byte subtraction)
    { let borrow = 0;
      for (let k = 31; k >= 0; k--) {
        let d = CV_N[k] - sig.s[k] - borrow;
        if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
        hiS[k] = d;
      } }
    const wrongpub = Uint8Array.from(pub); wrongpub[0] ^= 0x01;
    const vt: { nm: string; hh: Bytes; rr: Bytes; ss: Bytes; pk: Bytes }[] = [
      { nm: "valid",   hh: h,    rr: sig.r, ss: sig.s, pk: pub },
      { nm: "tamper",  hh: hbad, rr: sig.r, ss: sig.s, pk: pub },
      { nm: "r0",      hh: h,    rr: zero,  ss: sig.s, pk: pub },
      { nm: "s0",      hh: h,    rr: sig.r, ss: zero,  pk: pub },
      { nm: "rN",      hh: h,    rr: CV_N,  ss: sig.s, pk: pub },
      { nm: "sN",      hh: h,    rr: sig.r, ss: CV_N,  pk: pub },
      { nm: "highS",   hh: h,    rr: sig.r, ss: hiS,   pk: pub },
      { nm: "wrongpk", hh: h,    rr: sig.r, ss: sig.s, pk: wrongpub },
    ];
    let line = `ver${i}`;
    for (const t of vt) {
      const v = ecdsaVerify(t.hh, t.rr, t.ss, t.pk) ? 1 : 0;
      line += ` ${t.nm}=${v}`;
      FEED(u8(v));
    }
    out.push(line);
  }

  // ── 5. tiny-key KAT: priv=1 ⇒ pub=G ; priv=2 ⇒ pub=2G ──────────────────────
  { const p1 = new Uint8Array(32); p1[31] = 1; const pk1 = pubkey(p1)!;
    out.push(`priv1_pub=${hex(pk1)}`); FEED(pk1);
    const p2 = new Uint8Array(32); p2[31] = 2; const pk2 = pubkey(p2)!;
    out.push(`priv2_pub=${hex(pk2)}`); FEED(pk2); }

  // PRIMARY cross-language digest (sections 1–5).
  const combined = sha256(concat(...feeds));
  out.push(`combined ${hex(combined)}`);

  // ── 6. end-to-end: sign the real legacy sighash, attribute() with real curve ──
  const e2eOut = e2eEndToEnd();
  for (const l of e2eOut.lines) out.push(l);
  out.push(`combined_e2e ${hex(e2eOut.digest)}`);

  console.log(out.join("\n"));
  return 0;
}

// mirrors attrib.c `attrib_real_endtoend`.
function e2eEndToEnd(): { lines: string[]; digest: Bytes } {
  setRealCurve(true);
  const lines: string[] = [];
  const feeds: Bytes[] = [];
  const emit = (name: string, tx: RawTx | null): void => {
    if (!tx) { lines.push(`${name} PARSEFAIL`); return; }
    const res = attribute(tx, 0);
    lines.push(`${name} ${res.status}:${hex(res.identity)}`);
    feeds.push(u8(res.status)); feeds.push(res.sighash); feeds.push(res.identity);
  };

  // P2PKH scriptCode = OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG.
  const p2pkhScriptCode = (h160: Bytes): Bytes =>
    concat(u8(0x76), u8(0xa9), u8(0x14), h160, u8(0x88), u8(0xac));

  // ── A. P2PKH, correctly signed ⇒ FOUND (status 3) ──────────────────────────
  {
    const priv = new Uint8Array(32); priv[31] = 0x2a; // 42
    const pub = pubkey(priv)!;
    const h160 = hash160(pub);
    const sh = legacySighash(p2pkhScriptCode(h160));
    const sig = ecdsaSign(priv, sh)!;
    const der = derSig(sig.r, sig.s);
    const ss = concat(emitPush(der), emitPush(pub));
    emit("e2e_p2pkh_valid", parseTx(e2eRawtx(ss)));
  }
  // ── B. P2PKH, signed by the WRONG key ⇒ verify-drop (status 2) ──────────────
  {
    const priv = new Uint8Array(32); priv[31] = 0x2a;
    const wrong = new Uint8Array(32); wrong[31] = 0x2b;
    const pub = pubkey(priv)!;
    const h160 = hash160(pub);
    const sh = legacySighash(p2pkhScriptCode(h160));
    const sig = ecdsaSign(wrong, sh)!; // wrong key signs
    const der = derSig(sig.r, sig.s);
    const ss = concat(emitPush(der), emitPush(pub));
    emit("e2e_p2pkh_wrongkey", parseTx(e2eRawtx(ss)));
  }
  // ── C. 2-of-2 P2SH multisig, two in-order sigs ⇒ FOUND (status 3) ───────────
  {
    const priv: Bytes[] = [], pub: Bytes[] = [];
    for (let i = 0; i < 2; i++) {
      const p = new Uint8Array(32); p[31] = (0x50 + i) & 0xff;
      priv.push(p); pub.push(pubkey(p)!);
    }
    // redeemScript: OP_2 <k0> <k1> OP_2 OP_CHECKMULTISIG
    let rs = u8(0x52);
    for (let i = 0; i < 2; i++) rs = concat(rs, u8(0x21), pub[i]);
    rs = concat(rs, u8(0x52), u8(0xae));
    const sh = legacySighash(rs);
    let ss = u8(0x00); // NULLDUMMY
    for (let i = 0; i < 2; i++) {
      const sig = ecdsaSign(priv[i], sh)!;
      ss = concat(ss, emitPush(derSig(sig.r, sig.s)));
    }
    ss = concat(ss, emitPush(rs));
    emit("e2e_multisig_valid", parseTx(e2eRawtx(ss)));
  }

  setRealCurve(false);
  return { lines, digest: sha256(concat(...feeds)) };
}
