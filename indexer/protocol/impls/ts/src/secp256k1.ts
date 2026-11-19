// §4 Strategy B — real secp256k1 (clean-room TypeScript port of impls/c/src/secp256k1.c).
//
// Genuine elliptic-curve math over the field p = 2^256 − 2^32 − 977: field arithmetic,
// Jacobian point ops + double-and-add scalar multiply, ECDSA verify, and RFC-6979
// deterministic signing (HMAC-SHA256 nonce, low-S normalized). Native BigInt for all
// bignum (no limbs). NOT constant time — verifier/test oracle only, never secrets in prod.
// Mirrors C semantics exactly so the §13 curve-vector set is byte-identical cross-language.
import type { Bytes } from "./bytes.ts";
import { sha256 } from "./sha256.ts";

// ─── curve constants (ported from secp256k1.c; big-endian value semantics) ─────────────────────
export const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn; // 2^256−2^32−977
export const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
export const N_HALF = N >> 1n;
export const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
export const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

const MASK256 = (1n << 256n) - 1n;

// ─── 32-byte big-endian <-> bigint ─────────────────────────────────────────────────────────────
export function be32(v: bigint): Bytes {
  const out = new Uint8Array(32);
  let x = v & MASK256;
  for (let i = 31; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}
function fromBE(b: Bytes, off = 0, len = 32): bigint {
  let v = 0n;
  for (let i = 0; i < len; i++) v = (v << 8n) | BigInt(b[off + i]);
  return v;
}

// ─── field arithmetic mod p ──────────────────────────────────────────────────────────────────
const mod = (a: bigint, m: bigint): bigint => { const r = a % m; return r < 0n ? r + m : r; };
const fadd = (a: bigint, b: bigint): bigint => mod(a + b, P);
const fsub = (a: bigint, b: bigint): bigint => mod(a - b, P);
const fmul = (a: bigint, b: bigint): bigint => mod(a * b, P);
const fsqr = (a: bigint): bigint => mod(a * a, P);

function fpow(a: bigint, e: bigint): bigint {
  let acc = 1n, base = mod(a, P), exp = e;
  while (exp > 0n) {
    if (exp & 1n) acc = fmul(acc, base);
    base = fsqr(base);
    exp >>= 1n;
  }
  return acc;
}
const finv = (a: bigint): bigint => fpow(a, P - 2n);            // a^(p-2)
const fsqrt = (a: bigint): bigint => fpow(a, (P + 1n) >> 2n);   // a^((p+1)/4); p≡3 mod 4

// ─── points (Jacobian: affine = (X/Z^2, Y/Z^3); Z==0 ⇒ infinity) ──────────────────────────────
type Jac = { X: bigint; Y: bigint; Z: bigint; inf: boolean };
const jacInf = (): Jac => ({ X: 1n, Y: 1n, Z: 0n, inf: true });
const jacFromAffine = (x: bigint, y: bigint): Jac => ({ X: x, Y: y, Z: 1n, inf: false });

function jacDouble(p: Jac): Jac {
  if (p.inf || p.Y === 0n) return jacInf();
  const A = fsqr(p.X);
  const B = fsqr(p.Y);
  const C = fsqr(B);
  let t = fsqr(fadd(p.X, B));
  t = fsub(fsub(t, A), C);
  const D = fadd(t, t);
  const E = fadd(fadd(A, A), A);                                // 3A
  const F = fsqr(E);
  const X3 = fsub(fsub(F, D), D);                              // F - 2D
  let y3 = fmul(E, fsub(D, X3));
  let t2 = fadd(fadd(fadd(C, C), fadd(C, C)), fadd(fadd(C, C), fadd(C, C))); // 8C
  const Y3 = fsub(y3, t2);
  const Z3 = fadd(fmul(p.Y, p.Z), fmul(p.Y, p.Z));            // 2·Y·Z
  return { X: X3, Y: Y3, Z: Z3, inf: false };
}
function jacAdd(p: Jac, q: Jac): Jac {
  if (p.inf) return { ...q };
  if (q.inf) return { ...p };
  const Z1Z1 = fsqr(p.Z), Z2Z2 = fsqr(q.Z);
  const U1 = fmul(p.X, Z2Z2), U2 = fmul(q.X, Z1Z1);
  const S1 = fmul(fmul(p.Y, q.Z), Z2Z2);                       // Y1·Z2^3
  const S2 = fmul(fmul(q.Y, p.Z), Z1Z1);                       // Y2·Z1^3
  if (U1 === U2) {
    if (S1 !== S2) return jacInf();                            // P + (−P)
    return jacDouble(p);                                        // P == Q
  }
  const H = fsub(U2, U1), R = fsub(S2, S1);
  const HH = fsqr(H), HHH = fmul(H, HH), V = fmul(U1, HH);
  const X3 = fsub(fsub(fsqr(R), HHH), fadd(V, V));            // R^2 - HHH - 2V
  const Y3 = fsub(fmul(R, fsub(V, X3)), fmul(S1, HHH));       // R·(V-X3) - S1·HHH
  const Z3 = fmul(fmul(p.Z, q.Z), H);                          // Z1·Z2·H
  return { X: X3, Y: Y3, Z: Z3, inf: false };
}
// R = scalar·P (double-and-add, MSB first over 256 bits) — mirrors C jac_mul byte loop.
function jacMul(p: Jac, k: bigint): Jac {
  let acc = jacInf();
  for (let bit = 255; bit >= 0; bit--) {
    acc = jacDouble(acc);
    if ((k >> BigInt(bit)) & 1n) acc = jacAdd(acc, p);
  }
  return acc;
}
function jacAffine(p: Jac): { x: bigint; y: bigint } | null {
  if (p.inf || p.Z === 0n) return null;
  const zinv = finv(p.Z);
  const zinv2 = fsqr(zinv);
  const zinv3 = fmul(zinv2, zinv);
  return { x: fmul(p.X, zinv2), y: fmul(p.Y, zinv3) };
}
const secpG = (): Jac => jacFromAffine(GX, GY);

// ─── pubkey decode + on-curve ──────────────────────────────────────────────────────────────────
function rhsCurve(x: bigint): bigint { return fadd(fmul(fsqr(x), x), 7n); } // x^3 + 7
// decode to affine; returns null off-curve / bad encoding (mirrors C pub_decode).
function pubDecode(pub: Bytes): { x: bigint; y: bigint } | null {
  const plen = pub.length;
  if (plen === 33 && (pub[0] === 0x02 || pub[0] === 0x03)) {
    const x = fromBE(pub, 1, 32);
    if (x >= P) return null;
    const rhs = rhsCurve(x);
    let beta = fsqrt(rhs);
    if (fsqr(beta) !== rhs) return null;                       // non-residue ⇒ off curve
    const wantOdd = pub[0] === 0x03;
    if ((beta & 1n) === 1n !== wantOdd) beta = fsub(P, beta);
    return { x, y: beta };
  }
  if (plen === 65 && pub[0] === 0x04) {
    const x = fromBE(pub, 1, 32);
    const y = fromBE(pub, 33, 32);
    if (x >= P || y >= P) return null;
    if (fsqr(y) !== rhsCurve(x)) return null;
    return { x, y };
  }
  return null;
}
export function onCurve(pub: Bytes): boolean {
  return pubDecode(pub) !== null;
}

// ─── ECDSA verify ────────────────────────────────────────────────────────────────────────────
export function ecdsaVerify(hash32: Bytes, r32: Bytes, s32: Bytes, pub: Bytes): boolean {
  const q = pubDecode(pub);
  if (!q) return false;
  const r = fromBE(r32), s = fromBE(s32);
  if (r === 0n || r >= N) return false;                        // 1 ≤ r < n
  if (s === 0n || s >= N) return false;                        // 1 ≤ s < n
  const z = mod(fromBE(hash32), N);                            // z mod n
  const w = modInv(s, N);                                       // s^{-1}
  const u1 = mod(z * w, N), u2 = mod(r * w, N);
  const Rj = jacAdd(jacMul(secpG(), u1), jacMul(jacFromAffine(q.x, q.y), u2));
  const aff = jacAffine(Rj);
  if (!aff) return false;                                       // R == ∞
  return mod(aff.x, N) === r;
}

// ─── scalar arithmetic mod n ───────────────────────────────────────────────────────────────────
function modInv(a: bigint, m: bigint): bigint {
  // extended Euclid; a in [1,m). Returns a^{-1} mod m (m prime / coprime).
  let [old_r, r] = [mod(a, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const qq = old_r / r;
    [old_r, r] = [r, old_r - qq * r];
    [old_s, s] = [s, old_s - qq * s];
  }
  return mod(old_s, m);
}

// ─── HMAC-SHA256 (on top of the suite's self-rolled sha256) ────────────────────────────────────
function hmacSha256(key: Bytes, msg: Bytes): Bytes {
  const block = 64;
  let k = key;
  if (k.length > block) k = sha256(k);
  const kpad = new Uint8Array(block);
  kpad.set(k, 0);
  const ki = new Uint8Array(block), ko = new Uint8Array(block);
  for (let i = 0; i < block; i++) { ki[i] = kpad[i] ^ 0x36; ko[i] = kpad[i] ^ 0x5c; }
  const inner = sha256(cat(ki, msg));
  return sha256(cat(ko, inner));
}
function cat(a: Bytes, b: Bytes): Bytes {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0); out.set(b, a.length);
  return out;
}

// ─── RFC-6979 nonce + ECDSA sign ───────────────────────────────────────────────────────────────
// First valid k in [1,n) from the HMAC_DRBG stream keyed by (priv, h1). Mirrors C rfc6979_k.
function rfc6979K(priv32: Bytes, hash32: Bytes): bigint {
  const h1o = be32(mod(fromBE(hash32), N));                     // bits2octets(h1) = (h1 mod n) BE
  let V = new Uint8Array(32).fill(0x01);
  let K = new Uint8Array(32).fill(0x00);
  // K = HMAC_K(V ‖ 0x00 ‖ priv ‖ h1o)
  K = hmacSha256(K, cat(cat(V, Uint8Array.of(0x00)), cat(priv32, h1o)));
  V = hmacSha256(K, V);
  K = hmacSha256(K, cat(cat(V, Uint8Array.of(0x01)), cat(priv32, h1o)));
  V = hmacSha256(K, V);
  for (;;) {
    V = hmacSha256(K, V);                                       // T = V (qlen==256 ⇒ one block)
    const k = fromBE(V);
    if (k !== 0n && k < N) return k;
    K = hmacSha256(K, cat(V, Uint8Array.of(0x00)));
    V = hmacSha256(K, V);
  }
}
// RFC-6979 deterministic sign, low-S normalized. Returns {r,s} as 32-byte BE or null.
export function ecdsaSign(priv32: Bytes, hash32: Bytes): { r: Bytes; s: Bytes } | null {
  const d = fromBE(priv32);
  if (d === 0n || d >= N) return null;
  const z = mod(fromBE(hash32), N);
  let feed = Uint8Array.from(hash32);
  for (let attempt = 0; attempt < 64; attempt++) {
    const k = rfc6979K(priv32, feed);
    const Raff = jacAffine(jacMul(secpG(), k));
    if (!Raff) { feed = sha256(be32(k)); continue; }
    const r = mod(Raff.x, N);
    if (r === 0n) { feed = sha256(be32(k)); continue; }
    const kinv = modInv(k, N);
    let s = mod(kinv * mod(z + mod(r * d, N), N), N);
    if (s === 0n) { feed = sha256(be32(k)); continue; }
    if (s > N_HALF) s = N - s;                                  // low-S
    return { r: be32(r), s: be32(s) };
  }
  return null;
}
// derive the 33-byte compressed pubkey from a private scalar. Null if priv is 0 or ≥ n.
export function pubkey(priv32: Bytes): Bytes | null {
  const d = fromBE(priv32);
  if (d === 0n || d >= N) return null;
  const aff = jacAffine(jacMul(secpG(), d));
  if (!aff) return null;
  const out = new Uint8Array(33);
  out[0] = (aff.y & 1n) === 1n ? 0x03 : 0x02;
  out.set(be32(aff.x), 1);
  return out;
}

// ─── ECMH (Elliptic Curve Multiset Hash) ───────────────────────────────────────────────────────
// An accumulator is a 33-byte compressed point (0x02/0x03 ‖ X-be); the all-zero sentinel
// (prefix 0x00) is the identity ∞. Mirrors impls/c/src/secp256k1.c's ECMH block byte-for-byte.
const ECMH_H2C_TAG = Uint8Array.of(0x45, 0x43, 0x4d, 0x48, 0x68, 0x32, 0x63, 0x31); // "ECMHh2c1"

export function ecmhIdentity(): Bytes {
  return new Uint8Array(33);
}

// point → 33 bytes (∞ → zeros), real y-parity recompression.
function ecmhSer(p: Jac): Bytes {
  const aff = jacAffine(p);
  if (p.inf || !aff) return new Uint8Array(33);
  const out = new Uint8Array(33);
  out[0] = (aff.y & 1n) === 1n ? 0x03 : 0x02;
  out.set(be32(aff.x), 1);
  return out;
}
// 33 bytes → point (prefix 0x00 ⇒ ∞).
function ecmhLoad(in33: Bytes): Jac {
  if (in33[0] === 0) return jacInf();
  const dec = pubDecode(in33);
  if (!dec) return jacInf();
  return jacFromAffine(dec.x, dec.y);
}

// hash-to-curve, try-and-increment. Returns [33-byte even-Y compressed point, ctr used].
export function ecmhHash(pre: Bytes): { pt: Bytes; ctr: number } {
  for (let ctr = 0; ; ctr++) {
    // h = SHA256("ECMHh2c1" ‖ pre ‖ uint32_LE(ctr))
    const cb = Uint8Array.of(ctr & 0xff, (ctr >>> 8) & 0xff, (ctr >>> 16) & 0xff, (ctr >>> 24) & 0xff);
    const h = sha256(cat(cat(ECMH_H2C_TAG, pre), cb));
    const x = mod(fromBE(h), P);                  // x = SHA256(...) mod p
    const rhs = rhsCurve(x);                       // x³ + 7
    const beta = fsqrt(rhs);
    if (fsqr(beta) !== rhs) continue;              // not a QR ⇒ bump ctr
    const pt = new Uint8Array(33);
    pt[0] = 0x02;                                  // canonical even-Y
    pt.set(be32(x), 1);
    return { pt, ctr };
  }
}

export function ecmhNegate(pt33: Bytes): Bytes {
  const out = Uint8Array.from(pt33);
  if (out[0]) out[0] ^= 1;                         // identity (0x00) unchanged
  return out;
}

export function ecmhAdd(acc33: Bytes, pt33: Bytes): Bytes {
  const r = jacAdd(ecmhLoad(acc33), ecmhLoad(pt33));
  return ecmhSer(r);
}

// ─── self-check: pinned constants + 2G + n·G=∞ + decompress + sign/verify round-trip ───────────
export function secpSelftest(): number {
  let fail = 0;
  const F = (what: string): void => { fail++; if (process.env.SECP_KAT_VERBOSE) console.error("secp KAT FAIL:", what); };
  // constants: N_HALF = N>>1
  if ((N >> 1n) !== N_HALF) F("N_HALF");
  // G on curve (uncompressed)
  { const g = new Uint8Array(65); g[0] = 0x04; g.set(be32(GX), 1); g.set(be32(GY), 33);
    if (!onCurve(g)) F("G on curve"); }
  // 2G known-answer
  { const aff = jacAffine(jacMul(secpG(), 2n));
    const G2X = 0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5n;
    const G2Y = 0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52an;
    if (!aff || aff.x !== G2X || aff.y !== G2Y) F("2G value"); }
  // n·G == ∞
  { if (jacAffine(jacMul(secpG(), N)) !== null) F("n·G != inf"); }
  // decompress round-trip: compress G (even Y), decode, compare
  { const gc = new Uint8Array(33); gc[0] = 0x02; gc.set(be32(GX), 1);
    const dec = pubDecode(gc);
    if (!dec || dec.y !== GY) F("decompress G"); }
  // sign/verify round-trip + tamper over deterministic keys
  for (let t = 1; t <= 4; t++) {
    const priv = new Uint8Array(32); priv[31] = (t * 7 + 1) & 0xff;
    const pub = pubkey(priv);
    if (!pub) { F("pubkey"); continue; }
    const msg = new Uint8Array(32); for (let i = 0; i < 32; i++) msg[i] = (i * 13 + t) & 0xff;
    const mh = sha256(msg);
    const sig = ecdsaSign(priv, mh);
    if (!sig) { F("sign"); continue; }
    if (!ecdsaVerify(mh, sig.r, sig.s, pub)) F("verify");
    const mh2 = Uint8Array.from(mh); mh2[0] ^= 0x01;
    if (ecdsaVerify(mh2, sig.r, sig.s, pub)) F("tamper verify");
  }
  return fail;
}
