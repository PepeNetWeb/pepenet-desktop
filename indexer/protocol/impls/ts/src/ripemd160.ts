// Self-rolled RIPEMD-160 (the one new hash primitive, SPEC-conformance.md §13). KATs pinned in
// §13: ""→9c1185a5c5e9fc54612808977ee8f548b2258d31, "abc"→8eb208f7e05d987a9b044a8e98c6b087f15a0bfc,
// hash160("abc")=RIPEMD160(SHA256("abc"))→bb1be98c142444d7a56aa3981c3942a978e4dc33. Verified in
// the selftest. 32-bit lanes via `>>> 0` (control values, never the koinu value path).
import type { Bytes } from "./bytes.ts";
import { sha256 } from "./sha256.ts";

// message word selection
const ZL = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
  4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];
const ZR = [
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
  6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
  12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];
const SL = [
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
  11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
  9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];
const SR = [
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
  9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
  15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
  8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];
const KL = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
const KR = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

const rol = (x: number, n: number): number => ((x << n) | (x >>> (32 - n))) >>> 0;

function f(j: number, x: number, y: number, z: number): number {
  if (j < 16) return (x ^ y ^ z) >>> 0;
  if (j < 32) return ((x & y) | (~x & z)) >>> 0;
  if (j < 48) return ((x | ~y) ^ z) >>> 0;
  if (j < 64) return ((x & z) | (y & ~z)) >>> 0;
  return (x ^ (y | ~z)) >>> 0;
}

export function ripemd160(msg: Bytes): Bytes {
  const ml = msg.length;
  const bitLen = ml * 8;
  const padLen = ((ml + 8) >> 6) + 1;
  const buf = new Uint8Array(padLen * 64);
  buf.set(msg, 0);
  buf[ml] = 0x80;
  // 64-bit little-endian length in the final 8 bytes
  const lenLo = bitLen >>> 0;
  const lenHi = Math.floor(bitLen / 0x100000000) >>> 0;
  const off = buf.length - 8;
  buf[off] = lenLo & 0xff;
  buf[off + 1] = (lenLo >>> 8) & 0xff;
  buf[off + 2] = (lenLo >>> 16) & 0xff;
  buf[off + 3] = (lenLo >>> 24) & 0xff;
  buf[off + 4] = lenHi & 0xff;
  buf[off + 5] = (lenHi >>> 8) & 0xff;
  buf[off + 6] = (lenHi >>> 16) & 0xff;
  buf[off + 7] = (lenHi >>> 24) & 0xff;

  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  const X = new Uint32Array(16);

  for (let i = 0; i < buf.length; i += 64) {
    for (let t = 0; t < 16; t++) {
      const j = i + t * 4;
      X[t] = (buf[j] | (buf[j + 1] << 8) | (buf[j + 2] << 16) | (buf[j + 3] << 24)) >>> 0;
    }
    let al = h0, bl = h1, cl = h2, dl = h3, el = h4;
    let ar = h0, br = h1, cr = h2, dr = h3, er = h4;
    for (let j = 0; j < 80; j++) {
      const rnd = j >> 4;
      let t = (al + f(j, bl, cl, dl) + X[ZL[j]] + KL[rnd]) >>> 0;
      t = (rol(t, SL[j]) + el) >>> 0;
      al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = t;
      let tr = (ar + f(79 - j, br, cr, dr) + X[ZR[j]] + KR[rnd]) >>> 0;
      tr = (rol(tr, SR[j]) + er) >>> 0;
      ar = er; er = dr; dr = rol(cr, 10); cr = br; br = tr;
    }
    const t = (h1 + cl + dr) >>> 0;
    h1 = (h2 + dl + er) >>> 0;
    h2 = (h3 + el + ar) >>> 0;
    h3 = (h4 + al + br) >>> 0;
    h4 = (h0 + bl + cr) >>> 0;
    h0 = t;
  }

  const out = new Uint8Array(20);
  const hs = [h0, h1, h2, h3, h4];
  for (let i = 0; i < 5; i++) {
    out[i * 4] = hs[i] & 0xff;
    out[i * 4 + 1] = (hs[i] >>> 8) & 0xff;
    out[i * 4 + 2] = (hs[i] >>> 16) & 0xff;
    out[i * 4 + 3] = (hs[i] >>> 24) & 0xff;
  }
  return out;
}

// hash160 = RIPEMD160(SHA256(x)) — the §0/§4 legacy address hash.
export function hash160(x: Bytes): Bytes {
  return ripemd160(sha256(x));
}
