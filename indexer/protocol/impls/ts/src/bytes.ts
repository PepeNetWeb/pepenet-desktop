// Byte + little-endian helpers. Per SPEC-conformance.md §2/§4: every value-bearing field is a
// `bigint` (koinu/price/weight/time), read from LE bytes straight into bigint so a JS `number`
// never touches the value path. `number` is used ONLY for genuinely ≤32-bit, non-value quantities
// (vout, tx_index, array indices, counts, single bytes, UTF-8 code points) per §2.

export type Bytes = Uint8Array;

export const MASK64 = (1n << 64n) - 1n;
export const MASK128 = (1n << 128n) - 1n;

export function hex(b: Bytes): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

export function fromHex(s: string): Bytes {
  const clean = s.replace(/\s+/g, "");
  if (clean.length % 2 !== 0) throw new Error("odd-length hex");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(clean.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function concat(...parts: Bytes[]): Bytes {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function eqBytes(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// Unsigned bytewise lexicographic compare (the §3.5 owned-set ordering; the §4 digest sort key).
export function cmpBytes(a: Bytes, b: Bytes): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  if (a.length === b.length) return 0;
  return a.length < b.length ? -1 : 1;
}

// ─── LE integer read (bytes → bigint) ────────────────────────────────────────────────────────
export function rdLE(b: Bytes, off: number, len: number): bigint {
  let v = 0n;
  for (let i = len - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[off + i]);
  return v;
}

export function rdU32(b: Bytes, off: number): number {
  // vout / tx_index / counts — genuinely ≤32-bit, a `number` holds it exactly (§2).
  return b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | b[off + 3] * 0x1000000;
}

// ─── LE integer write (bigint → bytes) ───────────────────────────────────────────────────────
// Two's-complement for signed widths; the value is masked to width so a negative bigint serializes
// as its LE two's-complement form (matches "signed values are two's-complement LE", §4).
export function leBytes(v: bigint, len: number): Bytes {
  const mask = (1n << BigInt(8 * len)) - 1n;
  let x = v & mask; // two's-complement for negatives
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

export const u8 = (v: number): Bytes => Uint8Array.of(v & 0xff);
export const u32le = (v: number | bigint): Bytes => leBytes(BigInt(v), 4);
export const u64le = (v: bigint): Bytes => leBytes(v, 8);
export const i64le = (v: bigint): Bytes => leBytes(v, 8);
export const i128le = (v: bigint): Bytes => leBytes(v, 16);

// Bitcoin/Dogecoin CompactSize varint (used by the legacy-sighash serializer, §4 step 4).
export function varint(n: bigint): Bytes {
  if (n < 0xfdn) return u8(Number(n));
  if (n <= 0xffffn) return concat(u8(0xfd), leBytes(n, 2));
  if (n <= 0xffffffffn) return concat(u8(0xfe), leBytes(n, 4));
  return concat(u8(0xff), leBytes(n, 8));
}
