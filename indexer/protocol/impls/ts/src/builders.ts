// Test/generator construction helpers — build carrier payloads + abstract txs for the fold.
import type { Bytes } from "./bytes.ts";
import { concat, u8, u32le, u64le, leBytes } from "./bytes.ts";
import { OP, PREFIX0, PREFIX1, PREFIX2 } from "./constants.ts";
import type { FoldInput, FoldCarrier, FoldOutput, FoldTx } from "./fold.ts";

const enc = new TextEncoder();
export const str = (s: string): Bytes => enc.encode(s);

// generator identity scheme (conformance §5): h160 = byte(i) ‖ 18 zero bytes ‖ byte(i)
export function genId(i: number): Bytes {
  const b = new Uint8Array(20);
  b[0] = i & 0xff;
  b[19] = i & 0xff;
  return b;
}
export const genType = (i: number): number => (i % 4 === 3 ? 1 : 0); // P2SH if i%4==3 else P2PKH

export function input(id: Bytes | null, type = 0, sighashAll = true): FoldInput {
  return { id, type, sighashAll };
}
export function output(type: number, hash: Bytes, value: bigint): FoldOutput {
  return { type, hash, value };
}
export function tx(inputs: FoldInput[], carriers: FoldCarrier[], outputs: FoldOutput[] = []): FoldTx {
  return { inputs, carriers, outputs };
}

function frame(op: number, body: Bytes): Bytes {
  return concat(u8(PREFIX0), u8(PREFIX1), u8(PREFIX2), u8(op), body);
}
export function carrier(op: number, body: Bytes, value = 0n, vout = 0): FoldCarrier {
  return { payload: frame(op, body), value, vout };
}
export function rawCarrier(payload: Bytes, value = 0n, vout = 0): FoldCarrier {
  return { payload, value, vout };
}

// ─── per-op body builders (names-only 0x01–0x0C) ──────────────────────────────────────────────
export const commit = (commitment: Bytes, vout = 0): FoldCarrier =>
  carrier(OP.COMMIT, commitment, 0n, vout);
export const claim = (salt: Bytes, name: string, burn: bigint, vout = 0): FoldCarrier =>
  carrier(OP.CLAIM, concat(salt, str(name)), burn, vout);
export const renewAll = (burn: bigint, vout = 0): FoldCarrier =>
  carrier(OP.RENEW, new Uint8Array(0), burn, vout);
export const renewAllSafe = (anchor: bigint, burn: bigint, vout = 0): FoldCarrier =>
  carrier(OP.RENEW, leBytes(anchor, 5), burn, vout);
export const renewSel = (anchor: bigint, flags: Bytes, burn: bigint, vout = 0): FoldCarrier =>
  carrier(OP.RENEW, concat(leBytes(anchor, 5), flags), burn, vout);
export const transferAll = (target: Bytes, vout = 0): FoldCarrier =>
  carrier(OP.TRANSFER, target, 0n, vout);
export const transferSel = (target: Bytes, anchor: bigint, flags: Bytes, vout = 0): FoldCarrier =>
  carrier(OP.TRANSFER, concat(target, leBytes(anchor, 5), flags), 0n, vout);
export const sell = (price: bigint, window: bigint, name: string, vout = 0): FoldCarrier =>
  carrier(OP.SELL, concat(u64le(price), u32le(window), str(name)), 0n, vout);
export const reserve = (name: string, value: bigint, vout = 0): FoldCarrier =>
  carrier(OP.RESERVE, str(name), value, vout);
export const settle = (name: string, vout = 0): FoldCarrier =>
  carrier(OP.SETTLE, str(name), 0n, vout);
export const release = (anchor: bigint, flags: Bytes, vout = 0): FoldCarrier =>
  carrier(OP.RELEASE, concat(leBytes(anchor, 5), flags), 0n, vout);
export const sellTo = (price: bigint, buyer: Bytes, name: string, vout = 0): FoldCarrier =>
  carrier(OP.SELL_TO, concat(u64le(price), buyer, str(name)), 0n, vout);
export const pay = (name: string, vout = 0): FoldCarrier =>
  carrier(OP.PAY, str(name), 0n, vout);
export const asMarker = (index: number, vout = 0): FoldCarrier =>
  carrier(OP.AS, u8(index), 0n, vout);
export const trade = (idxA: number, idxB: number, nameA: string, nameB: string, vout = 0): FoldCarrier =>
  carrier(OP.TRADE, concat(u8(idxA), u8(idxB), str(nameA), str(",") , str(nameB)), 0n, vout);

// commitment = SHA256(salt ‖ name ‖ author_h160) — exported for test construction
import { sha256 } from "./sha256.ts";
export const commitmentOf = (salt: Bytes, name: string, author: Bytes): Bytes =>
  sha256(concat(salt, str(name), author));
