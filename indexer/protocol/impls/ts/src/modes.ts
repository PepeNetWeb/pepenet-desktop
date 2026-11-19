// Generator-driven invariant-battery modes (§8 properties · §9 fuzz · §10 reorg · §11 meta/reorgfuzz).
// Ported from impls/java/Modes.java to drive THIS clean-room's OWN fold/decoder/generator. The DIGESTS
// here do NOT match the gen.c-pinned soak goldens (the per-op draw order is not in prose) and are NOT
// claimed to — only the GENERATOR-INDEPENDENT assertions matter: properties' `violations==0` (the fold
// preserves every §8 invariant), meta/reorg/reorgfuzz's `failures==0` (the fold is drop-closed and a
// pure, reorg-safe function of the block sequence), and fuzz's `parser_crashes==0` (fail-closed decode).
//
// These modes ONLY add test scaffolding around the existing fold/decoder — no protocol logic changes.
import { SplitMix64 } from "./prng.ts";
import { Fold } from "./fold.ts";
import type { FoldTx, FoldInput, FoldCarrier, FoldOutput } from "./fold.ts";
import { sha256 } from "./sha256.ts";
import {
  concat, u8, u32le, u64le, i128le, hex, fromHex, cmpBytes, eqBytes, type Bytes,
} from "./bytes.ts";
import * as B from "./builders.ts";
import {
  OP, ST, N_IDS, NAME_POOL, BASE_TS, MAX_LEASE, SELL_PRICE_FLOOR, DUST_FLOOR,
  REORG_BUFFER, RESERVE_WINDOW, DIRECT_WINDOW, COMMIT_EXPIRY,
  RESERVE_BURN_BPS, RESERVE_PAY_BPS, BPS_DENOM,
} from "./constants.ts";

const dec = new TextDecoder();

// concat an ARRAY of byte chunks without spreading (a huge `concat(...arr)` spread overflows the
// JS arg-stack at ~1e5 chunks — the fuzz/properties digest accumulators reach that at 30k txs).
function concatAll(parts: Bytes[]): Bytes {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

// ─── recorded chain model (Java Model.Block) ──────────────────────────────────────────────────
// A RecBlock bundles {height, mtp, rate, txs} so a chain can be RECORDED once then re-folded /
// resumed / forked many times (Java's `recordChain` pattern). `txs[i]` carries its own txIndex.
type RecTx = { tx: FoldTx; txIndex: number };
type RecBlock = { height: bigint; mtp: bigint; rate: bigint; txs: RecTx[] };

// Fold a (sub-)range of a recorded chain into a fresh state, returning the digest.
function applyBlock(f: Fold, b: RecBlock): void {
  f.beginBlock(b.height, b.mtp, b.rate);
  for (const { tx, txIndex } of b.txs) f.applyTx(tx, txIndex);
}
function foldDigest(blocks: RecBlock[], lo: number, hi: number): string {
  const f = new Fold(0n);
  for (let i = lo; i < hi; i++) applyBlock(f, blocks[i]);
  return hex(f.digest());
}

// ─── op weights (names/market only) ───────────────────────────────────────────────────────────
// COMMIT,CLAIM,RENEW,TRANSFER,SELL,RESERVE,SETTLE,RELEASE,SELL_TO,PAY,TRADE — AS rides on RENEW.
const WEIGHTS = [14, 13, 5, 5, 8, 7, 7, 3, 6, 5, 4];
const W_SUM = WEIGHTS.reduce((a, b) => a + b, 0);

function nameOf(i: number): string { return "n" + i.toString(36); }
function saltOf(k: bigint): Bytes {
  const s = new Uint8Array(32);
  for (let i = 0; i < 8; i++) s[i] = Number((k >> BigInt(8 * i)) & 0xffn);
  s[31] = 0xa5;
  return s;
}

// MTP = median of the [H-11, H-1] timestamp window (SPEC-conformance §2; index k//2).
function computeMtp(ts: bigint[], H: number): bigint {
  const lo = Math.max(0, H - 11), hi = H; // [H-11, H-1]
  if (lo >= hi) return ts.length === 0 ? BASE_TS : ts[Math.min(H, ts.length - 1)];
  const w = ts.slice(lo, hi).slice().sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return w[Math.floor(w.length / 2)];
}

type Pending = { idIdx: number; name: string; salt: Bytes; commitHeight: bigint; commitTime: bigint };

// leg formula mirrors fold's private depositLegs (max(DUST_FLOOR, ⌊price·bps/10000⌋)).
function depositLeg(price: bigint, bps: bigint): bigint {
  const v = (price * bps) / BPS_DENOM;
  return v > DUST_FLOOR ? v : DUST_FLOOR;
}

// names in state by predicate (owner filter + state filter).
function namesWhere(f: Fold, owner: Bytes | null, reqSt: number): string[] {
  const out: string[] = [];
  for (const r of (f.names as Map<string, any>).values()) {
    if (owner !== null && !eqBytes(r.owner, owner)) continue;
    if (reqSt >= 0 && r.st !== reqSt) continue;
    out.push(dec.decode(r.name));
  }
  return out;
}
function ownedSetSorted(f: Fold, id: Bytes): string[] {
  const rows: Bytes[] = [];
  for (const r of (f.names as Map<string, any>).values()) {
    if (eqBytes(r.owner, id)) rows.push(r.name);
  }
  rows.sort(cmpBytes);
  return rows.map((n) => dec.decode(n));
}
function rowOf(f: Fold, name: string): any {
  for (const r of (f.names as Map<string, any>).values()) if (dec.decode(r.name) === name) return r;
  return undefined;
}
function idxOf(id: Bytes): number {
  for (let k = 0; k < N_IDS; k++) if (eqBytes(B.genId(k), id)) return k;
  return 0;
}
function lastMut(f: Fold, id: Bytes): bigint {
  const m = (f.muts as Map<string, any>).get(hex(id));
  return m ? m.height : -1n; // -1 == "never" sentinel
}

function oneIn(i: number, ...carriers: FoldCarrier[]): FoldTx {
  return B.tx([B.input(B.genId(i), B.genType(i), true)], carriers);
}

// ─── the rich generator (ports java Gen.buildTx) — exercises EVERY market path ─────────────────
function buildTx(r: SplitMix64, f: Fold, height: bigint, mtp: bigint, rate: bigint, ready: Pending[], saltCtr: bigint): FoldTx {
  let x = r.boundedN(W_SUM), op = 0;
  for (; op < WEIGHTS.length; op++) { if (x < WEIGHTS[op]) break; x -= WEIGHTS[op]; }
  const i = r.boundedN(N_IDS);
  const id = B.genId(i);
  const days = 1n + r.bounded(60);
  const rate28 = rate / 28n;
  const leaseVal = rate28 * days; // T == days

  switch (op) {
    case 0: { // COMMIT
      const j = r.boundedN(NAME_POOL);
      const name = nameOf(j), salt = saltOf(saltCtr);
      ready.push({ idIdx: i, name, salt, commitHeight: height, commitTime: mtp });
      return oneIn(i, B.commit(B.commitmentOf(salt, name, id)));
    }
    case 1: { // CLAIM a ready commit (≥1 deep, live, not already present)
      for (let k = 0; k < ready.length; k++) {
        const p = ready[k];
        if (p.commitHeight < height && mtp <= p.commitTime + COMMIT_EXPIRY && rowOf(f, p.name) === undefined) {
          ready.splice(k, 1);
          return oneIn(p.idIdx, B.claim(p.salt, p.name, leaseVal));
        }
      }
      break;
    }
    case 2: { // RENEW all (owner with names); ~1/8 AS-attributed
      if (namesWhere(f, id, -1).length > 0) {
        if (r.boundedN(8) === 0) {
          const other = r.boundedN(N_IDS);
          const idx = r.boundedN(4) === 0 ? (2 + r.boundedN(8)) : 1;
          return B.tx(
            [B.input(B.genId(other), B.genType(other), true), B.input(id, B.genType(i), true)],
            [B.asMarker(idx, 0), B.renewAll(leaseVal, 1)],
          );
        }
        return oneIn(i, B.renewAll(leaseVal));
      }
      break;
    }
    case 3: { // TRANSFER all to a random id
      if (namesWhere(f, id, ST.OWNED).length > 0) return oneIn(i, B.transferAll(B.genId(r.boundedN(N_IDS))));
      break;
    }
    case 4: { // SELL an owned name with enough lease tail
      for (const nm of namesWhere(f, id, ST.OWNED)) {
        const row = rowOf(f, nm);
        if (mtp + RESERVE_WINDOW + REORG_BUFFER <= row.leaseExpiry) {
          const price = 3n + r.bounded(100000);
          return oneIn(i, B.sell(price, 0n, nm)); // window 0 → defaults to RESERVE_WINDOW
        }
      }
      break;
    }
    case 5: { // RESERVE a listed name (buyer != seller carrier value ≥ burn; pay-leg output)
      const listed = namesWhere(f, null, ST.LISTED);
      if (listed.length > 0) {
        const nm = listed[r.boundedN(listed.length)];
        const row = rowOf(f, nm);
        const burn = depositLeg(row.price, RESERVE_BURN_BPS), payL = depositLeg(row.price, RESERVE_PAY_BPS);
        const buyer = r.boundedN(N_IDS);
        const carriers = [B.reserve(nm, burn)];
        const outs: FoldOutput[] = [B.output(row.sellerType, row.seller, payL)];
        return B.tx([B.input(B.genId(buyer), B.genType(buyer), true)], carriers, outs);
      }
      break;
    }
    case 6: { // SETTLE a reserved name (by its reserver)
      const res = namesWhere(f, null, ST.RESERVED);
      if (res.length > 0) {
        const nm = res[r.boundedN(res.length)];
        const row = rowOf(f, nm);
        const rem = row.price - row.burnLeg - row.payLeg;
        const buyer = idxOf(row.buyer);
        const outs: FoldOutput[] = [B.output(row.sellerType, row.seller, rem)];
        return B.tx([B.input(B.genId(buyer), B.genType(buyer), true)], [B.settle(nm)], outs);
      }
      break;
    }
    case 7: { // RELEASE owned names via a full bitmap
      const set = ownedSetSorted(f, id);
      if (set.length > 0) {
        const flags = new Uint8Array((set.length + 7) >> 3).fill(0xff);
        const lm = lastMut(f, id);
        const anchor = lm === -1n ? height : (lm > height - 1n ? lm : height - 1n);
        if (anchor <= height) return oneIn(i, B.release(anchor, flags.length ? flags : new Uint8Array([1])));
      }
      break;
    }
    case 8: { // SELL_TO
      for (const nm of namesWhere(f, id, ST.OWNED)) {
        const row = rowOf(f, nm);
        if (mtp + DIRECT_WINDOW + REORG_BUFFER <= row.leaseExpiry) {
          const price = 1n + r.bounded(100000);
          const buyer = B.genId(r.boundedN(N_IDS));
          return oneIn(i, B.sellTo(price, buyer, nm));
        }
      }
      break;
    }
    case 9: { // PAY an offered name (by its named buyer)
      const off = namesWhere(f, null, ST.OFFERED);
      if (off.length > 0) {
        const nm = off[r.boundedN(off.length)];
        const row = rowOf(f, nm);
        const buyer = idxOf(row.buyer);
        const outs: FoldOutput[] = [B.output(row.sellerType, row.seller, row.price)];
        return B.tx([B.input(B.genId(buyer), B.genType(buyer), true)], [B.pay(nm)], outs);
      }
      break;
    }
    case 10: { // TRADE two owned names between two ids
      const myOwned = namesWhere(f, id, ST.OWNED);
      const i2 = (i + 1 + r.boundedN(N_IDS - 1)) % N_IDS;
      const id2 = B.genId(i2);
      const theirs = namesWhere(f, id2, ST.OWNED);
      if (myOwned.length > 0 && theirs.length > 0) {
        const a1 = myOwned[0], b1 = theirs[0];
        if (a1 !== b1) {
          const ins: FoldInput[] = [B.input(id, B.genType(i), true), B.input(id2, B.genType(i2), true)];
          return B.tx(ins, [B.trade(0, 1, a1, b1)]);
        }
      }
      break;
    }
  }
  // COMMIT fallback (always valid): inert-safe default when the chosen path has no material.
  const j = r.boundedN(NAME_POOL);
  const salt = saltOf(saltCtr);
  const name = nameOf(j);
  ready.push({ idIdx: i, name, salt, commitHeight: height, commitTime: mtp });
  return oneIn(i, B.commit(B.commitmentOf(salt, name, id)));
}

// record the full chain (the shared chain that properties/reorg/meta/reorgfuzz re-fold).
function recordChain(seed: bigint, count: number): RecBlock[] {
  const r = new SplitMix64(seed);
  const f = new Fold(0n);
  const blocks: RecBlock[] = [];
  const tsList: bigint[] = [];
  const ready: Pending[] = [];
  let ts = BASE_TS, saltCtr = 1n;
  let height = 0, txCount = 0;
  while (txCount < count) {
    ts += BigInt(300 + r.boundedN(600));
    tsList.push(ts);
    const rate = 28n * (1n + r.bounded(4));
    const mtp = computeMtp(tsList, height);
    const nTxs = 1 + r.boundedN(8);
    const txs: RecTx[] = [];
    f.beginBlock(BigInt(height), mtp, rate);
    for (let ti = 0; ti < nTxs && txCount < count; ti++) {
      const tx = buildTx(r, f, BigInt(height), mtp, rate, ready, saltCtr);
      saltCtr += 4n;
      f.applyTx(tx, ti);
      txs.push({ tx, txIndex: ti });
      txCount++;
    }
    blocks.push({ height: BigInt(height), mtp, rate, txs });
    height++;
  }
  return blocks;
}

// ─── §8 property battery ─────────────────────────────────────────────────────────────────────
export function properties(seed: bigint, count: number): number {
  const blocks = recordChain(seed, count);
  const f = new Fold(0n);
  let violations = 0n;
  const pd: Bytes[] = [];
  for (const b of blocks) {
    applyBlock(f, b);
    violations += checkInvariants(f, b.height, b.mtp);
    fingerprint(pd, f);
  }
  console.log("violations=" + violations);
  console.log("property_digest=" + hex(sha256(concatAll(pd))));
  console.log("state_digest=" + hex(f.digest()));
  return violations !== 0n ? 1 : 0;
}

function checkInvariants(f: Fold, height: bigint, mtp: bigint): bigint {
  let v = 0n;
  for (const r of (f.names as Map<string, any>).values()) {
    // mtp < lease_expiry <= mtp + MAX_LEASE
    if (!(mtp < r.leaseExpiry)) v++;
    if (!(r.leaseExpiry <= mtp + MAX_LEASE)) v++;
    if (r.st === ST.LISTED || r.st === ST.OFFERED || r.st === ST.RESERVED) {
      if (!(r.offerExpiry + REORG_BUFFER <= r.leaseExpiry)) v++;
    }
    if (r.st === ST.LISTED || r.st === ST.RESERVED) {
      if (r.price < SELL_PRICE_FLOOR) v++;
    }
    if (r.st === ST.RESERVED) {
      if (!(r.reserveExpiry <= r.offerExpiry)) v++;
      if (r.price < r.burnLeg + r.payLeg) v++;
      if (r.burnLeg !== depositLeg(r.price, RESERVE_BURN_BPS)) v++;
      if (r.payLeg !== depositLeg(r.price, RESERVE_PAY_BPS)) v++;
      if (r.price - r.burnLeg - r.payLeg < DUST_FLOOR) v++;
    }
  }
  for (const m of (f.muts as Map<string, any>).values()) if (m.height > height) v++; // mut height ≤ cur height
  return v;
}

function fingerprint(pd: Bytes[], f: Fold): void {
  let nOwned = 0, nListed = 0, nOffered = 0, nReserved = 0;
  let sumLease = 0n, sumPrice = 0n, sumLegs = 0n;
  for (const r of (f.names as Map<string, any>).values()) {
    if (r.st === ST.OWNED) nOwned++;
    else if (r.st === ST.LISTED) nListed++;
    else if (r.st === ST.OFFERED) nOffered++;
    else if (r.st === ST.RESERVED) nReserved++;
    sumLease += r.leaseExpiry;
    if (r.st === ST.LISTED || r.st === ST.RESERVED) sumPrice += r.price;
    if (r.st === ST.RESERVED) sumLegs += r.burnLeg + r.payLeg;
  }
  pd.push(u32le(f.names.size), u32le(nOwned), u32le(nListed), u32le(nOffered), u32le(nReserved));
  pd.push(u32le(f.commits.length), u32le(f.muts.size));
  pd.push(i128le(sumLease), i128le(sumPrice), i128le(sumLegs));
}

// ─── §11 meta: an action the protocol IGNORES is provably inert ────────────────────────────────
export function meta(seed: bigint, count: number): number {
  const blocks = recordChain(seed, Math.min(count, 20000));
  const f = new Fold(0n);
  let failures = 0;
  for (const b of blocks) {
    applyBlock(f, b);
    const before = hex(f.digest());
    // apply ONE inert tx against the just-folded block context (cur* set by beginBlock above)
    f.applyTx(inertTx(), 0);
    if (hex(f.digest()) !== before) failures++;
  }
  console.log("failures=" + failures);
  console.log("state_digest=" + hex(f.digest()));
  return failures !== 0 ? 1 : 0;
}

function inertTx(): FoldTx {
  // Mirrors C build_inert_tx: truncated CLAIM, unknown opcode 0x20, bare UTF-8, overlay 0xD6.
  // All decode to IGNORE — none mutate the digested state.
  const badClaim = B.rawCarrier(new Uint8Array([0xff, 0x50, 0x4e, OP.CLAIM, 0, 0, 0, 0]), 0n, 0);
  const unk = B.rawCarrier(new Uint8Array([0xff, 0x50, 0x4e, 0x20]), 0n, 1);
  const utf8 = B.rawCarrier(new TextEncoder().encode("hello"), 1n, 2);
  const overlay = B.rawCarrier(new Uint8Array([0xff, 0x50, 0x4e, 0xd6, 0x00]), 0n, 3);
  return oneIn(0, badClaim, unk, utf8, overlay);
}

// ─── §10 reorg confluence: replay / resume / clear-rebuild / fork-and-return ───────────────────
export function reorg(seed: bigint, count: number): number {
  const blocks = recordChain(seed, Math.min(count, 20000));
  const n = blocks.length, J = n >> 1;
  let failures = 0;

  const dFull = foldDigest(blocks, 0, n);
  // 1. replay
  if (foldDigest(blocks, 0, n) !== dFull) failures++;
  // 2. resume: fold [0,J) → S_fork, continue [J,n) == D_full
  const s = new Fold(0n);
  for (let i = 0; i < J; i++) applyBlock(s, blocks[i]);
  const sFork = hex(s.digest());
  for (let i = J; i < n; i++) applyBlock(s, blocks[i]);
  if (hex(s.digest()) !== dFull) failures++;
  // 3. clear-rebuild: clear(), re-fold [0,J) == S_fork
  s.clear();
  for (let i = 0; i < J; i++) applyBlock(s, blocks[i]);
  if (hex(s.digest()) !== sFork) failures++;
  // 4. fork-and-return: divergent branch = canonical tail with each block's txs reversed
  const sa = new Fold(0n);
  for (let i = 0; i < J; i++) applyBlock(sa, blocks[i]);
  for (let i = J; i < n; i++) applyBlock(sa, reverseTxs(blocks[i]));
  const dAlt = hex(sa.digest());
  sa.clear();
  for (let i = 0; i < J; i++) applyBlock(sa, blocks[i]);
  if (hex(sa.digest()) !== sFork) failures++;
  for (let i = J; i < n; i++) applyBlock(sa, blocks[i]);
  if (hex(sa.digest()) !== dFull) failures++;

  const rd = concat(fromHex(dFull), fromHex(sFork), fromHex(dAlt));
  console.log(`blocks=${n} fork=${J} checks=6 failures=${failures}`);
  console.log("D_full=" + dFull);
  console.log("S_fork=" + sFork);
  console.log("D_alt=" + dAlt);
  console.log("reorg_digest=" + hex(sha256(rd)));
  return failures !== 0 ? 1 : 0;
}

function reverseTxs(b: RecBlock): RecBlock {
  // reverse the tx ORDER but keep each tx's own recorded txIndex tag (Java clones the array, the
  // Model.Tx keeps its txIndex). Folding replays them in the new order with their original indices.
  const r = b.txs.slice().reverse();
  return { height: b.height, mtp: b.mtp, rate: b.rate, txs: r };
}

// ─── §9 differential fuzz: random + grammar-perturbed payloads through decode → fold ───────────
export function fuzz(seed: bigint, count: number): number {
  const r = new SplitMix64(seed);
  const f = new Fold(0n);
  const inp: Bytes[] = [];
  let ts = BASE_TS, height = 0n, txCount = 0, crashes = 0;
  while (txCount < count) {
    ts += BigInt(300 + r.boundedN(600));
    const rate = 28n * (1n + r.bounded(4));
    const nTxs = 1 + r.boundedN(8);
    const txs: RecTx[] = [];
    for (let ti = 0; ti < nTxs && txCount < count; ti++) {
      const nIn = 1 + r.boundedN(4);
      const ins: FoldInput[] = [];
      for (let k = 0; k < nIn; k++)
        ins.push(B.input(B.genId(r.boundedN(N_IDS)), r.boundedN(4) === 3 ? 1 : 0, r.boundedN(8) !== 0));
      const nOut = 1 + r.boundedN(4);
      const carriers: FoldCarrier[] = [];
      const outs: FoldOutput[] = [];
      for (let o = 0; o < nOut; o++) {
        let val: bigint;
        switch (r.boundedN(3)) {
          case 0: val = 0n; break;
          case 1: val = (1n << 64n) - r.bounded(1000); break;
          default: val = 1n + r.bounded(1000); break;
        }
        if (r.boundedN(4) === 0) {
          outs.push(B.output(r.boundedN(2), B.genId(r.boundedN(N_IDS)), val));
          inp.push(u8(o), u64le(val));
        } else {
          const payload = fuzzPayload(r);
          carriers.push(B.rawCarrier(payload, val, o));
          inp.push(u8(o), u64le(val), u32le(payload.length), payload);
        }
      }
      txs.push({ tx: B.tx(ins, carriers, outs), txIndex: ti });
      txCount++;
    }
    try {
      f.beginBlock(height, ts, rate);
      for (const { tx, txIndex } of txs) f.applyTx(tx, txIndex);
    } catch (_e) {
      crashes++;
    }
    height++;
  }
  console.log("input_digest=" + hex(sha256(concatAll(inp))));
  console.log("state_digest=" + hex(f.digest()));
  console.log("parser_crashes=" + crashes);
  return crashes !== 0 ? 1 : 0;
}

function fuzzPayload(r: SplitMix64): Bytes {
  if (r.boundedN(10) < 4) { // dumb-random bytes
    const len = r.boundedN(81);
    const p = new Uint8Array(len);
    for (let i = 0; i < len; i++) p[i] = r.boundedN(256);
    if (r.boundedN(3) === 0 && len >= 4) { p[0] = 0xff; p[1] = 0x50; p[2] = 0x4e; p[3] = 1 + r.boundedN(15); }
    return p;
  }
  // grammar-aware: build a prefixed action-shaped payload, then maybe corrupt
  let payload = grammarPayload(r);
  switch (r.boundedN(6)) {
    case 2: if (payload.length > 0) payload = payload.subarray(0, payload.length - 1).slice(); break; // truncate
    case 3: if (payload.length > 0) { const cp = payload.slice(); cp[r.boundedN(cp.length)] ^= (1 << r.boundedN(8)); payload = cp; } break; // flip
    case 4: payload = concat(payload, new Uint8Array([r.boundedN(256)])); break; // extend
    default: break;
  }
  return payload;
}

function grammarPayload(r: SplitMix64): Bytes {
  const op = 1 + r.boundedN(15); // 0x01..0x0F
  let bodyLen: number;
  switch (op) {
    case OP.COMMIT: bodyLen = 32; break;
    case OP.CLAIM: bodyLen = 33 + r.boundedN(20); break;
    case OP.RENEW_NAME: case OP.RELEASE_NAME: bodyLen = 1 + r.boundedN(20); break;
    case OP.TRANSFER_NAME: bodyLen = 21 + r.boundedN(31); break;
    case OP.RENEW: bodyLen = [0, 5, 6 + r.boundedN(71)][r.boundedN(3)]; break;
    case OP.TRANSFER: bodyLen = r.boundedN(2) === 0 ? 20 : 26 + r.boundedN(51); break;
    case OP.SELL: bodyLen = 13 + r.boundedN(20); break;
    case OP.RESERVE: case OP.SETTLE: case OP.PAY: bodyLen = 1 + r.boundedN(20); break;
    case OP.RELEASE: bodyLen = 6 + r.boundedN(71); break;
    case OP.SELL_TO: bodyLen = 29 + r.boundedN(20); break;
    case OP.AS: bodyLen = 1; break;
    case OP.TRADE: bodyLen = 5 + r.boundedN(30); break;
    default: bodyLen = r.boundedN(77); break;
  }
  const p = new Uint8Array(4 + bodyLen);
  p[0] = 0xff; p[1] = 0x50; p[2] = 0x4e; p[3] = op;
  for (let i = 4; i < p.length; i++) p[i] = r.boundedN(256);
  return p;
}

// ─── §11 reorgfuzz: K=64 fork/divergence trials + clear-rebuild + canonical-replay purity ──────
export function reorgfuzz(seed: bigint, count: number): number {
  const blocks = recordChain(seed, Math.min(count, 20000));
  const n = blocks.length;
  const dFull = foldDigest(blocks, 0, n);
  const tr = new SplitMix64(seed ^ 0x5245464b5a475f31n);
  const altStream: Bytes[] = [];
  let failures = 0;
  for (let t = 0; t < 64; t++) {
    const J = Number(tr.bounded(n + 1));
    const kind = tr.boundedN(3);
    // divergent branch → D_alt
    const sd = new Fold(0n);
    for (let i = 0; i < J; i++) applyBlock(sd, blocks[i]);
    for (const b of divergentTail(blocks, J, n, kind)) applyBlock(sd, b);
    altStream.push(fromHex(hex(sd.digest())));
    // assert: clear-rebuild to J reproduces fold[0,J); canonical replay reproduces D_full
    const forkJ = foldDigest(blocks, 0, J);
    const sc = new Fold(0n);
    for (let i = 0; i < J; i++) applyBlock(sc, blocks[i]);
    if (hex(sc.digest()) !== forkJ) failures++;
    for (let i = J; i < n; i++) applyBlock(sc, blocks[i]);
    if (hex(sc.digest()) !== dFull) failures++;
  }
  altStream.push(fromHex(dFull));
  console.log(`blocks=${n} trials=64 failures=${failures}`);
  console.log("reorgfuzz_digest=" + hex(sha256(concatAll(altStream))));
  return failures !== 0 ? 1 : 0;
}

function divergentTail(blocks: RecBlock[], J: number, n: number, kind: number): RecBlock[] {
  const out: RecBlock[] = [];
  if (kind === 0) { for (let i = J; i < n; i++) out.push(reverseTxs(blocks[i])); }       // reversed tail
  else if (kind === 1) { for (let i = J; i < n; i += 2) out.push(blocks[i]); }            // every other block
  else { for (let i = J; i < n; i++) { out.push(blocks[i]); out.push(blocks[i]); } }       // tail folded twice
  return out;
}
