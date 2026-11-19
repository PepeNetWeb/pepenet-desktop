// §13.2 ECMH — the pinned, portable `sm ecmh` vector set.
//
// Clean-room TS port of impls/c/src/ecmh.c `ecmh_cmd()`. Runs the exact vector script against THIS
// impl's secp256k1 ECMH primitive and must print BYTE-IDENTICAL output to the C reference: a
// hash-to-curve KAT, accumulator algebra (identity / tagged multiset sum / commutativity / inverse
// round-trip), and a single cross-language `combined` digest. See SPEC-conformance.md §13.2.
//
// Names-only: 3 table tags (name/commit/mut). TAG_VOTE was removed with votes from consensus.
import type { Bytes } from "./bytes.ts";
import { hex, concat, u8 } from "./bytes.ts";
import { sha256 } from "./sha256.ts";
import { ecmhIdentity, ecmhHash, ecmhNegate, ecmhAdd } from "./secp256k1.ts";

// domain tags — second-preimage separation between tables (mirrors ecmh.c enum).
const TAG_NAME = 0x01, TAG_COMMIT = 0x02, TAG_MUT = 0x04;
const ECMH_REC_TAG = Uint8Array.of(0x45, 0x43, 0x4d, 0x48, 0x76, 0x31); // "ECMHv1"

// per-record H2C preimage = "ECMHv1" ‖ tag ‖ body.
function recPoint(tag: number, body: Bytes): Bytes {
  const pre = concat(ECMH_REC_TAG, u8(tag), body);
  return ecmhHash(pre).pt;
}

export function cmdEcmh(): number {
  const feeds: Bytes[] = [];
  const FEED = (b: Bytes): void => { feeds.push(b); };
  const out: string[] = [];

  // version self-doc
  out.push("ecmh ECMHv1"); FEED(ECMH_REC_TAG);

  // 1. hash-to-curve KAT — fixed preimages → (ctr, compressed even-Y point).
  const enc = new TextEncoder();
  const h2c: { label: string; pre: Bytes }[] = [
    { label: "empty", pre: new Uint8Array(0) },
    { label: "a",     pre: enc.encode("a") },
    { label: "pepe",  pre: enc.encode("pepenet") },
    { label: "doge",  pre: enc.encode("doge") },
    { label: "ff32",  pre: new Uint8Array(32).fill(0xff) },
    { label: "z32",   pre: new Uint8Array(32) },
  ];
  for (const e of h2c) {
    const { pt, ctr } = ecmhHash(e.pre);
    out.push(`h2c ${e.label} ctr=${ctr} pt=${hex(pt)}`);
    FEED(u8(ctr & 0xff)); FEED(pt);
  }

  // 2. identity (∞) serialization
  const id = ecmhIdentity();
  out.push(`identity ${hex(id)}`); FEED(id);

  // 3. tagged multiset sum — a fixed set of (tag ‖ body) records, summed two ways.
  const recs: { tag: number; body: Bytes }[] = [
    { tag: TAG_NAME,   body: enc.encode("\x03foo") },
    { tag: TAG_NAME,   body: enc.encode("\x03bar") },
    { tag: TAG_COMMIT, body: enc.encode("commitment-blob-32-bytes-xxxxxx") }, // 31 bytes
    { tag: TAG_MUT,    body: enc.encode("owner-mutation") },                  // 14 bytes
  ];
  let fwd = ecmhIdentity(), rev = ecmhIdentity();
  for (let i = 0; i < recs.length; i++) fwd = ecmhAdd(fwd, recPoint(recs[i].tag, recs[i].body));
  for (let i = recs.length - 1; i >= 0; i--) rev = ecmhAdd(rev, recPoint(recs[i].tag, recs[i].body));
  const commut = hex(fwd) === hex(rev) ? 1 : 0;
  out.push(`sum ${hex(fwd)}`);
  out.push(`commutative ${commut}`);
  FEED(fwd); FEED(u8(commut));

  // 4. inverse — remove the first record from the sum, re-add, must round-trip.
  {
    const pt0 = recPoint(recs[0].tag, recs[0].body);
    let acc = Uint8Array.from(fwd);
    acc = ecmhAdd(acc, ecmhNegate(pt0)); // remove rec[0]
    acc = ecmhAdd(acc, pt0);             // re-add rec[0]
    const roundtrip = hex(acc) === hex(fwd) ? 1 : 0;
    out.push(`inverse_roundtrip ${roundtrip}`);
    FEED(u8(roundtrip));
  }

  const combined = sha256(concat(...feeds));
  out.push(`combined ${hex(combined)}`);

  console.log(out.join("\n"));
  return 0;
}
