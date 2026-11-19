// Directed conformance vectors (cross-language adversarial scenarios) — the TS port of
// impls/c `scenario`. Each builds a deterministic, named construction and emits
// `name <digest>` (canonical §4 state digest) or `name <u64>`; the rolling `combined`
// hash is the single-line cross-language check. These pin the spec's named edge cases
// (§5) with auditable outcomes, and cover the rare branches the random soak almost never
// hits (deep displacement, i128 accumulation past 2^64, the fee oracle).
import type { Bytes } from "./bytes.ts";
import { concat, hex, u64le } from "./bytes.ts";
import { sha256 } from "./sha256.ts";
import { Fold } from "./fold.ts";
import type { OracleBlock } from "./oracle.ts";
import { oracleRate, computeMTP } from "./oracle.ts";
import { DOGE_SUBSIDY } from "./constants.ts";
import * as B from "./builders.ts";

// rate = 28 makes the burn equal the number of days (see impls/c RATE_DAYS).
const RATE = 28n;
const U64_MAX = (1n << 64n) - 1n; // used by deposit_2pow64

const salt = (b: number): Bytes => new Uint8Array(32).fill(b);

export function cmdScenario(): number {
  const feeds: Bytes[] = [];
  const A = B.genId(0xaa), Bb = B.genId(0xbb), Cc = B.genId(0xcc);

  const emitState = (name: string, f: Fold): void => {
    const d = f.digest();
    console.log(`${name} ${hex(d)}`);
    feeds.push(d);
  };
  const emitU64 = (name: string, v: bigint): void => {
    console.log(`${name} ${v}`);
    feeds.push(u64le(v));
  };
  // Commit `name`(author=tag, salt) at block `ch`, then CLAIM `days` at block `kh`.
  const commitThenClaim = (f: Fold, tag: number, nm: string, sb: number, days: bigint,
                           cmtp: bigint, ch: bigint, kmtp: bigint, kh: bigint): void => {
    const id = B.genId(tag);
    f.beginBlock(ch, cmtp, RATE);
    f.applyTx(B.tx([B.input(id)], [B.commit(B.commitmentOf(salt(sb), nm, id))]), 0);
    f.beginBlock(kh, kmtp, RATE);
    f.applyTx(B.tx([B.input(id)], [B.claim(salt(sb), nm, days)]), 0);
  };
  // Mint `name` to `tag` with `days` lease, leaving the fold at the claim's block.
  const minted = (tag: number, nm: string, days: bigint, claimMtp: bigint): Fold => {
    const f = new Fold(0n);
    commitThenClaim(f, tag, nm, 0x33, days, claimMtp - 100n, 10n, claimMtp, 11n);
    return f;
  };
  const twoNames = (): Fold => {
    const f = new Fold(0n);
    f.beginBlock(10n, 1000n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x01), "aaa", A))]), 0);
    f.applyTx(B.tx([B.input(Bb)], [B.commit(B.commitmentOf(salt(0x02), "bbb", Bb))]), 1);
    f.beginBlock(11n, 1500n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x01), "aaa", 30n)]), 0);
    f.applyTx(B.tx([B.input(Bb)], [B.claim(salt(0x02), "bbb", 30n)]), 1);
    return f;
  };

  { const f = new Fold(0n); emitState("01_empty", f); }

  { const f = new Fold(0n); commitThenClaim(f, 0xaa, "bob", 0x11, 10n, 1000n, 10n, 1500n, 11n);
    emitState("02_commit_claim", f); }

  { const f = new Fold(0n); f.beginBlock(11n, 1500n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x11), "bob", 10n)]), 0);
    emitState("03_naked_claim_drop", f); }

  { const f = new Fold(0n); f.beginBlock(11n, 1500n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x11), "bob", A), 0),
                                  B.claim(salt(0x11), "bob", 10n, 1)]), 0);
    emitState("04_shallow_commit_drop", f); }

  // priority: lower commit_height (A@10) wins ownership in BOTH claim orderings. The two digests
  // differ — a transiently-displaced mint leaves an incidental mutation-height bump that depends
  // on tx order — but each is cross-language-exact.
  for (let order = 0; order < 2; order++) {
    const f = new Fold(0n);
    f.beginBlock(10n, 1000n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x11), "bob", A))]), 0);
    f.beginBlock(12n, 1100n, RATE);
    f.applyTx(B.tx([B.input(Bb)], [B.commit(B.commitmentOf(salt(0x22), "bob", Bb))]), 0);
    f.beginBlock(20n, 1200n, RATE);
    const kA = B.tx([B.input(A)], [B.claim(salt(0x11), "bob", 10n)]);
    const kB = B.tx([B.input(Bb)], [B.claim(salt(0x22), "bob", 10n)]);
    if (order === 0) { f.applyTx(kB, 0); f.applyTx(kA, 1); } else { f.applyTx(kA, 0); f.applyTx(kB, 1); }
    emitState(order === 0 ? "05_priority_b_first" : "06_priority_a_first", f);
  }

  // commitment-copy: B reposts A's commitment bytes, then B claims → drop (author-bound); A claims → owns.
  { const f = new Fold(0n); const cm = B.commitmentOf(salt(0x33), "bob", A); // A-bound commitment
    f.beginBlock(10n, 1000n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.commit(cm)]), 0);
    f.applyTx(B.tx([B.input(Bb)], [B.commit(cm)]), 1);                       // B copies the commitment
    f.beginBlock(11n, 1100n, RATE);
    f.applyTx(B.tx([B.input(Bb)], [B.claim(salt(0x33), "bob", 10n)]), 0);    // B can't satisfy → drop
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x33), "bob", 10n)]), 1);     // A wins
    emitState("07_commitment_copy", f); }

  { const f = minted(0xaa, "bob", 10n, 1500n);  // expiry 865500
    f.beginBlock(12n, 865500n, RATE);           // MTP == expiry → lapse (exclusive)
    emitState("08_lease_lapse", f); }

  { const f = minted(0xaa, "bob", 10n, 1500n); f.beginBlock(12n, 1600n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.renewAll(5n)]), 0);
    emitState("09_renew_stack", f); }

  // water-fill even split: 3 names, renew-all buys 30 name-days → +10 each.
  { const f = new Fold(0n); const nm = ["a", "b", "c"];
    f.beginBlock(10n, 1000n, RATE);
    for (let i = 0; i < 3; i++) f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x40 + i), nm[i], A))]), i);
    f.beginBlock(11n, 1100n, RATE);
    for (let i = 0; i < 3; i++) f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x40 + i), nm[i], 1n)]), i);
    f.beginBlock(12n, 1200n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.renewAll(30n)]), 0);
    emitState("10_waterfill_even", f); }

  { const f = new Fold(0n); commitThenClaim(f, 0xaa, "bob", 0x11, 100000n, 1000n, 10n, 1500n, 11n); // huge → caps at 365d
    emitState("11_waterfill_maxlease", f); }

  { const f = minted(0xaa, "bob", 10n, 1500n); f.beginBlock(12n, 1600n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.transferAll(Bb)]), 0);
    emitState("12_transfer_gift", f); }

  { const f = minted(0xaa, "bob", 10n, 1500n); f.beginBlock(12n, 1600n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.release(11n, Uint8Array.of(0x01))]), 0);
    emitState("13_release", f); }

  { const f = minted(0xaa, "w", 300n, 1500n);
    f.beginBlock(12n, 1600n, RATE); f.applyTx(B.tx([B.input(A)], [B.sell(20000n, 50000n, "w")]), 0);
    f.beginBlock(13n, 1700n, RATE); f.applyTx(B.tx([B.input(Bb)], [B.reserve("w", 100n)], [B.output(0, A, 100n)]), 0);
    f.beginBlock(14n, 1800n, RATE); f.applyTx(B.tx([B.input(Bb)], [B.settle("w")], [B.output(0, A, 19800n)]), 0);
    emitState("14_market_full", f); }

  { const f = minted(0xaa, "w", 300n, 1500n); f.beginBlock(12n, 1600n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.sell(20000n, 50000n, "w")]), 0);
    f.beginBlock(13n, 1700n, RATE); f.applyTx(B.tx([B.input(Bb)], [B.reserve("w", 99n)], [B.output(0, A, 100n)]), 0);
    emitState("15_reserve_burn_short", f); }

  { const f = minted(0xaa, "w", 300n, 1500n); f.beginBlock(12n, 1600n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.sell(20000n, 50000n, "w")]), 0);
    f.beginBlock(13n, 1700n, RATE);
    f.applyTx(B.tx([B.input(Bb)], [B.reserve("w", 100n)], [B.output(0, A, 60n), B.output(0, A, 60n)]), 0);
    emitState("16_reserve_pay_summed", f); }

  // reserve near offer end → reserve_expiry clamps to offer_expiry.
  { const f = minted(0xaa, "w", 300n, 1500n); f.beginBlock(12n, 1600n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.sell(20000n, 0n, "w")]), 0);   // window default 18000 → offer_expiry 19600
    f.beginBlock(13n, 5000n, RATE);
    f.applyTx(B.tx([B.input(Bb)], [B.reserve("w", 100n)], [B.output(0, A, 100n)]), 0); // 5000+18000>19600 → clamp
    emitState("17_reserve_clamp", f); }

  { const f = minted(0xaa, "w", 300n, 1500n); f.beginBlock(12n, 1600n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.sell(2n, 0n, "w")]), 0);       // below 3·DUST
    emitState("18_sell_price_floor", f); }

  { const f = minted(0xaa, "w", 1n, 1500n); f.beginBlock(12n, 65000n, RATE);  // short tail
    f.applyTx(B.tx([B.input(A)], [B.sell(20000n, 0n, "w")]), 0);
    emitState("19_sell_window_overflow", f); }

  { const f = minted(0xaa, "w", 300n, 1500n); f.beginBlock(12n, 1600n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.sellTo(5000n, Bb, "w")]), 0);
    f.beginBlock(13n, 1700n, RATE);
    f.applyTx(B.tx([B.input(Cc)], [B.pay("w")], [B.output(0, A, 5000n)]), 0);  // stranger → drop
    f.applyTx(B.tx([B.input(Bb)], [B.pay("w")], [B.output(0, A, 5000n)]), 1);  // buyer → owns
    emitState("20_directed_pay", f); }

  // 2^64-1 price: the 128-bit deposit legs must be exact (a 64-bit impl wraps).
  { const f = minted(0xaa, "w", 300n, 1500n); f.beginBlock(12n, 1600n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.sell(U64_MAX, 50000n, "w")]), 0);
    const leg = (U64_MAX * 50n) / 10000n;
    f.beginBlock(13n, 1700n, RATE);
    f.applyTx(B.tx([B.input(Bb)], [B.reserve("w", leg)], [B.output(0, A, leg)]), 0);
    emitState("21_deposit_2pow64", f); }

  // AS attribution: claim attributed to vin[1]=B (matches B's commit).
  { const f = new Fold(0n); f.beginBlock(10n, 1000n, RATE);
    f.applyTx(B.tx([B.input(Bb)], [B.commit(B.commitmentOf(salt(0x55), "bob", Bb))]), 0);
    f.beginBlock(11n, 1500n, RATE);
    f.applyTx(B.tx([B.input(A), B.input(Bb)], [B.asMarker(1, 0), B.claim(salt(0x55), "bob", 10n, 1)]), 0);
    emitState("22_as_attribution", f); }

  { const f = new Fold(0n); f.beginBlock(10n, 1000n, RATE);
    f.applyTx(B.tx([B.input(Bb)], [B.commit(B.commitmentOf(salt(0x55), "bob", Bb))]), 0);
    f.beginBlock(11n, 1500n, RATE);
    f.applyTx(B.tx([B.input(A), B.input(Bb, 0, false)], [B.asMarker(1, 0), B.claim(salt(0x55), "bob", 10n, 1)]), 0);
    emitState("23_as_oob_drop", f); }

  { const f = twoNames(); f.beginBlock(12n, 1600n, RATE);
    f.applyTx(B.tx([B.input(A), B.input(Bb)], [B.trade(0, 1, "aaa", "bbb")]), 0);
    emitState("24_trade_swap", f); }

  { const f = twoNames(); f.beginBlock(12n, 1600n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.transferAll(Cc)]), 0);                     // aaa→C before the trade
    f.applyTx(B.tx([B.input(A), B.input(Bb)], [B.trade(0, 1, "aaa", "bbb")]), 1); // anti-rug → drop
    emitState("25_trade_rug_before", f); }

  // fee oracle (§3.4): signed under-claim clamp + participant filter + MIN_FEE_SAMPLE
  // degrade + lower-median + REF_SIZE scale + clamp. 4 participants < MIN_FEE_SAMPLE
  // ⇒ this small window now degrades to DUST_FLOOR (the big-window vectors are 49–51).
  { const cb = [1_000_000_200_000n, 1_000_000_400_000n, 999_999_999_950n, 1_000_001_000_000n, 1_000_000_600_000n]; // 3rd under-claims
    const win: OracleBlock[] = cb.map((c) => ({ coinbaseTotal: c, blockBytes: 1000n }));
    emitU64("29_oracle_rate", oracleRate(win)); }                    // |P|=4 < 1000 → DUST_FLOOR = 1
  { const win: OracleBlock[] = [0n, 0n, 0n].map((c) => ({ coinbaseTotal: c, blockBytes: 1000n })); // all under-claim → fees 0 → rate floor
    emitU64("30_oracle_floor", oracleRate(win)); }
  { const ts = [100n, 50n, 200n, 30n, 150n, 80n, 220n, 10n, 175n, 60n, 190n];
    emitU64("31_mtp_median", computeMTP(ts, 11)); }                  // median of 11

  // ── water-fill rare branches ──
  // 32: T < count — burn buys fewer name-days than names; the first T names
  // (ascending-lex) get +1 day, the rest none (§3.5 floor).
  { const f = new Fold(0n); const nm = ["a", "b", "c"];
    f.beginBlock(10n, 1000n, RATE);
    for (let i = 0; i < 3; i++) f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x50 + i), nm[i], A))]), i);
    f.beginBlock(11n, 1100n, RATE);
    for (let i = 0; i < 3; i++) f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x50 + i), nm[i], 1n)]), i);
    f.beginBlock(12n, 1200n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.renewAll(2n)]), 0);              // T=2 over 3 → a,b +1d, c none
    emitState("32_waterfill_floor", f); }

  // 33: every targeted name hits MAX_LEASE with T still remaining → surplus forfeited.
  { const f = new Fold(0n); const nm = ["a", "b"];
    f.beginBlock(10n, 1000n, RATE);
    for (let i = 0; i < 2; i++) f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x60 + i), nm[i], A))]), i);
    f.beginBlock(11n, 1100n, RATE);
    for (let i = 0; i < 2; i++) f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x60 + i), nm[i], 360n)]), i);  // ~360d each
    f.beginBlock(12n, 1100n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.renewAll(100000n)]), 0);         // huge → both cap @MAX_LEASE, forfeit
    emitState("33_waterfill_allcap_forfeit", f); }

  // ── reorg edge cases as deterministic vectors ──
  // 34: a same-block lapse-and-reclaim. (a) bob lapses at MTP==expiry, B reclaims → B owns.
  //     (b) the reorg restores A's earlier RENEW, so bob never lapses and B's reclaim drops.
  { const f = minted(0xaa, "bob", 10n, 1500n);                       // expiry 865500
    f.beginBlock(12n, 860000n, RATE);
    f.applyTx(B.tx([B.input(Bb)], [B.commit(B.commitmentOf(salt(0x44), "bob", Bb))]), 0);
    f.beginBlock(13n, 865500n, RATE);
    f.applyTx(B.tx([B.input(Bb)], [B.claim(salt(0x44), "bob", 10n)]), 0);  // lapse then B mints
    emitState("34a_reorg_lapse_reclaim", f); }
  { const f = minted(0xaa, "bob", 10n, 1500n);
    f.beginBlock(12n, 860000n, RATE);
    f.applyTx(B.tx([B.input(Bb)], [B.commit(B.commitmentOf(salt(0x44), "bob", Bb))]), 0);
    f.applyTx(B.tx([B.input(A)], [B.renewAll(10n)]), 1);             // A renews → bob survives past 865500
    f.beginBlock(13n, 865500n, RATE);
    f.applyTx(B.tx([B.input(Bb)], [B.claim(salt(0x44), "bob", 10n)]), 0);  // bob owned → drop
    emitState("34b_reorg_renew_blocks_reclaim", f); }

  // 35: a SETTLE un-confirmed by a reorg. (a) the reserve lapses without a settle →
  //     the listing reverts to the seller; (b) the settle confirms → buyer owns.
  { const f = minted(0xaa, "w", 300n, 1500n);
    f.beginBlock(12n, 1600n, RATE); f.applyTx(B.tx([B.input(A)], [B.sell(20000n, 50000n, "w")]), 0);
    f.beginBlock(13n, 1700n, RATE); f.applyTx(B.tx([B.input(Bb)], [B.reserve("w", 100n)], [B.output(0, A, 100n)]), 0);
    f.beginBlock(14n, 20000n, RATE);                    // MTP past reserve_expiry (19700) → revert to listing
    emitState("35a_settle_dropped_relisted", f); }
  { const f = minted(0xaa, "w", 300n, 1500n);
    f.beginBlock(12n, 1600n, RATE); f.applyTx(B.tx([B.input(A)], [B.sell(20000n, 50000n, "w")]), 0);
    f.beginBlock(13n, 1700n, RATE); f.applyTx(B.tx([B.input(Bb)], [B.reserve("w", 100n)], [B.output(0, A, 100n)]), 0);
    f.beginBlock(14n, 1800n, RATE); f.applyTx(B.tx([B.input(Bb)], [B.settle("w")], [B.output(0, A, 19800n)]), 0);
    emitState("35b_settle_confirmed", f); }

  // 36: an MTP boundary call that flips under a one-tick reorg. lease_expiry is an
  //     EXCLUSIVE bound: MTP == expiry−1 stays owned; MTP == expiry lapses.
  { const f = minted(0xaa, "bob", 10n, 1500n); f.beginBlock(12n, 865499n, RATE); emitState("36a_mtp_below_owned", f); }
  { const f = minted(0xaa, "bob", 10n, 1500n); f.beginBlock(12n, 865500n, RATE); emitState("36b_mtp_at_lapsed", f); }

  // ── pre-block ordering & intra-block market races ──
  // 38: a same-block RENEW-vs-CLAIM race at the exact lapse tie. The pre-block lapse returns
  //     `bob` to the pool BEFORE any tx runs, so A's renew-all renews only `keep` and the
  //     hunter B's CLAIM (commit ≥1 block deep) mints `bob`.
  { const f = new Fold(0n);
    f.beginBlock(10n, 1000n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x33), "bob", A))]), 0);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x34), "keep", A))]), 1);
    f.beginBlock(11n, 1500n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x33), "bob", 10n)]), 0);   // bob expiry 865500
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x34), "keep", 300n)]), 1); // keep long-lived
    f.beginBlock(12n, 860000n, RATE);
    f.applyTx(B.tx([B.input(Bb)], [B.commit(B.commitmentOf(salt(0x44), "bob", Bb))]), 0);  // hunter commits
    f.beginBlock(13n, 865500n, RATE);          // MTP == bob's expiry → bob lapses pre-block
    f.applyTx(B.tx([B.input(A)], [B.renewAll(5n)]), 0);                    // renews `keep` only
    f.applyTx(B.tx([B.input(Bb)], [B.claim(salt(0x44), "bob", 10n)]), 1);  // hunter mints bob
    emitState("38_lapse_renew_vs_claim", f); }

  // 39: a single pre-block tick that crosses reserve_expiry AND offer_expiry at once,
  //     cascading RESERVED→LISTED→OWNED in one pass (§5 type-order reserve→offer→lease).
  { const f = minted(0xaa, "w", 300n, 1500n);                       // lease_expiry = 25,921,500
    f.beginBlock(12n, 1600n, RATE); f.applyTx(B.tx([B.input(A)], [B.sell(20000n, 50000n, "w")]), 0);  // offer_expiry = 51600
    f.beginBlock(13n, 1700n, RATE); f.applyTx(B.tx([B.input(Bb)], [B.reserve("w", 100n)], [B.output(0, A, 100n)]), 0); // reserve_expiry = 19700 < 51600
    f.beginBlock(14n, 51600n, RATE);           // MTP == offer_expiry, > reserve_expiry → both legs fire
    emitState("39_preblock_reserve_offer_collapse", f); }

  // 40: intra-block RESERVE option theft. The first buyer (chain-order) wins the exclusive
  //     option; the second drops (no overwrite), so its later SETTLE fails the buyer-match.
  { const f = minted(0xaa, "w", 300n, 1500n);
    f.beginBlock(12n, 1600n, RATE); f.applyTx(B.tx([B.input(A)], [B.sell(20000n, 50000n, "w")]), 0);
    f.beginBlock(13n, 1700n, RATE);
    f.applyTx(B.tx([B.input(Bb)], [B.reserve("w", 100n)], [B.output(0, A, 100n)]), 0);  // B wins the option
    f.applyTx(B.tx([B.input(Cc)], [B.reserve("w", 100n)], [B.output(0, A, 100n)]), 1);  // C loses (row RESERVED) → drop
    f.applyTx(B.tx([B.input(Cc)], [B.settle("w")], [B.output(0, A, 19800n)]), 2);       // C settles → buyer-mismatch → drop
    emitState("40_reserve_option_theft", f); }

  // 41: value-collision in spendable-output matching. One tx does RESERVE(x)+SETTLE(y),
  //     both paying seller A, with two outputs to A: vout[0]=19800 (settle remainder) and
  //     vout[1]=5 (reserve pay-leg). The consume-once, exact-value, vout-order matcher must
  //     let RESERVE skip the larger vout[0] and take vout[1], then SETTLE take vout[0].
  { const f = new Fold(0n);
    f.beginBlock(10n, 1000n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x71), "x", A))]), 0);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x72), "y", A))]), 1);
    f.beginBlock(11n, 1500n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x71), "x", 300n)]), 0);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x72), "y", 300n)]), 1);
    f.beginBlock(12n, 1600n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.sell(1000n, 50000n, "x")]), 0);   // pay_leg(x) = 5
    f.applyTx(B.tx([B.input(A)], [B.sell(20000n, 50000n, "y")]), 1);  // remainder(y) = 19800
    f.beginBlock(13n, 1700n, RATE);
    f.applyTx(B.tx([B.input(Bb)], [B.reserve("y", 100n)], [B.output(0, A, 100n)]), 0);  // B reserves y
    f.beginBlock(14n, 1800n, RATE);
    f.applyTx(B.tx([B.input(Bb)], [B.reserve("x", 5n, 0), B.settle("y", 1)],
                   [B.output(0, A, 19800n),                            // vout[0] (lower) = settle remainder
                    B.output(0, A, 5n)]), 0);                          // vout[1] (higher) = reserve pay-leg
    emitState("41_vout_value_collision", f); }

  // ── priority tie-break + Tier-4 coverage (audit follow-ups) ──
  // 42: CLAIM priority tie-break is the COMMIT's tx_index (§3.2 tuple), NOT claim chain order.
  { const f = new Fold(0n);
    f.beginBlock(10n, 1000n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x81), "bob", A))]), 5);
    f.applyTx(B.tx([B.input(Bb)], [B.commit(B.commitmentOf(salt(0x82), "bob", Bb))]), 2);
    f.beginBlock(20n, 1500n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x81), "bob", 10n)]), 0);   // applied first
    f.applyTx(B.tx([B.input(Bb)], [B.claim(salt(0x82), "bob", 10n)]), 1);  // lower commit tx_index → wins
    emitState("42_claim_commit_txindex_tiebreak", f); }

  // 43: escrow movement-lock (§3.7 headline) — a LISTED name rejects every move:
  //     TRANSFER, RELEASE, re-SELL, and SELL_TO all no-op while it sits on the market.
  { const f = minted(0xaa, "w", 300n, 1500n);
    f.beginBlock(12n, 1600n, RATE); f.applyTx(B.tx([B.input(A)], [B.sell(20000n, 50000n, "w")]), 0);
    f.beginBlock(13n, 1700n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.transferAll(Bb)]), 0);                       // gift → locked, skip
    f.applyTx(B.tx([B.input(A)], [B.release(11n, Uint8Array.of(0x01))]), 1);     // release → locked, skip
    f.applyTx(B.tx([B.input(A)], [B.sell(30000n, 50000n, "w")]), 2);             // re-SELL → not OWNED, reject
    f.applyTx(B.tx([B.input(A)], [B.sellTo(5000n, Bb, "w")]), 3);                // SELL_TO → not OWNED, reject
    emitState("43_escrow_movement_lock", f); }

  // 44: anchor-guard reject (§3.5) — a bitmap op whose anchor is OLDER than the owner's
  //     last set-mutation is dropped (stale set-view could select the wrong names).
  { const f = new Fold(0n);
    f.beginBlock(10n, 1000n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x91), "a", A))]), 0);
    f.beginBlock(11n, 1500n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x91), "a", 30n)]), 0);           // lm(A)=11
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x92), "b", A))]), 1);
    f.beginBlock(12n, 1600n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x92), "b", 30n)]), 0);           // lm(A)=12 (set grew)
    f.beginBlock(13n, 1700n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.release(11n, Uint8Array.of(0x01))]), 0);     // anchor 11 < lm 12 → reject
    emitState("44_anchor_guard_reject", f); }

  // 45: COMMIT_EXPIRY prune — a commit older than COMMIT_EXPIRY (18000s) is pruned pre-block,
  //     so a later matching claim finds no live commit and drops (§3.2).
  { const f = new Fold(0n);
    f.beginBlock(10n, 1000n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x33), "bob", A))]), 0);
    f.beginBlock(11n, 19001n, RATE);                                             // 19001 > 1000 + 18000 → prune
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x33), "bob", 10n)]), 0);         // no live commit → drop
    emitState("45_commit_expiry_prune", f); }

  // 46: RESERVE burn leg is an inequality (car_value ≥ burn_leg), not exact — an OVER-funded
  //     burn (car_value 150 > burn_leg 100) still wins the option (cf. 15: 99 < 100 drops).
  { const f = minted(0xaa, "w", 300n, 1500n); f.beginBlock(12n, 1600n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.sell(20000n, 50000n, "w")]), 0);
    f.beginBlock(13n, 1700n, RATE);
    f.applyTx(B.tx([B.input(Bb)], [B.reserve("w", 150n)], [B.output(0, A, 100n)]), 0);
    emitState("46_reserve_overfunded_burn", f); }

  // 47: TRADE malformed drops — OOB index, idxA==idxB (one party), and nameA==nameB are
  //     each fail-closed; the two-name state is left untouched (§3.10).
  { const f = twoNames();
    f.beginBlock(12n, 1600n, RATE);
    f.applyTx(B.tx([B.input(A), B.input(Bb)], [B.trade(0, 5, "aaa", "bbb")]), 0);  // idx_b OOB → drop
    f.applyTx(B.tx([B.input(A), B.input(Bb)], [B.trade(0, 0, "aaa", "bbb")]), 1);  // idxA==idxB → drop
    f.applyTx(B.tx([B.input(A), B.input(Bb)], [B.trade(0, 1, "aaa", "aaa")]), 2);  // nameA==nameB → drop
    emitState("47_trade_malformed_drops", f); }

  // 48: selective TRANSFER (anchor+flags) gifts a SUBSET — bits {0,2} of A's sorted set
  //     {a,b,c} move to B; b stays with A. Exercises the bitmap-selected positive transfer.
  { const f = new Fold(0n);
    f.beginBlock(10n, 1000n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0xa1), "a", A))]), 0);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0xa2), "b", A))]), 1);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0xa3), "c", A))]), 2);
    f.beginBlock(11n, 1500n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0xa1), "a", 30n)]), 0);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0xa2), "b", 30n)]), 1);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0xa3), "c", 30n)]), 2);
    f.beginBlock(12n, 1600n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.transferSel(Bb, 11n, Uint8Array.of(0x05))]), 0);  // bits 0 and 2 → a, c
    emitState("48_transfer_selective", f); }

  // ── §3.4 participant-median oracle (fee-bearing filter + MIN_FEE_SAMPLE) ──
  // 49: |P| = 1000 EXACTLY (inclusive boundary) and EVEN, with an under-claim block inside
  //     the window. Lower median = index (1000−1)/2 = 499 of the sorted 100..1099 → 599 →
  //     rate 119,800. Every rival reading forks to a different number: unsigned-wrap enrolls
  //     the under-claim as a huge 1001st participant → 600 → 120,000; an exclusive boundary
  //     (|P| ≤ MIN degrades) → 1; an upper median → 600 → 120,000.
  { const win: OracleBlock[] = Array.from({ length: 1500 }, (_, i) => ({
      coinbaseTotal:
        i < 499 ? DOGE_SUBSIDY                                            // zero-fee → non-participant
        : i === 499 ? DOGE_SUBSIDY - 50n                                  // under-claim → non-participant
        : DOGE_SUBSIDY + (100n + BigInt(i - 500)) * 1000n,                // fpb 100..1099
      blockBytes: 1000n,
    }));
    emitU64("49_oracle_even_boundary", oracleRate(win)); }               // → 119800

  // 50: odd |P| = 1101 through the participant filter — the historical middle
  //     rule unchanged by the rewrite: index 550 of 100..1200 → 650 → 130,000.
  { const win: OracleBlock[] = Array.from({ length: 2000 }, (_, i) => ({
      coinbaseTotal: i < 899 ? DOGE_SUBSIDY : DOGE_SUBSIDY + (100n + BigInt(i - 899)) * 1000n, // fpb 100..1200
      blockBytes: 1000n,
    }));
    emitU64("50_oracle_odd_median", oracleRate(win)); }                  // → 130000

  // 51: |P| = 999 — one short of MIN_FEE_SAMPLE → degrade to DUST_FLOOR exactly.
  { const win: OracleBlock[] = Array.from({ length: 1500 }, (_, i) => ({
      coinbaseTotal: i < 501 ? DOGE_SUBSIDY : DOGE_SUBSIDY + (100n + BigInt(i - 501)) * 1000n, // 999 participants
      blockBytes: 1000n,
    }));
    emitU64("51_oracle_subsample_floor", oracleRate(win)); }             // → 1

  // 52: charset = a DNS label [a-z0-9-], 1..32: hyphen and a 32-byte name MINT;
  // '.' and '_' DROP (uppercase still drops), leaving exactly the two valid names.
  { const f = new Fold(0n);
    commitThenClaim(f, 0xaa, "shib-p2p",                         0x71, 10n, 1000n, 10n, 1500n, 11n);
    commitThenClaim(f, 0xaa, "abcdefghijklmnopqrstuvwxyz0123ab", 0x72, 10n, 2000n, 12n, 2500n, 13n);
    commitThenClaim(f, 0xaa, "shib.p2p",                         0x73, 10n, 3000n, 14n, 3500n, 15n);
    commitThenClaim(f, 0xaa, "shib_p2p",                         0x74, 10n, 4000n, 16n, 4500n, 17n);
    emitState("52_charset", f); }

  // 52b: structural name rejects — leading/trailing hyphen and xn-- ACE drop.
  { const f = new Fold(0n);
    commitThenClaim(f, 0xaa, "-lead", 0x81, 10n, 1000n, 10n, 1500n, 11n);
    commitThenClaim(f, 0xaa, "trail-", 0x82, 10n, 2000n, 12n, 2500n, 13n);
    commitThenClaim(f, 0xaa, "xn--x",  0x83, 10n, 3000n, 14n, 3500n, 15n);
    commitThenClaim(f, 0xaa, "ok-name",0x84, 10n, 4000n, 16n, 4500n, 17n);
    emitState("52b_structural", f); }

  // 54: NO per-tx count cap (§0). One tx carries 17 COMMIT carriers past the
  // historical 16; all fold. An impl that caps at 16 either drops the tx or the
  // 17th carrier → a different commit count.
  { const f = new Fold(0n);
    f.beginBlock(10n, 1000n, RATE);
    const carriers = [];
    for (let i = 0; i < 17; i++) {
      const c = new Uint8Array(32); c[0] = i & 0xff;
      carriers.push(B.commit(c, i));
    }
    const outs = [];
    for (let i = 0; i < 17; i++) outs.push(B.output(0, A, 1n));
    f.applyTx(B.tx([B.input(A)], carriers, outs), 0);
    emitState("54_no_txcap", f); }

  // 55: a name minted then RELEASEd earlier in the SAME block re-mints fresh on a
  // later CLAIM in that block (§3.6 "immediately reclaimable"; row existence is
  // authoritative, the block-local claim scratch never blocks a re-mint).
  { const f = new Fold(0n);
    f.beginBlock(10n, 1000n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x91), "foo", A))]), 0);
    f.beginBlock(11n, 1500n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x91), "foo", 10n)]), 0);          // mint foo→A
    f.applyTx(B.tx([B.input(A)], [B.release(11n, Uint8Array.of(0x01))]), 1);      // release foo (row gone)
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x91), "foo", 10n)]), 2);          // MUST re-mint foo→A
    emitState("55_claim_release_reclaim_sameblock", f); }

  // 55b: same, but the re-claim is by a DIFFERENT party B whose backing commit has
  // LOWER priority than the departed A's — B still mints fresh (a released name's
  // former owner priority is irrelevant once the row is gone).
  { const f = new Fold(0n);
    f.beginBlock(10n, 1000n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x91), "foo", A))]), 0);   // A commit (10, tx0)
    f.applyTx(B.tx([B.input(Bb)], [B.commit(B.commitmentOf(salt(0x92), "foo", Bb))]), 1); // B commit (10, tx1)
    f.beginBlock(11n, 1500n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x91), "foo", 10n)]), 0);          // A mints
    f.applyTx(B.tx([B.input(A)], [B.release(11n, Uint8Array.of(0x01))]), 1);      // A releases
    f.applyTx(B.tx([B.input(Bb)], [B.claim(salt(0x92), "foo", 10n)]), 2);         // B mints fresh
    emitState("55b_reclaim_by_other", f); }

  // 56: a self-transfer (TRANSFER-all whose target == the current owner) is a real
  // move — it bumps last_set_mutation_height (owner's mut goes 11 → 12), NOT a no-op.
  { const f = minted(0xaa, "bar", 10n, 1500n);
    f.beginBlock(12n, 1600n, RATE);
    f.applyTx(B.tx([B.input(A)], [B.transferAll(A)]), 0);
    emitState("56_self_transfer_bumps_mut", f); }

  // 57: fee oracle with block_bytes == 0 — the /0 guard substitutes divisor 1 (NOT
  // fee-per-byte 0), so the block still participates. 1000 blocks (== MIN_FEE_SAMPLE),
  // each fee 5000 ⇒ per-byte 5000 ⇒ median 5000 × REF_SIZE 200 = 1_000_000.
  { const win: OracleBlock[] = Array.from({ length: 1000 }, () => ({
      coinbaseTotal: 1_000_000_005_000n, blockBytes: 0n }));
    emitU64("57_oracle_zero_bytes", oracleRate(win)); }

  // 58: CLAIM burn near 2⁶⁴ at rate = DUST_FLOOR (1) — the lease day-count T overflows
  // 64 bits (computed in 128-bit / bignum) and clamps to MAX_LEASE (365 days).
  { const f = new Fold(0n);
    f.beginBlock(10n, 1000n, 1n);
    f.applyTx(B.tx([B.input(A)], [B.commit(B.commitmentOf(salt(0x95), "foo", A))]), 0);
    f.beginBlock(11n, 1500n, 1n);
    f.applyTx(B.tx([B.input(A)], [B.claim(salt(0x95), "foo", (1n << 64n) - 1n)]), 0);
    emitState("58_lease_clamp_huge_burn", f); }

  console.log(`combined ${hex(sha256(concat(...feeds)))}`);
  return 0;
}
