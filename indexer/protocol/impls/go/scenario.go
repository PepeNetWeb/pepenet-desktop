package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ---- test helpers for building abstract blocks ----

func idOf(n byte, styp byte) Identity {
	var h [20]byte
	h[0] = n
	h[19] = n
	return Identity{h160: h, styp: styp, ok: true}
}

func payload(op byte, body ...byte) []byte {
	p := []byte{0xFF, 0x50, 0x4E, op}
	return append(p, body...)
}

func leBytes32(v uint32) []byte { return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)} }
func leBytes64(v uint64) []byte {
	b := make([]byte, 8)
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * uint(i)))
	}
	return b
}
func leBytes40(v int64) []byte {
	b := make([]byte, 5)
	for i := 0; i < 5; i++ {
		b[i] = byte(v >> (8 * uint(i)))
	}
	return b
}

func commitment(salt [32]byte, name string, author [20]byte) [32]byte {
	buf := append([]byte{}, salt[:]...)
	buf = append(buf, name...)
	buf = append(buf, author[:]...)
	return sha256.Sum256(buf)
}

// carrier decodes a payload+value into a FoldCarrier at vout.
func carrier(vout uint32, value uint64, p []byte) FoldCarrier {
	return FoldCarrier{c: decode(p, value), value: value, vout: vout}
}

// ---- C-reference scenario battery (impls/c `scenario`, byte-identical) ----
// Builders mirroring the C reference's tx1/add_action/mk_* helpers: each op
// body is framed FF 53 50 <op> and decoded through the real wire decoder.

func mkTx(ins []Identity, cars []FoldCarrier, outs []FoldOutput) FoldTx {
	return FoldTx{inputs: ins, carriers: cars, spend: outs}
}
func opCar(op byte, body []byte, value uint64, vout uint32) FoldCarrier {
	return carrier(vout, value, payload(op, body...))
}
func bCommit(cm [32]byte, vout uint32) FoldCarrier { return opCar(OP_COMMIT, cm[:], 0, vout) }
func bClaim(sb [32]byte, nm string, burn uint64, vout uint32) FoldCarrier {
	body := append(append([]byte{}, sb[:]...), nm...)
	return opCar(OP_CLAIM, body, burn, vout)
}
func bRenewAll(burn uint64) FoldCarrier        { return opCar(OP_RENEW, nil, burn, 0) }
func bTransferAll(target [20]byte) FoldCarrier { return opCar(OP_TRANSFER, target[:], 0, 0) }
func bTransferSel(target [20]byte, anchor int64, flags []byte) FoldCarrier {
	body := append(append(append([]byte{}, target[:]...), leBytes40(anchor)...), flags...)
	return opCar(OP_TRANSFER, body, 0, 0)
}
func bRelease(anchor int64, flags []byte) FoldCarrier {
	return opCar(OP_RELEASE, append(leBytes40(anchor), flags...), 0, 0)
}
func bSell(price uint64, window uint32, nm string) FoldCarrier {
	body := append(append(leBytes64(price), leBytes32(window)...), nm...)
	return opCar(OP_SELL, body, 0, 0)
}
func bReserve(nm string, value uint64, vout uint32) FoldCarrier {
	return opCar(OP_RESERVE, []byte(nm), value, vout)
}
func bSettle(nm string, vout uint32) FoldCarrier { return opCar(OP_SETTLE, []byte(nm), 0, vout) }
func bSellTo(price uint64, buyer [20]byte, nm string) FoldCarrier {
	body := append(append(leBytes64(price), buyer[:]...), nm...)
	return opCar(OP_SELL_TO, body, 0, 0)
}
func bPay(nm string) FoldCarrier              { return opCar(OP_PAY, []byte(nm), 0, 0) }
func bAS(index byte, vout uint32) FoldCarrier { return opCar(OP_AS, []byte{index}, 0, vout) }
func bTrade(ia, ib byte, na, nb string) FoldCarrier {
	body := append([]byte{ia, ib}, na...)
	body = append(body, ',')
	body = append(body, nb...)
	return opCar(OP_TRADE, body, 0, 0)
}
func bOut(id Identity, value uint64) FoldOutput {
	return FoldOutput{h160: id.h160, styp: id.styp, value: value}
}

// scFold mirrors the C reference's sm_begin_block/sm_apply_tx build style over
// the block-at-a-time applyBlock fold: txs queue under the open block and flush
// on the next begin (or on state()).
type scFold struct {
	s    *FoldState
	blk  FoldBlock
	open bool
}

func newScFold() *scFold { return &scFold{s: newState()} }
func (f *scFold) begin(h, mtp int64) {
	f.flush()
	f.blk = FoldBlock{height: h, mtp: mtp, rate: scRate}
	f.open = true
}
func (f *scFold) tx(ti uint32, t FoldTx) {
	t.txIndex = ti
	f.blk.txs = append(f.blk.txs, t)
}
func (f *scFold) flush() {
	if f.open {
		f.s.applyBlock(f.blk)
		f.open = false
	}
}
func (f *scFold) state() *FoldState { f.flush(); return f.s }

// ctc mirrors the C reference's commit_then_claim(s, tag, nm, salt, days, cmtp, ch, kmtp, kh):
// COMMIT `nm`(author=tag, salt) at block ch (MTP cmtp), then CLAIM burn=days at block kh (MTP kmtp).
func ctc(f *scFold, tag byte, nm string, sb byte, days uint64, cmtp, ch, kmtp, kh int64) {
	id := idOf(tag, 0)
	f.begin(ch, cmtp)
	f.tx(0, mkTx([]Identity{id}, []FoldCarrier{bCommit(commitment(salt32(sb), nm, id.h160), 0)}, nil))
	f.begin(kh, kmtp)
	f.tx(0, mkTx([]Identity{id}, []FoldCarrier{bClaim(salt32(sb), nm, days, 0)}, nil))
}

// mintedF mints `nm` to `tag` with a `days` lease, leaving the fold at the claim's block.
func mintedF(tag byte, nm string, days uint64, claimMtp int64) *scFold {
	f := newScFold()
	ctc(f, tag, nm, 0x33, days, claimMtp-100, 10, claimMtp, 11)
	return f
}

// twoNamesF mints aaa→A and bbb→B (30d each) for the TRADE vectors.
func twoNamesF() *scFold {
	A, Bb := idOf(0xAA, 0), idOf(0xBB, 0)
	f := newScFold()
	f.begin(10, 1000)
	f.tx(0, mkTx([]Identity{A}, []FoldCarrier{bCommit(commitment(salt32(0x01), "aaa", A.h160), 0)}, nil))
	f.tx(1, mkTx([]Identity{Bb}, []FoldCarrier{bCommit(commitment(salt32(0x02), "bbb", Bb.h160), 0)}, nil))
	f.begin(11, 1500)
	f.tx(0, mkTx([]Identity{A}, []FoldCarrier{bClaim(salt32(0x01), "aaa", 30, 0)}, nil))
	f.tx(1, mkTx([]Identity{Bb}, []FoldCarrier{bClaim(salt32(0x02), "bbb", 30, 0)}, nil))
	return f
}

// runScenario emits the directed conformance vectors (cross-language adversarial
// scenarios) — the go port of impls/c `scenario`, line- and combined-identical.
// Each builds a deterministic, named construction and emits `name <digest>`
// (canonical §4 state digest) or `name <u64>`; the rolling `combined` hash is
// the single-line cross-language check. These pin the spec's named edge cases
// (§5) with auditable outcomes, and cover the rare branches the random soak
// almost never hits (deep displacement, fee oracle). The go-authored behavioral
// battery (scenarios_impl.go) runs in `selftest` (testFoldScenarios).
func runScenario() {
	var comb []byte
	emitState := func(name string, f *scFold) {
		d := f.state().stateDigest()
		fmt.Printf("%s %s\n", name, hex.EncodeToString(d[:]))
		comb = append(comb, d[:]...)
	}
	emitU64 := func(name string, v uint64) {
		fmt.Printf("%s %d\n", name, v)
		comb = append(comb, leBytes64(v)...)
	}
	A, Bb, Cc := idOf(0xAA, 0), idOf(0xBB, 0), idOf(0xCC, 0)
	one := func(id Identity, cars ...FoldCarrier) FoldTx { return mkTx([]Identity{id}, cars, nil) }
	const u64max = ^uint64(0)

	{ // 01
		f := newScFold()
		emitState("01_empty", f)
	}
	{ // 02
		f := newScFold()
		ctc(f, 0xAA, "bob", 0x11, 10, 1000, 10, 1500, 11)
		emitState("02_commit_claim", f)
	}
	{ // 03: CLAIM with no prior COMMIT → drop
		f := newScFold()
		f.begin(11, 1500)
		f.tx(0, one(A, bClaim(salt32(0x11), "bob", 10, 0)))
		emitState("03_naked_claim_drop", f)
	}
	{ // 04: same-block commit is not ≥1 deep → drop
		f := newScFold()
		f.begin(11, 1500)
		f.tx(0, one(A, bCommit(commitment(salt32(0x11), "bob", A.h160), 0),
			bClaim(salt32(0x11), "bob", 10, 1)))
		emitState("04_shallow_commit_drop", f)
	}
	// 05/06: priority — lower commit_height (A@10) wins ownership in BOTH claim orderings.
	for order := 0; order < 2; order++ {
		f := newScFold()
		f.begin(10, 1000)
		f.tx(0, one(A, bCommit(commitment(salt32(0x11), "bob", A.h160), 0)))
		f.begin(12, 1100)
		f.tx(0, one(Bb, bCommit(commitment(salt32(0x22), "bob", Bb.h160), 0)))
		f.begin(20, 1200)
		kA := one(A, bClaim(salt32(0x11), "bob", 10, 0))
		kB := one(Bb, bClaim(salt32(0x22), "bob", 10, 0))
		if order == 0 {
			f.tx(0, kB)
			f.tx(1, kA)
		} else {
			f.tx(0, kA)
			f.tx(1, kB)
		}
		if order == 0 {
			emitState("05_priority_b_first", f)
		} else {
			emitState("06_priority_a_first", f)
		}
	}
	{ // 07: B reposts A's commitment bytes → B's claim drops (author-bound); A's claim owns
		f := newScFold()
		cm := commitment(salt32(0x33), "bob", A.h160)
		f.begin(10, 1000)
		f.tx(0, one(A, bCommit(cm, 0)))
		f.tx(1, one(Bb, bCommit(cm, 0)))
		f.begin(11, 1100)
		f.tx(0, one(Bb, bClaim(salt32(0x33), "bob", 10, 0)))
		f.tx(1, one(A, bClaim(salt32(0x33), "bob", 10, 0)))
		emitState("07_commitment_copy", f)
	}
	{ // 08: MTP == expiry → lapse (exclusive bound)
		f := mintedF(0xAA, "bob", 10, 1500) // expiry 865500
		f.begin(12, 865500)
		emitState("08_lease_lapse", f)
	}
	{ // 09
		f := mintedF(0xAA, "bob", 10, 1500)
		f.begin(12, 1600)
		f.tx(0, one(A, bRenewAll(5)))
		emitState("09_renew_stack", f)
	}
	{ // 10: water-fill even split: 3 names, renew-all buys 30 name-days → +10 each
		f := newScFold()
		nm := []string{"a", "b", "c"}
		f.begin(10, 1000)
		for i := 0; i < 3; i++ {
			f.tx(uint32(i), one(A, bCommit(commitment(salt32(byte(0x40+i)), nm[i], A.h160), 0)))
		}
		f.begin(11, 1100)
		for i := 0; i < 3; i++ {
			f.tx(uint32(i), one(A, bClaim(salt32(byte(0x40+i)), nm[i], 1, 0)))
		}
		f.begin(12, 1200)
		f.tx(0, one(A, bRenewAll(30)))
		emitState("10_waterfill_even", f)
	}
	{ // 11: huge burn → caps at 365d
		f := newScFold()
		ctc(f, 0xAA, "bob", 0x11, 100000, 1000, 10, 1500, 11)
		emitState("11_waterfill_maxlease", f)
	}
	{ // 12
		f := mintedF(0xAA, "bob", 10, 1500)
		f.begin(12, 1600)
		f.tx(0, one(A, bTransferAll(Bb.h160)))
		emitState("12_transfer_gift", f)
	}
	{ // 13
		f := mintedF(0xAA, "bob", 10, 1500)
		f.begin(12, 1600)
		f.tx(0, one(A, bRelease(11, []byte{0x01})))
		emitState("13_release", f)
	}
	{ // 14: full escrow cycle sell→reserve→settle
		f := mintedF(0xAA, "w", 300, 1500)
		f.begin(12, 1600)
		f.tx(0, one(A, bSell(20000, 50000, "w")))
		f.begin(13, 1700)
		f.tx(0, mkTx([]Identity{Bb}, []FoldCarrier{bReserve("w", 100, 0)}, []FoldOutput{bOut(A, 100)}))
		f.begin(14, 1800)
		f.tx(0, mkTx([]Identity{Bb}, []FoldCarrier{bSettle("w", 0)}, []FoldOutput{bOut(A, 19800)}))
		emitState("14_market_full", f)
	}
	{ // 15: burn leg short (99 < 100) → reserve drops
		f := mintedF(0xAA, "w", 300, 1500)
		f.begin(12, 1600)
		f.tx(0, one(A, bSell(20000, 50000, "w")))
		f.begin(13, 1700)
		f.tx(0, mkTx([]Identity{Bb}, []FoldCarrier{bReserve("w", 99, 0)}, []FoldOutput{bOut(A, 100)}))
		emitState("15_reserve_burn_short", f)
	}
	{ // 16: pay leg summed over two outputs (60+60 ≥ 100)
		f := mintedF(0xAA, "w", 300, 1500)
		f.begin(12, 1600)
		f.tx(0, one(A, bSell(20000, 50000, "w")))
		f.begin(13, 1700)
		f.tx(0, mkTx([]Identity{Bb}, []FoldCarrier{bReserve("w", 100, 0)},
			[]FoldOutput{bOut(A, 60), bOut(A, 60)}))
		emitState("16_reserve_pay_summed", f)
	}
	{ // 17: reserve near offer end → reserve_expiry clamps to offer_expiry
		f := mintedF(0xAA, "w", 300, 1500)
		f.begin(12, 1600)
		f.tx(0, one(A, bSell(20000, 0, "w"))) // window default 18000 → offer_expiry 19600
		f.begin(13, 5000)
		f.tx(0, mkTx([]Identity{Bb}, []FoldCarrier{bReserve("w", 100, 0)}, []FoldOutput{bOut(A, 100)}))
		emitState("17_reserve_clamp", f)
	}
	{ // 18: price below 3·DUST → reject
		f := mintedF(0xAA, "w", 300, 1500)
		f.begin(12, 1600)
		f.tx(0, one(A, bSell(2, 0, "w")))
		emitState("18_sell_price_floor", f)
	}
	{ // 19: sell window overflows the short lease tail
		f := mintedF(0xAA, "w", 1, 1500)
		f.begin(12, 65000)
		f.tx(0, one(A, bSell(20000, 0, "w")))
		emitState("19_sell_window_overflow", f)
	}
	{ // 20: directed sale — stranger's PAY drops, buyer's PAY owns
		f := mintedF(0xAA, "w", 300, 1500)
		f.begin(12, 1600)
		f.tx(0, one(A, bSellTo(5000, Bb.h160, "w")))
		f.begin(13, 1700)
		f.tx(0, mkTx([]Identity{Cc}, []FoldCarrier{bPay("w")}, []FoldOutput{bOut(A, 5000)}))
		f.tx(1, mkTx([]Identity{Bb}, []FoldCarrier{bPay("w")}, []FoldOutput{bOut(A, 5000)}))
		emitState("20_directed_pay", f)
	}
	{ // 21: 2^64-1 price — the 128-bit deposit legs must be exact
		f := mintedF(0xAA, "w", 300, 1500)
		f.begin(12, 1600)
		f.tx(0, one(A, bSell(u64max, 50000, "w")))
		hi, lo := mul64(u64max, 50)
		leg := div128by64(hi, lo, 10000)
		f.begin(13, 1700)
		f.tx(0, mkTx([]Identity{Bb}, []FoldCarrier{bReserve("w", leg, 0)}, []FoldOutput{bOut(A, leg)}))
		emitState("21_deposit_2pow64", f)
	}
	{ // 22: AS attribution — claim attributed to vin[1]=B (matches B's commit)
		f := newScFold()
		f.begin(10, 1000)
		f.tx(0, one(Bb, bCommit(commitment(salt32(0x55), "bob", Bb.h160), 0)))
		f.begin(11, 1500)
		f.tx(0, mkTx([]Identity{A, Bb},
			[]FoldCarrier{bAS(1, 0), bClaim(salt32(0x55), "bob", 10, 1)}, nil))
		emitState("22_as_attribution", f)
	}
	{ // 23: AS to a non-attributable input → nameless actor, claim drops
		f := newScFold()
		f.begin(10, 1000)
		f.tx(0, one(Bb, bCommit(commitment(salt32(0x55), "bob", Bb.h160), 0)))
		nb := idOf(0xBB, 0)
		nb.ok = false
		f.begin(11, 1500)
		f.tx(0, mkTx([]Identity{A, nb},
			[]FoldCarrier{bAS(1, 0), bClaim(salt32(0x55), "bob", 10, 1)}, nil))
		emitState("23_as_oob_drop", f)
	}
	{ // 24
		f := twoNamesF()
		f.begin(12, 1600)
		f.tx(0, mkTx([]Identity{A, Bb}, []FoldCarrier{bTrade(0, 1, "aaa", "bbb")}, nil))
		emitState("24_trade_swap", f)
	}
	{ // 25: aaa→C before the trade → anti-rug drop
		f := twoNamesF()
		f.begin(12, 1600)
		f.tx(0, one(A, bTransferAll(Cc.h160)))
		f.tx(1, mkTx([]Identity{A, Bb}, []FoldCarrier{bTrade(0, 1, "aaa", "bbb")}, nil))
		emitState("25_trade_rug_before", f)
	}
	{ // 29: fee oracle — 4 participants < MIN_FEE_SAMPLE → DUST_FLOOR (big windows are 49–51)
		cb := []int64{1_000_000_200_000, 1_000_000_400_000, 999_999_999_950, 1_000_001_000_000, 1_000_000_600_000}
		sub, by := make([]int64, 5), make([]int64, 5)
		for i := range sub {
			sub[i], by[i] = SUBSIDY, 1000
		}
		emitU64("29_oracle_rate", oracleRate(cb, sub, by))
	}
	{ // 30: all under-claim → fees 0 → rate floor
		cb, sub, by := make([]int64, 3), make([]int64, 3), make([]int64, 3)
		for i := range cb {
			cb[i], sub[i], by[i] = 0, SUBSIDY, 1000
		}
		emitU64("30_oracle_floor", oracleRate(cb, sub, by))
	}
	{ // 31: MTP median of 11
		ts := []int64{100, 50, 200, 30, 150, 80, 220, 10, 175, 60, 190}
		emitU64("31_mtp_median", uint64(medianTimePast(ts)))
	}
	{ // 32: water-fill T < count — first T names (asc-lex) get +1 day, rest none (§3.5 floor)
		f := newScFold()
		nm := []string{"a", "b", "c"}
		f.begin(10, 1000)
		for i := 0; i < 3; i++ {
			f.tx(uint32(i), one(A, bCommit(commitment(salt32(byte(0x50+i)), nm[i], A.h160), 0)))
		}
		f.begin(11, 1100)
		for i := 0; i < 3; i++ {
			f.tx(uint32(i), one(A, bClaim(salt32(byte(0x50+i)), nm[i], 1, 0)))
		}
		f.begin(12, 1200)
		f.tx(0, one(A, bRenewAll(2))) // T=2 over 3 → a,b +1d, c none
		emitState("32_waterfill_floor", f)
	}
	{ // 33: every targeted name hits MAX_LEASE with T remaining → surplus forfeited
		f := newScFold()
		nm := []string{"a", "b"}
		f.begin(10, 1000)
		for i := 0; i < 2; i++ {
			f.tx(uint32(i), one(A, bCommit(commitment(salt32(byte(0x60+i)), nm[i], A.h160), 0)))
		}
		f.begin(11, 1100)
		for i := 0; i < 2; i++ {
			f.tx(uint32(i), one(A, bClaim(salt32(byte(0x60+i)), nm[i], 360, 0)))
		}
		f.begin(12, 1100)
		f.tx(0, one(A, bRenewAll(100000)))
		emitState("33_waterfill_allcap_forfeit", f)
	}
	{ // 34a: lapse at MTP==expiry, hunter reclaims → B owns
		f := mintedF(0xAA, "bob", 10, 1500) // expiry 865500
		f.begin(12, 860000)
		f.tx(0, one(Bb, bCommit(commitment(salt32(0x44), "bob", Bb.h160), 0)))
		f.begin(13, 865500)
		f.tx(0, one(Bb, bClaim(salt32(0x44), "bob", 10, 0)))
		emitState("34a_reorg_lapse_reclaim", f)
	}
	{ // 34b: the restored RENEW keeps bob owned → the reclaim drops
		f := mintedF(0xAA, "bob", 10, 1500)
		f.begin(12, 860000)
		f.tx(0, one(Bb, bCommit(commitment(salt32(0x44), "bob", Bb.h160), 0)))
		f.tx(1, one(A, bRenewAll(10)))
		f.begin(13, 865500)
		f.tx(0, one(Bb, bClaim(salt32(0x44), "bob", 10, 0)))
		emitState("34b_reorg_renew_blocks_reclaim", f)
	}
	{ // 35a: reserve lapses without a settle → listing reverts to the seller
		f := mintedF(0xAA, "w", 300, 1500)
		f.begin(12, 1600)
		f.tx(0, one(A, bSell(20000, 50000, "w")))
		f.begin(13, 1700)
		f.tx(0, mkTx([]Identity{Bb}, []FoldCarrier{bReserve("w", 100, 0)}, []FoldOutput{bOut(A, 100)}))
		f.begin(14, 20000) // MTP past reserve_expiry (19700)
		emitState("35a_settle_dropped_relisted", f)
	}
	{ // 35b: the settle confirms → buyer owns
		f := mintedF(0xAA, "w", 300, 1500)
		f.begin(12, 1600)
		f.tx(0, one(A, bSell(20000, 50000, "w")))
		f.begin(13, 1700)
		f.tx(0, mkTx([]Identity{Bb}, []FoldCarrier{bReserve("w", 100, 0)}, []FoldOutput{bOut(A, 100)}))
		f.begin(14, 1800)
		f.tx(0, mkTx([]Identity{Bb}, []FoldCarrier{bSettle("w", 0)}, []FoldOutput{bOut(A, 19800)}))
		emitState("35b_settle_confirmed", f)
	}
	{ // 36: exclusive expiry bound — expiry−1 owned / expiry lapsed
		f := mintedF(0xAA, "bob", 10, 1500)
		f.begin(12, 865499)
		emitState("36a_mtp_below_owned", f)
	}
	{
		f := mintedF(0xAA, "bob", 10, 1500)
		f.begin(12, 865500)
		emitState("36b_mtp_at_lapsed", f)
	}
	{ // 38: pre-block lapse returns bob to the pool; renew-all misses it, the hunter mints it
		f := newScFold()
		f.begin(10, 1000)
		f.tx(0, one(A, bCommit(commitment(salt32(0x33), "bob", A.h160), 0)))
		f.tx(1, one(A, bCommit(commitment(salt32(0x34), "keep", A.h160), 0)))
		f.begin(11, 1500)
		f.tx(0, one(A, bClaim(salt32(0x33), "bob", 10, 0)))   // bob expiry 865500
		f.tx(1, one(A, bClaim(salt32(0x34), "keep", 300, 0))) // keep long-lived
		f.begin(12, 860000)
		f.tx(0, one(Bb, bCommit(commitment(salt32(0x44), "bob", Bb.h160), 0)))
		f.begin(13, 865500) // MTP == bob's expiry → bob lapses pre-block
		f.tx(0, one(A, bRenewAll(5)))
		f.tx(1, one(Bb, bClaim(salt32(0x44), "bob", 10, 0)))
		emitState("38_lapse_renew_vs_claim", f)
	}
	{ // 39: one tick crosses reserve_expiry AND offer_expiry → RESERVED→LISTED→OWNED in one pass
		f := mintedF(0xAA, "w", 300, 1500)
		f.begin(12, 1600)
		f.tx(0, one(A, bSell(20000, 50000, "w"))) // offer_expiry 51600
		f.begin(13, 1700)
		f.tx(0, mkTx([]Identity{Bb}, []FoldCarrier{bReserve("w", 100, 0)}, []FoldOutput{bOut(A, 100)}))
		f.begin(14, 51600)
		emitState("39_preblock_reserve_offer_collapse", f)
	}
	{ // 40: intra-block RESERVE option theft — first buyer wins, second drops, its SETTLE fails
		f := mintedF(0xAA, "w", 300, 1500)
		f.begin(12, 1600)
		f.tx(0, one(A, bSell(20000, 50000, "w")))
		f.begin(13, 1700)
		f.tx(0, mkTx([]Identity{Bb}, []FoldCarrier{bReserve("w", 100, 0)}, []FoldOutput{bOut(A, 100)}))
		f.tx(1, mkTx([]Identity{Cc}, []FoldCarrier{bReserve("w", 100, 0)}, []FoldOutput{bOut(A, 100)}))
		f.tx(2, mkTx([]Identity{Cc}, []FoldCarrier{bSettle("w", 0)}, []FoldOutput{bOut(A, 19800)}))
		emitState("40_reserve_option_theft", f)
	}
	{ // 41: consume-once exact-value vout matcher under a value collision
		f := newScFold()
		f.begin(10, 1000)
		f.tx(0, one(A, bCommit(commitment(salt32(0x71), "x", A.h160), 0)))
		f.tx(1, one(A, bCommit(commitment(salt32(0x72), "y", A.h160), 0)))
		f.begin(11, 1500)
		f.tx(0, one(A, bClaim(salt32(0x71), "x", 300, 0)))
		f.tx(1, one(A, bClaim(salt32(0x72), "y", 300, 0)))
		f.begin(12, 1600)
		f.tx(0, one(A, bSell(1000, 50000, "x")))  // pay_leg(x) = 5
		f.tx(1, one(A, bSell(20000, 50000, "y"))) // remainder(y) = 19800
		f.begin(13, 1700)
		f.tx(0, mkTx([]Identity{Bb}, []FoldCarrier{bReserve("y", 100, 0)}, []FoldOutput{bOut(A, 100)}))
		f.begin(14, 1800)
		f.tx(0, mkTx([]Identity{Bb},
			[]FoldCarrier{bReserve("x", 5, 0), bSettle("y", 1)},
			[]FoldOutput{bOut(A, 19800), bOut(A, 5)}))
		emitState("41_vout_value_collision", f)
	}
	{ // 42: CLAIM priority tie-break is the COMMIT's tx_index, not claim chain order
		f := newScFold()
		f.begin(10, 1000)
		f.tx(5, one(A, bCommit(commitment(salt32(0x81), "bob", A.h160), 0)))
		f.tx(2, one(Bb, bCommit(commitment(salt32(0x82), "bob", Bb.h160), 0)))
		f.begin(20, 1500)
		f.tx(0, one(A, bClaim(salt32(0x81), "bob", 10, 0)))
		f.tx(1, one(Bb, bClaim(salt32(0x82), "bob", 10, 0))) // lower commit tx_index → wins
		emitState("42_claim_commit_txindex_tiebreak", f)
	}
	{ // 43: escrow movement-lock — a LISTED name rejects every move
		f := mintedF(0xAA, "w", 300, 1500)
		f.begin(12, 1600)
		f.tx(0, one(A, bSell(20000, 50000, "w")))
		f.begin(13, 1700)
		f.tx(0, one(A, bTransferAll(Bb.h160)))
		f.tx(1, one(A, bRelease(11, []byte{0x01})))
		f.tx(2, one(A, bSell(30000, 50000, "w")))
		f.tx(3, one(A, bSellTo(5000, Bb.h160, "w")))
		emitState("43_escrow_movement_lock", f)
	}
	{ // 44: anchor-guard reject — anchor older than the owner's last set-mutation drops
		f := newScFold()
		f.begin(10, 1000)
		f.tx(0, one(A, bCommit(commitment(salt32(0x91), "a", A.h160), 0)))
		f.begin(11, 1500)
		f.tx(0, one(A, bClaim(salt32(0x91), "a", 30, 0))) // lm(A)=11
		f.tx(1, one(A, bCommit(commitment(salt32(0x92), "b", A.h160), 0)))
		f.begin(12, 1600)
		f.tx(0, one(A, bClaim(salt32(0x92), "b", 30, 0))) // lm(A)=12 (set grew)
		f.begin(13, 1700)
		f.tx(0, one(A, bRelease(11, []byte{0x01}))) // anchor 11 < lm 12 → reject
		emitState("44_anchor_guard_reject", f)
	}
	{ // 45: COMMIT_EXPIRY prune — the stale commit is pruned pre-block, the claim drops
		f := newScFold()
		f.begin(10, 1000)
		f.tx(0, one(A, bCommit(commitment(salt32(0x33), "bob", A.h160), 0)))
		f.begin(11, 19001) // 19001 > 1000 + 18000 → prune
		f.tx(0, one(A, bClaim(salt32(0x33), "bob", 10, 0)))
		emitState("45_commit_expiry_prune", f)
	}
	{ // 46: RESERVE burn leg is ≥, not exact — over-funded burn still wins the option
		f := mintedF(0xAA, "w", 300, 1500)
		f.begin(12, 1600)
		f.tx(0, one(A, bSell(20000, 50000, "w")))
		f.begin(13, 1700)
		f.tx(0, mkTx([]Identity{Bb}, []FoldCarrier{bReserve("w", 150, 0)}, []FoldOutput{bOut(A, 100)}))
		emitState("46_reserve_overfunded_burn", f)
	}
	{ // 47: TRADE malformed drops — OOB index, idxA==idxB, nameA==nameB all fail-closed
		f := twoNamesF()
		f.begin(12, 1600)
		f.tx(0, mkTx([]Identity{A, Bb}, []FoldCarrier{bTrade(0, 5, "aaa", "bbb")}, nil))
		f.tx(1, mkTx([]Identity{A, Bb}, []FoldCarrier{bTrade(0, 0, "aaa", "bbb")}, nil))
		f.tx(2, mkTx([]Identity{A, Bb}, []FoldCarrier{bTrade(0, 1, "aaa", "aaa")}, nil))
		emitState("47_trade_malformed_drops", f)
	}
	{ // 48: selective TRANSFER (anchor+flags) gifts bits {0,2} of {a,b,c}; b stays
		f := newScFold()
		f.begin(10, 1000)
		f.tx(0, one(A, bCommit(commitment(salt32(0xa1), "a", A.h160), 0)))
		f.tx(1, one(A, bCommit(commitment(salt32(0xa2), "b", A.h160), 0)))
		f.tx(2, one(A, bCommit(commitment(salt32(0xa3), "c", A.h160), 0)))
		f.begin(11, 1500)
		f.tx(0, one(A, bClaim(salt32(0xa1), "a", 30, 0)))
		f.tx(1, one(A, bClaim(salt32(0xa2), "b", 30, 0)))
		f.tx(2, one(A, bClaim(salt32(0xa3), "c", 30, 0)))
		f.begin(12, 1600)
		f.tx(0, one(A, bTransferSel(Bb.h160, 11, []byte{0x05})))
		emitState("48_transfer_selective", f)
	}

	// §3.4 participant-median oracle at the MIN_FEE_SAMPLE boundary (big windows).
	emitU64("49_oracle_even_boundary", scOracleEvenBoundary())     // |P|=1000 inclusive, even → 119800
	emitU64("50_oracle_odd_median", scOracleOddMedian())           // odd |P|=1101 → 130000
	emitU64("51_oracle_subsample_floor", scOracleSubsampleFloor()) // |P|=999 → DUST_FLOOR

	// 52: charset = a DNS label [a-z0-9-], 1..32: hyphen and a 32-byte name MINT;
	// '.' and '_' DROP (uppercase still drops), leaving exactly the two valid names.
	{
		f := newScFold()
		ctc(f, 0xAA, "shib-p2p", 0x71, 10, 1000, 10, 1500, 11)
		ctc(f, 0xAA, "abcdefghijklmnopqrstuvwxyz0123ab", 0x72, 10, 2000, 12, 2500, 13)
		ctc(f, 0xAA, "shib.p2p", 0x73, 10, 3000, 14, 3500, 15)
		ctc(f, 0xAA, "shib_p2p", 0x74, 10, 4000, 16, 4500, 17)
		emitState("52_charset", f)
	}

	// 52b: structural name rejects — leading/trailing hyphen and xn-- ACE drop.
	{
		f := newScFold()
		ctc(f, 0xAA, "-lead", 0x81, 10, 1000, 10, 1500, 11)
		ctc(f, 0xAA, "trail-", 0x82, 10, 2000, 12, 2500, 13)
		ctc(f, 0xAA, "xn--x", 0x83, 10, 3000, 14, 3500, 15)
		ctc(f, 0xAA, "ok-name", 0x84, 10, 4000, 16, 4500, 17)
		emitState("52b_structural", f)
	}

	// 54: NO per-tx count cap (§0). One tx carries 17 COMMIT carriers past the
	// historical 16; all fold.
	{
		f := newScFold()
		f.begin(10, 1000)
		cars := make([]FoldCarrier, 0, 17)
		for i := 0; i < 17; i++ {
			var cm [32]byte
			cm[0] = byte(i)
			cars = append(cars, bCommit(cm, uint32(i)))
		}
		outs := make([]FoldOutput, 0, 17)
		for i := 0; i < 17; i++ {
			outs = append(outs, bOut(A, 1))
		}
		f.tx(0, mkTx([]Identity{A}, cars, outs))
		emitState("54_no_txcap", f)
	}
	{ // 55: mint→RELEASE→re-CLAIM in the same block re-mints fresh (§3.6)
		f := newScFold()
		f.begin(10, 1000)
		f.tx(0, one(A, bCommit(commitment(salt32(0x91), "foo", A.h160), 0)))
		f.begin(11, 1500)
		f.tx(0, one(A, bClaim(salt32(0x91), "foo", 10, 0)))
		f.tx(1, one(A, bRelease(11, []byte{0x01})))
		f.tx(2, one(A, bClaim(salt32(0x91), "foo", 10, 0)))
		emitState("55_claim_release_reclaim_sameblock", f)
	}
	{ // 55b: same-block re-claim by a lower-priority party B still mints fresh
		f := newScFold()
		f.begin(10, 1000)
		f.tx(0, one(A, bCommit(commitment(salt32(0x91), "foo", A.h160), 0)))
		f.tx(1, one(Bb, bCommit(commitment(salt32(0x92), "foo", Bb.h160), 0)))
		f.begin(11, 1500)
		f.tx(0, one(A, bClaim(salt32(0x91), "foo", 10, 0)))
		f.tx(1, one(A, bRelease(11, []byte{0x01})))
		f.tx(2, one(Bb, bClaim(salt32(0x92), "foo", 10, 0)))
		emitState("55b_reclaim_by_other", f)
	}
	{ // 56: self-transfer is a real move — bumps last_set_mutation_height
		f := mintedF(0xAA, "bar", 10, 1500)
		f.begin(12, 1600)
		f.tx(0, one(A, bTransferAll(A.h160)))
		emitState("56_self_transfer_bumps_mut", f)
	}
	{ // 57: fee oracle with block_bytes==0 → /0 guard substitutes divisor 1
		n := 1000
		cb, sub, by := make([]int64, n), make([]int64, n), make([]int64, n)
		for i := 0; i < n; i++ {
			sub[i], cb[i], by[i] = 1_000_000_000_000, 1_000_000_005_000, 0
		}
		emitU64("57_oracle_zero_bytes", oracleRate(cb, sub, by))
	}
	{ // 58: CLAIM burn near 2^64 at rate=DUST_FLOOR → T overflows, clamps to MAX_LEASE
		f := newScFold()
		f.begin(10, 1000)
		f.blk.rate = 1
		f.tx(0, one(A, bCommit(commitment(salt32(0x95), "foo", A.h160), 0)))
		f.begin(11, 1500)
		f.blk.rate = 1
		f.tx(0, one(A, bClaim(salt32(0x95), "foo", u64max, 0)))
		emitState("58_lease_clamp_huge_burn", f)
	}

	cd := sha256.Sum256(comb)
	fmt.Printf("combined %s\n", hex.EncodeToString(cd[:]))
}
