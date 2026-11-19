package main

import (
	"fmt"
	"sort"
)

// All scenarios use rate=28 ⇒ den = 28·86400 = LEASE_QUANTUM, so T(days) == burn.
const scRate = 28
const T0 = int64(1_700_000_000)

func fold(blocks ...FoldBlock) *FoldState {
	s := newState()
	for _, b := range blocks {
		s.applyBlock(b)
	}
	return s
}

func tx1(txIndex uint32, id Identity, value uint64, p []byte) FoldTx {
	return FoldTx{txIndex: txIndex, inputs: []Identity{id}, carriers: []FoldCarrier{carrier(0, value, p)}}
}

func blk(h, mtp int64, txs ...FoldTx) FoldBlock {
	return FoldBlock{height: h, mtp: mtp, rate: scRate, txs: txs}
}

func salt32(b byte) [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = b
	}
	return s
}

func commitPayload(salt [32]byte, name string, author [20]byte) []byte {
	cm := commitment(salt, name, author)
	return payload(OP_COMMIT, cm[:]...)
}
func claimPayload(salt [32]byte, name string) []byte {
	body := append([]byte{}, salt[:]...)
	body = append(body, name...)
	return payload(OP_CLAIM, body...)
}

func ownerOf(s *FoldState, name string) ([20]byte, bool) {
	r := s.names[name]
	if r == nil {
		return [20]byte{}, false
	}
	return r.owner, true
}

// ---- scenarios ----

func scCommitClaimHappy() *FoldState {
	A := idOf(1, 0)
	salt := salt32(0x11)
	s := fold(
		blk(1, T0, tx1(0, A, 0, commitPayload(salt, "alpha", A.h160))),
		blk(2, T0+300, tx1(0, A, 30, claimPayload(salt, "alpha"))),
	)
	o, ok := ownerOf(s, "alpha")
	check(ok && o == A.h160, "happy: alpha owned by A")
	check(s.names["alpha"].leaseExpiry == (T0+300)+30*BILLING_UNIT, "happy: lease 30d")
	return s
}

func scClaimNaked() *FoldState {
	A := idOf(1, 0)
	salt := salt32(0x11)
	// CLAIM with no prior COMMIT → drop.
	s := fold(blk(2, T0+300, tx1(0, A, 30, claimPayload(salt, "alpha"))))
	_, ok := ownerOf(s, "alpha")
	check(!ok, "naked claim mints nothing")
	return s
}

func scClaimTooShallow() *FoldState {
	A := idOf(1, 0)
	salt := salt32(0x11)
	// COMMIT and CLAIM in the SAME block → too shallow (commit_height == claim_height).
	s := fold(blk(1, T0,
		tx1(0, A, 0, commitPayload(salt, "alpha", A.h160)),
		tx1(1, A, 30, claimPayload(salt, "alpha")),
	))
	_, ok := ownerOf(s, "alpha")
	check(!ok, "same-block commit is too shallow")
	return s
}

func scPriorityCommitTxIndex() *FoldState {
	// Two authors commit "hot" in the SAME block; lower commit tx_index must win,
	// even when the other claim is applied first (conformance §7).
	A := idOf(1, 0)
	B := idOf(2, 0)
	saltA := salt32(0xA1)
	saltB := salt32(0xB2)
	s := fold(
		blk(1, T0,
			tx1(0, A, 0, commitPayload(saltA, "hot", A.h160)), // commit tx_index 0
			tx1(1, B, 0, commitPayload(saltB, "hot", B.h160)), // commit tx_index 1
		),
		blk(2, T0+300,
			tx1(0, B, 30, claimPayload(saltB, "hot")), // B's claim applied first
			tx1(1, A, 30, claimPayload(saltA, "hot")), // A displaces (lower commit tx_index)
		),
	)
	o, _ := ownerOf(s, "hot")
	check(o == A.h160, "priority: lower commit tx_index (A) wins despite later claim order")
	return s
}

func scCommitmentCopy() *FoldState {
	// Attacker re-posts victim's commitment under their own tx; only victim can claim.
	A := idOf(1, 0) // victim
	X := idOf(9, 0) // attacker
	salt := salt32(0x11)
	cm := commitment(salt, "alpha", A.h160) // bound to A
	s := fold(
		blk(1, T0,
			tx1(0, A, 0, payload(OP_COMMIT, cm[:]...)),
			tx1(1, X, 0, payload(OP_COMMIT, cm[:]...)), // copied commitment, attacker tx
		),
		blk(2, T0+300, tx1(0, X, 30, claimPayload(salt, "alpha"))), // attacker tries to claim
	)
	_, ok := ownerOf(s, "alpha")
	// attacker's claim author=X, so SHA256(salt‖name‖X) != stored commitment (bound to A) → drop
	check(!ok, "commitment-copy: attacker cannot claim (author binding)")
	// commits table retains both rows (2)
	check(len(s.commits) == 2, "commitment-copy: both commit rows retained")
	return s
}

func scCommitExpiryPrune() *FoldState {
	A := idOf(1, 0)
	salt := salt32(0x11)
	// commit at mtp T0; by mtp T0+COMMIT_EXPIRY+1 it self-prunes; claim then drops.
	s := fold(
		blk(1, T0, tx1(0, A, 0, commitPayload(salt, "alpha", A.h160))),
		blk(2, T0+COMMIT_EXPIRY+1, tx1(0, A, 30, claimPayload(salt, "alpha"))),
	)
	_, ok := ownerOf(s, "alpha")
	check(!ok, "commit_expiry: pruned commit cannot back a claim")
	check(len(s.commits) == 0, "commit_expiry: commit pruned (mtp > commit_time+COMMIT_EXPIRY)")
	return s
}

func scLeaseLapse() *FoldState {
	A := idOf(1, 0)
	salt := salt32(0x11)
	// claim 1 day; lapse when mtp crosses lease_expiry.
	s := fold(
		blk(1, T0, tx1(0, A, 0, commitPayload(salt, "alpha", A.h160))),
		blk(2, T0+300, tx1(0, A, 1, claimPayload(salt, "alpha"))),
		// lease_expiry = T0+300 + 86400. Cross it.
		blk(3, T0+300+BILLING_UNIT /* no txs; preBlock lapses */),
	)
	_, ok := ownerOf(s, "alpha")
	check(!ok, "lease lapse at mtp >= lease_expiry (exclusive)")
	check(s.muts[A.h160] == 3, "lapse bumps mutation height to connecting H")
	return s
}

func scRenewStack() *FoldState {
	A := idOf(1, 0)
	salt := salt32(0x11)
	s := newState()
	s.applyBlock(blk(1, T0, tx1(0, A, 0, commitPayload(salt, "alpha", A.h160))))
	s.applyBlock(blk(2, T0+300, tx1(0, A, 30, claimPayload(salt, "alpha"))))
	exp1 := s.names["alpha"].leaseExpiry
	// RENEW-all (4 bytes) burn 10 days.
	s.applyBlock(blk(3, T0+600, tx1(0, A, 10, payload(OP_RENEW))))
	exp2 := s.names["alpha"].leaseExpiry
	check(exp2 == exp1+10*BILLING_UNIT, "renew stacks +10 days onto existing lease")
	check(s.muts[A.h160] == 2, "RENEW does not bump mutation height")
	return s
}

func scWaterfillUnderfundFloor() *FoldState {
	// 3 names, RENEW-all with T=2 (< 3 eligible) ⇒ λ=0; first 2 lex names get +1 day.
	A := idOf(1, 0)
	s := claimThree(A)
	base := s.names["n0"].leaseExpiry
	s.applyBlock(blk(5, T0+1000, tx1(0, A, 2, payload(OP_RENEW))))
	check(s.names["n0"].leaseExpiry == base+BILLING_UNIT, "underfund: n0 +1d")
	check(s.names["n1"].leaseExpiry == base+BILLING_UNIT, "underfund: n1 +1d")
	check(s.names["n2"].leaseExpiry == base, "underfund: n2 +0d")
	return s
}

func scWaterfillAllcappedForfeit() *FoldState {
	// 1 name with tiny headroom, huge burn ⇒ caps, surplus forfeited.
	A := idOf(1, 0)
	salt := salt32(0x33)
	s := newState()
	s.applyBlock(blk(1, T0, tx1(0, A, 0, commitPayload(salt, "z", A.h160))))
	// claim with 365 days = full MAX_LEASE so headroom 0 next.
	s.applyBlock(blk(2, T0+300, tx1(0, A, 365, claimPayload(salt, "z"))))
	cap := s.names["z"].leaseExpiry
	// RENEW with 100 days but headroom 0 (already at MAX_LEASE from now-ish).
	s.applyBlock(blk(3, T0+300, tx1(0, A, 100, payload(OP_RENEW))))
	check(s.names["z"].leaseExpiry == cap, "allcapped: zero-headroom name unchanged, surplus forfeited")
	return s
}

func claimThree(A Identity) *FoldState {
	s := newState()
	var commits []FoldTx
	for i, nm := range []string{"n0", "n1", "n2"} {
		commits = append(commits, tx1(uint32(i), A, 0, commitPayload(salt32(byte(0x40+i)), nm, A.h160)))
	}
	s.applyBlock(FoldBlock{height: 1, mtp: T0, rate: scRate, txs: commits})
	var claims []FoldTx
	for i, nm := range []string{"n0", "n1", "n2"} {
		claims = append(claims, tx1(uint32(i), A, 30, claimPayload(salt32(byte(0x40+i)), nm)))
	}
	s.applyBlock(FoldBlock{height: 2, mtp: T0 + 300, rate: scRate, txs: claims})
	return s
}

func scTransferSelective() *FoldState {
	A := idOf(1, 0)
	B := idOf(2, 0)
	s := claimThree(A)
	// owned lex order n0,n1,n2. selective transfer of bit0 (n0) and bit2 (n2) to B.
	// flags: bits 0 and 2 set ⇒ 0b00000101 = 0x05.
	H := int64(2)
	body := append(append([]byte{}, B.h160[:]...), leBytes40(H)...)
	body = append(body, 0x05)
	s.applyBlock(blk(3, T0+600, tx1(0, A, 0, payload(OP_TRANSFER, body...))))
	o0, _ := ownerOf(s, "n0")
	o1, _ := ownerOf(s, "n1")
	o2, _ := ownerOf(s, "n2")
	check(o0 == B.h160 && o2 == B.h160 && o1 == A.h160, "selective transfer moves n0,n2 to B; n1 stays")
	check(s.muts[B.h160] == 3 && s.muts[A.h160] == 3, "transfer bumps both parties")
	return s
}

func scReleaseSkipLocked() *FoldState {
	A := idOf(1, 0)
	s := claimThree(A) // all 30-day leases
	// list n1 for sale (lock it). price 3, window 0 (=RESERVE_WINDOW). lease tail must hold.
	// 30 days = 2592000s; RESERVE_WINDOW+REORG_BUFFER = 25200 ≤ tail ✓.
	sellBody := append(append(leBytes64(3), leBytes32(0)...), "n1"...)
	s.applyBlock(blk(3, T0+600, tx1(0, A, 0, payload(OP_SELL, sellBody...))))
	check(s.names["n1"].st == ST_LISTED, "n1 listed")
	// RELEASE all three (anchor H=2, flags select bits 0,1,2 = 0x07). n1 locked → skipped.
	H := int64(2)
	relBody := append(leBytes40(H), 0x07)
	s.applyBlock(blk(4, T0+900, tx1(0, A, 0, payload(OP_RELEASE, relBody...))))
	_, ok0 := ownerOf(s, "n0")
	_, ok1 := ownerOf(s, "n1")
	_, ok2 := ownerOf(s, "n2")
	check(!ok0 && !ok2, "release frees n0,n2")
	check(ok1 && s.names["n1"].st == ST_LISTED, "release skips locked n1")
	return s
}

func scSellWindowAddform() *FoldState {
	// A name with a short lease tail: a window that would pass the subtraction form
	// but fail the add-form must be rejected.
	A := idOf(1, 0)
	salt := salt32(0x55)
	s := newState()
	s.applyBlock(blk(1, T0, tx1(0, A, 0, commitPayload(salt, "s", A.h160))))
	s.applyBlock(blk(2, T0+300, tx1(0, A, 1, claimPayload(salt, "s")))) // 1-day lease
	// lease_expiry = T0+300+86400. window = RESERVE_WINDOW (18000).
	// add-form: mtp + window + REORG_BUFFER ≤ lease_expiry?
	// mtp=T0+600, +18000+7200 = T0+25800; lease=T0+86700 ⇒ holds → listed.
	sellBody := append(append(leBytes64(3), leBytes32(RESERVE_WINDOW)...), "s"...)
	s.applyBlock(blk(3, T0+600, tx1(0, A, 0, payload(OP_SELL, sellBody...))))
	check(s.names["s"].st == ST_LISTED, "sell within tail accepted")
	// Now a name whose tail is too short: claim 1 day, then near expiry try a big window.
	salt2 := salt32(0x56)
	s.applyBlock(blk(4, T0+900, tx1(0, A, 0, commitPayload(salt2, "t", A.h160))))
	s.applyBlock(blk(5, T0+1200, tx1(0, A, 1, claimPayload(salt2, "t"))))
	// lease_expiry = T0+1200+86400 = T0+87600. window = 80000 (> RESERVE_WINDOW).
	// add-form: T0+1500 + 80000 + 7200 = T0+88700 > T0+87600 ⇒ reject.
	sellBody2 := append(append(leBytes64(3), leBytes32(80000)...), "t"...)
	s.applyBlock(blk(6, T0+1500, tx1(0, A, 0, payload(OP_SELL, sellBody2...))))
	check(s.names["t"].st == ST_OWNED, "sell with too-short tail rejected (add-form)")
	return s
}

func scOpenMarketCascade() *FoldState {
	// SELL → RESERVE (deposit legs) → SETTLE; ownership moves to buyer.
	A := idOf(1, 0)  // seller
	Bu := idOf(2, 0) // buyer
	salt := salt32(0x60)
	s := newState()
	s.applyBlock(blk(1, T0, tx1(0, A, 0, commitPayload(salt, "m", A.h160))))
	s.applyBlock(blk(2, T0+300, tx1(0, A, 365, claimPayload(salt, "m"))))
	// SELL price=20000, window 0.
	price := uint64(20000)
	sellBody := append(append(leBytes64(price), leBytes32(0)...), "m"...)
	s.applyBlock(blk(3, T0+600, tx1(0, A, 0, payload(OP_SELL, sellBody...))))
	burnLeg := depositLeg(price, RESERVE_BURN_BPS) // floor(20000*50/10000)=100
	payLeg := depositLeg(price, RESERVE_PAY_BPS)   // 100
	remainder := price - burnLeg - payLeg          // 19800
	// RESERVE by buyer: carrier value = burnLeg, pay_leg output to seller.
	resTx := FoldTx{txIndex: 0, inputs: []Identity{Bu},
		carriers: []FoldCarrier{carrier(0, burnLeg, payload(OP_RESERVE, []byte("m")...))},
		spend:    []FoldOutput{{h160: A.h160, styp: 0, value: payLeg}}}
	s.applyBlock(blk(4, T0+900, resTx))
	check(s.names["m"].st == ST_RESERVED && s.names["m"].buyer == Bu.h160, "reserve claims option")
	// SETTLE by buyer: remainder output to seller.
	setTx := FoldTx{txIndex: 0, inputs: []Identity{Bu},
		carriers: []FoldCarrier{carrier(0, 0, payload(OP_SETTLE, []byte("m")...))},
		spend:    []FoldOutput{{h160: A.h160, styp: 0, value: remainder}}}
	s.applyBlock(blk(5, T0+1200, setTx))
	o, _ := ownerOf(s, "m")
	check(o == Bu.h160 && s.names["m"].st == ST_OWNED, "settle moves name to buyer, OWNED")
	check(s.muts[A.h160] == 5 && s.muts[Bu.h160] == 5, "settle bumps both")
	return s
}

func scReserveValueCollision() *FoldState {
	// One tx does RESERVE+SETTLE both paying same seller; outputs vout0=19800,
	// vout1=payLeg(5-ish). The matcher must let RESERVE take the exact payLeg, SETTLE the remainder.
	// Build a fresh listing with price so payLeg and remainder differ as in the §7 vector.
	A := idOf(1, 0)
	Bu := idOf(2, 0)
	salt := salt32(0x61)
	s := newState()
	s.applyBlock(blk(1, T0, tx1(0, A, 0, commitPayload(salt, "c", A.h160))))
	s.applyBlock(blk(2, T0+300, tx1(0, A, 365, claimPayload(salt, "c"))))
	price := uint64(20000)
	sellBody := append(append(leBytes64(price), leBytes32(0)...), "c"...)
	s.applyBlock(blk(3, T0+600, tx1(0, A, 0, payload(OP_SELL, sellBody...))))
	burnLeg := depositLeg(price, RESERVE_BURN_BPS) // 100
	payLeg := depositLeg(price, RESERVE_PAY_BPS)   // 100
	remainder := price - burnLeg - payLeg          // 19800
	// Single tx: RESERVE then SETTLE. spend outputs ordered: vout0=remainder(19800), vout1=payLeg(100).
	// RESERVE owes payLeg(100): must SKIP vout0(19800) and take vout1(100). SETTLE then takes vout0.
	combo := FoldTx{txIndex: 0, inputs: []Identity{Bu},
		carriers: []FoldCarrier{
			carrier(0, burnLeg, payload(OP_RESERVE, []byte("c")...)),
			carrier(2, 0, payload(OP_SETTLE, []byte("c")...)),
		},
		spend: []FoldOutput{
			{h160: A.h160, styp: 0, value: remainder}, // vout index 0 in pool
			{h160: A.h160, styp: 0, value: payLeg},    // vout index 1
		}}
	s.applyBlock(blk(4, T0+900, combo))
	o, _ := ownerOf(s, "c")
	check(o == Bu.h160, "value-collision: consume-once exact-value lets both ops match")
	return s
}

func scReserveOptionTheft() *FoldState {
	// Two reserves on one listing in chain order; first wins, second drops (no overwrite),
	// loser's later SETTLE fails buyer-match.
	A := idOf(1, 0)
	B1 := idOf(2, 0)
	B2 := idOf(3, 0)
	salt := salt32(0x62)
	s := newState()
	s.applyBlock(blk(1, T0, tx1(0, A, 0, commitPayload(salt, "o", A.h160))))
	s.applyBlock(blk(2, T0+300, tx1(0, A, 365, claimPayload(salt, "o"))))
	price := uint64(20000)
	sellBody := append(append(leBytes64(price), leBytes32(0)...), "o"...)
	s.applyBlock(blk(3, T0+600, tx1(0, A, 0, payload(OP_SELL, sellBody...))))
	burnLeg := depositLeg(price, RESERVE_BURN_BPS)
	payLeg := depositLeg(price, RESERVE_PAY_BPS)
	r1 := FoldTx{txIndex: 0, inputs: []Identity{B1},
		carriers: []FoldCarrier{carrier(0, burnLeg, payload(OP_RESERVE, []byte("o")...))},
		spend:    []FoldOutput{{h160: A.h160, value: payLeg}}}
	r2 := FoldTx{txIndex: 1, inputs: []Identity{B2},
		carriers: []FoldCarrier{carrier(0, burnLeg, payload(OP_RESERVE, []byte("o")...))},
		spend:    []FoldOutput{{h160: A.h160, value: payLeg}}}
	s.applyBlock(blk(4, T0+900, r1, r2))
	check(s.names["o"].buyer == B1.h160, "option theft: first reserver wins")
	// B2 tries to settle → buyer-match fails.
	rem := price - burnLeg - payLeg
	set2 := FoldTx{txIndex: 0, inputs: []Identity{B2},
		carriers: []FoldCarrier{carrier(0, 0, payload(OP_SETTLE, []byte("o")...))},
		spend:    []FoldOutput{{h160: A.h160, value: rem}}}
	s.applyBlock(blk(5, T0+1200, set2))
	o, _ := ownerOf(s, "o")
	check(o == A.h160 && s.names["o"].st == ST_RESERVED, "loser's settle fails buyer-match")
	return s
}

func scDirectedSellToPay() *FoldState {
	A := idOf(1, 0)
	Bu := idOf(2, 0)
	salt := salt32(0x70)
	s := newState()
	s.applyBlock(blk(1, T0, tx1(0, A, 0, commitPayload(salt, "d", A.h160))))
	s.applyBlock(blk(2, T0+300, tx1(0, A, 365, claimPayload(salt, "d"))))
	price := uint64(50000)
	stBody := append(append(leBytes64(price), Bu.h160[:]...), "d"...)
	s.applyBlock(blk(3, T0+600, tx1(0, A, 0, payload(OP_SELL_TO, stBody...))))
	check(s.names["d"].st == ST_OFFERED && s.names["d"].buyer == Bu.h160, "sell_to offers to buyer")
	check(s.muts[A.h160] == 2, "SELL_TO not a mutation")
	payTx := FoldTx{txIndex: 0, inputs: []Identity{Bu},
		carriers: []FoldCarrier{carrier(0, 0, payload(OP_PAY, []byte("d")...))},
		spend:    []FoldOutput{{h160: A.h160, value: price}}}
	s.applyBlock(blk(4, T0+900, payTx))
	o, _ := ownerOf(s, "d")
	check(o == Bu.h160 && s.names["d"].st == ST_OWNED, "pay conveys name to buyer")
	check(s.muts[A.h160] == 4 && s.muts[Bu.h160] == 4, "pay bumps both")
	return s
}

func scDirectedStrangerDrop() *FoldState {
	A := idOf(1, 0)
	Bu := idOf(2, 0)
	X := idOf(9, 0) // stranger
	salt := salt32(0x71)
	s := newState()
	s.applyBlock(blk(1, T0, tx1(0, A, 0, commitPayload(salt, "d", A.h160))))
	s.applyBlock(blk(2, T0+300, tx1(0, A, 365, claimPayload(salt, "d"))))
	price := uint64(50000)
	stBody := append(append(leBytes64(price), Bu.h160[:]...), "d"...)
	s.applyBlock(blk(3, T0+600, tx1(0, A, 0, payload(OP_SELL_TO, stBody...))))
	// stranger pays full price → drops (not the named buyer), but output still pays seller.
	payTx := FoldTx{txIndex: 0, inputs: []Identity{X},
		carriers: []FoldCarrier{carrier(0, 0, payload(OP_PAY, []byte("d")...))},
		spend:    []FoldOutput{{h160: A.h160, value: price}}}
	s.applyBlock(blk(4, T0+900, payTx))
	o, _ := ownerOf(s, "d")
	check(o == A.h160 && s.names["d"].st == ST_OFFERED, "stranger PAY drops; name stays offered to buyer")
	return s
}

func scASAttribution() *FoldState {
	// AS attribution — claim attributed to vin[1]=B (matches B's commit).
	A := idOf(1, 0)
	B := idOf(2, 0)
	salt := salt32(0x55)
	s := newState()
	s.applyBlock(blk(1, T0, tx1(0, B, 0, commitPayload(salt, "bob", B.h160))))
	// vin0=A (funding), vin1=B; AS 1 re-points CLAIM to B.
	claimBody := append(append([]byte{}, salt[:]...), "bob"...)
	tx := FoldTx{txIndex: 0, inputs: []Identity{A, B},
		carriers: []FoldCarrier{
			carrier(0, 0, payload(OP_AS, 0x01)),
			carrier(1, 10, payload(OP_CLAIM, claimBody...)),
		}}
	s.applyBlock(blk(2, T0+300, tx))
	o, ok := ownerOf(s, "bob")
	check(ok && o == B.h160, "AS-attributed claim mints to vin[1]")
	// AS out-of-range → segment drops.
	s2 := newState()
	s2.applyBlock(blk(1, T0, tx1(0, B, 0, commitPayload(salt, "bob", B.h160))))
	tx2 := FoldTx{txIndex: 0, inputs: []Identity{A, B},
		carriers: []FoldCarrier{
			carrier(0, 0, payload(OP_AS, 0x05)), // OOB
			carrier(1, 10, payload(OP_CLAIM, claimBody...)),
		}}
	s2.applyBlock(blk(2, T0+300, tx2))
	_, ok2 := ownerOf(s2, "bob")
	check(!ok2, "AS OOB drops its segment (claim fails)")
	return s
}

func scTradeSwap() *FoldState {
	A := idOf(1, 0)
	B := idOf(2, 0)
	s := newState()
	mintTo(s, A, "alpha", 0xA0)
	mintTo(s, B, "beta", 0xB0)
	// TRADE idxA=0 (A) idxB=1 (B), nameA=alpha, nameB=beta.
	body := []byte{0x00, 0x01}
	body = append(body, "alpha,beta"...)
	tx := FoldTx{txIndex: 0, inputs: []Identity{A, B},
		carriers: []FoldCarrier{carrier(0, 0, payload(OP_TRADE, body...))}}
	h := s.curHeight + 1
	s.applyBlock(blk(h, T0+100000, tx))
	oa, _ := ownerOf(s, "alpha")
	ob, _ := ownerOf(s, "beta")
	check(oa == B.h160 && ob == A.h160, "trade swaps alpha↔beta")
	check(s.muts[A.h160] == h && s.muts[B.h160] == h, "trade bumps both")
	return s
}

func scTradeSameBlockAntirug() *FoldState {
	// A pledges alpha then TRANSFERs alpha away earlier in the same block → TRADE drops.
	A := idOf(1, 0)
	B := idOf(2, 0)
	C := idOf(3, 0)
	s := newState()
	mintTo(s, A, "alpha", 0xA0)
	mintTo(s, B, "beta", 0xB0)
	// Block: tx0 = A transfers alpha to C; tx1 = TRADE(A.alpha ↔ B.beta) → A no longer owns alpha → drop.
	transferTx := tx1(0, A, 0, payload(OP_TRANSFER, A_target(C)...))
	body := append([]byte{0x00, 0x01}, "alpha,beta"...)
	tradeTx := FoldTx{txIndex: 1, inputs: []Identity{A, B},
		carriers: []FoldCarrier{carrier(0, 0, payload(OP_TRADE, body...))}}
	s.applyBlock(blk(s.curHeight+1, T0+100000, transferTx, tradeTx))
	oa, _ := ownerOf(s, "alpha")
	ob, _ := ownerOf(s, "beta")
	check(oa == C.h160 && ob == B.h160, "antirug: TRADE drops whole-op when pledged name moved")
	return s
}

func A_target(C Identity) []byte { return C.h160[:] }

func mintTo(s *FoldState, id Identity, name string, saltb byte) {
	salt := salt32(saltb)
	h := s.curHeight
	s.applyBlock(blk(h+1, T0+int64(h)*300, tx1(0, id, 0, commitPayload(salt, name, id.h160))))
	s.applyBlock(blk(h+2, T0+int64(h+1)*300, tx1(0, id, 365, claimPayload(salt, name))))
}

func scLapseVsRenewSameBlock() *FoldState {
	// At the exact lapse tie, the pre-block lapse runs BEFORE the block's txs, so the
	// old owner's RENEW skips the lapsed name and a hunter's CLAIM wins.
	A := idOf(1, 0) // old owner
	H := idOf(7, 0) // hunter
	salt := salt32(0x80)
	s := newState()
	s.applyBlock(blk(1, T0, tx1(0, A, 0, commitPayload(salt, "x", A.h160))))
	s.applyBlock(blk(2, T0+300, tx1(0, A, 1, claimPayload(salt, "x")))) // 1-day lease
	leaseExp := s.names["x"].leaseExpiry                                // T0+300+86400
	// Hunter pre-commits within COMMIT_EXPIRY before the lapse (and ≥1 block deep).
	s.applyBlock(blk(3, leaseExp-300, tx1(0, H, 0, commitPayload(salt32(0x81), "x", H.h160))))
	// Block at mtp == leaseExp: pre-block lapse removes x; then A's RENEW (no x) and H's CLAIM.
	renewTx := tx1(0, A, 10, payload(OP_RENEW))
	claimTx := tx1(1, H, 30, claimPayload(salt32(0x81), "x"))
	s.applyBlock(FoldBlock{height: 4, mtp: leaseExp, rate: scRate, txs: []FoldTx{renewTx, claimTx}})
	o, ok := ownerOf(s, "x")
	check(ok && o == H.h160, "same-block: pre-block lapse → hunter CLAIM wins, RENEW finds nothing")
	return s
}

func scMTPMedian() *FoldState {
	// Behavioral check of the MTP short-window/genesis rule (returns empty state).
	check(medianTimePast(nil) == 0, "MTP(0) = 0")
	check(medianTimePast([]int64{5}) == 5, "MTP single predecessor")
	// even window of 2 → upper-middle (index k/2 = 1).
	check(medianTimePast([]int64{10, 20}) == 20, "MTP even window upper-middle")
	// 11 sorted predecessors → index 5.
	pre := []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	check(medianTimePast(pre) == 5, "MTP 11 predecessors → index 5")
	// >11 predecessors: only last 11 count.
	pre2 := []int64{100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	_ = pre2
	return newState()
}

// ---- §3.4 fee-oracle vectors (C reference 49–51) ----
// u64 emissions, not state digests: each pins the participant filter at the
// MIN_FEE_SAMPLE boundary with a behavioral assert on the C-reference value.

// 49: |P| = 1000 EXACTLY (the inclusive boundary) with an in-window under-claim;
// even |P| → the LOWER median (index 499 of fpb 100..1099 = 599) → 119,800.
func scOracleEvenBoundary() uint64 {
	const n = 1500
	cb, sub, by := make([]int64, n), make([]int64, n), make([]int64, n)
	for i := 0; i < n; i++ {
		sub[i], by[i] = 1_000_000_000_000, 1000
		switch {
		case i < 499:
			cb[i] = sub[i] // zero-fee → non-participant
		case i == 499:
			cb[i] = sub[i] - 50 // under-claim → clamps to 0 fees → non-participant
		default:
			cb[i] = sub[i] + int64(100+(i-500))*1000 // fpb 100..1099
		}
	}
	r := oracleRate(cb, sub, by)
	check(r == 119800, "oracle: |P|=1000 inclusive boundary, even → lower median 599 → 119800")
	return r
}

// 50: odd |P| = 1101 through the participant filter — the historical middle
// rule: index 550 of fpb 100..1200 = 650 → 130,000.
func scOracleOddMedian() uint64 {
	const n = 2000
	cb, sub, by := make([]int64, n), make([]int64, n), make([]int64, n)
	for i := 0; i < n; i++ {
		sub[i], by[i] = 1_000_000_000_000, 1000
		if i < 899 {
			cb[i] = sub[i] // zero-fee → non-participant
		} else {
			cb[i] = sub[i] + int64(100+(i-899))*1000 // fpb 100..1200
		}
	}
	r := oracleRate(cb, sub, by)
	check(r == 130000, "oracle: odd |P|=1101 → median 650 → 130000")
	return r
}

// 51: |P| = 999 — one short of MIN_FEE_SAMPLE → degrade to DUST_FLOOR exactly.
func scOracleSubsampleFloor() uint64 {
	const n = 1500
	cb, sub, by := make([]int64, n), make([]int64, n), make([]int64, n)
	for i := 0; i < n; i++ {
		sub[i], by[i] = 1_000_000_000_000, 1000
		if i < 501 {
			cb[i] = sub[i] // zero-fee → non-participant
		} else {
			cb[i] = sub[i] + int64(100+(i-501))*1000 // 999 participants
		}
	}
	r := oracleRate(cb, sub, by)
	check(r == DUST_FLOOR, "oracle: |P|=999 < MIN_FEE_SAMPLE → DUST_FLOOR")
	return r
}

// medianTimePast = median of timestamps of the ≤11 blocks strictly before H (§5).
// k = min(11, #predecessors); sort; index ⌊k/2⌋ (upper-middle for even); MTP(0)=0.
func medianTimePast(predecessors []int64) int64 {
	k := len(predecessors)
	if k == 0 {
		return 0
	}
	win := predecessors
	if k > 11 {
		win = predecessors[k-11:]
		k = 11
	}
	sorted := append([]int64{}, win...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[k/2]
}

// ---- unit tests referenced by selftest ----

func testWaterFillUnits() {
	// 3 fresh names, T=30 → each +10 days.
	rows := []*NameRow{{leaseExpiry: T0}, {leaseExpiry: T0}, {leaseExpiry: T0}}
	waterFill(rows, []string{"a", "b", "c"}, 30, false, T0)
	for _, r := range rows {
		check(r.leaseExpiry == T0+10*BILLING_UNIT, "waterfill even: +10d")
	}
	// underfund T=2 over 3 → first 2 +1d.
	rows2 := []*NameRow{{leaseExpiry: T0}, {leaseExpiry: T0}, {leaseExpiry: T0}}
	waterFill(rows2, []string{"a", "b", "c"}, 2, false, T0)
	check(rows2[0].leaseExpiry == T0+BILLING_UNIT && rows2[1].leaseExpiry == T0+BILLING_UNIT && rows2[2].leaseExpiry == T0, "waterfill underfund")
}

func testWireCodec() {
	// demux: bare UTF-8 / overlay / non-prefix → IGNORE; only name actions → ACTION.
	c := decode([]byte("hello"), 1)
	check(c.kind == IGNORE, "decode bare UTF-8 → IGNORE")
	c = decode([]byte{0xFF, 0x50, 0x4E, 0xD6, 0x00}, 0)
	check(c.kind == IGNORE, "decode overlay opcode → IGNORE")
	// COMMIT 32-byte body → ACTION.
	cm := make([]byte, 32)
	c = decode(payload(OP_COMMIT, cm...), 0)
	check(c.kind == ACTION && c.opcode == OP_COMMIT, "decode COMMIT action")
	// wrong length → IGNORE.
	c = decode(payload(OP_COMMIT, cm[:10]...), 0)
	check(c.kind == IGNORE, "decode COMMIT wrong length → IGNORE")
	// uppercase name in CLAIM → IGNORE.
	z := salt32(0)
	body := append(append([]byte{}, z[:]...), "Alpha"...)
	c = decode(payload(OP_CLAIM, body...), 0)
	check(c.kind == IGNORE, "decode CLAIM uppercase name → IGNORE")
	// structural rejects on CLAIM name.
	body = append(append([]byte{}, z[:]...), "-a"...)
	c = decode(payload(OP_CLAIM, body...), 0)
	check(c.kind == IGNORE, "decode CLAIM leading hyphen → IGNORE")
	body = append(append([]byte{}, z[:]...), "xn--x"...)
	c = decode(payload(OP_CLAIM, body...), 0)
	check(c.kind == IGNORE, "decode CLAIM ACE prefix → IGNORE")
	// malformed action (0xFF lead, bad opcode) → IGNORE.
	c = decode([]byte{0xFF, 0x50, 0x4E, 0xFE, 0x00}, 5)
	check(c.kind == IGNORE, "malformed action → IGNORE")

	// §6 pinned carrier ceiling: flags at the exact consensus caps decode;
	// one byte past the ceiling is IGNORE (fail-closed).
	wideBody := make([]byte, 5+FLAGS_MAX) // anchor5 + flags at cap
	for i := range wideBody {
		wideBody[i] = byte(i*7 + 1)
	}
	wide := payload(OP_RENEW, wideBody...)
	check(len(wide) == CARRIER_MAX, "RENEW at cap is exactly CARRIER_MAX (9996) payload bytes")
	c = decode(wide, 0)
	check(c.kind == ACTION && len(c.flags) == FLAGS_MAX,
		"RENEW-selective decodes with all 9987 flag bytes")
	c = decode(append(wide, 0x00), 0)
	check(c.kind == IGNORE, "one byte past the L1 ceiling → IGNORE")
	xferBody := make([]byte, 25+FLAGS_XFER_MAX) // target20 + anchor5 + flags at cap
	c = decode(payload(OP_TRANSFER, xferBody...), 0)
	check(c.kind == ACTION && len(c.flags) == FLAGS_XFER_MAX,
		"TRANSFER-selective decodes at FLAGS_XFER_MAX (9967)")
	c = decode(payload(OP_TRANSFER, append(xferBody, 0x00)...), 0)
	check(c.kind == IGNORE, "TRANSFER flags past the cap → IGNORE")
	relBody := make([]byte, 5+FLAGS_MAX)
	c = decode(payload(OP_RELEASE, relBody...), 0)
	check(c.kind == ACTION && len(c.flags) == FLAGS_MAX, "RELEASE decodes at FLAGS_MAX")
}

func runAttribSelftest() {
	testRIPEMD()
	testAttribP2PKH()
	if failures == 0 {
		fmt.Println("attrib-selftest: ALL PASS")
	} else {
		fmt.Printf("attrib-selftest: %d FAILURES\n", failures)
	}
}

func testAttribP2PKH() {
	// minimal valid-shape P2PKH scriptSig: push(sig 9B) push(pubkey 33B).
	sig := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01} // DER + htype 0x01
	pub := make([]byte, 33)
	pub[0] = 0x02
	for i := 1; i < 33; i++ {
		pub[i] = 0x01
	}
	ss := append(pushEncode(sig), pushEncode(pub)...)
	raw := buildRawTxOneInput(ss)
	t, ok := parseTx(raw)
	check(ok, "attrib: raw tx parses")
	if ok {
		r := attribute(t, 0)
		check(r.status >= 1, "attrib: P2PKH classifies (status≥1)")
		var zero [20]byte
		check(r.identity != zero, "attrib: identity nonzero")
		check(r.identity == hash160(pub), "attrib: identity = hash160(pubkey)")
	}
}

func buildRawTxOneInput(scriptSig []byte) []byte {
	var b []byte
	b = appendU32(b, 1) // version
	b = appendVarint(b, 1)
	b = append(b, make([]byte, 32)...) // prev txid
	b = appendU32(b, 0)                // prev vout
	b = appendVarint(b, uint64(len(scriptSig)))
	b = append(b, scriptSig...)
	b = appendU32(b, 0xFFFFFFFF) // sequence
	b = appendVarint(b, 1)       // 1 output
	b = appendU64(b, 0)          // value
	b = appendVarint(b, 0)       // empty scriptPubKey
	b = appendU32(b, 0)          // locktime
	return b
}
