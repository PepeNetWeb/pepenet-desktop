package main

// forkvectors — the prose-pinned consensus-fork differential vectors (Tier 2).
//
// This impl uses its OWN generator (not gen.c), so it cannot reproduce the
// byte-for-byte seed soak (§5/§6). Instead it cross-validates exactly what the
// PROSE pins: each independent reference impl must independently reproduce the
// spec-mandated outcome for every consensus-critical vector. See
// SPEC-conformance.md §"Two conformance tiers".
//
// Vectors (same set the other reference impls carry):
//   TV-1  COMMIT_EXPIRY boundary is INCLUSIVE (live through commit_time+EXPIRY)
//   TV-5b claim multiplicity — the MINIMUM backing commit tx_index wins
//   TV-6  selection bitmap is LSB-first
//   TV-7  a lapse bumps the owner's set-mutation height → a stale-anchored RENEW drops
//   TV-8  a locked (LISTED) name is selectively skipped, not freed
//   M9    TRADE settles via its named parties even when vin[0] (acting id) is ⊥
//   H8    a used commit lingers in the table until the COMMIT_EXPIRY prune
//   H3    a set-mutation row persists after the owner's set empties
//
// Each vector asserts the outcome; the runner greps for "0 diverge".

import (
	"fmt"
	"os"
)

var fvDiverge int
var fvMatch int

func fvCheck(cond bool, vec, msg string) {
	if cond {
		fvMatch++
	} else {
		fvDiverge++
		fmt.Printf("DIVERGE %s: %s\n", vec, msg)
	}
}

// bottom (⊥) identity: a vin that failed §4 / SIGHASH_ALL.
func bottomID() Identity { return Identity{ok: false} }

func runForkvectors() {
	fvTV1()
	fvTV5b()
	fvTV6()
	fvTV7()
	fvTV8()
	fvM9()
	fvH8()
	fvH3()
	fmt.Printf("forkvectors: %d match, %d diverge\n", fvMatch, fvDiverge)
	if fvDiverge != 0 {
		os.Exit(1)
	}
}

// TV-1: the COMMIT_EXPIRY window is INCLUSIVE. A claim at MTP == commit_time +
// COMMIT_EXPIRY still sees a live commit; one tick later the pre-block prune has
// removed it and the claim drops.
func fvTV1() {
	A := idOf(1, 0)
	salt := salt32(0x11)
	build := func(claimMTP int64) *FoldState {
		s := newState()
		s.applyBlock(blk(1, T0, tx1(0, A, 0, commitPayload(salt, "alpha", A.h160))))
		s.applyBlock(blk(2, claimMTP, tx1(0, A, 30, claimPayload(salt, "alpha"))))
		return s
	}
	// commit_time = T0. boundary = T0 + COMMIT_EXPIRY (inclusive → live).
	sOK := build(T0 + COMMIT_EXPIRY)
	_, ok := ownerOf(sOK, "alpha")
	fvCheck(ok, "TV-1", "claim at commit_time+COMMIT_EXPIRY must succeed (inclusive window)")
	// one tick past → pruned in pre-block → claim drops.
	sNo := build(T0 + COMMIT_EXPIRY + 1)
	_, ok2 := ownerOf(sNo, "alpha")
	fvCheck(!ok2, "TV-1", "claim one tick past the window must drop (commit pruned)")
}

// TV-5b: an author may post the same commitment multiple times; the claim's
// priority uses the MINIMUM backing commit tx_index, so A (commits at tx0 & tx2)
// displaces B (commit at tx1) even though B's claim is applied first.
func fvTV5b() {
	A := idOf(1, 0)
	B := idOf(2, 0)
	saltA := salt32(0xAA)
	saltB := salt32(0xBB)
	s := newState()
	s.applyBlock(blk(1, T0,
		tx1(0, A, 0, commitPayload(saltA, "hot", A.h160)), // A commit tx_index 0
		tx1(1, B, 0, commitPayload(saltB, "hot", B.h160)), // B commit tx_index 1
		tx1(2, A, 0, commitPayload(saltA, "hot", A.h160)), // A duplicate commit tx_index 2
	))
	s.applyBlock(blk(2, T0+300,
		tx1(0, B, 30, claimPayload(saltB, "hot")), // B claims first
		tx1(1, A, 30, claimPayload(saltA, "hot")), // A displaces — min commit tx_index 0 < 1
	))
	o, _ := ownerOf(s, "hot")
	fvCheck(o == A.h160, "TV-5b", "minimum backing commit tx_index (A=0) wins, not max (2) or claim order")
}

// TV-6: the selection bitmap is LSB-first. flags=0x05 selects bits 0 and 2.
func fvTV6() {
	A := idOf(1, 0)
	B := idOf(2, 0)
	s := claimThree(A) // owns n0,n1,n2 (lex order), A.mut = 2
	H := int64(2)
	body := append(append([]byte{}, B.h160[:]...), leBytes40(H)...)
	body = append(body, 0x05) // bits 0,2 LSB-first
	s.applyBlock(blk(3, T0+600, tx1(0, A, 0, payload(OP_TRANSFER, body...))))
	o0, _ := ownerOf(s, "n0")
	o1, _ := ownerOf(s, "n1")
	o2, _ := ownerOf(s, "n2")
	fvCheck(o0 == B.h160 && o2 == B.h160 && o1 == A.h160,
		"TV-6", "flags=0x05 selects n0,n2 (LSB-first); an MSB-first reader forks")
}

// TV-7: a lapse in the pre-block phase bumps the owner's last_set_mutation_height
// to the connecting height, so a RENEW carrying a stale anchor (valid before the
// lapse) fails the anchor guard and drops — the name's lease is unchanged.
func fvTV7() {
	A := idOf(1, 0)
	s := newState()
	s.applyBlock(blk(1, T0,
		tx1(0, A, 0, commitPayload(salt32(0x40), "n0", A.h160)),
		tx1(1, A, 0, commitPayload(salt32(0x41), "n1", A.h160)),
	))
	// n0 gets a 1-day lease; n1 a long (300-day) lease. A.mut = 2.
	s.applyBlock(blk(2, T0+300,
		tx1(0, A, 1, claimPayload(salt32(0x40), "n0")),
		tx1(1, A, 300, claimPayload(salt32(0x41), "n1")),
	))
	n1Before := s.names["n1"].leaseExpiry
	// block 3 at n0's expiry: pre-block lapses n0 → bumps A.mut to 3. In the same
	// block A submits an all-safe RENEW anchored at height 2 (the pre-lapse set).
	lapseMTP := (T0 + 300) + 1*BILLING_UNIT
	renewBody := leBytes40(2) // all-safe, anchor = 2 (stale)
	s.applyBlock(blk(3, lapseMTP, tx1(0, A, 10, payload(OP_RENEW, renewBody...))))
	_, n0ok := ownerOf(s, "n0")
	fvCheck(!n0ok, "TV-7", "n0 lapses in the pre-block phase")
	fvCheck(s.muts[A.h160] == 3, "TV-7", "the lapse bumps A's set-mutation height to the connecting height (3)")
	fvCheck(s.names["n1"] != nil && s.names["n1"].leaseExpiry == n1Before,
		"TV-7", "the stale-anchored RENEW (anchor=2 < mut=3) drops; n1's lease is unchanged")
}

// TV-8: a RELEASE-all selectively SKIPS a LISTED (locked) name instead of freeing it.
func fvTV8() {
	A := idOf(1, 0)
	s := claimThree(A)
	// list n1 (lock it). 30-day tail covers the window comfortably.
	sellBody := append(append(leBytes64(3), leBytes32(0)...), "n1"...)
	s.applyBlock(blk(3, T0+600, tx1(0, A, 0, payload(OP_SELL, sellBody...))))
	// RELEASE all three (flags 0x07), anchor = 2 (SELL is not a set-mutation).
	relBody := append(leBytes40(2), 0x07)
	s.applyBlock(blk(4, T0+900, tx1(0, A, 0, payload(OP_RELEASE, relBody...))))
	_, ok0 := ownerOf(s, "n0")
	_, ok2 := ownerOf(s, "n2")
	r1 := s.names["n1"]
	fvCheck(!ok0 && !ok2, "TV-8", "RELEASE frees the unlocked n0,n2")
	fvCheck(r1 != nil && r1.st == ST_LISTED, "TV-8", "RELEASE skips the locked (LISTED) n1, not freeing it")
}

// M9: TRADE is attributed to its named parties vin[idxA]/vin[idxB], NOT the tx's
// acting identity, so a TRADE whose vin[0] is ⊥ still settles.
func fvM9() {
	A := idOf(1, 0)
	B := idOf(2, 0)
	s := newState()
	mintTo(s, A, "alpha", 0xA0)
	mintTo(s, B, "beta", 0xB0)
	// inputs: vin0 = ⊥ (failed §4), vin1 = A, vin2 = B. TRADE idxA=1, idxB=2.
	body := append([]byte{0x01, 0x02}, "alpha,beta"...)
	tx := FoldTx{txIndex: 0, inputs: []Identity{bottomID(), A, B},
		carriers: []FoldCarrier{carrier(0, 0, payload(OP_TRADE, body...))}}
	h := s.curHeight + 1
	s.applyBlock(blk(h, T0+100000, tx))
	oa, _ := ownerOf(s, "alpha")
	ob, _ := ownerOf(s, "beta")
	fvCheck(oa == B.h160 && ob == A.h160,
		"M9", "TRADE settles via named parties even when vin[0] acting identity is ⊥")
}

// H8: a commit consumed by a successful claim is NOT removed at claim time; it
// lingers in the commits table until the COMMIT_EXPIRY pre-block prune.
func fvH8() {
	A := idOf(1, 0)
	salt := salt32(0x11)
	s := newState()
	s.applyBlock(blk(1, T0, tx1(0, A, 0, commitPayload(salt, "alpha", A.h160))))
	s.applyBlock(blk(2, T0+300, tx1(0, A, 30, claimPayload(salt, "alpha"))))
	_, ok := ownerOf(s, "alpha")
	fvCheck(ok, "H8", "claim succeeds")
	fvCheck(len(s.commits) == 1, "H8", "the used commit lingers in the table after the claim")
	// advance past commit_time+COMMIT_EXPIRY → pre-block prune removes it.
	s.applyBlock(blk(3, T0+COMMIT_EXPIRY+1))
	fvCheck(len(s.commits) == 0, "H8", "the lingering commit is pruned once MTP passes commit_time+COMMIT_EXPIRY")
	_, stillOwned := ownerOf(s, "alpha")
	fvCheck(stillOwned, "H8", "pruning the commit does not affect the already-minted name")
}

// H3: a set-mutation (last_set_mutation_height) row is never pruned — it persists
// even after the owner's live name set falls to empty.
func fvH3() {
	A := idOf(1, 0)
	salt := salt32(0x11)
	s := newState()
	s.applyBlock(blk(1, T0, tx1(0, A, 0, commitPayload(salt, "solo", A.h160))))
	s.applyBlock(blk(2, T0+300, tx1(0, A, 1, claimPayload(salt, "solo")))) // 1-day lease
	// lapse it.
	s.applyBlock(blk(3, (T0+300)+1*BILLING_UNIT))
	_, ok := ownerOf(s, "solo")
	mh, present := s.muts[A.h160]
	fvCheck(!ok, "H3", "A's only name lapses → A owns nothing")
	fvCheck(present && mh == 3, "H3", "A's set-mutation row persists (stamped at the lapse height 3) after the set empties")
}
