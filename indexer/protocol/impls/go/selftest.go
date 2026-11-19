package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
)

var failures int

func check(cond bool, msg string) {
	if !cond {
		failures++
		fmt.Printf("FAIL: %s\n", msg)
	}
}

func checkEq(got, want string, msg string) {
	if got != want {
		failures++
		fmt.Printf("FAIL: %s\n  got=%s\n want=%s\n", msg, got, want)
	}
}

func runSelftest() {
	testPRNG()
	testRIPEMD()
	testWaterFillUnits()
	testOracleRate()
	testWireCodec()
	testSecp256k1KAT()
	testAttribA7OffcurveP2PKH()
	testEcmh()
	testFoldScenarios() // the hand-authored fold battery's behavioral asserts
	testDottedNames()   // §3.1 charset re-pin lock (2026-07-02)

	// empty-state digests (cross-impl pinned, §4 / §13.2).
	empty := newState()
	fmt.Printf("empty_state_digest=%s\n", hexstr(must32(empty.stateDigest())))
	fmt.Printf("empty_state_ecmh=%s\n", hexstr(must32(empty.stateEcmh())))

	if failures == 0 {
		fmt.Println("selftest: ALL PASS")
	} else {
		fmt.Printf("selftest: %d FAILURES\n", failures)
		os.Exit(1)
	}
}

// testOracleRate — §3.4 participant-median units. Windows are built ≥
// MIN_FEE_SAMPLE participants wide so the clamp legs are reached (a small
// window now degrades to DUST_FLOOR before the median/clamp can run).
func testOracleRate() {
	mkWin := func(n int, fill func(i int) int64) (cb, sub, by []int64) {
		cb, sub, by = make([]int64, n), make([]int64, n), make([]int64, n)
		for i := 0; i < n; i++ {
			sub[i], by[i] = 1_000_000_000_000, 1000
			cb[i] = sub[i] + fill(i)
		}
		return
	}
	// 1000 participants all at fpb=1 → median 1 → 1·REF_SIZE = 200 (above the floor).
	cb, sub, by := mkWin(1000, func(i int) int64 { return 1000 })
	check(oracleRate(cb, sub, by) == 200, "oracle: 1000×fpb=1 → 1·REF_SIZE = 200")
	// RATE_CAP clamp: 1000 participants at fpb=600000 → 600000·200 = 1.2e8 > cap.
	cb, sub, by = mkWin(1000, func(i int) int64 { return 600_000 * 1000 })
	check(oracleRate(cb, sub, by) == RATE_CAP, "oracle: median·REF_SIZE past the cap clamps to RATE_CAP")
	// Inclusive-1000 even boundary with an under-claim → lower median 599 → 119800.
	cb, sub, by = mkWin(1500, func(i int) int64 {
		switch {
		case i < 499:
			return 0 // zero-fee → non-participant
		case i == 499:
			return -50 // under-claim → clamps to 0 → non-participant
		default:
			return int64(100+(i-500)) * 1000 // fpb 100..1099
		}
	})
	check(oracleRate(cb, sub, by) == 119800, "oracle: |P|=1000 (inclusive) even → lower median → 119800")
	// 999 participants — one short of MIN_FEE_SAMPLE → DUST_FLOOR degrade.
	cb, sub, by = mkWin(1500, func(i int) int64 {
		if i < 501 {
			return 0
		}
		return int64(100+(i-501)) * 1000
	})
	check(oracleRate(cb, sub, by) == DUST_FLOOR, "oracle: |P|=999 → DUST_FLOOR degrade")
	// Sub-koinu fees floor to 0 AFTER the division → non-participants.
	cb, sub, by = mkWin(2000, func(i int) int64 { return 999 }) // 999/1000 → 0
	check(oracleRate(cb, sub, by) == DUST_FLOOR, "oracle: fees flooring to 0/byte do not participate")
	// Empty window → DUST_FLOOR.
	check(oracleRate(nil, nil, nil) == DUST_FLOOR, "oracle: empty window → DUST_FLOOR")
	// block_bytes=0 hits the division guard (b→1), not a panic.
	cb, sub, by = mkWin(1000, func(i int) int64 { return 5000 })
	for i := range by {
		by[i] = 0
	}
	check(oracleRate(cb, sub, by) == 1_000_000, "oracle: zero-byte block takes the b=1 guard (fpb 5000 → 1e6)")
}

func testPRNG() {
	p := newPRNG(0)
	got := fmt.Sprintf("%016X", p.next())
	checkEq(got, "E220A8397B1DCDAF", "SplitMix64 seed=0 first next()")
}

func testRIPEMD() {
	checkEq(hex.EncodeToString(ripemdBytes("")), "9c1185a5c5e9fc54612808977ee8f548b2258d31", "RIPEMD160(\"\")")
	checkEq(hex.EncodeToString(ripemdBytes("abc")), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", "RIPEMD160(\"abc\")")
	h := hash160([]byte("abc"))
	checkEq(hex.EncodeToString(h[:]), "bb1be98c142444d7a56aa3981c3942a978e4dc33", "hash160(\"abc\")")
}

func ripemdBytes(s string) []byte {
	r := ripemd160([]byte(s))
	return r[:]
}

// testSecp256k1KAT pins the real §4 Strategy-B curve (mirrors C secp_selftest):
// constants, the 2G known-answer, n·G=∞, decompress G, and a sign/verify+tamper
// round-trip. These are what make `attrib-curve`'s digests reproducible.
func testSecp256k1KAT() {
	// N_HALF == N>>1.
	nHalf := new(big.Int).Rsh(secpN, 1)
	check(nHalf.Cmp(secpNH) == 0, "secp: N_HALF == N>>1")
	// G on curve (uncompressed encoding).
	guncomp := append([]byte{0x04}, append(be32(secpGx), be32(secpGy)...)...)
	check(secpOnCurve(guncomp), "secp: G on curve")
	// 2G known-answer.
	g2 := ecMul(big.NewInt(2), ecGenerator())
	check(!g2.isInf(), "secp: 2G not infinity")
	checkEq(hexstr(be32(g2.x)), "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", "secp: 2G.x")
	checkEq(hexstr(be32(g2.y)), "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a", "secp: 2G.y")
	// n·G == ∞.
	check(ecMul(secpN, ecGenerator()).isInf(), "secp: n·G == infinity")
	// decompress G: 0x02 ‖ Gx (Gy even) recovers Gy.
	gcomp := append([]byte{0x02}, be32(secpGx)...)
	gp := pubDecode(gcomp)
	check(gp != nil, "secp: decompress G")
	if gp != nil {
		checkEq(hexstr(be32(gp.y)), hexstr(be32(secpGy)), "secp: decompress Gy")
	}
	// sign/verify round-trip + tamper, over a few deterministic keys.
	for t := 1; t <= 4; t++ {
		priv := make([]byte, 32)
		priv[31] = byte(t*7 + 1)
		pub, ok := secpPubkey(priv)
		check(ok, "secp: pubkey derive")
		msg := make([]byte, 32)
		for i := range msg {
			msg[i] = byte(i*13 + t)
		}
		mh := sha256.Sum256(msg)
		r32, s32, sok := secpEcdsaSign(priv, mh[:])
		check(sok, "secp: sign")
		check(secpEcdsaVerify(mh, r32, s32, pub), "secp: verify round-trip")
		mh2 := mh
		mh2[0] ^= 0x01
		check(!secpEcdsaVerify(mh2, r32, s32, pub), "secp: tamper rejected")
	}
}

// testAttribA7OffcurveP2PKH locks the §13 rule (cross-impl finding A7): a P2PKH
// pubkey that is canonical in ENCODING (0x02/03, X<p) but OFF the curve is a
// status-1 on-curve-drop — NOT found (3) and NOT verify-drop (2) — and it still
// carries the real hash160 identity + legacy sighash (both formed at
// classification, before the curve gate). The on-curve gate, not the verify
// step, is the discriminator. The seed soak almost never lands a canonical
// off-curve key on the P2PKH path (the curve gate was historically exercised
// only via multisig — exactly the A7 blind spot), so this is pinned directly.
func testAttribA7OffcurveP2PKH() {
	// valid strict-DER, low-S sig (R=1, S=1) + SIGHASH_ALL (0x01).
	sig := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01}

	offPub := findCanonicalPub(true) // canonical encoding, off the curve
	onPub := findCanonicalPub(false) // canonical encoding, on the curve
	check(offPub != nil, "A7: found a canonical off-curve compressed pubkey")
	check(onPub != nil, "A7: found a canonical on-curve compressed pubkey")
	if offPub == nil || onPub == nil {
		return
	}

	var z20 [20]byte
	var z32 [32]byte

	rOff := attribOneInput(sig, offPub)
	check(rOff.status == 1, "A7: off-curve canonical P2PKH pubkey → status 1 (on-curve-drop)")
	check(rOff.identity != z20 && rOff.identity == hash160(offPub),
		"A7: a status-1 row carries the real hash160 identity")
	check(rOff.sighash != z32,
		"A7: a status-1 row carries the real legacy sighash (formed before the curve gate)")

	rOn := attribOneInput(sig, onPub)
	check(rOn.status != 1, "A7: on-curve canonical P2PKH pubkey → status != 1 (verify decides 2/3)")
}

// testEcmh mirrors C's test_ecmh (§13.2): ECMH primitive algebra plus the binding
// that ECMH equality tracks the canonical state-digest equality relation.
func testEcmh() {
	// 1. ECMH algebra: identity / commutativity / inverse / round-trip.
	pa, _ := secpEcmhHash([]byte("alpha"))
	pb, _ := secpEcmhHash([]byte("beta"))
	id := secpEcmhIdentity()
	acc1 := secpEcmhIdentity()
	secpEcmhAdd(acc1, pa)
	secpEcmhAdd(acc1, pb)
	acc2 := secpEcmhIdentity()
	secpEcmhAdd(acc2, pb)
	secpEcmhAdd(acc2, pa)
	check(bytes.Equal(acc1, acc2), "ECMH algebra: commutativity")
	acc1 = secpEcmhIdentity()
	secpEcmhAdd(acc1, pa)
	check(bytes.Equal(acc1, pa), "ECMH algebra: identity (∞ + P == P)")
	npa := append([]byte{}, pa...)
	secpEcmhNegate(npa)
	acc1 = secpEcmhIdentity()
	secpEcmhAdd(acc1, pa)
	secpEcmhAdd(acc1, npa)
	check(bytes.Equal(acc1, id), "ECMH algebra: inverse (P + (−P) == ∞)")

	// 2. ECMH empty-state stable across independent recomputes.
	ea := newState().stateEcmh()
	eb := newState().stateEcmh()
	check(ea == eb, "ECMH empty-state stable")

	// 3. ECMH equality tracks digest equality. s1/s2 = same logical rows, claims
	// applied in opposite order (permutes the names array, identical content);
	// s3 differs (only "a"). Commits stay in the SAME order in s1/s2.
	A := idOf(0xAA, 0)
	sA := salt32(0xA1)
	sB := salt32(0xA2)

	s1 := fold(
		blk(10, 1000, tx1(0, A, 0, commitPayload(sA, "a", A.h160)),
			tx1(1, A, 0, commitPayload(sB, "b", A.h160))),
		blk(11, 1500, tx1(0, A, 30, claimPayload(sA, "a")),
			tx1(1, A, 30, claimPayload(sB, "b"))),
	)
	s2 := fold(
		blk(10, 1000, tx1(0, A, 0, commitPayload(sA, "a", A.h160)),
			tx1(1, A, 0, commitPayload(sB, "b", A.h160))),
		blk(11, 1500, tx1(1, A, 30, claimPayload(sB, "b")),
			tx1(0, A, 30, claimPayload(sA, "a"))),
	)
	s3 := fold(
		blk(10, 1000, tx1(0, A, 0, commitPayload(sA, "a", A.h160))),
		blk(11, 1500, tx1(0, A, 30, claimPayload(sA, "a"))),
	)

	d1, d2, d3 := s1.stateDigest(), s2.stateDigest(), s3.stateDigest()
	e1, e2, e3 := s1.stateEcmh(), s2.stateEcmh(), s3.stateEcmh()
	check(d1 == d2, "ECMH test setup: reordered builds give equal digest")
	check((d1 == d2) == (e1 == e2), "ECMH equality tracks digest (equal states)")
	check((d1 == d3) == (e1 == e3), "ECMH equality tracks digest (differing states)")
}

// findCanonicalPub returns a 33-byte compressed pubkey (0x02 ‖ X) with X far below
// SECP_P, whose injected on-curve verdict matches wantOffCurve. onCurve(pub) =
// SHA256(0x4F ‖ pub)[0] != 0x00, so an off-curve key is one whose hash byte is 0x00.
func findCanonicalPub(wantOffCurve bool) []byte {
	pub := make([]byte, 33)
	pub[0] = 0x02
	for c := uint32(0); c < 4_000_000; c++ {
		pub[29] = byte(c >> 24)
		pub[30] = byte(c >> 16)
		pub[31] = byte(c >> 8)
		pub[32] = byte(c)
		if !onCurve(pub) == wantOffCurve {
			out := make([]byte, 33)
			copy(out, pub)
			return out
		}
	}
	return nil
}

func attribOneInput(sig, pub []byte) attribResult {
	ss := append(pushEncode(sig), pushEncode(pub)...)
	t, ok := parseTx(buildRawTxOneInput(ss))
	if !ok {
		return attribResult{}
	}
	return attribute(t, 0)
}

// testFoldScenarios runs the hand-authored behavioral fold battery
// (scenarios_impl.go): each construction self-checks via check(); the returned
// states are discarded. The cross-language digest battery is `scenario`
// (runScenario), which mirrors the C reference byte-for-byte.
func testFoldScenarios() {
	for _, fn := range []func() *FoldState{
		scCommitClaimHappy, scClaimNaked, scClaimTooShallow, scPriorityCommitTxIndex,
		scCommitmentCopy, scCommitExpiryPrune, scLeaseLapse, scRenewStack,
		scWaterfillUnderfundFloor, scWaterfillAllcappedForfeit, scTransferSelective,
		scReleaseSkipLocked, scSellWindowAddform, scOpenMarketCascade,
		scReserveValueCollision, scReserveOptionTheft, scDirectedSellToPay,
		scDirectedStrangerDrop, scASAttribution, scTradeSwap, scTradeSameBlockAntirug,
		scLapseVsRenewSameBlock, scMTPMedian,
	} {
		fn()
	}
	scOracleEvenBoundary()
	scOracleOddMedian()
	scOracleSubsampleFloor()
}

// testDottedNames locks §3.1: charset [a-z0-9-], 1..32 + structural rejects
// (leading/trailing hyphen, `--` at positions 3–4 / xn--).
func testDottedNames() {
	A := idOf(0xAA, 0)
	check(validName([]byte("shib-p2p")), "hyphen name valid")
	check(validName([]byte("abcdefghijklmnopqrstuvwxyz0123ab")), "32-byte name valid")
	check(!validName([]byte("abcdefghijklmnopqrstuvwxyz0123abc")), "33-byte name invalid (max 32)")
	check(!validName([]byte("shib.p2p")), "dot now invalid")
	check(!validName([]byte("shib_p2p")), "underscore now invalid")
	check(!validName([]byte("Shib-p2p")), "uppercase still invalid")
	check(!validName([]byte("a,b")), "comma still invalid (TRADE pair split relies on it)")
	check(!validName([]byte("-a")), "leading hyphen invalid")
	check(!validName([]byte("a-")), "trailing hyphen invalid")
	check(!validName([]byte("xn--x")), "ACE prefix (xn--) invalid")

	f := newScFold()
	f.begin(10, 1000)
	f.tx(0, mkTx([]Identity{A}, []FoldCarrier{bCommit(commitment(salt32(0x71), "shib-p2p", A.h160), 0)}, nil))
	f.tx(1, mkTx([]Identity{A}, []FoldCarrier{bCommit(commitment(salt32(0x74), "shib.p2p", A.h160), 0)}, nil))
	f.begin(11, 1500)
	f.tx(0, mkTx([]Identity{A}, []FoldCarrier{bClaim(salt32(0x71), "shib-p2p", 10, 0)}, nil))
	f.tx(1, mkTx([]Identity{A}, []FoldCarrier{bClaim(salt32(0x74), "shib.p2p", 10, 0)}, nil))
	s := f.state()
	o, ok := ownerOf(s, "shib-p2p")
	check(ok && o == A.h160, "hyphen claim mints")
	_, dot := ownerOf(s, "shib.p2p")
	check(!dot && len(s.names) == 1, "dotted claim drops")
}
