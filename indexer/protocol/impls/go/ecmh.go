package main

// §13.2 — the pinned, portable ECMH primitive vector set (`sm ecmh`).
//
// Mirrors impls/c/src/ecmh.c's ecmh_cmd(): hash-to-curve KATs, identity
// serialization, a tagged multiset sum proven commutative, and an inverse
// round-trip — printed as a cross-language byte-identical `combined` golden
// (SPEC-conformance.md §13.2). Reuses this impl's self-rolled secp256k1.

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

// domain tags — second-preimage separation between tables.
// names=01 commits=02 muts=04 (tag 0x03 was votes; left vacant).
const (
	ecmhTagName   = 0x01
	ecmhTagCommit = 0x02
	ecmhTagMut    = 0x04
)

var ecmhRecTag = []byte{'E', 'C', 'M', 'H', 'v', '1'}

// ecmhFoldRow does acc ← acc + H2C("ECMHv1" ‖ tag ‖ rowBytes).
func ecmhFoldRow(acc []byte, tag byte, rowBytes []byte) {
	pre := append(append([]byte{}, ecmhRecTag...), tag)
	pre = append(pre, rowBytes...)
	pt, _ := secpEcmhHash(pre)
	secpEcmhAdd(acc, pt)
}

// stateEcmh is the incremental twin of stateDigest (§13.2): a per-table
// Elliptic-Curve Multiset Hash over the SAME canonical per-row encoding the
// state digest uses (so the two induce the identical equality relation),
// combined into one 32-byte value. Three sub-accumulators (names/commits/muts);
// combined = SHA256("ECMHtop1" ‖ A_names ‖ A_commits ‖ A_muts).
func (s *FoldState) stateEcmh() [32]byte {
	an := secpEcmhIdentity()
	ac := secpEcmhIdentity()
	am := secpEcmhIdentity()

	// names — per-row fields BYTE-IDENTICAL to digest.go (owner_type NOT encoded).
	for k, r := range s.names {
		var b bytes.Buffer
		b.WriteByte(byte(len(k)))
		b.WriteString(k)
		b.Write(r.owner[:])
		b.WriteByte(byte(r.st))
		wI64(&b, r.leaseExpiry)
		b.Write(r.seller[:])
		b.WriteByte(r.sellerType)
		wU64(&b, r.price)
		wI64(&b, r.offerExpiry)
		b.Write(r.buyer[:])
		wU64(&b, r.burnLeg)
		wU64(&b, r.payLeg)
		wI64(&b, r.reserveExpiry)
		ecmhFoldRow(an, ecmhTagName, b.Bytes())
	}
	for _, c := range s.commits {
		var b bytes.Buffer
		b.Write(c.commitment[:])
		wI64(&b, c.height)
		wU32(&b, c.txIndex)
		wI64(&b, c.commitTime)
		ecmhFoldRow(ac, ecmhTagCommit, b.Bytes())
	}
	for o, h := range s.muts {
		var b bytes.Buffer
		b.Write(o[:])
		wI64(&b, h)
		ecmhFoldRow(am, ecmhTagMut, b.Bytes())
	}

	// combined = SHA256("ECMHtop1" ‖ three sub-accumulators).
	h := sha256.New()
	h.Write([]byte("ECMHtop1"))
	h.Write(an)
	h.Write(ac)
	h.Write(am)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func runEcmh() {
	comb := sha256.New()
	feed := func(b []byte) { comb.Write(b) }

	// version self-doc
	fmt.Printf("ecmh ECMHv1\n")
	feed(ecmhRecTag)

	// 1. hash-to-curve KAT — fixed preimages → (ctr, compressed even-Y point).
	type h2cVec struct {
		label string
		pre   []byte
	}
	ff := bytes.Repeat([]byte{0xFF}, 32)
	z32 := make([]byte, 32)
	h2cs := []h2cVec{
		{"empty", []byte{}},
		{"a", []byte("a")},
		{"pepe", []byte("pepenet")},
		{"doge", []byte("doge")},
		{"ff32", ff},
		{"z32", z32},
	}
	for _, v := range h2cs {
		pt, ctr := secpEcmhHash(v.pre)
		fmt.Printf("h2c %s ctr=%d pt=%s\n", v.label, ctr, hexstr(pt))
		feed([]byte{byte(ctr)})
		feed(pt)
	}

	// 2. identity (∞) serialization
	id := secpEcmhIdentity()
	fmt.Printf("identity %s\n", hexstr(id))
	feed(id)

	// 3. tagged multiset sum — a fixed set of (tag ‖ row) records, summed two ways.
	type rec struct {
		tag  byte
		body []byte
	}
	recs := []rec{
		{ecmhTagName, []byte("\x03foo")},
		{ecmhTagName, []byte("\x03bar")},
		{ecmhTagCommit, []byte("commitment-blob-32-bytes-xxxxxx")},
		{ecmhTagMut, []byte("owner-mutation")},
	}
	recPoint := func(r rec) []byte {
		pre := append(append([]byte{}, ecmhRecTag...), r.tag)
		pre = append(pre, r.body...)
		pt, _ := secpEcmhHash(pre)
		return pt
	}
	fwd := secpEcmhIdentity()
	for i := 0; i < len(recs); i++ {
		secpEcmhAdd(fwd, recPoint(recs[i]))
	}
	rev := secpEcmhIdentity()
	for i := len(recs) - 1; i >= 0; i-- {
		secpEcmhAdd(rev, recPoint(recs[i]))
	}
	commut := 0
	if bytes.Equal(fwd, rev) {
		commut = 1
	}
	fmt.Printf("sum %s\n", hexstr(fwd))
	fmt.Printf("commutative %d\n", commut)
	feed(fwd)
	feed([]byte{byte(commut)})

	// 4. inverse — remove the first record from the sum, re-add, must round-trip.
	pt0 := recPoint(recs[0])
	acc := append([]byte{}, fwd...)
	npt := append([]byte{}, pt0...)
	secpEcmhNegate(npt)
	secpEcmhAdd(acc, npt) // remove rec[0]
	secpEcmhAdd(acc, pt0) // re-add rec[0]
	roundtrip := 0
	if bytes.Equal(acc, fwd) {
		roundtrip = 1
	}
	fmt.Printf("inverse_roundtrip %d\n", roundtrip)
	feed([]byte{byte(roundtrip)})

	cd := comb.Sum(nil)
	fmt.Printf("combined %s\n", hexstr(cd))
}
