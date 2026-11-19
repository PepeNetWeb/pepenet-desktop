package main

// §4 Strategy B — the pinned ECDSA curve-vector set (`sm attrib-curve`).
//
// Mirrors impls/c/src/attrib_curve.c + attrib_real_endtoend: pinned P/N/N_HALF
// constants, on-curve membership at the edges, RFC-6979 deterministic (r,s) +
// canonical-DER known-answers, ECDSA verify accept/reject at the scalar
// boundaries, a tiny-key KAT, the PRIMARY `combined` digest, and an end-to-end
// real-curve pipeline (`combined_e2e`). Output must be byte-identical across all
// 7 reference impls. See SPEC-conformance.md §13 + SPEC-RATIONALE.md §11.

import (
	"crypto/sha256"
	"fmt"
)

// curve-vector constants (mirror secp256k1.c; pinned so the script self-contains
// its expected scalars cross-language).
var (
	cvP    = mustHex32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	cvN    = mustHex32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	cvNH   = mustHex32("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0")
	cvGx   = mustHex32("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	cvGy   = mustHex32("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
)

const hexd = "0123456789abcdef"

func hexstr(d []byte) string {
	out := make([]byte, 0, len(d)*2)
	for _, b := range d {
		out = append(out, hexd[b>>4], hexd[b&15])
	}
	return string(out)
}

// canonical strict-DER encoding of (r,s) ‖ SIGHASH_ALL.
func derIntCurve(v []byte) []byte {
	i := 0
	for i < 31 && v[i] == 0 {
		i++
	}
	body := v[i:]
	out := []byte{0x02}
	if body[0]&0x80 != 0 {
		out = append(out, byte(len(body)+1), 0x00)
	} else {
		out = append(out, byte(len(body)))
	}
	return append(out, body...)
}

func derSigCurve(r, s []byte) []byte {
	body := append(derIntCurve(r), derIntCurve(s)...)
	out := []byte{0x30, byte(len(body))}
	out = append(out, body...)
	return append(out, 0x01) // SIGHASH_ALL
}

func runAttribCurve() {
	comb := sha256.New()
	feed := func(b []byte) { comb.Write(b) }

	// ── 1. pinned constants ────────────────────────────────────────────────────
	fmt.Printf("p %s\n", hexstr(cvP[:]))
	feed(cvP[:])
	fmt.Printf("n %s\n", hexstr(cvN[:]))
	feed(cvN[:])
	fmt.Printf("nhalf %s\n", hexstr(cvNH[:]))
	feed(cvNH[:])

	// ── 2. on-curve membership at the edges ────────────────────────────────────
	type ocVec struct {
		name string
		key  []byte
	}
	var ocs []ocVec
	add := func(name string, key []byte) { ocs = append(ocs, ocVec{name, key}) }

	guncomp := append([]byte{0x04}, append(append([]byte{}, cvGx[:]...), cvGy[:]...)...)
	add("oc_G_uncomp", guncomp)
	add("oc_G_comp02", append([]byte{0x02}, cvGx[:]...))
	add("oc_G_comp03", append([]byte{0x03}, cvGx[:]...))
	badY := append([]byte{0x04}, append(append([]byte{}, cvGx[:]...), cvGy[:]...)...)
	badY[64] ^= 0x01
	add("oc_G_badY", badY)
	add("oc_X0", append([]byte{0x02}, make([]byte, 32)...))
	x1 := make([]byte, 32)
	x1[31] = 1
	add("oc_X1", append([]byte{0x02}, x1...))
	add("oc_Xeqp", append([]byte{0x04}, append(append([]byte{}, cvP[:]...), cvGy[:]...)...))
	add("oc_comp_Xeqp", append([]byte{0x02}, cvP[:]...))
	add("oc_badprefix", append([]byte{0x05}, cvGx[:]...))

	for _, o := range ocs {
		v := 0
		if secpOnCurve(o.key) {
			v = 1
		}
		fmt.Printf("%s %d\n", o.name, v)
		feed([]byte{byte(v)})
		feed(o.key)
	}

	// ── 3 & 4. RFC-6979 deterministic sign + ECDSA verify at the boundaries ─────
	for i := 0; i < 4; i++ {
		priv := make([]byte, 32)
		priv[28] = 0xC0
		priv[29] = 0xFF
		priv[30] = 0xEE
		priv[31] = byte(0x10 + i)
		pub, ok := secpPubkey(priv)
		if !ok {
			fmt.Printf("sig%d PUBFAIL\n", i)
			continue
		}
		m := fmt.Sprintf("strategy-b curve vector %d", i)
		h := sha256.Sum256([]byte(m))
		r32, s32, sok := secpEcdsaSign(priv, h[:])
		if !sok {
			fmt.Printf("sig%d SIGNFAIL\n", i)
			continue
		}
		der := derSigCurve(r32[:], s32[:])
		fmt.Printf("sig%d pub=%s r=%s s=%s der=%s\n", i, hexstr(pub), hexstr(r32[:]), hexstr(s32[:]), hexstr(der))
		feed(pub)
		feed(r32[:])
		feed(s32[:])
		feed(der)

		// verify boundary battery.
		var zero [32]byte
		var hh [32]byte
		copy(hh[:], h[:])
		var hbad [32]byte
		copy(hbad[:], h[:])
		hbad[0] ^= 0x01
		var hiS [32]byte // high-S = n - s
		borrow := 0
		for k := 31; k >= 0; k-- {
			d := int(cvN[k]) - int(s32[k]) - borrow
			if d < 0 {
				d += 256
				borrow = 1
			} else {
				borrow = 0
			}
			hiS[k] = byte(d)
		}
		wrongpub := append([]byte{}, pub...)
		wrongpub[0] ^= 0x01

		type vt struct {
			nm string
			h  [32]byte
			r  [32]byte
			s  [32]byte
			pk []byte
		}
		vts := []vt{
			{"valid", hh, r32, s32, pub},
			{"tamper", hbad, r32, s32, pub},
			{"r0", hh, zero, s32, pub},
			{"s0", hh, r32, zero, pub},
			{"rN", hh, cvN, s32, pub},
			{"sN", hh, r32, cvN, pub},
			{"highS", hh, r32, hiS, pub},
			{"wrongpk", hh, r32, s32, wrongpub},
		}
		fmt.Printf("ver%d", i)
		for _, t := range vts {
			v := 0
			if secpEcdsaVerify(t.h, t.r, t.s, t.pk) {
				v = 1
			}
			fmt.Printf(" %s=%d", t.nm, v)
			feed([]byte{byte(v)})
		}
		fmt.Printf("\n")
	}

	// ── 5. tiny-key KAT: priv=1 ⇒ pub=G ; priv=2 ⇒ pub=2G ──────────────────────
	p1 := make([]byte, 32)
	p1[31] = 1
	pk1, _ := secpPubkey(p1)
	fmt.Printf("priv1_pub=%s\n", hexstr(pk1))
	feed(pk1)
	p2 := make([]byte, 32)
	p2[31] = 2
	pk2, _ := secpPubkey(p2)
	fmt.Printf("priv2_pub=%s\n", hexstr(pk2))
	feed(pk2)

	// PRIMARY cross-language digest.
	cd := comb.Sum(nil)
	fmt.Printf("combined %s\n", hexstr(cd))

	// ── 6. end-to-end: sign the real legacy sighash, attribute() with real curve ──
	e2e := sha256.New()
	attribRealEndToEnd(e2e)
	ed := e2e.Sum(nil)
	fmt.Printf("combined_e2e %s\n", hexstr(ed))
}

// attribRealEndToEnd mirrors C attrib_real_endtoend: builds 3 txs (P2PKH valid,
// P2PKH wrong-key, 2-of-2 multisig), signs the genuine legacy sighash with
// RFC-6979, and runs the full attribute() pipeline with the REAL curve.
func attribRealEndToEnd(comb interface{ Write([]byte) (int, error) }) {
	gRealCurve = true
	defer func() { gRealCurve = false }()

	emit := func(name string, t rawTx, k int) {
		res := attribute(t, k)
		fmt.Printf("%s %d:%s\n", name, res.status, hexstr(res.identity[:]))
		comb.Write([]byte{byte(res.status)})
		comb.Write(res.sighash[:])
		comb.Write(res.identity[:])
	}

	// shared skeleton: input outpoint 0x11×36, seq FFFFFFFF, output value 100000
	// scriptPubKey OP_RETURN (0x6a), version 1, locktime 0.
	skeleton := func() rawTx {
		var t rawTx
		t.version = 1
		var op [32]byte
		for i := range op {
			op[i] = 0x11
		}
		t.prevTxid = append(t.prevTxid, op)
		t.prevVout = append(t.prevVout, 0x11111111)
		t.vin = append(t.vin, txIn{})
		t.seq = append(t.seq, 0xFFFFFFFF)
		t.vout = append(t.vout, txOut{value: 100000, script: []byte{0x6a}})
		return t
	}
	sighashOf := func(scriptCode []byte) [32]byte { return legacySighash(skeleton(), 0, scriptCode) }

	// assemble raw tx carrying scriptSig ss; same structural fields as skeleton.
	rawWith := func(ss []byte) []byte {
		var b []byte
		b = appendU32(b, 1)
		b = appendVarint(b, 1)
		for i := 0; i < 36; i++ {
			b = append(b, 0x11)
		}
		b = appendVarint(b, uint64(len(ss)))
		b = append(b, ss...)
		b = appendU32(b, 0xFFFFFFFF)
		b = appendVarint(b, 1)
		b = appendU64(b, 100000)
		b = appendVarint(b, 1)
		b = append(b, 0x6a)
		b = appendU32(b, 0)
		return b
	}

	// ── A. P2PKH, correctly signed ⇒ FOUND (3) ──────────────────────────────────
	{
		priv := make([]byte, 32)
		priv[31] = 0x2A
		pub, _ := secpPubkey(priv)
		h160 := hash160(pub)
		sc := p2pkhScript(h160)
		sh := sighashOf(sc)
		r32, s32, _ := secpEcdsaSign(priv, sh[:])
		der := derSigCurve(r32[:], s32[:])
		ss := append(pushEncode(der), pushEncode(pub)...)
		if t, ok := parseTx(rawWith(ss)); ok {
			emit("e2e_p2pkh_valid", t, 0)
		} else {
			fmt.Println("e2e_p2pkh_valid PARSEFAIL")
		}
	}
	// ── B. P2PKH, signed by the WRONG key ⇒ verify-drop (2) ─────────────────────
	{
		priv := make([]byte, 32)
		priv[31] = 0x2A
		wrong := make([]byte, 32)
		wrong[31] = 0x2B
		pub, _ := secpPubkey(priv)
		h160 := hash160(pub)
		sc := p2pkhScript(h160)
		sh := sighashOf(sc)
		r32, s32, _ := secpEcdsaSign(wrong, sh[:])
		der := derSigCurve(r32[:], s32[:])
		ss := append(pushEncode(der), pushEncode(pub)...)
		if t, ok := parseTx(rawWith(ss)); ok {
			emit("e2e_p2pkh_wrongkey", t, 0)
		} else {
			fmt.Println("e2e_p2pkh_wrongkey PARSEFAIL")
		}
	}
	// ── C. 2-of-2 P2SH multisig, two in-order sigs ⇒ FOUND (3) ──────────────────
	{
		var pubs [2][]byte
		var privs [2][]byte
		for i := 0; i < 2; i++ {
			priv := make([]byte, 32)
			priv[31] = byte(0x50 + i)
			privs[i] = priv
			pubs[i], _ = secpPubkey(priv)
		}
		// OP_2 <k0><k1> OP_2 OP_CHECKMULTISIG
		rs := []byte{0x52}
		for i := 0; i < 2; i++ {
			rs = append(rs, 0x21)
			rs = append(rs, pubs[i]...)
		}
		rs = append(rs, 0x52, 0xae)
		sh := sighashOf(rs)
		ss := []byte{0x00} // NULLDUMMY
		for i := 0; i < 2; i++ {
			r32, s32, _ := secpEcdsaSign(privs[i], sh[:])
			ss = append(ss, pushEncode(derSigCurve(r32[:], s32[:]))...)
		}
		ss = append(ss, pushEncode(rs)...)
		if t, ok := parseTx(rawWith(ss)); ok {
			emit("e2e_multisig_valid", t, 0)
		} else {
			fmt.Println("e2e_multisig_valid PARSEFAIL")
		}
	}
}
