package main

// §4 Strategy B — real secp256k1 (self-rolled, stdlib-only via math/big).
//
// Replaces the injected curve oracle in the §4 attribution shell with genuine
// elliptic-curve math: field arithmetic mod p = 2^256 − 2^32 − 977, affine point
// ops, ECDSA verify, and RFC-6979 deterministic signing (HMAC-SHA256 nonce,
// low-S normalized). Mirrors impls/c/src/secp256k1.c semantics exactly; output is
// cross-language byte-identical. NOT constant time — verifier/test oracle only.

import (
	"crypto/hmac"
	"crypto/sha256"
	"math/big"
)

// curve constants (big-endian hex → big.Int).
var (
	secpP    = bigHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	secpN    = bigHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	secpNH   = bigHex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0")
	secpGx   = bigHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
	secpGy   = bigHex("483ADA7726A3C465 5DA4FBFC0E1108A8 FD17B448A6855419 9C47D08FFB10D4B8")
	secpSeven = big.NewInt(7)
)

func bigHex(s string) *big.Int {
	// strip spaces (used only for readability above)
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' {
			out = append(out, s[i])
		}
	}
	n := new(big.Int)
	n.SetString(string(out), 16)
	return n
}

// be32 renders n as a fixed 32-byte big-endian slice (left-padded, no leading-zero trim).
func be32(n *big.Int) []byte {
	out := make([]byte, 32)
	b := n.Bytes()
	if len(b) > 32 {
		b = b[len(b)-32:]
	}
	copy(out[32-len(b):], b)
	return out
}

// ── affine point (nil = point at infinity) ────────────────────────────────────
type ecPoint struct {
	x, y *big.Int
}

func ecInf() *ecPoint { return nil }

func (p *ecPoint) isInf() bool { return p == nil }

func ecGenerator() *ecPoint { return &ecPoint{x: new(big.Int).Set(secpGx), y: new(big.Int).Set(secpGy)} }

func fieldMul(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(a, b), secpP) }
func fieldSub(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Sub(a, b), secpP) }
func fieldAdd(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Add(a, b), secpP) }
func fieldInv(a *big.Int) *big.Int    { return new(big.Int).ModInverse(a, secpP) }

func ecDouble(p *ecPoint) *ecPoint {
	if p.isInf() || p.y.Sign() == 0 {
		return ecInf()
	}
	// lambda = (3x^2) / (2y)
	num := fieldMul(big.NewInt(3), fieldMul(p.x, p.x))
	den := fieldInv(fieldMul(big.NewInt(2), p.y))
	lam := fieldMul(num, den)
	x3 := fieldSub(fieldSub(fieldMul(lam, lam), p.x), p.x)
	y3 := fieldSub(fieldMul(lam, fieldSub(p.x, x3)), p.y)
	return &ecPoint{x: x3, y: y3}
}

func ecAdd(p, q *ecPoint) *ecPoint {
	if p.isInf() {
		return q
	}
	if q.isInf() {
		return p
	}
	if p.x.Cmp(q.x) == 0 {
		if p.y.Cmp(q.y) != 0 {
			return ecInf() // P + (-P)
		}
		return ecDouble(p)
	}
	lam := fieldMul(fieldSub(q.y, p.y), fieldInv(fieldSub(q.x, p.x)))
	x3 := fieldSub(fieldSub(fieldMul(lam, lam), p.x), q.x)
	y3 := fieldSub(fieldMul(lam, fieldSub(p.x, x3)), p.y)
	return &ecPoint{x: x3, y: y3}
}

// ecMul = k·P, double-and-add MSB-first.
func ecMul(k *big.Int, p *ecPoint) *ecPoint {
	acc := ecInf()
	for i := k.BitLen() - 1; i >= 0; i-- {
		acc = ecDouble(acc)
		if k.Bit(i) == 1 {
			acc = ecAdd(acc, p)
		}
	}
	return acc
}

// ── pubkey decode + on-curve ──────────────────────────────────────────────────
// rhsCurve = x^3 + 7 mod p.
func rhsCurve(x *big.Int) *big.Int {
	x3 := fieldMul(fieldMul(x, x), x)
	return fieldAdd(x3, secpSeven)
}

// pubDecode parses a 33-byte compressed or 65-byte uncompressed pubkey to an affine
// point; returns nil if not on curve / bad encoding.
func pubDecode(pub []byte) *ecPoint {
	if len(pub) == 33 && (pub[0] == 0x02 || pub[0] == 0x03) {
		x := new(big.Int).SetBytes(pub[1:33])
		if x.Cmp(secpP) >= 0 {
			return nil
		}
		rhs := rhsCurve(x)
		// beta = rhs^((p+1)/4) mod p
		exp := new(big.Int).Rsh(new(big.Int).Add(secpP, big.NewInt(1)), 2)
		beta := new(big.Int).Exp(rhs, exp, secpP)
		if fieldMul(beta, beta).Cmp(rhs) != 0 {
			return nil // not a quadratic residue ⇒ off curve
		}
		wantOdd := pub[0] == 0x03
		if (beta.Bit(0) == 1) != wantOdd {
			beta = new(big.Int).Sub(secpP, beta)
		}
		return &ecPoint{x: x, y: beta}
	}
	if len(pub) == 65 && pub[0] == 0x04 {
		x := new(big.Int).SetBytes(pub[1:33])
		y := new(big.Int).SetBytes(pub[33:65])
		if x.Cmp(secpP) >= 0 || y.Cmp(secpP) >= 0 {
			return nil
		}
		if fieldMul(y, y).Cmp(rhsCurve(x)) != 0 {
			return nil
		}
		return &ecPoint{x: x, y: y}
	}
	return nil
}

func secpOnCurve(pub []byte) bool { return pubDecode(pub) != nil }

// ── ECDSA verify (does NOT enforce low-S) ─────────────────────────────────────
func secpEcdsaVerify(hash32, r32, s32 [32]byte, pub []byte) bool {
	Q := pubDecode(pub)
	if Q == nil {
		return false
	}
	r := new(big.Int).SetBytes(r32[:])
	s := new(big.Int).SetBytes(s32[:])
	if r.Sign() == 0 || r.Cmp(secpN) >= 0 {
		return false
	}
	if s.Sign() == 0 || s.Cmp(secpN) >= 0 {
		return false
	}
	z := new(big.Int).Mod(new(big.Int).SetBytes(hash32[:]), secpN)
	w := new(big.Int).ModInverse(s, secpN)
	if w == nil {
		return false
	}
	u1 := new(big.Int).Mod(new(big.Int).Mul(z, w), secpN)
	u2 := new(big.Int).Mod(new(big.Int).Mul(r, w), secpN)
	R := ecAdd(ecMul(u1, ecGenerator()), ecMul(u2, Q))
	if R.isInf() {
		return false
	}
	xr := new(big.Int).Mod(R.x, secpN)
	return xr.Cmp(r) == 0
}

// ── RFC-6979 nonce + ECDSA sign ───────────────────────────────────────────────
func hmacSha256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// rfc6979K returns the first valid nonce k in [1,n) from the HMAC_DRBG stream.
func rfc6979K(priv32, hash32 []byte) *big.Int {
	// bits2octets(h1) = (h1 mod n) as 32-byte BE.
	hz := new(big.Int).Mod(new(big.Int).SetBytes(hash32), secpN)
	h1o := be32(hz)
	x := make([]byte, 32)
	copy(x, priv32)

	V := make([]byte, 32)
	K := make([]byte, 32)
	for i := range V {
		V[i] = 0x01
	}
	// K = HMAC_K(V ‖ 0x00 ‖ x ‖ h1o)
	buf := append(append(append(append([]byte{}, V...), 0x00), x...), h1o...)
	K = hmacSha256(K, buf)
	V = hmacSha256(K, V)
	// K = HMAC_K(V ‖ 0x01 ‖ x ‖ h1o)
	buf = append(append(append(append([]byte{}, V...), 0x01), x...), h1o...)
	K = hmacSha256(K, buf)
	V = hmacSha256(K, V)
	for {
		V = hmacSha256(K, V) // T = V (qlen == 256 ⇒ one block)
		k := new(big.Int).SetBytes(V)
		if k.Sign() != 0 && k.Cmp(secpN) < 0 {
			return k
		}
		K = hmacSha256(K, append(append([]byte{}, V...), 0x00))
		V = hmacSha256(K, V)
	}
}

// secpEcdsaSign produces a low-S signature (32-byte BE r,s); ok=false if priv invalid.
func secpEcdsaSign(priv32, hash32 []byte) (r32, s32 [32]byte, ok bool) {
	d := new(big.Int).SetBytes(priv32)
	if d.Sign() == 0 || d.Cmp(secpN) >= 0 {
		return
	}
	z := new(big.Int).Mod(new(big.Int).SetBytes(hash32), secpN)
	feed := make([]byte, 32)
	copy(feed, hash32)
	for attempt := 0; attempt < 64; attempt++ {
		k := rfc6979K(priv32, feed)
		R := ecMul(k, ecGenerator())
		if R.isInf() {
			h := sha256.Sum256(be32(k))
			copy(feed, h[:])
			continue
		}
		r := new(big.Int).Mod(R.x, secpN)
		if r.Sign() == 0 {
			h := sha256.Sum256(be32(k))
			copy(feed, h[:])
			continue
		}
		kinv := new(big.Int).ModInverse(k, secpN)
		if kinv == nil {
			h := sha256.Sum256(be32(k))
			copy(feed, h[:])
			continue
		}
		// s = kinv·(z + r·d) mod n
		rd := new(big.Int).Mod(new(big.Int).Mul(r, d), secpN)
		zrd := new(big.Int).Mod(new(big.Int).Add(z, rd), secpN)
		s := new(big.Int).Mod(new(big.Int).Mul(kinv, zrd), secpN)
		if s.Sign() == 0 {
			h := sha256.Sum256(be32(k))
			copy(feed, h[:])
			continue
		}
		if s.Cmp(secpNH) > 0 { // low-S: s = n - s
			s = new(big.Int).Sub(secpN, s)
		}
		copy(r32[:], be32(r))
		copy(s32[:], be32(s))
		ok = true
		return
	}
	return
}

// ── ECMH (Elliptic Curve Multiset Hash) ───────────────────────────────────────
// An accumulator is a 33-byte compressed point (0x02/0x03 ‖ X-be); the all-zero
// sentinel (prefix 0x00) is the identity ∞. Mirrors impls/c/src/secp256k1.c.
var ecmhH2cTag = []byte{'E', 'C', 'M', 'H', 'h', '2', 'c', '1'}

func secpEcmhIdentity() []byte { return make([]byte, 33) }

// ecmhSer renders an affine point to 33 bytes (∞ → zeros).
func ecmhSer(p *ecPoint) []byte {
	out := make([]byte, 33)
	if p.isInf() {
		return out
	}
	if p.y.Bit(0) == 1 {
		out[0] = 0x03
	} else {
		out[0] = 0x02
	}
	copy(out[1:], be32(p.x))
	return out
}

// ecmhLoad parses 33 bytes to an affine point (prefix 0x00 ⇒ ∞).
func ecmhLoad(in33 []byte) *ecPoint {
	if in33[0] == 0 {
		return ecInf()
	}
	return pubDecode(in33)
}

// secpEcmhHash hashes pre onto the curve (try-and-increment); returns the
// 33-byte even-Y compressed point and the ctr used.
func secpEcmhHash(pre []byte) (pt33 []byte, ctr int) {
	exp := new(big.Int).Rsh(new(big.Int).Add(secpP, big.NewInt(1)), 2)
	for ctr = 0; ; ctr++ {
		h := sha256.New()
		h.Write(ecmhH2cTag)
		if len(pre) > 0 {
			h.Write(pre)
		}
		cb := []byte{byte(ctr), byte(ctr >> 8), byte(ctr >> 16), byte(ctr >> 24)}
		h.Write(cb)
		digest := h.Sum(nil)
		x := new(big.Int).Mod(new(big.Int).SetBytes(digest), secpP)
		rhs := rhsCurve(x)
		beta := new(big.Int).Exp(rhs, exp, secpP)
		if fieldMul(beta, beta).Cmp(rhs) != 0 {
			continue // x³+7 not a QR ⇒ bump ctr
		}
		out := make([]byte, 33)
		out[0] = 0x02 // canonical even-Y
		copy(out[1:], be32(x))
		return out, ctr
	}
}

// secpEcmhNegate flips the parity bit (identity unchanged).
func secpEcmhNegate(pt33 []byte) {
	if pt33[0] != 0 {
		pt33[0] ^= 1
	}
}

// secpEcmhAdd does acc ← acc + pt (EC point addition), recompressing in place.
func secpEcmhAdd(acc33 []byte, pt33 []byte) {
	a := ecmhLoad(acc33)
	p := ecmhLoad(pt33)
	r := ecAdd(a, p)
	copy(acc33, ecmhSer(r))
}

// secpPubkey derives the 33-byte compressed pubkey from a private scalar.
func secpPubkey(priv32 []byte) ([]byte, bool) {
	d := new(big.Int).SetBytes(priv32)
	if d.Sign() == 0 || d.Cmp(secpN) >= 0 {
		return nil, false
	}
	P := ecMul(d, ecGenerator())
	if P.isInf() {
		return nil, false
	}
	out := make([]byte, 33)
	if P.y.Bit(0) == 1 {
		out[0] = 0x03
	} else {
		out[0] = 0x02
	}
	copy(out[1:], be32(P.x))
	return out, true
}
