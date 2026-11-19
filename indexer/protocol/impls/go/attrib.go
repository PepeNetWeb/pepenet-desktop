package main

import "crypto/sha256"

// §4 Stateless Identity & Attribution. raw tx -> per-input {status, sighash, identity}.
// Real byte-logic; only the curve (on_curve/verify) is the injected oracle (§13).

// secp256k1 constants (big-endian 32-byte). Used for X<p range and S<=N/2 low-S.
var (
	SECP_P = mustHex32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F")
	SECP_N = mustHex32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	SECP_N_HALF = mustHex32("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0")
)

func mustHex32(s string) [32]byte {
	var out [32]byte
	for i := 0; i < 32; i++ {
		out[i] = hexByte(s[i*2])<<4 | hexByte(s[i*2+1])
	}
	return out
}
func hexByte(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return 0
}

// cmpBE compares two big-endian 32-byte integers: -1,0,1.
func cmpBE(a, b [32]byte) int {
	for i := 0; i < 32; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

// ---- curve oracle (§13) ----
// gRealCurve toggles between the injected pseudo-funcs (default; keeps attrib/
// attrib-scenario/selftest byte-identical) and the real secp256k1 (§4 Strategy B,
// used by the attrib-curve e2e vectors).
var gRealCurve = false

func onCurve(pubkey []byte) bool {
	if gRealCurve {
		return secpOnCurve(pubkey)
	}
	h := sha256.Sum256(append([]byte{0x4F}, pubkey...))
	return h[0] != 0x00
}
func curveVerify(hash32, r32, s32 [32]byte, pubkey []byte) bool {
	if gRealCurve {
		return secpEcdsaVerify(hash32, r32, s32, pubkey)
	}
	buf := make([]byte, 0, 1+32+32+32+len(pubkey))
	buf = append(buf, 0x56)
	buf = append(buf, hash32[:]...)
	buf = append(buf, r32[:]...)
	buf = append(buf, s32[:]...)
	buf = append(buf, pubkey...)
	h := sha256.Sum256(buf)
	return h[0] >= 0x20
}

// ---- raw tx parsing (legacy, no SegWit) ----
type txIn struct {
	scriptSig []byte
}
type txOut struct {
	value  uint64
	script []byte
}
type rawTx struct {
	version  uint32
	vin      []txIn
	vout     []txOut
	locktime uint32
	// full prevout fields kept for sighash re-serialization:
	prevTxid [][32]byte
	prevVout []uint32
	seq      []uint32
}

type cursor struct {
	b   []byte
	i   int
	bad bool
}

func (c *cursor) u8() byte {
	if c.i+1 > len(c.b) {
		c.bad = true
		return 0
	}
	v := c.b[c.i]
	c.i++
	return v
}
func (c *cursor) take(n int) []byte {
	if n < 0 || c.i+n > len(c.b) {
		c.bad = true
		return nil
	}
	v := c.b[c.i : c.i+n]
	c.i += n
	return v
}
func (c *cursor) u32() uint32 {
	b := c.take(4)
	if c.bad {
		return 0
	}
	return leU32(b)
}
func (c *cursor) u64() uint64 {
	b := c.take(8)
	if c.bad {
		return 0
	}
	return leU64(b)
}
func (c *cursor) varint() uint64 {
	x := c.u8()
	if c.bad {
		return 0
	}
	switch x {
	case 0xfd:
		b := c.take(2)
		if c.bad {
			return 0
		}
		return uint64(b[0]) | uint64(b[1])<<8
	case 0xfe:
		return uint64(c.u32())
	case 0xff:
		return c.u64()
	default:
		return uint64(x)
	}
}

func parseTx(raw []byte) (rawTx, bool) {
	c := &cursor{b: raw}
	var t rawTx
	t.version = c.u32()
	nin := c.varint()
	if c.bad || nin == 0 || nin > 100000 {
		return t, false
	}
	for k := uint64(0); k < nin; k++ {
		txid := c.take(32)
		vout := c.u32()
		sl := c.varint()
		ss := c.take(int(sl))
		seq := c.u32()
		if c.bad {
			return t, false
		}
		var id [32]byte
		copy(id[:], txid)
		t.prevTxid = append(t.prevTxid, id)
		t.prevVout = append(t.prevVout, vout)
		t.vin = append(t.vin, txIn{scriptSig: cloneBytes(ss)})
		t.seq = append(t.seq, seq)
	}
	nout := c.varint()
	if c.bad || nout > 100000 {
		return t, false
	}
	for k := uint64(0); k < nout; k++ {
		val := c.u64()
		sl := c.varint()
		spk := c.take(int(sl))
		if c.bad {
			return t, false
		}
		t.vout = append(t.vout, txOut{value: val, script: cloneBytes(spk)})
	}
	t.locktime = c.u32()
	if c.bad || c.i != len(raw) {
		return t, false
	}
	return t, true
}

// ---- script push tokenizer (minimal-push enforced) ----
type pushItem struct {
	data   []byte
	op     byte // the leading push opcode (0x00 for OP_0)
}

// tokenizePushes parses a scriptSig into a list of data pushes. Returns ok=false
// if any non-push opcode appears or any push is non-minimal. OP_0 (0x00) yields an
// empty item; direct 0x01..0x4b; PUSHDATA1 0x4c (76..255); PUSHDATA2 0x4d (256..520).
func tokenizePushes(s []byte) ([]pushItem, bool) {
	var out []pushItem
	i := 0
	for i < len(s) {
		op := s[i]
		i++
		switch {
		case op == 0x00:
			out = append(out, pushItem{data: []byte{}, op: 0x00})
		case op >= 0x01 && op <= 0x4b:
			n := int(op)
			if i+n > len(s) {
				return nil, false
			}
			out = append(out, pushItem{data: s[i : i+n], op: op})
			i += n
		case op == 0x4c: // PUSHDATA1
			if i+1 > len(s) {
				return nil, false
			}
			n := int(s[i])
			i++
			if n < 76 { // must be 76..255 (non-minimal otherwise)
				return nil, false
			}
			if i+n > len(s) {
				return nil, false
			}
			out = append(out, pushItem{data: s[i : i+n], op: 0x4c})
			i += n
		case op == 0x4d: // PUSHDATA2
			if i+2 > len(s) {
				return nil, false
			}
			n := int(s[i]) | int(s[i+1])<<8
			i += 2
			if n < 256 || n > 520 {
				return nil, false
			}
			if i+n > len(s) {
				return nil, false
			}
			out = append(out, pushItem{data: s[i : i+n], op: 0x4d})
			i += n
		default:
			return nil, false // any non-push opcode
		}
	}
	return out, true
}

// minimalPushOpFor returns the canonical minimal push-encoding length-prefix for n bytes.
func pushEncode(data []byte) []byte {
	n := len(data)
	switch {
	case n <= 75:
		return append([]byte{byte(n)}, data...)
	case n <= 255:
		return append([]byte{0x4c, byte(n)}, data...)
	default:
		return append([]byte{0x4d, byte(n), byte(n >> 8)}, data...)
	}
}

// ---- strict DER + low-S (BIP66 + self-imposed low-S, Rule 4) ----
// Returns r32, s32 (big-endian, zero-padded), hashtype, ok.
func parseDERSig(sig []byte) (r32, s32 [32]byte, htype byte, ok bool) {
	// sig = DER || hashtype(1)
	if len(sig) < 9 || len(sig) > 73 {
		return
	}
	htype = sig[len(sig)-1]
	der := sig[:len(sig)-1]
	if der[0] != 0x30 {
		return
	}
	if int(der[1]) != len(der)-2 {
		return
	}
	// R
	if der[2] != 0x02 {
		return
	}
	lenR := int(der[3])
	if 4+lenR > len(der) {
		return
	}
	R := der[4 : 4+lenR]
	// S
	sOff := 4 + lenR
	if sOff+2 > len(der) {
		return
	}
	if der[sOff] != 0x02 {
		return
	}
	lenS := int(der[sOff+1])
	if sOff+2+lenS != len(der) {
		return
	}
	S := der[sOff+2 : sOff+2+lenS]
	if !derIntValid(R) || !derIntValid(S) {
		return
	}
	// low-S: S <= N/2
	sb, ok2 := beTo32(S)
	if !ok2 {
		return
	}
	if cmpBE(sb, SECP_N_HALF) > 0 {
		return
	}
	rb, ok3 := beTo32(R)
	if !ok3 {
		return
	}
	return rb, sb, htype, true
}

// derIntValid: BIP66 integer rules — nonempty, no negative (high bit clear),
// no extraneous leading zero.
func derIntValid(v []byte) bool {
	if len(v) == 0 {
		return false
	}
	if v[0]&0x80 != 0 {
		return false // negative
	}
	if v[0] == 0x00 && len(v) > 1 && v[1]&0x80 == 0 {
		return false // non-minimal leading zero
	}
	return true
}

// beTo32 left-pads a minimal big-endian integer (after stripping a sign 0x00) to 32 bytes.
// AMBIGUITY: the curve oracle takes r32/s32 but the prose never pins their width/padding;
// we use 32-byte big-endian zero-pad of the integer value. (Logged.)
func beTo32(v []byte) ([32]byte, bool) {
	var out [32]byte
	// strip a single leading 0x00 sign byte if present
	if len(v) > 0 && v[0] == 0x00 {
		v = v[1:]
	}
	if len(v) > 32 {
		return out, false
	}
	copy(out[32-len(v):], v)
	return out, true
}

// ---- pubkey canonical encoding (Rule 4) ----
// returns ok (well-encoded incl. X<p,(Y<p)); curve-on handled separately.
func pubkeyCanonical(pk []byte) bool {
	switch {
	case len(pk) == 33 && (pk[0] == 0x02 || pk[0] == 0x03):
		var x [32]byte
		copy(x[:], pk[1:33])
		return cmpBE(x, SECP_P) < 0
	case len(pk) == 65 && pk[0] == 0x04:
		var x, y [32]byte
		copy(x[:], pk[1:33])
		copy(y[:], pk[33:65])
		return cmpBE(x, SECP_P) < 0 && cmpBE(y, SECP_P) < 0
	default:
		return false // hybrid 0x06/0x07, bad length, etc.
	}
}

// ---- attribution result ----
type attribResult struct {
	status   int // 0 classify-drop, 1 on-curve-drop, 2 verify-drop, 3 found
	sighash  [32]byte
	identity [20]byte
}

// attribute runs §4 on input k of tx.
func attribute(t rawTx, k int) attribResult {
	var res attribResult
	if k < 0 || k >= len(t.vin) {
		return res // status 0, all-zero
	}
	ss := t.vin[k].scriptSig
	pushes, ok := tokenizePushes(ss)
	if !ok {
		return res
	}

	// --- P2PKH: exactly two pushes [sig][pubkey] ---
	if len(pushes) == 2 && pushes[0].op != 0x00 && pushes[1].op != 0x00 {
		sig := pushes[0].data
		pk := pushes[1].data
		r32, s32, ht, sigOK := parseDERSig(sig)
		if sigOK && ht == 0x01 && pubkeyCanonical(pk) {
			// classification succeeded → form identity + sighash now.
			id := hash160(pk)
			scriptCode := p2pkhScript(id)
			sh := legacySighash(t, k, scriptCode)
			res.identity = id
			res.sighash = sh
			res.status = 1
			if !onCurve(pk) {
				return res // on-curve-drop
			}
			if curveVerify(sh, r32, s32, pk) {
				res.status = 3
			} else {
				res.status = 2
			}
			return res
		}
		// not a valid P2PKH → fall through to try P2SH (won't match) → classify-drop
	}

	// --- P2SH multisig: OP_0 [sig]xm [redeemScript] ---
	if len(pushes) >= 3 && pushes[0].op == 0x00 && len(pushes[0].data) == 0 {
		redeem := pushes[len(pushes)-1].data
		sigPushes := pushes[1 : len(pushes)-1]
		m, keys, tmplOK := parseMultisigTemplate(redeem)
		if tmplOK && len(sigPushes) == m {
			// All sigs strict-DER+low-S+0x01.
			var sds []sigRS
			allSig := true
			for _, sp := range sigPushes {
				r32, s32, ht, sigOK := parseDERSig(sp.data)
				if !sigOK || ht != 0x01 {
					allSig = false
					break
				}
				sds = append(sds, sigRS{r32, s32})
			}
			if allSig {
				// classification succeeded → identity + sighash (with FindAndDelete).
				id := hash160(redeem)
				res.identity = id
				res.status = 1
				// on-curve on ALL n keys up front.
				offcurve := false
				for _, key := range keys {
					if !onCurve(key) {
						offcurve = true
						break
					}
				}
				// sighash: scriptCode = redeemScript with FaD per checked sig.
				scriptCode := applyFindAndDeleteAll(redeem, sigPushes)
				sh := legacySighash(t, k, scriptCode)
				res.sighash = sh
				if offcurve {
					return res // status 1
				}
				// in-order scan: m sigs vs n keys.
				if inOrderScan(sds, keys, sh) {
					res.status = 3
				} else {
					res.status = 2
				}
				return res
			}
		}
	}
	return res // status 0
}

func p2pkhScript(h [20]byte) []byte {
	out := []byte{0x76, 0xa9, 0x14}
	out = append(out, h[:]...)
	return append(out, 0x88, 0xac)
}

// parseMultisigTemplate: OP_m (n×0x21 33-key) OP_n OP_CHECKMULTISIG, 1<=m<=n<=15,
// compressed keys (0x02/0x03), X<p, no trailing.
func parseMultisigTemplate(s []byte) (m int, keys [][]byte, ok bool) {
	if len(s) < 1 {
		return
	}
	if s[0] < 0x51 || s[0] > 0x60 { // OP_1..OP_16
		return
	}
	m = int(s[0] - 0x50)
	i := 1
	for i < len(s) && s[i] == 0x21 {
		if i+1+33 > len(s) {
			return 0, nil, false
		}
		key := s[i+1 : i+1+33]
		if key[0] != 0x02 && key[0] != 0x03 {
			return 0, nil, false
		}
		var x [32]byte
		copy(x[:], key[1:33])
		if cmpBE(x, SECP_P) >= 0 {
			return 0, nil, false
		}
		keys = append(keys, key)
		i += 34
	}
	// OP_n
	if i >= len(s) || s[i] < 0x51 || s[i] > 0x60 {
		return 0, nil, false
	}
	n := int(s[i] - 0x50)
	i++
	if i >= len(s) || s[i] != 0xae { // OP_CHECKMULTISIG
		return 0, nil, false
	}
	i++
	if i != len(s) { // trailing
		return 0, nil, false
	}
	if n != len(keys) || m < 1 || m > n || n > 15 {
		return 0, nil, false
	}
	return m, keys, true
}

type sigRS struct{ r32, s32 [32]byte }

// inOrderScan: the m sigs must match a subsequence of n keys in order.
func inOrderScan(sds []sigRS, keys [][]byte, sh [32]byte) bool {
	ki := 0
	si := 0
	for si < len(sds) && ki < len(keys) {
		if curveVerify(sh, sds[si].r32, sds[si].s32, keys[ki]) {
			si++
			ki++
		} else {
			ki++
		}
	}
	return si == len(sds)
}

// applyFindAndDeleteAll applies Bitcoin Core CScript::FindAndDelete of each
// checked-signature push against the scriptCode, boundary-aligned (GetOp iteration).
func applyFindAndDeleteAll(scriptCode []byte, sigPushes []pushItem) []byte {
	sc := cloneBytes(scriptCode)
	for _, sp := range sigPushes {
		pattern := pushEncode(sp.data)
		sc = findAndDelete(sc, pattern)
	}
	return sc
}

// findAndDelete removes all boundary-aligned occurrences of pattern from script.
func findAndDelete(script, pattern []byte) []byte {
	if len(pattern) == 0 {
		return script
	}
	var out []byte
	i := 0
	for i < len(script) {
		// determine opcode boundary length at i
		opLen := opSpan(script, i)
		if opLen <= 0 {
			// undecodable tail: copy rest verbatim
			out = append(out, script[i:]...)
			break
		}
		if i+len(pattern) <= len(script) && bytesEqual(script[i:i+len(pattern)], pattern) {
			// boundary-aligned match → delete
			i += len(pattern)
			continue
		}
		out = append(out, script[i:i+opLen]...)
		i += opLen
	}
	return out
}

// opSpan returns the byte length of the opcode+data starting at i, or 0 if undecodable.
func opSpan(s []byte, i int) int {
	op := s[i]
	switch {
	case op < 0x4c:
		if i+1+int(op) > len(s) {
			return 0
		}
		return 1 + int(op)
	case op == 0x4c:
		if i+2 > len(s) {
			return 0
		}
		return 2 + int(s[i+1])
	case op == 0x4d:
		if i+3 > len(s) {
			return 0
		}
		return 3 + (int(s[i+1]) | int(s[i+2])<<8)
	case op == 0x4e:
		if i+5 > len(s) {
			return 0
		}
		n := int(s[i+1]) | int(s[i+2])<<8 | int(s[i+3])<<16 | int(s[i+4])<<24
		return 5 + n
	default:
		return 1
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// legacySighash: double-SHA256 of the tx serialized with input k carrying scriptCode,
// others empty, hashtype appended as 4-byte LE int32 (0x01000000). DOGE has no SegWit.
func legacySighash(t rawTx, k int, scriptCode []byte) [32]byte {
	var b []byte
	b = appendU32(b, t.version)
	b = appendVarint(b, uint64(len(t.vin)))
	for idx := range t.vin {
		b = append(b, t.prevTxid[idx][:]...)
		b = appendU32(b, t.prevVout[idx])
		if idx == k {
			b = appendVarint(b, uint64(len(scriptCode)))
			b = append(b, scriptCode...)
		} else {
			b = appendVarint(b, 0)
		}
		b = appendU32(b, t.seq[idx])
	}
	b = appendVarint(b, uint64(len(t.vout)))
	for _, o := range t.vout {
		b = appendU64(b, o.value)
		b = appendVarint(b, uint64(len(o.script)))
		b = append(b, o.script...)
	}
	b = appendU32(b, t.locktime)
	// hashtype 0x01 as 4-byte LE int32
	b = append(b, 0x01, 0x00, 0x00, 0x00)
	h1 := sha256.Sum256(b)
	return sha256.Sum256(h1[:])
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}
func appendU64(b []byte, v uint64) []byte {
	for i := 0; i < 8; i++ {
		b = append(b, byte(v>>(8*uint(i))))
	}
	return b
}
func appendVarint(b []byte, v uint64) []byte {
	switch {
	case v < 0xfd:
		return append(b, byte(v))
	case v <= 0xffff:
		return append(b, 0xfd, byte(v), byte(v>>8))
	case v <= 0xffffffff:
		return append(b, 0xfe, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	default:
		return appendU64(append(b, 0xff), v)
	}
}
