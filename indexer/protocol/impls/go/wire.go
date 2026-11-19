package main

// Wire decoder: payload bytes (+ output value) → ACTION | IGNORE.
// Strict, fail-closed (protocol-spec.md §0/§1/§2, SPEC-conformance.md §9).
// A malformed payload NEVER panics and NEVER errors to the caller — it decodes
// to IGNORE. Every slice read is bounds-guarded. Names-only: no text-POST branch;
// bare UTF-8 and the overlay band fall through to IGNORE.

type carrierKind int

const (
	IGNORE carrierKind = iota
	ACTION
)

// Decoded carrier handed to the fold.
type Carrier struct {
	kind   carrierKind
	opcode byte

	// Per-opcode parsed fields (only those relevant to opcode are set):
	commit [32]byte // COMMIT commitment
	salt   [32]byte // CLAIM salt
	name   []byte   // CLAIM/SELL/RESERVE/SETTLE/PAY/SELL_TO name
	price  uint64   // SELL/SELL_TO
	window uint32   // SELL
	target [20]byte // TRANSFER target
	buyer  [20]byte // SELL_TO buyer
	anchor int64    // RENEW/TRANSFER/RELEASE 5-byte height anchor (-1 if absent)
	flags  []byte   // RENEW/TRANSFER/RELEASE bitmap (nil if absent / all-form)
	hasAnchor bool

	asIndex int    // AS index
	idxA    int    // TRADE
	idxB    int    // TRADE
	nameA   []byte // TRADE
	nameB   []byte // TRADE
}

// validName enforces §3.1: charset [a-z0-9-], length 1..32, reject-not-fold, plus
// structural (RFC-1123 / IDNA): no leading/trailing hyphen; no `--` at positions
// 3–4 (kills xn-- and every ACE prefix). Every consensus-valid name is a safe
// hostname label.
func validName(b []byte) bool {
	if len(b) < 1 || len(b) > 32 {
		return false
	}
	for _, c := range b {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	if b[0] == '-' || b[len(b)-1] == '-' {
		return false
	}
	if len(b) >= 4 && b[2] == '-' && b[3] == '-' {
		return false
	}
	return true
}

func leU32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
func leU64(b []byte) uint64 {
	var v uint64
	for i := 0; i < 8; i++ {
		v |= uint64(b[i]) << (8 * uint(i))
	}
	return v
}
func leU40(b []byte) int64 { // 5-byte little-endian height anchor
	var v int64
	for i := 0; i < 5; i++ {
		v |= int64(b[i]) << (8 * uint(i))
	}
	return v
}

// decode is the pure, fail-closed payload classifier. value is accepted for
// API compatibility with OP_RETURN carriers but is not used (names-only demux).
func decode(payload []byte, value uint64) Carrier {
	_ = value
	ig := Carrier{kind: IGNORE}

	// §1 action recognition: prefix 0xFF 'P' 'N' + opcode 0x01..0x0C.
	if len(payload) >= 4 && payload[0] == 0xFF && payload[1] == 0x50 && payload[2] == 0x4E {
		return decodeAction(payload)
	}
	// everything else (UTF-8 noise, overlay, empty) → IGNORE
	return ig
}

func decodeAction(payload []byte) Carrier {
	ig := Carrier{kind: IGNORE}
	op := payload[3]
	body := payload[4:]
	bl := len(body)
	c := Carrier{kind: ACTION, opcode: op, anchor: -1, asIndex: -1, idxA: -1, idxB: -1}

	if op < OP_MIN || op > OP_MAX {
		return ig
	}

	switch op {
	case OP_COMMIT:
		if bl != 32 {
			return ig
		}
		copy(c.commit[:], body[0:32])
		return c

	case OP_CLAIM:
		if bl < 33 || bl > 64 { // salt32 + name1..32
			return ig
		}
		copy(c.salt[:], body[0:32])
		nm := body[32:]
		if !validName(nm) {
			return ig
		}
		c.name = cloneBytes(nm)
		return c

	case OP_RENEW:
		// 0 = all; 5 = all-safe (anchor5); [6,BODY_MAX] = selective (anchor5 + flags1..FLAGS_MAX)
		switch {
		case bl == 0:
			return c
		case bl == 5:
			c.hasAnchor = true
			c.anchor = leU40(body[0:5])
			return c
		case bl >= 6 && bl <= BODY_MAX:
			c.hasAnchor = true
			c.anchor = leU40(body[0:5])
			c.flags = cloneBytes(body[5:]) // 1..FLAGS_MAX bytes
			return c
		default:
			return ig
		}

	case OP_TRANSFER:
		// 20 = all; [26,BODY_MAX] = selective (target20 + anchor5 + flags1..FLAGS_XFER_MAX)
		switch {
		case bl == 20:
			copy(c.target[:], body[0:20])
			return c
		case bl >= 26 && bl <= BODY_MAX:
			copy(c.target[:], body[0:20])
			c.hasAnchor = true
			c.anchor = leU40(body[20:25])
			c.flags = cloneBytes(body[25:]) // 1..FLAGS_XFER_MAX
			return c
		default:
			return ig
		}

	case OP_SELL:
		if bl < 13 || bl > 44 { // price8 + window4 + name1..32
			return ig
		}
		c.price = leU64(body[0:8])
		c.window = leU32(body[8:12])
		nm := body[12:]
		if !validName(nm) {
			return ig
		}
		c.name = cloneBytes(nm)
		return c

	case OP_RENEW_NAME, OP_RELEASE_NAME, OP_RESERVE, OP_SETTLE, OP_PAY:
		if bl < 1 || bl > 32 { // name1..32
			return ig
		}
		if !validName(body) {
			return ig
		}
		c.name = cloneBytes(body)
		return c

	case OP_TRANSFER_NAME:
		if bl < 21 || bl > 52 { // target20 + name1..32
			return ig
		}
		copy(c.target[:], body[0:20])
		nm := body[20:]
		if !validName(nm) {
			return ig
		}
		c.name = cloneBytes(nm)
		return c

	case OP_RELEASE:
		if bl < 6 || bl > BODY_MAX {
			return ig
		}
		c.hasAnchor = true
		c.anchor = leU40(body[0:5])
		c.flags = cloneBytes(body[5:]) // 1..FLAGS_MAX
		return c

	case OP_SELL_TO:
		if bl < 29 || bl > 60 { // price8 + buyer20 + name1..32
			return ig
		}
		c.price = leU64(body[0:8])
		copy(c.buyer[:], body[8:28])
		nm := body[28:]
		if !validName(nm) {
			return ig
		}
		c.name = cloneBytes(nm)
		return c

	case OP_AS:
		if bl != 1 {
			return ig
		}
		c.asIndex = int(body[0])
		return c

	case OP_TRADE:
		if bl < 5 {
			return ig
		}
		c.idxA = int(body[0])
		c.idxB = int(body[1])
		rest := body[2:]
		// exactly one 0x2C, both sides valid §3.1
		comma := -1
		count := 0
		for i, b := range rest {
			if b == 0x2C {
				count++
				comma = i
			}
		}
		if count != 1 {
			return ig
		}
		na := rest[:comma]
		nb := rest[comma+1:]
		if !validName(na) || !validName(nb) {
			return ig
		}
		c.nameA = cloneBytes(na)
		c.nameB = cloneBytes(nb)
		return c

	default:
		return ig
	}
}

func cloneBytes(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
