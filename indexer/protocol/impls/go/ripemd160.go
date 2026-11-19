package main

// Self-rolled RIPEMD-160 (no stdlib package exists; golang.org/x/crypto is
// third-party and forbidden). Implemented directly from the RIPEMD-160 spec
// (Dobbertin/Bosselaers/Preneel). KATs are asserted in selftest.go.

// ripemd160 returns the 20-byte RIPEMD-160 digest of msg.
func ripemd160(msg []byte) [20]byte {
	var h [5]uint32 = [5]uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}

	// Pre-processing: append 0x80, pad with zeros to 56 mod 64, then 64-bit LE length in bits.
	ml := uint64(len(msg)) * 8
	data := make([]byte, len(msg))
	copy(data, msg)
	data = append(data, 0x80)
	for len(data)%64 != 56 {
		data = append(data, 0x00)
	}
	for i := 0; i < 8; i++ {
		data = append(data, byte(ml>>(8*uint(i))))
	}

	for off := 0; off < len(data); off += 64 {
		var x [16]uint32
		for i := 0; i < 16; i++ {
			j := off + i*4
			x[i] = uint32(data[j]) | uint32(data[j+1])<<8 | uint32(data[j+2])<<16 | uint32(data[j+3])<<24
		}
		ripemdBlock(&h, &x)
	}

	var out [20]byte
	for i := 0; i < 5; i++ {
		out[i*4] = byte(h[i])
		out[i*4+1] = byte(h[i] >> 8)
		out[i*4+2] = byte(h[i] >> 16)
		out[i*4+3] = byte(h[i] >> 24)
	}
	return out
}

func rol(x uint32, n uint) uint32 { return (x << n) | (x >> (32 - n)) }

// Boolean functions per round.
func rf(j int, x, y, z uint32) uint32 {
	switch {
	case j < 16:
		return x ^ y ^ z
	case j < 32:
		return (x & y) | (^x & z)
	case j < 48:
		return (x | ^y) ^ z
	case j < 64:
		return (x & z) | (y & ^z)
	default:
		return x ^ (y | ^z)
	}
}

var (
	// message word selection (left and right lines)
	rL = [80]int{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
		3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
		1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
		4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
	}
	rR = [80]int{
		5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
		6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
		15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
		8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
		12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
	}
	// rotate amounts
	sL = [80]uint{
		11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
		7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
		11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
		11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
		9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
	}
	sR = [80]uint{
		8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
		9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
		9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
		15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
		8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
	}
	// added constants
	kL = [5]uint32{0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E}
	kR = [5]uint32{0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000}
)

func ripemdBlock(h *[5]uint32, x *[16]uint32) {
	al, bl, cl, dl, el := h[0], h[1], h[2], h[3], h[4]
	ar, br, cr, dr, er := h[0], h[1], h[2], h[3], h[4]

	for j := 0; j < 80; j++ {
		// left line
		t := rol(al+rf(j, bl, cl, dl)+x[rL[j]]+kL[j/16], sL[j]) + el
		al = el
		el = dl
		dl = rol(cl, 10)
		cl = bl
		bl = t
		// right line (boolean function index is reversed: 79-j)
		t2 := rol(ar+rf(79-j, br, cr, dr)+x[rR[j]]+kR[j/16], sR[j]) + er
		ar = er
		er = dr
		dr = rol(cr, 10)
		cr = br
		br = t2
	}

	t := h[1] + cl + dr
	h[1] = h[2] + dl + er
	h[2] = h[3] + el + ar
	h[3] = h[4] + al + br
	h[4] = h[0] + bl + cr
	h[0] = t
}
