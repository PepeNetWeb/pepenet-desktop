// Hash primitives — derived from the spec.
//   - SHA-256 via the JDK (a standard, unambiguous primitive).
//   - RIPEMD-160 self-rolled (the one primitive not in the JDK; §13 mandates it
//     and pins KATs: ""->9c1185a5..., "abc"->8eb208f7...f15a0bfc).
//   - hash160(x) = RIPEMD160(SHA256(x))   (§0 address_hash, §4 Identity)
//   - dsha256(x) = SHA256(SHA256(x))      (legacy sighash, §4 / off-chain digest §5)
//
// RIPEMD-160 implemented straight from the public algorithm (Dobbertin–Bosselaers
// –Preneel). KATs in Selftest gate every table below; a transposed constant fails
// loudly rather than silently forking.

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

final class Hashes {

    static byte[] sha256(byte[] in) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(in);
        } catch (NoSuchAlgorithmException e) { throw new RuntimeException(e); }
    }

    static byte[] dsha256(byte[] in) { return sha256(sha256(in)); }

    static byte[] hash160(byte[] in) { return ripemd160(sha256(in)); }

    // ---- RIPEMD-160 ----------------------------------------------------------

    // left-line message word order
    private static final int[] RL = {
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
        7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
        3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
        1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
        4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13 };
    // right-line message word order
    private static final int[] RR = {
        5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
        6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
        15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
        8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
        12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11 };
    // left-line rotate amounts
    private static final int[] SL = {
        11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
        7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
        11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
        11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
        9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6 };
    // right-line rotate amounts
    private static final int[] SR = {
        8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
        9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
        9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
        15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
        8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11 };

    private static int f(int j, int x, int y, int z) {
        if (j < 16) return x ^ y ^ z;
        if (j < 32) return (x & y) | (~x & z);
        if (j < 48) return (x | ~y) ^ z;
        if (j < 64) return (x & z) | (y & ~z);
        return x ^ (y | ~z);
    }
    private static int kl(int j) {
        if (j < 16) return 0x00000000;
        if (j < 32) return 0x5A827999;
        if (j < 48) return 0x6ED9EBA1;
        if (j < 64) return 0x8F1BBCDC;
        return 0xA953FD4E;
    }
    private static int kr(int j) {
        if (j < 16) return 0x50A28BE6;
        if (j < 32) return 0x5C4DD124;
        if (j < 48) return 0x6D703EF3;
        if (j < 64) return 0x7A6D76E9;
        return 0x00000000;
    }

    static byte[] ripemd160(byte[] msg) {
        int h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0;

        long bitLen = (long) msg.length * 8;
        // pad: 0x80, then zeros, then 64-bit little-endian length, to a 64-byte multiple
        int padLen = (int) ((56 - (msg.length + 1) % 64 + 64) % 64);
        byte[] m = new byte[msg.length + 1 + padLen + 8];
        System.arraycopy(msg, 0, m, 0, msg.length);
        m[msg.length] = (byte) 0x80;
        for (int i = 0; i < 8; i++) m[m.length - 8 + i] = (byte) (bitLen >>> (8 * i));

        int[] X = new int[16];
        for (int off = 0; off < m.length; off += 64) {
            for (int i = 0; i < 16; i++) {
                X[i] = (m[off + 4 * i] & 0xFF)
                     | ((m[off + 4 * i + 1] & 0xFF) << 8)
                     | ((m[off + 4 * i + 2] & 0xFF) << 16)
                     | ((m[off + 4 * i + 3] & 0xFF) << 24);
            }
            int al = h0, bl = h1, cl = h2, dl = h3, el = h4;
            int ar = h0, br = h1, cr = h2, dr = h3, er = h4;
            for (int j = 0; j < 80; j++) {
                int t = Integer.rotateLeft(al + f(j, bl, cl, dl) + X[RL[j]] + kl(j), SL[j]) + el;
                al = el; el = dl; dl = Integer.rotateLeft(cl, 10); cl = bl; bl = t;
                t = Integer.rotateLeft(ar + f(79 - j, br, cr, dr) + X[RR[j]] + kr(j), SR[j]) + er;
                ar = er; er = dr; dr = Integer.rotateLeft(cr, 10); cr = br; br = t;
            }
            int t = h1 + cl + dr;
            h1 = h2 + dl + er;
            h2 = h3 + el + ar;
            h3 = h4 + al + br;
            h4 = h0 + bl + cr;
            h0 = t;
        }

        byte[] out = new byte[20];
        int[] h = { h0, h1, h2, h3, h4 };
        for (int i = 0; i < 5; i++)
            for (int b = 0; b < 4; b++) out[4 * i + b] = (byte) (h[i] >>> (8 * b));
        return out;
    }
}
