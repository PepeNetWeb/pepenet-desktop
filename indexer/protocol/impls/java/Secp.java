import java.math.BigInteger;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

// §4 Strategy B — real secp256k1 (self-rolled, BigInteger-backed). Mirrors the C
// reference impls/c/src/secp256k1.c semantics exactly, byte-for-byte at the API edge:
//   • field arithmetic mod p = 2^256 − 2^32 − 977
//   • affine point ops + double-and-add scalar multiply
//   • pubkey decode / on-curve / decompress (33-byte 02/03 via sqrt a^((p+1)/4);
//     65-byte 04; reject X≥p / non-residue / bad prefix)
//   • ECDSA verify (does NOT enforce low-S; rejects r/s==0 or ≥n)
//   • RFC-6979 deterministic sign (HMAC-SHA256, low-S normalized)
//   • compressed pubkey derivation, canonical strict-DER
// Correctness, not speed; not constant time — verifier/test oracle only.
final class Secp {

    // ── constants (ported from secp256k1.c) ──────────────────────────────────
    static final BigInteger P = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    static final BigInteger N = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    static final BigInteger N_HALF = new BigInteger(
        "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0", 16);
    static final BigInteger GX = new BigInteger(
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    static final BigInteger GY = new BigInteger(
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    static final BigInteger SEVEN = BigInteger.valueOf(7);
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);

    // ── affine point (null == point at infinity) ─────────────────────────────
    static final class Pt { final BigInteger x, y; Pt(BigInteger x, BigInteger y) { this.x = x; this.y = y; } }
    private static final Pt INF = null;
    static final Pt G = new Pt(GX, GY);

    private static Pt add(Pt p, Pt q) {
        if (p == INF) return q;
        if (q == INF) return p;
        if (p.x.equals(q.x)) {
            if (p.y.add(q.y).mod(P).signum() == 0) return INF;   // P + (−P)
            return dbl(p);                                        // P == Q
        }
        BigInteger lam = q.y.subtract(p.y).multiply(q.x.subtract(p.x).modInverse(P)).mod(P);
        BigInteger x3 = lam.multiply(lam).subtract(p.x).subtract(q.x).mod(P);
        BigInteger y3 = lam.multiply(p.x.subtract(x3)).subtract(p.y).mod(P);
        return new Pt(x3, y3);
    }
    private static Pt dbl(Pt p) {
        if (p == INF || p.y.signum() == 0) return INF;
        BigInteger lam = THREE.multiply(p.x).multiply(p.x)
            .multiply(TWO.multiply(p.y).modInverse(P)).mod(P);
        BigInteger x3 = lam.multiply(lam).subtract(TWO.multiply(p.x)).mod(P);
        BigInteger y3 = lam.multiply(p.x.subtract(x3)).subtract(p.y).mod(P);
        return new Pt(x3, y3);
    }
    // k·P, double-and-add MSB-first (k taken mod nothing here; caller passes [1,n))
    private static Pt mul(BigInteger k, Pt p) {
        Pt acc = INF;
        for (int i = k.bitLength() - 1; i >= 0; i--) {
            acc = dbl(acc);
            if (k.testBit(i)) acc = add(acc, p);
        }
        return acc;
    }

    // ── field helpers ────────────────────────────────────────────────────────
    private static BigInteger rhs(BigInteger x) { return x.multiply(x).multiply(x).add(SEVEN).mod(P); }
    // modular sqrt for p ≡ 3 (mod 4): a^((p+1)/4)
    private static BigInteger sqrtP(BigInteger a) { return a.modPow(P.add(BigInteger.ONE).shiftRight(2), P); }

    // ── 32-byte big-endian helpers (strip sign byte / left-pad) ──────────────
    static byte[] be32(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] r = new byte[32];
        int src = Math.max(0, b.length - 32), len = Math.min(32, b.length);
        System.arraycopy(b, src, r, 32 - len, len);
        return r;
    }
    private static BigInteger fromBE(byte[] b, int off, int len) {
        return new BigInteger(1, Arrays.copyOfRange(b, off, off + len));
    }

    // ── pubkey decode + on-curve ─────────────────────────────────────────────
    // returns the decoded affine point, or null if off-curve / malformed.
    static Pt decode(byte[] pub) {
        if (pub.length == 33 && (pub[0] == 0x02 || pub[0] == 0x03)) {
            BigInteger x = fromBE(pub, 1, 32);
            if (x.compareTo(P) >= 0) return null;
            BigInteger r = rhs(x);
            BigInteger beta = sqrtP(r);
            if (!beta.multiply(beta).mod(P).equals(r)) return null;   // non-residue ⇒ off curve
            boolean wantOdd = (pub[0] == 0x03);
            if (beta.testBit(0) != wantOdd) beta = P.subtract(beta);
            return new Pt(x, beta);
        }
        if (pub.length == 65 && pub[0] == 0x04) {
            BigInteger x = fromBE(pub, 1, 32), y = fromBE(pub, 33, 32);
            if (x.compareTo(P) >= 0 || y.compareTo(P) >= 0) return null;
            if (!y.multiply(y).mod(P).equals(rhs(x))) return null;
            return new Pt(x, y);
        }
        return null;
    }
    static boolean onCurve(byte[] pub) { return decode(pub) != null; }

    // ── ECDSA verify (low-S NOT enforced; reject r/s==0 or ≥n) ───────────────
    static boolean ecdsaVerify(byte[] hash32, byte[] r32, byte[] s32, byte[] pub) {
        Pt q = decode(pub);
        if (q == null) return false;
        BigInteger r = fromBE(r32, 0, 32), s = fromBE(s32, 0, 32);
        if (r.signum() == 0 || r.compareTo(N) >= 0) return false;
        if (s.signum() == 0 || s.compareTo(N) >= 0) return false;
        BigInteger z = fromBE(hash32, 0, 32).mod(N);
        BigInteger w = s.modInverse(N);
        BigInteger u1 = z.multiply(w).mod(N), u2 = r.multiply(w).mod(N);
        Pt rj = add(mul(u1, G), mul(u2, q));
        if (rj == INF) return false;
        return rj.x.mod(N).equals(r);
    }

    // ── HMAC-SHA256 (javax.crypto, standard) ─────────────────────────────────
    private static byte[] hmac(byte[] key, byte[] msg) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(key, "HmacSHA256"));
            return m.doFinal(msg);
        } catch (Exception e) { throw new RuntimeException(e); }
    }
    private static byte[] cat(byte[]... parts) {
        int n = 0; for (byte[] p : parts) n += p.length;
        byte[] r = new byte[n]; int o = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, r, o, p.length); o += p.length; }
        return r;
    }

    // ── RFC-6979 deterministic nonce k ∈ [1,n) ───────────────────────────────
    private static BigInteger rfc6979k(byte[] priv32, byte[] hash32) {
        byte[] h1o = be32(fromBE(hash32, 0, 32).mod(N));      // bits2octets = (h1 mod n) BE
        byte[] V = new byte[32]; Arrays.fill(V, (byte) 0x01);
        byte[] K = new byte[32]; // 0x00*32
        K = hmac(K, cat(V, new byte[]{0x00}, priv32, h1o));
        V = hmac(K, V);
        K = hmac(K, cat(V, new byte[]{0x01}, priv32, h1o));
        V = hmac(K, V);
        for (;;) {
            V = hmac(K, V);                                  // T = V (qlen == 256 ⇒ one block)
            BigInteger k = fromBE(V, 0, 32);
            if (k.signum() != 0 && k.compareTo(N) < 0) return k;
            K = hmac(K, cat(V, new byte[]{0x00}));
            V = hmac(K, V);
        }
    }

    // ── ECDSA sign (RFC-6979, low-S). r32/s32 32-byte BE; null on failure ────
    static byte[][] ecdsaSign(byte[] priv32, byte[] hash32) {
        BigInteger d = fromBE(priv32, 0, 32);
        if (d.signum() == 0 || d.compareTo(N) >= 0) return null;
        BigInteger z = fromBE(hash32, 0, 32).mod(N);
        byte[] feed = Arrays.copyOf(hash32, 32);
        for (int attempt = 0; attempt < 64; attempt++) {
            BigInteger k = rfc6979k(priv32, feed);
            Pt rp = mul(k, G);
            if (rp == INF) { feed = Hashes.sha256(be32(k)); continue; }
            BigInteger r = rp.x.mod(N);
            if (r.signum() == 0) { feed = Hashes.sha256(be32(k)); continue; }
            BigInteger s = k.modInverse(N).multiply(z.add(r.multiply(d).mod(N)).mod(N)).mod(N);
            if (s.signum() == 0) { feed = Hashes.sha256(be32(k)); continue; }
            if (s.compareTo(N_HALF) > 0) s = N.subtract(s);   // low-S
            return new byte[][]{ be32(r), be32(s) };
        }
        return null;
    }

    // ── compressed pubkey (0x02/0x03 ‖ X) from a private scalar ──────────────
    static byte[] pubkey(byte[] priv32) {
        BigInteger d = fromBE(priv32, 0, 32);
        if (d.signum() == 0 || d.compareTo(N) >= 0) return null;
        Pt p = mul(d, G);
        if (p == INF) return null;
        byte[] out = new byte[33];
        out[0] = p.y.testBit(0) ? (byte) 0x03 : (byte) 0x02;
        System.arraycopy(be32(p.x), 0, out, 1, 32);
        return out;
    }

    // ── canonical strict-DER of (r,s) ‖ SIGHASH_ALL (mirrors C der_int/der_sig)
    static byte[] derInt(byte[] v) {                          // minimal positive INTEGER
        int i = 0; while (i < 31 && v[i] == 0) i++;
        int len = 32 - i; int pad = ((v[i] & 0x80) != 0) ? 1 : 0;
        byte[] out = new byte[2 + pad + len];
        int n = 0;
        out[n++] = 0x02; out[n++] = (byte) (len + pad);
        if (pad == 1) out[n++] = 0x00;
        System.arraycopy(v, i, out, n, len);
        return out;
    }
    static byte[] derSig(byte[] r, byte[] s) {
        byte[] ir = derInt(r), is = derInt(s);
        int bl = ir.length + is.length;
        byte[] out = new byte[2 + bl + 1];
        out[0] = 0x30; out[1] = (byte) bl;
        System.arraycopy(ir, 0, out, 2, ir.length);
        System.arraycopy(is, 0, out, 2 + ir.length, is.length);
        out[2 + bl] = 0x01;                                  // SIGHASH_ALL
        return out;
    }

    // ── ECMH (Elliptic Curve Multiset Hash) ──────────────────────────────────
    // An accumulator is a 33-byte compressed point (0x02/0x03 ‖ X-be); the all-
    // zero sentinel (prefix 0x00) is the identity ∞. Mirrors secp256k1.c.
    private static final byte[] ECMH_H2C_TAG = { 'E','C','M','H','h','2','c','1' };

    static byte[] ecmhIdentity() { return new byte[33]; }

    // point → 33 bytes (∞ → zeros)
    private static byte[] ecmhSer(Pt p) {
        if (p == INF) return new byte[33];
        byte[] out = new byte[33];
        out[0] = p.y.testBit(0) ? (byte) 0x03 : (byte) 0x02;
        System.arraycopy(be32(p.x), 0, out, 1, 32);
        return out;
    }
    // 33 bytes → point (prefix 0x00 ⇒ ∞)
    private static Pt ecmhLoad(byte[] in33) {
        if (in33[0] == 0) return INF;
        return decode(in33);
    }

    // try-and-increment hash-to-curve. Returns {pt33, [ctr]} (ctr in second slot).
    static byte[][] ecmhHash(byte[] pre) {
        for (int ctr = 0; ; ctr++) {
            byte[] cb = { (byte) ctr, (byte) (ctr >> 8), (byte) (ctr >> 16), (byte) (ctr >> 24) };
            byte[] msg = (pre.length > 0)
                ? cat(ECMH_H2C_TAG, pre, cb)
                : cat(ECMH_H2C_TAG, cb);
            byte[] h = Hashes.sha256(msg);
            BigInteger x = new BigInteger(1, h).mod(P);          // x = SHA256(...) mod p
            BigInteger r = rhs(x);
            BigInteger beta = sqrtP(r);
            if (!beta.multiply(beta).mod(P).equals(r)) continue; // x³+7 not a QR ⇒ bump ctr
            byte[] pt = new byte[33];
            pt[0] = 0x02;                                         // canonical even-Y
            System.arraycopy(be32(x), 0, pt, 1, 32);
            byte[] ctrb = { (byte) ctr };
            return new byte[][]{ pt, ctrb };
        }
    }

    static void ecmhNegate(byte[] pt33) { if (pt33[0] != 0) pt33[0] ^= 1; }

    static byte[] ecmhAdd(byte[] acc33, byte[] pt33) {
        Pt a = ecmhLoad(acc33), p = ecmhLoad(pt33);
        return ecmhSer(add(a, p));
    }

    // ── self-check KAT (mirrors secp_selftest); 0 = pass, else failure count ──
    static int selftest() {
        int fail = 0;
        // constants: N_HALF == N>>1
        if (!N.shiftRight(1).equals(N_HALF)) fail++;
        // G on curve via uncompressed encoding
        { byte[] g = new byte[65]; g[0] = 0x04;
          System.arraycopy(be32(GX), 0, g, 1, 32); System.arraycopy(be32(GY), 0, g, 33, 32);
          if (!onCurve(g)) fail++; }
        // 2G known-answer
        { Pt p2 = mul(TWO, G);
          BigInteger G2X = new BigInteger("C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5", 16);
          BigInteger G2Y = new BigInteger("1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A", 16);
          if (p2 == null || !p2.x.equals(G2X) || !p2.y.equals(G2Y)) fail++; }
        // n·G == ∞
        { if (mul(N, G) != null) fail++; }
        // decompress G round-trip: compress (Gy even ⇒ 0x02), decode, compare
        { byte[] gc = new byte[33]; gc[0] = 0x02; System.arraycopy(be32(GX), 0, gc, 1, 32);
          Pt p = decode(gc);
          if (p == null || !p.y.equals(GY)) fail++; }
        // sign / verify round-trip + tamper over a few deterministic keys
        for (int t = 1; t <= 4; t++) {
            byte[] priv = new byte[32]; priv[31] = (byte) (t * 7 + 1);
            byte[] pub = pubkey(priv); if (pub == null) { fail++; continue; }
            byte[] msg = new byte[32]; for (int i = 0; i < 32; i++) msg[i] = (byte) (i * 13 + t);
            byte[] mh = Hashes.sha256(msg);
            byte[][] rs = ecdsaSign(priv, mh); if (rs == null) { fail++; continue; }
            if (!ecdsaVerify(mh, rs[0], rs[1], pub)) fail++;
            byte[] mh2 = Arrays.copyOf(mh, 32); mh2[0] ^= 0x01;
            if (ecdsaVerify(mh2, rs[0], rs[1], pub)) fail++;
        }
        return fail;
    }
}
