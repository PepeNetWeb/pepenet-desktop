using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Pepenet;

/// <summary>
/// §4 Strategy B — real secp256k1 (self-rolled, BCL-only). Mirrors impls/c/src/secp256k1.c:
/// field arithmetic mod p = 2^256 − 2^32 − 977, point ops, ECDSA verify, and RFC-6979
/// deterministic signing (HMAC-SHA256, low-S normalized). Correctness, not speed; never
/// constant time — verifier/test oracle only. Uses System.Numerics.BigInteger (always
/// treated as unsigned mod p/n, emitted fixed 32-byte big-endian).
/// </summary>
public static class Secp256k1
{
    // p = 2^256 − 2^32 − 977 ; n = group order.
    public static readonly BigInteger P  = ParseBe("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    public static readonly BigInteger N  = ParseBe("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    public static readonly BigInteger NHalf = ParseBe("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0");
    public static readonly BigInteger Gx = ParseBe("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    public static readonly BigInteger Gy = ParseBe("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");

    // ── affine point; null == infinity ─────────────────────────────────────────
    public readonly struct Point
    {
        public readonly BigInteger X, Y;
        public readonly bool Inf;
        private Point(BigInteger x, BigInteger y, bool inf) { X = x; Y = y; Inf = inf; }
        public static readonly Point Infinity = new(BigInteger.Zero, BigInteger.Zero, true);
        public static Point Affine(BigInteger x, BigInteger y) => new(x, y, false);
    }

    private static readonly Point G = Point.Affine(Gx, Gy);

    private static BigInteger Mod(BigInteger a, BigInteger m)
    {
        BigInteger r = a % m;
        return r.Sign < 0 ? r + m : r;
    }

    private static BigInteger ModInv(BigInteger a, BigInteger m)
    {
        // extended euclid; a treated as in [0,m)
        BigInteger g = m, x = 0, x1 = 1, aa = Mod(a, m);
        BigInteger old_r = aa, r = m;
        BigInteger old_s = 1, s = 0;
        while (r != 0)
        {
            BigInteger q = old_r / r;
            (old_r, r) = (r, old_r - q * r);
            (old_s, s) = (s, old_s - q * s);
        }
        // old_r == gcd; old_s == inverse
        return Mod(old_s, m);
    }

    // ── point ops over GF(p) (affine; a = 0, b = 7) ─────────────────────────────
    private static Point Add(Point p, Point q)
    {
        if (p.Inf) return q;
        if (q.Inf) return p;
        if (p.X == q.X)
        {
            if (Mod(p.Y + q.Y, P) == 0) return Point.Infinity; // P + (−P)
            return Double(p);                                   // P == Q
        }
        BigInteger lam = Mod((q.Y - p.Y) * ModInv(Mod(q.X - p.X, P), P), P);
        BigInteger x3 = Mod(lam * lam - p.X - q.X, P);
        BigInteger y3 = Mod(lam * (p.X - x3) - p.Y, P);
        return Point.Affine(x3, y3);
    }

    private static Point Double(Point p)
    {
        if (p.Inf || p.Y == 0) return Point.Infinity;
        BigInteger lam = Mod((3 * p.X * p.X) * ModInv(Mod(2 * p.Y, P), P), P);
        BigInteger x3 = Mod(lam * lam - 2 * p.X, P);
        BigInteger y3 = Mod(lam * (p.X - x3) - p.Y, P);
        return Point.Affine(x3, y3);
    }

    // k·P, k as 32-byte big-endian (double-and-add, MSB first).
    private static Point Mul(Point p, byte[] kBe)
    {
        BigInteger k = ParseBeBytes(kBe);
        Point acc = Point.Infinity;
        for (int bit = 255; bit >= 0; bit--)
        {
            acc = Double(acc);
            if (((k >> bit) & 1) == 1) acc = Add(acc, p);
        }
        return acc;
    }

    // ── pubkey decode + on-curve ────────────────────────────────────────────────
    private static BigInteger RhsCurve(BigInteger x) => Mod(x * x % P * x + 7, P);

    // decode to affine; returns true iff on curve (and parity-consistent for 02/03).
    private static bool PubDecode(byte[] pub, out Point pt)
    {
        pt = Point.Infinity;
        if (pub.Length == 33 && (pub[0] == 0x02 || pub[0] == 0x03))
        {
            BigInteger x = ParseBeSpan(pub, 1, 32);
            if (x >= P) return false;
            BigInteger rhs = RhsCurve(x);
            BigInteger beta = BigInteger.ModPow(rhs, (P + 1) / 4, P); // p ≡ 3 mod 4
            if (Mod(beta * beta, P) != rhs) return false;            // non-residue ⇒ off curve
            bool wantOdd = pub[0] == 0x03;
            if ((beta.IsEven ? false : true) != wantOdd) beta = Mod(P - beta, P);
            pt = Point.Affine(x, beta);
            return true;
        }
        if (pub.Length == 65 && pub[0] == 0x04)
        {
            BigInteger x = ParseBeSpan(pub, 1, 32);
            BigInteger y = ParseBeSpan(pub, 33, 32);
            if (x >= P || y >= P) return false;
            if (Mod(y * y, P) != RhsCurve(x)) return false;
            pt = Point.Affine(x, y);
            return true;
        }
        return false;
    }

    public static bool OnCurve(byte[] pub) => PubDecode(pub, out _);

    // ── ECDSA verify (does NOT enforce low-S; rejects r/s == 0 or ≥ n) ───────────
    public static bool EcdsaVerify(byte[] hash32, byte[] r32, byte[] s32, byte[] pub)
    {
        if (!PubDecode(pub, out Point q)) return false;
        BigInteger r = ParseBeBytes(r32), s = ParseBeBytes(s32);
        if (r == 0 || r >= N) return false;
        if (s == 0 || s >= N) return false;
        BigInteger z = Mod(ParseBeBytes(hash32), N);
        BigInteger w = ModInv(s, N);
        BigInteger u1 = Mod(z * w, N);
        BigInteger u2 = Mod(r * w, N);
        Point a = Mul(G, To32Be(u1));
        Point b = Mul(q, To32Be(u2));
        Point rp = Add(a, b);
        if (rp.Inf) return false;
        return Mod(rp.X, N) == r;
    }

    // ── pubkey derivation (33-byte compressed) ──────────────────────────────────
    public static bool Pubkey(byte[] priv32, out byte[] pub33)
    {
        pub33 = new byte[33];
        BigInteger d = ParseBeBytes(priv32);
        if (d == 0 || d >= N) return false;
        Point p = Mul(G, priv32);
        if (p.Inf) return false;
        pub33[0] = p.Y.IsEven ? (byte)0x02 : (byte)0x03;
        byte[] xb = To32Be(p.X);
        Buffer.BlockCopy(xb, 0, pub33, 1, 32);
        return true;
    }

    // ── HMAC-SHA256 (BCL) ───────────────────────────────────────────────────────
    private static byte[] Hmac(byte[] key, byte[] msg)
    {
        using var h = new HMACSHA256(key);
        return h.ComputeHash(msg);
    }

    // ── RFC-6979 nonce ──────────────────────────────────────────────────────────
    private static byte[] Rfc6979K(byte[] priv32, byte[] hash32)
    {
        // bits2octets(h1) = (h1 mod n) as 32B BE
        byte[] h1o = To32Be(Mod(ParseBeBytes(hash32), N));
        byte[] V = new byte[32]; for (int i = 0; i < 32; i++) V[i] = 0x01;
        byte[] K = new byte[32];                                  // all-zero
        K = Hmac(K, Cat(V, new byte[] { 0x00 }, priv32, h1o));    // K = HMAC(K, V‖00‖x‖h1o)
        V = Hmac(K, V);
        K = Hmac(K, Cat(V, new byte[] { 0x01 }, priv32, h1o));    // K = HMAC(K, V‖01‖x‖h1o)
        V = Hmac(K, V);
        while (true)
        {
            V = Hmac(K, V);                                       // T = V (qlen == 256)
            BigInteger k = ParseBeBytes(V);
            if (k != 0 && k < N) return (byte[])V.Clone();
            K = Hmac(K, Cat(V, new byte[] { 0x00 }));
            V = Hmac(K, V);
        }
    }

    // ── RFC-6979 deterministic sign, low-S normalized ───────────────────────────
    public static bool EcdsaSign(byte[] priv32, byte[] hash32, out byte[] r32, out byte[] s32)
    {
        r32 = new byte[32]; s32 = new byte[32];
        BigInteger d = ParseBeBytes(priv32);
        if (d == 0 || d >= N) return false;
        BigInteger z = Mod(ParseBeBytes(hash32), N);
        byte[] feed = (byte[])hash32.Clone();
        for (int attempt = 0; attempt < 64; attempt++)
        {
            byte[] kb = Rfc6979K(priv32, feed);
            Point rp = Mul(G, kb);
            if (rp.Inf) { feed = Hashing.Sha256(kb); continue; }
            BigInteger r = Mod(rp.X, N);
            if (r == 0) { feed = Hashing.Sha256(kb); continue; }
            BigInteger k = ParseBeBytes(kb);
            BigInteger kinv = ModInv(k, N);
            BigInteger s = Mod(kinv * (z + r * d), N);
            if (s == 0) { feed = Hashing.Sha256(kb); continue; }
            if (s > NHalf) s = N - s;                            // low-S
            r32 = To32Be(r); s32 = To32Be(s);
            return true;
        }
        return false;
    }

    // ── byte helpers (always unsigned, fixed 32-byte BE) ────────────────────────
    private static BigInteger ParseBe(string hex)
    {
        byte[] b = new byte[hex.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return ParseBeBytes(b);
    }
    private static BigInteger ParseBeBytes(byte[] be) => ParseBeSpan(be, 0, be.Length);
    private static BigInteger ParseBeSpan(byte[] be, int off, int len)
    {
        // build a little-endian array with a trailing 0x00 to force a positive value.
        byte[] le = new byte[len + 1];
        for (int i = 0; i < len; i++) le[i] = be[off + len - 1 - i];
        le[len] = 0;
        return new BigInteger(le);
    }
    public static byte[] To32Be(BigInteger v)
    {
        byte[] le = v.ToByteArray(); // little-endian, possibly with trailing 0x00 sign byte
        byte[] outp = new byte[32];
        int n = Math.Min(le.Length, 32);
        for (int i = 0; i < n; i++)
        {
            // strip the sign byte if it lands past index 31 (handled by Min); copy LE→BE
            outp[31 - i] = le[i];
        }
        return outp;
    }
    private static byte[] Cat(params byte[][] parts)
    {
        int len = 0; foreach (var p in parts) len += p.Length;
        byte[] r = new byte[len]; int o = 0;
        foreach (var p in parts) { Buffer.BlockCopy(p, 0, r, o, p.Length); o += p.Length; }
        return r;
    }

    // ── ECMH (Elliptic Curve Multiset Hash) ─────────────────────────────────────
    // An accumulator is a 33-byte compressed point (0x02/0x03 ‖ X-be); the all-zero
    // sentinel (prefix 0x00) is the identity ∞. Mirrors secp256k1.c's ECMH block.
    private static readonly byte[] EcmhH2cTag = { (byte)'E', (byte)'C', (byte)'M', (byte)'H', (byte)'h', (byte)'2', (byte)'c', (byte)'1' };

    public static byte[] EcmhIdentity() => new byte[33];

    private static byte[] EcmhSer(Point p)            // point → 33 bytes (∞ → zeros)
    {
        byte[] o = new byte[33];
        if (p.Inf) return o;
        o[0] = p.Y.IsEven ? (byte)0x02 : (byte)0x03;
        Buffer.BlockCopy(To32Be(p.X), 0, o, 1, 32);
        return o;
    }
    private static Point EcmhLoad(byte[] in33)         // 33 bytes → point
    {
        if (in33[0] == 0) return Point.Infinity;
        PubDecode(in33, out Point p);
        return p;
    }

    // try-and-increment hash-to-curve; returns the compressed even-Y point and the ctr.
    public static int EcmhHash(byte[] pre, out byte[] pt33)
    {
        for (int ctr = 0; ; ctr++)
        {
            byte[] cb = { (byte)ctr, (byte)(ctr >> 8), (byte)(ctr >> 16), (byte)(ctr >> 24) };
            byte[] buf = Cat(EcmhH2cTag, pre ?? Array.Empty<byte>(), cb);
            byte[] h = Hashing.Sha256(buf);
            BigInteger x = Mod(ParseBeBytes(h), P);    // x = SHA256(...) mod p
            BigInteger rhs = RhsCurve(x);
            BigInteger beta = BigInteger.ModPow(rhs, (P + 1) / 4, P); // p ≡ 3 mod 4
            if (Mod(beta * beta, P) != rhs) continue;  // x³+7 not a QR ⇒ bump ctr
            pt33 = new byte[33];
            pt33[0] = 0x02;                            // canonical even-Y
            Buffer.BlockCopy(To32Be(x), 0, pt33, 1, 32);
            return ctr;
        }
    }

    public static void EcmhNegate(byte[] pt33) { if (pt33[0] != 0) pt33[0] ^= 1; }

    public static void EcmhAdd(byte[] acc33, byte[] pt33)
    {
        Point r = Add(EcmhLoad(acc33), EcmhLoad(pt33));
        byte[] o = EcmhSer(r);
        Buffer.BlockCopy(o, 0, acc33, 0, 33);
    }

    // ── self-check (mirrors secp_selftest): returns failure count ───────────────
    public static int Selftest()
    {
        int fail = 0;
        // N_HALF = N >> 1
        if ((N >> 1) != NHalf) fail++;
        // G on curve (uncompressed)
        byte[] gUncomp = new byte[65]; gUncomp[0] = 0x04;
        Buffer.BlockCopy(To32Be(Gx), 0, gUncomp, 1, 32);
        Buffer.BlockCopy(To32Be(Gy), 0, gUncomp, 33, 32);
        if (!OnCurve(gUncomp)) fail++;
        // 2G known-answer
        BigInteger g2x = ParseBe("C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5");
        BigInteger g2y = ParseBe("1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A");
        byte[] two = new byte[32]; two[31] = 2;
        Point p2 = Mul(G, two);
        if (p2.Inf || p2.X != g2x || p2.Y != g2y) fail++;
        // n·G == ∞
        if (!Mul(G, To32Be(N)).Inf) fail++;
        // decompress round-trip: compress G (Gy even ⇒ 0x02), decode, compare Y
        byte[] gc = new byte[33]; gc[0] = 0x02;
        Buffer.BlockCopy(To32Be(Gx), 0, gc, 1, 32);
        if (!PubDecode(gc, out Point gdec) || gdec.Y != Gy) fail++;
        // sign/verify round-trip + tamper over a few deterministic keys
        for (int t = 1; t <= 4; t++)
        {
            byte[] priv = new byte[32]; priv[31] = (byte)(t * 7 + 1);
            if (!Pubkey(priv, out byte[] pub)) { fail++; continue; }
            byte[] msg = new byte[32]; for (int i = 0; i < 32; i++) msg[i] = (byte)(i * 13 + t);
            byte[] mh = Hashing.Sha256(msg);
            if (!EcdsaSign(priv, mh, out byte[] r, out byte[] s)) { fail++; continue; }
            if (!EcdsaVerify(mh, r, s, pub)) fail++;
            byte[] mh2 = (byte[])mh.Clone(); mh2[0] ^= 0x01;
            if (EcdsaVerify(mh2, r, s, pub)) fail++;
        }
        return fail;
    }
}
