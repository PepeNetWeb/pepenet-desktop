import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

// Little-endian serialization buffer for the canonical state digest (§4) and the
// generator's hash_tx. Signed values are two's-complement LE; the JDK `long` bit
// pattern already IS two's complement, so i64 and u64 share one writer.
final class Buf {
    private final ByteArrayOutputStream b = new ByteArrayOutputStream();

    Buf u8(int v) { b.write(v & 0xFF); return this; }

    Buf u32(long v) {
        for (int i = 0; i < 4; i++) b.write((int) ((v >>> (8 * i)) & 0xFF));
        return this;
    }

    // i64 and u64 are byte-identical (two's-complement == unsigned bit pattern).
    Buf i64(long v) {
        for (int i = 0; i < 8; i++) b.write((int) ((v >>> (8 * i)) & 0xFF));
        return this;
    }

    // u64 from a BigInteger in [0, 2^64): low 8 bytes LE.
    Buf u64(BigInteger v) {
        BigInteger m = v.mod(Const.TWO64);
        for (int i = 0; i < 8; i++) b.write(m.shiftRight(8 * i).and(BigInteger.valueOf(0xFF)).intValue());
        return this;
    }

    // signed i128, 16 bytes two's-complement LE (wrapping mod 2^128) — property fingerprint aggregates.
    Buf i128(BigInteger v) {
        BigInteger m = v.mod(Const.TWO128); // mod yields non-negative two's-complement repr
        for (int i = 0; i < 16; i++) b.write(m.shiftRight(8 * i).and(BigInteger.valueOf(0xFF)).intValue());
        return this;
    }

    Buf bytes(byte[] x) { b.write(x, 0, x.length); return this; }

    byte[] toBytes() { return b.toByteArray(); }
    int size() { return b.size(); }

    // ---- LE readers over a byte[] (decoder / wire) --------------------------
    static long u32(byte[] a, int off) {
        return (a[off] & 0xFFL) | ((a[off+1] & 0xFFL) << 8) | ((a[off+2] & 0xFFL) << 16) | ((a[off+3] & 0xFFL) << 24);
    }
    static BigInteger u64(byte[] a, int off) {
        BigInteger v = BigInteger.ZERO;
        for (int i = 0; i < 8; i++) v = v.or(BigInteger.valueOf(a[off+i] & 0xFFL).shiftLeft(8 * i));
        return v;
    }
    // 5-byte LE height anchor
    static long u40(byte[] a, int off) {
        long v = 0;
        for (int i = 0; i < 5; i++) v |= (a[off+i] & 0xFFL) << (8 * i);
        return v;
    }
}
