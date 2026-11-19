// Hex helpers (lowercase, no separators).
final class Hex {
    private static final char[] D = "0123456789abcdef".toCharArray();

    static String enc(byte[] b) {
        char[] c = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) {
            c[2 * i] = D[(b[i] >> 4) & 0xF];
            c[2 * i + 1] = D[b[i] & 0xF];
        }
        return new String(c);
    }

    static String enc(byte[] b, int n) { // first n bytes
        byte[] s = new byte[n];
        System.arraycopy(b, 0, s, 0, n);
        return enc(s);
    }

    static byte[] dec(String s) {
        int n = s.length() / 2;
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++)
            b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }
}
