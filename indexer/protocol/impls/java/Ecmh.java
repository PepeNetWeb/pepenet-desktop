import java.security.MessageDigest;

// ECMH state digest (§13.2) — the pinned, portable `sm ecmh` vector set.
//
// Mirrors impls/c/src/ecmh.c (ecmh_cmd) byte-for-byte: hash-to-curve KATs,
// accumulator algebra (identity / negate / add), and a tagged multiset sum,
// printed as a cross-language byte-identical `combined` golden. Runs Java's OWN
// secp256k1 (Secp.java) and must print output identical to the C reference.
// Names-only: 3 domain tags (NAME/COMMIT/MUT); no VOTE/DECOR.
final class Ecmh {

    private static MessageDigest sha256ctx() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (Exception e) { throw new RuntimeException(e); }
    }

    // domain tags — second-preimage separation between tables.
    private static final byte TAG_NAME   = 0x01;
    private static final byte TAG_COMMIT = 0x02;
    private static final byte TAG_MUT    = 0x04;
    private static final byte[] ECMH_REC_TAG = { 'E','C','M','H','v','1' };

    // per-record H2C point: P("ECMHv1" ‖ tag ‖ body)
    private static byte[] recPt(byte tag, byte[] body) {
        byte[] pre = new byte[ECMH_REC_TAG.length + 1 + body.length];
        System.arraycopy(ECMH_REC_TAG, 0, pre, 0, ECMH_REC_TAG.length);
        pre[ECMH_REC_TAG.length] = tag;
        System.arraycopy(body, 0, pre, ECMH_REC_TAG.length + 1, body.length);
        return Secp.ecmhHash(pre)[0];
    }

    static void run() {
        StringBuilder out = new StringBuilder();
        MessageDigest comb = sha256ctx();

        // version self-doc
        out.append("ecmh ECMHv1\n"); comb.update(ECMH_REC_TAG);

        // 1. hash-to-curve KAT — fixed preimages → (ctr, compressed even-Y point).
        String[] labels = { "empty", "a", "pepe", "doge", "ff32", "z32" };
        byte[][] pres = new byte[6][];
        pres[0] = new byte[0];
        pres[1] = Sm.utf8("a");
        pres[2] = Sm.utf8("pepenet");
        pres[3] = Sm.utf8("doge");
        pres[4] = new byte[32]; java.util.Arrays.fill(pres[4], (byte) 0xFF);
        pres[5] = new byte[32];
        for (int i = 0; i < 6; i++) {
            byte[][] h = Secp.ecmhHash(pres[i]);
            byte[] pt = h[0]; int ctr = h[1][0] & 0xFF;
            out.append("h2c ").append(labels[i]).append(" ctr=").append(ctr)
               .append(" pt=").append(Hex.enc(pt)).append("\n");
            comb.update((byte) ctr); comb.update(pt);
        }

        // 2. identity (∞) serialization
        byte[] id = Secp.ecmhIdentity();
        out.append("identity ").append(Hex.enc(id)).append("\n"); comb.update(id);

        // 3. tagged multiset sum — a fixed set of (tag ‖ body) records, summed two ways.
        //    Names-only: NAME, NAME, COMMIT, MUT (no VOTE).
        byte[] tags = { TAG_NAME, TAG_NAME, TAG_COMMIT, TAG_MUT };
        byte[][] bodies = {
            new byte[]{ 0x03, 'f', 'o', 'o' },
            new byte[]{ 0x03, 'b', 'a', 'r' },
            Sm.utf8("commitment-blob-32-bytes-xxxxxx"),
            Sm.utf8("owner-mutation"),
        };
        int nr = tags.length;
        byte[] fwd = Secp.ecmhIdentity(), rev = Secp.ecmhIdentity();
        for (int i = 0; i < nr; i++)        fwd = Secp.ecmhAdd(fwd, recPt(tags[i], bodies[i]));
        for (int i = nr - 1; i >= 0; i--)   rev = Secp.ecmhAdd(rev, recPt(tags[i], bodies[i]));
        int commut = java.util.Arrays.equals(fwd, rev) ? 1 : 0;
        out.append("sum ").append(Hex.enc(fwd)).append("\n");
        out.append("commutative ").append(commut).append("\n");
        comb.update(fwd); comb.update((byte) commut);

        // 4. inverse — remove the first record from the sum, re-add, must round-trip.
        byte[] pt0 = recPt(tags[0], bodies[0]);
        byte[] acc = fwd.clone();
        byte[] npt = pt0.clone(); Secp.ecmhNegate(npt);
        acc = Secp.ecmhAdd(acc, npt);   // remove rec[0]
        acc = Secp.ecmhAdd(acc, pt0);   // re-add rec[0]
        int roundtrip = java.util.Arrays.equals(acc, fwd) ? 1 : 0;
        out.append("inverse_roundtrip ").append(roundtrip).append("\n");
        comb.update((byte) roundtrip);

        byte[] cd = comb.digest();
        out.append("combined ").append(Hex.enc(cd)).append("\n");

        System.out.print(out);
    }
}
