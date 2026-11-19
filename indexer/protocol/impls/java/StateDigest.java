import java.util.*;

// Canonical state digest — SPEC-conformance §4. Serialize into a buffer (LE; signed
// two's-complement LE) then SHA-256. Sort keys are pinned per table. Magic "SMv1".
// Names-only: names + commits + muts (no votes / decors / overflow flag).
// owner_type is NOT digested; seller_type IS.
final class StateDigest {

    static byte[] serialize(State s) {
        Buf b = new Buf();
        b.bytes(new byte[]{'S','M','v','1'});

        // names — ascending by raw name bytes
        List<String> nk = new ArrayList<>(s.names.keySet());
        nk.sort(State::cmpNameKey);
        b.u32(nk.size());
        for (String k : nk) {
            State.NameRow r = s.names.get(k);
            byte[] nm = k.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            b.u8(nm.length).bytes(nm)
             .bytes(r.owner).u8(r.st).i64(r.leaseExpiry)
             .bytes(r.seller).u8(r.sellerType).u64(r.price).i64(r.offerExpiry)
             .bytes(r.buyer).u64(r.burnLeg).u64(r.payLeg).i64(r.reserveExpiry);
        }

        // commits — by commitment bytes (then height, tx_index, time for a total order)
        List<State.Commit> cs = new ArrayList<>(s.commits);
        cs.sort((x, y) -> {
            int d = State.cmpBytes(x.commitment, y.commitment);
            if (d != 0) return d;
            d = Long.compare(x.commitHeight, y.commitHeight); if (d != 0) return d;
            d = Long.compare(x.txIndex, y.txIndex); if (d != 0) return d;
            return Long.compare(x.commitTime, y.commitTime);
        });
        b.u32(cs.size());
        for (State.Commit c : cs)
            b.bytes(c.commitment).i64(c.commitHeight).u32(c.txIndex).i64(c.commitTime);

        // muts — by owner bytes
        List<Map.Entry<String, Long>> ms = new ArrayList<>(s.muts.entrySet());
        ms.sort((x, y) -> State.cmpBytes(Hex.dec(x.getKey()), Hex.dec(y.getKey())));
        b.u32(ms.size());
        for (Map.Entry<String, Long> e : ms)
            b.bytes(Hex.dec(e.getKey())).i64(e.getValue());

        return b.toBytes();
    }

    static String digest(State s) { return Hex.enc(Hashes.sha256(serialize(s))); }
    static String digest16(State s) { return digest(s).substring(0, 16); }

    // ── per-row encoders (BYTE-IDENTICAL to serialize()'s per-row field bytes,
    //    WITHOUT count prefixes / SMv1 framing) — reused by stateEcmh.
    private static byte[] rowName(State.NameRow r, String k) {
        byte[] nm = k.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        return new Buf().u8(nm.length).bytes(nm)
            .bytes(r.owner).u8(r.st).i64(r.leaseExpiry)
            .bytes(r.seller).u8(r.sellerType).u64(r.price).i64(r.offerExpiry)
            .bytes(r.buyer).u64(r.burnLeg).u64(r.payLeg).i64(r.reserveExpiry).toBytes();
    }
    private static byte[] rowCommit(State.Commit c) {
        return new Buf().bytes(c.commitment).i64(c.commitHeight).u32(c.txIndex).i64(c.commitTime).toBytes();
    }
    private static byte[] rowMut(byte[] owner, long height) {
        return new Buf().bytes(owner).i64(height).toBytes();
    }

    // domain tags — second-preimage separation between tables (3 tags; TAG_VOTE/TAG_DECOR removed).
    private static final byte TAG_NAME = 0x01, TAG_COMMIT = 0x02, TAG_MUT = 0x04;
    private static final byte[] ECMH_REC_TAG = { 'E','C','M','H','v','1' };

    // acc ← acc + H2C("ECMHv1" ‖ tag ‖ row_bytes)
    private static byte[] ecmhFold(byte[] acc, byte tag, byte[] row) {
        byte[] pre = new byte[ECMH_REC_TAG.length + 1 + row.length];
        System.arraycopy(ECMH_REC_TAG, 0, pre, 0, ECMH_REC_TAG.length);
        pre[ECMH_REC_TAG.length] = tag;
        System.arraycopy(row, 0, pre, ECMH_REC_TAG.length + 1, row.length);
        return Secp.ecmhAdd(acc, Secp.ecmhHash(pre)[0]);
    }

    // §13.2 — the incremental ECMH twin of the canonical state digest. Three
    // per-table multiset sums (order-independent) folded into one SHA-256.
    static byte[] stateEcmh(State s) {
        byte[] an = Secp.ecmhIdentity(), ac = Secp.ecmhIdentity(), am = Secp.ecmhIdentity();
        for (Map.Entry<String, State.NameRow> e : s.names.entrySet())
            an = ecmhFold(an, TAG_NAME, rowName(e.getValue(), e.getKey()));
        for (State.Commit c : s.commits)
            ac = ecmhFold(ac, TAG_COMMIT, rowCommit(c));
        for (Map.Entry<String, Long> e : s.muts.entrySet())
            am = ecmhFold(am, TAG_MUT, rowMut(Hex.dec(e.getKey()), e.getValue()));

        // combined = SHA256("ECMHtop1" ‖ the three sub-accumulators).
        Buf top = new Buf();
        top.bytes(new byte[]{'E','C','M','H','t','o','p','1'});
        top.bytes(an).bytes(ac).bytes(am);
        return Hashes.sha256(top.toBytes());
    }

    static String ecmhHex(State s) { return Hex.enc(stateEcmh(s)); }
}
