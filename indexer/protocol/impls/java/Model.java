import java.math.BigInteger;

// Abstract transaction / block model for the fold modes. Per §5/§5 the fold
// consumes already-resolved identities (the raw-tx §4 attribution lives in
// Attrib.java, a separate layer). Identities are bare hash160 + a script type.
final class Model {

    static final class TxIn {
        final byte[] id;       // 20-byte hash160 (the resolved §4 Identity)
        final int type;        // P2PKH / P2SH
        final boolean sigAll;  // signs exactly SIGHASH_ALL (Rule 3); AS-named inputs need this
        TxIn(byte[] id, int type, boolean sigAll) { this.id = id; this.type = type; this.sigAll = sigAll; }
    }

    static final class TxOut {
        final BigInteger value;
        final byte[] payload;  // non-null => OP_RETURN carrier (single minimal push already extracted)
        final byte[] spkHash;  // non-null => spendable output destination (hash160)
        final int spkType;
        private TxOut(BigInteger value, byte[] payload, byte[] spkHash, int spkType) {
            this.value = value; this.payload = payload; this.spkHash = spkHash; this.spkType = spkType;
        }
        static TxOut carrier(BigInteger value, byte[] payload) { return new TxOut(value, payload, null, 0); }
        static TxOut spend(BigInteger value, byte[] hash, int type) { return new TxOut(value, null, hash, type); }
        boolean isOpReturn() { return payload != null; }
    }

    static final class Tx {
        final TxIn[] ins;
        final TxOut[] outs;    // in vout order
        int txIndex;           // position within block (set at assembly)
        Tx(TxIn[] ins, TxOut[] outs) { this.ins = ins; this.outs = outs; }
    }

    static final class Block {
        final long height;
        final long mtp;        // MTP(height) = median(timestamp[H-11..H-1]) (driver-computed, §5)
        final BigInteger rate; // koinu per name per LEASE_QUANTUM (drawn in soak; oracle-computed in §3.4 scenario)
        final Tx[] txs;
        Block(long height, long mtp, BigInteger rate, Tx[] txs) {
            this.height = height; this.mtp = mtp; this.rate = rate; this.txs = txs;
        }
    }

    // synthetic post id (§3): u64_le(height) || u32_le(txindex) || 12 zero bytes
    static byte[] synthTxid(long height, int txIndex) {
        byte[] t = new byte[32];
        for (int i = 0; i < 8; i++) t[i] = (byte) (height >>> (8 * i));
        for (int i = 0; i < 4; i++) t[8 + i] = (byte) (txIndex >>> (8 * i));
        return t;
    }

    private Model() {}
}
