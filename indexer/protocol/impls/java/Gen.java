import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;

// Generator (§5) — derived from prose. The PER-OP field draw sequence is pinned to
// impls/c/src/gen.c (NOT prose), so this draw order is an INDEPENDENT reconstruction
// and will NOT reproduce the gen.c-pinned input_digest/state_digest goldens. That is
// expected and reported. The chain it produces is nonetheless a valid, varied chain
// that exercises the fold richly — enough to drive the generator-INDEPENDENT property
// / reorg / meta assertions (violations==0, failures==0), which are the real
// independent confirmations of fold correctness here.
//
// Names-only weights: COMMIT,CLAIM,RENEW,TRANSFER,SELL,RESERVE,SETTLE,RELEASE,SELL_TO,PAY,TRADE
// (POST/VOTE removed; fall-back is COMMIT).
final class Gen {
    static final int N_IDS = 16, NAME_POOL = 400;
    static final long BASE_TS = 1_700_000_000L;
    // weights pinned to C gen.c (names/market only)
    static final int[] WEIGHTS = {14, 13, 5, 5, 8, 7, 7, 3, 6, 5, 4};
    static int WSUM; static { int s=0; for (int w: WEIGHTS) s+=w; WSUM=s; }

    static byte[] identity(int i) { byte[] h = new byte[20]; h[0]=(byte)i; h[19]=(byte)i; return h; }
    static int idType(int i) { return i % 4 == 3 ? Const.P2SH : Const.P2PKH; }
    static byte[] nameOf(int i) { return ("n" + base36(i)).getBytes(StandardCharsets.US_ASCII); }
    static String base36(int v) { if (v==0) return "0"; StringBuilder sb=new StringBuilder(); String d="0123456789abcdefghijklmnopqrstuvwxyz"; while(v>0){sb.insert(0,d.charAt(v%36)); v/=36;} return sb.toString(); }
    static byte[] saltOf(long k) { byte[] s=new byte[32]; for(int i=0;i<8;i++) s[i]=(byte)(k>>>(8*i)); s[31]=(byte)0xA5; return s; }

    static final class Pending { int idIdx; byte[] name; byte[] salt; long commitHeight; long commitTime; }

    static long computeMtp(List<Long> ts, long H) {
        int lo = (int) Math.max(0, H - 11), hi = (int) H; // [H-11, H-1]
        if (lo >= hi) return ts.isEmpty() ? BASE_TS : ts.get((int) Math.min(H, ts.size()-1));
        List<Long> w = new ArrayList<>(ts.subList(lo, hi));
        Collections.sort(w);
        return w.get(w.size() / 2); // index k//2 (SPEC-conformance §2)
    }

    // record the full chain (the same chain soak/properties/reorg/meta share)
    static List<Model.Block> recordChain(long seed, int count) {
        Rng rng = new Rng(seed);
        State st = new State(); Fold fold = new Fold(st);
        List<Model.Block> blocks = new ArrayList<>();
        List<Long> tsList = new ArrayList<>();
        List<Pending> ready = new ArrayList<>();
        long ts = BASE_TS, saltCtr = 1;
        long height = 0; int txCount = 0;
        while (txCount < count) {
            long tsStep = 300 + rng.bounded(600); ts += tsStep; tsList.add(ts);
            BigInteger rate = BigInteger.valueOf(28L * (1 + rng.bounded(4)));
            long mtp = computeMtp(tsList, height);
            int nTxs = 1 + rng.bnd(8);
            List<Model.Tx> txs = new ArrayList<>();
            for (int ti = 0; ti < nTxs && txCount < count; ti++) {
                Model.Tx tx = buildTx(rng, st, height, mtp, rate, ready, saltCtr);
                saltCtr += 4;
                tx.txIndex = ti;
                txs.add(tx); txCount++;
            }
            Model.Block b = new Model.Block(height, mtp, rate, txs.toArray(new Model.Tx[0]));
            fold.applyBlock(b);
            blocks.add(b);
            height++;
        }
        return blocks;
    }

    static int pickOp(Rng rng) {
        int x = rng.bnd(WSUM), acc = 0;
        for (int i = 0; i < WEIGHTS.length; i++) { acc += WEIGHTS[i]; if (x < acc) return i; }
        return 0;
    }

    // names in state by predicate
    static List<String> namesWhere(State st, byte[] owner, int reqSt) {
        List<String> r = new ArrayList<>();
        for (Map.Entry<String, State.NameRow> e : st.names.entrySet()) {
            State.NameRow row = e.getValue();
            if (owner != null && !Arrays.equals(row.owner, owner)) continue;
            if (reqSt >= 0 && row.st != reqSt) continue;
            r.add(e.getKey());
        }
        return r;
    }

    static Model.Tx oneIn(int i, Model.TxOut... outs) { return new Model.Tx(new Model.TxIn[]{ new Model.TxIn(identity(i), idType(i), true) }, outs); }

    static Model.Tx buildTx(Rng rng, State st, long height, long mtp, BigInteger rate, List<Pending> ready, long saltCtr) {
        int op = pickOp(rng);
        int i = rng.bnd(N_IDS);
        byte[] id = identity(i);
        long days = 1 + rng.bnd(60);
        BigInteger rate28 = rate.divide(BigInteger.valueOf(28));
        BigInteger leaseVal = rate28.multiply(BigInteger.valueOf(days)); // T == days

        switch (op) {
            case 0 -> { // COMMIT
                int j = rng.bnd(NAME_POOL); byte[] name = nameOf(j); byte[] salt = saltOf(saltCtr);
                Pending p = new Pending(); p.idIdx = i; p.name = name; p.salt = salt; p.commitHeight = height; p.commitTime = mtp;
                ready.add(p);
                Action a = new Action(); a.op = Const.COMMIT; a.commitment = Hashes.sha256(Fold.concat(salt, name, id));
                return oneIn(i, Model.TxOut.carrier(BigInteger.ZERO, Wire.encode(a)));
            }
            case 1 -> { // CLAIM a ready commit (>=1 deep, live)
                for (int k = 0; k < ready.size(); k++) {
                    Pending p = ready.get(k);
                    if (p.commitHeight < height && mtp <= p.commitTime + Const.COMMIT_EXPIRY && !st.names.containsKey(State.nameKey(p.name))) {
                        ready.remove(k);
                        Action a = new Action(); a.op = Const.CLAIM; a.salt = p.salt; a.name = p.name;
                        return oneIn(p.idIdx, Model.TxOut.carrier(leaseVal, Wire.encode(a)));
                    }
                }
            }
            case 2 -> { // RENEW all (owner with names)
                List<String> owned = namesWhere(st, id, -1);
                if (!owned.isEmpty()) { Action a = new Action(); a.op = Const.RENEW; a.renewMode = 0; return oneIn(i, Model.TxOut.carrier(leaseVal, Wire.encode(a))); }
            }
            case 3 -> { // TRANSFER all to a random id
                List<String> owned = namesWhere(st, id, Const.OWNED);
                if (!owned.isEmpty()) { Action a = new Action(); a.op = Const.TRANSFER; a.tTarget = identity(rng.bnd(N_IDS)); a.selective = false; return oneIn(i, Model.TxOut.carrier(BigInteger.ZERO, Wire.encode(a))); }
            }
            case 4 -> { // SELL an owned name with enough lease tail
                List<String> owned = namesWhere(st, id, Const.OWNED);
                for (String nm : owned) {
                    State.NameRow r = st.names.get(nm);
                    if (mtp + Const.RESERVE_WINDOW + Const.REORG_BUFFER <= r.leaseExpiry) {
                        long price = 3 + rng.bnd(100000);
                        Action a = new Action(); a.op = Const.SELL; a.price = BigInteger.valueOf(price); a.window = 0; a.name = nm.getBytes(StandardCharsets.US_ASCII);
                        return oneIn(i, Model.TxOut.carrier(BigInteger.ZERO, Wire.encode(a)));
                    }
                }
            }
            case 5 -> { // RESERVE a listed name (buyer != seller)
                List<String> listed = namesWhere(st, null, Const.LISTED);
                if (!listed.isEmpty()) {
                    String nm = listed.get(rng.bnd(listed.size())); State.NameRow r = st.names.get(nm);
                    int buyer = rng.bnd(N_IDS);
                    BigInteger burn = Fold.depositLeg(r.price, Const.RESERVE_BURN_BPS), payL = Fold.depositLeg(r.price, Const.RESERVE_PAY_BPS);
                    Action a = new Action(); a.op = Const.RESERVE; a.name = nm.getBytes(StandardCharsets.US_ASCII);
                    return oneIn(buyer, Model.TxOut.carrier(burn, Wire.encode(a)), Model.TxOut.spend(payL, r.seller, r.sellerType));
                }
            }
            case 6 -> { // SETTLE a reserved name (by its reserver)
                List<String> res = namesWhere(st, null, Const.RESERVED);
                if (!res.isEmpty()) {
                    String nm = res.get(rng.bnd(res.size())); State.NameRow r = st.names.get(nm);
                    BigInteger rem = r.price.subtract(r.burnLeg).subtract(r.payLeg);
                    int buyer = idxOf(r.buyer);
                    Action a = new Action(); a.op = Const.SETTLE; a.name = nm.getBytes(StandardCharsets.US_ASCII);
                    return oneIn(buyer, Model.TxOut.carrier(BigInteger.ZERO, Wire.encode(a)), Model.TxOut.spend(rem, r.seller, r.sellerType));
                }
            }
            case 7 -> { // RELEASE owned names via a full-ish bitmap
                List<String> set = st.ownedSetSorted(id);
                if (!set.isEmpty()) {
                    byte[] flags = new byte[(set.size() + 7) / 8]; Arrays.fill(flags, (byte) 0xFF);
                    if (flags.length == 0) flags = new byte[]{1};
                    Action a = new Action(); a.op = Const.RELEASE; a.anchor = st.lastMut(id) == Long.MIN_VALUE ? height : Math.max(st.lastMut(id), height - 1); a.flags = flags;
                    if (a.anchor <= height) return oneIn(i, Model.TxOut.carrier(BigInteger.ZERO, Wire.encode(a)));
                }
            }
            case 8 -> { // SELL_TO
                List<String> owned = namesWhere(st, id, Const.OWNED);
                for (String nm : owned) {
                    State.NameRow r = st.names.get(nm);
                    if (mtp + Const.DIRECT_WINDOW + Const.REORG_BUFFER <= r.leaseExpiry) {
                        Action a = new Action(); a.op = Const.SELL_TO; a.price = BigInteger.valueOf(1 + rng.bnd(100000)); a.buyer = identity(rng.bnd(N_IDS)); a.name = nm.getBytes(StandardCharsets.US_ASCII);
                        return oneIn(i, Model.TxOut.carrier(BigInteger.ZERO, Wire.encode(a)));
                    }
                }
            }
            case 9 -> { // PAY an offered name (by its named buyer)
                List<String> off = namesWhere(st, null, Const.OFFERED);
                if (!off.isEmpty()) {
                    String nm = off.get(rng.bnd(off.size())); State.NameRow r = st.names.get(nm);
                    int buyer = idxOf(r.buyer);
                    Action a = new Action(); a.op = Const.PAY; a.name = nm.getBytes(StandardCharsets.US_ASCII);
                    return oneIn(buyer, Model.TxOut.carrier(BigInteger.ZERO, Wire.encode(a)), Model.TxOut.spend(r.price, r.seller, r.sellerType));
                }
            }
            case 10 -> { // TRADE two owned names between two ids
                List<String> myOwned = namesWhere(st, id, Const.OWNED);
                int i2 = (i + 1 + rng.bnd(N_IDS - 1)) % N_IDS; byte[] id2 = identity(i2);
                List<String> theirs = namesWhere(st, id2, Const.OWNED);
                if (!myOwned.isEmpty() && !theirs.isEmpty()) {
                    String a1 = myOwned.get(0), b1 = theirs.get(0);
                    if (!a1.equals(b1)) {
                        Action a = new Action(); a.op = Const.TRADE; a.idxA = 0; a.idxB = 1; a.nameA = a1.getBytes(StandardCharsets.US_ASCII); a.nameB = b1.getBytes(StandardCharsets.US_ASCII);
                        Model.TxIn[] ins = { new Model.TxIn(id, idType(i), true), new Model.TxIn(id2, idType(i2), true) };
                        return new Model.Tx(ins, new Model.TxOut[]{ Model.TxOut.carrier(BigInteger.ZERO, Wire.encode(a)) });
                    }
                }
            }
        }
        // COMMIT fallback (always valid) when the chosen op has no target
        int j = rng.bnd(NAME_POOL); byte[] name = nameOf(j); byte[] salt = saltOf(saltCtr + 99);
        Action a = new Action(); a.op = Const.COMMIT; a.commitment = Hashes.sha256(Fold.concat(salt, name, id));
        return oneIn(i, Model.TxOut.carrier(BigInteger.ZERO, Wire.encode(a)));
    }

    static int idxOf(byte[] id) { for (int k = 0; k < N_IDS; k++) if (Arrays.equals(identity(k), id)) return k; return 0; }

    // streaming input_digest over the recorded chain (own hash_tx format)
    static String inputDigest(List<Model.Block> blocks) {
        Buf b = new Buf();
        for (Model.Block blk : blocks) {
            b.i64(blk.height).i64(blk.mtp).u64(blk.rate);
            for (Model.Tx tx : blk.txs) {
                b.u32(tx.txIndex);
                b.u32(tx.ins.length);
                for (Model.TxIn in : tx.ins) b.bytes(in.id).u8(in.type).u8(in.sigAll ? 1 : 0);
                b.u32(tx.outs.length);
                for (Model.TxOut o : tx.outs) {
                    b.u64(o.value);
                    if (o.isOpReturn()) { b.u8(1).u32(o.payload.length).bytes(o.payload); }
                    else { b.u8(0).bytes(o.spkHash).u8(o.spkType); }
                }
            }
        }
        return Hex.enc(Hashes.sha256(b.toBytes()));
    }
}
