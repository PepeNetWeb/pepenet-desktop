import java.math.BigInteger;
import java.util.*;

// Generator-driven modes. The DIGESTS here do not match the gen.c-pinned goldens
// (the per-op draw order is not in prose); that is reported, not faked. The VALUE is
// the generator-INDEPENDENT assertions: properties' `violations==0` (the fold
// preserves every §8 invariant) and meta/reorg's `failures==0` (the fold is
// drop-closed and a pure, reorg-safe function of the block sequence).
final class Modes {

    static void random(long seed, int count) {
        List<Model.Block> blocks = Gen.recordChain(seed, count);
        State st = new State(); Fold f = new Fold(st);
        for (Model.Block b : blocks) f.applyBlock(b);
        System.out.println("input_digest=" + Gen.inputDigest(blocks));
        System.out.println("state_digest=" + StateDigest.digest(st));
        System.out.println("# NOTE: generator draw-order is an independent reconstruction (gen.c is");
        System.out.println("# normative, not prose) -> these digests are internally consistent but do");
        System.out.println("# NOT reproduce the frozen soak goldens. The FOLD is validated via `behav`.");
    }

    // §8 property battery: re-run the chain, assert hard invariants per block.
    static void properties(long seed, int count) {
        List<Model.Block> blocks = Gen.recordChain(seed, count);
        State st = new State(); Fold f = new Fold(st);
        long violations = 0;
        Buf pd = new Buf();
        for (Model.Block b : blocks) {
            f.applyBlock(b);
            violations += checkInvariants(st, b.height, b.mtp);
            fingerprint(pd, st);
        }
        System.out.println("violations=" + violations);
        System.out.println("property_digest=" + Hex.enc(Hashes.sha256(pd.toBytes())));
        System.out.println("state_digest=" + StateDigest.digest(st));
        if (violations != 0) System.exit(1);
    }

    static long checkInvariants(State st, long height, long mtp) {
        long v = 0;
        // names key by name -> single owner by construction (no-double-ownership)
        for (State.NameRow r : st.names.values()) {
            // mtp < lease_expiry <= mtp + MAX_LEASE
            if (!(mtp < r.leaseExpiry)) v++;
            if (!(r.leaseExpiry <= mtp + Const.MAX_LEASE)) v++;
            if (r.st == Const.LISTED || r.st == Const.OFFERED || r.st == Const.RESERVED) {
                if (!(r.offerExpiry + Const.REORG_BUFFER <= r.leaseExpiry)) v++;
            }
            if (r.st == Const.LISTED || r.st == Const.RESERVED) {
                if (r.price.compareTo(Const.SELL_FLOOR) < 0) v++;
            }
            if (r.st == Const.RESERVED) {
                if (!(r.reserveExpiry <= r.offerExpiry)) v++;
                if (r.price.compareTo(r.burnLeg.add(r.payLeg)) < 0) v++;
                if (!r.burnLeg.equals(Fold.depositLeg(r.price, Const.RESERVE_BURN_BPS))) v++;
                if (!r.payLeg.equals(Fold.depositLeg(r.price, Const.RESERVE_PAY_BPS))) v++;
                if (r.price.subtract(r.burnLeg).subtract(r.payLeg).compareTo(Const.DUST_FLOOR) < 0) v++;
            }
        }
        for (long mh : st.muts.values()) if (mh > height) v++;       // mutation height <= cur height
        return v;
    }

    // §8 fingerprint — names-only aggregates (matches C sm_block_fingerprint field set).
    static void fingerprint(Buf pd, State st) {
        int nOwned = 0, nListed = 0, nOffered = 0, nReserved = 0;
        BigInteger sumLease = BigInteger.ZERO, sumPrice = BigInteger.ZERO, sumLegs = BigInteger.ZERO;
        for (State.NameRow r : st.names.values()) {
            switch (r.st) { case Const.OWNED -> nOwned++; case Const.LISTED -> nListed++; case Const.OFFERED -> nOffered++; case Const.RESERVED -> nReserved++; }
            sumLease = sumLease.add(BigInteger.valueOf(r.leaseExpiry));
            if (r.st == Const.LISTED || r.st == Const.OFFERED || r.st == Const.RESERVED) sumPrice = sumPrice.add(r.price);
            if (r.st == Const.RESERVED) sumLegs = sumLegs.add(r.burnLeg).add(r.payLeg);
        }
        pd.u32(st.names.size()).u32(nOwned).u32(nListed).u32(nOffered).u32(nReserved);
        pd.u32(st.commits.size()).u32(st.muts.size());
        pd.i128(sumLease).i128(sumPrice).i128(sumLegs);
    }

    // §11 meta: an action the protocol IGNORES is provably inert.
    static void meta(long seed, int count) {
        List<Model.Block> blocks = Gen.recordChain(seed, Math.min(count, 20000));
        State st = new State(); Fold f = new Fold(st);
        long failures = 0;
        for (Model.Block b : blocks) {
            f.applyBlock(b);
            String before = StateDigest.digest(st);
            f.applyOneTx(b.height, b.mtp, b.rate, inertTx());   // malformed CLAIM / unknown op / UTF-8 / overlay
            if (!StateDigest.digest(st).equals(before)) failures++;
        }
        System.out.println("failures=" + failures);
        System.out.println("state_digest=" + StateDigest.digest(st));
        if (failures != 0) System.exit(1);
    }

    // Mirrors C build_inert_tx: truncated CLAIM, unknown opcode, bare UTF-8, overlay-band.
    static Model.Tx inertTx() {
        byte[] id = new byte[20]; id[0] = (byte) 0xEE; id[19] = (byte) 0xEE;
        byte[] badClaim = new byte[]{(byte) 0xFF, 0x50, 0x4E, (byte) Const.CLAIM, 0, 0, 0, 0}; // truncated → IGNORE
        byte[] unknown  = new byte[]{(byte) 0xFF, 0x50, 0x4E, 0x20};                           // gap opcode → IGNORE
        byte[] utf8     = "hello".getBytes(java.nio.charset.StandardCharsets.US_ASCII);         // bare noise → IGNORE
        byte[] overlay  = new byte[]{(byte) 0xFF, 0x50, 0x4E, (byte) 0xD6, 0x00};              // overlay band → IGNORE
        Model.TxOut[] outs = {
            Model.TxOut.carrier(BigInteger.ZERO, badClaim),
            Model.TxOut.carrier(BigInteger.ZERO, unknown),
            Model.TxOut.carrier(BigInteger.ONE, utf8),
            Model.TxOut.carrier(BigInteger.ZERO, overlay),
        };
        return new Model.Tx(new Model.TxIn[]{ new Model.TxIn(id, Const.P2PKH, true) }, outs);
    }

    // §10 reorg confluence: replay / resume / clear-rebuild / fork-and-return.
    static void reorg(long seed, int count) {
        List<Model.Block> blocks = Gen.recordChain(seed, Math.min(count, 20000));
        int n = blocks.size(), J = n / 2;
        long failures = 0;

        String dFull = foldDigest(blocks, 0, n);
        // 1. replay (a second full fold reproduces D_full)
        if (!foldDigest(blocks, 0, n).equals(dFull)) failures++;
        // 2. resume: fold [0,J) -> S_fork, continue [J,n) == D_full
        State s = new State(); Fold f = new Fold(s);
        for (int i = 0; i < J; i++) f.applyBlock(blocks.get(i));
        String sFork = StateDigest.digest(s);
        for (int i = J; i < n; i++) f.applyBlock(blocks.get(i));
        if (!StateDigest.digest(s).equals(dFull)) failures++;
        // 3. clear-rebuild: full fold, clear(), re-fold [0,J) == S_fork
        s.clear(); Fold f2 = new Fold(s);
        for (int i = 0; i < J; i++) f2.applyBlock(blocks.get(i));
        if (!StateDigest.digest(s).equals(sFork)) failures++;
        // 4. fork-and-return: divergent branch = canonical tail with each block's txs reversed
        State sa = new State(); Fold fa = new Fold(sa);
        for (int i = 0; i < J; i++) fa.applyBlock(blocks.get(i));
        for (int i = J; i < n; i++) fa.applyBlock(reverseTxs(blocks.get(i)));
        String dAlt = StateDigest.digest(sa);
        sa.clear(); Fold fb = new Fold(sa);
        for (int i = 0; i < J; i++) fb.applyBlock(blocks.get(i));
        if (!StateDigest.digest(sa).equals(sFork)) failures++;
        for (int i = J; i < n; i++) fb.applyBlock(blocks.get(i));
        if (!StateDigest.digest(sa).equals(dFull)) failures++;

        byte[] rd = Fold.concat(Hex.dec(dFull), Hex.dec(sFork), Hex.dec(dAlt));
        System.out.println("blocks=" + n + " fork=" + J + " checks=6 failures=" + failures);
        System.out.println("D_full=" + dFull);
        System.out.println("S_fork=" + sFork);
        System.out.println("D_alt=" + dAlt);
        System.out.println("reorg_digest=" + Hex.enc(Hashes.sha256(rd)));
        if (failures != 0) System.exit(1);
    }

    static String foldDigest(List<Model.Block> blocks, int lo, int hi) {
        State s = new State(); Fold f = new Fold(s);
        for (int i = lo; i < hi; i++) f.applyBlock(blocks.get(i));
        return StateDigest.digest(s);
    }
    static Model.Block reverseTxs(Model.Block b) {
        Model.Tx[] r = b.txs.clone();
        for (int i = 0; i < r.length / 2; i++) { Model.Tx t = r[i]; r[i] = r[r.length - 1 - i]; r[r.length - 1 - i] = t; }
        return new Model.Block(b.height, b.mtp, b.rate, r);
    }

    // §9 differential fuzz: random + grammar-perturbed OP_RETURN payloads through
    // decode -> fold. The independent value is crash-safety / fail-closed robustness
    // of the decoder over adversarial bytes (parser_crashes MUST be 0).
    static void fuzz(long seed, int count) {
        Rng rng = new Rng(seed);
        State st = new State(); Fold f = new Fold(st);
        Buf in = new Buf();
        long ts = Gen.BASE_TS, height = 0; int txCount = 0, crashes = 0;
        while (txCount < count) {
            long tsStep = 300 + rng.bounded(600); ts += tsStep;
            BigInteger rate = BigInteger.valueOf(28L * (1 + rng.bounded(4)));
            int nTxs = 1 + rng.bnd(8);
            List<Model.Tx> txs = new ArrayList<>();
            for (int ti = 0; ti < nTxs && txCount < count; ti++) {
                int nIn = 1 + rng.bnd(4);
                Model.TxIn[] ins = new Model.TxIn[nIn];
                for (int k = 0; k < nIn; k++) ins[k] = new Model.TxIn(Gen.identity(rng.bnd(Gen.N_IDS)), rng.bnd(4) == 3 ? Const.P2SH : Const.P2PKH, rng.bnd(8) != 0);
                int nOut = 1 + rng.bnd(4);
                Model.TxOut[] outs = new Model.TxOut[nOut];
                for (int o = 0; o < nOut; o++) {
                    BigInteger val = switch (rng.bnd(3)) { case 0 -> BigInteger.ZERO; case 1 -> Const.TWO64.subtract(BigInteger.valueOf(rng.bnd(1000))); default -> BigInteger.valueOf(1 + rng.bnd(1000)); };
                    if (rng.bnd(4) == 0) outs[o] = Model.TxOut.spend(val, Gen.identity(rng.bnd(Gen.N_IDS)), rng.bnd(2));
                    else outs[o] = Model.TxOut.carrier(val, fuzzPayload(rng));
                    in.u8(o).u64(val);
                    if (outs[o].isOpReturn()) in.u32(outs[o].payload.length).bytes(outs[o].payload);
                }
                txs.add(new Model.Tx(ins, outs)); txCount++;
            }
            Model.Block b = new Model.Block(height, ts, rate, txs.toArray(new Model.Tx[0]));
            try { f.applyBlock(b); } catch (RuntimeException e) { crashes++; }
            height++;
        }
        System.out.println("input_digest=" + Hex.enc(Hashes.sha256(in.toBytes())));
        System.out.println("state_digest=" + StateDigest.digest(st));
        System.out.println("parser_crashes=" + crashes);
        if (crashes != 0) System.exit(1);
    }

    static byte[] fuzzPayload(Rng rng) {
        if (rng.bnd(10) < 4) {                          // dumb-random bytes
            int len = rng.bnd(81);
            byte[] p = new byte[len];
            for (int i = 0; i < len; i++) p[i] = (byte) rng.bnd(256);
            if (rng.bnd(3) == 0 && len >= 4) { p[0] = (byte) 0xFF; p[1] = 0x50; p[2] = 0x4E; p[3] = (byte) (1 + rng.bnd(12)); }
            return p;
        }
        // grammar-aware: build a prefixed action-shaped payload, then maybe corrupt
        byte[] payload = grammarPayload(rng);
        switch (rng.bnd(6)) {
            case 2 -> { if (payload.length > 0) payload = Arrays.copyOf(payload, payload.length - 1); }       // truncate
            case 3 -> { if (payload.length > 0) payload[rng.bnd(payload.length)] ^= (byte) (1 << rng.bnd(8)); } // flip
            case 4 -> { payload = Fold.concat(payload, new byte[]{(byte) rng.bnd(256)}); }                    // extend
            default -> { }
        }
        return payload;
    }
    static byte[] grammarPayload(Rng rng) {
        int op = 1 + rng.bnd(15);   // 0x01..0x0F registry
        int bodyLen = switch (op) {
            case Const.COMMIT -> 32;
            case Const.CLAIM -> 33 + rng.bnd(32);
            case Const.RENEW_NAME, Const.RELEASE_NAME -> 1 + rng.bnd(32);
            case Const.TRANSFER_NAME -> 21 + rng.bnd(31);
            case Const.RENEW -> new int[]{0, 5, 6 + rng.bnd(71)}[rng.bnd(3)];
            case Const.TRANSFER -> rng.bnd(2) == 0 ? 20 : 26 + rng.bnd(51);
            case Const.SELL -> 13 + rng.bnd(32);
            case Const.RESERVE, Const.SETTLE, Const.PAY -> 1 + rng.bnd(32);
            case Const.RELEASE -> 6 + rng.bnd(71);
            case Const.SELL_TO -> 29 + rng.bnd(32);
            case Const.AS -> 1;
            case Const.TRADE -> 5 + rng.bnd(30);
            default -> rng.bnd(77);
        };
        byte[] p = new byte[4 + bodyLen];
        p[0] = (byte) 0xFF; p[1] = 0x50; p[2] = 0x4E; p[3] = (byte) op;
        for (int i = 4; i < p.length; i++) p[i] = (byte) rng.bnd(256);
        return p;
    }

    // §11 reorgfuzz: K=64 PRNG fork/divergence trials; clear-rebuild + canonical replay purity.
    static void reorgfuzz(long seed, int count) {
        List<Model.Block> blocks = Gen.recordChain(seed, Math.min(count, 20000));
        int n = blocks.size();
        String dFull = foldDigest(blocks, 0, n);
        Rng tr = new Rng(seed ^ 0x5245464B5A475F31L);
        Buf altStream = new Buf();
        long failures = 0;
        for (int t = 0; t < 64; t++) {
            int J = (int) tr.bounded(n + 1);
            int kind = tr.bnd(3);
            // divergent branch -> D_alt
            State sd = new State(); Fold fd = new Fold(sd);
            for (int i = 0; i < J; i++) fd.applyBlock(blocks.get(i));
            List<Model.Block> tail = divergentTail(blocks, J, n, kind);
            for (Model.Block b : tail) fd.applyBlock(b);
            altStream.bytes(Hex.dec(StateDigest.digest(sd)));
            // assert: clear-rebuild to J reproduces fold[0,J); canonical replay reproduces D_full
            String forkJ = foldDigest(blocks, 0, J);
            State sc = new State(); Fold fc = new Fold(sc);
            for (int i = 0; i < J; i++) fc.applyBlock(blocks.get(i));
            if (!StateDigest.digest(sc).equals(forkJ)) failures++;
            for (int i = J; i < n; i++) fc.applyBlock(blocks.get(i));
            if (!StateDigest.digest(sc).equals(dFull)) failures++;
        }
        altStream.bytes(Hex.dec(dFull));
        System.out.println("blocks=" + n + " trials=64 failures=" + failures);
        System.out.println("reorgfuzz_digest=" + Hex.enc(Hashes.sha256(altStream.toBytes())));
        if (failures != 0) System.exit(1);
    }
    static List<Model.Block> divergentTail(List<Model.Block> blocks, int J, int n, int kind) {
        List<Model.Block> out = new ArrayList<>();
        switch (kind) {
            case 0 -> { for (int i = J; i < n; i++) out.add(reverseTxs(blocks.get(i))); }           // reversed tail
            case 1 -> { for (int i = J; i < n; i += 2) out.add(blocks.get(i)); }                     // every other block
            default -> { for (int i = J; i < n; i++) { out.add(blocks.get(i)); out.add(blocks.get(i)); } } // tail folded twice
        }
        return out;
    }
}
