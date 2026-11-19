import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;

// Behavioral vector suite — hand-authored constructions encoding the §5/§7
// enumerated consensus behaviors. Generator-INDEPENDENT: tests the fold against
// the spec's stated outcomes directly, so a failure means either a misreading
// (fix) or a spec contradiction (finding). This is the from-prose consensus check.
final class Behav {
    static int pass = 0, fail = 0;
    static final BigInteger R28 = BigInteger.valueOf(28);     // rate=28 -> value(koinu) == days
    static final long BASE = 1_700_000_000L;

    static void chk(String name, boolean ok) {
        if (ok) { pass++; System.out.println("  ok   " + name); }
        else    { fail++; System.out.println("FAIL   " + name); }
    }

    // ---- accessors ---------------------------------------------------------
    static byte[] owner(State s, String nm) { State.NameRow r = s.names.get(nm); return r == null ? null : r.owner; }
    static int stOf(State s, String nm) { State.NameRow r = s.names.get(nm); return r == null ? -1 : r.st; }
    static long lease(State s, String nm) { State.NameRow r = s.names.get(nm); return r == null ? -1 : r.leaseExpiry; }
    static boolean has(State s, String nm) { return s.names.containsKey(nm); }
    static boolean ownedBy(State s, String nm, byte[] id) { byte[] o = owner(s, nm); return o != null && Arrays.equals(o, id); }
    static long mut(State s, byte[] id) { return s.lastMut(id); }

    // ---- builders ----------------------------------------------------------
    static byte[] id(int i) { byte[] b = new byte[20]; Arrays.fill(b, (byte) i); return b; }
    static byte[] salt(int i) { byte[] b = new byte[32]; Arrays.fill(b, (byte) i); return b; }
    static byte[] nm(String s) { return s.getBytes(StandardCharsets.US_ASCII); }
    static BigInteger bi(long v) { return BigInteger.valueOf(v); }

    static final class TxB {
        final List<Model.TxIn> ins = new ArrayList<>();
        final List<Model.TxOut> outs = new ArrayList<>();
        TxB in(byte[] id) { ins.add(new Model.TxIn(id, Const.P2PKH, true)); return this; }
        TxB in(byte[] id, int type, boolean sig) { ins.add(new Model.TxIn(id, type, sig)); return this; }
        TxB act(long value, Action a) { outs.add(Model.TxOut.carrier(bi(value), Wire.encode(a))); return this; }
        TxB raw(long value, byte[] payload) { outs.add(Model.TxOut.carrier(bi(value), payload)); return this; }
        TxB spend(long value, byte[] hash) { outs.add(Model.TxOut.spend(bi(value), hash, Const.P2PKH)); return this; }
        TxB spend(long value, byte[] hash, int type) { outs.add(Model.TxOut.spend(bi(value), hash, type)); return this; }
        Model.Tx t() { return new Model.Tx(ins.toArray(new Model.TxIn[0]), outs.toArray(new Model.TxOut[0])); }
    }

    static Model.Block blk(long height, long mtp, BigInteger rate, TxB... txs) {
        Model.Tx[] t = new Model.Tx[txs.length];
        for (int i = 0; i < txs.length; i++) t[i] = txs[i].t();
        return new Model.Block(height, mtp, rate, t);
    }
    static void fold(State s, Model.Block... bs) { Fold f = new Fold(s); for (Model.Block b : bs) f.applyBlock(b); }

    // ---- action factory ----------------------------------------------------
    static Action commitFor(byte[] salt, byte[] name, byte[] author) {
        Action a = new Action(); a.op = Const.COMMIT;
        a.commitment = Hashes.sha256(Fold.concat(salt, name, author)); return a;
    }
    static Action claim(byte[] salt, byte[] name) { Action a = new Action(); a.op = Const.CLAIM; a.salt = salt; a.name = name; return a; }
    static Action renewAll() { Action a = new Action(); a.op = Const.RENEW; a.renewMode = 0; return a; }
    static Action renewSel(long anchor, byte[] flags) { Action a = new Action(); a.op = Const.RENEW; a.renewMode = 2; a.anchor = anchor; a.flags = flags; return a; }
    static Action transferAll(byte[] target) { Action a = new Action(); a.op = Const.TRANSFER; a.tTarget = target; a.selective = false; return a; }
    static Action transferSel(byte[] target, long anchor, byte[] flags) { Action a = new Action(); a.op = Const.TRANSFER; a.tTarget = target; a.selective = true; a.anchor = anchor; a.flags = flags; return a; }
    static Action sell(long price, long window, byte[] name) { Action a = new Action(); a.op = Const.SELL; a.price = bi(price); a.window = window; a.name = name; return a; }
    static Action reserve(byte[] name) { Action a = new Action(); a.op = Const.RESERVE; a.name = name; return a; }
    static Action settle(byte[] name) { Action a = new Action(); a.op = Const.SETTLE; a.name = name; return a; }
    static Action release(long anchor, byte[] flags) { Action a = new Action(); a.op = Const.RELEASE; a.anchor = anchor; a.flags = flags; return a; }
    static Action sellTo(long price, byte[] buyer, byte[] name) { Action a = new Action(); a.op = Const.SELL_TO; a.price = bi(price); a.buyer = buyer; a.name = name; return a; }
    static Action pay(byte[] name) { Action a = new Action(); a.op = Const.PAY; a.name = name; return a; }
    static Action as(int idx) { Action a = new Action(); a.op = Const.AS; a.asIndex = idx; return a; }
    static Action trade(int ia, int ib, byte[] nameA, byte[] nameB) { Action a = new Action(); a.op = Const.TRADE; a.idxA = ia; a.idxB = ib; a.nameA = nameA; a.nameB = nameB; return a; }

    // mtp helper
    static long mtp(long h) { return BASE + h * 1000; }

    static void run() {
        commitClaim();
        priorityTuple();
        leaseAndWaterfill();
        bitmaps();
        market();
        directed();
        multiIdentity();
        timeTransitions();
        forkVectors();
        oracleVectors();
        System.out.println("────");
        System.out.println("behav: " + pass + " pass, " + fail + " fail");
        if (fail > 0) System.exit(1);
    }

    // ===== commit -> claim ==================================================
    static void commitClaim() {
        // happy path: commit at H, claim at H+1 -> mint
        {
            State s = new State();
            fold(s, blk(5, mtp(5), R28, new TxB().in(id(1)).act(0, commitFor(salt(1), nm("alice"), id(1)))),
                    blk(6, mtp(6), R28, new TxB().in(id(1)).act(10, claim(salt(1), nm("alice")))));
            chk("commit->claim happy: alice owned by id1", ownedBy(s, "alice", id(1)));
            chk("commit->claim happy: lease = mtp(6)+10d", lease(s, "alice") == mtp(6) + 10L * Const.BILLING_UNIT);
        }
        // naked claim (no commit) -> drop
        {
            State s = new State();
            fold(s, blk(6, mtp(6), R28, new TxB().in(id(1)).act(10, claim(salt(1), nm("bob")))));
            chk("naked claim dropped (no FCFS)", !has(s, "bob"));
        }
        // same-block commit too shallow -> drop
        {
            State s = new State();
            fold(s, blk(6, mtp(6), R28,
                    new TxB().in(id(1)).act(0, commitFor(salt(1), nm("cat"), id(1))),
                    new TxB().in(id(1)).act(10, claim(salt(1), nm("cat")))));
            chk("same-block commit too shallow -> claim dropped", !has(s, "cat"));
        }
        // commitment-copy author binding: attacker reposts victim's commitment, then both claim
        {
            State s = new State();
            byte[] victimCommit = Hashes.sha256(Fold.concat(salt(1), nm("dog"), id(1))); // victim id1
            Action copy = new Action(); copy.op = Const.COMMIT; copy.commitment = victimCommit; // attacker id2 reposts
            fold(s, blk(5, mtp(5), R28,
                        new TxB().in(id(1)).act(0, commitFor(salt(1), nm("dog"), id(1))),  // victim commit (tx0)
                        new TxB().in(id(2)).act(0, copy)),                                  // attacker copies (tx1)
                    blk(6, mtp(6), R28,
                        new TxB().in(id(2)).act(10, claim(salt(1), nm("dog")))));           // attacker claims w/ victim salt
            chk("commitment-copy: attacker claim dropped (author term)", !has(s, "dog"));
            // victim can still claim
            fold(s, blk(7, mtp(7), R28, new TxB().in(id(1)).act(10, claim(salt(1), nm("dog")))));
            chk("commitment-copy: victim still claims", ownedBy(s, "dog", id(1)));
        }
        // already-owned claim -> dropped
        {
            State s = new State();
            fold(s, blk(5, mtp(5), R28, new TxB().in(id(1)).act(0, commitFor(salt(1), nm("ed"), id(1)))),
                    blk(6, mtp(6), R28, new TxB().in(id(1)).act(10, claim(salt(1), nm("ed")))),
                    blk(7, mtp(7), R28, new TxB().in(id(2)).act(0, commitFor(salt(2), nm("ed"), id(2)))),
                    blk(8, mtp(8), R28, new TxB().in(id(2)).act(10, claim(salt(2), nm("ed")))));
            chk("already-owned claim dropped (cross-block, no displace)", ownedBy(s, "ed", id(1)));
        }
    }

    // ===== priority tuple (vector 42 — the real consensus bug) ==============
    static void priorityTuple() {
        // two authors commit one name in the SAME block; lower commit tx_index must win
        // even when the other claim is applied first.
        State s = new State();
        fold(s, blk(5, mtp(5), R28,
                    new TxB().in(id(1)).act(0, commitFor(salt(1), nm("hot"), id(1))),   // A commit, tx_index 0
                    new TxB().in(id(2)).act(0, commitFor(salt(2), nm("hot"), id(2)))),  // B commit, tx_index 1
                blk(6, mtp(6), R28,
                    new TxB().in(id(2)).act(10, claim(salt(2), nm("hot"))),             // B claims FIRST (tx0)
                    new TxB().in(id(1)).act(10, claim(salt(1), nm("hot")))));           // A claims second (tx1)
        chk("priority tuple: lower COMMIT tx_index (A) wins despite later claim order", ownedBy(s, "hot", id(1)));

        // reverse claim order -> A still wins (same backing commit tuple)
        State s2 = new State();
        fold(s2, blk(5, mtp(5), R28,
                    new TxB().in(id(1)).act(0, commitFor(salt(1), nm("hot"), id(1))),
                    new TxB().in(id(2)).act(0, commitFor(salt(2), nm("hot"), id(2)))),
                 blk(6, mtp(6), R28,
                    new TxB().in(id(1)).act(10, claim(salt(1), nm("hot"))),             // A claims first
                    new TxB().in(id(2)).act(10, claim(salt(2), nm("hot")))));           // B second
        chk("priority tuple: A wins in the other ordering too", ownedBy(s2, "hot", id(1)));

        // earlier commit_height wins (the front-run protection): attacker commits in the claim block
        State s3 = new State();
        fold(s3, blk(5, mtp(5), R28, new TxB().in(id(1)).act(0, commitFor(salt(1), nm("zed"), id(1)))), // honest commit H=5
                 blk(6, mtp(6), R28,
                    new TxB().in(id(2)).act(0, commitFor(salt(2), nm("zed"), id(2))),   // reactive attacker commits H=6
                    new TxB().in(id(1)).act(10, claim(salt(1), nm("zed")))),            // honest claim H=6 (commit H=5)
                 blk(7, mtp(7), R28, new TxB().in(id(2)).act(10, claim(salt(2), nm("zed"))))); // attacker claim H=7
        chk("priority: earlier commit_height (honest) wins, reactive attacker loses", ownedBy(s3, "zed", id(1)));
    }

    // ===== leases & water-fill =============================================
    static void leaseAndWaterfill() {
        // even split: 2 names, renew-all T=10 -> +5 each
        {
            State s = setupTwoNames();      // id1 owns "aa","bb", each lease mtp(6)+1d
            long base = mtp(6) + 1L * Const.BILLING_UNIT;
            fold(s, blk(7, mtp(7), R28, new TxB().in(id(1)).act(10, renewAll())));
            chk("water-fill even split (+5,+5)",
                lease(s, "aa") == base + 5L * Const.BILLING_UNIT && lease(s, "bb") == base + 5L * Const.BILLING_UNIT);
        }
        // lex remainder: 2 names T=11 -> +6 to first lex ("aa"), +5 to "bb"
        {
            State s = setupTwoNames();
            long base = mtp(6) + 1L * Const.BILLING_UNIT;
            fold(s, blk(7, mtp(7), R28, new TxB().in(id(1)).act(11, renewAll())));
            chk("water-fill lex remainder (+6 to lexicographically-first)",
                lease(s, "aa") == base + 6L * Const.BILLING_UNIT && lease(s, "bb") == base + 5L * Const.BILLING_UNIT);
        }
        // T<count floor: 3 names T=2 -> first 2 lex get +1, third none
        {
            State s = setupThreeNames();
            long base = mtp(6) + 1L * Const.BILLING_UNIT;
            fold(s, blk(7, mtp(7), R28, new TxB().in(id(1)).act(2, renewAll())));
            chk("water-fill T<count floor (first T lex names get a day)",
                lease(s, "aa") == base + Const.BILLING_UNIT && lease(s, "bb") == base + Const.BILLING_UNIT
                && lease(s, "cc") == base);
        }
        // MAX_LEASE cap-forfeit: claim with a huge burn caps at 365d
        {
            State s = new State();
            fold(s, blk(5, mtp(5), R28, new TxB().in(id(1)).act(0, commitFor(salt(1), nm("big"), id(1)))),
                    blk(6, mtp(6), R28, new TxB().in(id(1)).act(100000, claim(salt(1), nm("big"))))); // T=100000 days
            long maxDays = Const.MAX_LEASE / Const.BILLING_UNIT;  // 365
            chk("claim caps at MAX_LEASE (365d), surplus forfeited",
                lease(s, "big") == mtp(6) + maxDays * Const.BILLING_UNIT);
        }
        // all-capped multi-name forfeit: 2 names already at MAX_LEASE, renew adds nothing
        {
            State s = setupTwoNames();
            // push both to MAX_LEASE first
            fold(s, blk(7, mtp(7), R28, new TxB().in(id(1)).act(100000, renewAll())));
            long capped_aa = lease(s, "aa"), capped_bb = lease(s, "bb");
            fold(s, blk(8, mtp(7), R28, new TxB().in(id(1)).act(50, renewAll())));  // same mtp -> headroom 0
            chk("all-capped multi-name forfeit (no change)",
                lease(s, "aa") == capped_aa && lease(s, "bb") == capped_bb);
        }
        // T==0 fail-closed: rate huge so value buys < 1 day
        {
            State s = new State();
            fold(s, blk(5, mtp(5), R28, new TxB().in(id(1)).act(0, commitFor(salt(1), nm("zer"), id(1)))),
                    blk(6, mtp(6), BigInteger.valueOf(1000), new TxB().in(id(1)).act(1, claim(salt(1), nm("zer")))));
            chk("claim T==0 fail-closed (drop)", !has(s, "zer"));
        }
    }

    // ===== bitmaps: anchor guard, OOB bit, SELL doesn't bump ================
    static void bitmaps() {
        // selective renew with LSB-first bitmap; OOB bit ignored
        {
            State s = setupThreeNames();    // id1 owns aa,bb,cc (lex order)
            long base = mtp(6) + 1L * Const.BILLING_UNIT;
            long anchor = 6;                // last mutation was the claims at h=6
            // flags = bit0(aa) + bit2(cc) + bit7(OOB, K=3) => 0b10000101 = 0x85
            fold(s, blk(7, mtp(7), R28, new TxB().in(id(1)).act(10, renewSel(anchor, new byte[]{(byte) 0x85}))));
            // T=10 over the 2 selected (aa,cc) -> +5 each; bb untouched; OOB bit7 ignored (not fatal)
            chk("selective renew picks aa,cc; OOB bit ignored",
                lease(s, "aa") == base + 5L * Const.BILLING_UNIT && lease(s, "cc") == base + 5L * Const.BILLING_UNIT
                && lease(s, "bb") == base);
        }
        // anchor guard: stale anchor (set mutated after H) -> reject
        {
            State s = setupTwoNames();      // claims at h=6, so last_mut(id1)=6
            // claim a third name at h=7 (bumps mutation to 7), then a selective renew anchored at 6 must reject
            fold(s, blk(7, mtp(7), R28, new TxB().in(id(1)).act(0, commitFor(salt(9), nm("dd"), id(1)))));
            fold(s, blk(8, mtp(8), R28, new TxB().in(id(1)).act(1, claim(salt(9), nm("dd"))))); // mut->8
            long base = lease(s, "aa");
            fold(s, blk(9, mtp(9), R28, new TxB().in(id(1)).act(10, renewSel(6, new byte[]{0x01})))); // anchor 6 < last_mut 8
            chk("anchor guard rejects stale bitmap (set mutated since H)", lease(s, "aa") == base);
        }
        // SELL does NOT bump the mutation height; SETTLE DOES (checked in market())
        {
            State s = setupTwoNames();      // last_mut(id1) = 6
            fold(s, blk(7, mtp(7), R28, new TxB().in(id(1)).act(0, sell(300, 0, nm("aa")))));
            chk("SELL listing does not bump last_set_mutation_height", mut(s, id(1)) == 6);
        }
    }

    // ===== open market: SELL/RESERVE/SETTLE ================================
    static void market() {
        // full happy flow + lease conveyance + SETTLE bumps both
        {
            State s = sellable("aa", id(1), 1000);  // id1 owns+lists aa @1000, long lease
            long leaseAa = lease(s, "aa");
            BigInteger burn = Fold.depositLeg(bi(1000), 50), payL = Fold.depositLeg(bi(1000), 50);
            BigInteger rem = bi(1000).subtract(burn).subtract(payL);
            // buyer id2 reserves (burn-leg as value, pay-leg output to seller id1)
            fold(s, blk(10, mtp(10), R28, new TxB().in(id(2)).act(burn.longValue(), reserve(nm("aa"))).spend(payL.longValue(), id(1))));
            chk("RESERVE claims option (state RESERVED, buyer=id2)", stOf(s, "aa") == Const.RESERVED && Arrays.equals(s.names.get("aa").buyer, id(2)));
            // settle (remainder output to seller)
            fold(s, blk(11, mtp(11), R28, new TxB().in(id(2)).act(0, settle(nm("aa"))).spend(rem.longValue(), id(1))));
            chk("SETTLE conveys name to buyer + lease conveys", ownedBy(s, "aa", id(2)) && stOf(s, "aa") == Const.OWNED && lease(s, "aa") == leaseAa);
            chk("SETTLE bumps BOTH parties", mut(s, id(1)) == 11 && mut(s, id(2)) == 11);
        }
        // SELL price floor: price < 3 ignored
        {
            State s = owns("aa", id(1));
            fold(s, blk(10, mtp(10), R28, new TxB().in(id(1)).act(0, sell(2, 0, nm("aa")))));
            chk("SELL below 3*DUST_FLOOR ignored", stOf(s, "aa") == Const.OWNED);
        }
        // SELL window add-form: a short-tailed name (lease just above floor) rejects a too-long window
        {
            State s = new State();
            // claim with 1-day lease; lease tail = 86400. window 80000 + REORG 7200 = 87200 > 86400 -> reject
            fold(s, blk(5, mtp(5), R28, new TxB().in(id(1)).act(0, commitFor(salt(1), nm("aa"), id(1)))),
                    blk(6, mtp(6), R28, new TxB().in(id(1)).act(1, claim(salt(1), nm("aa")))));
            fold(s, blk(7, mtp(6), R28, new TxB().in(id(1)).act(0, sell(300, 80000, nm("aa")))));
            chk("SELL window add-form rejects short-tailed listing (no underflow)", stOf(s, "aa") == Const.OWNED);
        }
        // RESERVE under-funded burn leg -> drop
        {
            State s = sellable("aa", id(1), 1000);
            BigInteger burn = Fold.depositLeg(bi(1000), 50), payL = Fold.depositLeg(bi(1000), 50);
            fold(s, blk(10, mtp(10), R28, new TxB().in(id(2)).act(burn.longValue() - 1, reserve(nm("aa"))).spend(payL.longValue(), id(1))));
            chk("RESERVE under-funded burn leg dropped", stOf(s, "aa") == Const.LISTED);
        }
        // losing reserve: second reserver on a RESERVED row drops without overwriting
        {
            State s = sellable("aa", id(1), 1000);
            BigInteger burn = Fold.depositLeg(bi(1000), 50), payL = Fold.depositLeg(bi(1000), 50);
            fold(s, blk(10, mtp(10), R28, new TxB().in(id(2)).act(burn.longValue(), reserve(nm("aa"))).spend(payL.longValue(), id(1))));
            fold(s, blk(11, mtp(11), R28, new TxB().in(id(3)).act(burn.longValue(), reserve(nm("aa"))).spend(payL.longValue(), id(1))));
            chk("losing reserve drops; first reserver keeps option", Arrays.equals(s.names.get("aa").buyer, id(2)));
        }
        // reserve_expiry clamp to offer_expiry
        {
            State s = sellable("aa", id(1), 1000);  // window defaulted to RESERVE_WINDOW=18000 at sell mtp
            long offerExp = s.names.get("aa").offerExpiry;
            BigInteger burn = Fold.depositLeg(bi(1000), 50), payL = Fold.depositLeg(bi(1000), 50);
            // reserve LATER so mtp_reserve + RESERVE_WINDOW > offer_expiry -> clamps
            long rmtp = offerExp - 100;  // close to expiry but still listed
            fold(s, blk(10, rmtp, R28, new TxB().in(id(2)).act(burn.longValue(), reserve(nm("aa"))).spend(payL.longValue(), id(1))));
            chk("reserve_expiry clamped to offer_expiry", s.names.get("aa").reserveExpiry == offerExp);
        }
        // 2^64-1 deposit: 128-bit legs do not wrap to near-zero
        {
            State s = new State();
            BigInteger huge = Const.TWO64.subtract(BigInteger.ONE); // 2^64-1
            // claim a name then list at the huge price (needs long lease tail)
            fold(s, blk(5, mtp(5), R28, new TxB().in(id(1)).act(0, commitFor(salt(1), nm("aa"), id(1)))),
                    blk(6, mtp(6), R28, new TxB().in(id(1)).act(200, claim(salt(1), nm("aa"))))); // 200d lease
            Action sellHuge = new Action(); sellHuge.op = Const.SELL; sellHuge.price = huge; sellHuge.window = 0; sellHuge.name = nm("aa");
            fold(s, blk(7, mtp(6), R28, new TxB().in(id(1)).act(0, sellHuge)));
            BigInteger burn = Fold.depositLeg(huge, 50);
            chk("2^64-1 deposit leg = floor(price*50/10000) (no wrap)", burn.equals(huge.multiply(bi(50)).divide(bi(10000))));
            chk("huge-price listing recorded", stOf(s, "aa") == Const.LISTED && s.names.get("aa").price.equals(huge));
        }
        // per-tx output matcher: value-collision, skip larger, take exact (vector 41 shape)
        {
            // seller id1 owns+offers two names to buyer id2 at prices 100, 200 (directed, simpler)
            State s = owns2("aa", "bb", id(1));
            fold(s, blk(10, mtp(10), R28,
                    new TxB().in(id(1)).act(0, sellTo(100, id(2), nm("aa"))),
                    new TxB().in(id(1)).act(0, sellTo(200, id(2), nm("bb")))));
            // buyer pays both in ONE tx; outputs ordered [200, 100] so a naive matcher would misassign
            fold(s, blk(11, mtp(11), R28, new TxB().in(id(2))
                    .act(0, pay(nm("aa")))            // owed 100 -> must skip out0=200, take out1=100
                    .act(0, pay(nm("bb")))            // owed 200 -> take out0=200
                    .spend(200, id(1)).spend(100, id(1))));
            chk("per-tx matcher: consume-once exact-value vout-order (both PAYs honored)",
                ownedBy(s, "aa", id(2)) && ownedBy(s, "bb", id(2)));
        }
    }

    // ===== directed sales: SELL_TO / PAY ===================================
    static void directed() {
        // happy directed flow + lock + no-bump on SELL_TO
        {
            State s = owns("aa", id(1));
            long mutBefore = mut(s, id(1));
            fold(s, blk(10, mtp(10), R28, new TxB().in(id(1)).act(0, sellTo(500, id(2), nm("aa")))));
            chk("SELL_TO locks name (OFFERED) and does NOT bump mutation",
                stOf(s, "aa") == Const.OFFERED && mut(s, id(1)) == mutBefore);
            // stranger PAY -> dropped (but in reality pays seller); state unchanged
            fold(s, blk(11, mtp(11), R28, new TxB().in(id(3)).act(0, pay(nm("aa"))).spend(500, id(1))));
            chk("PAY by stranger dropped (directed exclusivity)", stOf(s, "aa") == Const.OFFERED);
            // named buyer PAY -> conveys + bumps both
            fold(s, blk(12, mtp(12), R28, new TxB().in(id(2)).act(0, pay(nm("aa"))).spend(500, id(1))));
            chk("PAY by named buyer conveys name + bumps both", ownedBy(s, "aa", id(2)) && mut(s, id(1)) == 12 && mut(s, id(2)) == 12);
        }
        // SELL_TO lease-tail requirement
        {
            State s = new State();
            fold(s, blk(5, mtp(5), R28, new TxB().in(id(1)).act(0, commitFor(salt(1), nm("aa"), id(1)))),
                    blk(6, mtp(6), R28, new TxB().in(id(1)).act(1, claim(salt(1), nm("aa"))))); // 1d lease
            // DIRECT_WINDOW 7200 + REORG 7200 = 14400 < 86400 -> ok actually; use near-expiry mtp
            long nearExp = mtp(6) + 86400 - 10000; // tail = 10000 < 14400 -> reject
            fold(s, blk(7, nearExp, R28, new TxB().in(id(1)).act(0, sellTo(500, id(2), nm("aa")))));
            chk("SELL_TO rejects insufficient lease tail", stOf(s, "aa") == Const.OWNED);
        }
    }

    // ===== AS / TRADE / multi-identity =====================================
    static void multiIdentity() {
        // AS re-points attribution: vin[0]=sponsor funds, AS 1 attributes claim to vin[1]
        {
            State s = new State();
            fold(s, blk(5, mtp(5), R28, new TxB().in(id(9)).in(id(1)).act(0, as(1)).act(0, commitFor(salt(1), nm("aa"), id(1)))),
                    blk(6, mtp(6), R28, new TxB().in(id(9)).in(id(1)).act(0, as(1)).act(10, claim(salt(1), nm("aa")))));
            chk("AS re-points attribution to vin[k] (name owned by id1, not sponsor id9)", ownedBy(s, "aa", id(1)));
        }
        // AS out-of-range -> segment drops (claim dropped)
        {
            State s = new State();
            fold(s, blk(5, mtp(5), R28, new TxB().in(id(1)).act(0, commitFor(salt(1), nm("bb"), id(1)))),
                    blk(6, mtp(6), R28, new TxB().in(id(1)).act(0, as(5)).act(10, claim(salt(1), nm("bb")))));
            chk("AS out-of-range -> segment actions drop", !has(s, "bb"));
        }
        // TRADE atomic swap + lease conveyance + bump both
        {
            State s = owns("aa", id(1)); addOwned(s, "bb", id(2));
            long la = lease(s, "aa"), lb = lease(s, "bb");
            fold(s, blk(10, mtp(10), R28, new TxB().in(id(1)).in(id(2)).act(0, trade(0, 1, nm("aa"), nm("bb")))));
            chk("TRADE swaps ownership atomically", ownedBy(s, "aa", id(2)) && ownedBy(s, "bb", id(1)));
            chk("TRADE conveys leases", lease(s, "aa") == la && lease(s, "bb") == lb);
            chk("TRADE bumps both mutation heights", mut(s, id(1)) == 10 && mut(s, id(2)) == 10);
        }
        // TRADE anti-rug: pledged name moved away earlier in same block -> whole TRADE drops
        {
            State s = owns("aa", id(1)); addOwned(s, "bb", id(2));
            // id1 transfers aa away (tx0), then TRADE(aa,bb) in tx1 -> id1 no longer owns aa -> drop
            fold(s, blk(10, mtp(10), R28,
                    new TxB().in(id(1)).act(0, transferAll(id(7))),
                    new TxB().in(id(1)).in(id(2)).act(0, trade(0, 1, nm("aa"), nm("bb")))));
            chk("TRADE anti-rug: drops when a pledged name moved earlier same-block",
                ownedBy(s, "aa", id(7)) && ownedBy(s, "bb", id(2)));
        }
        // TRADE fail-closed: idxA==idxB, nameA==nameB, OOB
        {
            State s = owns("aa", id(1)); addOwned(s, "bb", id(2));
            fold(s, blk(10, mtp(10), R28, new TxB().in(id(1)).in(id(2)).act(0, trade(0, 0, nm("aa"), nm("bb")))));
            chk("TRADE idxA==idxB drops", ownedBy(s, "aa", id(1)) && ownedBy(s, "bb", id(2)));
        }
        // TRADE locked name -> drops
        {
            State s = owns("aa", id(1)); addOwned(s, "bb", id(2));
            fold(s, blk(10, mtp(10), R28, new TxB().in(id(1)).act(0, sellTo(50, id(5), nm("aa")))));  // lock aa
            fold(s, blk(11, mtp(11), R28, new TxB().in(id(1)).in(id(2)).act(0, trade(0, 1, nm("aa"), nm("bb")))));
            chk("TRADE drops when a pledged name is locked (offered)", stOf(s, "aa") == Const.OFFERED && ownedBy(s, "bb", id(2)));
        }
    }

    // ===== time-triggered transitions ======================================
    static void timeTransitions() {
        // lapse: name lapses when MTP passes lease_expiry, reclaimable
        {
            State s = new State();
            fold(s, blk(5, mtp(5), R28, new TxB().in(id(1)).act(0, commitFor(salt(1), nm("aa"), id(1)))),
                    blk(6, mtp(6), R28, new TxB().in(id(1)).act(1, claim(salt(1), nm("aa"))))); // 1d lease
            long exp = lease(s, "aa");
            fold(s, blk(7, exp, R28));  // MTP == lease_expiry -> exclusive bound -> lapse
            chk("name lapses at MTP >= lease_expiry (exclusive bound)", !has(s, "aa"));
        }
        // same-block lapse-and-reclaim: lapse in preBlock, reclaim in tx.
        // The reclaimer's COMMIT must be live (within COMMIT_EXPIRY) at the lapse,
        // so place it just before the lapse height.
        {
            State s = new State();
            long M = BASE;
            fold(s, blk(5, M - 1000, R28, new TxB().in(id(1)).act(0, commitFor(salt(1), nm("aa"), id(1)))),
                    blk(6, M, R28, new TxB().in(id(1)).act(1, claim(salt(1), nm("aa")))));   // lease = M + 1 day
            long exp = lease(s, "aa");
            fold(s, blk(7, exp - 1000, R28, new TxB().in(id(2)).act(0, commitFor(salt(2), nm("aa"), id(2))))); // commit live near lapse
            fold(s, blk(8, exp, R28, new TxB().in(id(2)).act(1, claim(salt(2), nm("aa")))));  // pre-block lapse, then reclaim
            chk("same-block lapse-and-reclaim (lapse before tx; id2 mints)", ownedBy(s, "aa", id(2)));
        }
        // listing closes at offer_expiry (name reverts to OWNED for the seller)
        {
            State s = sellable("aa", id(1), 1000);
            long offerExp = s.names.get("aa").offerExpiry;
            fold(s, blk(20, offerExp, R28));  // MTP >= offer_expiry -> close
            chk("unsettled listing closes at offer_expiry -> OWNED", stOf(s, "aa") == Const.OWNED);
        }
        // lapsed reserve reverts RESERVED -> LISTED
        {
            State s = sellable("aa", id(1), 1000);
            long offerExp = s.names.get("aa").offerExpiry;
            BigInteger burn = Fold.depositLeg(bi(1000), 50), payL = Fold.depositLeg(bi(1000), 50);
            long rmtp = offerExp - 5000;
            fold(s, blk(10, rmtp, R28, new TxB().in(id(2)).act(burn.longValue(), reserve(nm("aa"))).spend(payL.longValue(), id(1))));
            long resExp = s.names.get("aa").reserveExpiry;
            fold(s, blk(11, resExp, R28));  // MTP >= reserve_expiry but < offer_expiry? clamp makes resExp<=offerExp
            int st = stOf(s, "aa");
            chk("lapsed reserve reverts (RESERVED->LISTED or closed)", st == Const.LISTED || st == Const.OWNED);
        }
    }

    // ===== fork-risk differential vectors (TV-1..TV-14) =====================
    // Each encodes a HIGH-risk point the 2026-06-29 spec-hardening pass pinned
    // (see SPEC-RATIONALE.md). A correct impl produces the asserted outcome;
    // a forking impl produces the other. These make the pinned readings executable.
    static void forkVectors() {
        // TV-1: COMMIT_EXPIRY is INCLUSIVE — a commit is live THROUGH commit_time+COMMIT_EXPIRY.
        // commit_time = MTP of the commit block (TV-2 folded in). Claim at MTP==boundary MINTS.
        {
            State s = new State();
            long ct = BASE + 5000;                              // commit block MTP == commit_time
            long boundary = ct + Const.COMMIT_EXPIRY;
            fold(s, blk(5, ct, R28, new TxB().in(id(1)).act(0, commitFor(salt(1), nm("edge"), id(1)))),
                    blk(6, boundary, R28, new TxB().in(id(1)).act(10, claim(salt(1), nm("edge")))));
            chk("TV-1 COMMIT_EXPIRY inclusive: claim at MTP==commit_time+COMMIT_EXPIRY mints", ownedBy(s, "edge", id(1)));
        }
        // TV-1 (other side): one tick past the boundary -> commit pruned -> claim DROPS.
        {
            State s = new State();
            long ct = BASE + 5000;
            long past = ct + Const.COMMIT_EXPIRY + 1;
            fold(s, blk(5, ct, R28, new TxB().in(id(1)).act(0, commitFor(salt(1), nm("edge"), id(1)))),
                    blk(6, past, R28, new TxB().in(id(1)).act(10, claim(salt(1), nm("edge")))));
            chk("TV-1 COMMIT_EXPIRY: claim one tick past boundary drops (pruned)", !has(s, "edge"));
        }
        // TV-5b: one author with MULTIPLE matching commits — the backing commit minimizes
        // (commit_height, tx_index). Author commits at tx0 & tx2, rival at tx1; author (tx0) beats rival (tx1).
        {
            State s = new State();
            Action authorCommit = commitFor(salt(1), nm("dup"), id(1));
            Action rivalCommit  = commitFor(salt(2), nm("dup"), id(2));
            fold(s, blk(5, mtp(5), R28,
                        new TxB().in(id(1)).act(0, authorCommit),     // author commit, tx_index 0 (the MIN)
                        new TxB().in(id(2)).act(0, rivalCommit),      // rival  commit, tx_index 1
                        new TxB().in(id(1)).act(0, authorCommit)),    // author commit again, tx_index 2
                    blk(6, mtp(6), R28,
                        new TxB().in(id(2)).act(10, claim(salt(2), nm("dup"))),    // rival claims first
                        new TxB().in(id(1)).act(10, claim(salt(1), nm("dup")))));  // author claims second
            chk("TV-5b author-multiplicity: backing commit = min(commit_height,tx_index); author tx0 beats rival tx1",
                ownedBy(s, "dup", id(1)));
        }
        // M9: TRADE is attributed to its OWN named inputs (idxA/idxB), NOT the acting identity. A
        // TRADE whose vin[0] is ⊥ (did not sign SIGHASH_ALL) still settles iff both parties are valid.
        {
            State s = new State();
            fold(s, blk(5, mtp(5), R28,
                        new TxB().in(id(1)).act(0, commitFor(salt(1), nm("na"), id(1))),
                        new TxB().in(id(2)).act(0, commitFor(salt(2), nm("nb"), id(2)))),
                    blk(6, mtp(6), R28,
                        new TxB().in(id(1)).act(50, claim(salt(1), nm("na"))),
                        new TxB().in(id(2)).act(50, claim(salt(2), nm("nb")))),
                    blk(7, mtp(7), R28,
                        new TxB().in(id(9), Const.P2PKH, false).in(id(1)).in(id(2)).act(0, trade(1, 2, nm("na"), nm("nb")))));
            chk("M9 TRADE bypasses ⊥ acting identity (settles on parties idxA/idxB alone)",
                ownedBy(s, "na", id(2)) && ownedBy(s, "nb", id(1)));
        }
        // TV-6: bitmap is LSB-first — flag byte 0x01 selects lexicographic name 0 (aa), not the high-bit name.
        {
            State s = setupThreeNames();                         // id1 owns aa,bb,cc (lex)
            long base = mtp(6) + 1L * Const.BILLING_UNIT;
            fold(s, blk(7, mtp(7), R28, new TxB().in(id(1)).act(10, renewSel(6, new byte[]{0x01}))));
            chk("TV-6 LSB-first: flag 0x01 renews lex-name-0 (aa), not a high-bit name",
                lease(s, "aa") == base + 10L * Const.BILLING_UNIT && lease(s, "bb") == base && lease(s, "cc") == base);
        }
        // TV-7: a pre-block LAPSE stamps last_set_mutation_height = H (connecting height), so a
        // same-block selective RENEW anchored at H-1 is REJECTED by the anchor guard.
        {
            State s = new State();
            long M = BASE;
            fold(s, blk(5, M, R28,
                        new TxB().in(id(1)).act(0, commitFor(salt(1), nm("aa"), id(1))),
                        new TxB().in(id(1)).act(0, commitFor(salt(2), nm("keep"), id(1)))),
                    blk(6, M, R28,
                        new TxB().in(id(1)).act(1, claim(salt(1), nm("aa"))),        // 1-day lease -> expiry M+1d
                        new TxB().in(id(1)).act(100, claim(salt(2), nm("keep")))));  // 100-day lease
            long aaExp = lease(s, "aa");
            long keepBase = lease(s, "keep");
            // block H=7 with MTP==aaExp: "aa" lapses (pre-block), stamping last_mut(id1)=7;
            // RENEW "keep" (now bit 0) anchored at H-1=6 -> last_mut 7 > 6 -> REJECT.
            fold(s, blk(7, aaExp, R28, new TxB().in(id(1)).act(10, renewSel(6, new byte[]{0x01}))));
            chk("TV-7 lapse stamps H: same-block RENEW anchored H-1 rejected (lease unchanged)",
                !has(s, "aa") && lease(s, "keep") == keepBase);
        }
        // TV-8: a selective TRANSFER selecting a LOCKED (listed) name SKIPS it and moves the rest —
        // per-name filter, never a whole-op drop.
        {
            State s = new State();
            fold(s, blk(5, mtp(5), R28,
                        new TxB().in(id(1)).act(0, commitFor(salt(1), nm("aa"), id(1))),
                        new TxB().in(id(1)).act(0, commitFor(salt(2), nm("bb"), id(1))),
                        new TxB().in(id(1)).act(0, commitFor(salt(3), nm("cc"), id(1)))),
                    blk(6, mtp(6), R28,
                        new TxB().in(id(1)).act(200, claim(salt(1), nm("aa"))),
                        new TxB().in(id(1)).act(200, claim(salt(2), nm("bb"))),
                        new TxB().in(id(1)).act(200, claim(salt(3), nm("cc")))));   // all 200-day leases, last_mut=6
            fold(s, blk(7, mtp(7), R28, new TxB().in(id(1)).act(0, sell(300, 0, nm("bb")))));  // bb LISTED (SELL doesn't bump)
            // selective TRANSFER to id7 selecting aa(bit0)+bb(bit1)=0x03, anchored at 6
            fold(s, blk(8, mtp(8), R28, new TxB().in(id(1)).act(0, transferSel(id(7), 6, new byte[]{0x03}))));
            chk("TV-8 locked-name skip: aa moves to id7, bb (listed) skipped & stays with id1, cc untouched",
                ownedBy(s, "aa", id(7)) && stOf(s, "bb") == Const.LISTED && ownedBy(s, "bb", id(1)) && ownedBy(s, "cc", id(1)));
        }
        // TV-10a: a row LEAVING a market state physically zeros its market fields (fixed-width digest stability).
        {
            State s = sellable("q", id(1), 1000);                // q LISTED
            long offerExp = s.names.get("q").offerExpiry;
            fold(s, blk(20, offerExp, R28));                     // offer closes -> OWNED
            State.NameRow r = s.names.get("q");
            chk("TV-10a reverted listing physically zeros market fields (fixed-width digest)",
                r.st == Const.OWNED && Arrays.equals(r.seller, State.ZERO20) && r.price.signum() == 0
                && r.offerExpiry == 0 && Arrays.equals(r.buyer, State.ZERO20));
        }
        // TV-10b: synthetic post id is exactly 32 bytes (u64 ‖ u32 ‖ 20 zero), filling target[32]/txid[32].
        {
            chk("TV-10b synthetic post id is 32 bytes (u64‖u32‖20 zero)", Model.synthTxid(5, 3).length == 32);
        }
    }

    // ===== §3.4 participant-median fee oracle ===============================
    // Mirrors the c scenario constructions (29_oracle_rate/30_oracle_floor +
    // 49–51): the SIGNED under-claim clamp, the post-floor fee-bearing participant
    // filter, the INCLUSIVE MIN_FEE_SAMPLE boundary, and the LOWER-median
    // single-element index rule.
    static void oracleVectors() {
        final long S = 1_000_000_000_000L;                   // flat 10,000-DOGE subsidy
        // 29-shape: 4 fee-bearing blocks (plus one under-claim) < MIN_FEE_SAMPLE → degrade.
        {
            long[] sub = { S, S, S, S, S };
            long[] cb  = { S + 200_000, S + 400_000, S - 50, S + 1_000_000, S + 600_000 }; // 3rd under-claims
            long[] by  = { 1000, 1000, 1000, 1000, 1000 };
            chk("oracle small window: |P|=4 < MIN_FEE_SAMPLE -> DUST_FLOOR", Oracle.rate(cb, sub, by).equals(bi(1)));
        }
        // 30-shape: every block under-claims → fees clamp to 0 → |P|=0 → floor.
        {
            long[] sub = { S, S, S };
            long[] cb  = { 0, 0, 0 };
            long[] by  = { 1000, 1000, 1000 };
            chk("oracle under-claim clamp: all fees 0 -> DUST_FLOOR", Oracle.rate(cb, sub, by).equals(bi(1)));
        }
        // 49: |P| = 1000 EXACTLY (inclusive boundary) and EVEN, with an under-claim
        //     block inside the window. Lower median = sorted index (1000-1)/2 = 499
        //     of 100..1099 → 599 → rate 119,800 (never an average, never index 500).
        {
            int n = 1500;
            long[] sub = new long[n], cb = new long[n], by = new long[n];
            for (int i = 0; i < n; i++) {
                sub[i] = S; by[i] = 1000;
                if (i < 499)       cb[i] = sub[i];                                  // zero-fee -> non-participant
                else if (i == 499) cb[i] = sub[i] - 50;                             // under-claim -> non-participant
                else               cb[i] = sub[i] + (100L + (i - 500)) * 1000;      // fpb 100..1099
            }
            chk("oracle even boundary: |P|==MIN_FEE_SAMPLE inclusive, lower median 599 -> 119800",
                Oracle.rate(cb, sub, by).equals(bi(119_800)));
        }
        // 50: odd |P| = 1101 through the participant filter — the true middle,
        //     index 550 of 100..1200 → 650 → 130,000.
        {
            int n = 2000;
            long[] sub = new long[n], cb = new long[n], by = new long[n];
            for (int i = 0; i < n; i++) {
                sub[i] = S; by[i] = 1000;
                cb[i] = (i < 899) ? sub[i] : sub[i] + (100L + (i - 899)) * 1000;    // fpb 100..1200
            }
            chk("oracle odd median: |P|=1101, middle 650 -> 130000", Oracle.rate(cb, sub, by).equals(bi(130_000)));
        }
        // 51: |P| = 999 — one short of MIN_FEE_SAMPLE → degrade to DUST_FLOOR exactly.
        {
            int n = 1500;
            long[] sub = new long[n], cb = new long[n], by = new long[n];
            for (int i = 0; i < n; i++) {
                sub[i] = S; by[i] = 1000;
                cb[i] = (i < 501) ? sub[i] : sub[i] + (100L + (i - 501)) * 1000;    // 999 participants
            }
            chk("oracle subsample: |P|=999 one short -> DUST_FLOOR", Oracle.rate(cb, sub, by).equals(bi(1)));
        }
    }

    // ---- setup helpers -----------------------------------------------------
    static State setupTwoNames() {
        State s = new State();
        fold(s, blk(5, mtp(5), R28,
                new TxB().in(id(1)).act(0, commitFor(salt(1), nm("aa"), id(1))),
                new TxB().in(id(1)).act(0, commitFor(salt(2), nm("bb"), id(1)))),
             blk(6, mtp(6), R28,
                new TxB().in(id(1)).act(1, claim(salt(1), nm("aa"))),
                new TxB().in(id(1)).act(1, claim(salt(2), nm("bb")))));
        return s;
    }
    static State setupThreeNames() {
        State s = new State();
        fold(s, blk(5, mtp(5), R28,
                new TxB().in(id(1)).act(0, commitFor(salt(1), nm("aa"), id(1))),
                new TxB().in(id(1)).act(0, commitFor(salt(2), nm("bb"), id(1))),
                new TxB().in(id(1)).act(0, commitFor(salt(3), nm("cc"), id(1)))),
             blk(6, mtp(6), R28,
                new TxB().in(id(1)).act(1, claim(salt(1), nm("aa"))),
                new TxB().in(id(1)).act(1, claim(salt(2), nm("bb"))),
                new TxB().in(id(1)).act(1, claim(salt(3), nm("cc")))));
        return s;   // all three share base lease = mtp(6) + 1 day; mutation height = 6
    }
    // give id a freshly-owned name with a long (200d) lease, via real commit->claim
    static State owns(String name, byte[] id) { State s = new State(); addOwned(s, name, id); return s; }
    static State owns2(String a, String b, byte[] id) { State s = owns(a, id); addOwned(s, b, id); return s; }
    static int seedCtr = 50;
    static void addOwned(State s, String name, byte[] id) {
        int sd = seedCtr++;
        fold(s, blk(5, mtp(5), R28, new TxB().in(id).act(0, commitFor(salt(sd), nm(name), id))),
                blk(6, mtp(6), R28, new TxB().in(id).act(200, claim(salt(sd), nm(name)))));
    }
    static State sellable(String name, byte[] id, long price) {
        State s = owns(name, id);
        fold(s, blk(7, mtp(6), R28, new TxB().in(id).act(0, sell(price, 0, nm(name)))));
        return s;
    }
}
