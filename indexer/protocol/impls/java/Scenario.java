import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.*;

// Directed conformance vectors (cross-language adversarial scenarios) — the Java
// port of impls/c `scenario`. Each builds a deterministic, named construction and
// emits `name <digest>` (canonical §4 state digest) or `name <u64>`; the rolling
// `combined` hash is the single-line cross-language check. These pin the spec's
// named edge cases (§5) with auditable outcomes, and cover the rare branches the
// random soak almost never hits (deep displacement, deposit 2^64, the fee oracle).
// Names-only: vote / decorate / POST vectors removed (matches impls/c).
final class Scenario {
    // rate = 28 makes the burn equal the number of days (see impls/c RATE_DAYS).
    static final BigInteger RATE = BigInteger.valueOf(28);
    static final BigInteger U64_MAX = Const.TWO64.subtract(BigInteger.ONE);
    static final long SUBSIDY = 1_000_000_000_000L;    // 10000 DOGE flat (§3.4)

    static MessageDigest comb;

    // ---- identities & bytes (impls/c id_of: h160[0]=tag, h160[19]=tag) ------
    static byte[] genId(int tag) { byte[] h = new byte[20]; h[0] = (byte) tag; h[19] = (byte) tag; return h; }
    static byte[] salt(int b) { byte[] s = new byte[32]; Arrays.fill(s, (byte) b); return s; }
    static byte[] nm(String s) { return s.getBytes(java.nio.charset.StandardCharsets.US_ASCII); }

    // ---- fold driver: begin_block + apply_tx with an EXPLICIT tx_index ------
    static final class S {
        final State st = new State();
        final Fold f = new Fold(st);
        long h, m;
        BigInteger r = RATE;
        void begin(long height, long mtp) { begin(height, mtp, RATE); }
        void begin(long height, long mtp, BigInteger rate) {
            h = height; m = mtp; r = rate;
            f.applyBlock(new Model.Block(height, mtp, rate, new Model.Tx[0]));  // scratch reset + pre-block transitions
        }
        void apply(T t, int txIndex) {
            Model.Tx tx = t.t();
            tx.txIndex = txIndex;
            f.applyOneTx(h, m, r, tx);
        }
    }

    // ---- tx builder (BigInteger-valued carriers; outputs sit after carriers) -
    static final class T {
        final List<Model.TxIn> ins = new ArrayList<>();
        final List<Model.TxOut> outs = new ArrayList<>();
        T in(byte[] id) { ins.add(new Model.TxIn(id, Const.P2PKH, true)); return this; }
        T in(byte[] id, boolean sigAll) { ins.add(new Model.TxIn(id, Const.P2PKH, sigAll)); return this; }
        T act(long value, Action a) { return act(BigInteger.valueOf(value), a); }
        T act(BigInteger value, Action a) { outs.add(Model.TxOut.carrier(value, Wire.encode(a))); return this; }
        T out(byte[] dest, long value) { return out(dest, BigInteger.valueOf(value)); }
        T out(byte[] dest, BigInteger value) { outs.add(Model.TxOut.spend(value, dest, Const.P2PKH)); return this; }
        Model.Tx t() { return new Model.Tx(ins.toArray(new Model.TxIn[0]), outs.toArray(new Model.TxOut[0])); }
    }

    // ---- emitters -----------------------------------------------------------
    static void emitState(String name, S s) {
        byte[] d = Hashes.sha256(StateDigest.serialize(s.st));
        System.out.println(name + " " + Hex.enc(d));
        comb.update(d);
    }
    static void emitU64(String name, long v) {
        System.out.println(name + " " + Long.toUnsignedString(v));
        comb.update(new Buf().i64(v).toBytes());
    }

    // ---- shared constructions (mirror impls/c helpers) ----------------------
    // Commit `name`(author=tag, salt) at block `ch`, then CLAIM `days` at block `kh`.
    static void commitThenClaim(S s, int tag, String name, int saltB, long days,
                                long cmtp, long ch, long kmtp, long kh) {
        byte[] id = genId(tag);
        s.begin(ch, cmtp);
        s.apply(new T().in(id).act(0, Behav.commitFor(salt(saltB), nm(name), id)), 0);
        s.begin(kh, kmtp);
        s.apply(new T().in(id).act(days, Behav.claim(salt(saltB), nm(name))), 0);
    }
    // Mint `name` to `tag` with `days` lease, leaving the fold at the claim's block.
    static S minted(int tag, String name, long days, long claimMtp) {
        S s = new S();
        commitThenClaim(s, tag, name, 0x33, days, claimMtp - 100, 10, claimMtp, 11);
        return s;
    }
    static S twoNames(byte[] A, byte[] B) {
        S s = new S();
        s.begin(10, 1000);
        s.apply(new T().in(A).act(0, Behav.commitFor(salt(0x01), nm("aaa"), A)), 0);
        s.apply(new T().in(B).act(0, Behav.commitFor(salt(0x02), nm("bbb"), B)), 1);
        s.begin(11, 1500);
        s.apply(new T().in(A).act(30, Behav.claim(salt(0x01), nm("aaa"))), 0);
        s.apply(new T().in(B).act(30, Behav.claim(salt(0x02), nm("bbb"))), 1);
        return s;
    }
    // MTP(H) = sorted middle element at index n/2 of the last ≤11 timestamps (BIP113-style).
    static long mtpMedian(long[] ts) {
        long[] t = ts.clone();
        Arrays.sort(t);
        return t[t.length / 2];
    }
    static long[] fill(int n, long v) { long[] a = new long[n]; Arrays.fill(a, v); return a; }

    static void run() {
        try { comb = MessageDigest.getInstance("SHA-256"); }
        catch (Exception e) { throw new RuntimeException(e); }
        byte[] A = genId(0xAA), B = genId(0xBB), C = genId(0xCC);

        { S s = new S(); emitState("01_empty", s); }

        { S s = new S(); commitThenClaim(s, 0xAA, "bob", 0x11, 10, 1000, 10, 1500, 11);
          emitState("02_commit_claim", s); }

        { S s = new S(); s.begin(11, 1500);
          s.apply(new T().in(A).act(10, Behav.claim(salt(0x11), nm("bob"))), 0);
          emitState("03_naked_claim_drop", s); }

        { S s = new S(); s.begin(11, 1500);
          s.apply(new T().in(A).act(0, Behav.commitFor(salt(0x11), nm("bob"), A))
                         .act(10, Behav.claim(salt(0x11), nm("bob"))), 0);
          emitState("04_shallow_commit_drop", s); }

        // priority: lower commit_height (A@10) wins ownership in BOTH claim orderings. The two
        // digests differ — a transiently-displaced mint leaves an incidental mutation-height
        // bump that depends on tx order — but each is cross-language-exact.
        for (int order = 0; order < 2; order++) {
            S s = new S();
            s.begin(10, 1000); s.apply(new T().in(A).act(0, Behav.commitFor(salt(0x11), nm("bob"), A)), 0);
            s.begin(12, 1100); s.apply(new T().in(B).act(0, Behav.commitFor(salt(0x22), nm("bob"), B)), 0);
            s.begin(20, 1200);
            T kA = new T().in(A).act(10, Behav.claim(salt(0x11), nm("bob")));
            T kB = new T().in(B).act(10, Behav.claim(salt(0x22), nm("bob")));
            if (order == 0) { s.apply(kB, 0); s.apply(kA, 1); } else { s.apply(kA, 0); s.apply(kB, 1); }
            emitState(order == 0 ? "05_priority_b_first" : "06_priority_a_first", s);
        }

        // commitment-copy: B reposts A's commitment bytes, then B claims → drop (author-bound); A claims → owns.
        { S s = new S();
          Action ca = Behav.commitFor(salt(0x33), nm("bob"), A);   // A-bound commitment
          Action copy = new Action(); copy.op = Const.COMMIT; copy.commitment = ca.commitment;
          s.begin(10, 1000);
          s.apply(new T().in(A).act(0, ca), 0);
          s.apply(new T().in(B).act(0, copy), 1);                  // B copies the commitment
          s.begin(11, 1100);
          s.apply(new T().in(B).act(10, Behav.claim(salt(0x33), nm("bob"))), 0);  // B can't satisfy → drop
          s.apply(new T().in(A).act(10, Behav.claim(salt(0x33), nm("bob"))), 1);  // A wins
          emitState("07_commitment_copy", s); }

        { S s = minted(0xAA, "bob", 10, 1500);   // expiry 865500
          s.begin(12, 865500);                   // MTP == expiry → lapse (exclusive)
          emitState("08_lease_lapse", s); }

        { S s = minted(0xAA, "bob", 10, 1500); s.begin(12, 1600);
          s.apply(new T().in(A).act(5, Behav.renewAll()), 0);
          emitState("09_renew_stack", s); }

        // water-fill even split: 3 names, renew-all buys 30 name-days → +10 each.
        { S s = new S(); String[] names = { "a", "b", "c" };
          s.begin(10, 1000);
          for (int i = 0; i < 3; i++) s.apply(new T().in(A).act(0, Behav.commitFor(salt(0x40 + i), nm(names[i]), A)), i);
          s.begin(11, 1100);
          for (int i = 0; i < 3; i++) s.apply(new T().in(A).act(1, Behav.claim(salt(0x40 + i), nm(names[i]))), i);
          s.begin(12, 1200);
          s.apply(new T().in(A).act(30, Behav.renewAll()), 0);
          emitState("10_waterfill_even", s); }

        { S s = new S(); commitThenClaim(s, 0xAA, "bob", 0x11, 100000, 1000, 10, 1500, 11);  // huge → caps at 365d
          emitState("11_waterfill_maxlease", s); }

        { S s = minted(0xAA, "bob", 10, 1500); s.begin(12, 1600);
          s.apply(new T().in(A).act(0, Behav.transferAll(B)), 0);
          emitState("12_transfer_gift", s); }

        { S s = minted(0xAA, "bob", 10, 1500); s.begin(12, 1600);
          s.apply(new T().in(A).act(0, Behav.release(11, new byte[]{ 0x01 })), 0);
          emitState("13_release", s); }

        { S s = minted(0xAA, "w", 300, 1500);
          s.begin(12, 1600); s.apply(new T().in(A).act(0, Behav.sell(20000, 50000, nm("w"))), 0);
          s.begin(13, 1700); s.apply(new T().in(B).act(100, Behav.reserve(nm("w"))).out(A, 100), 0);
          s.begin(14, 1800); s.apply(new T().in(B).act(0, Behav.settle(nm("w"))).out(A, 19800), 0);
          emitState("14_market_full", s); }

        { S s = minted(0xAA, "w", 300, 1500); s.begin(12, 1600);
          s.apply(new T().in(A).act(0, Behav.sell(20000, 50000, nm("w"))), 0);
          s.begin(13, 1700); s.apply(new T().in(B).act(99, Behav.reserve(nm("w"))).out(A, 100), 0);
          emitState("15_reserve_burn_short", s); }

        { S s = minted(0xAA, "w", 300, 1500); s.begin(12, 1600);
          s.apply(new T().in(A).act(0, Behav.sell(20000, 50000, nm("w"))), 0);
          s.begin(13, 1700); s.apply(new T().in(B).act(100, Behav.reserve(nm("w"))).out(A, 60).out(A, 60), 0);
          emitState("16_reserve_pay_summed", s); }

        // reserve near offer end → reserve_expiry clamps to offer_expiry.
        { S s = minted(0xAA, "w", 300, 1500); s.begin(12, 1600);
          s.apply(new T().in(A).act(0, Behav.sell(20000, 0, nm("w"))), 0);   // window default 18000 → offer_expiry 19600
          s.begin(13, 5000);
          s.apply(new T().in(B).act(100, Behav.reserve(nm("w"))).out(A, 100), 0); // 5000+18000>19600 → clamp
          emitState("17_reserve_clamp", s); }

        { S s = minted(0xAA, "w", 300, 1500); s.begin(12, 1600);
          s.apply(new T().in(A).act(0, Behav.sell(2, 0, nm("w"))), 0);       // below 3·DUST
          emitState("18_sell_price_floor", s); }

        { S s = minted(0xAA, "w", 1, 1500); s.begin(12, 65000);              // short tail
          s.apply(new T().in(A).act(0, Behav.sell(20000, 0, nm("w"))), 0);
          emitState("19_sell_window_overflow", s); }

        { S s = minted(0xAA, "w", 300, 1500); s.begin(12, 1600);
          s.apply(new T().in(A).act(0, Behav.sellTo(5000, B, nm("w"))), 0);
          s.begin(13, 1700);
          s.apply(new T().in(C).act(0, Behav.pay(nm("w"))).out(A, 5000), 0);  // stranger → drop
          s.apply(new T().in(B).act(0, Behav.pay(nm("w"))).out(A, 5000), 1);  // buyer → owns
          emitState("20_directed_pay", s); }

        // 2^64-1 price: the 128-bit deposit legs must be exact (a 64-bit impl wraps).
        { S s = minted(0xAA, "w", 300, 1500); s.begin(12, 1600);
          Action sellMax = Behav.sell(0, 50000, nm("w")); sellMax.price = U64_MAX;
          s.apply(new T().in(A).act(0, sellMax), 0);
          BigInteger leg = U64_MAX.multiply(BigInteger.valueOf(50)).divide(BigInteger.valueOf(10000));
          s.begin(13, 1700);
          s.apply(new T().in(B).act(leg, Behav.reserve(nm("w"))).out(A, leg), 0);
          emitState("21_deposit_2pow64", s); }

        // AS attribution: claim attributed to vin[1]=B (matches B's commit).
        { S s = new S(); s.begin(10, 1000);
          s.apply(new T().in(B).act(0, Behav.commitFor(salt(0x55), nm("bob"), B)), 0);
          s.begin(11, 1500);
          s.apply(new T().in(A).in(B).act(0, Behav.as(1)).act(10, Behav.claim(salt(0x55), nm("bob"))), 0);
          emitState("22_as_attribution", s); }

        { S s = new S(); s.begin(10, 1000);
          s.apply(new T().in(B).act(0, Behav.commitFor(salt(0x55), nm("bob"), B)), 0);
          s.begin(11, 1500);
          s.apply(new T().in(A).in(B, false).act(0, Behav.as(1)).act(10, Behav.claim(salt(0x55), nm("bob"))), 0);
          emitState("23_as_oob_drop", s); }

        { S s = twoNames(A, B); s.begin(12, 1600);
          s.apply(new T().in(A).in(B).act(0, Behav.trade(0, 1, nm("aaa"), nm("bbb"))), 0);
          emitState("24_trade_swap", s); }

        { S s = twoNames(A, B); s.begin(12, 1600);
          s.apply(new T().in(A).act(0, Behav.transferAll(C)), 0);                       // aaa→C before the trade
          s.apply(new T().in(A).in(B).act(0, Behav.trade(0, 1, nm("aaa"), nm("bbb"))), 1); // anti-rug → drop
          emitState("25_trade_rug_before", s); }

        // fee oracle (§3.4): signed under-claim clamp + participant filter + MIN_FEE_SAMPLE
        // degrade + lower-median + REF_SIZE scale + clamp. 4 participants < MIN_FEE_SAMPLE
        // ⇒ this small window now degrades to DUST_FLOOR (the big-window vectors are 49–51).
        // (vote/decorate vectors 26–28 removed — names-only consensus.)
        { long[] cb = { 1_000_000_200_000L, 1_000_000_400_000L, 999_999_999_950L, 1_000_001_000_000L, 1_000_000_600_000L };  // 3rd under-claims
          emitU64("29_oracle_rate", Oracle.rate(cb, fill(5, SUBSIDY), fill(5, 1000)).longValueExact()); }  // |P|=4 < 1000 → DUST_FLOOR = 1
        { long[] cb = { 0, 0, 0 };                                           // all under-claim → fees 0 → rate floor
          emitU64("30_oracle_floor", Oracle.rate(cb, fill(3, SUBSIDY), fill(3, 1000)).longValueExact()); }
        { long[] ts = { 100, 50, 200, 30, 150, 80, 220, 10, 175, 60, 190 };
          emitU64("31_mtp_median", mtpMedian(ts)); }                          // median of 11

        // ── water-fill rare branches ──
        // 32: T < count — burn buys fewer name-days than names; the first T names
        // (ascending-lex) get +1 day, the rest none (§3.5 floor).
        { S s = new S(); String[] names = { "a", "b", "c" };
          s.begin(10, 1000);
          for (int i = 0; i < 3; i++) s.apply(new T().in(A).act(0, Behav.commitFor(salt(0x50 + i), nm(names[i]), A)), i);
          s.begin(11, 1100);
          for (int i = 0; i < 3; i++) s.apply(new T().in(A).act(1, Behav.claim(salt(0x50 + i), nm(names[i]))), i);
          s.begin(12, 1200);
          s.apply(new T().in(A).act(2, Behav.renewAll()), 0);                // T=2 over 3 → a,b +1d, c none
          emitState("32_waterfill_floor", s); }

        // 33: every targeted name hits MAX_LEASE with T still remaining → surplus forfeited.
        { S s = new S(); String[] names = { "a", "b" };
          s.begin(10, 1000);
          for (int i = 0; i < 2; i++) s.apply(new T().in(A).act(0, Behav.commitFor(salt(0x60 + i), nm(names[i]), A)), i);
          s.begin(11, 1100);
          for (int i = 0; i < 2; i++) s.apply(new T().in(A).act(360, Behav.claim(salt(0x60 + i), nm(names[i]))), i);  // ~360d each
          s.begin(12, 1100);
          s.apply(new T().in(A).act(100000, Behav.renewAll()), 0);           // huge → both cap @MAX_LEASE, forfeit
          emitState("33_waterfill_allcap_forfeit", s); }

        // ── reorg edge cases as deterministic vectors ──
        // 34: a same-block lapse-and-reclaim. (a) bob lapses at MTP==expiry, B reclaims → B owns.
        //     (b) the reorg restores A's earlier RENEW, so bob never lapses and B's reclaim drops.
        { S s = minted(0xAA, "bob", 10, 1500);                               // expiry 865500
          s.begin(12, 860000);
          s.apply(new T().in(B).act(0, Behav.commitFor(salt(0x44), nm("bob"), B)), 0);
          s.begin(13, 865500);
          s.apply(new T().in(B).act(10, Behav.claim(salt(0x44), nm("bob"))), 0);  // lapse then B mints
          emitState("34a_reorg_lapse_reclaim", s); }
        { S s = minted(0xAA, "bob", 10, 1500);
          s.begin(12, 860000);
          s.apply(new T().in(B).act(0, Behav.commitFor(salt(0x44), nm("bob"), B)), 0);
          s.apply(new T().in(A).act(10, Behav.renewAll()), 1);               // A renews → bob survives past 865500
          s.begin(13, 865500);
          s.apply(new T().in(B).act(10, Behav.claim(salt(0x44), nm("bob"))), 0);  // bob owned → drop
          emitState("34b_reorg_renew_blocks_reclaim", s); }

        // 35: a SETTLE un-confirmed by a reorg. (a) the reserve lapses without a settle →
        //     the listing reverts to the seller; (b) the settle confirms → buyer owns.
        { S s = minted(0xAA, "w", 300, 1500);
          s.begin(12, 1600); s.apply(new T().in(A).act(0, Behav.sell(20000, 50000, nm("w"))), 0);
          s.begin(13, 1700); s.apply(new T().in(B).act(100, Behav.reserve(nm("w"))).out(A, 100), 0);
          s.begin(14, 20000);                    // MTP past reserve_expiry (19700) → revert to listing
          emitState("35a_settle_dropped_relisted", s); }
        { S s = minted(0xAA, "w", 300, 1500);
          s.begin(12, 1600); s.apply(new T().in(A).act(0, Behav.sell(20000, 50000, nm("w"))), 0);
          s.begin(13, 1700); s.apply(new T().in(B).act(100, Behav.reserve(nm("w"))).out(A, 100), 0);
          s.begin(14, 1800); s.apply(new T().in(B).act(0, Behav.settle(nm("w"))).out(A, 19800), 0);
          emitState("35b_settle_confirmed", s); }

        // 36: an MTP boundary call that flips under a one-tick reorg. lease_expiry is an
        //     EXCLUSIVE bound: MTP == expiry−1 stays owned; MTP == expiry lapses.
        { S s = minted(0xAA, "bob", 10, 1500); s.begin(12, 865499); emitState("36a_mtp_below_owned", s); }
        { S s = minted(0xAA, "bob", 10, 1500); s.begin(12, 865500); emitState("36b_mtp_at_lapsed", s); }

        // (37 vote-neg removed — names-only)

        // ── pre-block ordering & intra-block market races ──
        // 38: a same-block RENEW-vs-CLAIM race at the exact lapse tie. The pre-block lapse
        //     returns `bob` to the pool BEFORE any tx runs, so A's renew-all renews only
        //     `keep` and the hunter B's CLAIM (commit ≥1 block deep) mints `bob`.
        { S s = new S();
          s.begin(10, 1000);
          s.apply(new T().in(A).act(0, Behav.commitFor(salt(0x33), nm("bob"), A)), 0);
          s.apply(new T().in(A).act(0, Behav.commitFor(salt(0x34), nm("keep"), A)), 1);
          s.begin(11, 1500);
          s.apply(new T().in(A).act(10, Behav.claim(salt(0x33), nm("bob"))), 0);   // bob expiry 865500
          s.apply(new T().in(A).act(300, Behav.claim(salt(0x34), nm("keep"))), 1); // keep long-lived
          s.begin(12, 860000);
          s.apply(new T().in(B).act(0, Behav.commitFor(salt(0x44), nm("bob"), B)), 0);  // hunter commits
          s.begin(13, 865500);                   // MTP == bob's expiry → bob lapses pre-block
          s.apply(new T().in(A).act(5, Behav.renewAll()), 0);                      // renews `keep` only
          s.apply(new T().in(B).act(10, Behav.claim(salt(0x44), nm("bob"))), 1);   // hunter mints bob
          emitState("38_lapse_renew_vs_claim", s); }

        // 39: a single pre-block tick that crosses reserve_expiry AND offer_expiry at once,
        //     cascading RESERVED→LISTED→OWNED in one pass (§5 type-order reserve→offer→lease).
        { S s = minted(0xAA, "w", 300, 1500);                                // lease_expiry = 25,921,500
          s.begin(12, 1600); s.apply(new T().in(A).act(0, Behav.sell(20000, 50000, nm("w"))), 0);  // offer_expiry = 51600
          s.begin(13, 1700); s.apply(new T().in(B).act(100, Behav.reserve(nm("w"))).out(A, 100), 0); // reserve_expiry = 19700 < 51600
          s.begin(14, 51600);                    // MTP == offer_expiry, > reserve_expiry → both legs fire
          emitState("39_preblock_reserve_offer_collapse", s); }

        // 40: intra-block RESERVE option theft. The first buyer (chain-order) wins the exclusive
        //     option; the second drops (no overwrite), so its later SETTLE fails the buyer-match.
        { S s = minted(0xAA, "w", 300, 1500);
          s.begin(12, 1600); s.apply(new T().in(A).act(0, Behav.sell(20000, 50000, nm("w"))), 0);
          s.begin(13, 1700);
          s.apply(new T().in(B).act(100, Behav.reserve(nm("w"))).out(A, 100), 0);  // B wins the option
          s.apply(new T().in(C).act(100, Behav.reserve(nm("w"))).out(A, 100), 1);  // C loses (row RESERVED) → drop
          s.apply(new T().in(C).act(0, Behav.settle(nm("w"))).out(A, 19800), 2);   // C settles → buyer-mismatch → drop
          emitState("40_reserve_option_theft", s); }

        // 41: value-collision in spendable-output matching. One tx does RESERVE(x)+SETTLE(y),
        //     both paying seller A, with two outputs to A: vout[0]=19800 (settle remainder) and
        //     vout[1]=5 (reserve pay-leg). The consume-once, exact-value, vout-order matcher must
        //     let RESERVE skip the larger vout[0] and take vout[1], then SETTLE take vout[0].
        { S s = new S();
          s.begin(10, 1000);
          s.apply(new T().in(A).act(0, Behav.commitFor(salt(0x71), nm("x"), A)), 0);
          s.apply(new T().in(A).act(0, Behav.commitFor(salt(0x72), nm("y"), A)), 1);
          s.begin(11, 1500);
          s.apply(new T().in(A).act(300, Behav.claim(salt(0x71), nm("x"))), 0);
          s.apply(new T().in(A).act(300, Behav.claim(salt(0x72), nm("y"))), 1);
          s.begin(12, 1600);
          s.apply(new T().in(A).act(0, Behav.sell(1000, 50000, nm("x"))), 0);   // pay_leg(x) = 5
          s.apply(new T().in(A).act(0, Behav.sell(20000, 50000, nm("y"))), 1);  // remainder(y) = 19800
          s.begin(13, 1700);
          s.apply(new T().in(B).act(100, Behav.reserve(nm("y"))).out(A, 100), 0);  // B reserves y
          s.begin(14, 1800);
          s.apply(new T().in(B).act(5, Behav.reserve(nm("x")))                  // car_value 5 ≥ burn_leg(x)=5
                         .act(0, Behav.settle(nm("y")))
                         .out(A, 19800)                                         // vout[0] (lower) = settle remainder
                         .out(A, 5), 0);                                        // vout[1] (higher) = reserve pay-leg
          emitState("41_vout_value_collision", s); }

        // ── priority tie-break + Tier-4 coverage (audit follow-ups) ──
        // 42: CLAIM priority tie-break is the COMMIT's tx_index (§3.2 tuple), NOT claim chain order.
        { S s = new S();
          s.begin(10, 1000);
          s.apply(new T().in(A).act(0, Behav.commitFor(salt(0x81), nm("bob"), A)), 5);
          s.apply(new T().in(B).act(0, Behav.commitFor(salt(0x82), nm("bob"), B)), 2);
          s.begin(20, 1500);
          s.apply(new T().in(A).act(10, Behav.claim(salt(0x81), nm("bob"))), 0);   // applied first
          s.apply(new T().in(B).act(10, Behav.claim(salt(0x82), nm("bob"))), 1);   // lower commit tx_index → wins
          emitState("42_claim_commit_txindex_tiebreak", s); }

        // 43: escrow movement-lock (§3.7 headline) — a LISTED name rejects every move:
        //     TRANSFER, RELEASE, re-SELL, and SELL_TO all no-op while it sits on the market.
        { S s = minted(0xAA, "w", 300, 1500);
          s.begin(12, 1600); s.apply(new T().in(A).act(0, Behav.sell(20000, 50000, nm("w"))), 0);
          s.begin(13, 1700);
          s.apply(new T().in(A).act(0, Behav.transferAll(B)), 0);                   // gift → locked, skip
          s.apply(new T().in(A).act(0, Behav.release(11, new byte[]{ 0x01 })), 1);  // release → locked, skip
          s.apply(new T().in(A).act(0, Behav.sell(30000, 50000, nm("w"))), 2);      // re-SELL → not OWNED, reject
          s.apply(new T().in(A).act(0, Behav.sellTo(5000, B, nm("w"))), 3);         // SELL_TO → not OWNED, reject
          emitState("43_escrow_movement_lock", s); }

        // 44: anchor-guard reject (§3.5) — a bitmap op whose anchor is OLDER than the owner's
        //     last set-mutation is dropped (stale set-view could select the wrong names).
        { S s = new S();
          s.begin(10, 1000);
          s.apply(new T().in(A).act(0, Behav.commitFor(salt(0x91), nm("a"), A)), 0);
          s.begin(11, 1500);
          s.apply(new T().in(A).act(30, Behav.claim(salt(0x91), nm("a"))), 0);      // lm(A)=11
          s.apply(new T().in(A).act(0, Behav.commitFor(salt(0x92), nm("b"), A)), 1);
          s.begin(12, 1600);
          s.apply(new T().in(A).act(30, Behav.claim(salt(0x92), nm("b"))), 0);      // lm(A)=12 (set grew)
          s.begin(13, 1700);
          s.apply(new T().in(A).act(0, Behav.release(11, new byte[]{ 0x01 })), 0);  // anchor 11 < lm 12 → reject
          emitState("44_anchor_guard_reject", s); }

        // 45: COMMIT_EXPIRY prune — a commit older than COMMIT_EXPIRY (18000s) is pruned pre-block,
        //     so a later matching claim finds no live commit and drops (§3.2).
        { S s = new S();
          s.begin(10, 1000);
          s.apply(new T().in(A).act(0, Behav.commitFor(salt(0x33), nm("bob"), A)), 0);
          s.begin(11, 19001);                                                       // 19001 > 1000 + 18000 → prune
          s.apply(new T().in(A).act(10, Behav.claim(salt(0x33), nm("bob"))), 0);     // no live commit → drop
          emitState("45_commit_expiry_prune", s); }

        // 46: RESERVE burn leg is an inequality (car_value ≥ burn_leg), not exact — an OVER-funded
        //     burn (car_value 150 > burn_leg 100) still wins the option (cf. 15: 99 < 100 drops).
        { S s = minted(0xAA, "w", 300, 1500); s.begin(12, 1600);
          s.apply(new T().in(A).act(0, Behav.sell(20000, 50000, nm("w"))), 0);
          s.begin(13, 1700);
          s.apply(new T().in(B).act(150, Behav.reserve(nm("w"))).out(A, 100), 0);
          emitState("46_reserve_overfunded_burn", s); }

        // 47: TRADE malformed drops — OOB index, idxA==idxB (one party), and nameA==nameB are
        //     each fail-closed; the two-name state is left untouched (§3.10).
        { S s = twoNames(A, B);
          s.begin(12, 1600);
          s.apply(new T().in(A).in(B).act(0, Behav.trade(0, 5, nm("aaa"), nm("bbb"))), 0);  // idx_b OOB → drop
          s.apply(new T().in(A).in(B).act(0, Behav.trade(0, 0, nm("aaa"), nm("bbb"))), 1);  // idxA==idxB → drop
          s.apply(new T().in(A).in(B).act(0, Behav.trade(0, 1, nm("aaa"), nm("aaa"))), 2);  // nameA==nameB → drop
          emitState("47_trade_malformed_drops", s); }

        // 48: selective TRANSFER (anchor+flags) gifts a SUBSET — bits {0,2} of A's sorted set
        //     {a,b,c} move to B; b stays with A. Exercises the bitmap-selected positive transfer.
        { S s = new S();
          s.begin(10, 1000);
          s.apply(new T().in(A).act(0, Behav.commitFor(salt(0xA1), nm("a"), A)), 0);
          s.apply(new T().in(A).act(0, Behav.commitFor(salt(0xA2), nm("b"), A)), 1);
          s.apply(new T().in(A).act(0, Behav.commitFor(salt(0xA3), nm("c"), A)), 2);
          s.begin(11, 1500);
          s.apply(new T().in(A).act(30, Behav.claim(salt(0xA1), nm("a"))), 0);
          s.apply(new T().in(A).act(30, Behav.claim(salt(0xA2), nm("b"))), 1);
          s.apply(new T().in(A).act(30, Behav.claim(salt(0xA3), nm("c"))), 2);
          s.begin(12, 1600);
          s.apply(new T().in(A).act(0, Behav.transferSel(B, 11, new byte[]{ 0x05 })), 0);  // bits 0 and 2 → a, c
          emitState("48_transfer_selective", s); }

        // ── §3.4 participant-median oracle (fee-bearing filter + MIN_FEE_SAMPLE) ──
        // 49: |P| = 1000 EXACTLY (inclusive boundary) and EVEN, with an under-claim
        //     block inside the window. Lower median = index (1000−1)/2 = 499 of the
        //     sorted 100..1099 → 599 → rate 119,800.
        { int n = 1500; long[] cb = new long[n];
          for (int i = 0; i < n; i++) {
              if (i < 499)       cb[i] = SUBSIDY;                                    // zero-fee → non-participant
              else if (i == 499) cb[i] = SUBSIDY - 50;                               // under-claim → non-participant
              else               cb[i] = SUBSIDY + (long) (100 + (i - 500)) * 1000;  // fpb 100..1099
          }
          emitU64("49_oracle_even_boundary", Oracle.rate(cb, fill(n, SUBSIDY), fill(n, 1000)).longValueExact()); }  // → 119800

        // 50: odd |P| = 1101 through the participant filter — the historical middle
        //     rule unchanged by the rewrite: index 550 of 100..1200 → 650 → 130,000.
        { int n = 2000; long[] cb = new long[n];
          for (int i = 0; i < n; i++)
              cb[i] = (i < 899) ? SUBSIDY : SUBSIDY + (long) (100 + (i - 899)) * 1000;  // fpb 100..1200
          emitU64("50_oracle_odd_median", Oracle.rate(cb, fill(n, SUBSIDY), fill(n, 1000)).longValueExact()); }     // → 130000

        // 51: |P| = 999 — one short of MIN_FEE_SAMPLE → degrade to DUST_FLOOR exactly.
        { int n = 1500; long[] cb = new long[n];
          for (int i = 0; i < n; i++)
              cb[i] = (i < 501) ? SUBSIDY : SUBSIDY + (long) (100 + (i - 501)) * 1000;  // 999 participants
          emitU64("51_oracle_subsample_floor", Oracle.rate(cb, fill(n, SUBSIDY), fill(n, 1000)).longValueExact()); } // → 1

        // 52: charset = a DNS label [a-z0-9-], 1..32 (re-pinned 2026-07-07, supersedes
        // the 2026-07-02 dot rule): hyphen and a 32-byte name MINT; '.' and '_' now DROP
        // (uppercase still drops), leaving exactly the two valid names.
        { S s = new S();
          commitThenClaim(s, 0xAA, "shib-p2p",                         0x71, 10, 1000, 10, 1500, 11);
          commitThenClaim(s, 0xAA, "abcdefghijklmnopqrstuvwxyz0123ab", 0x72, 10, 2000, 12, 2500, 13);
          commitThenClaim(s, 0xAA, "shib.p2p",                         0x73, 10, 3000, 14, 3500, 15);
          commitThenClaim(s, 0xAA, "shib_p2p",                         0x74, 10, 4000, 16, 4500, 17);
          emitState("52_charset", s); }

        // 52b: structural name rejects — leading/trailing hyphen and xn-- ACE drop.
        { S s = new S();
          commitThenClaim(s, 0xAA, "-lead",  0x81, 10, 1000, 10, 1500, 11);
          commitThenClaim(s, 0xAA, "trail-", 0x82, 10, 2000, 12, 2500, 13);
          commitThenClaim(s, 0xAA, "xn--x",  0x83, 10, 3000, 14, 3500, 15);
          commitThenClaim(s, 0xAA, "ok-name",0x84, 10, 4000, 16, 4500, 17);
          emitState("52b_structural", s); }

        // 54: NO per-tx count cap (§0). One tx carries 17 COMMIT carriers — past the
        // historical 16 — plus 17 payee outs; all fold. Proves the reference agrees with
        // an unbounded impl. (Was VOTE pre names-only; now COMMIT.)
        { S s = new S(); s.begin(10, 1000);
          T t = new T().in(A);
          for (int i = 0; i < 17; i++) {
              Action a = new Action(); a.op = Const.COMMIT; a.commitment = new byte[32]; a.commitment[0] = (byte) i;
              t.act(0, a);
          }
          for (int i = 0; i < 17; i++) t.out(A, 1);
          s.apply(t, 0);
          emitState("54_no_txcap", s); }

        // 55: a name minted then RELEASEd earlier in the SAME block re-mints fresh on a
        // later CLAIM in that block (§3.6 "immediately reclaimable"; row existence is
        // authoritative, the block-local claim scratch never blocks a re-mint).
        { S s = new S();
          s.begin(10, 1000);
          s.apply(new T().in(A).act(0, Behav.commitFor(salt(0x91), nm("foo"), A)), 0);
          s.begin(11, 1500);
          s.apply(new T().in(A).act(10, Behav.claim(salt(0x91), nm("foo"))), 0);       // mint foo→A
          s.apply(new T().in(A).act(0, Behav.release(11, new byte[]{ 0x01 })), 1);     // release foo (row gone, scratch lingers)
          s.apply(new T().in(A).act(10, Behav.claim(salt(0x91), nm("foo"))), 2);       // MUST re-mint foo→A
          emitState("55_claim_release_reclaim_sameblock", s); }

        // 55b: same, but the re-claim is by a DIFFERENT party B whose backing commit has
        // LOWER priority than the departed A's — B still mints fresh (a released name's
        // former owner priority is irrelevant once the row is gone).
        { S s = new S();
          s.begin(10, 1000);
          s.apply(new T().in(A).act(0, Behav.commitFor(salt(0x91), nm("foo"), A)), 0); // A commit (10, tx0) — higher priority
          s.apply(new T().in(B).act(0, Behav.commitFor(salt(0x92), nm("foo"), B)), 1); // B commit (10, tx1) — lower priority
          s.begin(11, 1500);
          s.apply(new T().in(A).act(10, Behav.claim(salt(0x91), nm("foo"))), 0);       // A mints
          s.apply(new T().in(A).act(0, Behav.release(11, new byte[]{ 0x01 })), 1);     // A releases
          s.apply(new T().in(B).act(10, Behav.claim(salt(0x92), nm("foo"))), 2);       // B mints fresh (owns foo)
          emitState("55b_reclaim_by_other", s); }

        // 56: a self-transfer (TRANSFER-all whose target == the current owner) is a real
        // move — it bumps last_set_mutation_height (owner's mut goes 11 → 12), NOT a no-op.
        { S s = minted(0xAA, "bar", 10, 1500);
          s.begin(12, 1600);
          s.apply(new T().in(A).act(0, Behav.transferAll(A)), 0);
          emitState("56_self_transfer_bumps_mut", s); }

        // 57: fee oracle with block_bytes == 0 — the /0 guard substitutes divisor 1 (NOT
        // fee-per-byte 0), so the block still participates. 1000 blocks (== MIN_FEE_SAMPLE),
        // each fee 5000 ⇒ per-byte 5000 ⇒ median 5000 × REF_SIZE 200 = 1_000_000.
        { int n = 1000; long[] cb = new long[n], sub = new long[n], by = new long[n];
          for (int i = 0; i < n; i++) { sub[i] = 1_000_000_000_000L; cb[i] = 1_000_000_005_000L; by[i] = 0; }
          emitU64("57_oracle_zero_bytes", Oracle.rate(cb, sub, by).longValueExact()); }

        // 58: CLAIM burn near 2⁶⁴ at rate = DUST_FLOOR (1) — the lease day-count T overflows
        // 64 bits (computed in bignum) and clamps to MAX_LEASE (365 days):
        // lease_expiry = 1500 + 365·86400.
        { S s = new S();
          s.begin(10, 1000, BigInteger.ONE);
          s.apply(new T().in(A).act(0, Behav.commitFor(salt(0x95), nm("foo"), A)), 0);
          s.begin(11, 1500, BigInteger.ONE);
          s.apply(new T().in(A).act(U64_MAX, Behav.claim(salt(0x95), nm("foo"))), 0);
          emitState("58_lease_clamp_huge_burn", s); }

        System.out.println("combined " + Hex.enc(comb.digest()));
    }

    private Scenario() {}
}
