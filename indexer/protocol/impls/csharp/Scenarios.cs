using System;
using System.Collections.Generic;
using System.Linq;

namespace Pepenet;

/// <summary>
/// Directed conformance vectors — the C# port of impls/c `scenario`. Each builds a
/// deterministic, named construction and emits `name &lt;digest&gt;` (canonical §4 state
/// digest) or `name &lt;u64&gt;`; the rolling `combined` sha256 (raw 32-byte digests /
/// u64 LE) is the single-line cross-language check. These pin the spec's named edge
/// cases (§5) with auditable outcomes, and cover the rare branches the random soak
/// almost never hits (deep displacement, i128 accumulation past 2^64, the fee oracle).
/// </summary>
public static class Scenarios
{
    private const ulong RATE = 28;      // burn == days (impls/c RATE_DAYS)

    private static readonly byte[] A  = B.Id(0xAA);
    private static readonly byte[] Bb = B.Id(0xBB);
    private static readonly byte[] Cc = B.Id(0xCC);

    // impls/c id_of(): ALWAYS a P2PKH input regardless of tag (B.IdType would make
    // 0xBB a P2SH input and fork the seller_type/attribution bytes).
    private static Input In(byte tag, bool sah = true) =>
        new() { H160 = B.Id(tag), Type = K.TYPE_P2PKH, SighashAll = sah };

    private static Tx Tx1(byte tag, params Out[] outs) =>
        new() { Inputs = new List<Input> { In(tag) }, Outputs = outs.ToList() };
    private static Tx Tx2(byte t0, byte t1, params Out[] outs) =>
        new() { Inputs = new List<Input> { In(t0), In(t1) }, Outputs = outs.ToList() };

    private static byte[] Cmt(byte saltByte, string name, byte[] author) =>
        B.Commitment(B.Salt(saltByte), B.Name(name), author);

    /// <summary>Block driver mirroring C's sm_begin_block/sm_apply_tx: pre-block
    /// transitions via an empty ApplyBlock, then txs with EXPLICIT tx indexes.</summary>
    private sealed class S
    {
        public readonly Fold F = new(0);
        private long _h, _mtp;
        public void Begin(long h, long mtp)
        {
            _h = h; _mtp = mtp;
            F.ApplyBlock(new Block { Height = h, Mtp = mtp, Rate = RATE }); // pre-block + scratch clear
        }
        public void Apply(Tx tx, int txIndex) => F.ApplyOneTx(tx, _h, _mtp, RATE, txIndex);
    }

    // Commit `name`(author=tag, salt) at block `ch`, then CLAIM `days` at block `kh`.
    private static void CommitThenClaim(S s, byte tag, string nm, byte saltByte, ulong days,
                                        long cmtp, long ch, long kmtp, long kh)
    {
        s.Begin(ch, cmtp);
        s.Apply(Tx1(tag, Out.Carrier(B.Commit(Cmt(saltByte, nm, B.Id(tag))), 0)), 0);
        s.Begin(kh, kmtp);
        s.Apply(Tx1(tag, Out.Carrier(B.Claim(B.Salt(saltByte), nm), days)), 0);
    }

    // Mint `name` to `tag` with `days` lease, leaving the fold at the claim's block.
    private static S Minted(byte tag, string nm, ulong days, long claimMtp)
    {
        var s = new S();
        CommitThenClaim(s, tag, nm, 0x33, days, claimMtp - 100, 10, claimMtp, 11);
        return s;
    }

    // Mint aaa→A and bbb→B, leaving the fold at height 11.
    private static S TwoNames()
    {
        var s = new S();
        s.Begin(10, 1000);
        s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(Cmt(0x01, "aaa", A)), 0)), 0);
        s.Apply(Tx1(0xBB, Out.Carrier(B.Commit(Cmt(0x02, "bbb", Bb)), 0)), 1);
        s.Begin(11, 1500);
        s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt(0x01), "aaa"), 30)), 0);
        s.Apply(Tx1(0xBB, Out.Carrier(B.Claim(B.Salt(0x02), "bbb"), 30)), 1);
        return s;
    }

    public static int Run()
    {
        var feeds = new List<byte[]>();
        void EmitState(string name, S s)
        {
            byte[] d = Digest.Compute(s.F);
            Console.WriteLine($"{name} {Hashing.Hex(d)}");
            feeds.Add(d);
        }
        void EmitU64(string name, ulong v)
        {
            Console.WriteLine($"{name} {v}");
            feeds.Add(B.U64(v));
        }

        { var s = new S(); EmitState("01_empty", s); }

        { var s = new S(); CommitThenClaim(s, 0xAA, "bob", 0x11, 10, 1000, 10, 1500, 11);
          EmitState("02_commit_claim", s); }

        { var s = new S(); s.Begin(11, 1500);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt(0x11), "bob"), 10)), 0);
          EmitState("03_naked_claim_drop", s); }

        { var s = new S(); s.Begin(11, 1500);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(Cmt(0x11, "bob", A)), 0),
                            Out.Carrier(B.Claim(B.Salt(0x11), "bob"), 10)), 0);
          EmitState("04_shallow_commit_drop", s); }

        // priority: lower commit_height (A@10) wins ownership in BOTH claim orderings. The two
        // digests differ — a transiently-displaced mint leaves an incidental mutation-height bump
        // that depends on tx order — but each is cross-language-exact.
        for (int order = 0; order < 2; order++)
        {
            var s = new S();
            s.Begin(10, 1000); s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(Cmt(0x11, "bob", A)), 0)), 0);
            s.Begin(12, 1100); s.Apply(Tx1(0xBB, Out.Carrier(B.Commit(Cmt(0x22, "bob", Bb)), 0)), 0);
            s.Begin(20, 1200);
            var kA = Tx1(0xAA, Out.Carrier(B.Claim(B.Salt(0x11), "bob"), 10));
            var kB = Tx1(0xBB, Out.Carrier(B.Claim(B.Salt(0x22), "bob"), 10));
            if (order == 0) { s.Apply(kB, 0); s.Apply(kA, 1); } else { s.Apply(kA, 0); s.Apply(kB, 1); }
            EmitState(order == 0 ? "05_priority_b_first" : "06_priority_a_first", s);
        }

        // commitment-copy: B reposts A's commitment bytes, then B claims → drop (author-bound); A claims → owns.
        { var s = new S(); byte[] cm = Cmt(0x33, "bob", A);          // A-bound commitment
          s.Begin(10, 1000);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(cm), 0)), 0);
          s.Apply(Tx1(0xBB, Out.Carrier(B.Commit(cm), 0)), 1);       // B copies the commitment
          s.Begin(11, 1100);
          s.Apply(Tx1(0xBB, Out.Carrier(B.Claim(B.Salt(0x33), "bob"), 10)), 0);  // B can't satisfy → drop
          s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt(0x33), "bob"), 10)), 1);  // A wins
          EmitState("07_commitment_copy", s); }

        { var s = Minted(0xAA, "bob", 10, 1500);  // expiry 865500
          s.Begin(12, 865500);                    // MTP == expiry → lapse (exclusive)
          EmitState("08_lease_lapse", s); }

        { var s = Minted(0xAA, "bob", 10, 1500); s.Begin(12, 1600);
          s.Apply(Tx1(0xAA, Out.Carrier(B.RenewAll(), 5)), 0);
          EmitState("09_renew_stack", s); }

        // water-fill even split: 3 names, renew-all buys 30 name-days → +10 each.
        { var s = new S(); string[] nm = { "a", "b", "c" };
          s.Begin(10, 1000);
          for (int i = 0; i < 3; i++) s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(Cmt((byte)(0x40 + i), nm[i], A)), 0)), i);
          s.Begin(11, 1100);
          for (int i = 0; i < 3; i++) s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt((byte)(0x40 + i)), nm[i]), 1)), i);
          s.Begin(12, 1200);
          s.Apply(Tx1(0xAA, Out.Carrier(B.RenewAll(), 30)), 0);
          EmitState("10_waterfill_even", s); }

        { var s = new S(); CommitThenClaim(s, 0xAA, "bob", 0x11, 100000, 1000, 10, 1500, 11); // huge → caps at 365d
          EmitState("11_waterfill_maxlease", s); }

        { var s = Minted(0xAA, "bob", 10, 1500); s.Begin(12, 1600);
          s.Apply(Tx1(0xAA, Out.Carrier(B.TransferAll(Bb), 0)), 0);
          EmitState("12_transfer_gift", s); }

        { var s = Minted(0xAA, "bob", 10, 1500); s.Begin(12, 1600);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Release(11, new byte[] { 0x01 }), 0)), 0);
          EmitState("13_release", s); }

        { var s = Minted(0xAA, "w", 300, 1500);
          s.Begin(12, 1600); s.Apply(Tx1(0xAA, Out.Carrier(B.Sell(20000, 50000, "w"), 0)), 0);
          s.Begin(13, 1700); s.Apply(Tx1(0xBB, Out.Carrier(B.Reserve("w"), 100), B.Spend(A, K.TYPE_P2PKH, 100)), 0);
          s.Begin(14, 1800); s.Apply(Tx1(0xBB, Out.Carrier(B.Settle("w"), 0), B.Spend(A, K.TYPE_P2PKH, 19800)), 0);
          EmitState("14_market_full", s); }

        { var s = Minted(0xAA, "w", 300, 1500); s.Begin(12, 1600);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Sell(20000, 50000, "w"), 0)), 0);
          s.Begin(13, 1700); s.Apply(Tx1(0xBB, Out.Carrier(B.Reserve("w"), 99), B.Spend(A, K.TYPE_P2PKH, 100)), 0);
          EmitState("15_reserve_burn_short", s); }

        { var s = Minted(0xAA, "w", 300, 1500); s.Begin(12, 1600);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Sell(20000, 50000, "w"), 0)), 0);
          s.Begin(13, 1700);
          s.Apply(Tx1(0xBB, Out.Carrier(B.Reserve("w"), 100),
                            B.Spend(A, K.TYPE_P2PKH, 60), B.Spend(A, K.TYPE_P2PKH, 60)), 0);
          EmitState("16_reserve_pay_summed", s); }

        // reserve near offer end → reserve_expiry clamps to offer_expiry.
        { var s = Minted(0xAA, "w", 300, 1500); s.Begin(12, 1600);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Sell(20000, 0, "w"), 0)), 0);   // window default 18000 → offer_expiry 19600
          s.Begin(13, 5000);
          s.Apply(Tx1(0xBB, Out.Carrier(B.Reserve("w"), 100), B.Spend(A, K.TYPE_P2PKH, 100)), 0); // 5000+18000>19600 → clamp
          EmitState("17_reserve_clamp", s); }

        { var s = Minted(0xAA, "w", 300, 1500); s.Begin(12, 1600);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Sell(2, 0, "w"), 0)), 0);       // below 3·DUST
          EmitState("18_sell_price_floor", s); }

        { var s = Minted(0xAA, "w", 1, 1500); s.Begin(12, 65000);         // short tail
          s.Apply(Tx1(0xAA, Out.Carrier(B.Sell(20000, 0, "w"), 0)), 0);
          EmitState("19_sell_window_overflow", s); }

        { var s = Minted(0xAA, "w", 300, 1500); s.Begin(12, 1600);
          s.Apply(Tx1(0xAA, Out.Carrier(B.SellTo(5000, Bb, "w"), 0)), 0);
          s.Begin(13, 1700);
          s.Apply(Tx1(0xCC, Out.Carrier(B.Pay("w"), 0), B.Spend(A, K.TYPE_P2PKH, 5000)), 0);  // stranger → drop
          s.Apply(Tx1(0xBB, Out.Carrier(B.Pay("w"), 0), B.Spend(A, K.TYPE_P2PKH, 5000)), 1);  // buyer → owns
          EmitState("20_directed_pay", s); }

        // 2^64-1 price: the 128-bit deposit legs must be exact (a 64-bit impl wraps).
        { var s = Minted(0xAA, "w", 300, 1500); s.Begin(12, 1600);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Sell(ulong.MaxValue, 50000, "w"), 0)), 0);
          ulong leg = (ulong)((UInt128)ulong.MaxValue * 50 / 10000);
          s.Begin(13, 1700);
          s.Apply(Tx1(0xBB, Out.Carrier(B.Reserve("w"), leg), B.Spend(A, K.TYPE_P2PKH, leg)), 0);
          EmitState("21_deposit_2pow64", s); }

        // AS attribution: claim attributed to vin[1]=B (matches B's commit).
        { var s = new S(); s.Begin(10, 1000);
          s.Apply(Tx1(0xBB, Out.Carrier(B.Commit(Cmt(0x55, "bob", Bb)), 0)), 0);
          s.Begin(11, 1500);
          s.Apply(Tx2(0xAA, 0xBB, Out.Carrier(B.As(1), 0), Out.Carrier(B.Claim(B.Salt(0x55), "bob"), 10)), 0);
          EmitState("22_as_attribution", s); }

        { var s = new S(); s.Begin(10, 1000);
          s.Apply(Tx1(0xBB, Out.Carrier(B.Commit(Cmt(0x55, "bob", Bb)), 0)), 0);
          s.Begin(11, 1500);
          var t = Tx2(0xAA, 0xBB, Out.Carrier(B.As(1), 0), Out.Carrier(B.Claim(B.Salt(0x55), "bob"), 10));
          t.Inputs[1].SighashAll = false;                                 // AS → ⊥ (not SIGHASH_ALL)
          s.Apply(t, 0);
          EmitState("23_as_oob_drop", s); }

        { var s = TwoNames(); s.Begin(12, 1600);
          s.Apply(Tx2(0xAA, 0xBB, Out.Carrier(B.Trade(0, 1, "aaa", "bbb"), 0)), 0);
          EmitState("24_trade_swap", s); }

        { var s = TwoNames(); s.Begin(12, 1600);
          s.Apply(Tx1(0xAA, Out.Carrier(B.TransferAll(Cc), 0)), 0);                 // aaa→C before the trade
          s.Apply(Tx2(0xAA, 0xBB, Out.Carrier(B.Trade(0, 1, "aaa", "bbb"), 0)), 1); // anti-rug → drop
          EmitState("25_trade_rug_before", s); }

        // fee oracle (§3.4): signed under-claim clamp + participant filter + MIN_FEE_SAMPLE
        // degrade + lower-median + REF_SIZE scale + clamp. 4 participants < MIN_FEE_SAMPLE
        // ⇒ this small window now degrades to DUST_FLOOR (the big-window vectors are 49–51).
        { var cb = new ulong[] { 1_000_000_200_000, 1_000_000_400_000, 999_999_999_950, 1_000_001_000_000, 1_000_000_600_000 }; // 3rd under-claims
          var by = new ulong[] { 1000, 1000, 1000, 1000, 1000 };
          EmitU64("29_oracle_rate", Oracle.Rate(cb, by)); }               // |P|=4 < 1000 → DUST_FLOOR = 1
        { EmitU64("30_oracle_floor", Oracle.Rate(new ulong[] { 0, 0, 0 }, new ulong[] { 1000, 1000, 1000 })); } // all under-claim → floor
        { var ts = new long[] { 100, 50, 200, 30, 150, 80, 220, 10, 175, 60, 190 };
          EmitU64("31_mtp_median", (ulong)Oracle.Mtp(ts, 11)); }          // median of 11

        // ── water-fill rare branches ──
        // 32: T < count — burn buys fewer name-days than names; the first T names
        // (ascending-lex) get +1 day, the rest none (§3.5 floor).
        { var s = new S(); string[] nm = { "a", "b", "c" };
          s.Begin(10, 1000);
          for (int i = 0; i < 3; i++) s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(Cmt((byte)(0x50 + i), nm[i], A)), 0)), i);
          s.Begin(11, 1100);
          for (int i = 0; i < 3; i++) s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt((byte)(0x50 + i)), nm[i]), 1)), i);
          s.Begin(12, 1200);
          s.Apply(Tx1(0xAA, Out.Carrier(B.RenewAll(), 2)), 0);            // T=2 over 3 → a,b +1d, c none
          EmitState("32_waterfill_floor", s); }

        // 33: every targeted name hits MAX_LEASE with T still remaining → surplus forfeited.
        { var s = new S(); string[] nm = { "a", "b" };
          s.Begin(10, 1000);
          for (int i = 0; i < 2; i++) s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(Cmt((byte)(0x60 + i), nm[i], A)), 0)), i);
          s.Begin(11, 1100);
          for (int i = 0; i < 2; i++) s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt((byte)(0x60 + i)), nm[i]), 360)), i); // ~360d each
          s.Begin(12, 1100);
          s.Apply(Tx1(0xAA, Out.Carrier(B.RenewAll(), 100000)), 0);       // huge → both cap @MAX_LEASE, forfeit
          EmitState("33_waterfill_allcap_forfeit", s); }

        // ── reorg edge cases as deterministic vectors ──
        // 34: a same-block lapse-and-reclaim. (a) bob lapses at MTP==expiry, B reclaims → B owns.
        //     (b) the reorg restores A's earlier RENEW, so bob never lapses and B's reclaim drops.
        { var s = Minted(0xAA, "bob", 10, 1500);                          // expiry 865500
          s.Begin(12, 860000);
          s.Apply(Tx1(0xBB, Out.Carrier(B.Commit(Cmt(0x44, "bob", Bb)), 0)), 0);
          s.Begin(13, 865500);
          s.Apply(Tx1(0xBB, Out.Carrier(B.Claim(B.Salt(0x44), "bob"), 10)), 0);  // lapse then B mints
          EmitState("34a_reorg_lapse_reclaim", s); }
        { var s = Minted(0xAA, "bob", 10, 1500);
          s.Begin(12, 860000);
          s.Apply(Tx1(0xBB, Out.Carrier(B.Commit(Cmt(0x44, "bob", Bb)), 0)), 0);
          s.Apply(Tx1(0xAA, Out.Carrier(B.RenewAll(), 10)), 1);           // A renews → bob survives past 865500
          s.Begin(13, 865500);
          s.Apply(Tx1(0xBB, Out.Carrier(B.Claim(B.Salt(0x44), "bob"), 10)), 0);  // bob owned → drop
          EmitState("34b_reorg_renew_blocks_reclaim", s); }

        // 35: a SETTLE un-confirmed by a reorg. (a) the reserve lapses without a settle →
        //     the listing reverts to the seller; (b) the settle confirms → buyer owns.
        { var s = Minted(0xAA, "w", 300, 1500);
          s.Begin(12, 1600); s.Apply(Tx1(0xAA, Out.Carrier(B.Sell(20000, 50000, "w"), 0)), 0);
          s.Begin(13, 1700); s.Apply(Tx1(0xBB, Out.Carrier(B.Reserve("w"), 100), B.Spend(A, K.TYPE_P2PKH, 100)), 0);
          s.Begin(14, 20000);                          // MTP past reserve_expiry (19700) → revert to listing
          EmitState("35a_settle_dropped_relisted", s); }
        { var s = Minted(0xAA, "w", 300, 1500);
          s.Begin(12, 1600); s.Apply(Tx1(0xAA, Out.Carrier(B.Sell(20000, 50000, "w"), 0)), 0);
          s.Begin(13, 1700); s.Apply(Tx1(0xBB, Out.Carrier(B.Reserve("w"), 100), B.Spend(A, K.TYPE_P2PKH, 100)), 0);
          s.Begin(14, 1800); s.Apply(Tx1(0xBB, Out.Carrier(B.Settle("w"), 0), B.Spend(A, K.TYPE_P2PKH, 19800)), 0);
          EmitState("35b_settle_confirmed", s); }

        // 36: an MTP boundary call that flips under a one-tick reorg. lease_expiry is an
        //     EXCLUSIVE bound: MTP == expiry−1 stays owned; MTP == expiry lapses.
        { var s = Minted(0xAA, "bob", 10, 1500); s.Begin(12, 865499); EmitState("36a_mtp_below_owned", s); }
        { var s = Minted(0xAA, "bob", 10, 1500); s.Begin(12, 865500); EmitState("36b_mtp_at_lapsed", s); }

        // ── pre-block ordering & intra-block market races ──
        // 38: a same-block RENEW-vs-CLAIM race at the exact lapse tie. The pre-block lapse
        //     returns `bob` to the pool BEFORE any tx runs, so A's renew-all renews only `keep`
        //     and the hunter B's CLAIM (commit ≥1 block deep) mints `bob`.
        { var s = new S();
          s.Begin(10, 1000);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(Cmt(0x33, "bob", A)), 0)), 0);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(Cmt(0x34, "keep", A)), 0)), 1);
          s.Begin(11, 1500);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt(0x33), "bob"), 10)), 0);   // bob expiry 865500
          s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt(0x34), "keep"), 300)), 1); // keep long-lived
          s.Begin(12, 860000);
          s.Apply(Tx1(0xBB, Out.Carrier(B.Commit(Cmt(0x44, "bob", Bb)), 0)), 0);  // hunter commits
          s.Begin(13, 865500);                         // MTP == bob's expiry → bob lapses pre-block
          s.Apply(Tx1(0xAA, Out.Carrier(B.RenewAll(), 5)), 0);                    // renews `keep` only
          s.Apply(Tx1(0xBB, Out.Carrier(B.Claim(B.Salt(0x44), "bob"), 10)), 1);   // hunter mints bob
          EmitState("38_lapse_renew_vs_claim", s); }

        // 39: a single pre-block tick that crosses reserve_expiry AND offer_expiry at once,
        //     cascading RESERVED→LISTED→OWNED in one pass (§5 type-order reserve→offer→lease).
        { var s = Minted(0xAA, "w", 300, 1500);                           // lease_expiry = 25,921,500
          s.Begin(12, 1600); s.Apply(Tx1(0xAA, Out.Carrier(B.Sell(20000, 50000, "w"), 0)), 0);   // offer_expiry = 51600
          s.Begin(13, 1700); s.Apply(Tx1(0xBB, Out.Carrier(B.Reserve("w"), 100), B.Spend(A, K.TYPE_P2PKH, 100)), 0); // reserve_expiry = 19700 < 51600
          s.Begin(14, 51600);                          // MTP == offer_expiry, > reserve_expiry → both legs fire
          EmitState("39_preblock_reserve_offer_collapse", s); }

        // 40: intra-block RESERVE option theft. The first buyer (chain-order) wins the exclusive
        //     option; the second drops (no overwrite), so its later SETTLE fails the buyer-match.
        { var s = Minted(0xAA, "w", 300, 1500);
          s.Begin(12, 1600); s.Apply(Tx1(0xAA, Out.Carrier(B.Sell(20000, 50000, "w"), 0)), 0);
          s.Begin(13, 1700);
          s.Apply(Tx1(0xBB, Out.Carrier(B.Reserve("w"), 100), B.Spend(A, K.TYPE_P2PKH, 100)), 0);   // B wins the option
          s.Apply(Tx1(0xCC, Out.Carrier(B.Reserve("w"), 100), B.Spend(A, K.TYPE_P2PKH, 100)), 1);   // C loses (row RESERVED) → drop
          s.Apply(Tx1(0xCC, Out.Carrier(B.Settle("w"), 0), B.Spend(A, K.TYPE_P2PKH, 19800)), 2);    // C settles → buyer-mismatch → drop
          EmitState("40_reserve_option_theft", s); }

        // 41: value-collision in spendable-output matching. One tx does RESERVE(x)+SETTLE(y),
        //     both paying seller A, with two outputs to A: 19800 (settle remainder) first and
        //     5 (reserve pay-leg) second. The consume-once, exact-value, vout-order matcher must
        //     let RESERVE skip the larger output and take 5, then SETTLE take 19800.
        { var s = new S();
          s.Begin(10, 1000);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(Cmt(0x71, "x", A)), 0)), 0);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(Cmt(0x72, "y", A)), 0)), 1);
          s.Begin(11, 1500);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt(0x71), "x"), 300)), 0);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt(0x72), "y"), 300)), 1);
          s.Begin(12, 1600);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Sell(1000, 50000, "x"), 0)), 0);   // pay_leg(x) = 5
          s.Apply(Tx1(0xAA, Out.Carrier(B.Sell(20000, 50000, "y"), 0)), 1);  // remainder(y) = 19800
          s.Begin(13, 1700);
          s.Apply(Tx1(0xBB, Out.Carrier(B.Reserve("y"), 100), B.Spend(A, K.TYPE_P2PKH, 100)), 0);  // B reserves y
          s.Begin(14, 1800);
          s.Apply(Tx1(0xBB, Out.Carrier(B.Reserve("x"), 5),               // car_value 5 ≥ burn_leg(x)=5
                            Out.Carrier(B.Settle("y"), 0),
                            B.Spend(A, K.TYPE_P2PKH, 19800),              // lower vout = settle remainder
                            B.Spend(A, K.TYPE_P2PKH, 5)), 0);             // higher vout = reserve pay-leg
          EmitState("41_vout_value_collision", s); }

        // ── priority tie-break + Tier-4 coverage (audit follow-ups) ──
        // 42: CLAIM priority tie-break is the COMMIT's tx_index (§3.2 tuple), NOT claim chain order.
        { var s = new S();
          s.Begin(10, 1000);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(Cmt(0x81, "bob", A)), 0)), 5);
          s.Apply(Tx1(0xBB, Out.Carrier(B.Commit(Cmt(0x82, "bob", Bb)), 0)), 2);
          s.Begin(20, 1500);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt(0x81), "bob"), 10)), 0);  // applied first
          s.Apply(Tx1(0xBB, Out.Carrier(B.Claim(B.Salt(0x82), "bob"), 10)), 1);  // lower commit tx_index → wins
          EmitState("42_claim_commit_txindex_tiebreak", s); }

        // 43: escrow movement-lock (§3.7 headline) — a LISTED name rejects every move:
        //     TRANSFER, RELEASE, re-SELL, and SELL_TO all no-op while it sits on the market.
        { var s = Minted(0xAA, "w", 300, 1500);
          s.Begin(12, 1600); s.Apply(Tx1(0xAA, Out.Carrier(B.Sell(20000, 50000, "w"), 0)), 0);
          s.Begin(13, 1700);
          s.Apply(Tx1(0xAA, Out.Carrier(B.TransferAll(Bb), 0)), 0);                        // gift → locked, skip
          s.Apply(Tx1(0xAA, Out.Carrier(B.Release(11, new byte[] { 0x01 }), 0)), 1);       // release → locked, skip
          s.Apply(Tx1(0xAA, Out.Carrier(B.Sell(30000, 50000, "w"), 0)), 2);                // re-SELL → not OWNED, reject
          s.Apply(Tx1(0xAA, Out.Carrier(B.SellTo(5000, Bb, "w"), 0)), 3);                  // SELL_TO → not OWNED, reject
          EmitState("43_escrow_movement_lock", s); }

        // 44: anchor-guard reject (§3.5) — a bitmap op whose anchor is OLDER than the owner's
        //     last set-mutation is dropped (stale set-view could select the wrong names).
        { var s = new S();
          s.Begin(10, 1000);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(Cmt(0x91, "a", A)), 0)), 0);
          s.Begin(11, 1500);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt(0x91), "a"), 30)), 0);              // lm(A)=11
          s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(Cmt(0x92, "b", A)), 0)), 1);
          s.Begin(12, 1600);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt(0x92), "b"), 30)), 0);              // lm(A)=12 (set grew)
          s.Begin(13, 1700);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Release(11, new byte[] { 0x01 }), 0)), 0);       // anchor 11 < lm 12 → reject
          EmitState("44_anchor_guard_reject", s); }

        // 45: COMMIT_EXPIRY prune — a commit older than COMMIT_EXPIRY (18000s) is pruned pre-block,
        //     so a later matching claim finds no live commit and drops (§3.2).
        { var s = new S();
          s.Begin(10, 1000);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(Cmt(0x33, "bob", A)), 0)), 0);
          s.Begin(11, 19001);                                                              // 19001 > 1000 + 18000 → prune
          s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt(0x33), "bob"), 10)), 0);            // no live commit → drop
          EmitState("45_commit_expiry_prune", s); }

        // 46: RESERVE burn leg is an inequality (car_value ≥ burn_leg), not exact — an OVER-funded
        //     burn (car_value 150 > burn_leg 100) still wins the option (cf. 15: 99 < 100 drops).
        { var s = Minted(0xAA, "w", 300, 1500); s.Begin(12, 1600);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Sell(20000, 50000, "w"), 0)), 0);
          s.Begin(13, 1700);
          s.Apply(Tx1(0xBB, Out.Carrier(B.Reserve("w"), 150), B.Spend(A, K.TYPE_P2PKH, 100)), 0);
          EmitState("46_reserve_overfunded_burn", s); }

        // 47: TRADE malformed drops — OOB index, idxA==idxB (one party), and nameA==nameB are
        //     each fail-closed; the two-name state is left untouched (§3.10).
        { var s = TwoNames();
          s.Begin(12, 1600);
          s.Apply(Tx2(0xAA, 0xBB, Out.Carrier(B.Trade(0, 5, "aaa", "bbb"), 0)), 0);  // idx_b OOB → drop
          s.Apply(Tx2(0xAA, 0xBB, Out.Carrier(B.Trade(0, 0, "aaa", "bbb"), 0)), 1);  // idxA==idxB → drop
          s.Apply(Tx2(0xAA, 0xBB, Out.Carrier(B.Trade(0, 1, "aaa", "aaa"), 0)), 2);  // nameA==nameB → drop
          EmitState("47_trade_malformed_drops", s); }

        // 48: selective TRANSFER (anchor+flags) gifts a SUBSET — bits {0,2} of A's sorted set
        //     {a,b,c} move to B; b stays with A. Exercises the bitmap-selected positive transfer.
        { var s = new S();
          s.Begin(10, 1000);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(Cmt(0xA1, "a", A)), 0)), 0);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(Cmt(0xA2, "b", A)), 0)), 1);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(Cmt(0xA3, "c", A)), 0)), 2);
          s.Begin(11, 1500);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt(0xA1), "a"), 30)), 0);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt(0xA2), "b"), 30)), 1);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt(0xA3), "c"), 30)), 2);
          s.Begin(12, 1600);
          s.Apply(Tx1(0xAA, Out.Carrier(B.TransferSel(Bb, 11, new byte[] { 0x05 }), 0)), 0); // bits 0 and 2 → a, c
          EmitState("48_transfer_selective", s); }

        // ── §3.4 participant-median oracle (fee-bearing filter + MIN_FEE_SAMPLE) ──
        // 49: |P| = 1000 EXACTLY (inclusive boundary) and EVEN, with an under-claim block
        //     inside the window: lower median = index (1000−1)/2 = 499 of the sorted
        //     100..1099 → 599 → rate 119,800.
        { var cb = new ulong[1500]; var by = new ulong[1500];
          for (int i = 0; i < 1500; i++)
          {
              by[i] = 1000;
              cb[i] = i < 499 ? K.SUBSIDY_KOINU                                    // zero-fee → non-participant
                    : i == 499 ? K.SUBSIDY_KOINU - 50                              // under-claim → non-participant
                    : K.SUBSIDY_KOINU + (ulong)(100 + (i - 500)) * 1000;           // fpb 100..1099
          }
          EmitU64("49_oracle_even_boundary", Oracle.Rate(cb, by)); }               // → 119800

        // 50: odd |P| = 1101 through the participant filter — the historical middle rule:
        //     index 550 of the sorted 100..1200 → 650 → rate 130,000.
        { var cb = new ulong[2000]; var by = new ulong[2000];
          for (int i = 0; i < 2000; i++)
          {
              by[i] = 1000;
              cb[i] = i < 899 ? K.SUBSIDY_KOINU
                    : K.SUBSIDY_KOINU + (ulong)(100 + (i - 899)) * 1000;           // fpb 100..1200
          }
          EmitU64("50_oracle_odd_median", Oracle.Rate(cb, by)); }                  // → 130000

        // 51: |P| = 999 — one short of MIN_FEE_SAMPLE → degrade to DUST_FLOOR exactly.
        { var cb = new ulong[1500]; var by = new ulong[1500];
          for (int i = 0; i < 1500; i++)
          {
              by[i] = 1000;
              cb[i] = i < 501 ? K.SUBSIDY_KOINU
                    : K.SUBSIDY_KOINU + (ulong)(100 + (i - 501)) * 1000;           // 999 participants
          }
          EmitU64("51_oracle_subsample_floor", Oracle.Rate(cb, by)); }             // → 1

        // 52: charset = a DNS label [a-z0-9-], 1..32: hyphen and a 32-byte name MINT;
        // '.' and '_' DROP (uppercase still drops), leaving exactly the two valid names.
        { var s = new S();
          CommitThenClaim(s, 0xAA, "shib-p2p",                         0x71, 10, 1000, 10, 1500, 11);
          CommitThenClaim(s, 0xAA, "abcdefghijklmnopqrstuvwxyz0123ab", 0x72, 10, 2000, 12, 2500, 13);
          CommitThenClaim(s, 0xAA, "shib.p2p",                         0x73, 10, 3000, 14, 3500, 15);
          CommitThenClaim(s, 0xAA, "shib_p2p",                         0x74, 10, 4000, 16, 4500, 17);
          EmitState("52_charset", s); }

        // 52b: structural name rejects — leading/trailing hyphen and xn-- ACE drop.
        { var s = new S();
          CommitThenClaim(s, 0xAA, "-lead", 0x81, 10, 1000, 10, 1500, 11);
          CommitThenClaim(s, 0xAA, "trail-", 0x82, 10, 2000, 12, 2500, 13);
          CommitThenClaim(s, 0xAA, "xn--x",  0x83, 10, 3000, 14, 3500, 15);
          CommitThenClaim(s, 0xAA, "ok-name",0x84, 10, 4000, 16, 4500, 17);
          EmitState("52b_structural", s); }

        // 54: NO per-tx count cap (§0). One tx carries 17 COMMIT carriers past the
        // historical 16; all fold. An impl that caps at 16 → a different commit count.
        { var s = new S();
          s.Begin(10, 1000);
          var outs = new List<Out>();
          for (int i = 0; i < 17; i++)
          {
              var cmt = new byte[32]; cmt[0] = (byte)i;
              outs.Add(Out.Carrier(B.Commit(cmt), 0));
          }
          for (int i = 0; i < 17; i++) outs.Add(B.Spend(A, K.TYPE_P2PKH, 1));
          s.Apply(Tx1(0xAA, outs.ToArray()), 0);
          EmitState("54_no_txcap", s); }

        // 55: a name minted then RELEASEd earlier in the SAME block re-mints fresh on a
        // later CLAIM in that block (§3.6 "immediately reclaimable"; row existence is
        // authoritative, the block-local claim scratch never blocks a re-mint).
        { var s = new S();
          s.Begin(10, 1000);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(Cmt(0x91, "foo", A)), 0)), 0);
          s.Begin(11, 1500);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt(0x91), "foo"), 10)), 0);              // mint foo→A (A mut=11)
          s.Apply(Tx1(0xAA, Out.Carrier(B.Release(11, new byte[] { 0x01 }), 0)), 1);         // release (row gone, scratch lingers)
          s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt(0x91), "foo"), 10)), 2);              // MUST re-mint foo→A
          EmitState("55_claim_release_reclaim_sameblock", s); }

        // 55b: same, but the re-claim is by a DIFFERENT party B whose backing commit has
        // LOWER priority than the departed A's — B still mints fresh (a released name's
        // former owner priority is irrelevant once the row is gone).
        { var s = new S();
          s.Begin(10, 1000);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Commit(Cmt(0x91, "foo", A)), 0)), 0);              // A commit (10, tx0) — higher priority
          s.Apply(Tx1(0xBB, Out.Carrier(B.Commit(Cmt(0x92, "foo", Bb)), 0)), 1);             // B commit (10, tx1) — lower priority
          s.Begin(11, 1500);
          s.Apply(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt(0x91), "foo"), 10)), 0);              // A mints
          s.Apply(Tx1(0xAA, Out.Carrier(B.Release(11, new byte[] { 0x01 }), 0)), 1);         // A releases
          s.Apply(Tx1(0xBB, Out.Carrier(B.Claim(B.Salt(0x92), "foo"), 10)), 2);              // B mints fresh (owns foo)
          EmitState("55b_reclaim_by_other", s); }

        // 56: a self-transfer (TRANSFER-all whose target == the current owner) is a real
        // move — it bumps last_set_mutation_height (owner's mut goes 11 → 12), NOT a no-op.
        { var s = Minted(0xAA, "bar", 10, 1500);
          s.Begin(12, 1600);
          s.Apply(Tx1(0xAA, Out.Carrier(B.TransferAll(A), 0)), 0);
          EmitState("56_self_transfer_bumps_mut", s); }

        // 57: fee oracle with block_bytes == 0 — the /0 guard substitutes divisor 1 (NOT
        // fee-per-byte 0), so the block still participates. 1000 blocks (== MIN_FEE_SAMPLE),
        // each fee 5000 ⇒ per-byte 5000 ⇒ median 5000 × REF_SIZE 200 = 1_000_000.
        { var cb = new ulong[1000]; var by = new ulong[1000];
          for (int i = 0; i < 1000; i++) { cb[i] = K.SUBSIDY_KOINU + 5000; by[i] = 0; }
          EmitU64("57_oracle_zero_bytes", Oracle.Rate(cb, by)); }                            // → 1000000

        // 58: CLAIM burn near 2⁶⁴ at rate = DUST_FLOOR (1) — the lease day-count T overflows
        // 64 bits (computed in 128-bit) and clamps to MAX_LEASE (365 days).
        { var f = new Fold(0);
          f.ApplyBlock(new Block { Height = 10, Mtp = 1000, Rate = 1 });
          f.ApplyOneTx(Tx1(0xAA, Out.Carrier(B.Commit(Cmt(0x95, "foo", A)), 0)), 10, 1000, 1, 0);
          f.ApplyBlock(new Block { Height = 11, Mtp = 1500, Rate = 1 });
          f.ApplyOneTx(Tx1(0xAA, Out.Carrier(B.Claim(B.Salt(0x95), "foo"), ulong.MaxValue)), 11, 1500, 1, 0);
          byte[] d58 = Digest.Compute(f);
          Console.WriteLine($"58_lease_clamp_huge_burn {Hashing.Hex(d58)}");
          feeds.Add(d58); }

        Console.WriteLine($"combined {Hashing.Hex(Hashing.Sha256(B.Concat(feeds.ToArray())))}");
        return 0;
    }
}

