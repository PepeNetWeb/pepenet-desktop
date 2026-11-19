using System;
using System.Collections.Generic;
using System.Linq;

namespace Pepenet;

public static class SelfTest
{
    private static int _pass, _fail;
    private static readonly List<string> _failures = new();

    private static void Check(string name, bool ok)
    {
        if (ok) _pass++;
        else { _fail++; _failures.Add(name); }
    }

    public static int Run()
    {
        _pass = 0; _fail = 0; _failures.Clear();

        Primitives();
        Decoder_();
        WaterFillUnits();
        CommitClaim();
        Priority();
        Lapse();
        TransferRelease();
        OpenMarket();
        ValueCollision();
        Directed();
        Trade();
        DottedNames();
        OracleTests();
        MtpTests();
        Attrib();
        AttribA7();
        Secp();
        Ecmh_();

        Console.WriteLine($"selftest: {_pass} passed, {_fail} failed");
        foreach (var f in _failures) Console.WriteLine($"  FAIL: {f}");

        // empty-state anchors (cross-impl pinned).
        Console.WriteLine($"empty_state_digest={Digest.ComputeHex(new Fold())}");
        Console.WriteLine($"empty_state_ecmh={StateEcmh.ComputeHex(new Fold())}");
        return _fail == 0 ? 0 : 1;
    }

    // ---- helpers ----
    private static byte[]? Owner(Fold f, string name) =>
        f.Names.TryGetValue(name, out var r) ? r.Owner : null;
    private static bool OwnedBy(Fold f, string name, int id) =>
        Owner(f, name) is { } o && o.SequenceEqual(B.Id(id));

    private static Tx Tx(IEnumerable<Input> ins, IEnumerable<Out> outs)
        => new() { Inputs = ins.ToList(), Outputs = outs.ToList() };

    private static Block Blk(long h, long mtp, ulong rate, params Tx[] txs)
        => new() { Height = h, Mtp = mtp, Rate = rate, Txs = txs.ToList() };

    // ---- primitives ----
    private static void Primitives()
    {
        var rng = new SplitMix64(0);
        Check("prng-kat", rng.Next() == 0xE220A8397B1DCDAFUL);

        Check("ripemd-empty", Hashing.Hex(Ripemd160.Hash(Array.Empty<byte>())) == "9c1185a5c5e9fc54612808977ee8f548b2258d31");
        Check("ripemd-abc", Hashing.Hex(Ripemd160.Hash(System.Text.Encoding.ASCII.GetBytes("abc"))) == "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
        Check("hash160-abc", Hashing.Hex(Hashing.Hash160(System.Text.Encoding.ASCII.GetBytes("abc"))).StartsWith("bb1be98c"));
    }

    // ---- decoder (names-only: ACTION | IGNORE) ----
    private static void Decoder_()
    {
        // bare UTF-8 (value>0) → IGNORE (no text-post demux)
        Check("dec-bare-utf8-ignore", Decoder.Decode(System.Text.Encoding.ASCII.GetBytes("hello"), 1).Kind == DecodeKind.Ignore);
        // zero-value bare → ignore
        Check("dec-bare-zero-ignore", Decoder.Decode(System.Text.Encoding.ASCII.GetBytes("hello"), 0).Kind == DecodeKind.Ignore);
        // overlay-band opcode → ignore
        Check("dec-overlay-ignore", Decoder.Decode(new byte[] { 0xFF, 0x50, 0x4E, 0xD6, 0x00 }, 0).Kind == DecodeKind.Ignore);
        // opcode 0x00 / 0x10 → ignore
        Check("dec-op00-ignore", Decoder.Decode(new byte[] { 0xFF, 0x50, 0x4E, 0x00 }, 1).Kind == DecodeKind.Ignore);
        Check("dec-op10-ignore", Decoder.Decode(new byte[] { 0xFF, 0x50, 0x4E, 0x10 }, 1).Kind == DecodeKind.Ignore);
        // valid COMMIT
        Check("dec-commit", Decoder.Decode(B.Commit(new byte[32]), 0).Kind == DecodeKind.Action);
        // short COMMIT → ignore
        Check("dec-commit-short", Decoder.Decode(B.Payload(K.OP_COMMIT, new byte[31]), 0).Kind == DecodeKind.Ignore);
        // uppercase name in CLAIM rejected (no fold)
        var badClaim = B.Payload(K.OP_CLAIM, B.Concat(B.Salt(1), B.Name("Alice")));
        Check("dec-claim-upper", Decoder.Decode(badClaim, 1).Kind == DecodeKind.Ignore);
        // structural name rejects
        Check("dec-claim-lead-hyphen", Decoder.Decode(B.Claim(B.Salt(1), "-a"), 1).Kind == DecodeKind.Ignore);
        Check("dec-claim-trail-hyphen", Decoder.Decode(B.Claim(B.Salt(1), "a-"), 1).Kind == DecodeKind.Ignore);
        Check("dec-claim-ace", Decoder.Decode(B.Claim(B.Salt(1), "xn--x"), 1).Kind == DecodeKind.Ignore);
        // TRADE exactly one comma
        Check("dec-trade-ok", Decoder.Decode(B.Trade(0, 1, "a", "b"), 0).Kind == DecodeKind.Action);
        var twoComma = B.Payload(K.OP_TRADE, B.Concat(new byte[] { 0, 1 }, B.Name("a"), new byte[] { 0x2C }, B.Name("b"), new byte[] { 0x2C }, B.Name("c")));
        Check("dec-trade-twocomma", Decoder.Decode(twoComma, 0).Kind == DecodeKind.Ignore);
        // RENEW length bands
        Check("dec-renew-all", Decoder.Decode(B.RenewAll(), 0).Kind == DecodeKind.Action);
        Check("dec-renew-bl1-invalid", Decoder.Decode(B.Payload(K.OP_RENEW, new byte[1]), 0).Kind == DecodeKind.Ignore);
        Check("dec-renew-safe", Decoder.Decode(B.RenewAllSafe(0), 0).Kind == DecodeKind.Action);

        // §6 pinned carrier ceiling: flags at the exact consensus caps decode;
        // one byte past the ceiling is IGNORE (fail-closed).
        var wide = B.Payload(K.OP_RENEW, new byte[5 + K.FLAGS_MAX]);
        Check("dec-renew-at-carrier-max", wide.Length == K.CARRIER_MAX
              && Decoder.Decode(wide, 0).Kind == DecodeKind.Action);
        Check("dec-renew-past-ceiling", Decoder.Decode(B.Payload(K.OP_RENEW, new byte[5 + K.FLAGS_MAX + 1]), 0).Kind == DecodeKind.Ignore);
        Check("dec-transfer-at-xfer-max", Decoder.Decode(B.Payload(K.OP_TRANSFER, new byte[25 + K.FLAGS_XFER_MAX]), 0).Kind == DecodeKind.Action);
        Check("dec-transfer-past-ceiling", Decoder.Decode(B.Payload(K.OP_TRANSFER, new byte[25 + K.FLAGS_XFER_MAX + 1]), 0).Kind == DecodeKind.Ignore);
        Check("dec-release-at-flags-max", Decoder.Decode(B.Payload(K.OP_RELEASE, new byte[5 + K.FLAGS_MAX]), 0).Kind == DecodeKind.Action);
    }

    // ---- water-fill units ----
    private static void WaterFillUnits()
    {
        Check("wf-single-50", Lease.WaterFill(50, new long[] { 365 })[0] == 50);
        var u = Lease.WaterFill(3, new long[] { 365, 365, 365, 365, 365 });
        Check("wf-underfund", u[0] == 1 && u[1] == 1 && u[2] == 1 && u[3] == 0 && u[4] == 0);
        var c = Lease.WaterFill(12, new long[] { 2, 2, 365, 365, 365 });
        Check("wf-cap-redistribute", c[0] == 2 && c[1] == 2 && c[2] == 3 && c[3] == 3 && c[4] == 2);
        var allcap = Lease.WaterFill(1000, new long[] { 2, 3 });
        Check("wf-allcap-forfeit", allcap[0] == 2 && allcap[1] == 3);
        var withzero = Lease.WaterFill(50, new long[] { 0, 365 }); // h=0 skipped, one eligible takes 50
        Check("wf-skip-zero-headroom", withzero[0] == 0 && withzero[1] == 50);
    }

    // ---- commit/claim ----
    private static void CommitClaim()
    {
        // happy path
        var f = new Fold();
        byte[] salt = B.Salt(7);
        byte[] cmt = B.Commitment(salt, B.Name("alice"), B.Id(0));
        f.ApplyBlock(Blk(0, 1000, 28, Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Commit(cmt), 0) })));
        f.ApplyBlock(Blk(1, 2000, 28, Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Claim(salt, "alice"), 30) })));
        Check("claim-happy", OwnedBy(f, "alice", 0));
        Check("claim-lease", f.Names["alice"].LeaseExpiry == 2000 + 30 * K.BILLING_UNIT);

        // naked claim (no commit) → dropped
        var f2 = new Fold();
        f2.ApplyBlock(Blk(1, 2000, 28, Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Claim(salt, "alice"), 30) })));
        Check("claim-naked-drop", !f2.Names.ContainsKey("alice"));

        // same-block commit too shallow → dropped
        var f3 = new Fold();
        f3.ApplyBlock(Blk(0, 1000, 28,
            Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Commit(cmt), 0) }),
            Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Claim(salt, "alice"), 30) })));
        Check("claim-same-block-shallow", !f3.Names.ContainsKey("alice"));

        // commitment-copy: attacker re-posts victim's commitment; only victim can claim
        var fc = new Fold();
        byte[] vsalt = B.Salt(9);
        byte[] vcmt = B.Commitment(vsalt, B.Name("vic"), B.Id(0)); // bound to Id0
        // attacker (Id1) re-posts the same commitment bytes
        fc.ApplyBlock(Blk(0, 1000, 28, Tx(new[] { B.In(1) }, new[] { Out.Carrier(B.Commit(vcmt), 0) })));
        // attacker tries to claim with the same salt — author term (Id1) differs → recomputed commitment won't match
        fc.ApplyBlock(Blk(1, 2000, 28, Tx(new[] { B.In(1) }, new[] { Out.Carrier(B.Claim(vsalt, "vic"), 30) })));
        Check("commit-copy-inert", !fc.Names.ContainsKey("vic"));

        // COMMIT_EXPIRY prune: claim after the inclusive window expires → drop
        var fe = new Fold();
        fe.ApplyBlock(Blk(0, 1000, 28, Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Commit(cmt), 0) })));
        // mtp 1000 + 18000 = 19000 is the last live; 19001 prunes
        fe.ApplyBlock(Blk(1, 19001, 28, Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Claim(salt, "alice"), 30) })));
        Check("commit-expiry-prune", !fe.Names.ContainsKey("alice"));
    }

    // ---- priority tie-break on commit tx_index ----
    private static void Priority()
    {
        var f = new Fold();
        byte[] s1 = B.Salt(1), s2 = B.Salt(2);
        byte[] c1 = B.Commitment(s1, B.Name("bob"), B.Id(1)); // committer Id1, tx0
        byte[] c2 = B.Commitment(s2, B.Name("bob"), B.Id(2)); // committer Id2, tx1
        f.ApplyBlock(Blk(0, 1000, 28,
            Tx(new[] { B.In(1) }, new[] { Out.Carrier(B.Commit(c1), 0) }),   // commit tx_index 0
            Tx(new[] { B.In(2) }, new[] { Out.Carrier(B.Commit(c2), 0) }))); // commit tx_index 1
        // both claim in block1; Id2 (higher commit tx) claims FIRST, Id1 (lower) claims SECOND and must displace
        f.ApplyBlock(Blk(1, 2000, 28,
            Tx(new[] { B.In(2) }, new[] { Out.Carrier(B.Claim(s2, "bob"), 30) }),
            Tx(new[] { B.In(1) }, new[] { Out.Carrier(B.Claim(s1, "bob"), 30) })));
        Check("priority-commit-txindex", OwnedBy(f, "bob", 1));
    }

    // ---- lapse ----
    private static void Lapse()
    {
        var f = new Fold();
        byte[] salt = B.Salt(3);
        byte[] cmt = B.Commitment(salt, B.Name("temp"), B.Id(0));
        f.ApplyBlock(Blk(0, 1000, 28, Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Commit(cmt), 0) })));
        f.ApplyBlock(Blk(1, 2000, 28, Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Claim(salt, "temp"), 1) }))); // 1 day
        long exp = f.Names["temp"].LeaseExpiry; // 2000 + 86400
        // block whose MTP >= exp lapses it pre-block
        f.ApplyBlock(Blk(2, exp, 28));
        Check("lapse-removed", !f.Names.ContainsKey("temp"));
        Check("lapse-bumped-mut", f.Muts.TryGetValue(Hashing.Hex(B.Id(0)), out var m) && m == 2);
    }

    // ---- transfer / release ----
    private static void TransferRelease()
    {
        var f = ClaimName("xfer", 0, 100, out _);
        f.ApplyBlock(Blk(5, 3000, 28, Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.TransferAll(B.Id(8)), 0) })));
        Check("transfer-all", OwnedBy(f, "xfer", 8));
        Check("transfer-bumps-both", f.Muts[Hashing.Hex(B.Id(0))] == 5 && f.Muts[Hashing.Hex(B.Id(8))] == 5);

        var fr = ClaimName("rel", 0, 100, out _);
        fr.ApplyBlock(Blk(5, 3000, 28, Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Release(5, new byte[] { 0x01 }), 0) })));
        Check("release", !fr.Names.ContainsKey("rel"));
    }

    // ---- open market ----
    private static void OpenMarket()
    {
        var f = ClaimName("shop", 0, 365, out long claimMtp);
        long sellMtp = claimMtp + 1000;
        // SELL price 300, window 0 → RESERVE_WINDOW
        f.ApplyBlock(Blk(5, sellMtp, 28, Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Sell(300, 0, "shop"), 0) })));
        Check("sell-listed", f.Names["shop"].St == K.ST_LISTED && f.Names["shop"].Price == 300);

        // RESERVE by Id4: burn_leg = max(1, 300*50/10000=1)=1, pay_leg=1
        long resMtp = sellMtp + 100;
        var reserveTx = Tx(new[] { B.In(4) }, new Out[]
        {
            Out.Carrier(B.Reserve("shop"), 1),     // carrier value ≥ burn_leg(1)
            B.Spend(0, 1),                          // pay_leg to seller Id0
        });
        f.ApplyBlock(Blk(6, resMtp, 28, reserveTx));
        Check("reserve-reserved", f.Names["shop"].St == K.ST_RESERVED && f.Names["shop"].Buyer.SequenceEqual(B.Id(4)));

        // SETTLE by Id4: remainder = 300-1-1 = 298
        long setMtp = resMtp + 100;
        var settleTx = Tx(new[] { B.In(4) }, new Out[]
        {
            Out.Carrier(B.Settle("shop"), 0),
            B.Spend(0, 298),
        });
        f.ApplyBlock(Blk(7, setMtp, 28, settleTx));
        Check("settle-owner", OwnedBy(f, "shop", 4) && f.Names["shop"].St == K.ST_OWNED);

        // SELL below floor (price 2 < 3) → ignored
        var fb = ClaimName("cheap", 0, 365, out long cm);
        fb.ApplyBlock(Blk(5, cm + 100, 28, Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Sell(2, 0, "cheap"), 0) })));
        Check("sell-below-floor", fb.Names["cheap"].St == K.ST_OWNED);

        // RESERVE without pay_leg output → drop (listing stays OPEN)
        var fn = ClaimName("noout", 0, 365, out long nm);
        fn.ApplyBlock(Blk(5, nm + 100, 28, Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Sell(300, 0, "noout"), 0) })));
        fn.ApplyBlock(Blk(6, nm + 200, 28, Tx(new[] { B.In(4) }, new[] { Out.Carrier(B.Reserve("noout"), 1) }))); // no pay_leg output
        Check("reserve-no-output-drop", fn.Names["noout"].St == K.ST_LISTED);

        // LISTED name rejects TRANSFER (escrow lock) — skipped, name stays
        var fl = ClaimName("locked", 0, 365, out long lm);
        fl.ApplyBlock(Blk(5, lm + 100, 28, Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Sell(300, 0, "locked"), 0) })));
        fl.ApplyBlock(Blk(6, lm + 200, 28, Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.TransferAll(B.Id(8)), 0) })));
        Check("escrow-lock-transfer-skip", OwnedBy(fl, "locked", 0));
    }

    // ---- value-collision matcher (§7) ----
    private static void ValueCollision()
    {
        var f = ClaimName("coll", 0, 365, out long cm);
        // price 20000 → burn_leg=100, pay_leg=100, remainder=19800
        f.ApplyBlock(Blk(5, cm + 100, 28, Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Sell(20000, 0, "coll"), 0) })));
        long mtp = cm + 200;
        // one tx: RESERVE then SETTLE, both to seller Id0; remainder output BEFORE pay_leg output
        var tx = Tx(new[] { B.In(4) }, new Out[]
        {
            Out.Carrier(B.Reserve("coll"), 100),   // vout0 carrier, owed pay_leg=100
            Out.Carrier(B.Settle("coll"), 0),       // vout1 carrier, owed remainder=19800
            B.Spend(0, 19800),                       // vout2 spendable (larger)
            B.Spend(0, 100),                         // vout3 spendable (smaller)
        });
        f.ApplyBlock(Blk(6, mtp, 28, tx));
        Check("value-collision-settle", OwnedBy(f, "coll", 4));
    }

    // ---- directed sale ----
    private static void Directed()
    {
        var f = ClaimName("otc", 0, 365, out long cm);
        f.ApplyBlock(Blk(5, cm + 100, 28, Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.SellTo(500, B.Id(5), "otc"), 0) })));
        Check("sellto-offered", f.Names["otc"].St == K.ST_OFFERED && f.Names["otc"].Buyer.SequenceEqual(B.Id(5)));

        // stranger PAY → drop
        var strangerTx = Tx(new[] { B.In(6) }, new Out[] { Out.Carrier(B.Pay("otc"), 0), B.Spend(0, 500) });
        f.ApplyBlock(Blk(6, cm + 200, 28, strangerTx));
        Check("pay-stranger-drop", f.Names["otc"].St == K.ST_OFFERED);

        // correct buyer PAY → owner Id5
        var payTx = Tx(new[] { B.In(5) }, new Out[] { Out.Carrier(B.Pay("otc"), 0), B.Spend(0, 500) });
        f.ApplyBlock(Blk(7, cm + 300, 28, payTx));
        Check("pay-buyer-owns", OwnedBy(f, "otc", 5));
    }

    // ---- trade ----
    private static void Trade()
    {
        var f = ClaimName("ta", 0, 365, out long cm);
        // also claim "tb" owned by Id1
        byte[] s = B.Salt(50);
        byte[] cmt = B.Commitment(s, B.Name("tb"), B.Id(1));
        f.ApplyBlock(Blk(5, cm + 100, 28, Tx(new[] { B.In(1) }, new[] { Out.Carrier(B.Commit(cmt), 0) })));
        f.ApplyBlock(Blk(6, cm + 200, 28, Tx(new[] { B.In(1) }, new[] { Out.Carrier(B.Claim(s, "tb"), 100) })));
        // TRADE
        f.ApplyBlock(Blk(7, cm + 300, 28, Tx(new[] { B.In(0), B.In(1) }, new[] { Out.Carrier(B.Trade(0, 1, "ta", "tb"), 0) })));
        Check("trade-swap", OwnedBy(f, "ta", 1) && OwnedBy(f, "tb", 0));

        // anti-rug: same-block TRANSFER of pledged name BEFORE trade → trade drops
        var f2 = ClaimName("ra", 0, 365, out long cm2);
        byte[] s2 = B.Salt(51);
        byte[] cmt2 = B.Commitment(s2, B.Name("rb"), B.Id(1));
        f2.ApplyBlock(Blk(5, cm2 + 100, 28, Tx(new[] { B.In(1) }, new[] { Out.Carrier(B.Commit(cmt2), 0) })));
        f2.ApplyBlock(Blk(6, cm2 + 200, 28, Tx(new[] { B.In(1) }, new[] { Out.Carrier(B.Claim(s2, "rb"), 100) })));
        f2.ApplyBlock(Blk(7, cm2 + 300, 28,
            Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.TransferAll(B.Id(9)), 0) }),       // Id0 moves "ra" away first
            Tx(new[] { B.In(0), B.In(1) }, new[] { Out.Carrier(B.Trade(0, 1, "ra", "rb"), 0) })));
        Check("trade-antirug", OwnedBy(f2, "ra", 9) && OwnedBy(f2, "rb", 1)); // trade dropped, rb stays Id1
    }

    // ---- charset + structural rules (§3.1) ----
    // [a-z0-9-], 1..32; no leading/trailing hyphen; no `--` at positions 3–4.
    private static bool NameOk(string s)
    {
        byte[] b = B.Name(s);
        return Decoder.ValidName(b, 0, b.Length);
    }

    private static void DottedNames()
    {
        Check("hyphen-name-valid", NameOk("shib-p2p"));
        Check("name-32-valid", NameOk("abcdefghijklmnopqrstuvwxyz0123ab"));
        Check("name-33-invalid", !NameOk("abcdefghijklmnopqrstuvwxyz0123abc"));
        Check("dot-invalid", !NameOk("shib.p2p"));
        Check("underscore-invalid", !NameOk("shib_p2p"));
        Check("upper-invalid", !NameOk("Shib-p2p"));
        Check("comma-invalid", !NameOk("a,b")); // TRADE pair split relies on it
        Check("leading-hyphen-invalid", !NameOk("-a"));
        Check("trailing-hyphen-invalid", !NameOk("a-"));
        Check("ace-prefix-invalid", !NameOk("xn--x"));

        var f = new Fold();
        byte[] sLo = B.Salt(0x71), sUp = B.Salt(0x74);
        f.ApplyBlock(Blk(10, 1000, 28,
            Tx(new[] { B.In(0xAA) }, new[] { Out.Carrier(B.Commit(B.Commitment(sLo, B.Name("shib-p2p"), B.Id(0xAA))), 0) }),
            Tx(new[] { B.In(0xAA) }, new[] { Out.Carrier(B.Commit(B.Commitment(sUp, B.Name("shib.p2p"), B.Id(0xAA))), 0) })));
        f.ApplyBlock(Blk(11, 1500, 28,
            Tx(new[] { B.In(0xAA) }, new[] { Out.Carrier(B.Claim(sLo, "shib-p2p"), 10) }),
            Tx(new[] { B.In(0xAA) }, new[] { Out.Carrier(B.Claim(sUp, "shib.p2p"), 10) })));
        Check("hyphen-claim-mints", OwnedBy(f, "shib-p2p", 0xAA));
        Check("dotted-claim-drops", !f.Names.ContainsKey("shib.p2p") && f.Names.Count == 1);
    }

    // ---- oracle ----
    private static void OracleTests()
    {
        ulong sub = K.SUBSIDY_KOINU;

        // 1001 participants, fee_per_byte 20 each (fees 2000, bytes 100) → median 20
        var cb = new ulong[1001]; var by = new ulong[1001];
        for (int i = 0; i < 1001; i++) { cb[i] = sub + 2000; by[i] = 100; }
        Check("oracle-median", Oracle.Rate(cb, by) == 20 * K.REF_SIZE);

        // under-claim: coinbase < subsidy → fees 0 (no wrap → NON-participant); |P|=0 → DUST_FLOOR
        // (an unsigned wrap would enroll every block as a huge participant → RATE_CAP)
        var cb2 = new ulong[1001];
        for (int i = 0; i < 1001; i++) cb2[i] = sub - (ulong)(1 + i % 9);
        Check("oracle-underclaim", Oracle.Rate(cb2, by) == K.DUST_FLOOR);

        // cap: 1001 participants with huge fees → RATE_CAP
        var cb3 = new ulong[1001];
        for (int i = 0; i < 1001; i++) cb3[i] = sub + 100_000_000_000UL;
        Check("oracle-cap", Oracle.Rate(cb3, by) == K.RATE_CAP);

        // |P| = 1000 EXACTLY (inclusive boundary) and EVEN, under-claim inside the window:
        // 499 zero-fee + 1 under-claim + fpb 100..1099 → lower median index 499 → 599 → 119_800
        var cb4 = new ulong[1500]; var by4 = new ulong[1500];
        for (int i = 0; i < 1500; i++)
        {
            by4[i] = 1000;
            cb4[i] = i < 499 ? sub : i == 499 ? sub - 50 : sub + (ulong)(100 + (i - 500)) * 1000;
        }
        Check("oracle-even-boundary", Oracle.Rate(cb4, by4) == 119_800UL);

        // |P| = 999 — one short of MIN_FEE_SAMPLE → degrade to DUST_FLOOR exactly
        var cb5 = new ulong[1500];
        for (int i = 0; i < 1500; i++)
            cb5[i] = i < 501 ? sub : sub + (ulong)(100 + (i - 501)) * 1000;
        Check("oracle-subsample-floor", Oracle.Rate(cb5, by4) == K.DUST_FLOOR);
    }

    // ---- mtp ----
    private static void MtpTests()
    {
        var ts = new List<long>();
        for (int i = 0; i < 12; i++) ts.Add(1000 + i * 10); // 1000,1010,...,1110
        Check("mtp-zero", Oracle.Mtp(ts, 0) == 0);
        // H=5: window ts[0..4] = {1000,1010,1020,1030,1040}; k=5; index 2 → 1020
        Check("mtp-short", Oracle.Mtp(ts, 5) == 1020);
        // H=11: window ts[0..10]; k=11; index 5 → 1050
        Check("mtp-full", Oracle.Mtp(ts, 11) == 1050);
        // even window upper-middle: H=4 → ts[0..3]={1000,1010,1020,1030}; k=4; index 2 → 1020
        Check("mtp-even-upper", Oracle.Mtp(ts, 4) == 1020);
    }

    // ---- attribution ----
    private static void Attrib()
    {
        Check("fad-empty-noop", Attribution.FindAndDelete(new byte[] { 0x01, 0x02 }, Array.Empty<byte>()).Length == 2);
        // FindAndDelete removes a boundary-aligned push
        var script = new byte[] { 0x01, 0xAA, 0x02, 0xBB, 0xCC }; // push(0xAA), push(0xBB 0xCC)
        var pat = new byte[] { 0x01, 0xAA };
        var fad = Attribution.FindAndDelete(script, pat);
        Check("fad-boundary-remove", fad.Length == 3 && fad[0] == 0x02);
        // pubkey canonical
        var goodPub = new byte[33]; goodPub[0] = 0x02;
        Check("pub-canonical", Attribution.CanonicalPubkeyEncoding(goodPub));
        var hybrid = new byte[33]; hybrid[0] = 0x06;
        Check("pub-hybrid-reject", !Attribution.CanonicalPubkeyEncoding(hybrid));
    }

    // ---- §4 Strategy B: real secp256k1 KAT (constants, 2G, n·G=∞, decompress, sign/verify) ----
    private static void Secp()
    {
        Check("secp256k1-selftest", Secp256k1.Selftest() == 0);
    }

    // ---- §13.2: state-level ECMH binds to the canonical state digest ----
    private static void Ecmh_()
    {
        // empty-state ECMH is stable across independent recomputes (and equals the anchor).
        byte[] ea = StateEcmh.Compute(new Fold()), eb = StateEcmh.Compute(new Fold());
        Check("ecmh-empty-stable", ea.SequenceEqual(eb));

        // ECMH induces the SAME equality relation as the canonical digest. Build the same
        // logical rows in two insertion orders (commits a,b in BOTH; CLAIM reversed in s2 ⇒
        // names array permuted, commits identical since a claim doesn't prune its commit),
        // and a third smaller state. Whenever the digest calls two states equal, ECMH agrees.
        Fold S1()
        {
            var f = new Fold();
            byte[] sa = B.Salt(0xA1), sb = B.Salt(0xA2);
            byte[] ca = B.Commitment(sa, B.Name("a"), B.Id(0));
            byte[] cb = B.Commitment(sb, B.Name("b"), B.Id(0));
            f.ApplyBlock(Blk(10, 1000, 28,
                Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Commit(ca), 0) }),
                Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Commit(cb), 0) })));
            f.ApplyBlock(Blk(11, 1500, 28,
                Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Claim(sa, "a"), 30) }),
                Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Claim(sb, "b"), 30) })));
            return f;
        }
        Fold S2()
        {
            var f = new Fold();
            byte[] sa = B.Salt(0xA1), sb = B.Salt(0xA2);
            byte[] ca = B.Commitment(sa, B.Name("a"), B.Id(0));
            byte[] cb = B.Commitment(sb, B.Name("b"), B.Id(0));
            f.ApplyBlock(Blk(10, 1000, 28,
                Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Commit(ca), 0) }),
                Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Commit(cb), 0) })));
            f.ApplyBlock(Blk(11, 1500, 28,
                Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Claim(sb, "b"), 30) }),   // reversed claim order
                Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Claim(sa, "a"), 30) })));
            return f;
        }
        Fold S3()
        {
            var f = new Fold();
            byte[] sa = B.Salt(0xA1);
            byte[] ca = B.Commitment(sa, B.Name("a"), B.Id(0));
            f.ApplyBlock(Blk(10, 1000, 28, Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Commit(ca), 0) })));
            f.ApplyBlock(Blk(11, 1500, 28, Tx(new[] { B.In(0) }, new[] { Out.Carrier(B.Claim(sa, "a"), 30) })));
            return f;
        }

        var s1 = S1(); var s2 = S2(); var s3 = S3();
        byte[] d1 = Digest.Compute(s1), d2 = Digest.Compute(s2), d3 = Digest.Compute(s3);
        byte[] m1 = StateEcmh.Compute(s1), m2 = StateEcmh.Compute(s2), m3 = StateEcmh.Compute(s3);
        Check("ecmh-setup-reorder-equal-digest", d1.SequenceEqual(d2));
        Check("ecmh-tracks-digest-equal", d1.SequenceEqual(d2) == m1.SequenceEqual(m2));
        Check("ecmh-tracks-digest-differ", d1.SequenceEqual(d3) == m1.SequenceEqual(m3));
    }

    // ---- shared: claim a name owned by `id` with `days` lease ----
    private static Fold ClaimName(string name, int id, ulong days, out long claimMtp)
    {
        var f = new Fold();
        byte[] salt = B.Salt((byte)(name.GetHashCode() & 0x7F));
        byte[] cmt = B.Commitment(salt, B.Name(name), B.Id(id));
        f.ApplyBlock(Blk(0, 1000, 28, Tx(new[] { B.In(id) }, new[] { Out.Carrier(B.Commit(cmt), 0) })));
        claimMtp = 2000;
        f.ApplyBlock(Blk(1, claimMtp, 28, Tx(new[] { B.In(id) }, new[] { Out.Carrier(B.Claim(salt, name), days) })));
        return f;
    }

    // ---- A7: off-curve-but-canonical P2PKH → on-curve-drop (status 1) ----
    // Reference-tier regression for the SPEC-conformance §13 rule the Rust clean-room
    // surfaced: the status taxonomy applies to the P2PKH pubkey too (not redeemScript
    // keys only). A P2PKH pubkey canonically ENCODED (0x02‖X, X<p) but OFF the curve
    // drops at the on-curve gate (status 1) carrying its REAL hash160 + legacy sighash —
    // never a classify-drop (status 0) and never a verify-drop (status 2).
    private static void AttribA7()
    {
        // valid low-S SIGHASH_ALL DER sig: DER(R=1, S=1) ‖ hashtype 0x01.
        byte[] sig = { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01 };

        byte[] offPub = FindCanonicalPub(wantOffCurve: true);
        AttribResult off = AttribOneInput(sig, offPub);
        Check("a7-offcurve-p2pkh-status1", off.Status == 1);
        Check("a7-offcurve-real-identity", off.Identity.SequenceEqual(Hashing.Hash160(offPub)));
        Check("a7-offcurve-real-sighash", off.Sighash.Any(b => b != 0));

        byte[] onPub = FindCanonicalPub(wantOffCurve: false);
        AttribResult on = AttribOneInput(sig, onPub);
        Check("a7-oncurve-not-status1", on.Status != 1);
    }

    // search a canonically-encoded compressed pubkey (0x02‖X, high X bytes 0 ⇒ X<p) with the
    // requested curve status via the injected oracle on_curve(pk) = SHA256(0x4F‖pk)[0] != 0.
    private static byte[] FindCanonicalPub(bool wantOffCurve)
    {
        byte[] pub = new byte[33];
        pub[0] = 0x02;
        for (uint v = 0; v < uint.MaxValue; v++)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(pub.AsSpan(29, 4), v);
            bool offCurve = !Attribution.OnCurve(pub);
            if (offCurve == wantOffCurve) return (byte[])pub.Clone();
        }
        throw new Exception("no canonical pubkey found (unreachable)");
    }

    // build a single-input P2PKH-shaped raw tx [push(sig)][push(pub)] and attribute vin0.
    private static AttribResult AttribOneInput(byte[] sig, byte[] pub)
    {
        byte[] ss = B.Concat(Push(sig), Push(pub));
        var tx = new RawTx
        {
            Version = 1,
            Inputs = { new RawInput { PrevHash = new byte[32], PrevN = 0, ScriptSig = ss, Sequence = 0xFFFFFFFF } },
            Outputs = { new RawOutput { Value = 0, ScriptPubKey = new byte[] { 0x6a } } },
            Locktime = 0,
        };
        return Attribution.Attribute(tx, 0);
    }

    private static byte[] Push(byte[] data)
    {
        byte[] r = new byte[1 + data.Length]; // minimal direct push (sig=9, pubkey=33, both < 76)
        r[0] = (byte)data.Length;
        Buffer.BlockCopy(data, 0, r, 1, data.Length);
        return r;
    }
}
