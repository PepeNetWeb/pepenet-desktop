// Independent anchors: the KATs the spec pins outright, checkable without any
// generator agreement. These gate the foundation (PRNG + hashes) before the
// fold/decoder/attribution are built on top.

final class Selftest {
    private static int pass = 0, fail = 0;

    private static void check(String what, boolean ok) {
        if (ok) { pass++; System.out.println("  ok   " + what); }
        else    { fail++; System.out.println("FAIL   " + what); }
    }
    private static void eq(String what, String got, String want) {
        check(what + "  got=" + got + " want=" + want, got.equals(want));
    }

    // §13.2 — ECMH state digest binds to the canonical state digest: it must
    // induce the SAME equality relation. Mirrors C's test_ecmh (main.c).
    private static byte[] mkH160(int seed) { byte[] h = new byte[20]; java.util.Arrays.fill(h, (byte) seed); return h; }

    private static void addCommit(State s, String name, byte[] owner, int tag, long height, long txIndex) {
        State.Commit c = new State.Commit();
        // commitment = SHA256("commit" ‖ name ‖ owner ‖ tag) — a deterministic stand-in.
        byte[] pre = new Buf().bytes(Sm.utf8("commit")).bytes(Sm.utf8(name)).bytes(owner).u8(tag).toBytes();
        c.commitment = Hashes.sha256(pre);
        c.commitHeight = height; c.txIndex = txIndex; c.commitTime = 1000;
        s.commits.add(c);
    }
    private static void addName(State s, String name, byte[] owner, long leaseExpiry) {
        State.NameRow r = new State.NameRow();
        r.owner = owner; r.st = Const.OWNED; r.leaseExpiry = leaseExpiry;
        s.names.put(name, r);
        s.bumpMut(owner, 11);
    }

    // §3.1 charset + structural rules: [a-z0-9-], 1..32; no leading/trailing hyphen;
    // no `--` at positions 3–4 (kills xn--). Mirrors C's test_dotted_names.
    private static Model.Tx oneCarrierTx(byte[] id, long value, Action a) {
        return new Model.Tx(new Model.TxIn[]{ new Model.TxIn(id, Const.P2PKH, true) },
                            new Model.TxOut[]{ Model.TxOut.carrier(java.math.BigInteger.valueOf(value), Wire.encode(a)) });
    }
    // §6 pinned carrier ceiling: flags at the exact consensus caps decode;
    // one byte past the ceiling is IGNORE (fail-closed).
    private static void testL1CarrierCeiling() {
        byte[] wide = new byte[4 + 5 + Const.FLAGS_MAX];
        wide[0] = Const.P0; wide[1] = Const.P1; wide[2] = Const.P2; wide[3] = (byte) Const.RENEW;
        for (int i = 9; i < wide.length; i++) wide[i] = (byte) (i * 7 + 1);
        check("RENEW at cap is exactly CARRIER_MAX bytes", wide.length == Const.CARRIER_MAX);
        Wire.Decoded d = Wire.decode(wide, java.math.BigInteger.ZERO);
        check("RENEW-selective decodes with all 9987 flag bytes",
              d.kind == Wire.Kind.ACTION && d.action.flags.length == Const.FLAGS_MAX);
        byte[] over = java.util.Arrays.copyOf(wide, wide.length + 1);
        check("one byte past the L1 ceiling -> IGNORE",
              Wire.decode(over, java.math.BigInteger.ZERO).kind == Wire.Kind.IGNORE);
        byte[] xfer = new byte[4 + 20 + 5 + Const.FLAGS_XFER_MAX];
        xfer[0] = Const.P0; xfer[1] = Const.P1; xfer[2] = Const.P2; xfer[3] = (byte) Const.TRANSFER;
        d = Wire.decode(xfer, java.math.BigInteger.ZERO);
        check("TRANSFER-selective decodes at FLAGS_XFER_MAX",
              d.kind == Wire.Kind.ACTION && d.action.flags.length == Const.FLAGS_XFER_MAX);
        byte[] xover = java.util.Arrays.copyOf(xfer, xfer.length + 1);
        check("TRANSFER flags past the cap -> IGNORE",
              Wire.decode(xover, java.math.BigInteger.ZERO).kind == Wire.Kind.IGNORE);
    }

    private static void testDottedNames() {
        check("hyphen name valid", Wire.validName(Sm.utf8("shib-p2p")));
        check("32-byte name valid", Wire.validName(Sm.utf8("abcdefghijklmnopqrstuvwxyz0123ab")));
        check("33-byte name invalid (max 32)", !Wire.validName(Sm.utf8("abcdefghijklmnopqrstuvwxyz0123abc")));
        check("dot now invalid", !Wire.validName(Sm.utf8("shib.p2p")));
        check("underscore now invalid", !Wire.validName(Sm.utf8("shib_p2p")));
        check("uppercase still invalid", !Wire.validName(Sm.utf8("Shib-p2p")));
        check("comma still invalid (TRADE pair split relies on it)", !Wire.validName(Sm.utf8("a,b")));
        check("leading hyphen invalid", !Wire.validName(Sm.utf8("-a")));
        check("trailing hyphen invalid", !Wire.validName(Sm.utf8("a-")));
        check("ACE prefix (xn--) invalid", !Wire.validName(Sm.utf8("xn--x")));

        byte[] A = new byte[20]; A[0] = (byte) 0xAA; A[19] = (byte) 0xAA;
        byte[] s71 = new byte[32]; java.util.Arrays.fill(s71, (byte) 0x71);
        byte[] s74 = new byte[32]; java.util.Arrays.fill(s74, (byte) 0x74);

        Action c71 = new Action(); c71.op = Const.COMMIT;
        c71.commitment = Hashes.sha256(Fold.concat(s71, Sm.utf8("shib-p2p"), A));
        Action c74 = new Action(); c74.op = Const.COMMIT;
        c74.commitment = Hashes.sha256(Fold.concat(s74, Sm.utf8("shib.p2p"), A));
        Action k71 = new Action(); k71.op = Const.CLAIM; k71.salt = s71; k71.name = Sm.utf8("shib-p2p");
        Action k74 = new Action(); k74.op = Const.CLAIM; k74.salt = s74; k74.name = Sm.utf8("shib.p2p");

        java.math.BigInteger rate = java.math.BigInteger.valueOf(28);   // burn == days
        State st = new State();
        Fold f = new Fold(st);
        f.applyBlock(new Model.Block(10, 1000, rate,
                new Model.Tx[]{ oneCarrierTx(A, 0, c71), oneCarrierTx(A, 0, c74) }));
        f.applyBlock(new Model.Block(11, 1500, rate,
                new Model.Tx[]{ oneCarrierTx(A, 10, k71), oneCarrierTx(A, 10, k74) }));

        State.NameRow row = st.names.get("shib-p2p");
        check("hyphen claim mints", row != null && java.util.Arrays.equals(row.owner, A));
        check("dotted claim drops", !st.names.containsKey("shib.p2p") && st.names.size() == 1);
    }

    private static void testEcmhState() {
        // empty-state ECMH stable across independent recomputes + anchor.
        check("ECMH empty-state stable",
              java.util.Arrays.equals(StateDigest.stateEcmh(new State()), StateDigest.stateEcmh(new State())));

        byte[] A = mkH160(0xAA);
        // s1: commits a(0),b(1); names a,b.
        State s1 = new State();
        addCommit(s1, "a", A, 0xA1, 10, 0);
        addCommit(s1, "b", A, 0xA2, 10, 1);
        addName(s1, "a", A, 30);
        addName(s1, "b", A, 30);
        // s2: identical logical rows, claim/name in reverse order (permuted arrays).
        State s2 = new State();
        addCommit(s2, "a", A, 0xA1, 10, 0);
        addCommit(s2, "b", A, 0xA2, 10, 1);
        addName(s2, "b", A, 30);
        addName(s2, "a", A, 30);
        // s3: smaller — only a.
        State s3 = new State();
        addCommit(s3, "a", A, 0xA1, 10, 0);
        addName(s3, "a", A, 30);

        byte[] d1 = Hashes.sha256(StateDigest.serialize(s1));
        byte[] d2 = Hashes.sha256(StateDigest.serialize(s2));
        byte[] d3 = Hashes.sha256(StateDigest.serialize(s3));
        byte[] e1 = StateDigest.stateEcmh(s1), e2 = StateDigest.stateEcmh(s2), e3 = StateDigest.stateEcmh(s3);

        check("ECMH test setup: reordered builds give equal digest", java.util.Arrays.equals(d1, d2));
        check("ECMH equality tracks digest (equal states)",
              java.util.Arrays.equals(d1, d2) == java.util.Arrays.equals(e1, e2));
        check("ECMH equality tracks digest (differing states)",
              java.util.Arrays.equals(d1, d3) == java.util.Arrays.equals(e1, e3));
    }

    static void run() {
        // §1 PRNG — next() from seed=0 returns 0xE220A8397B1DCDAF first.
        Rng r = new Rng(0);
        long first = r.next();
        eq("prng next(seed=0)[0]", String.format("%016x", first), "e220a8397b1dcdaf");

        // §13 RIPEMD-160 KATs
        eq("ripemd160(\"\")",  Hex.enc(Hashes.ripemd160(new byte[0])),
                "9c1185a5c5e9fc54612808977ee8f548b2258d31");
        eq("ripemd160(\"abc\")", Hex.enc(Hashes.ripemd160(Sm.utf8("abc"))),
                "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
        // §13 hash160("abc") = RIPEMD160(SHA256("abc")) -> bb1be98c...
        eq("hash160(\"abc\")[..4]", Hex.enc(Hashes.hash160(Sm.utf8("abc")), 4), "bb1be98c");

        // SHA-256 sanity (JDK): sha256("abc")
        eq("sha256(\"abc\")", Hex.enc(Hashes.sha256(Sm.utf8("abc"))),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

        // §4 Strategy B — real secp256k1 KAT (constants, 2G, n·G=∞, decompress G,
        // sign/verify + tamper). Secp.selftest() returns the failure count.
        check("secp256k1 KAT (constants/2G/n·G=∞/decompress/sign-verify-tamper)", Secp.selftest() == 0);

        testDottedNames();
        testL1CarrierCeiling();
        testEcmhState();

        System.out.println("────");
        // §4 / §13.2 — empty-state digests (cross-impl anchors; match C `sm selftest | head -2`).
        System.out.println("empty_state_digest=" + StateDigest.digest(new State()));
        System.out.println("empty_state_ecmh=" + StateDigest.ecmhHex(new State()));
        System.out.println("selftest: " + pass + " pass, " + fail + " fail");
        if (fail > 0) System.exit(1);
    }
}
