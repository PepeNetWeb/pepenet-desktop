import java.math.BigInteger;
import java.util.*;

// §4 attribution validation (attrib-scenario). Validates the byte-logic that is
// independently pinnable: RIPEMD160/hash160 KATs, FindAndDelete boundary semantics,
// strict-DER/low-S accept/reject, canonical-pubkey accept/reject, P2PKH + P2SH
// multisig classification + identity, and the in-order scan. The injected curve
// oracle is deterministic, so each end-to-end status is cross-checked against an
// independent recomputation of on_curve/verify (a self-consistency proof of the
// parse->sighash->identity pipeline). The shipped `combined` golden can't be matched
// without the (prose-gap) exact sighash serialization; that is reported, not faked.
final class AttribScenario {
    static int pass = 0, fail = 0;
    static void chk(String n, boolean ok) { if (ok) { pass++; System.out.println("  ok   " + n); } else { fail++; System.out.println("FAIL   " + n); } }

    // a minimal valid strict-DER + low-S signature with hashtype 0x01, params (r,s)
    static byte[] der(int r, int s) { return new byte[]{0x30, 0x06, 0x02, 0x01, (byte) r, 0x02, 0x01, (byte) s, 0x01}; }
    static byte[] compressedKey(int x0) { byte[] k = new byte[33]; k[0] = 0x02; k[32] = (byte) x0; return k; }
    static byte[] push(byte[] d) { return Attrib.pushOf(d); }

    static Attrib.Tx p2pkhTx(byte[] sig, byte[] pk) {
        Attrib.Tx t = new Attrib.Tx(); t.version = 1; t.locktime = 0;
        Attrib.In in = new Attrib.In(); in.prevTxid = new byte[32]; in.prevVout = 0; in.sequence = 0xFFFFFFFFL;
        in.scriptSig = Fold.concat(push(sig), push(pk));
        t.ins.add(in);
        Attrib.Out o = new Attrib.Out(); o.value = BigInteger.valueOf(1000); o.spk = new byte[]{0x6a}; // OP_RETURN
        t.outs.add(o);
        return t;
    }

    static void run() {
        // RIPEMD160 / hash160 KATs (§13)
        chk("ripemd160(\"\")", Hex.enc(Hashes.ripemd160(new byte[0])).equals("9c1185a5c5e9fc54612808977ee8f548b2258d31"));
        chk("ripemd160(\"abc\")", Hex.enc(Hashes.ripemd160(Sm.utf8("abc"))).equals("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"));
        chk("hash160(\"abc\")", Hex.enc(Hashes.hash160(Sm.utf8("abc"))).startsWith("bb1be98c"));

        // FindAndDelete: boundary removal vs in-body non-removal
        {
            byte[] sig = der(1, 1);                 // a "signature" push value
            byte[] sigPush = push(sig);             // 0x09 30 06 ... 01
            // script = [push sig][OP_CHECKSIG] -> FaD removes the boundary-aligned push
            byte[] script = Fold.concat(sigPush, new byte[]{(byte) 0xAC});
            byte[] afterFad = Attrib.findAndDelete(script, sigPush);
            chk("FaD removes a boundary-aligned push", Arrays.equals(afterFad, new byte[]{(byte) 0xAC}));
            // pattern that appears only inside a larger push's data (not boundary-aligned) -> NOT removed
            byte[] big = Fold.concat(new byte[]{0x0A}, sig, new byte[]{0x42}); // push of 10 bytes containing sig bytes
            byte[] afterFad2 = Attrib.findAndDelete(big, sigPush);
            chk("FaD does NOT remove an in-body (non-boundary) occurrence", Arrays.equals(afterFad2, big));
        }

        // P2PKH end-to-end, cross-checked against the deterministic oracle
        {
            byte[] sig = der(1, 1), pk = compressedKey(7);
            Attrib.Tx t = p2pkhTx(sig, pk);
            byte[] raw = Attrib.serialize(t);
            Attrib.Tx pt = Attrib.parseTx(raw);
            chk("raw tx round-trips through parseTx", pt != null && pt.ins.size() == 1);
            Attrib.Result r = Attrib.attribute(pt, 0);
            byte[] expectId = Hashes.hash160(pk);
            chk("P2PKH identity = hash160(pubkey)", Arrays.equals(r.identity, expectId));
            // independent expected status
            int expected;
            if (!Attrib.onCurve(pk)) expected = 1;
            else {
                byte[] sc = Attrib.findAndDelete(Attrib.p2pkhScript(expectId), push(sig));
                byte[] sh = Attrib.sighash(pt, 0, sc);
                byte[][] rs = Attrib.rs32(sig);
                expected = Attrib.ecdsaVerify(sh, rs[0], rs[1], pk) ? 3 : 2;
            }
            chk("P2PKH status matches independent oracle recompute (status=" + r.status + ")", r.status == expected);
        }

        // strict-DER rejection -> classify-drop (status 0)
        {
            byte[] badSig = new byte[]{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02}; // hashtype 0x02 != SIGHASH_ALL
            Attrib.Tx t = p2pkhTx(badSig, compressedKey(7));
            Attrib.Result r = Attrib.attribute(Attrib.parseTx(Attrib.serialize(t)), 0);
            chk("bad sighash-type sig -> classify-drop (status 0)", r.status == 0);
        }
        {
            byte[] highS = new byte[]{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01}; // S=1 ok; make S high instead
            // craft S > N/2: lenS=32 of 0xFF... too long for this minimal frame; use a 33-byte form
            Buf b = new Buf();
            byte[] sBytes = Attrib.be32(Attrib.SECP_N_HALF.add(BigInteger.ONE)); // > N/2
            b.u8(0x30).u8(4 + 2 + 33).u8(0x02).u8(1).u8(0x01).u8(0x02).u8(33).u8(0x00).bytes(sBytes).u8(0x01);
            Attrib.Tx t = p2pkhTx(b.toBytes(), compressedKey(7));
            Attrib.Result r = Attrib.attribute(Attrib.parseTx(Attrib.serialize(t)), 0);
            chk("high-S sig -> classify-drop (status 0)", r.status == 0);
        }
        // non-canonical pubkey -> classify-drop
        {
            byte[] badpk = new byte[34]; badpk[0] = 0x02; // wrong length (34)
            Attrib.Tx t = p2pkhTx(der(1, 1), badpk);
            Attrib.Result r = Attrib.attribute(Attrib.parseTx(Attrib.serialize(t)), 0);
            chk("non-canonical pubkey (bad length) -> classify-drop", r.status == 0);
        }
        // hybrid pubkey prefix 0x06 -> drop
        {
            byte[] hyb = new byte[65]; hyb[0] = 0x06;
            Attrib.Tx t = p2pkhTx(der(1, 1), hyb);
            Attrib.Result r = Attrib.attribute(Attrib.parseTx(Attrib.serialize(t)), 0);
            chk("hybrid 0x06 pubkey -> classify-drop", r.status == 0);
        }

        // P2SH 2-of-3 multisig: identity = hash160(redeemScript), status per in-order scan
        {
            byte[] k1 = compressedKey(11), k2 = compressedKey(12), k3 = compressedKey(13);
            Buf rs = new Buf();
            rs.u8(0x52); // OP_2
            rs.u8(0x21).bytes(k1).u8(0x21).bytes(k2).u8(0x21).bytes(k3);
            rs.u8(0x53).u8(0xAE); // OP_3 OP_CHECKMULTISIG
            byte[] redeem = rs.toBytes();
            byte[] sig1 = der(1, 1), sig2 = der(2, 2);
            byte[] ss = Fold.concat(new byte[]{0x00}, push(sig1), push(sig2), push(redeem));
            Attrib.Tx t = new Attrib.Tx(); t.version = 1;
            Attrib.In in = new Attrib.In(); in.prevTxid = new byte[32]; in.prevVout = 0; in.sequence = 0xFFFFFFFFL; in.scriptSig = ss;
            t.ins.add(in);
            Attrib.Out o = new Attrib.Out(); o.value = BigInteger.valueOf(1000); o.spk = new byte[]{0x6a}; t.outs.add(o);
            Attrib.Tx pt = Attrib.parseTx(Attrib.serialize(t));
            Attrib.Result r = Attrib.attribute(pt, 0);
            chk("P2SH multisig identity = hash160(redeemScript)", Arrays.equals(r.identity, Hashes.hash160(redeem)));
            chk("P2SH multisig parses to a real status (0..3), not crash", r.status >= 0 && r.status <= 3);
            // wrong sig count (1 sig for m=2) -> classify-drop
            byte[] ss1 = Fold.concat(new byte[]{0x00}, push(sig1), push(redeem));
            Attrib.Tx t1 = new Attrib.Tx(); t1.version = 1;
            Attrib.In in1 = new Attrib.In(); in1.prevTxid = new byte[32]; in1.prevVout = 0; in1.sequence = 0xFFFFFFFFL; in1.scriptSig = ss1;
            t1.ins.add(in1); Attrib.Out o1 = new Attrib.Out(); o1.value = BigInteger.ONE; o1.spk = new byte[]{0x6a}; t1.outs.add(o1);
            Attrib.Result r1 = Attrib.attribute(Attrib.parseTx(Attrib.serialize(t1)), 0);
            chk("P2SH multisig wrong sig count (1 != m=2) -> classify-drop", r1.status == 0);
        }
        // unparseable scriptSig (truncated push) -> classify-drop
        {
            Attrib.Tx t = new Attrib.Tx(); t.version = 1;
            Attrib.In in = new Attrib.In(); in.prevTxid = new byte[32]; in.prevVout = 0; in.sequence = 0; in.scriptSig = new byte[]{0x05, 0x01, 0x02}; // push 5, only 2 bytes
            t.ins.add(in); Attrib.Out o = new Attrib.Out(); o.value = BigInteger.ONE; o.spk = new byte[]{0x6a}; t.outs.add(o);
            Attrib.Result r = Attrib.attribute(Attrib.parseTx(Attrib.serialize(t)), 0);
            chk("unparseable scriptSig -> classify-drop (status 0)", r.status == 0);
        }

        forkVectors();
        System.out.println("────");
        System.out.println("attrib-scenario: " + pass + " pass, " + fail + " fail");
        System.out.println("NOTE: the shipped `combined` golden depends on the exact legacy-sighash");
        System.out.println("serialization (a spec-prose gap, register #8) — not reproducible from prose alone.");
        if (fail > 0) System.exit(1);
    }

    // ===== fork-risk differential vectors (TV-11..TV-14) ====================
    // The §4/§13 attribution points the 2026-06-29 hardening pass pinned to MATCH this
    // independent impl (SPEC-RATIONALE.md, TV-11..14). impls/c remains the unverified
    // authority for these exact bytes (the §4 surfaces it is normative for).
    static void forkVectors() {
        // TV-12: legacy sighash appends a 4-byte LE hashtype (0x01000000), never 1 byte.
        {
            byte[] sig = der(1, 1), pk = compressedKey(7);
            Attrib.Tx t = p2pkhTx(sig, pk);
            byte[] sc = Attrib.findAndDelete(Attrib.p2pkhScript(Hashes.hash160(pk)), push(sig));
            byte[] got = Attrib.sighash(t, 0, sc);
            chk("TV-12 sighash uses 4-byte LE hashtype (matches 4-byte preimage, differs from 1-byte)",
                Arrays.equals(got, manualPreimageHash(t, 0, sc, 4)) && !Arrays.equals(got, manualPreimageHash(t, 0, sc, 1)));
        }
        // TV-13: on_curve checked on ALL n redeemScript keys up front — an off-curve UNUSED key -> status 1.
        byte[] k1 = findKey(true, 1000), k2 = findKey(true, 50000), k3 = findKey(false, 1);
        byte[] redeem13 = build2of3(k1, k2, k3);
        Attrib.Result r13 = Attrib.attribute(Attrib.parseTx(Attrib.serialize(multisigTx(redeem13, der(1, 1), der(2, 2)))), 0);
        chk("TV-13 on_curve on ALL keys up front: off-curve unused key -> status 1", r13.status == 1);
        // TV-14: m sig pushes present but the in-order scan verifies fewer than m -> status 2 (verify-drop).
        byte[] j1 = findKey(true, 2000), j2 = findKey(true, 60000), j3 = findKey(true, 120000);
        byte[] redeem14 = build2of3(j1, j2, j3);
        byte[] sh = Attrib.sighash(Attrib.parseTx(Attrib.serialize(multisigTx(redeem14, der(1, 1), der(1, 1)))), 0, redeem14); // FaD inert on template
        byte[] bad = findNonVerifying(sh, new byte[][]{j1, j2, j3});
        Attrib.Result r14 = Attrib.attribute(Attrib.parseTx(Attrib.serialize(multisigTx(redeem14, bad, bad))), 0);
        chk("TV-14 under-threshold (2 valid-DER sigs, none verify) -> status 2 (verify-drop)", r14.status == 2);
        // TV-11: drop-row bytes — status 1 = ZERO32 sighash + REAL identity; status 2 = REAL sighash + REAL identity.
        chk("TV-11 status-1 row: REAL sighash + REAL identity (sighash formed before on-curve gate, matches impls/c)",
            !allZero(r13.sighash) && Arrays.equals(r13.identity, Hashes.hash160(redeem13)));
        chk("TV-11 status-2 row: REAL sighash + REAL identity (hash160 of redeemScript)",
            !allZero(r14.sighash) && Arrays.equals(r14.identity, Hashes.hash160(redeem14)));
    }

    static boolean allZero(byte[] b) { for (byte x : b) if (x != 0) return false; return true; }

    // a compressed key (0x02 prefix) whose injected on_curve matches `wantOnCurve`; distinct per seed range
    static byte[] findKey(boolean wantOnCurve, int seed) {
        for (int x = seed; x < seed + 300000; x++) {
            byte[] k = new byte[33]; k[0] = 0x02;
            k[30] = (byte) (x >> 16); k[31] = (byte) (x >> 8); k[32] = (byte) x;
            if (Attrib.onCurve(k) == wantOnCurve) return k;
        }
        throw new RuntimeException("no key (wantOnCurve=" + wantOnCurve + ")");
    }
    static byte[] build2of3(byte[] a, byte[] b, byte[] c) {
        Buf rs = new Buf();
        rs.u8(0x52).u8(0x21).bytes(a).u8(0x21).bytes(b).u8(0x21).bytes(c).u8(0x53).u8(0xAE); // OP_2 k k k OP_3 OP_CHECKMULTISIG
        return rs.toBytes();
    }
    static Attrib.Tx multisigTx(byte[] redeem, byte[]... sigs) {
        Buf ss = new Buf();
        ss.u8(0x00);                                 // OP_0 NULLDUMMY
        for (byte[] sig : sigs) ss.bytes(push(sig));
        ss.bytes(push(redeem));
        Attrib.Tx t = new Attrib.Tx(); t.version = 1; t.locktime = 0;
        Attrib.In in = new Attrib.In(); in.prevTxid = new byte[32]; in.prevVout = 0; in.sequence = 0xFFFFFFFFL;
        in.scriptSig = ss.toBytes(); t.ins.add(in);
        Attrib.Out o = new Attrib.Out(); o.value = BigInteger.valueOf(1000); o.spk = new byte[]{0x6a}; t.outs.add(o);
        return t;
    }
    // a valid-DER low-S 0x01 sig (r,s in 1..127) whose injected verify is FALSE against every key
    static byte[] findNonVerifying(byte[] sh, byte[][] keys) {
        for (int r = 1; r < 128; r++) for (int s = 1; s < 128; s++) {
            byte[] sig = der(r, s);
            byte[][] rs = Attrib.rs32(sig);
            boolean any = false;
            for (byte[] k : keys) if (Attrib.ecdsaVerify(sh, rs[0], rs[1], k)) { any = true; break; }
            if (!any) return sig;
        }
        throw new RuntimeException("no non-verifying sig found");
    }
    // the legacy sighash preimage hash with a chosen hashtype width (to prove the 4-byte LE pin)
    static byte[] manualPreimageHash(Attrib.Tx t, int k, byte[] sc, int htBytes) {
        Buf b = new Buf();
        b.u32(t.version);
        b.bytes(Attrib.varint(t.ins.size()));
        for (int i = 0; i < t.ins.size(); i++) {
            Attrib.In in = t.ins.get(i);
            b.bytes(in.prevTxid).u32(in.prevVout);
            byte[] s = (i == k) ? sc : new byte[0];
            b.bytes(Attrib.varint(s.length)).bytes(s);
            b.u32(in.sequence);
        }
        b.bytes(Attrib.varint(t.outs.size()));
        for (Attrib.Out o : t.outs) b.u64(o.value).bytes(Attrib.varint(o.spk.length)).bytes(o.spk);
        b.u32(t.locktime);
        if (htBytes == 4) b.u32(0x01); else b.u8(0x01);
        return Hashes.dsha256(b.toBytes());
    }
}
