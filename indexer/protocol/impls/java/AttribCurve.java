import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;

// §4 Strategy B — the pinned ECDSA curve-vector set (`sm attrib-curve`).
//
// Mirrors impls/c/src/attrib_curve.c (attrib_cmd_curve) + attrib.c (attrib_real_endtoend)
// byte-for-byte. Runs Java's OWN secp256k1 (Secp.java) and must print output identical
// to the C reference. Covers pinned P/N/N_HALF constants, on-curve membership at the
// edges, ECDSA verify accept/reject at the scalar boundaries, RFC-6979 deterministic
// (r,s) + canonical-DER known-answers, the tiny-key KAT, the PRIMARY `combined` digest,
// and the real-curve end-to-end attribution vectors + `combined_e2e`.
final class AttribCurve {

    // a streaming SHA-256 accumulator (the C single-CTX feed)
    private static MessageDigest sha256ctx() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (Exception e) { throw new RuntimeException(e); }
    }

    private static final byte[] CV_P     = Secp.be32(Secp.P);
    private static final byte[] CV_N     = Secp.be32(Secp.N);
    private static final byte[] CV_NHALF = Secp.be32(Secp.N_HALF);
    private static final byte[] CV_GX    = Secp.be32(Secp.GX);
    private static final byte[] CV_GY    = Secp.be32(Secp.GY);

    static void run() {
        StringBuilder out = new StringBuilder();
        MessageDigest comb = sha256ctx();

        // ── 1. pinned constants ──────────────────────────────────────────────
        out.append("p ").append(Hex.enc(CV_P)).append("\n");         comb.update(CV_P);
        out.append("n ").append(Hex.enc(CV_N)).append("\n");         comb.update(CV_N);
        out.append("nhalf ").append(Hex.enc(CV_NHALF)).append("\n"); comb.update(CV_NHALF);

        // ── 2. on-curve membership at the edges ──────────────────────────────
        String[] ocName = new String[16];
        byte[][] ocKey = new byte[16][];
        int noc = 0;
        byte[] buf;
        // G uncompressed (on)
        buf = new byte[65]; buf[0] = 0x04; sys(buf, 1, CV_GX); sys(buf, 33, CV_GY);
        ocKey[noc] = buf; ocName[noc] = "oc_G_uncomp"; noc++;
        // G compressed even (on)
        buf = new byte[33]; buf[0] = 0x02; sys(buf, 1, CV_GX);
        ocKey[noc] = buf; ocName[noc] = "oc_G_comp02"; noc++;
        // G compressed odd-prefix (still on curve: yields p−Gy)
        buf = new byte[33]; buf[0] = 0x03; sys(buf, 1, CV_GX);
        ocKey[noc] = buf; ocName[noc] = "oc_G_comp03"; noc++;
        // (Gx, Gy^lsb) uncompressed (off curve)
        buf = new byte[65]; buf[0] = 0x04; sys(buf, 1, CV_GX); sys(buf, 33, CV_GY); buf[64] ^= 0x01;
        ocKey[noc] = buf; ocName[noc] = "oc_G_badY"; noc++;
        // compressed X=0
        buf = new byte[33]; buf[0] = 0x02;
        ocKey[noc] = buf; ocName[noc] = "oc_X0"; noc++;
        // compressed X=1
        buf = new byte[33]; buf[0] = 0x02; buf[32] = 1;
        ocKey[noc] = buf; ocName[noc] = "oc_X1"; noc++;
        // uncompressed X=p ⇒ decode-reject
        buf = new byte[65]; buf[0] = 0x04; sys(buf, 1, CV_P); sys(buf, 33, CV_GY);
        ocKey[noc] = buf; ocName[noc] = "oc_Xeqp"; noc++;
        // compressed X=p ⇒ decode-reject
        buf = new byte[33]; buf[0] = 0x02; sys(buf, 1, CV_P);
        ocKey[noc] = buf; ocName[noc] = "oc_comp_Xeqp"; noc++;
        // bad prefix 0x05 ⇒ reject
        buf = new byte[33]; buf[0] = 0x05; sys(buf, 1, CV_GX);
        ocKey[noc] = buf; ocName[noc] = "oc_badprefix"; noc++;
        for (int i = 0; i < noc; i++) {
            int v = Secp.onCurve(ocKey[i]) ? 1 : 0;
            out.append(ocName[i]).append(" ").append(v).append("\n");
            comb.update((byte) v); comb.update(ocKey[i]);
        }

        // ── 3 & 4. RFC-6979 sign + ECDSA verify at the boundaries ────────────
        for (int i = 0; i < 4; i++) {
            byte[] priv = new byte[32];
            priv[28] = (byte) 0xC0; priv[29] = (byte) 0xFF; priv[30] = (byte) 0xEE; priv[31] = (byte) (0x10 + i);
            byte[] pub = Secp.pubkey(priv);
            if (pub == null) { out.append("sig").append(i).append(" PUBFAIL\n"); continue; }
            byte[] m = Sm.utf8("strategy-b curve vector " + i);
            byte[] h = Hashes.sha256(m);
            byte[][] rs = Secp.ecdsaSign(priv, h);
            if (rs == null) { out.append("sig").append(i).append(" SIGNFAIL\n"); continue; }
            byte[] r = rs[0], s = rs[1];
            byte[] der = Secp.derSig(r, s);
            out.append("sig").append(i)
               .append(" pub=").append(Hex.enc(pub))
               .append(" r=").append(Hex.enc(r))
               .append(" s=").append(Hex.enc(s))
               .append(" der=").append(Hex.enc(der)).append("\n");
            comb.update(pub); comb.update(r); comb.update(s); comb.update(der);

            // verify boundary battery
            byte[] zero = new byte[32];
            byte[] hbad = Arrays.copyOf(h, 32); hbad[0] ^= 0x01;
            byte[] hiS = new byte[32];                       // high-S = n - s (byte subtraction)
            { int borrow = 0;
              for (int k = 31; k >= 0; k--) {
                  int d = (CV_N[k] & 0xFF) - (s[k] & 0xFF) - borrow;
                  if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
                  hiS[k] = (byte) d;
              } }
            byte[] wrongpub = Arrays.copyOf(pub, 33); wrongpub[0] ^= 0x01;
            String[] vn = { "valid", "tamper", "r0", "s0", "rN", "sN", "highS", "wrongpk" };
            byte[][] vh = { h, hbad, h, h, h, h, h, h };
            byte[][] vr = { r, r, zero, r, CV_N, r, r, r };
            byte[][] vs = { s, s, s, zero, s, CV_N, hiS, s };
            byte[][] vp = { pub, pub, pub, pub, pub, pub, pub, wrongpub };
            out.append("ver").append(i);
            for (int t = 0; t < vn.length; t++) {
                int v = Secp.ecdsaVerify(vh[t], vr[t], vs[t], vp[t]) ? 1 : 0;
                out.append(" ").append(vn[t]).append("=").append(v);
                comb.update((byte) v);
            }
            out.append("\n");
        }

        // ── 5. tiny-key KAT: priv=1 ⇒ pub=G ; priv=2 ⇒ pub=2G ─────────────────
        { byte[] p1 = new byte[32]; p1[31] = 1; byte[] pk1 = Secp.pubkey(p1);
          out.append("priv1_pub=").append(Hex.enc(pk1)).append("\n"); comb.update(pk1);
          byte[] p2 = new byte[32]; p2[31] = 2; byte[] pk2 = Secp.pubkey(p2);
          out.append("priv2_pub=").append(Hex.enc(pk2)).append("\n"); comb.update(pk2); }

        // PRIMARY cross-language digest (sections 1–5)
        byte[] cd = comb.digest();
        out.append("combined ").append(Hex.enc(cd)).append("\n");

        // ── 6. end-to-end: real legacy sighash signing + attribute() ─────────
        MessageDigest e2e = sha256ctx();
        realEndToEnd(out, e2e);
        byte[] ed = e2e.digest();
        out.append("combined_e2e ").append(Hex.enc(ed)).append("\n");

        System.out.print(out);
    }

    // ── shared tx skeleton: 1 input (outpoint 0x11.. seq=FFFFFFFF), 1 output
    //    (value=100000, OP_RETURN), version 1, locktime 0. attribute()'s
    //    recomputed sighash equals the one we sign. ──────────────────────────
    private static Attrib.Tx skeleton(byte[] scriptSig) {
        Attrib.Tx t = new Attrib.Tx(); t.version = 1; t.locktime = 0;
        Attrib.In in = new Attrib.In();
        // C outpoint is 36 bytes all 0x11: txid[32]=0x11.., vout=0x11111111.
        in.prevTxid = new byte[32]; Arrays.fill(in.prevTxid, (byte) 0x11);
        in.prevVout = 0x11111111L;
        in.sequence = 0xFFFFFFFFL;
        in.scriptSig = scriptSig;
        t.ins.add(in);
        Attrib.Out o = new Attrib.Out();
        o.value = BigInteger.valueOf(100000); o.spk = new byte[]{0x6a};
        t.outs.add(o);
        return t;
    }
    // legacy sighash of the skeleton with the given scriptCode for input 0
    private static byte[] skelSighash(byte[] scriptCode) {
        Attrib.Tx sk = skeleton(new byte[0]);
        return Attrib.sighash(sk, 0, scriptCode);
    }

    private static void emitE2E(StringBuilder out, MessageDigest comb, String name, Attrib.Tx t) {
        Attrib.Result res = Attrib.attribute(t, 0);
        out.append(name).append(" ").append(res.status).append(":").append(Hex.enc(res.identity)).append("\n");
        comb.update((byte) res.status);
        comb.update(res.sighash);
        comb.update(res.identity);
    }

    static void realEndToEnd(StringBuilder out, MessageDigest comb) {
        Attrib.realCurve = true;
        try {
            // ── A. P2PKH, correctly signed ⇒ FOUND ───────────────────────────
            {
                byte[] priv = new byte[32]; priv[31] = 0x2A;     // priv = 42
                byte[] pub = Secp.pubkey(priv);
                byte[] h160 = Hashes.hash160(pub);
                byte[] sc = Attrib.p2pkhScript(h160);            // OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
                byte[] sh = skelSighash(sc);
                byte[][] rs = Secp.ecdsaSign(priv, sh);
                byte[] der = Secp.derSig(rs[0], rs[1]);
                byte[] ss = Fold.concat(Attrib.pushOf(der), Attrib.pushOf(pub));
                emitE2E(out, comb, "e2e_p2pkh_valid", skeleton(ss));
            }
            // ── B. P2PKH, WRONG key ⇒ verify-drop (status 2) ──────────────────
            {
                byte[] priv = new byte[32]; priv[31] = 0x2A;
                byte[] wrong = new byte[32]; wrong[31] = 0x2B;
                byte[] pub = Secp.pubkey(priv);
                byte[] h160 = Hashes.hash160(pub);
                byte[] sc = Attrib.p2pkhScript(h160);
                byte[] sh = skelSighash(sc);
                byte[][] rs = Secp.ecdsaSign(wrong, sh);          // wrong key signs
                byte[] der = Secp.derSig(rs[0], rs[1]);
                byte[] ss = Fold.concat(Attrib.pushOf(der), Attrib.pushOf(pub));
                emitE2E(out, comb, "e2e_p2pkh_wrongkey", skeleton(ss));
            }
            // ── C. 2-of-2 P2SH multisig, two correct in-order sigs ⇒ FOUND ────
            {
                byte[][] priv = new byte[2][32], pub = new byte[2][];
                for (int i = 0; i < 2; i++) { priv[i][31] = (byte) (0x50 + i); pub[i] = Secp.pubkey(priv[i]); }
                Buf rsB = new Buf();
                rsB.u8(0x52);                                     // OP_2
                for (int i = 0; i < 2; i++) rsB.u8(0x21).bytes(pub[i]);
                rsB.u8(0x52).u8(0xAE);                            // OP_2 OP_CHECKMULTISIG
                byte[] redeem = rsB.toBytes();
                byte[] sh = skelSighash(redeem);
                Buf ssB = new Buf(); ssB.u8(0x00);                // NULLDUMMY
                for (int i = 0; i < 2; i++) {
                    byte[][] rs = Secp.ecdsaSign(priv[i], sh);
                    ssB.bytes(Attrib.pushOf(Secp.derSig(rs[0], rs[1])));
                }
                ssB.bytes(Attrib.pushOf(redeem));
                emitE2E(out, comb, "e2e_multisig_valid", skeleton(ssB.toBytes()));
            }
        } finally {
            Attrib.realCurve = false;
        }
    }

    private static void sys(byte[] dst, int off, byte[] src) { System.arraycopy(src, 0, dst, off, src.length); }
}
