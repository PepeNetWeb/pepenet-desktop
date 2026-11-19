import java.math.BigInteger;
import java.util.*;

// §4 Stateless Identity & Attribution byte-logic (spec §4 + SPEC-conformance §13).
//
// raw tx bytes -> per input k: attribute(tx,k) = (status, sighash32, identity20).
//   status: 0 classify-drop · 1 on-curve-drop · 2 verify-drop · 3 found
//
// Everything that forks between languages is real byte manipulation (strict-DER,
// low-S, pubkey canonical encoding, minimal-push, P2SH-multisig template, in-order
// scan, legacy sighash incl. FindAndDelete, RIPEMD160 identity). Only the curve is
// abstracted by the pinned injected oracle (on_curve / verify).
//
// NOTE (register #8): the EXACT legacy-sighash preimage serialization is a spec-prose
// gap. This uses standard Bitcoin Core legacy sighash (4-byte LE hashtype suffix,
// standard tx serialization). The injected-oracle digests therefore can't be golden-
// matched without reading impls/c; the byte-logic (parse/DER/template/FaD/identity)
// and the RIPEMD KATs ARE independently validatable.
final class Attrib {

    // secp256k1 constants — named in the spec but their hex is in NEITHER doc
    // (register gap #11). Standard secp256k1 values supplied from outside the corpus.
    static final BigInteger SECP_P = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    static final BigInteger SECP_N = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    static final BigInteger SECP_N_HALF = SECP_N.shiftRight(1);

    static final int OP_0=0x00, OP_PUSHDATA1=0x4C, OP_PUSHDATA2=0x4D, OP_1=0x51, OP_16=0x60,
        OP_DUP=0x76, OP_EQUAL=0x87, OP_EQUALVERIFY=0x88, OP_HASH160=0xA9, OP_CHECKSIG=0xAC, OP_CHECKMULTISIG=0xAE;

    // ---- curve oracle selector (§4 Strategy B handoff seam) ----------------
    // false = injected pseudo-funcs (Tier-1 self-regression; the attrib/attrib-scenario/
    // selftest goldens), true = REAL secp256k1 (the attrib-curve end-to-end vectors).
    // attrib/attrib-scenario/selftest never flip this, so their digests stay identical.
    static boolean realCurve = false;

    static boolean onCurve(byte[] pubkey) {
        if (realCurve) return Secp.onCurve(pubkey);
        byte[] h = Hashes.sha256(Fold.concat(new byte[]{0x4F}, pubkey));
        return (h[0] & 0xFF) != 0x00;
    }
    static boolean ecdsaVerify(byte[] hash32, byte[] r32, byte[] s32, byte[] pubkey) {
        if (realCurve) return Secp.ecdsaVerify(hash32, r32, s32, pubkey);
        byte[] h = Hashes.sha256(Fold.concat(new byte[]{0x56}, hash32, r32, s32, pubkey));
        return (h[0] & 0xFF) >= 0x20;
    }

    // ---- raw tx model ------------------------------------------------------
    static final class In { byte[] prevTxid; long prevVout; byte[] scriptSig; long sequence; }
    static final class Out { BigInteger value; byte[] spk; }
    static final class Tx { long version; List<In> ins = new ArrayList<>(); List<Out> outs = new ArrayList<>(); long locktime; }

    static final class Cursor { byte[] b; int p; Cursor(byte[] b) { this.b = b; } }
    static long rdU32(Cursor c) { long v = Buf.u32(c.b, c.p); c.p += 4; return v; }
    static BigInteger rdU64(Cursor c) { BigInteger v = Buf.u64(c.b, c.p); c.p += 8; return v; }
    static long rdVarint(Cursor c) {
        int x = c.b[c.p++] & 0xFF;
        if (x < 0xFD) return x;
        if (x == 0xFD) { long v = (c.b[c.p] & 0xFFL) | ((c.b[c.p+1] & 0xFFL) << 8); c.p += 2; return v; }
        if (x == 0xFE) { long v = rdU32(c); return v; }
        long v = rdU64(c).longValueExact(); return v;
    }
    static byte[] rdBytes(Cursor c, int n) { byte[] r = Arrays.copyOfRange(c.b, c.p, c.p + n); c.p += n; return r; }

    // parse a legacy tx; returns null on a structural overrun (whole tx -> 0xFF)
    static Tx parseTx(byte[] raw) {
        try {
            Cursor c = new Cursor(raw);
            Tx t = new Tx();
            t.version = rdU32(c);
            long nin = rdVarint(c);
            if (nin == 0) return null;                 // legacy-only (no segwit marker collision)
            for (long i = 0; i < nin; i++) {
                In in = new In();
                in.prevTxid = rdBytes(c, 32);
                in.prevVout = rdU32(c);
                long sl = rdVarint(c);
                in.scriptSig = rdBytes(c, (int) sl);
                in.sequence = rdU32(c);
                t.ins.add(in);
            }
            long nout = rdVarint(c);
            for (long i = 0; i < nout; i++) {
                Out o = new Out();
                o.value = rdU64(c);
                long pl = rdVarint(c);
                o.spk = rdBytes(c, (int) pl);
                t.outs.add(o);
            }
            t.locktime = rdU32(c);
            if (c.p != raw.length) return null;        // trailing bytes -> unparseable
            return t;
        } catch (RuntimeException e) { return null; }
    }

    // ---- minimal-push script iterator (GetOp), enforcing minimal encoding --
    static final class Op { int opcode; byte[] data; int start; int end; } // data!=null for a push
    static List<Op> parseScript(byte[] s) {
        List<Op> ops = new ArrayList<>();
        int i = 0;
        while (i < s.length) {
            int op = s[i] & 0xFF; int start = i; i++;
            if (op < OP_PUSHDATA1) {                   // direct push 1..75
                if (i + op > s.length) return null;
                byte[] d = Arrays.copyOfRange(s, i, i + op); i += op;
                Op o = new Op(); o.opcode = op; o.data = d; o.start = start; o.end = i; ops.add(o);
            } else if (op == OP_PUSHDATA1) {
                if (i + 1 > s.length) return null;
                int n = s[i] & 0xFF; i++;
                if (n < 76) return null;               // non-minimal: must use direct push
                if (i + n > s.length) return null;
                byte[] d = Arrays.copyOfRange(s, i, i + n); i += n;
                Op o = new Op(); o.opcode = op; o.data = d; o.start = start; o.end = i; ops.add(o);
            } else if (op == OP_PUSHDATA2) {
                if (i + 2 > s.length) return null;
                int n = (s[i] & 0xFF) | ((s[i+1] & 0xFF) << 8); i += 2;
                if (n < 256 || n > 520) return null;   // non-minimal / over-range
                if (i + n > s.length) return null;
                byte[] d = Arrays.copyOfRange(s, i, i + n); i += n;
                Op o = new Op(); o.opcode = op; o.data = d; o.start = start; o.end = i; ops.add(o);
            } else {                                   // a non-push opcode
                Op o = new Op(); o.opcode = op; o.data = null; o.start = start; o.end = i; ops.add(o);
            }
        }
        return ops;
    }

    // ---- strict-DER + low-S + SIGHASH_ALL byte ----------------------------
    // sig = DER(r,s) ‖ hashtype; require hashtype==0x01 and S<=N/2.
    static boolean validSig(byte[] sig) {
        int n = sig.length;
        if (n < 9 || n > 73) return false;
        if ((sig[n-1] & 0xFF) != 0x01) return false;   // SIGHASH_ALL only (Rule 3)
        int derLen = n - 1;
        if ((sig[0] & 0xFF) != 0x30) return false;
        if ((sig[1] & 0xFF) != derLen - 2) return false;
        if ((sig[2] & 0xFF) != 0x02) return false;
        int lenR = sig[3] & 0xFF;
        if (lenR == 0) return false;
        if (4 + lenR + 2 > derLen) return false;
        if ((sig[4] & 0x80) != 0) return false;        // R negative
        if (lenR > 1 && sig[4] == 0x00 && (sig[5] & 0x80) == 0) return false; // non-minimal pad
        int sOff = 4 + lenR;
        if ((sig[sOff] & 0xFF) != 0x02) return false;
        int lenS = sig[sOff+1] & 0xFF;
        if (lenS == 0) return false;
        if (sOff + 2 + lenS != derLen) return false;   // exact, no trailing
        int sValOff = sOff + 2;
        if ((sig[sValOff] & 0x80) != 0) return false;  // S negative
        if (lenS > 1 && sig[sValOff] == 0x00 && (sig[sValOff+1] & 0x80) == 0) return false; // non-minimal pad
        // low-S: S <= N/2
        BigInteger S = new BigInteger(1, Arrays.copyOfRange(sig, sValOff, sValOff + lenS));
        if (S.compareTo(SECP_N_HALF) > 0) return false;
        return true;
    }
    // (r32, s32) big-endian fixed-width for the oracle
    static byte[][] rs32(byte[] sig) {
        int lenR = sig[3] & 0xFF, sOff = 4 + lenR, lenS = sig[sOff+1] & 0xFF;
        BigInteger R = new BigInteger(1, Arrays.copyOfRange(sig, 4, 4 + lenR));
        BigInteger S = new BigInteger(1, Arrays.copyOfRange(sig, sOff + 2, sOff + 2 + lenS));
        return new byte[][]{ be32(R), be32(S) };
    }
    static byte[] be32(BigInteger v) {
        byte[] r = new byte[32];
        byte[] b = v.toByteArray();
        int src = Math.max(0, b.length - 32), len = Math.min(32, b.length);
        System.arraycopy(b, src, r, 32 - len, len);
        return r;
    }

    // ---- canonical pubkey (Rule 4) ----------------------------------------
    static boolean canonicalPubkey(byte[] pk) {
        if (pk.length == 33 && (pk[0] == 0x02 || pk[0] == 0x03)) {
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(pk, 1, 33));
            return x.compareTo(SECP_P) < 0;
        }
        if (pk.length == 65 && pk[0] == 0x04) {
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(pk, 1, 33));
            BigInteger y = new BigInteger(1, Arrays.copyOfRange(pk, 33, 65));
            return x.compareTo(SECP_P) < 0 && y.compareTo(SECP_P) < 0;
        }
        return false;   // hybrid 0x06/0x07, bad length, wrong prefix
    }

    // ---- legacy sighash incl. FindAndDelete --------------------------------
    // standard Bitcoin legacy sighash for input k, scriptCode = subscript (FaD applied).
    static byte[] sighash(Tx t, int k, byte[] scriptCode) {
        Buf b = new Buf();
        b.u32(t.version);
        b.bytes(varint(t.ins.size()));
        for (int i = 0; i < t.ins.size(); i++) {
            In in = t.ins.get(i);
            b.bytes(in.prevTxid).u32(in.prevVout);
            byte[] sc = (i == k) ? scriptCode : new byte[0];
            b.bytes(varint(sc.length)).bytes(sc);
            b.u32(in.sequence);
        }
        b.bytes(varint(t.outs.size()));
        for (Out o : t.outs) { b.u64(o.value).bytes(varint(o.spk.length)).bytes(o.spk); }
        b.u32(t.locktime);
        b.u32(0x01);                    // hashtype SIGHASH_ALL as 4-byte LE (0x01000000)
        return Hashes.dsha256(b.toBytes());
    }
    static byte[] varint(long n) {
        if (n < 0xFD) return new byte[]{(byte) n};
        if (n <= 0xFFFF) return new byte[]{(byte) 0xFD, (byte) n, (byte) (n >> 8)};
        if (n <= 0xFFFFFFFFL) { Buf b = new Buf(); b.u8(0xFE).u32(n); return b.toBytes(); }
        Buf b = new Buf(); b.u8(0xFF).i64(n); return b.toBytes();
    }
    // Bitcoin Core CScript::FindAndDelete(script, pattern): remove every boundary-aligned
    // occurrence of `pattern` (a full push) via GetOp iteration.
    static byte[] findAndDelete(byte[] script, byte[] pattern) {
        if (pattern.length == 0) return script;
        List<Op> ops = parseScript(script);
        if (ops == null) return script;            // unparseable -> leave as-is
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (Op o : ops) {
            byte[] chunk = Arrays.copyOfRange(script, o.start, o.end);
            if (!Arrays.equals(chunk, pattern)) out.write(chunk, 0, chunk.length);
        }
        return out.toByteArray();
    }
    // the scriptSig push bytes for a signature (so FaD can target it): minimal push of sig
    static byte[] pushOf(byte[] data) {
        Buf b = new Buf();
        if (data.length < OP_PUSHDATA1) b.u8(data.length);
        else if (data.length <= 0xFF) b.u8(OP_PUSHDATA1).u8(data.length);
        else b.u8(OP_PUSHDATA2).u8(data.length & 0xFF).u8((data.length >> 8) & 0xFF);
        b.bytes(data);
        return b.toBytes();
    }

    // ---- attribute one input ----------------------------------------------
    static final class Result { int status; byte[] sighash = new byte[32]; byte[] identity = new byte[20]; }

    static Result attribute(Tx t, int k) {
        Result r = new Result();
        byte[] ss = t.ins.get(k).scriptSig;
        List<Op> ops = parseScript(ss);
        if (ops == null) { r.status = 0; return r; }

        // P2PKH: exactly [push sig][push pubkey]
        if (ops.size() == 2 && ops.get(0).data != null && ops.get(1).data != null) {
            byte[] sig = ops.get(0).data, pk = ops.get(1).data;
            if (validSig(sig) && canonicalPubkey(pk)) {
                byte[] identity = Hashes.hash160(pk);
                System.arraycopy(identity, 0, r.identity, 0, 20);
                byte[] scriptCode = p2pkhScript(identity);
                scriptCode = findAndDelete(scriptCode, pushOf(sig)); // inert (hash only), but applied
                byte[] sh = sighash(t, k, scriptCode);
                System.arraycopy(sh, 0, r.sighash, 0, 32);           // sighash formed BEFORE the on-curve gate (matches impls/c)
                if (!onCurve(pk)) { r.status = 1; return r; }
                byte[][] rs = rs32(sig);
                if (!ecdsaVerify(sh, rs[0], rs[1], pk)) { r.status = 2; return r; }
                r.status = 3; return r;
            }
            // fall through: not a valid P2PKH; try multisig shape (won't match) -> classify-drop
        }

        // P2SH multisig: OP_0 [push sig]xm [push redeemScript]. NULLDUMMY = exactly OP_0
        // (parsed as a zero-length push: opcode 0x00, empty data).
        if (ops.size() >= 3 && ops.get(0).opcode == OP_0 && ops.get(0).data != null && ops.get(0).data.length == 0) {
            Op last = ops.get(ops.size() - 1);
            if (last.data == null) { r.status = 0; return r; }
            byte[] redeem = last.data;
            Multisig ms = parseMultisig(redeem);
            if (ms == null) { r.status = 0; return r; }
            int nSig = ops.size() - 2;            // between OP_0 and redeemScript
            if (nSig != ms.m) { r.status = 0; return r; }
            byte[][] sigs = new byte[nSig][];
            for (int i = 0; i < nSig; i++) { Op o = ops.get(1 + i); if (o.data == null) { r.status = 0; return r; } sigs[i] = o.data; }
            for (byte[] sig : sigs) if (!validSig(sig)) { r.status = 0; return r; }
            // canonical keys already enforced by parseMultisig; on-curve check per key
            byte[] identity = Hashes.hash160(redeem);
            System.arraycopy(identity, 0, r.identity, 0, 20);
            // sighash (scriptCode = redeemScript, FaD each checked sig push) is formed BEFORE the
            // on-curve gate (matches impls/c), so an on-curve-drop still carries the real sighash
            byte[] scriptCode = redeem;
            for (byte[] sig : sigs) scriptCode = findAndDelete(scriptCode, pushOf(sig));
            byte[] sh = sighash(t, k, scriptCode);
            System.arraycopy(sh, 0, r.sighash, 0, 32);
            for (byte[] key : ms.keys) if (!onCurve(key)) { r.status = 1; return r; }
            // in-order scan: m sigs against n keys in order
            int si = 0;
            for (int ki = 0; ki < ms.keys.length && si < nSig; ki++) {
                byte[][] rs = rs32(sigs[si]);
                if (ecdsaVerify(sh, rs[0], rs[1], ms.keys[ki])) si++;
            }
            if (si == nSig) { r.status = 3; return r; }
            r.status = 2; return r;             // threshold not met after scan
        }

        r.status = 0; return r;
    }

    static byte[] p2pkhScript(byte[] h20) {
        Buf b = new Buf();
        b.u8(OP_DUP).u8(OP_HASH160).u8(20).bytes(h20).u8(OP_EQUALVERIFY).u8(OP_CHECKSIG);
        return b.toBytes();
    }

    static final class Multisig { int m, n; byte[][] keys; }
    // redeemScript = OP_m (0x21 33-key)xn OP_n OP_CHECKMULTISIG, compressed keys only, 1<=m<=n<=15
    static Multisig parseMultisig(byte[] rs) {
        List<Op> ops = parseScript(rs);
        if (ops == null || ops.size() < 4) return null;
        Op first = ops.get(0), nOp = ops.get(ops.size() - 2), cms = ops.get(ops.size() - 1);
        if (first.data != null || nOp.data != null || cms.data != null) return null;
        if (cms.opcode != OP_CHECKMULTISIG) return null;
        int m = opN(first.opcode), n = opN(nOp.opcode);
        if (m < 1 || n < 1 || n > 15 || m > n) return null;
        int keyCount = ops.size() - 3;
        if (keyCount != n) return null;
        byte[][] keys = new byte[n][];
        for (int i = 0; i < n; i++) {
            Op o = ops.get(1 + i);
            if (o.data == null || o.opcode != 0x21 || o.data.length != 33) return null; // compressed, direct 0x21 push
            if (!(o.data[0] == 0x02 || o.data[0] == 0x03)) return null;
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(o.data, 1, 33));
            if (x.compareTo(SECP_P) >= 0) return null;
            keys[i] = o.data;
        }
        Multisig ms = new Multisig(); ms.m = m; ms.n = n; ms.keys = keys; return ms;
    }
    static int opN(int op) { if (op >= OP_1 && op <= OP_16) return op - OP_1 + 1; return -1; }

    // serialize a legacy tx (inverse of parseTx) — for building test vectors
    static byte[] serialize(Tx t) {
        Buf b = new Buf();
        b.u32(t.version);
        b.bytes(varint(t.ins.size()));
        for (In in : t.ins) b.bytes(in.prevTxid).u32(in.prevVout).bytes(varint(in.scriptSig.length)).bytes(in.scriptSig).u32(in.sequence);
        b.bytes(varint(t.outs.size()));
        for (Out o : t.outs) b.u64(o.value).bytes(varint(o.spk.length)).bytes(o.spk);
        b.u32(t.locktime);
        return b.toBytes();
    }
}
