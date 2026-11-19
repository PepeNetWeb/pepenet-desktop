import java.math.BigInteger;
import java.util.Arrays;

// Strict wire codec — derived from SPEC-conformance §9 + spec §1/§2/§3.1.
//
// decode(payload, value) -> ACTION | IGNORE, fail-closed (no POST). encode(Action)
// is the canonical inverse (used by the generators + round-trip selftest). The
// single-minimal-push carrier rule (§1) is handled one layer up (Output gives us
// the already-extracted lone-push payload, or null if not a single minimal push).
final class Wire {

    enum Kind { ACTION, IGNORE }

    static final class Decoded {
        final Kind kind;
        final Action action;
        Decoded(Kind k, Action a) { kind = k; action = a; }
        static final Decoded IGNORE = new Decoded(Kind.IGNORE, null);
        static Decoded action(Action a) { return new Decoded(Kind.ACTION, a); }
    }

    // ---- decode ------------------------------------------------------------

    static Decoded decode(byte[] p, BigInteger value) {
        // value unused by demux (kept for call-site uniformity); everything non-action → IGNORE
        if (p.length >= 4 && p[0] == Const.P0 && p[1] == Const.P1 && p[2] == Const.P2) {
            Action a = decodeAction(p);
            return a != null ? Decoded.action(a) : Decoded.IGNORE; // malformed / unknown opcode
        }
        return Decoded.IGNORE;
    }

    private static Action decodeAction(byte[] p) {
        int op = p[3] & 0xFF;
        if (op < Const.OP_MIN || op > Const.OP_MAX) return null;
        int bl = p.length - 4;
        byte[] b = Arrays.copyOfRange(p, 4, p.length);
        Action a = new Action();
        a.op = op;
        switch (op) {
            case Const.COMMIT -> {
                if (bl != 32) return null;
                a.commitment = Arrays.copyOfRange(b, 0, 32);
            }
            case Const.CLAIM -> {
                if (bl < 33 || bl > 64) return null;    // salt32 + name1..32
                a.salt = Arrays.copyOfRange(b, 0, 32);
                a.name = Arrays.copyOfRange(b, 32, bl);
                if (!validName(a.name)) return null;
            }
            case Const.RENEW -> {
                if (bl == 0) { a.renewMode = 0; }                       // all
                else if (bl == 5) { a.renewMode = 1; a.anchor = Buf.u40(b, 0); } // all-safe
                else if (bl >= 6 && bl <= Const.BODY_MAX) {              // selective: anchor5 + flags 1..FLAGS_MAX
                    a.renewMode = 2; a.anchor = Buf.u40(b, 0);
                    a.flags = Arrays.copyOfRange(b, 5, bl);
                } else return null;
            }
            case Const.TRANSFER -> {
                if (bl == 20) { a.tTarget = Arrays.copyOfRange(b, 0, 20); a.selective = false; } // all
                else if (bl >= 26 && bl <= Const.BODY_MAX) {             // selective: target20 + anchor5 + flags 1..FLAGS_XFER_MAX
                    a.tTarget = Arrays.copyOfRange(b, 0, 20);
                    a.anchor = Buf.u40(b, 20);
                    a.flags = Arrays.copyOfRange(b, 25, bl);
                    a.selective = true;
                } else return null;
            }
            case Const.SELL -> {
                if (bl < 13 || bl > 44) return null;    // price8 + window4 + name1..32
                a.price = Buf.u64(b, 0);
                a.window = Buf.u32(b, 8);
                a.name = Arrays.copyOfRange(b, 12, bl);
                if (!validName(a.name)) return null;
            }
            case Const.RENEW_NAME, Const.RELEASE_NAME, Const.RESERVE, Const.SETTLE, Const.PAY -> {
                if (bl < 1 || bl > 32) return null;     // name1..32
                a.name = Arrays.copyOfRange(b, 0, bl);
                if (!validName(a.name)) return null;
            }
            case Const.TRANSFER_NAME -> {
                if (bl < 21 || bl > 52) return null;    // target20 + name1..32
                a.tTarget = Arrays.copyOfRange(b, 0, 20);
                a.name = Arrays.copyOfRange(b, 20, bl);
                if (!validName(a.name)) return null;
            }
            case Const.RELEASE -> {
                if (bl < 6 || bl > Const.BODY_MAX) return null;          // anchor5 + flags 1..FLAGS_MAX
                a.anchor = Buf.u40(b, 0);
                a.flags = Arrays.copyOfRange(b, 5, bl);
            }
            case Const.SELL_TO -> {
                if (bl < 29 || bl > 60) return null;    // price8 + buyer20 + name1..32
                a.price = Buf.u64(b, 0);
                a.buyer = Arrays.copyOfRange(b, 8, 28);
                a.name = Arrays.copyOfRange(b, 28, bl);
                if (!validName(a.name)) return null;
            }
            case Const.AS -> {
                if (bl != 1) return null;
                a.asIndex = b[0] & 0xFF;
            }
            case Const.TRADE -> {
                if (bl < 5) return null;
                a.idxA = b[0] & 0xFF;
                a.idxB = b[1] & 0xFF;
                byte[] rest = Arrays.copyOfRange(b, 2, bl);
                int comma = -1, count = 0;
                for (int i = 0; i < rest.length; i++) if (rest[i] == 0x2C) { count++; comma = i; }
                if (count != 1) return null;                            // exactly one comma
                a.nameA = Arrays.copyOfRange(rest, 0, comma);
                a.nameB = Arrays.copyOfRange(rest, comma + 1, rest.length);
                if (!validName(a.nameA) || !validName(a.nameB)) return null;
            }
            default -> { return null; }   // opcode out of 0x01..0x0F
        }
        return a;
    }

    // ---- encode (canonical inverse) ----------------------------------------

    static byte[] encode(Action a) {
        Buf body = new Buf();
        switch (a.op) {
            case Const.COMMIT -> body.bytes(a.commitment);
            case Const.CLAIM -> body.bytes(a.salt).bytes(a.name);
            case Const.RENEW -> {
                if (a.renewMode == 1) body.bytes(le40(a.anchor));
                else if (a.renewMode == 2) body.bytes(le40(a.anchor)).bytes(a.flags);
            }
            case Const.TRANSFER -> {
                body.bytes(a.tTarget);
                if (a.selective) body.bytes(le40(a.anchor)).bytes(a.flags);
            }
            case Const.SELL -> body.u64(a.price).u32(a.window).bytes(a.name);
            case Const.RENEW_NAME, Const.RELEASE_NAME, Const.RESERVE, Const.SETTLE, Const.PAY -> body.bytes(a.name);
            case Const.TRANSFER_NAME -> body.bytes(a.tTarget).bytes(a.name);
            case Const.RELEASE -> body.bytes(le40(a.anchor)).bytes(a.flags);
            case Const.SELL_TO -> body.u64(a.price).bytes(a.buyer).bytes(a.name);
            case Const.AS -> body.u8(a.asIndex);
            case Const.TRADE -> body.u8(a.idxA).u8(a.idxB).bytes(a.nameA).u8(0x2C).bytes(a.nameB);
            default -> throw new IllegalStateException("encode op " + a.op);
        }
        byte[] bb = body.toBytes();
        Buf out = new Buf();
        out.u8(0xFF).u8(0x50).u8(0x4E).u8(a.op).bytes(bb);
        return out.toBytes();
    }

    static byte[] le40(long v) {
        byte[] r = new byte[5];
        for (int i = 0; i < 5; i++) r[i] = (byte) (v >>> (8 * i));
        return r;
    }

    // ---- validators --------------------------------------------------------

    // §3.1: [a-z0-9-], 1..32; no leading/trailing hyphen; no `--` at positions 3–4
    // (kills xn-- and every ACE prefix). Every consensus-valid name is a safe hostname label.
    static boolean validName(byte[] n) {
        if (n.length < 1 || n.length > 32) return false;
        for (byte x : n) {
            int c = x & 0xFF;
            boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
            if (!ok) return false;
        }
        if ((n[0] & 0xFF) == '-' || (n[n.length - 1] & 0xFF) == '-') return false;
        if (n.length >= 4 && (n[2] & 0xFF) == '-' && (n[3] & 0xFF) == '-') return false;
        return true;
    }
}
