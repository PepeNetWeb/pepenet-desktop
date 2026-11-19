using System;

namespace Pepenet;

public enum DecodeKind { Ignore, Action }

/// <summary>Result of the strict, fail-closed wire decode (§9). Never throws.</summary>
public readonly struct Decoded
{
    public readonly DecodeKind Kind;
    public readonly byte Opcode;     // meaningful only when Kind==Action
    public readonly byte[] Body;     // payload[4:] for Action; empty for Ignore

    private Decoded(DecodeKind kind, byte opcode, byte[] body) { Kind = kind; Opcode = opcode; Body = body; }

    public static readonly Decoded Ignore = new(DecodeKind.Ignore, 0, Array.Empty<byte>());
    public static Decoded Action(byte opcode, byte[] body) => new(DecodeKind.Action, opcode, body);
}

public static class Decoder
{
    /// <summary>
    /// sm_decode_payload (SPEC-conformance §9). Names-only demux: prefix 0xFF 'P' 'N'
    /// + opcode 0x01..0x0F with valid fields → ACTION; everything else (UTF-8 noise,
    /// overlay band, malformed) → IGNORE. <paramref name="value"/> is unused by the
    /// demux (kept for call-site uniformity).
    /// </summary>
    public static Decoded Decode(byte[] payload, ulong value)
    {
        _ = value;
        if (payload.Length >= 4 && payload[0] == K.PFX0 && payload[1] == K.PFX1 && payload[2] == K.PFX2)
        {
            byte op = payload[3];
            int bl = payload.Length - 4;
            byte[] body = new byte[bl];
            Array.Copy(payload, 4, body, 0, bl);
            return ValidateAction(op, body) ? Decoded.Action(op, body) : Decoded.Ignore;
        }
        return Decoded.Ignore;
    }

    private static bool ValidateAction(byte op, byte[] b)
    {
        int bl = b.Length;
        switch (op)
        {
            case K.OP_COMMIT:
                return bl == 32;
            case K.OP_CLAIM:
                return bl >= 33 && bl <= 64 && ValidName(b, 32, bl - 32);  // salt32 + name1..32
            case K.OP_RENEW:
                return bl == 0 || bl == 5 || (bl >= 6 && bl <= K.BODY_MAX); // {0,5}∪[6,BODY_MAX]
            case K.OP_TRANSFER:
                return bl == 20 || (bl >= 26 && bl <= K.BODY_MAX);         // 20 ∪ [26,BODY_MAX]
            case K.OP_SELL:
                return bl >= 13 && bl <= 44 && ValidName(b, 12, bl - 12);  // price8+window4+name1..32
            case K.OP_RENEW_NAME:
            case K.OP_RELEASE_NAME:
            case K.OP_RESERVE:
            case K.OP_SETTLE:
            case K.OP_PAY:
                return bl >= 1 && bl <= 32 && ValidName(b, 0, bl);         // name 1..32
            case K.OP_TRANSFER_NAME:
                return bl >= 21 && bl <= 52 && ValidName(b, 20, bl - 20);  // target20 + name1..32
            case K.OP_RELEASE:
                return bl >= 6 && bl <= K.BODY_MAX;                        // anchor5 + flags1..FLAGS_MAX
            case K.OP_SELL_TO:
                return bl >= 29 && bl <= 60 && ValidName(b, 28, bl - 28);  // price8+buyer20+name1..32
            case K.OP_AS:
                return bl == 1;
            case K.OP_TRADE:
                return ValidateTrade(b);
            default:
                return false; // opcode outside 0x01..0x0F
        }
    }

    /// <summary>TRADE: bl≥5, exactly one 0x2C, both sides §3.1-valid (1..32). (§9/§3.10)</summary>
    private static bool ValidateTrade(byte[] b)
    {
        if (b.Length < 5) return false;
        // [idxA:1][idxB:1] then nameA,nameB
        int commaCount = 0, commaPos = -1;
        for (int i = 2; i < b.Length; i++)
            if (b[i] == 0x2C) { commaCount++; commaPos = i; }
        if (commaCount != 1) return false;
        int aStart = 2, aLen = commaPos - aStart;
        int bStart = commaPos + 1, bLen = b.Length - bStart;
        return ValidName(b, aStart, aLen) && ValidName(b, bStart, bLen);
    }

    /// <summary>
    /// Name validation §3.1: charset [a-z0-9-], length 1..32, byte-exact, NO case-folding,
    /// plus structural rules (RFC-1123 / IDNA): no leading/trailing hyphen; no `--` at
    /// positions 3–4 (kills xn-- and every ACE prefix). Every consensus-valid name is a
    /// safe hostname label.
    /// </summary>
    public static bool ValidName(byte[] b, int off, int len)
    {
        if (len < 1 || len > 32) return false;
        if (off < 0 || off + len > b.Length) return false;
        for (int i = 0; i < len; i++)
        {
            byte c = b[off + i];
            bool ok = (c >= (byte)'a' && c <= (byte)'z') ||
                      (c >= (byte)'0' && c <= (byte)'9') ||
                      (c == (byte)'-');
            if (!ok) return false;
        }
        // structural: no leading/trailing hyphen; no `--` at positions 3–4
        if (b[off] == (byte)'-' || b[off + len - 1] == (byte)'-') return false;
        if (len >= 4 && b[off + 2] == (byte)'-' && b[off + 3] == (byte)'-') return false;
        return true;
    }
}
