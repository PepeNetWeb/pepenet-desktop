using System;
using System.Collections.Generic;

namespace Pepenet;

// ---- Transaction input/output model (abstract; real §4 byte-logic is the attrib layer) ----

/// <summary>A transaction input. In the abstract fold, identity is pre-resolved:
/// the input carries its §4 hash160 + script type and whether it signs SIGHASH_ALL.
/// Real raw-tx attribution is the separate `attrib` surface (Attribution.cs).</summary>
public sealed class Input
{
    public byte[] H160 = new byte[20];
    public byte Type = K.TYPE_P2PKH;
    public bool SighashAll = true;
}

public enum OutKind { Carrier, Spendable }

/// <summary>A transaction output. Carrier = an OP_RETURN single-push payload + value.
/// Spendable = a payable output addressed by (h160, type) + value.</summary>
public sealed class Out
{
    public OutKind Kind;
    public byte[] Payload = Array.Empty<byte>(); // Carrier
    public byte[] H160 = new byte[20];           // Spendable
    public byte Type = K.TYPE_P2PKH;             // Spendable
    public ulong Value;

    public static Out Carrier(byte[] payload, ulong value) =>
        new() { Kind = OutKind.Carrier, Payload = payload, Value = value };
    public static Out Spend(byte[] h160, byte type, ulong value) =>
        new() { Kind = OutKind.Spendable, H160 = h160, Type = type, Value = value };
}

public sealed class Tx
{
    public List<Input> Inputs = new();
    public List<Out> Outputs = new(); // vout order = list order
}

public sealed class Block
{
    public long Height;
    public long Mtp;     // MTP(H) supplied per block (abstract SM models mtp as a per-block given, SPEC-conformance §10)
    public ulong Rate;   // per-block rent rate (generator injects; oracle is a separate tested function)
    public List<Tx> Txs = new();
}

// ---- Fold state rows ----

/// <summary>A name row. All market fields are physically reset to zero when a state
/// is left, so two indexers at the same logical st serialize identical bytes (§4 conformance).</summary>
public sealed class NameRow
{
    public byte[] Name = Array.Empty<byte>();
    public byte[] Owner = new byte[20];
    public byte St = K.ST_OWNED;
    public long LeaseExpiry;

    // Market fields (zero unless active):
    public byte[] Seller = new byte[20];
    public byte SellerType;
    public ulong Price;
    public long OfferExpiry;
    public byte[] Buyer = new byte[20]; // reserver (RESERVED) or directed buyer (OFFERED)
    public ulong BurnLeg;
    public ulong PayLeg;
    public long ReserveExpiry;

    public bool Locked => St == K.ST_LISTED || St == K.ST_OFFERED || St == K.ST_RESERVED;

    public void ResetMarket()
    {
        Seller = new byte[20]; SellerType = 0; Price = 0; OfferExpiry = 0;
        Buyer = new byte[20]; BurnLeg = 0; PayLeg = 0; ReserveExpiry = 0;
    }
}

public sealed class CommitRow
{
    public byte[] Commitment = new byte[32];
    public long CommitHeight;
    public uint TxIndex;
    public long CommitTime;
}
