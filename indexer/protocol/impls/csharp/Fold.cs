using System;
using System.Collections.Generic;
using System.Buffers.Binary;

namespace Pepenet;

/// <summary>
/// The deterministic fold (§3 + §5). A single forward pass: pre-block
/// time-triggered transitions, then txs in (tx_index, vout) order.
/// Identity is pre-resolved (abstract); the real §4 byte-logic is Attribution.cs.
/// Names-only: only name-action carriers mutate state.
/// </summary>
public sealed class Fold
{
    public readonly long ActivationHeight;

    // Live state (names + commits + muts — the digested tables).
    public readonly Dictionary<string, NameRow> Names = new();          // key = name as Latin1 string
    public readonly List<CommitRow> Commits = new();
    public readonly Dictionary<string, long> Muts = new();               // key = hex(owner20)
    public readonly Dictionary<string, byte[]> MutOwnerBytes = new();

    // Per-block claim displacement scratch (reset each begin_block; NOT digested).
    private readonly Dictionary<string, (long ch, uint ctx, byte[] owner)> _claimScratch = new();

    public Fold(long activationHeight = 0) { ActivationHeight = activationHeight; }

    // ---------------- driver ----------------

    public void ApplyBlock(Block blk)
    {
        PreBlock(blk.Height, blk.Mtp);
        _claimScratch.Clear();
        for (int ti = 0; ti < blk.Txs.Count; ti++)
            ApplyTx(blk.Txs[ti], blk.Height, blk.Mtp, blk.Rate, ti);
    }

    public void ApplyBlocks(IEnumerable<Block> blocks)
    {
        foreach (var b in blocks) ApplyBlock(b);
    }

    /// <summary>Apply a single tx in isolation at (height, mtp, rate) with the given tx_index.
    /// Used by the `meta` mode to inject an inert tx without re-running pre-block logic.</summary>
    public void ApplyOneTx(Tx tx, long height, long mtp, ulong rate, int txIndex)
        => ApplyTx(tx, height, mtp, rate, txIndex);

    /// <summary>Reset EVERY digested field/collection to its empty/zero state, so a fresh
    /// fold can be rebuilt in place. Needed by reorg/reorgfuzz clear-and-rebuild. The
    /// per-block claim scratch is also cleared (it is never digested but must not leak).</summary>
    public void Clear()
    {
        Names.Clear();
        Commits.Clear();
        Muts.Clear();
        MutOwnerBytes.Clear();
        _claimScratch.Clear();
    }

    // ---------------- pre-block time-triggered transitions ----------------

    private void PreBlock(long height, long mtp)
    {
        // Iterate names in lex order for determinism (distinct names are independent).
        foreach (var name in SortedNameKeys())
        {
            if (!Names.TryGetValue(name, out var r)) continue;

            // 1. reserve_expiry: RESERVED → LISTED (exclusive bound: revert when !(MTP < reserve_expiry)).
            if (r.St == K.ST_RESERVED && mtp >= r.ReserveExpiry)
            {
                r.St = K.ST_LISTED;
                r.Buyer = new byte[20]; r.BurnLeg = 0; r.PayLeg = 0; r.ReserveExpiry = 0; // keep listing fields
            }
            // 2. offer_expiry: LISTED or OFFERED → OWNED (name was always seller's; no bump).
            if ((r.St == K.ST_LISTED || r.St == K.ST_OFFERED) && mtp >= r.OfferExpiry)
            {
                r.St = K.ST_OWNED;
                r.ResetMarket();
            }
            // 3. lease_expiry: lapse → remove, stamp owner mutation to connecting height H.
            if (mtp >= r.LeaseExpiry)
            {
                Bump(r.Owner, height);
                Names.Remove(name);
            }
        }

        // COMMIT_EXPIRY pruning (independent; inclusive window — prune once MTP > commit_time+COMMIT_EXPIRY).
        Commits.RemoveAll(c => mtp > c.CommitTime + K.COMMIT_EXPIRY);
    }

    // ---------------- per-tx ----------------

    private void ApplyTx(Tx tx, long height, long mtp, ulong rate, int txIndex)
    {
        // Acting identity: vin[0] if it signs SIGHASH_ALL (Rule 3), else ⊥.
        byte[]? actor = ActorOf(tx, 0);
        byte actorType = actor != null ? tx.Inputs[0].Type : (byte)0;

        bool[] consumed = new bool[tx.Outputs.Count];

        for (int vout = 0; vout < tx.Outputs.Count; vout++)
        {
            var o = tx.Outputs[vout];
            if (o.Kind != OutKind.Carrier) continue; // spendable outputs are matched by the market ops

            Decoded d = Decoder.Decode(o.Payload, o.Value);
            if (d.Kind != DecodeKind.Action) continue; // IGNORE

            byte op = d.Opcode;

            // Forward-only activation gate (§3.0): all ops gate at one height.
            if (height < ActivationHeight) continue;

            if (op == K.OP_AS)
            {
                int k = d.Body[0];
                actor = ActorOf(tx, k);
                actorType = actor != null ? tx.Inputs[k].Type : (byte)0;
                continue;
            }

            if (op == K.OP_TRADE)
            {
                DispatchTrade(tx, d.Body, height); // never consults `actor`
                continue;
            }

            // Every other op acts as the acting identity.
            if (actor == null) continue; // ⊥ ⇒ drop

            DispatchAction(op, d.Body, o.Value, actor, actorType, tx, consumed, height, mtp, rate, txIndex);
        }
    }

    /// <summary>Returns the input's hash160 if vin[k] exists and signs SIGHASH_ALL, else null (⊥).</summary>
    private static byte[]? ActorOf(Tx tx, int k)
    {
        if (k < 0 || k >= tx.Inputs.Count) return null;
        var inp = tx.Inputs[k];
        if (!inp.SighashAll) return null; // §4 Rule 3
        return inp.H160;
    }

    // ---------------- opcode dispatch ----------------

    private void DispatchAction(byte op, byte[] body, ulong value, byte[] actor, byte actorType,
        Tx tx, bool[] consumed, long height, long mtp, ulong rate, int txIndex)
    {
        switch (op)
        {
            case K.OP_COMMIT:    Commit(body, height, mtp, txIndex); break;
            case K.OP_CLAIM:     Claim(body, value, actor, rate, height, mtp); break;
            case K.OP_RENEW:     Renew(body, value, actor, rate, height, mtp); break;
            case K.OP_TRANSFER:  Transfer(body, actor, height); break;
            case K.OP_RELEASE:   Release(body, actor, height); break;
            case K.OP_RENEW_NAME:    RenewName(body, value, actor, rate, mtp); break;
            case K.OP_TRANSFER_NAME: TransferName(body, actor, height); break;
            case K.OP_RELEASE_NAME:  ReleaseName(body, actor, height); break;
            case K.OP_SELL:      Sell(body, actor, actorType, mtp); break;
            case K.OP_RESERVE:   Reserve(body, value, actor, tx, consumed, mtp); break;
            case K.OP_SETTLE:    Settle(body, actor, tx, consumed, height, mtp); break;
            case K.OP_SELL_TO:   SellTo(body, actor, actorType, mtp); break;
            case K.OP_PAY:       Pay(body, actor, tx, consumed, height, mtp); break;
        }
    }

    // ---- COMMIT ----
    private void Commit(byte[] body, long height, long mtp, int txIndex)
    {
        Commits.Add(new CommitRow
        {
            Commitment = body[..32],
            CommitHeight = height,
            TxIndex = (uint)txIndex,
            CommitTime = mtp,
        });
    }

    // ---- CLAIM ----
    private void Claim(byte[] body, ulong burn, byte[] actor, ulong rate, long height, long mtp)
    {
        byte[] salt = body[..32];
        byte[] name = body[32..];
        string key = NameKey(name);

        // commitment = SHA-256(salt ‖ name ‖ author_hash160)
        byte[] pre = new byte[32 + name.Length + 20];
        Buffer.BlockCopy(salt, 0, pre, 0, 32);
        Buffer.BlockCopy(name, 0, pre, 32, name.Length);
        Buffer.BlockCopy(actor, 0, pre, 32 + name.Length, 20);
        byte[] commitment = Hashing.Sha256(pre);

        // Find backing commit: matches, strictly earlier block, still live (inclusive window),
        // minimizing (commit_height, tx_index).
        long bestCh = long.MaxValue; uint bestTx = uint.MaxValue; bool found = false;
        foreach (var c in Commits)
        {
            if (!ByteEq(c.Commitment, commitment)) continue;
            if (!(c.CommitHeight < height)) continue;                 // strictly earlier block
            if (mtp > c.CommitTime + K.COMMIT_EXPIRY) continue;       // live (inclusive)
            if (c.CommitHeight < bestCh || (c.CommitHeight == bestCh && c.TxIndex < bestTx))
            { bestCh = c.CommitHeight; bestTx = c.TxIndex; found = true; }
        }
        if (!found) return; // no live ≥1-deep commit → drop (no FCFS fallback)

        // Lease: water-fill over a single fresh name (baseline expiry = now).
        UInt128 T = Lease.TotalNameDays(burn, rate);
        if (T == UInt128.Zero) return;                                // T≥1 required (fail closed)
        long headroom = Lease.HeadroomDays(mtp, mtp);                 // = MAX_LEASE/BILLING_UNIT
        long add = Lease.WaterFill(T, new[] { headroom })[0];
        if (add <= 0) return;
        long leaseExpiry = mtp + add * K.BILLING_UNIT;

        bool owned = Names.ContainsKey(key);
        bool fresh = _claimScratch.TryGetValue(key, out var prev);

        if (owned && !fresh) return;                                  // owned from a prior block → drop

        if (owned && fresh)
        {
            var r = Names[key];
            // Displacement only if the row is STILL that provisional owner's fresh OWNED mint
            // (a same-block transfer/sale could have moved or locked it since — SPEC-conformance §3).
            bool stillFresh = r.St == K.ST_OWNED && ByteEq(r.Owner, prev.owner);
            if (!stillFresh) return;

            // Same-block displacement iff (commit_height, commit_tx) lexicographically smaller.
            if (bestCh < prev.ch || (bestCh == prev.ch && bestTx < prev.ctx))
            {
                r.Owner = (byte[])actor.Clone();
                r.St = K.ST_OWNED; r.LeaseExpiry = leaseExpiry; r.ResetMarket();
                _claimScratch[key] = (bestCh, bestTx, (byte[])actor.Clone());
                Bump(actor, height);
            }
            return; // larger-or-equal tuple loses; does not displace
        }

        // Fresh mint.
        var row = new NameRow { Name = (byte[])name.Clone(), Owner = (byte[])actor.Clone(), St = K.ST_OWNED, LeaseExpiry = leaseExpiry };
        Names[key] = row;
        _claimScratch[key] = (bestCh, bestTx, (byte[])actor.Clone());
        Bump(actor, height);
    }

    // ---- RENEW ----
    private void Renew(byte[] body, ulong burn, byte[] actor, ulong rate, long height, long mtp)
    {
        int bl = body.Length;
        List<NameRow> owned = OwnedSortedRows(actor);

        List<NameRow> selected;
        if (bl == 0)                          // renew-all (cheap, no anchor)
        {
            selected = owned;
        }
        else if (bl == 5)                     // renew-all (safe) — anchor only
        {
            if (!AnchorOk(actor, body, 0, height)) return;
            selected = owned;
        }
        else                                  // selective: anchor5 + flags
        {
            if (!AnchorOk(actor, body, 0, height)) return;
            selected = SelectByBitmap(owned, body, 5);
        }

        // RENEW renews locked names too (no skip).
        if (selected.Count == 0) return; // no-op
        UInt128 T = Lease.TotalNameDays(burn, rate);
        if (T == UInt128.Zero) return;

        // selected is in lex order (owned is sorted; bitmap preserves order).
        long[] head = new long[selected.Count];
        for (int i = 0; i < selected.Count; i++) head[i] = Lease.HeadroomDays(selected[i].LeaseExpiry, mtp);
        long[] add = Lease.WaterFill(T, head);
        for (int i = 0; i < selected.Count; i++)
            selected[i].LeaseExpiry += add[i] * K.BILLING_UNIT;
        // RENEW is not a set/ordering mutation → no anchor bump.
    }

    // ---- the by-name forms (§3.5): singleton siblings of the bitmap ops ----
    // A name string is its own position-independent address into the owned set —
    // no anchor, no anchor guard. The name MUST be the actor's (the owner stays
    // the seller while LISTED/OFFERED/RESERVED); else drop.
    private NameRow? FindMine(byte[] name, byte[] actor)
    {
        if (!Names.TryGetValue(NameKey(name), out var r)) return null;
        return ByteEq(r.Owner, actor) ? r : null;
    }

    private void RenewName(byte[] body, ulong burn, byte[] actor, ulong rate, long mtp)
    {
        var r = FindMine(body, actor);
        if (r == null) return;                                   // absent / not mine → drop
        UInt128 T = Lease.TotalNameDays(burn, rate);
        if (T == UInt128.Zero) return;                           // fail-closed at T=0
        long[] add = Lease.WaterFill(T, new[] { Lease.HeadroomDays(r.LeaseExpiry, mtp) });
        r.LeaseExpiry += add[0] * K.BILLING_UNIT;
        // renewal is not a set mutation → no bump (listed/offered still renewable)
    }

    private void TransferName(byte[] body, byte[] actor, long height)
    {
        byte[] target = body[..20];
        var r = FindMine(body[20..], actor);
        if (r == null || r.Locked) return;                       // absent / not mine / locked → no-op
        r.Owner = (byte[])target.Clone();                        // lease conveys
        Bump(actor, height);                                     // a move bumps BOTH parties
        Bump(target, height);
    }

    private void ReleaseName(byte[] body, byte[] actor, long height)
    {
        var r = FindMine(body, actor);
        if (r == null || r.Locked) return;                       // absent / not mine / locked → no-op
        Names.Remove(NameKey(r.Name));                           // → pool, immediately reclaimable
        Bump(actor, height);
    }

    // ---- TRANSFER ----
    private void Transfer(byte[] body, byte[] actor, long height)
    {
        byte[] target = body[..20];
        List<NameRow> owned = OwnedSortedRows(actor);
        List<NameRow> selected;
        if (body.Length == 20)               // all (no anchor)
        {
            selected = owned;
        }
        else                                 // selective: target20 + anchor5 + flags
        {
            if (!AnchorOk(actor, body, 20, height)) return;
            selected = SelectByBitmap(owned, body, 25);
        }

        bool moved = false;
        foreach (var r in selected)
        {
            if (r.Locked) continue;          // locked names are skipped (not fatal)
            r.Owner = (byte[])target.Clone();
            moved = true;
        }
        if (moved) { Bump(actor, height); Bump(target, height); } // both parties bump
    }

    // ---- RELEASE ----
    private void Release(byte[] body, byte[] actor, long height)
    {
        if (!AnchorOk(actor, body, 0, height)) return;
        List<NameRow> owned = OwnedSortedRows(actor);
        List<NameRow> selected = SelectByBitmap(owned, body, 5);
        bool released = false;
        foreach (var r in selected)
        {
            if (r.Locked) continue;          // locked skipped
            Names.Remove(NameKey(r.Name));
            released = true;
        }
        if (released) Bump(actor, height);
    }

    // ---- SELL ----
    private void Sell(byte[] body, byte[] actor, byte actorType, long mtp)
    {
        ulong price = BinaryPrimitives.ReadUInt64LittleEndian(body.AsSpan(0, 8));
        uint window = BinaryPrimitives.ReadUInt32LittleEndian(body.AsSpan(8, 4));
        byte[] name = body[12..];
        string key = NameKey(name);

        if (!Names.TryGetValue(key, out var r)) return;                       // must exist
        if (!ByteEq(r.Owner, actor)) return;                                  // must own
        if (r.St != K.ST_OWNED) return;                                       // not already listed/offered
        if (price < 3 * K.DUST_FLOOR) return;                                 // price floor

        long w = window == 0 ? K.RESERVE_WINDOW : window;                      // 0 ⇒ default RESERVE_WINDOW
        if (window != 0 && window < K.RESERVE_WINDOW) return;                  // [1, RESERVE_WINDOW) out of range
        // upper bound in ADD-form (no unsigned underflow): MTP + window + REORG_BUFFER ≤ lease_expiry
        if ((ulong)mtp + (ulong)w + (ulong)K.REORG_BUFFER > (ulong)r.LeaseExpiry) return;

        r.St = K.ST_LISTED;
        r.Seller = (byte[])actor.Clone(); r.SellerType = actorType;
        r.Price = price; r.OfferExpiry = mtp + w;
        // reservation fields stay zero
    }

    // ---- RESERVE ----
    private void Reserve(byte[] body, ulong carValue, byte[] actor, Tx tx, bool[] consumed, long mtp)
    {
        string key = NameKey(body);
        if (!Names.TryGetValue(key, out var r)) return;
        if (r.St != K.ST_LISTED) return;                                      // must be open (not already RESERVED/OFFERED)

        ulong burnLeg = DepositLeg(r.Price, K.RESERVE_BURN_BPS);
        ulong payLeg  = DepositLeg(r.Price, K.RESERVE_PAY_BPS);

        if (carValue < burnLeg) return;                                       // carrier value gate (non-output precond)

        // Output matcher last; consume only on success.
        if (!MatchOutput(tx, consumed, r.Seller, r.SellerType, payLeg)) return;

        r.St = K.ST_RESERVED;
        r.Buyer = (byte[])actor.Clone();                                      // reserver
        r.BurnLeg = burnLeg; r.PayLeg = payLeg;
        r.ReserveExpiry = Math.Min(mtp + K.RESERVE_WINDOW, r.OfferExpiry);     // clamp to offer_expiry
    }

    // ---- SETTLE ----
    private void Settle(byte[] body, byte[] actor, Tx tx, bool[] consumed, long height, long mtp)
    {
        string key = NameKey(body);
        if (!Names.TryGetValue(key, out var r)) return;
        if (r.St != K.ST_RESERVED) return;
        if (!ByteEq(r.Buyer, actor)) return;                                  // exclusive reserver
        if (!(mtp < r.ReserveExpiry)) return;                                 // timing gate
        ulong remainder = r.Price - r.BurnLeg - r.PayLeg;                     // ≥ DUST_FLOOR by the price floor
        if (!MatchOutput(tx, consumed, r.Seller, r.SellerType, remainder)) return;

        byte[] oldOwner = r.Owner;
        r.Owner = (byte[])actor.Clone();
        r.St = K.ST_OWNED; r.ResetMarket();                                   // lease conveys (unchanged)
        Bump(oldOwner, height); Bump(actor, height);                          // bump both
    }

    // ---- SELL_TO ----
    private void SellTo(byte[] body, byte[] actor, byte actorType, long mtp)
    {
        ulong price = BinaryPrimitives.ReadUInt64LittleEndian(body.AsSpan(0, 8));
        byte[] buyer = body[8..28];
        byte[] name = body[28..];
        string key = NameKey(name);

        if (!Names.TryGetValue(key, out var r)) return;
        if (!ByteEq(r.Owner, actor)) return;
        if (r.St != K.ST_OWNED) return;
        if (price < K.DUST_FLOOR) return;                                     // ≥ DUST_FLOOR
        // lease tail: MTP + DIRECT_WINDOW + REORG_BUFFER ≤ lease_expiry (add-form)
        if ((ulong)mtp + (ulong)K.DIRECT_WINDOW + (ulong)K.REORG_BUFFER > (ulong)r.LeaseExpiry) return;

        r.St = K.ST_OFFERED;
        r.Seller = (byte[])actor.Clone(); r.SellerType = actorType;
        r.Buyer = (byte[])buyer.Clone(); r.Price = price;
        r.OfferExpiry = mtp + K.DIRECT_WINDOW;
    }

    // ---- PAY ----
    private void Pay(byte[] body, byte[] actor, Tx tx, bool[] consumed, long height, long mtp)
    {
        string key = NameKey(body);
        if (!Names.TryGetValue(key, out var r)) return;
        if (r.St != K.ST_OFFERED) return;                                     // live directed offer
        if (!ByteEq(r.Buyer, actor)) return;                                  // directed exclusivity
        if (!(mtp < r.OfferExpiry)) return;                                   // timing
        if (!MatchOutput(tx, consumed, r.Seller, r.SellerType, r.Price)) return; // full price

        byte[] oldOwner = r.Owner;
        r.Owner = (byte[])actor.Clone();
        r.St = K.ST_OWNED; r.ResetMarket();                                   // lease conveys
        Bump(oldOwner, height); Bump(actor, height);
    }

    // ---- TRADE ----
    private void DispatchTrade(Tx tx, byte[] body, long height)
    {
        int idxA = body[0], idxB = body[1];
        if (idxA == idxB) return;
        byte[]? pA = ActorOf(tx, idxA);
        byte[]? pB = ActorOf(tx, idxB);
        if (pA == null || pB == null) return;                                 // OOB / not SIGHASH_ALL

        // split nameA,nameB on the single comma (decoder guaranteed exactly one + valid names)
        int commaPos = -1;
        for (int i = 2; i < body.Length; i++) if (body[i] == 0x2C) { commaPos = i; break; }
        byte[] nameA = body[2..commaPos];
        byte[] nameB = body[(commaPos + 1)..];
        if (ByteEq(nameA, nameB)) return;                                     // nameA == nameB → drop

        string kA = NameKey(nameA), kB = NameKey(nameB);
        if (!Names.TryGetValue(kA, out var rA) || !Names.TryGetValue(kB, out var rB)) return;
        if (!ByteEq(rA.Owner, pA) || rA.Locked) return;                       // pA must still own nameA, unlocked
        if (!ByteEq(rB.Owner, pB) || rB.Locked) return;                       // pB must still own nameB, unlocked

        // atomic swap (leases convey)
        rA.Owner = (byte[])pB.Clone();
        rB.Owner = (byte[])pA.Clone();
        Bump(pA, height); Bump(pB, height);
    }

    // ---------------- helpers ----------------

    /// <summary>Owned-set rows for an owner, sorted ascending unsigned-bytewise on raw name (§3.5).</summary>
    private List<NameRow> OwnedSortedRows(byte[] owner)
    {
        var list = new List<NameRow>();
        foreach (var r in Names.Values) if (ByteEq(r.Owner, owner)) list.Add(r);
        list.Sort((a, b) => ByteArrayComparer.Instance.Compare(a.Name, b.Name));
        return list;
    }

    /// <summary>LSB-first bitmap selection: bit i = (flags[i>>3] >> (i&7)) & 1; bits ≥ K ignored.</summary>
    private static List<NameRow> SelectByBitmap(List<NameRow> owned, byte[] body, int flagsOff)
    {
        var sel = new List<NameRow>();
        int K_ = owned.Count;
        int flagBytes = body.Length - flagsOff;
        for (int i = 0; i < K_; i++)
        {
            int byteIdx = i >> 3;
            if (byteIdx >= flagBytes) break;                                  // no more flag bytes
            int bit = (body[flagsOff + byteIdx] >> (i & 7)) & 1;
            if (bit == 1) sel.Add(owned[i]);
        }
        return sel;
    }

    /// <summary>Anchor guard (§3.5): valid iff last_mutation ≤ H ≤ confirm AND confirm − H ≤ MAX_ANCHOR_AGE.</summary>
    private bool AnchorOk(byte[] owner, byte[] body, int off, long confirm)
    {
        long h = ReadU40LE(body, off);
        long lastMut = Muts.TryGetValue(Hashing.Hex(owner), out var m) ? m : 0;
        if (lastMut > h) return false;
        if (h > confirm) return false;                                        // fail-closed upper bound
        if (confirm - h > K.MAX_ANCHOR_AGE) return false;
        return true;
    }

    private bool MatchOutput(Tx tx, bool[] consumed, byte[] sellerH160, byte sellerType, ulong owed)
    {
        for (int v = 0; v < tx.Outputs.Count; v++)
        {
            if (consumed[v]) continue;
            var o = tx.Outputs[v];
            if (o.Kind != OutKind.Spendable) continue;
            if (o.Value == owed && o.Type == sellerType && ByteEq(o.H160, sellerH160))
            {
                consumed[v] = true;
                return true;
            }
        }
        return false;
    }

    private static ulong DepositLeg(ulong price, ulong bps)
    {
        UInt128 prod = (UInt128)price * (UInt128)bps;       // overflows int64 ⇒ 128-bit
        ulong floored = (ulong)(prod / 10000);              // floor
        return Math.Max(K.DUST_FLOOR, floored);
    }

    private void Bump(byte[] owner, long height)
    {
        string key = Hashing.Hex(owner);
        long cur = Muts.TryGetValue(key, out var m) ? m : long.MinValue;
        if (height > cur) { Muts[key] = height; MutOwnerBytes[key] = (byte[])owner.Clone(); }
        else if (!MutOwnerBytes.ContainsKey(key)) MutOwnerBytes[key] = (byte[])owner.Clone();
    }

    public static byte[] SyntheticTxid(long height, int txIndex)
    {
        byte[] t = new byte[32];
        BinaryPrimitives.WriteUInt64LittleEndian(t.AsSpan(0, 8), (ulong)height);
        BinaryPrimitives.WriteUInt32LittleEndian(t.AsSpan(8, 4), (uint)txIndex);
        return t; // 20 trailing zero bytes already
    }

    private IEnumerable<string> SortedNameKeys()
    {
        var keys = new List<NameRow>(Names.Values);
        keys.Sort((a, b) => ByteArrayComparer.Instance.Compare(a.Name, b.Name));
        var result = new List<string>(keys.Count);
        foreach (var r in keys) result.Add(NameKey(r.Name));
        return result;
    }

    private static long ReadU40LE(byte[] b, int off)
    {
        long v = 0;
        for (int i = 0; i < 5; i++) v |= (long)b[off + i] << (8 * i);
        return v;
    }

    public static string NameKey(byte[] name)
    {
        // names are ASCII [a-z0-9-]; Latin1 round-trips bytes 1:1.
        var chars = new char[name.Length];
        for (int i = 0; i < name.Length; i++) chars[i] = (char)name[i];
        return new string(chars);
    }

    private static bool ByteEq(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) => a.SequenceEqual(b);
}
