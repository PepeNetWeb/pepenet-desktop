import java.math.BigInteger;
import java.util.*;

// The deterministic fold (§3 logic + §5 ordering). Mutates a State block-by-block.
// Derived purely from prose; ambiguities are commented with FORK-RISK and resolved
// by the most natural reading.
final class Fold {
    final State st;
    Fold(State st) { this.st = st; }

    // ---- block ------------------------------------------------------------

    void applyBlock(Model.Block b) {
        st.claimScratch.clear();                 // per-block scratch, never digested (§3 conformance)
        preBlock(b.height, b.mtp);               // time-triggered transitions BEFORE txs (§5)
        for (int i = 0; i < b.txs.length; i++) {
            b.txs[i].txIndex = i;                // (tx index) order
            applyTx(b, b.txs[i]);
        }
    }

    // Time-triggered transitions (no tx). Per §5: COMMIT_EXPIRY prune (independent),
    // then per name in TYPE order reserve_expiry -> offer_expiry -> lease_expiry,
    // each guarded/idempotent. Bounds are EXCLUSIVE (owned iff MTP < lease_expiry),
    // so a transition fires when MTP >= boundary.
    private void preBlock(long height, long mtp) {
        // COMMIT_EXPIRY: live for MTP in [commit_time, commit_time + COMMIT_EXPIRY]
        // (inclusive bracket per §3.2). FORK-RISK: inclusive vs exclusive upper edge.
        st.commits.removeIf(c -> mtp > c.commitTime + Const.COMMIT_EXPIRY);

        for (String k : new ArrayList<>(st.names.keySet())) {
            State.NameRow r = st.names.get(k);
            if (r == null) continue;
            // reserve_expiry: revert RESERVED -> LISTED
            if (r.st == Const.RESERVED && mtp >= r.reserveExpiry) {
                r.st = Const.LISTED;
                r.buyer = State.ZERO20; r.burnLeg = BigInteger.ZERO; r.payLeg = BigInteger.ZERO; r.reserveExpiry = 0;
            }
            // offer_expiry: close LISTED or OFFERED -> OWNED (name was always the seller's)
            if ((r.st == Const.LISTED || r.st == Const.OFFERED) && mtp >= r.offerExpiry) {
                r.st = Const.OWNED;
                r.seller = State.ZERO20; r.sellerType = 0; r.price = BigInteger.ZERO; r.offerExpiry = 0;
                r.buyer = State.ZERO20;
            }
            // lease_expiry: lapse to pool (remove; bump former owner's mutation height)
            if (mtp >= r.leaseExpiry) {
                byte[] owner = r.owner;
                st.names.remove(k);
                st.bumpMut(owner, height);       // lapse touches the set (§3.5)
            }
        }
    }

    // ---- transaction ------------------------------------------------------

    // apply a single tx WITHOUT the pre-block time-triggered transitions (for the
    // meta drop-closed probe: an inert tx must leave state byte-unchanged).
    void applyOneTx(long height, long mtp, BigInteger rate, Model.Tx tx) {
        applyTx(new Model.Block(height, mtp, rate, new Model.Tx[0]), tx);
    }

    private void applyTx(Model.Block b, Model.Tx tx) {
        long height = b.height, mtp = b.mtp;
        BigInteger rate = b.rate;

        // consumable spendable-output pool for the per-tx market matcher (§3.5)
        MatchPool pool = new MatchPool(tx);

        // acting identity (Rule 1b): default vin[0], re-pointed by AS until next AS / tx-end
        Model.TxIn actor = tx.ins.length > 0 ? tx.ins[0] : null;
        boolean actorValid = actor != null && actor.sigAll;   // abstract proxy for §4 success + Rule 3

        for (int vout = 0; vout < tx.outs.length; vout++) {
            Model.TxOut o = tx.outs[vout];
            if (!o.isOpReturn()) continue;               // spendable handled by matcher
            Wire.Decoded d = Wire.decode(o.payload, o.value);

            if (d.kind != Wire.Kind.ACTION) continue;    // IGNORE (names-only: no POST)

            // ACTION
            Action a = d.action;

            // forward-only activation gate (§3.0): all ops gate at one height.
            if (height < Const.ACTIVATION_HEIGHT) continue;

            if (a.op == Const.AS) {
                int k = a.asIndex;
                if (k < tx.ins.length && tx.ins[k].sigAll) { actor = tx.ins[k]; actorValid = true; }
                else { actor = null; actorValid = false; }   // bottom: segment drops until next AS / tx-end
                continue;
            }

            // TRADE is attributed to its OWN named inputs vin[idxA]/vin[idxB], NOT the acting identity
            // (§3.10/§5): it dispatches regardless of whether the acting identity verified, and never
            // consults `actor`, so it MUST run before the acting-identity drop gate below. (Requiring a
            // verified actor here would drop trades the spec settles — the M9 fork.)
            if (a.op == Const.TRADE) { trade(a, tx, height); continue; }

            if (!actorValid) continue;                   // run §4 on actor; drop if bottom/unverified

            switch (a.op) {
                case Const.COMMIT -> commit(a, height, mtp, tx.txIndex);
                case Const.CLAIM -> claim(a, actor, o.value, height, mtp, rate);
                case Const.RENEW -> renew(a, actor, o.value, height, mtp, rate);
                case Const.TRANSFER -> transfer(a, actor, height);
                case Const.RENEW_NAME -> renewName(a, actor, o.value, mtp, rate);
                case Const.TRANSFER_NAME -> transferName(a, actor, height);
                case Const.RELEASE_NAME -> releaseName(a, actor, height);
                case Const.SELL -> sell(a, actor, mtp);
                case Const.RESERVE -> reserve(a, actor, o.value, mtp, pool);
                case Const.SETTLE -> settle(a, actor, mtp, pool, height);
                case Const.RELEASE -> release(a, actor, height);
                case Const.SELL_TO -> sellTo(a, actor, mtp);
                case Const.PAY -> pay(a, actor, mtp, pool, height);
                // TRADE is intercepted above (before the acting-identity gate) — never reaches here.
                default -> { /* unknown / unreachable */ }
            }
        }
    }

    // ---- per-op handlers --------------------------------------------------

    private void commit(Action a, long height, long mtp, int txIndex) {
        State.Commit c = new State.Commit();
        c.commitment = a.commitment.clone();
        c.commitHeight = height; c.txIndex = txIndex; c.commitTime = mtp;
        st.commits.add(c);
    }

    private void claim(Action a, Model.TxIn actor, BigInteger value, long height, long mtp, BigInteger rate) {
        String key = State.nameKey(a.name);
        // backing commit: commitment == SHA256(salt||name||author), strictly earlier block, still live;
        // earliest (commit_height, tx_index) backs it (§3.2 priority tuple).
        byte[] target = Hashes.sha256(concat(a.salt, a.name, actor.id));
        long bch = Long.MAX_VALUE, btx = Long.MAX_VALUE; boolean found = false;
        for (State.Commit c : st.commits) {
            if (!Arrays.equals(c.commitment, target)) continue;
            if (!(c.commitHeight < height)) continue;                 // strictly earlier
            if (mtp > c.commitTime + Const.COMMIT_EXPIRY) continue;    // still live
            if (c.commitHeight < bch || (c.commitHeight == bch && c.txIndex < btx)) { bch = c.commitHeight; btx = c.txIndex; found = true; }
        }
        if (!found) return;                                           // no live >=1-deep commit (no FCFS)

        long[] add = Lease.waterfill(new long[]{ mtp }, mtp, value, rate);
        if (add == null) return;                                      // T==0 fail-closed
        long newExpiry = mtp + add[0] * Const.BILLING_UNIT;

        State.NameRow row = st.names.get(key);
        if (row == null) {
            // fresh mint
            State.NameRow r = new State.NameRow();
            r.owner = actor.id.clone(); r.ownerType = actor.type; r.st = Const.OWNED; r.leaseExpiry = newExpiry;
            st.names.put(key, r);
            st.bumpMut(actor.id, height);
            mark(key, bch, actor.id, btx);
        } else {
            // already owned — same-block displacement? (§3 conformance + vector 42)
            State.ClaimMark mk = st.claimScratch.get(key);
            boolean freshMint = mk != null && row.st == Const.OWNED && Arrays.equals(row.owner, mk.owner);
            boolean strictlyBetter = bch < mk_ch(mk) || (mk != null && bch == mk.commitHeight && btx < mk.commitTxIndex);
            if (freshMint && strictlyBetter) {
                byte[] prev = row.owner;
                row.owner = actor.id.clone(); row.ownerType = actor.type; row.leaseExpiry = newExpiry; row.st = Const.OWNED;
                st.bumpMut(prev, height); st.bumpMut(actor.id, height);
                mark(key, bch, actor.id, btx);
            }
            // else: drop (already owned)
        }
    }
    private long mk_ch(State.ClaimMark mk) { return mk == null ? Long.MIN_VALUE : mk.commitHeight; }
    private void mark(String key, long ch, byte[] owner, long tx) {
        State.ClaimMark m = new State.ClaimMark(); m.commitHeight = ch; m.owner = owner.clone(); m.commitTxIndex = tx;
        st.claimScratch.put(key, m);
    }

    private void renew(Action a, Model.TxIn actor, BigInteger value, long height, long mtp, BigInteger rate) {
        List<String> targets;
        if (a.renewMode == 0) {                                       // renew-all (no anchor)
            targets = st.ownedSetSorted(actor.id);
        } else {                                                      // all-safe / selective: anchor guard
            if (!anchorOk(actor.id, a.anchor, height)) return;
            List<String> set = st.ownedSetSorted(actor.id);
            if (a.renewMode == 1) targets = set;                      // all-safe == every owned name
            else targets = selectBits(set, a.flags);                 // selective bitmap
        }
        if (targets.isEmpty()) return;
        long[] cur = new long[targets.size()];
        for (int i = 0; i < targets.size(); i++) cur[i] = st.names.get(targets.get(i)).leaseExpiry;
        long[] add = Lease.waterfill(cur, mtp, value, rate);
        if (add == null) return;                                     // T==0 fail-closed
        for (int i = 0; i < targets.size(); i++)
            st.names.get(targets.get(i)).leaseExpiry = cur[i] + add[i] * Const.BILLING_UNIT;
    }

    // ---- the by-name forms (§3.5): singleton siblings of the bitmap ops ----
    // A name string is its own position-independent address into the owned set —
    // no anchor, no anchor guard. The name MUST be the actor's (the owner stays
    // the seller while LISTED/OFFERED/RESERVED); else drop.
    private State.NameRow findMine(Action a, Model.TxIn actor) {
        State.NameRow r = st.names.get(State.nameKey(a.name));
        if (r == null || !Arrays.equals(r.owner, actor.id)) return null;
        return r;
    }

    private void renewName(Action a, Model.TxIn actor, BigInteger value, long mtp, BigInteger rate) {
        State.NameRow r = findMine(a, actor);
        if (r == null) return;                                       // absent / not mine -> drop
        long[] cur = new long[]{ r.leaseExpiry };
        long[] add = Lease.waterfill(cur, mtp, value, rate);
        if (add == null) return;                                     // T==0 fail-closed
        r.leaseExpiry = cur[0] + add[0] * Const.BILLING_UNIT;
        // renewal is not a set mutation -> no bump (listed/offered still renewable)
    }

    private void transferName(Action a, Model.TxIn actor, long height) {
        State.NameRow r = findMine(a, actor);
        if (r == null || r.st != Const.OWNED) return;                // absent / not mine / locked -> no-op
        r.owner = a.tTarget.clone(); r.ownerType = Const.P2PKH;      // lease conveys (cosmetic type)
        st.bumpMut(actor.id, height); st.bumpMut(a.tTarget, height); // a move bumps BOTH parties
    }

    private void releaseName(Action a, Model.TxIn actor, long height) {
        State.NameRow r = findMine(a, actor);
        if (r == null || r.st != Const.OWNED) return;                // absent / not mine / locked -> no-op
        st.names.remove(State.nameKey(a.name));                      // -> pool, immediately reclaimable
        st.bumpMut(actor.id, height);
    }

    private void transfer(Action a, Model.TxIn actor, long height) {
        List<String> targets;
        if (!a.selective) {                                           // all: every OWNED (unlocked) name
            targets = new ArrayList<>();
            for (String k : st.ownedSetSorted(actor.id)) if (st.names.get(k).st == Const.OWNED) targets.add(k);
        } else {
            if (!anchorOk(actor.id, a.anchor, height)) return;
            List<String> set = st.ownedSetSorted(actor.id);
            targets = selectBits(set, a.flags);
        }
        boolean moved = false;
        for (String k : targets) {
            State.NameRow r = st.names.get(k);
            if (r.st != Const.OWNED) continue;                       // locked names skipped (FORK-RISK: skip vs whole-drop)
            r.owner = a.tTarget.clone(); r.ownerType = Const.P2PKH;  // target carries no script type (cosmetic)
            moved = true;
        }
        if (moved) { st.bumpMut(actor.id, height); st.bumpMut(a.tTarget, height); }
    }

    private void sell(Action a, Model.TxIn actor, long mtp) {
        State.NameRow r = st.names.get(State.nameKey(a.name));
        if (r == null || !Arrays.equals(r.owner, actor.id) || r.st != Const.OWNED) return;
        if (a.price.compareTo(Const.SELL_FLOOR) < 0) return;          // >= 3*DUST_FLOOR
        long window = (a.window == 0) ? Const.RESERVE_WINDOW : a.window;
        if (window < Const.RESERVE_WINDOW) return;                   // below floor -> ignored
        if (mtp + window + Const.REORG_BUFFER > r.leaseExpiry) return; // add-form upper bound (never subtract)
        r.st = Const.LISTED; r.seller = actor.id.clone(); r.sellerType = actor.type;
        r.price = a.price; r.offerExpiry = mtp + window;
    }

    private void reserve(Action a, Model.TxIn actor, BigInteger value, long mtp, MatchPool pool) {
        State.NameRow r = st.names.get(State.nameKey(a.name));
        if (r == null || r.st != Const.LISTED) return;               // only an open listing; loser/RESERVED/OFFERED drops
        BigInteger burnLeg = depositLeg(r.price, Const.RESERVE_BURN_BPS);
        BigInteger payLeg  = depositLeg(r.price, Const.RESERVE_PAY_BPS);
        if (value.compareTo(burnLeg) < 0) return;                    // OP_RETURN value must carry >= burn_leg
        if (!pool.consume(r.seller, r.sellerType, payLeg)) return;   // pay_leg exact-value output to seller
        r.st = Const.RESERVED; r.buyer = actor.id.clone();
        r.burnLeg = burnLeg; r.payLeg = payLeg;
        r.reserveExpiry = Math.min(mtp + Const.RESERVE_WINDOW, r.offerExpiry); // clamp (load-bearing)
    }

    private void settle(Action a, Model.TxIn actor, long mtp, MatchPool pool, long height) {
        State.NameRow r = st.names.get(State.nameKey(a.name));
        if (r == null || r.st != Const.RESERVED) return;
        if (!Arrays.equals(r.buyer, actor.id)) return;               // exclusive reserver only
        if (!(mtp < r.reserveExpiry)) return;                        // timing gate
        BigInteger remainder = r.price.subtract(r.burnLeg).subtract(r.payLeg); // >= DUST by SELL floor
        if (!pool.consume(r.seller, r.sellerType, remainder)) return;
        byte[] seller = r.owner;                                     // current owner == seller
        r.owner = actor.id.clone(); r.ownerType = actor.type; r.st = Const.OWNED;
        r.seller = State.ZERO20; r.sellerType = 0; r.price = BigInteger.ZERO; r.offerExpiry = 0;
        r.buyer = State.ZERO20; r.burnLeg = BigInteger.ZERO; r.payLeg = BigInteger.ZERO; r.reserveExpiry = 0;
        st.bumpMut(seller, height); st.bumpMut(actor.id, height);    // bump both (§3.5)
    }

    private void release(Action a, Model.TxIn actor, long height) {
        if (!anchorOk(actor.id, a.anchor, height)) return;
        List<String> set = st.ownedSetSorted(actor.id);
        List<String> targets = selectBits(set, a.flags);
        boolean any = false;
        for (String k : targets) {
            State.NameRow r = st.names.get(k);
            if (r.st != Const.OWNED) continue;                       // listed/offered locked -> skip
            st.names.remove(k); any = true;
        }
        if (any) st.bumpMut(actor.id, height);                       // RELEASE is a set mutation
    }

    private void sellTo(Action a, Model.TxIn actor, long mtp) {
        State.NameRow r = st.names.get(State.nameKey(a.name));
        if (r == null || !Arrays.equals(r.owner, actor.id) || r.st != Const.OWNED) return;
        if (a.price.compareTo(Const.DUST_FLOOR) < 0) return;         // >= DUST_FLOOR (no deposit split)
        if (mtp + Const.DIRECT_WINDOW + Const.REORG_BUFFER > r.leaseExpiry) return; // lease tail
        r.st = Const.OFFERED; r.buyer = a.buyer.clone(); r.seller = actor.id.clone(); r.sellerType = actor.type;
        r.price = a.price; r.offerExpiry = mtp + Const.DIRECT_WINDOW;
    }

    private void pay(Action a, Model.TxIn actor, long mtp, MatchPool pool, long height) {
        State.NameRow r = st.names.get(State.nameKey(a.name));
        if (r == null || r.st != Const.OFFERED) return;
        if (!Arrays.equals(r.buyer, actor.id)) return;               // only the named buyer
        if (!(mtp < r.offerExpiry)) return;
        if (!pool.consume(r.seller, r.sellerType, r.price)) return;  // full price exact-value output
        byte[] seller = r.owner;
        r.owner = actor.id.clone(); r.ownerType = actor.type; r.st = Const.OWNED;
        r.seller = State.ZERO20; r.sellerType = 0; r.price = BigInteger.ZERO; r.offerExpiry = 0; r.buyer = State.ZERO20;
        st.bumpMut(seller, height); st.bumpMut(actor.id, height);
    }

    private void trade(Action a, Model.Tx tx, long height) {
        int ia = a.idxA, ib = a.idxB;
        if (ia >= tx.ins.length || ib >= tx.ins.length) return;      // index OOB
        if (ia == ib) return;
        if (!tx.ins[ia].sigAll || !tx.ins[ib].sigAll) return;        // both pass §4 + SIGHASH_ALL
        String ka = State.nameKey(a.nameA), kb = State.nameKey(a.nameB);
        if (ka.equals(kb)) return;                                   // nameA == nameB
        State.NameRow ra = st.names.get(ka), rb = st.names.get(kb);
        if (ra == null || rb == null) return;
        if (!Arrays.equals(ra.owner, tx.ins[ia].id) || ra.st != Const.OWNED) return;   // live-ownership + unlocked
        if (!Arrays.equals(rb.owner, tx.ins[ib].id) || rb.st != Const.OWNED) return;
        ra.owner = tx.ins[ib].id.clone(); ra.ownerType = tx.ins[ib].type;             // nameA -> idxB
        rb.owner = tx.ins[ia].id.clone(); rb.ownerType = tx.ins[ia].type;             // nameB -> idxA
        st.bumpMut(tx.ins[ia].id, height); st.bumpMut(tx.ins[ib].id, height);
    }

    // ---- shared helpers ---------------------------------------------------

    private boolean anchorOk(byte[] owner, long H, long confirm) {
        long lastMut = st.lastMut(owner);
        // valid iff last_mutation <= H <= confirm AND confirm - H <= MAX_ANCHOR_AGE (§3.5)
        if (lastMut != Long.MIN_VALUE && lastMut > H) return false;
        if (H > confirm) return false;
        if (confirm - H > Const.MAX_ANCHOR_AGE) return false;
        return true;
    }

    // select owned names by an LSB-first bitmap; bits >= K (set size) are ignored (§3.5)
    private List<String> selectBits(List<String> set, byte[] flags) {
        List<String> out = new ArrayList<>();
        int K = set.size();
        int maxBits = flags.length * 8;
        for (int i = 0; i < maxBits && i < K; i++)
            if (((flags[i >> 3] >> (i & 7)) & 1) != 0) out.add(set.get(i));
        return out;
    }

    static BigInteger depositLeg(BigInteger price, long bps) {
        // max(DUST_FLOOR, floor(price * bps / 10000)) — price*bps in >=128-bit (BigInteger exact)
        return price.multiply(BigInteger.valueOf(bps)).divide(Const.BPS_DEN).max(Const.DUST_FLOOR);
    }

    static byte[] concat(byte[]... parts) {
        int n = 0; for (byte[] p : parts) n += p.length;
        byte[] r = new byte[n]; int o = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, r, o, p.length); o += p.length; }
        return r;
    }

    // per-tx market output matcher (§3.5): consume lowest-vout not-yet-consumed
    // spendable output whose (hash, type, value) == (seller, owed) exactly.
    static final class MatchPool {
        final List<Model.TxOut> outs = new ArrayList<>();
        final boolean[] consumed;
        MatchPool(Model.Tx tx) {
            for (Model.TxOut o : tx.outs) outs.add(o);
            consumed = new boolean[outs.size()];
        }
        boolean consume(byte[] sellerHash, int sellerType, BigInteger owed) {
            for (int i = 0; i < outs.size(); i++) {
                if (consumed[i]) continue;
                Model.TxOut o = outs.get(i);
                if (o.isOpReturn()) continue;
                if (o.spkType == sellerType && Arrays.equals(o.spkHash, sellerHash) && o.value.equals(owed)) {
                    consumed[i] = true; return true;
                }
            }
            return false;
        }
    }
}
