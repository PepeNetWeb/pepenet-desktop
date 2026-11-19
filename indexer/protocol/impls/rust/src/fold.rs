//! The deterministic fold (§3 + §5). Single forward pass: pre-block time-triggered
//! transitions (reserve → offer → lease, then COMMIT_EXPIRY prune), then txs in
//! (tx_index, vout) order, each change visible to everything after it.

use std::collections::BTreeMap;

use crate::decode::*;
use crate::model::*;
use crate::sha256::sha256;
use crate::types::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum St {
    Owned = 0,
    Listed = 1,
    Offered = 2,
    Reserved = 3,
}

#[derive(Clone, Debug)]
pub struct NameRow {
    pub owner: Hash160,
    pub otype: ScriptType, // NOT digested (cosmetic)
    pub lease_expiry: i64,
    pub st: St,
    pub seller: Hash160,
    pub seller_type: ScriptType,
    pub price: u64,
    pub offer_expiry: i64,
    pub buyer: Hash160, // OFFERED buyer OR RESERVED reserver
    pub burn_leg: u64,
    pub pay_leg: u64,
    pub reserve_expiry: i64,
}

impl NameRow {
    fn owned(owner: Hash160, otype: ScriptType, lease_expiry: i64) -> Self {
        NameRow {
            owner,
            otype,
            lease_expiry,
            st: St::Owned,
            seller: [0u8; 20],
            seller_type: ScriptType::P2pkh,
            price: 0,
            offer_expiry: 0,
            buyer: [0u8; 20],
            burn_leg: 0,
            pay_leg: 0,
            reserve_expiry: 0,
        }
    }
    fn reset_market(&mut self) {
        self.st = St::Owned;
        self.seller = [0u8; 20];
        self.seller_type = ScriptType::P2pkh;
        self.price = 0;
        self.offer_expiry = 0;
        self.buyer = [0u8; 20];
        self.burn_leg = 0;
        self.pay_leg = 0;
        self.reserve_expiry = 0;
    }
    fn locked(&self) -> bool {
        matches!(self.st, St::Listed | St::Offered | St::Reserved)
    }
}

#[derive(Clone, Debug)]
pub struct CommitRow {
    pub commitment: [u8; 32],
    pub commit_height: i64,
    pub tx_index: u32,
    pub commit_time: i64,
}

pub struct State {
    pub names: BTreeMap<Vec<u8>, NameRow>,
    pub commits: Vec<CommitRow>,
    pub muts: BTreeMap<Hash160, i64>,
    pub activation_height: i64,
    scratch: BTreeMap<Vec<u8>, (i64, u32, Hash160)>,
}

/// Spendable-output pool entry: (vout, hash160, type, value, consumed).
type SpendPool = Vec<(u32, Hash160, ScriptType, u64, bool)>;

impl State {
    pub fn new(activation_height: i64) -> Self {
        State {
            names: BTreeMap::new(),
            commits: Vec::new(),
            muts: BTreeMap::new(),
            activation_height,
            scratch: BTreeMap::new(),
        }
    }

    pub fn clear(&mut self) {
        let ah = self.activation_height;
        *self = State::new(ah);
    }

    fn bump_mut(&mut self, owner: Hash160, h: i64) {
        let e = self.muts.entry(owner).or_insert(i64::MIN);
        if h > *e {
            *e = h;
        }
    }

    fn last_mut(&self, owner: &Hash160) -> i64 {
        *self.muts.get(owner).unwrap_or(&i64::MIN)
    }

    /// Owned-set of `owner`, lexicographic (BTreeMap key order = unsigned bytewise).
    fn owned_names(&self, owner: &Hash160) -> Vec<Vec<u8>> {
        self.names
            .iter()
            .filter(|(_, r)| &r.owner == owner)
            .map(|(k, _)| k.clone())
            .collect()
    }

    // ----- top-level -----

    pub fn apply_block(&mut self, blk: &Block, prev_timestamps: &[i64]) {
        let mtp = crate::oracle::mtp(blk.height, prev_timestamps);
        self.scratch.clear();
        self.pre_block(blk.height, mtp);
        for (txi, tx) in blk.txs.iter().enumerate() {
            self.apply_tx(tx, blk, mtp, txi as u32);
        }
    }

    /// Test-only entry point (used by `meta` mode): apply ONLY a block's txs against the
    /// CURRENT state, with no pre-block time sweep. Mirrors java `Fold.applyOneTx`. The
    /// fold tx-dispatch logic is unchanged — this just skips the pre-block transitions so a
    /// provably-inert tx can be asserted against an already-settled state.
    pub fn apply_block_txs_only(&mut self, blk: &Block, mtp: i64) {
        self.scratch.clear();
        for (txi, tx) in blk.txs.iter().enumerate() {
            self.apply_tx(tx, blk, mtp, txi as u32);
        }
    }

    fn pre_block(&mut self, h: i64, mtp: i64) {
        // 1. reserve_expiry: RESERVED → LISTED (exclusive: revert when MTP >= reserve_expiry)
        for r in self.names.values_mut() {
            if r.st == St::Reserved && mtp >= r.reserve_expiry {
                r.st = St::Listed;
                r.buyer = [0u8; 20];
                r.burn_leg = 0;
                r.pay_leg = 0;
                r.reserve_expiry = 0;
            }
        }
        // 2. offer_expiry: LISTED/OFFERED → OWNED
        for r in self.names.values_mut() {
            if matches!(r.st, St::Listed | St::Offered) && mtp >= r.offer_expiry {
                r.reset_market();
            }
        }
        // 3. lease_expiry: lapse → pool, stamp owner's mutation height to H
        let lapsed: Vec<(Vec<u8>, Hash160)> = self
            .names
            .iter()
            .filter(|(_, r)| mtp >= r.lease_expiry)
            .map(|(k, r)| (k.clone(), r.owner))
            .collect();
        for (k, owner) in lapsed {
            self.names.remove(&k);
            self.bump_mut(owner, h);
        }
        // 4. COMMIT_EXPIRY prune — INCLUSIVE window (pruned only once MTP > commit_time+EXPIRY)
        self.commits.retain(|c| mtp <= c.commit_time + COMMIT_EXPIRY);
    }

    fn apply_tx(&mut self, tx: &Tx, blk: &Block, mtp: i64, txi: u32) {
        let h = blk.height;
        let mut actor: Option<Hash160> = resolve_actor(tx, 0);
        let mut actor_type: ScriptType =
            tx.inputs.get(0).map(|i| i.stype).unwrap_or(ScriptType::P2pkh);

        let mut spends: SpendPool = Vec::new();
        for (vout, o) in tx.outputs.iter().enumerate() {
            if let Output::Spend { hash160, stype, value } = o {
                spends.push((vout as u32, *hash160, *stype, *value, false));
            }
        }

        for (_vout, o) in tx.outputs.iter().enumerate() {
            let (payload, value) = match o {
                Output::Carrier { payload, value } => (payload.as_slice(), *value),
                Output::Spend { .. } => continue,
            };
            match decode_payload(payload, value) {
                Decoded::Ignore => {}
                Decoded::Action(act) => {
                    // forward-only activation gate (§3.0): all ops gate at one height.
                    if h < self.activation_height {
                        continue;
                    }
                    match act {
                        Action::As { index } => {
                            actor = resolve_actor(tx, index as usize);
                            actor_type = tx
                                .inputs
                                .get(index as usize)
                                .map(|i| i.stype)
                                .unwrap_or(ScriptType::P2pkh);
                        }
                        Action::Trade { idx_a, idx_b, name_a, name_b } => {
                            // TRADE never consults the acting identity (§3.10).
                            self.do_trade(tx, h, idx_a, idx_b, &name_a, &name_b);
                        }
                        other => {
                            let a = match actor {
                                Some(a) => a,
                                None => continue, // ⊥ actor → drop
                            };
                            self.dispatch(other, a, actor_type, blk, mtp, txi, value, &mut spends);
                        }
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch(
        &mut self,
        act: Action,
        actor: Hash160,
        actor_type: ScriptType,
        blk: &Block,
        mtp: i64,
        txi: u32,
        value: u64,
        spends: &mut SpendPool,
    ) {
        let h = blk.height;
        match act {
            Action::Commit { commitment } => self.commits.push(CommitRow {
                commitment,
                commit_height: h,
                tx_index: txi,
                commit_time: mtp,
            }),
            Action::Claim { salt, name } => {
                self.do_claim(actor, actor_type, &salt, &name, h, mtp, value, blk.rate)
            }
            Action::Renew { mode } => self.do_renew(actor, &mode, h, mtp, value, blk.rate),
            Action::Transfer { target, sel } => self.do_transfer(actor, target, &sel, h),
            Action::RenewName { name } => self.do_renew_name(actor, &name, mtp, value, blk.rate),
            Action::TransferName { target, name } => self.do_transfer_name(actor, target, &name, h),
            Action::ReleaseName { name } => self.do_release_name(actor, &name, h),
            Action::Sell { price, window, name } => {
                self.do_sell(actor, actor_type, price, window, &name, mtp)
            }
            Action::Reserve { name } => self.do_reserve(actor, &name, mtp, value, spends),
            Action::Settle { name } => self.do_settle(actor, &name, h, mtp, spends),
            Action::Release { anchor, flags } => self.do_release(actor, anchor, &flags, h),
            Action::SellTo { price, buyer, name } => {
                self.do_sell_to(actor, actor_type, price, buyer, &name, mtp)
            }
            Action::Pay { name } => self.do_pay(actor, &name, h, mtp, spends),
            Action::As { .. } | Action::Trade { .. } => unreachable!(),
        }
    }

    // ----- claim -----
    #[allow(clippy::too_many_arguments)]
    fn do_claim(
        &mut self,
        actor: Hash160,
        actor_type: ScriptType,
        salt: &[u8; 32],
        name: &[u8],
        h: i64,
        mtp: i64,
        value: u64,
        rate: u64,
    ) {
        // backing commit (needed in both fresh and displacement paths)
        let mut pre = Vec::with_capacity(32 + name.len() + 20);
        pre.extend_from_slice(salt);
        pre.extend_from_slice(name);
        pre.extend_from_slice(&actor);
        let commitment = sha256(&pre);
        let mut best: Option<(i64, u32)> = None;
        for c in &self.commits {
            if c.commitment == commitment && c.commit_height < h {
                let cand = (c.commit_height, c.tx_index);
                best = Some(best.map_or(cand, |b| b.min(cand)));
            }
        }
        let backing = match best {
            Some(x) => x,
            None => return, // no live ≥1-deep commit → drop
        };

        // existing row?
        if self.names.contains_key(name) {
            // displacement only if minted THIS block (in scratch) and lex-smaller backing
            if let Some(&(s_ch, s_ctx, s_owner)) = self.scratch.get(name) {
                let row_ok = self
                    .names
                    .get(name)
                    .map(|r| r.owner == s_owner && r.st == St::Owned)
                    .unwrap_or(false);
                if row_ok && backing < (s_ch, s_ctx) {
                    // displace: re-mint to actor with this claim's own lease
                    let days = water_fill_single_fresh(value, rate);
                    if days == 0 {
                        return; // T==0 fail-closed; existing provisional mint stays
                    }
                    let exp = mtp + (days as i64) * (BILLING_UNIT as i64);
                    self.names
                        .insert(name.to_vec(), NameRow::owned(actor, actor_type, exp));
                    self.scratch
                        .insert(name.to_vec(), (backing.0, backing.1, actor));
                    self.bump_mut(actor, h);
                }
            }
            return; // owned from prior block, or not displacing → drop
        }

        // fresh mint
        let days = water_fill_single_fresh(value, rate);
        if days == 0 {
            return; // must cover ≥1 day
        }
        let exp = mtp + (days as i64) * (BILLING_UNIT as i64);
        self.names
            .insert(name.to_vec(), NameRow::owned(actor, actor_type, exp));
        self.scratch
            .insert(name.to_vec(), (backing.0, backing.1, actor));
        self.bump_mut(actor, h);
    }

    // ----- renew -----
    fn do_renew(&mut self, actor: Hash160, mode: &RenewMode, h: i64, mtp: i64, value: u64, rate: u64) {
        let owned = self.owned_names(&actor); // lex order
        let selected: Vec<Vec<u8>> = match mode {
            RenewMode::All => owned.clone(),
            RenewMode::AllSafe { anchor } => {
                if !self.anchor_ok(&actor, *anchor, h) {
                    return;
                }
                owned.clone()
            }
            RenewMode::Selective { anchor, flags } => {
                if !self.anchor_ok(&actor, *anchor, h) {
                    return;
                }
                select_bits(&owned, flags)
            }
        };
        if selected.is_empty() {
            return;
        }
        // RENEW renews even locked names (still renewable) — no locked skip.
        let cur: Vec<i64> = selected
            .iter()
            .map(|n| self.names.get(n).map(|r| r.lease_expiry).unwrap_or(mtp))
            .collect();
        let adds = match water_fill(value, rate, mtp, &cur) {
            Some(a) => a,
            None => return, // T==0 fail-closed
        };
        for (n, add) in selected.iter().zip(adds.iter()) {
            if let Some(r) = self.names.get_mut(n) {
                r.lease_expiry += (*add as i64) * (BILLING_UNIT as i64);
            }
        }
        // RENEW does NOT bump last_set_mutation_height (no membership/ordering change).
    }

    // ----- the by-name forms (§3.5): singleton siblings of the bitmap ops -----
    // A name string is its own position-independent address into the owned set:
    // no anchor, no anchor guard. The name MUST be the actor's (the owner stays
    // the seller while listed/offered/reserved); else drop.

    fn do_renew_name(&mut self, actor: Hash160, name: &[u8], mtp: i64, value: u64, rate: u64) {
        match self.names.get(name) {
            Some(r) if r.owner == actor => {}
            _ => return, // absent / not mine → drop
        }
        let cur = vec![self.names.get(name).map(|r| r.lease_expiry).unwrap_or(mtp)];
        let adds = match water_fill(value, rate, mtp, &cur) {
            Some(a) => a,
            None => return, // T==0 fail-closed
        };
        if let Some(r) = self.names.get_mut(name) {
            r.lease_expiry += (adds[0] as i64) * (BILLING_UNIT as i64);
        }
        // renewal is not a set mutation → no bump.
    }

    fn do_transfer_name(&mut self, actor: Hash160, target: Hash160, name: &[u8], h: i64) {
        match self.names.get(name) {
            Some(r) if r.owner == actor && !r.locked() => {}
            _ => return, // absent / not mine / locked → no-op, no bump
        }
        if let Some(r) = self.names.get_mut(name) {
            r.owner = target;
            r.otype = ScriptType::P2pkh; // owner_type cosmetic / not digested
        }
        self.bump_mut(actor, h); // a move bumps BOTH parties (self-target included)
        self.bump_mut(target, h);
    }

    fn do_release_name(&mut self, actor: Hash160, name: &[u8], h: i64) {
        match self.names.get(name) {
            Some(r) if r.owner == actor && !r.locked() => {}
            _ => return, // absent / not mine / locked → no-op, no bump
        }
        self.names.remove(name);
        self.bump_mut(actor, h);
    }

    // ----- transfer -----
    fn do_transfer(&mut self, actor: Hash160, target: Hash160, sel: &Option<BitmapSel>, h: i64) {
        let owned = self.owned_names(&actor);
        let selected: Vec<Vec<u8>> = match sel {
            None => owned.clone(), // transfer-all (no anchor)
            Some(BitmapSel { anchor, flags }) => {
                if !self.anchor_ok(&actor, *anchor, h) {
                    return;
                }
                select_bits(&owned, flags)
            }
        };
        let mut moved = 0;
        for n in selected {
            let locked = self.names.get(&n).map(|r| r.locked()).unwrap_or(true);
            if locked {
                continue; // listed/offered name skipped (per-name filter)
            }
            if let Some(r) = self.names.get_mut(&n) {
                r.owner = target;
                r.otype = ScriptType::P2pkh; // owner_type cosmetic / not digested
                moved += 1;
            }
        }
        if moved > 0 {
            self.bump_mut(actor, h);
            self.bump_mut(target, h);
        }
    }

    // ----- sell -----
    fn do_sell(
        &mut self,
        actor: Hash160,
        actor_type: ScriptType,
        price: u64,
        window: u32,
        name: &[u8],
        mtp: i64,
    ) {
        if price < 3 * DUST_FLOOR {
            return;
        }
        let row = match self.names.get(name) {
            Some(r) if r.owner == actor && r.st == St::Owned => r,
            _ => return, // not owned, or already listed/offered (locked) → drop
        };
        let lease_expiry = row.lease_expiry;
        // window: 0 → RESERVE_WINDOW. nonzero must be ≥ RESERVE_WINDOW and pass add-form upper bound.
        let w: i64 = if window == 0 { RESERVE_WINDOW } else { window as i64 };
        if w < RESERVE_WINDOW {
            return; // nonzero window below floor → out of range
        }
        // add-form upper bound: MTP_now + window + REORG_BUFFER ≤ lease_expiry (unsigned/no underflow)
        if mtp + w + REORG_BUFFER > lease_expiry {
            return;
        }
        let r = self.names.get_mut(name).unwrap();
        r.st = St::Listed;
        r.seller = actor;
        r.seller_type = actor_type;
        r.price = price;
        r.offer_expiry = mtp + w;
        // SELL is not a set mutation → no bump.
    }

    // ----- reserve -----
    fn do_reserve(&mut self, actor: Hash160, name: &[u8], mtp: i64, value: u64, spends: &mut SpendPool) {
        let row = match self.names.get(name) {
            Some(r) if r.st == St::Listed => r.clone(),
            _ => return, // not an open listing (OWNED / already RESERVED / OFFERED) → drop
        };
        let burn_leg = deposit_leg(row.price, RESERVE_BURN_BPS);
        let pay_leg = deposit_leg(row.price, RESERVE_PAY_BPS);
        if value < burn_leg {
            return; // carrier value short of burn_leg → drop
        }
        // pay_leg output to seller (exact value, consume-once vout order)
        if !consume_output(spends, &row.seller, row.seller_type, pay_leg) {
            return; // pay_leg output absent → drop, listing stays OPEN
        }
        let reserve_expiry = (mtp + RESERVE_WINDOW).min(row.offer_expiry);
        let r = self.names.get_mut(name).unwrap();
        r.st = St::Reserved;
        r.buyer = actor; // reserver
        r.burn_leg = burn_leg;
        r.pay_leg = pay_leg;
        r.reserve_expiry = reserve_expiry;
        // no mutation bump (name stays seller's set)
    }

    // ----- settle -----
    fn do_settle(&mut self, actor: Hash160, name: &[u8], h: i64, mtp: i64, spends: &mut SpendPool) {
        let row = match self.names.get(name) {
            Some(r) if r.st == St::Reserved => r.clone(),
            _ => return,
        };
        if actor != row.buyer {
            return; // only the exclusive reserver may settle
        }
        if mtp >= row.reserve_expiry {
            return; // MTP < reserve_expiry gate
        }
        let remainder = row.price - row.burn_leg - row.pay_leg; // ≥ DUST_FLOOR by price floor
        if !consume_output(spends, &row.seller, row.seller_type, remainder) {
            return; // settle remainder output absent → drop
        }
        let seller = row.seller;
        let buyer = row.buyer;
        let r = self.names.get_mut(name).unwrap();
        r.owner = buyer;
        r.otype = ScriptType::P2pkh; // cosmetic
        r.reset_market(); // lease conveys (lease_expiry unchanged)
        self.bump_mut(seller, h);
        self.bump_mut(buyer, h);
    }

    // ----- release -----
    fn do_release(&mut self, actor: Hash160, anchor: i64, flags: &[u8], h: i64) {
        if !self.anchor_ok(&actor, anchor, h) {
            return;
        }
        let owned = self.owned_names(&actor);
        let selected = select_bits(&owned, flags);
        let mut released = 0;
        for n in selected {
            let locked = self.names.get(&n).map(|r| r.locked()).unwrap_or(true);
            if locked {
                continue; // listed/offered skipped
            }
            if self.names.remove(&n).is_some() {
                released += 1;
            }
        }
        if released > 0 {
            self.bump_mut(actor, h);
        }
    }

    // ----- sell_to -----
    fn do_sell_to(
        &mut self,
        actor: Hash160,
        actor_type: ScriptType,
        price: u64,
        buyer: Hash160,
        name: &[u8],
        mtp: i64,
    ) {
        if price < DUST_FLOOR {
            return;
        }
        let row = match self.names.get(name) {
            Some(r) if r.owner == actor && r.st == St::Owned => r,
            _ => return,
        };
        let lease_expiry = row.lease_expiry;
        // lease tail: MTP + DIRECT_WINDOW + REORG_BUFFER ≤ lease_expiry
        if mtp + DIRECT_WINDOW + REORG_BUFFER > lease_expiry {
            return;
        }
        let r = self.names.get_mut(name).unwrap();
        r.st = St::Offered;
        r.seller = actor;
        r.seller_type = actor_type;
        r.price = price;
        r.buyer = buyer;
        r.offer_expiry = mtp + DIRECT_WINDOW;
        // SELL_TO is not a set mutation → no bump.
    }

    // ----- pay -----
    fn do_pay(&mut self, actor: Hash160, name: &[u8], h: i64, mtp: i64, spends: &mut SpendPool) {
        let row = match self.names.get(name) {
            Some(r) if r.st == St::Offered => r.clone(),
            _ => return,
        };
        if actor != row.buyer {
            return; // only the named buyer may PAY
        }
        if mtp >= row.offer_expiry {
            return;
        }
        if !consume_output(spends, &row.seller, row.seller_type, row.price) {
            return; // full-price output absent → drop
        }
        let seller = row.seller;
        let buyer = row.buyer;
        let r = self.names.get_mut(name).unwrap();
        r.owner = buyer;
        r.otype = ScriptType::P2pkh;
        r.reset_market();
        self.bump_mut(seller, h);
        self.bump_mut(buyer, h);
    }

    // ----- trade -----
    fn do_trade(&mut self, tx: &Tx, h: i64, idx_a: u8, idx_b: u8, name_a: &[u8], name_b: &[u8]) {
        if idx_a == idx_b {
            return;
        }
        let ia = match resolve_actor(tx, idx_a as usize) {
            Some(x) => x,
            None => return, // OOB or fails §4/SIGHASH_ALL
        };
        let ib = match resolve_actor(tx, idx_b as usize) {
            Some(x) => x,
            None => return,
        };
        if name_a == name_b {
            return;
        }
        // live-ownership re-check at confirm, both unlocked
        let a_ok = self
            .names
            .get(name_a)
            .map(|r| r.owner == ia && !r.locked())
            .unwrap_or(false);
        let b_ok = self
            .names
            .get(name_b)
            .map(|r| r.owner == ib && !r.locked())
            .unwrap_or(false);
        if !a_ok || !b_ok {
            return; // whole-op drop
        }
        // atomic swap; leases convey
        self.names.get_mut(name_a).unwrap().owner = ib;
        self.names.get_mut(name_b).unwrap().owner = ia;
        self.bump_mut(ia, h);
        self.bump_mut(ib, h);
    }

    // ----- anchor guard (§3.5) -----
    fn anchor_ok(&self, owner: &Hash160, anchor: i64, confirm: i64) -> bool {
        let lm = self.last_mut(owner);
        lm <= anchor && anchor <= confirm && (confirm - anchor) <= MAX_ANCHOR_AGE
    }
}

// ---------- free helpers ----------

fn resolve_actor(tx: &Tx, k: usize) -> Option<Hash160> {
    let inp = tx.inputs.get(k)?;
    if !inp.sighash_all {
        return None;
    }
    inp.identity
}

/// Select owned names by bitmap (LSB-first), ignoring out-of-bounds bits (≥K).
fn select_bits(owned: &[Vec<u8>], flags: &[u8]) -> Vec<Vec<u8>> {
    let k = owned.len();
    let mut out = Vec::new();
    for i in 0..k {
        let byte = i >> 3;
        if byte < flags.len() && (flags[byte] >> (i & 7)) & 1 == 1 {
            out.push(owned[i].clone());
        }
    }
    out
}

/// Reserve/settle/pay deposit/payment leg: max(DUST_FLOOR, ⌊price·bps/10000⌋) in 128-bit.
pub(crate) fn deposit_leg(price: u64, bps: u64) -> u64 {
    let v = ((price as u128) * (bps as u128)) / 10000u128;
    let v = v as u64; // ≤ price ≤ u64
    v.max(DUST_FLOOR)
}

/// Consume the lowest-vout not-yet-consumed spendable output matching (hash160, type, value).
fn consume_output(spends: &mut SpendPool, who: &Hash160, stype: ScriptType, owed: u64) -> bool {
    let mut best: Option<usize> = None;
    for (idx, e) in spends.iter().enumerate() {
        if !e.4 && &e.1 == who && e.2 == stype && e.3 == owed {
            best = Some(match best {
                None => idx,
                Some(b) => {
                    if spends[b].0 <= e.0 {
                        b
                    } else {
                        idx
                    }
                }
            });
        }
    }
    if let Some(i) = best {
        spends[i].4 = true;
        true
    } else {
        false
    }
}

/// Single fresh-name water-fill: T days (= min(T, MAX_LEASE/BILLING_UNIT)). Returns 0 if T==0.
fn water_fill_single_fresh(burn: u64, rate: u64) -> u64 {
    let t = lease_days_total(burn, rate); // u128
    if t == 0 {
        return 0;
    }
    let cap = (MAX_LEASE / BILLING_UNIT) as u128; // 365
    t.min(cap) as u64
}

/// T = ⌊burn · LEASE_QUANTUM / (rate · BILLING_UNIT)⌋ in 128-bit (numerator overflows 64-bit).
fn lease_days_total(burn: u64, rate: u64) -> u128 {
    if rate == 0 {
        return 0; // guard; rate ≥ DUST_FLOOR in practice
    }
    let num = (burn as u128) * (LEASE_QUANTUM as u128);
    let den = (rate as u128) * (BILLING_UNIT as u128);
    num / den
}

/// Multi-name water-fill (§3.5): even level + MAX_LEASE-cap redistribute + ascending-lex remainder.
/// `cur` = current lease_expiry per (lex-sorted) name. Returns per-name added DAYS, or None if T==0.
fn water_fill(burn: u64, rate: u64, now: i64, cur: &[i64]) -> Option<Vec<u64>> {
    let t_total = lease_days_total(burn, rate);
    if t_total == 0 {
        return None;
    }
    let count = cur.len();
    // per-name headroom in days
    let headroom: Vec<u64> = cur
        .iter()
        .map(|&e| {
            let rem = MAX_LEASE as i64 - (e - now); // days*BILLING headroom in seconds
            if rem <= 0 {
                0
            } else {
                (rem / BILLING_UNIT as i64) as u64
            }
        })
        .collect();
    let total_h: u128 = headroom.iter().map(|&x| x as u128).sum();
    // cap T to total headroom (surplus forfeited); now fits in u64
    let mut t = t_total.min(total_h) as u64;
    let mut alloc = vec![0u64; count];
    loop {
        // active = names not yet capped
        let active: Vec<usize> = (0..count).filter(|&i| alloc[i] < headroom[i]).collect();
        if active.is_empty() || t == 0 {
            break;
        }
        let na = active.len() as u64;
        let level = t / na;
        if level == 0 {
            // remainder: +1 day to first `t` active names in lex order (names pre-sorted)
            for &i in active.iter().take(t as usize) {
                alloc[i] += 1;
            }
            break;
        }
        for &i in &active {
            let room = headroom[i] - alloc[i];
            let add = level.min(room);
            alloc[i] += add;
            t -= add;
        }
    }
    Some(alloc)
}
