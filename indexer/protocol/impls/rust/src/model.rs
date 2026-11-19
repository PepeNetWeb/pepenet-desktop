//! Transaction / block model fed to the fold. The fold is fed already-resolved
//! identities (§13: "the §5 fold is fed an already-resolved identity"); the §4
//! attribution byte-logic lives separately in attrib.rs.

use crate::types::{Hash160, ScriptType};

#[derive(Clone, Debug)]
pub struct Input {
    /// Resolved §4 identity, or None if vin[k] is unattributable (⊥).
    pub identity: Option<Hash160>,
    pub stype: ScriptType,
    /// Whether this input signs exactly SIGHASH_ALL (Rule 3).
    pub sighash_all: bool,
}

#[derive(Clone, Debug)]
pub enum Output {
    /// An OP_RETURN carrier: the single-minimal-push payload + the output value.
    Carrier { payload: Vec<u8>, value: u64 },
    /// A spendable output: scriptPubKey reconstructed from (hash160, type) + value.
    Spend { hash160: Hash160, stype: ScriptType, value: u64 },
}

#[derive(Clone, Debug)]
pub struct Tx {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

#[derive(Clone, Debug)]
pub struct Block {
    pub height: i64,
    /// The block's own timestamp. The fold evaluates boundaries against MTP (median of the
    /// 11 prior blocks, §5), never this field directly — kept for model completeness.
    #[allow(dead_code)]
    pub timestamp: i64,
    /// Rate (koinu per name·quantum) for this block. In the `random` generator this
    /// is drawn directly (§5); the fee oracle (oracle.rs) is exercised separately.
    pub rate: u64,
    pub txs: Vec<Tx>,
}
