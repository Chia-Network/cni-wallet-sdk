//! CLVM types for the legacy prefarm/internal-custody puzzles. These are distinct
//! from MIPS vaults and `ClawbackV2`. No wallet request format or trust policy lives here.
use crate::{MerkleProof, Mod};
use chia_protocol::Bytes32;
use chia_puzzle_types::singleton::SingletonStruct;
use clvm_traits::{FromClvm, ToClvm};
use clvm_utils::TreeHash;
use std::borrow::Cow;
mod mods;
pub use mods::*;

/// The pair of child-puzzle commitments in prefarm STATE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct InternalCustodyPuzzleHashes {
    pub rekey: Bytes32,
    #[clvm(rest)]
    pub payment: Bytes32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct InternalCustodyTimelocks {
    pub withdrawal: u64,
    pub rekey_increment: u64,
    #[clvm(rest)]
    pub slow_rekey: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct InternalCustodyState {
    pub puzzles: InternalCustodyPuzzleHashes,
    #[clvm(rest)]
    pub timelocks: InternalCustodyTimelocks,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct InternalCustodyRekeyFilter {
    pub puzzle_hash: Bytes32,
    #[clvm(rest)]
    pub allowed_timelock: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct InternalCustodyPaymentFilter {
    pub puzzle_hash: Bytes32,
    #[clvm(rest)]
    pub clawback_puzzle_hash: Bytes32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct InternalCustodyFilterConfig {
    pub rekey: InternalCustodyRekeyFilter,
    #[clvm(rest)]
    pub payment: InternalCustodyPaymentFilter,
}

/// Curried prefarm configuration: (rekey-hash . payment-hash) and timelocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct InternalCustodyPrefarmArgs {
    pub mod_hash: Bytes32,
    pub puzzle_root: Bytes32,
    pub config: InternalCustodyState,
}

#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct InternalCustodyMerkleArgs<I> {
    pub inner_puzzle: I,
    pub merkle_root: Bytes32,
}

/// The payment filter uses an additional empty curry argument; it must not be
/// confused with the two-argument ACH/rekey Merkle puzzle.
#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct InternalCustodyFilterArgs<I> {
    pub inner_puzzle: I,
    pub merkle_root: Bytes32,
    pub extra: (),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct InternalCustodyRekeyAndPaymentArgs {
    pub config: InternalCustodyFilterConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct InternalCustodyAchCompletionArgs {
    pub timelock: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct InternalCustodyAchClawbackArgs {
    pub return_puzzle_hash: Bytes32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct InternalCustodyRekeyCompletionArgs {
    pub singleton_struct: SingletonStruct,
    pub timelock: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalCustodyRekeyClawback;

macro_rules! module {
    ($ty:ty, $bytes:ident, $hash:ident $(, $generic:ident)?) => {
        impl $(<$generic>)? Mod for $ty {
            fn mod_reveal() -> Cow<'static, [u8]> { Cow::Borrowed(&$bytes) }
            fn mod_hash() -> TreeHash { $hash.into() }
        }
    };
}
module!(
    InternalCustodyPrefarmArgs,
    INTERNAL_CUSTODY_PREFARM_INNER,
    INTERNAL_CUSTODY_PREFARM_INNER_HASH
);
module!(
    InternalCustodyMerkleArgs<I>,
    INTERNAL_CUSTODY_P2_MERKLE_TREE,
    INTERNAL_CUSTODY_P2_MERKLE_TREE_HASH,
    I
);
module!(
    InternalCustodyFilterArgs<I>,
    INTERNAL_CUSTODY_P2_MERKLE_TREE,
    INTERNAL_CUSTODY_P2_MERKLE_TREE_HASH,
    I
);
module!(
    InternalCustodyRekeyAndPaymentArgs,
    INTERNAL_CUSTODY_REKEY_AND_PAYMENT,
    INTERNAL_CUSTODY_REKEY_AND_PAYMENT_HASH
);
module!(
    InternalCustodyAchCompletionArgs,
    INTERNAL_CUSTODY_ACH_COMPLETION,
    INTERNAL_CUSTODY_ACH_COMPLETION_HASH
);
module!(
    InternalCustodyAchClawbackArgs,
    INTERNAL_CUSTODY_ACH_CLAWBACK,
    INTERNAL_CUSTODY_ACH_CLAWBACK_HASH
);
module!(
    InternalCustodyRekeyCompletionArgs,
    INTERNAL_CUSTODY_REKEY_COMPLETION,
    INTERNAL_CUSTODY_REKEY_COMPLETION_HASH
);
module!(
    InternalCustodyRekeyClawback,
    INTERNAL_CUSTODY_REKEY_CLAWBACK,
    INTERNAL_CUSTODY_REKEY_CLAWBACK_HASH
);

/// Raw prefarm solution. The action arguments depend on `spend_type`; clear
/// signing must explicitly recognize an operation before interpreting them.
#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct InternalCustodySpendSolution<A, F, S> {
    pub amount: u64,
    pub spend_type: u8,
    pub action: A,
    pub filter_puzzle: F,
    pub filter_proof: MerkleProof,
    pub filter_solution: S,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct InternalCustodyPaymentArguments {
    pub outgoing: u64,
    pub incoming: u64,
    pub destination: Bytes32,
}
#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct InternalCustodyMerkleSolution<P, S> {
    pub puzzle: P,
    pub proof: MerkleProof,
    pub solution: S,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clvm_utils::tree_hash;
    use clvmr::{Allocator, serde::node_from_bytes};
    #[test]
    fn pinned_module_hashes_match_reveals() -> anyhow::Result<()> {
        for (bytes, hash) in [
            (
                &INTERNAL_CUSTODY_PREFARM_INNER[..],
                INTERNAL_CUSTODY_PREFARM_INNER_HASH,
            ),
            (
                &INTERNAL_CUSTODY_P2_MERKLE_TREE[..],
                INTERNAL_CUSTODY_P2_MERKLE_TREE_HASH,
            ),
            (
                &INTERNAL_CUSTODY_REKEY_AND_PAYMENT[..],
                INTERNAL_CUSTODY_REKEY_AND_PAYMENT_HASH,
            ),
            (
                &INTERNAL_CUSTODY_ACH_COMPLETION[..],
                INTERNAL_CUSTODY_ACH_COMPLETION_HASH,
            ),
            (
                &INTERNAL_CUSTODY_ACH_CLAWBACK[..],
                INTERNAL_CUSTODY_ACH_CLAWBACK_HASH,
            ),
            (
                &INTERNAL_CUSTODY_REKEY_COMPLETION[..],
                INTERNAL_CUSTODY_REKEY_COMPLETION_HASH,
            ),
            (
                &INTERNAL_CUSTODY_REKEY_CLAWBACK[..],
                INTERNAL_CUSTODY_REKEY_CLAWBACK_HASH,
            ),
        ] {
            let mut a = Allocator::new();
            let ptr = node_from_bytes(&mut a, bytes)?;
            assert_eq!(tree_hash(&a, ptr), hash.into());
        }
        Ok(())
    }
}
