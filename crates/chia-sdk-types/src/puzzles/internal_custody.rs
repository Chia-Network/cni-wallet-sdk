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
    /// Rekey branch configuration.
    pub rekey: Bytes32,
    #[clvm(rest)]
    /// Payment branch configuration.
    pub payment: Bytes32,
}
/// Withdrawal and rekey timing parameters in the legacy STATE tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct InternalCustodyTimelocks {
    /// Withdrawal timelock in seconds.
    pub withdrawal: u64,
    /// Base rekey timelock in seconds.
    pub rekey_increment: u64,
    #[clvm(rest)]
    /// Additional penalty in seconds for slower rekey paths.
    pub slow_rekey: u64,
}
/// Puzzle commitments and timelocks curried into the prefarm singleton.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct InternalCustodyState {
    /// Child puzzle commitments.
    pub puzzles: InternalCustodyPuzzleHashes,
    #[clvm(rest)]
    /// Withdrawal and rekey timing parameters.
    pub timelocks: InternalCustodyTimelocks,
}
/// Authorized rekey puzzle and timelock multiple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct InternalCustodyRekeyFilter {
    /// Committed puzzle hash.
    pub puzzle_hash: Bytes32,
    #[clvm(rest)]
    /// Authorized rekey timelock multiple.
    pub allowed_timelock: u64,
}
/// ACH puzzle and clawback-return commitments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct InternalCustodyPaymentFilter {
    /// Committed puzzle hash.
    pub puzzle_hash: Bytes32,
    #[clvm(rest)]
    /// Puzzle hash receiving clawed-back funds.
    pub clawback_puzzle_hash: Bytes32,
}
/// Rekey and payment restrictions applied to the delegated conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct InternalCustodyFilterConfig {
    /// Rekey branch configuration.
    pub rekey: InternalCustodyRekeyFilter,
    #[clvm(rest)]
    /// Payment branch configuration.
    pub payment: InternalCustodyPaymentFilter,
}

/// Curried prefarm configuration: (rekey-hash . payment-hash) and timelocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct InternalCustodyPrefarmArgs {
    /// Self-commitment to the prefarm module hash.
    pub mod_hash: Bytes32,
    /// Merkle root committing to the authorized custody puzzles.
    pub puzzle_root: Bytes32,
    /// Configuration committed by this puzzle.
    pub config: InternalCustodyState,
}

/// Curried Merkle-gated puzzle used by ACH and rekey branches.
#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct InternalCustodyMerkleArgs<I> {
    /// Inner puzzle to execute after proving inclusion.
    pub inner_puzzle: I,
    /// Merkle root authorizing the revealed puzzle.
    pub merkle_root: Bytes32,
}

/// The payment filter uses an additional empty curry argument; it must not be
/// confused with the two-argument ACH/rekey Merkle puzzle.
#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct InternalCustodyFilterArgs<I> {
    /// Inner puzzle to execute after proving inclusion.
    pub inner_puzzle: I,
    /// Merkle root authorizing the revealed puzzle.
    pub merkle_root: Bytes32,
    /// Empty curry argument required by the payment filter.
    pub extra: (),
}

/// Curried configuration for the payment/rekey restriction filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct InternalCustodyRekeyAndPaymentArgs {
    /// Configuration committed by this puzzle.
    pub config: InternalCustodyFilterConfig,
}

/// Curried relative delay for ACH completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct InternalCustodyAchCompletionArgs {
    /// Relative completion delay in seconds.
    pub timelock: u64,
}
/// Curried return destination for ACH clawback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct InternalCustodyAchClawbackArgs {
    /// Puzzle hash receiving clawed-back funds.
    pub return_puzzle_hash: Bytes32,
}
/// Curried singleton identity and relative rekey delay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct InternalCustodyRekeyCompletionArgs {
    /// Singleton identity and top-layer commitments.
    pub singleton_struct: SingletonStruct,
    /// Relative completion delay in seconds.
    pub timelock: u64,
}
/// Uncurried legacy rekey cancellation module.
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
    /// Input coin amount in mojos.
    pub amount: u64,
    /// Legacy operation discriminator; payment handling uses 2.
    pub spend_type: u8,
    /// Arguments specific to the selected operation.
    pub action: A,
    /// Authorized filter puzzle reveal.
    pub filter_puzzle: F,
    /// Filter inclusion proof under the custody root.
    pub filter_proof: MerkleProof,
    /// Solution passed to the filter puzzle.
    pub filter_solution: S,
}
/// Incoming, outgoing and recipient arguments for payment handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct InternalCustodyPaymentArguments {
    /// Outgoing ACH amount in mojos.
    pub outgoing: u64,
    /// Absorbed deposit amount in mojos.
    pub incoming: u64,
    /// Recipient puzzle hash committed by the outgoing payment.
    pub destination: Bytes32,
}
/// Revealed puzzle, inclusion proof and solution for a Merkle gate.
#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct InternalCustodyMerkleSolution<P, S> {
    /// Puzzle reveal whose inclusion must be proven.
    pub puzzle: P,
    /// Merkle inclusion path for the leaf.
    pub proof: MerkleProof,
    /// Solution passed to the revealed puzzle.
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
