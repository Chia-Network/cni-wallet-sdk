use crate::{
    DriverError, InternalCustodyError, InternalCustodyLayer, InternalCustodyPolicy, Layer,
    SpendContext, SpendWithConditions, StandardLayer,
};
use chia_bls::PublicKey;
use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_puzzle_types::DeriveSynthetic;
use chia_puzzle_types::{
    Memos, Proof,
    singleton::{SingletonArgs, SingletonSolution, SingletonStruct},
};
use chia_sdk_types::{
    Conditions, MerkleTree, Mod,
    puzzles::{
        InternalCustodyAchClawbackArgs, InternalCustodyAchCompletionArgs,
        InternalCustodyFilterArgs, InternalCustodyFilterConfig, InternalCustodyMerkleArgs,
        InternalCustodyMerkleSolution, InternalCustodyPaymentArguments,
        InternalCustodyPaymentFilter, InternalCustodyRekeyAndPaymentArgs,
        InternalCustodyRekeyClawback, InternalCustodyRekeyCompletionArgs,
        InternalCustodyRekeyFilter, InternalCustodySpendSolution, P2SingletonArgs,
    },
};
use clvm_traits::{clvm_curried_args, clvm_list};
use clvm_utils::{CurriedProgram, ToTreeHash};
use clvmr::NodePtr;

impl InternalCustodyPolicy {
    pub(crate) fn selected_key(&self, signers: &[PublicKey]) -> Result<PublicKey, DriverError> {
        if signers.len() != self.thresholds().required as usize
            || !signers
                .windows(2)
                .all(|w| w[0].to_bytes() < w[1].to_bytes())
            || signers
                .iter()
                .any(|pk| pk.is_inf() || !self.keys().contains(pk))
        {
            return Err(InternalCustodyError::InvalidSigningSet.into());
        }
        let aggregate = signers
            .iter()
            .fold(PublicKey::default(), |sum, pk| sum + pk);
        let synthetic = aggregate.derive_synthetic();
        if aggregate.is_inf() || synthetic.is_inf() {
            return Err(InternalCustodyError::InvalidSigningSet.into());
        }
        Ok(synthetic)
    }
    pub fn inner_layer(&self, ctx: &mut SpendContext) -> Result<InternalCustodyLayer, DriverError> {
        let info = self.info();
        let rekey = self.rekey_puzzle(ctx)?;
        let payment = self.payment_puzzle(ctx)?;
        Ok(InternalCustodyLayer {
            puzzle_root: info.puzzle_root,
            rekey_puzzle_hash: ctx.tree_hash(rekey).into(),
            payment_puzzle_hash: ctx.tree_hash(payment).into(),
            withdrawal_timelock: info.withdrawal_timelock,
            rekey_increment: info.rekey_increment,
            slow_rekey: info.slow_rekey,
        })
    }
    pub fn singleton_puzzle(&self, ctx: &mut SpendContext) -> Result<NodePtr, DriverError> {
        let inner_puzzle = self.inner_layer(ctx)?.construct_puzzle(ctx)?;
        ctx.curry(SingletonArgs {
            singleton_struct: SingletonStruct::new(self.info().launcher_id),
            inner_puzzle,
        })
    }
    pub(crate) fn payment_puzzle(&self, ctx: &mut SpendContext) -> Result<NodePtr, DriverError> {
        let complete = InternalCustodyAchCompletionArgs {
            timelock: self.info().payment_clawback,
        };
        let clawback = InternalCustodyAchClawbackArgs {
            return_puzzle_hash: P2SingletonArgs::new(self.info().launcher_id)
                .curry_tree_hash()
                .into(),
        };
        let root = MerkleTree::new(&[
            complete.curry_tree_hash().into(),
            clawback.curry_tree_hash().into(),
        ])
        .root();
        let inner_puzzle = ctx.alloc(&clvm_list!(2u8, 2u8, 5u8))?;
        ctx.curry(InternalCustodyMerkleArgs {
            inner_puzzle,
            merkle_root: root,
        })
    }
    fn rekey_puzzle(&self, ctx: &mut SpendContext) -> Result<NodePtr, DriverError> {
        let complete = InternalCustodyRekeyCompletionArgs {
            singleton_struct: SingletonStruct::new(self.info().launcher_id),
            timelock: self.info().rekey_clawback,
        };
        let root = MerkleTree::new(&[
            complete.curry_tree_hash().into(),
            InternalCustodyRekeyClawback::mod_hash().into(),
        ])
        .root();
        let inner_puzzle = ctx.alloc(&clvm_list!(2u8, 2u8, 5u8))?;
        ctx.curry(InternalCustodyMerkleArgs {
            inner_puzzle,
            merkle_root: root,
        })
    }
    pub(crate) fn pending_payment_puzzle(
        &self,
        ctx: &mut SpendContext,
        destination: Bytes32,
    ) -> Result<NodePtr, DriverError> {
        let payment = self.payment_puzzle(ctx)?;
        ctx.alloc(&CurriedProgram {
            program: payment,
            args: clvm_curried_args!((self.info().puzzle_root, destination)),
        })
    }
    /// Complete a previously authorized pending payment. No custody signature is
    /// required: its destination and delay are already fixed by the pending coin.
    /// The caller must establish chain inclusion and relative-time eligibility.
    pub fn completion_spend(
        &self,
        ctx: &mut SpendContext,
        pending: Coin,
        destination: Bytes32,
    ) -> Result<CoinSpend, DriverError> {
        let puzzle = self.pending_payment_puzzle(ctx, destination)?;
        if pending.amount == 0
            || !pending.amount.is_multiple_of(2)
            || ctx.tree_hash(puzzle) != pending.puzzle_hash.into()
        {
            return Err(DriverError::WrongPuzzleHash);
        }
        let complete = InternalCustodyAchCompletionArgs {
            timelock: self.info().payment_clawback,
        };
        let clawback = InternalCustodyAchClawbackArgs {
            return_puzzle_hash: P2SingletonArgs::new(self.info().launcher_id)
                .curry_tree_hash()
                .into(),
        };
        let complete_hash = complete.curry_tree_hash();
        let tree = MerkleTree::new(&[complete_hash.into(), clawback.curry_tree_hash().into()]);
        let proof = tree
            .proof(complete_hash.into())
            .ok_or(InternalCustodyError::InvalidPolicy)?;
        let complete_puzzle = ctx.curry(complete)?;
        let solution = InternalCustodyMerkleSolution {
            puzzle: complete_puzzle,
            proof,
            solution: clvm_list!(pending.amount),
        };
        Ok(CoinSpend::new(
            pending,
            ctx.serialize(&puzzle)?,
            ctx.serialize(&solution)?,
        ))
    }
    /// Construct the exact supported initial payment, with no claims or extra
    /// delegated conditions. This does not check current chain availability.
    pub fn payment_spend(
        &self,
        ctx: &mut SpendContext,
        coin: Coin,
        proof: Proof,
        amount: u64,
        destination: Bytes32,
        signers: &[PublicKey],
    ) -> Result<CoinSpend, DriverError> {
        if amount == 0
            || !amount.is_multiple_of(2)
            || coin.amount.is_multiple_of(2)
            || amount >= coin.amount
        {
            return Err(InternalCustodyError::InvalidPayment.into());
        }
        let synthetic_key = self.selected_key(signers)?;
        let standard = StandardLayer::new(synthetic_key);
        let leaf_hash = standard.tree_hash();
        let leaf = self
            .leaf_proofs
            .iter()
            .find(|p| p.leaf == leaf_hash.into())
            .ok_or(InternalCustodyError::InvalidSigningSet)?;
        let root = leaf
            .proof
            .root(leaf.leaf)
            .ok_or(InternalCustodyError::InvalidPolicy)?;
        let rekey = self.rekey_puzzle(ctx)?;
        let payment = self.payment_puzzle(ctx)?;
        let filter = ctx.curry(InternalCustodyRekeyAndPaymentArgs {
            config: InternalCustodyFilterConfig {
                rekey: InternalCustodyRekeyFilter {
                    puzzle_hash: ctx.tree_hash(rekey).into(),
                    allowed_timelock: 1,
                },
                payment: InternalCustodyPaymentFilter {
                    puzzle_hash: ctx.tree_hash(payment).into(),
                    clawback_puzzle_hash: P2SingletonArgs::new(self.info().launcher_id)
                        .curry_tree_hash()
                        .into(),
                },
            },
        })?;
        let filter = ctx.curry(InternalCustodyFilterArgs {
            inner_puzzle: filter,
            merkle_root: root,
            extra: (),
        })?;
        let filter_hash: Bytes32 = ctx.tree_hash(filter).into();
        let filter_proof = self
            .filter_proofs
            .iter()
            .find(|p| {
                p.leaf == filter_hash && p.proof.root(p.leaf) == Some(self.info().puzzle_root)
            })
            .ok_or(InternalCustodyError::InvalidPolicy)?;
        let inner = self.inner_layer(ctx)?.construct_puzzle(ctx)?;
        let pending = self.pending_payment_puzzle(ctx, destination)?;
        let conditions = Conditions::new()
            .create_coin(
                ctx.tree_hash(inner).into(),
                coin.amount - amount,
                Memos::None,
            )
            .create_coin(ctx.tree_hash(pending).into(), amount, Memos::None);
        let standard_spend = standard.spend_with_conditions(ctx, conditions)?;
        let filter_solution = InternalCustodyMerkleSolution {
            puzzle: standard_spend.puzzle,
            proof: leaf.proof.clone(),
            solution: clvm_list!(
                standard_spend.solution,
                (self.info().puzzle_root, destination)
            ),
        };
        let solution = SingletonSolution {
            lineage_proof: proof,
            amount: coin.amount,
            inner_solution: InternalCustodySpendSolution {
                amount: coin.amount,
                spend_type: 2,
                action: InternalCustodyPaymentArguments {
                    outgoing: amount,
                    incoming: 0,
                    destination,
                },
                filter_puzzle: filter,
                filter_proof: filter_proof.proof.clone(),
                filter_solution,
            },
        };
        let puzzle = self.singleton_puzzle(ctx)?;
        if ctx.tree_hash(puzzle) != coin.puzzle_hash.into() {
            return Err(DriverError::WrongPuzzleHash);
        }
        Ok(CoinSpend::new(
            coin,
            ctx.serialize(&puzzle)?,
            ctx.serialize(&solution)?,
        ))
    }
}
