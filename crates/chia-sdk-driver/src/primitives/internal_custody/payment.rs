use crate::{
    DriverError, InternalCustodyError, InternalCustodyLayer, InternalCustodyPolicy,
    InternalCustodyWithdrawal, Layer, P2SingletonLayer, SpendContext, SpendWithConditions,
    StandardLayer,
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
    /// Construct the committed inner custody layer.
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
    /// Construct the full singleton puzzle for this policy.
    pub fn singleton_puzzle(&self, ctx: &mut SpendContext) -> Result<NodePtr, DriverError> {
        let inner_puzzle = self.inner_layer(ctx)?.construct_puzzle(ctx)?;
        ctx.curry(SingletonArgs {
            singleton_struct: SingletonStruct::new(self.info().launcher_id),
            inner_puzzle,
        })
    }
    pub(crate) fn payment_puzzle(&self, ctx: &mut SpendContext) -> Result<NodePtr, DriverError> {
        let (_, tree) = self.payment_completion_tree();
        let root = tree.root();
        let inner_puzzle = ctx.alloc(&clvm_list!(2u8, 2u8, 5u8))?;
        ctx.curry(InternalCustodyMerkleArgs {
            inner_puzzle,
            merkle_root: root,
        })
    }
    fn payment_completion_tree(&self) -> (InternalCustodyAchCompletionArgs, MerkleTree) {
        let complete = InternalCustodyAchCompletionArgs {
            timelock: self.info().payment_clawback,
        };
        let clawback = InternalCustodyAchClawbackArgs {
            return_puzzle_hash: P2SingletonArgs::new(self.info().launcher_id)
                .curry_tree_hash()
                .into(),
        };
        let tree = MerkleTree::new(&[
            complete.curry_tree_hash().into(),
            clawback.curry_tree_hash().into(),
        ]);
        (complete, tree)
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
        let (complete, tree) = self.payment_completion_tree();
        let complete_hash = complete.curry_tree_hash();
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
    /// Construct an authorized withdrawal, deposit absorption, or both. The first
    /// spend is the singleton; remaining inputs are p2-singleton deposits ordered
    /// by coin ID. No fees or other delegated conditions are permitted here.
    /// Deposit totals must be even to preserve the singleton's odd amount.
    /// Pass no withdrawal for claim-only; it creates no pending payment.
    /// Callers must check current input availability and relative-time eligibility.
    pub fn payment_spends(
        &self,
        ctx: &mut SpendContext,
        coin: Coin,
        proof: Proof,
        withdrawal: Option<InternalCustodyWithdrawal>,
        signers: &[PublicKey],
        deposits: &[Coin],
    ) -> Result<Vec<CoinSpend>, DriverError> {
        let (amount, destination) =
            withdrawal.map_or((0, Bytes32::default()), |p| (p.amount, p.destination));
        if withdrawal.is_some_and(|p| p.amount == 0) {
            return Err(InternalCustodyError::InvalidPayment.into());
        }
        let incoming = self.validate_deposits(coin, deposits)?;
        let remaining = coin
            .amount
            .checked_add(incoming)
            .and_then(|balance| balance.checked_sub(amount))
            .ok_or(InternalCustodyError::InvalidPayment)?;
        if !amount.is_multiple_of(2)
            || coin.amount.is_multiple_of(2)
            || remaining == 0
            || (amount == 0 && (incoming == 0 || destination != Bytes32::default()))
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
        let mut conditions =
            Conditions::new().create_coin(ctx.tree_hash(inner).into(), remaining, Memos::None);
        if amount > 0 {
            conditions = conditions.create_coin(ctx.tree_hash(pending).into(), amount, Memos::None);
        }
        let deposit_layer = P2SingletonLayer::new(self.info().launcher_id);
        let inner_hash: Bytes32 = ctx.tree_hash(inner).into();
        let mut deposit_spends = Vec::with_capacity(deposits.len());
        for deposit in deposits {
            let id = deposit.coin_id();
            conditions = conditions
                .create_puzzle_announcement(id.into())
                .assert_coin_announcement(deposit_announcement(id).into());
            let spend = deposit_layer.spend(ctx, id, inner_hash)?;
            deposit_spends.push(CoinSpend::new(
                *deposit,
                ctx.serialize(&spend.puzzle)?,
                ctx.serialize(&spend.solution)?,
            ));
        }
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
                    incoming,
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
        let mut spends = vec![CoinSpend::new(
            coin,
            ctx.serialize(&puzzle)?,
            ctx.serialize(&solution)?,
        )];
        spends.extend(deposit_spends);
        Ok(spends)
    }

    fn validate_deposits(&self, singleton: Coin, deposits: &[Coin]) -> Result<u64, DriverError> {
        let puzzle_hash: Bytes32 = P2SingletonArgs::new(self.info().launcher_id)
            .curry_tree_hash()
            .into();
        if deposits.len() >= super::MAX_INTERNAL_CUSTODY_INPUTS
            || !deposits.windows(2).all(|w| w[0].coin_id() < w[1].coin_id())
        {
            return Err(InternalCustodyError::InvalidPayment.into());
        }
        let mut total = 0u64;
        for coin in deposits {
            if coin.puzzle_hash != puzzle_hash || coin.amount == 0 || *coin == singleton {
                return Err(InternalCustodyError::InvalidPayment.into());
            }
            total = total
                .checked_add(coin.amount)
                .ok_or(InternalCustodyError::InvalidPayment)?;
        }
        if !total.is_multiple_of(2) {
            return Err(InternalCustodyError::InvalidPayment.into());
        }
        Ok(total)
    }
}

pub(crate) fn deposit_announcement(id: Bytes32) -> [u8; 32] {
    let mut hash = chia_sha2::Sha256::new();
    hash.update(id.as_ref());
    hash.update(b"$");
    hash.finalize()
}
