use crate::{
    DriverError, InternalCustodyError, InternalCustodyLayer, InternalCustodyPolicy, Layer, Puzzle,
    SingletonLayer, SpendContext,
};
use chia_bls::{PublicKey, SecretKey, Signature};
use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_puzzle_types::{Memos, singleton::SingletonSolution};
use chia_sdk_signer::{AggSigConstants, RequiredBlsSignature};
use chia_sdk_types::{
    Condition,
    conditions::{AggSig, AggSigKind},
    puzzles::{InternalCustodyPaymentArguments, InternalCustodySpendSolution},
};
use clvm_traits::FromClvm;
use clvmr::{
    ChiaDialect, ClvmFlags, NodePtr, run_program,
    serde::{node_from_bytes, node_to_bytes},
};

/// Facts derived from the exact supported initial pending-payment spend. The
/// clawback starts when `pending_coin` confirms; completion is a separate spend.
/// Neither this record nor the verifier establishes chain freshness/unspentness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalCustodyPayment {
    pub input_coin: Coin,
    pub vault_child: Coin,
    pub pending_coin: Coin,
    pub launcher_id: Bytes32,
    pub destination: Bytes32,
    pub clawback_seconds: u64,
    pub withdrawal_seconds: u64,
}

/// An immutable verified payment and signing context. Only the parser can create
/// it. Wallet transport, configuration provenance, user approval and private-key
/// storage remain the caller's responsibilities.
#[derive(Debug, Clone)]
pub struct VerifiedInternalCustodyPayment {
    payment: InternalCustodyPayment,
    selected_signers: Vec<PublicKey>,
    signature: RequiredBlsSignature,
}
impl VerifiedInternalCustodyPayment {
    pub fn payment(&self) -> &InternalCustodyPayment {
        &self.payment
    }
    pub fn selected_signers(&self) -> &[PublicKey] {
        &self.selected_signers
    }
    pub fn required_signature(&self) -> &RequiredBlsSignature {
        &self.signature
    }

    /// Check a public synthetic-offset hint against the verified aggregate key.
    /// The offset is public derivation data, not a custodian's private key.
    pub fn verify_synthetic_offset(&self, offset: &SecretKey) -> bool {
        let aggregate = self
            .selected_signers
            .iter()
            .fold(PublicKey::default(), |sum, key| sum + key);
        aggregate + &offset.public_key() == self.signature.public_key
    }
    /// Produce a share only for a participant in the verified frozen subset.
    /// Callers must obtain user approval of `payment()` before accessing the key.
    pub fn sign_partial(&self, key: &SecretKey) -> Result<Signature, DriverError> {
        if !self.selected_signers.contains(&key.public_key()) {
            return Err(InternalCustodyError::InvalidSigningSet.into());
        }
        Ok(self.signature.sign_partial(key)?)
    }
    pub fn verify_partial(&self, participant: &PublicKey, signature: &Signature) -> bool {
        self.selected_signers.contains(participant)
            && self.signature.verify_partial(participant, signature)
    }
}

/// Verify the exact supported initial payment under caller-trusted policy and
/// signature-domain constants. Rejects extra inputs, claims, rekeys, arbitrary
/// conditions and alternative signing modes. Input programs must be canonical.
///
/// `ctx` must use an appropriately bounded allocator for untrusted inputs. CLVM
/// execution uses the explicit `max_cost` and the consensus dialect directly,
/// avoiding debug dialect logs for offline signer requests. This is local proof
/// checking, not consensus validation of current chain state or relative time.
pub fn parse_internal_custody_payment(
    ctx: &mut SpendContext,
    policy: &InternalCustodyPolicy,
    coin_spends: &[CoinSpend],
    selected_signers: &[PublicKey],
    constants: &AggSigConstants,
    max_cost: u64,
) -> Result<VerifiedInternalCustodyPayment, DriverError> {
    let [spend] = coin_spends else {
        return Err(InternalCustodyError::UnsupportedOperation.into());
    };
    let puzzle = canonical_program(ctx, spend.puzzle_reveal.as_ref())?;
    let solution = canonical_program(ctx, spend.solution.as_ref())?;
    if ctx.tree_hash(puzzle) != spend.coin.puzzle_hash.into() {
        return Err(DriverError::WrongPuzzleHash);
    }
    let Some(layer) =
        SingletonLayer::<InternalCustodyLayer>::parse_puzzle(ctx, Puzzle::parse(ctx, puzzle))?
    else {
        return Err(InternalCustodyError::UnsupportedOperation.into());
    };
    if layer.launcher_id != policy.info().launcher_id
        || layer.inner_puzzle != policy.inner_layer(ctx)?
    {
        return Err(InternalCustodyError::InvalidPolicy.into());
    }
    let singleton =
        SingletonSolution::<InternalCustodySpendSolution<NodePtr, NodePtr, NodePtr>>::from_clvm(
            &**ctx, solution,
        )?;
    if singleton.inner_solution.spend_type != 2 {
        return Err(InternalCustodyError::UnsupportedOperation.into());
    }
    let action =
        InternalCustodyPaymentArguments::from_clvm(&**ctx, singleton.inner_solution.action)?;
    if action.incoming != 0 {
        return Err(InternalCustodyError::UnsupportedOperation.into());
    }
    let expected = policy.payment_spend(
        ctx,
        spend.coin,
        singleton.lineage_proof,
        action.outgoing,
        action.destination,
        selected_signers,
    )?;
    if &expected != spend {
        return Err(InternalCustodyError::UnexpectedConditions.into());
    }
    let final_key = policy.selected_key(selected_signers)?;
    let info = policy.info();
    let pending_puzzle = policy.pending_payment_puzzle(ctx, action.destination)?;
    let payment = InternalCustodyPayment {
        input_coin: spend.coin,
        vault_child: Coin::new(
            spend.coin.coin_id(),
            spend.coin.puzzle_hash,
            spend.coin.amount - action.outgoing,
        ),
        pending_coin: Coin::new(
            spend.coin.coin_id(),
            ctx.tree_hash(pending_puzzle).into(),
            action.outgoing,
        ),
        launcher_id: info.launcher_id,
        destination: action.destination,
        clawback_seconds: info.payment_clawback,
        withdrawal_seconds: info.withdrawal_timelock,
    };
    let output = run_program(
        ctx,
        &ChiaDialect::new(ClvmFlags::empty()),
        puzzle,
        solution,
        max_cost,
    )?
    .1;
    let conditions = Vec::<Condition>::from_clvm(&**ctx, output)?;
    let mut signature = None;
    let mut outputs = Vec::new();
    let mut parents = 0;
    let mut amounts = 0;
    let mut timelocks = 0;
    for condition in conditions {
        match condition {
            Condition::AggSigMe(c)
                if signature.is_none() && c.public_key == final_key && c.message.len() == 32 =>
            {
                signature = Some(RequiredBlsSignature::try_from_condition(
                    &spend.coin,
                    AggSig {
                        kind: AggSigKind::Me,
                        public_key: c.public_key,
                        message: c.message,
                    },
                    constants,
                )?);
            }
            Condition::CreateCoin(c) if c.memos == Memos::<NodePtr>::None => {
                outputs.push(Coin::new(spend.coin.coin_id(), c.puzzle_hash, c.amount));
            }
            Condition::AssertMyParentId(c) if c.parent_id == spend.coin.parent_coin_info => {
                parents += 1;
            }
            Condition::AssertMyAmount(c) if c.amount == spend.coin.amount => {
                amounts += 1;
            }
            Condition::AssertSecondsRelative(c) if c.seconds == info.withdrawal_timelock => {
                timelocks += 1;
            }
            Condition::AssertMyParentId(_) | Condition::AssertMyAmount(_) => {
                return Err(InternalCustodyError::CoinAssertion.into());
            }
            _ => return Err(InternalCustodyError::UnexpectedConditions.into()),
        }
    }
    if parents != 1
        || amounts != 2
        || timelocks != 1
        || outputs != [payment.vault_child, payment.pending_coin]
    {
        return Err(InternalCustodyError::UnexpectedConditions.into());
    }
    Ok(VerifiedInternalCustodyPayment {
        payment,
        selected_signers: selected_signers.to_vec(),
        signature: signature.ok_or(InternalCustodyError::UnexpectedConditions)?,
    })
}
fn canonical_program(ctx: &mut SpendContext, bytes: &[u8]) -> Result<NodePtr, DriverError> {
    if bytes.is_empty() || bytes.len() > 256 * 1024 {
        return Err(InternalCustodyError::InvalidProgram.into());
    }
    let node = node_from_bytes(ctx, bytes)?;
    if node_to_bytes(ctx, node)? != bytes {
        return Err(InternalCustodyError::InvalidProgram.into());
    }
    Ok(node)
}

#[cfg(test)]
mod tests;
