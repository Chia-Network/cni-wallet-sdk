//! Construction and public policy data for the legacy prefarm custody puzzles.
mod payment;
mod policy;
pub use policy::*;

/// Invalid or unsupported legacy custody data. The clear-signing parser supports
/// only payments and deposit absorption, never a generic delegated spend fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InternalCustodyError {
    /// Invalid internal-custody policy.
    #[error("invalid internal-custody policy")]
    InvalidPolicy,
    /// Invalid internal-custody signing subset.
    #[error("invalid internal-custody signing subset")]
    InvalidSigningSet,
    /// Unsupported internal-custody operation.
    #[error("unsupported internal-custody operation")]
    UnsupportedOperation,
    /// Invalid internal-custody payment.
    #[error("invalid internal-custody payment")]
    InvalidPayment,
    /// Noncanonical or oversized internal-custody program.
    #[error("noncanonical or oversized internal-custody program")]
    InvalidProgram,
    /// Internal-custody coin assertion or lineage mismatch.
    #[error("internal-custody coin assertion or lineage mismatch")]
    CoinAssertion,
    /// Internal-custody conditions do not match the verified payment.
    #[error("internal-custody conditions do not match the verified payment")]
    UnexpectedConditions,
}

pub(crate) use payment::deposit_announcement;

/// Maximum supported singleton-plus-deposit inputs in a verified custody operation.
/// This bounds reconstruction and per-input execution work alongside the cost budget.
pub const MAX_INTERNAL_CUSTODY_INPUTS: usize = 64;

/// An outgoing payment to create alongside the vault continuation.
/// Use `None` in `InternalCustodyPolicy::payment_spends` for claim-only absorption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalCustodyWithdrawal {
    /// Positive, even payment amount in mojos.
    pub amount: u64,
    /// Destination puzzle hash released by ACH completion.
    pub destination: chia_protocol::Bytes32,
}
