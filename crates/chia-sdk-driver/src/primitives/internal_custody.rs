//! Construction and public policy data for the legacy prefarm custody puzzles.
mod payment;
mod policy;
pub use policy::*;

/// Invalid or unsupported legacy custody data. The clear-signing parser supports
/// only an initial pending payment, never a generic delegated spend fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InternalCustodyError {
    #[error("invalid internal-custody policy")]
    InvalidPolicy,
    #[error("invalid internal-custody signing subset")]
    InvalidSigningSet,
    #[error("unsupported internal-custody operation")]
    UnsupportedOperation,
    #[error("invalid internal-custody payment")]
    InvalidPayment,
    #[error("noncanonical or oversized internal-custody program")]
    InvalidProgram,
    #[error("internal-custody coin assertion or lineage mismatch")]
    CoinAssertion,
    #[error("internal-custody conditions do not match the verified payment")]
    UnexpectedConditions,
}
