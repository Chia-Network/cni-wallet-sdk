use clvm_traits::FromClvmError;
use clvmr::reduction::EvalErr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Eval error: {0}")]
    Eval(#[from] EvalErr),

    #[error("CLVM error: {0}")]
    FromClvm(#[from] FromClvmError),

    #[error("Invalid puzzle")]
    InvalidPuzzle,

    #[error("Incorrect hint")]
    MissingCreateCoin,

    #[error("DID singleton struct mismatch")]
    DidSingletonStructMismatch,

    #[error("Invalid singleton struct")]
    InvalidSingletonStruct,

    #[error("Unknown DID output")]
    UnknownDidOutput,
}