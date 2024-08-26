use chia_bls::PublicKey;
use chia_protocol::{Bytes, Bytes32};
use chia_sdk_derive::conditions;
use clvm_traits::{FromClvm, ToClvm};
use clvmr::sha2::Sha256;

conditions! {
    pub enum Condition<T> {
        Remark<T> as Copy {
            opcode: i8 if 1,
            ...rest: T,
        },
        AggSigParent {
            opcode: i8 if 43,
            public_key: PublicKey,
            message: Bytes,
        },
        AggSigPuzzle {
            opcode: i8 if 44,
            public_key: PublicKey,
            message: Bytes,
        },
        AggSigAmount {
            opcode: i8 if 45,
            public_key: PublicKey,
            message: Bytes,
        },
        AggSigPuzzleAmount {
            opcode: i8 if 46,
            public_key: PublicKey,
            message: Bytes,
        },
        AggSigParentAmount {
            opcode: i8 if 47,
            public_key: PublicKey,
            message: Bytes,
        },
        AggSigParentPuzzle {
            opcode: i8 if 48,
            public_key: PublicKey,
            message: Bytes,
        },
        AggSigUnsafe {
            opcode: i8 if 49,
            public_key: PublicKey,
            message: Bytes,
        },
        AggSigMe {
            opcode: i8 if 50,
            public_key: PublicKey,
            message: Bytes,
        },
        CreateCoin {
            opcode: i8 if 51,
            puzzle_hash: Bytes32,
            amount: u64,
            memos?: Vec<Bytes>,
        },
        ReserveFee as Copy {
            opcode: i8 if 52,
            amount: u64,
        },
        CreateCoinAnnouncement {
            opcode: i8 if 60,
            message: Bytes,
        },
        AssertCoinAnnouncement as Copy {
            opcode: i8 if 61,
            announcement_id: Bytes32,
        },
        CreatePuzzleAnnouncement {
            opcode: i8 if 62,
            message: Bytes,
        },
        AssertPuzzleAnnouncement as Copy {
            opcode: i8 if 63,
            announcement_id: Bytes32,
        },
        AssertConcurrentSpend as Copy {
            opcode: i8 if 64,
            coin_id: Bytes32,
        },
        AssertConcurrentPuzzle as Copy {
            opcode: i8 if 65,
            puzzle_hash: Bytes32,
        },
        AssertMyCoinId as Copy {
            opcode: i8 if 70,
            coin_id: Bytes32,
        },
        AssertMyParentId as Copy {
            opcode: i8 if 71,
            parent_id: Bytes32,
        },
        AssertMyPuzzleHash as Copy {
            opcode: i8 if 72,
            puzzle_hash: Bytes32,
        },
        AssertMyAmount as Copy {
            opcode: i8 if 73,
            amount: u64,
        },
        AssertMyBirthSeconds as Copy {
            opcode: i8 if 74,
            seconds: u64,
        },
        AssertMyBirthHeight as Copy {
            opcode: i8 if 75,
            height: u32,
        },
        AssertEphemeral as Default + Copy {
            opcode: i8 if 76,
        },
        AssertSecondsRelative as Copy {
            opcode: i8 if 80,
            seconds: u64,
        },
        AssertSecondsAbsolute as Copy {
            opcode: i8 if 81,
            seconds: u64,
        },
        AssertHeightRelative as Copy {
            opcode: i8 if 82,
            height: u32,
        },
        AssertHeightAbsolute as Copy {
            opcode: i8 if 83,
            height: u32,
        },
        AssertBeforeSecondsRelative as Copy {
            opcode: i8 if 84,
            seconds: u64,
        },
        AssertBeforeSecondsAbsolute as Copy {
            opcode: i8 if 85,
            seconds: u64,
        },
        AssertBeforeHeightRelative as Copy {
            opcode: i8 if 86,
            height: u32,
        },
        AssertBeforeHeightAbsolute as Copy {
            opcode: i8 if 87,
            height: u32,
        },
        Softfork<T> as Copy {
            opcode: i8 if 90,
            cost: u64,
            ...rest: T,
        },
        MeltSingleton as Default + Copy {
            opcode: i8 if 51,
            puzzle_hash: () if (),
            magic_amount: i8 if -113,
        },
        TransferNft as Default {
            opcode: i8 if -10,
            did_id: Option<Bytes32>,
            trade_prices: Vec<(u16, Bytes32)>,
            did_inner_puzzle_hash: Option<Bytes32>,
        },
        RevealCatTail<P, S> as Copy {
            opcode: u8 if 51,
            puzzle_hash: () if (),
            magic_amount: i8 if -113,
            program: P,
            solution: S,
        },
        UpdateNftMetadata<P, S> as Copy {
            opcode: i8 if -24,
            updater_puzzle_reveal: P,
            updater_solution: S,
        },
        UpdateDataStoreMerkleRoot {
            opcode: i8 if -13,
            new_merkle_root: Bytes32,
            memos: Vec<Bytes>,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct NewMetadataInfo<M> {
    pub new_metadata: M,
    pub new_updater_puzzle_hash: Bytes32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct NewMetadataOutput<M, C> {
    pub metadata_info: NewMetadataInfo<M>,
    pub conditions: C,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm, Hash)]
#[repr(u8)]
#[clvm(atom)]
pub enum AggSigKind {
    Parent = 43,
    Puzzle = 44,
    Amount = 45,
    PuzzleAmount = 46,
    ParentAmount = 47,
    ParentPuzzle = 48,
    Unsafe = 49,
    Me = 50,
}

#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(list)]
pub struct AggSig {
    pub kind: AggSigKind,
    pub public_key: PublicKey,
    pub message: Bytes,
}

impl AggSig {
    pub fn new(kind: AggSigKind, public_key: PublicKey, message: Bytes) -> Self {
        Self {
            kind,
            public_key,
            message,
        }
    }
}

impl<T> Condition<T> {
    pub fn into_agg_sig(self) -> Option<AggSig> {
        match self {
            Condition::AggSigParent(inner) => Some(AggSig::new(
                AggSigKind::Parent,
                inner.public_key,
                inner.message,
            )),
            Condition::AggSigPuzzle(inner) => Some(AggSig::new(
                AggSigKind::Puzzle,
                inner.public_key,
                inner.message,
            )),
            Condition::AggSigAmount(inner) => Some(AggSig::new(
                AggSigKind::Amount,
                inner.public_key,
                inner.message,
            )),
            Condition::AggSigPuzzleAmount(inner) => Some(AggSig::new(
                AggSigKind::PuzzleAmount,
                inner.public_key,
                inner.message,
            )),
            Condition::AggSigParentAmount(inner) => Some(AggSig::new(
                AggSigKind::ParentAmount,
                inner.public_key,
                inner.message,
            )),
            Condition::AggSigParentPuzzle(inner) => Some(AggSig::new(
                AggSigKind::ParentPuzzle,
                inner.public_key,
                inner.message,
            )),
            Condition::AggSigUnsafe(inner) => Some(AggSig::new(
                AggSigKind::Unsafe,
                inner.public_key,
                inner.message,
            )),
            Condition::AggSigMe(inner) => {
                Some(AggSig::new(AggSigKind::Me, inner.public_key, inner.message))
            }
            _ => None,
        }
    }

    pub fn is_agg_sig(&self) -> bool {
        matches!(
            self,
            Condition::AggSigParent(..)
                | Condition::AggSigPuzzle(..)
                | Condition::AggSigAmount(..)
                | Condition::AggSigPuzzleAmount(..)
                | Condition::AggSigParentAmount(..)
                | Condition::AggSigParentPuzzle(..)
                | Condition::AggSigUnsafe(..)
                | Condition::AggSigMe(..)
        )
    }
}

pub fn announcement_id(coin_info: Bytes32, message: impl AsRef<[u8]>) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(coin_info.as_ref());
    hasher.update(message.as_ref());
    Bytes32::from(hasher.finalize())
}
