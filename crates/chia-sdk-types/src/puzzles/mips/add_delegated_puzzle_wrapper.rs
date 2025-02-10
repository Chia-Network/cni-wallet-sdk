use clvm_traits::{FromClvm, ToClvm};
use clvm_utils::TreeHash;
use hex_literal::hex;

use crate::Mod;

#[derive(Debug, Clone, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(curry)]
pub struct AddDelegatedPuzzleWrapper<W, P> {
    pub wrapper: W,
    pub delegated_puzzle: P,
}

impl<W, P> AddDelegatedPuzzleWrapper<W, P> {
    pub fn new(wrapper: W, delegated_puzzle: P) -> Self {
        Self {
            wrapper,
            delegated_puzzle,
        }
    }
}

impl<W, P> Mod for AddDelegatedPuzzleWrapper<W, P> {
    const MOD_REVEAL: &[u8] = &ADD_DELEGATED_PUZZLE_WRAPPER_PUZZLE;
    const MOD_HASH: TreeHash = ADD_DELEGATED_PUZZLE_WRAPPER_PUZZLE_HASH;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ToClvm, FromClvm)]
#[clvm(solution)]
pub struct AddDelegatedPuzzleWrapperSolution<W, P> {
    pub wrapper_solution: W,
    pub delegated_solution: P,
}

impl<W, P> AddDelegatedPuzzleWrapperSolution<W, P> {
    pub fn new(wrapper_solution: W, delegated_solution: P) -> Self {
        Self {
            wrapper_solution,
            delegated_solution,
        }
    }
}
pub const ADD_DELEGATED_PUZZLE_WRAPPER_PUZZLE: [u8; 19] =
    hex!("ff02ff02ffff04ffff02ff05ff1780ff0b8080");

pub const ADD_DELEGATED_PUZZLE_WRAPPER_PUZZLE_HASH: TreeHash = TreeHash::new(hex!(
    "6427724905f2dcf8187300ef9a0436a3c96198e4fcd17101d1ded9bc61c3f3bf"
));
