use chia_protocol::Bytes32;
use chia_puzzles::singleton::{
    SingletonArgs, SingletonSolution, SingletonStruct, SINGLETON_LAUNCHER_PUZZLE_HASH,
    SINGLETON_TOP_LAYER_PUZZLE_HASH,
};
use clvm_traits::FromClvm;
use clvm_utils::{CurriedProgram, ToTreeHash, TreeHash};
use clvmr::{Allocator, NodePtr};

use crate::{DriverError, Layer, Puzzle, SpendContext};

#[derive(Debug)]
pub struct SingletonLayer<I> {
    /// The unique launcher id for the singleton. Also referred to as the singleton id.
    pub launcher_id: Bytes32,
    /// The inner puzzle layer. For singletons, this determines the actual behavior of the coin.
    pub inner_puzzle: I,
}

impl<I> SingletonLayer<I> {
    pub fn new(launcher_id: Bytes32, inner_puzzle: I) -> Self {
        Self {
            launcher_id,
            inner_puzzle,
        }
    }
}

impl<I> Layer for SingletonLayer<I>
where
    I: Layer,
{
    type Solution = SingletonSolution<I::Solution>;

    fn parse_puzzle(allocator: &Allocator, puzzle: Puzzle) -> Result<Option<Self>, DriverError> {
        let Some(puzzle) = puzzle.as_curried() else {
            return Ok(None);
        };

        if puzzle.mod_hash != SINGLETON_TOP_LAYER_PUZZLE_HASH {
            return Ok(None);
        }

        let args = SingletonArgs::<NodePtr>::from_clvm(allocator, puzzle.args)?;

        if args.singleton_struct.mod_hash != SINGLETON_TOP_LAYER_PUZZLE_HASH.into()
            || args.singleton_struct.launcher_puzzle_hash != SINGLETON_LAUNCHER_PUZZLE_HASH.into()
        {
            return Err(DriverError::InvalidSingletonStruct);
        }

        let Some(inner_puzzle) =
            I::parse_puzzle(allocator, Puzzle::parse(allocator, args.inner_puzzle))?
        else {
            return Ok(None);
        };

        Ok(Some(Self {
            launcher_id: args.singleton_struct.launcher_id,
            inner_puzzle,
        }))
    }

    fn parse_solution(
        allocator: &Allocator,
        solution: NodePtr,
    ) -> Result<Self::Solution, DriverError> {
        let solution = SingletonSolution::<NodePtr>::from_clvm(allocator, solution)?;
        let inner_solution = I::parse_solution(allocator, solution.inner_solution)?;
        Ok(SingletonSolution {
            lineage_proof: solution.lineage_proof,
            amount: solution.amount,
            inner_solution,
        })
    }

    fn construct_puzzle(&self, ctx: &mut SpendContext) -> Result<NodePtr, DriverError> {
        let curried = CurriedProgram {
            program: ctx.singleton_top_layer()?,
            args: SingletonArgs {
                singleton_struct: SingletonStruct::new(self.launcher_id),
                inner_puzzle: self.inner_puzzle.construct_puzzle(ctx)?,
            },
        };
        Ok(ctx.alloc(&curried)?)
    }

    fn construct_solution(
        &self,
        ctx: &mut SpendContext,
        solution: Self::Solution,
    ) -> Result<NodePtr, DriverError> {
        let inner_solution = self
            .inner_puzzle
            .construct_solution(ctx, solution.inner_solution)?;
        Ok(ctx.alloc(&SingletonSolution {
            lineage_proof: solution.lineage_proof,
            amount: solution.amount,
            inner_solution,
        })?)
    }
}

impl<I> ToTreeHash for SingletonLayer<I>
where
    I: ToTreeHash,
{
    fn tree_hash(&self) -> TreeHash {
        let inner_puzzle = self.inner_puzzle.tree_hash();
        SingletonArgs {
            singleton_struct: SingletonStruct::new(self.launcher_id),
            inner_puzzle,
        }
        .tree_hash()
    }
}