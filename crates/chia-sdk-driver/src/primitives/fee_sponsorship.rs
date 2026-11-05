use crate::{DriverError, SpendContext};
use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_sdk_types::Conditions;
use clvm_traits::clvm_quote;
use clvm_utils::{ToTreeHash, TreeHash};

/// Keyless, irrevocable fee funding for a particular input coin. The fixed
/// conditions enforce exact funding, concurrency and the reserved fee. There
/// are no outputs or signatures. If the target spends without this coin, the
/// funding is stranded. Concurrency binds the input, not a particular spend path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeSponsorship {
    target_coin_id: Bytes32,
    amount: u64,
}
impl FeeSponsorship {
    pub fn new(target_coin_id: Bytes32, amount: u64) -> Result<Self, DriverError> {
        if amount == 0 {
            return Err(DriverError::Custom(
                "fee sponsorship must be positive".into(),
            ));
        }
        Ok(Self {
            target_coin_id,
            amount,
        })
    }
    fn conditions(&self) -> Conditions<()> {
        Conditions::default()
            .assert_my_amount(self.amount)
            .assert_concurrent_spend(self.target_coin_id)
            .reserve_fee(self.amount)
    }
    pub fn puzzle_hash(&self) -> TreeHash {
        clvm_quote!(self.conditions()).tree_hash()
    }
    pub fn amount(&self) -> u64 {
        self.amount
    }
    pub fn target_coin_id(&self) -> Bytes32 {
        self.target_coin_id
    }
    pub fn spend(&self, ctx: &mut SpendContext, coin: Coin) -> Result<CoinSpend, DriverError> {
        if coin.amount != self.amount || coin.puzzle_hash != self.puzzle_hash().into() {
            return Err(DriverError::WrongPuzzleHash);
        }
        Ok(CoinSpend::new(
            coin,
            ctx.serialize(&clvm_quote!(self.conditions()))?,
            ctx.serialize(&())?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chia_sdk_types::Condition;
    use clvm_traits::{FromClvm, ToClvm};
    use clvmr::{ChiaDialect, run_program};
    #[test]
    fn only_exact_funding_can_sponsor_the_committed_input() -> anyhow::Result<()> {
        let fee = FeeSponsorship::new([1; 32].into(), 500_000)?;
        let coin = Coin::new([2; 32].into(), fee.puzzle_hash().into(), 500_000);
        let ctx = &mut SpendContext::new();
        let spend = fee.spend(ctx, coin)?;
        let puzzle = spend.puzzle_reveal.to_clvm(&mut **ctx)?;
        let solution = spend.solution.to_clvm(&mut **ctx)?;
        let output = run_program(ctx, &ChiaDialect::new(0), puzzle, solution, 1_000_000)?.1;
        let actual = Vec::<Condition<()>>::from_clvm(&**ctx, output)?;
        assert_eq!(actual, fee.conditions().into_vec());
        assert!(
            fee.spend(
                ctx,
                Coin::new(coin.parent_coin_info, coin.puzzle_hash, 500_001)
            )
            .is_err()
        );
        assert!(
            fee.spend(
                ctx,
                Coin::new(coin.parent_coin_info, coin.puzzle_hash, 499_999)
            )
            .is_err()
        );
        assert_ne!(
            fee.puzzle_hash(),
            FeeSponsorship::new([3; 32].into(), 500_000)?.puzzle_hash()
        );
        assert!(FeeSponsorship::new([1; 32].into(), 0).is_err());
        Ok(())
    }
}
