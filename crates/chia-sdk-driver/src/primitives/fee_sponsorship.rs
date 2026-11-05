use crate::{DriverError, SpendContext};
use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_puzzle_types::Memos;
use chia_sdk_types::Conditions;
use clvm_traits::clvm_quote;
use clvm_utils::{ToTreeHash, TreeHash};

/// Keyless, irrevocable fee funding for a particular input coin. The fixed
/// conditions enforce exact funding, concurrency and the reserved fee. Ordinary sponsorship has no outputs; reserved sponsorship creates one fixed
/// child fee coin. Neither requires signatures. If the target spends without this coin, the
/// funding is stranded. Concurrency binds the input, not a particular spend path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeSponsorship {
    target_coin_id: Bytes32,
    amount: u64,
    reserve: Option<(Bytes32, u64)>,
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
            reserve: None,
        })
    }
    /// Fund this fee and create a second, fixed fee-sponsorship coin atomically.
    /// The reserve is bound to `reserve_target`, whose ID may be known before it exists.
    /// There is no refund/change path; ordinary sponsorship's stranding rules still apply.
    pub fn with_reserve(
        target_coin_id: Bytes32,
        fee: u64,
        reserve_target: Bytes32,
        reserve_fee: u64,
    ) -> Result<Self, DriverError> {
        let mut result = Self::new(target_coin_id, fee)?;
        Self::new(reserve_target, reserve_fee)?;
        fee.checked_add(reserve_fee)
            .ok_or_else(|| DriverError::Custom("fee funding overflow".into()))?;
        result.reserve = Some((reserve_target, reserve_fee));
        Ok(result)
    }
    fn conditions(&self) -> Conditions<()> {
        let mut conditions = Conditions::default()
            .assert_my_amount(self.amount())
            .assert_concurrent_spend(self.target_coin_id)
            .reserve_fee(self.amount);
        if let Some((target, amount)) = self.reserve {
            let reserve = Self {
                target_coin_id: target,
                amount,
                reserve: None,
            };
            conditions = conditions.create_coin(reserve.puzzle_hash().into(), amount, Memos::None);
        }
        conditions
    }
    /// The child reserve coin is identified by its exact parent, puzzle and amount.
    pub fn reserved_coin(&self, funding_coin: Coin) -> Result<Option<Coin>, DriverError> {
        self.validate_coin(funding_coin)?;
        Ok(self.reserve.map(|(target, amount)| {
            let reserve = Self {
                target_coin_id: target,
                amount,
                reserve: None,
            };
            Coin::new(funding_coin.coin_id(), reserve.puzzle_hash().into(), amount)
        }))
    }
    fn validate_coin(&self, coin: Coin) -> Result<(), DriverError> {
        if coin.amount != self.amount() || coin.puzzle_hash != self.puzzle_hash().into() {
            return Err(DriverError::WrongPuzzleHash);
        }
        Ok(())
    }
    pub fn puzzle_hash(&self) -> TreeHash {
        clvm_quote!(self.conditions()).tree_hash()
    }
    /// Exact funding amount, including any reserve.
    pub fn amount(&self) -> u64 {
        self.amount + self.reserve.map_or(0, |(_, amount)| amount)
    }
    pub fn fee(&self) -> u64 {
        self.amount
    }

    pub fn target_coin_id(&self) -> Bytes32 {
        self.target_coin_id
    }
    pub fn spend(&self, ctx: &mut SpendContext, coin: Coin) -> Result<CoinSpend, DriverError> {
        self.validate_coin(coin)?;
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
    #[test]
    fn reserve_is_exact_and_committed_to_both_inputs() -> anyhow::Result<()> {
        let sponsor =
            FeeSponsorship::with_reserve([1; 32].into(), 500_000, [2; 32].into(), 700_000)?;
        assert_eq!(sponsor.amount(), 1_200_000);
        assert_eq!(sponsor.fee(), 500_000);
        let coin = Coin::new(
            [3; 32].into(),
            sponsor.puzzle_hash().into(),
            sponsor.amount(),
        );
        let reserve = sponsor.reserved_coin(coin)?.unwrap();
        assert_eq!(reserve.parent_coin_info, coin.coin_id());
        assert_eq!(reserve.amount, 700_000);
        let next = FeeSponsorship::new([2; 32].into(), 700_000)?;
        assert_eq!(reserve.puzzle_hash, next.puzzle_hash().into());
        let ctx = &mut SpendContext::new();
        let spend = sponsor.spend(ctx, coin)?;
        let puzzle = spend.puzzle_reveal.to_clvm(&mut **ctx)?;
        let solution = spend.solution.to_clvm(&mut **ctx)?;
        let output = run_program(ctx, &ChiaDialect::new(0), puzzle, solution, 1_000_000)?.1;
        assert_eq!(
            Vec::<Condition<()>>::from_clvm(&**ctx, output)?,
            vec![
                Condition::AssertMyAmount(chia_sdk_types::conditions::AssertMyAmount::new(
                    1_200_000
                )),
                Condition::AssertConcurrentSpend(
                    chia_sdk_types::conditions::AssertConcurrentSpend::new([1; 32].into())
                ),
                Condition::ReserveFee(chia_sdk_types::conditions::ReserveFee::new(500_000)),
                Condition::CreateCoin(chia_sdk_types::conditions::CreateCoin::new(
                    reserve.puzzle_hash,
                    700_000,
                    Memos::None
                )),
            ]
        );
        assert!(FeeSponsorship::with_reserve([1; 32].into(), u64::MAX, [2; 32].into(), 1).is_err());
        assert!(FeeSponsorship::with_reserve([1; 32].into(), 1, [2; 32].into(), 0).is_err());
        assert_ne!(
            sponsor.puzzle_hash(),
            FeeSponsorship::with_reserve([1; 32].into(), 500_000, [4; 32].into(), 700_000)?
                .puzzle_hash()
        );
        assert!(
            sponsor
                .reserved_coin(Coin::new(
                    coin.parent_coin_info,
                    coin.puzzle_hash,
                    1_200_001
                ))
                .is_err()
        );
        assert!(
            sponsor
                .reserved_coin(Coin::new(
                    coin.parent_coin_info,
                    next.puzzle_hash().into(),
                    1_200_000
                ))
                .is_err()
        );
        Ok(())
    }
}
