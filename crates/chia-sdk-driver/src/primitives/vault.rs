mod vault_launcher;

use chia_protocol::{Bytes32, Coin};
use chia_puzzles::{
    singleton::{SingletonArgs, SingletonSolution},
    LineageProof, Proof,
};
use clvm_utils::TreeHash;

use crate::{DriverError, Spend, SpendContext};

use super::{member_puzzle_hash, MipsSpend, Restriction};

#[derive(Debug, Clone, Copy)]
pub struct Vault {
    pub coin: Coin,
    pub launcher_id: Bytes32,
    pub proof: Proof,
    pub custody_hash: TreeHash,
}

impl Vault {
    pub fn new(coin: Coin, launcher_id: Bytes32, proof: Proof, custody_hash: TreeHash) -> Self {
        Self {
            coin,
            launcher_id,
            proof,
            custody_hash,
        }
    }

    pub fn custody_hash(
        nonce: usize,
        restrictions: Vec<Restriction>,
        inner_puzzle_hash: TreeHash,
    ) -> TreeHash {
        member_puzzle_hash(nonce, restrictions, inner_puzzle_hash, true)
    }

    pub fn child_lineage_proof(&self) -> LineageProof {
        LineageProof {
            parent_parent_coin_info: self.coin.parent_coin_info,
            parent_inner_puzzle_hash: self.custody_hash.into(),
            parent_amount: self.coin.amount,
        }
    }

    #[must_use]
    pub fn child(&self, custody_hash: TreeHash) -> Self {
        Self {
            coin: Coin::new(
                self.coin.coin_id(),
                SingletonArgs::curry_tree_hash(self.launcher_id, custody_hash).into(),
                self.coin.amount,
            ),
            launcher_id: self.launcher_id,
            proof: Proof::Lineage(self.child_lineage_proof()),
            custody_hash,
        }
    }

    pub fn spend(&self, ctx: &mut SpendContext, spend: &MipsSpend) -> Result<(), DriverError> {
        let custody_spend = spend.spend(ctx, self.custody_hash)?;

        let puzzle = ctx.curry(SingletonArgs::new(self.launcher_id, custody_spend.puzzle))?;
        let solution = ctx.alloc(&SingletonSolution {
            lineage_proof: self.proof,
            amount: self.coin.amount,
            inner_solution: custody_spend.solution,
        })?;

        ctx.spend(self.coin, Spend::new(puzzle, solution))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chia_sdk_test::{test_k1_key, test_k1_keys, Simulator};
    use chia_sdk_types::{Conditions, Mod, Secp256k1Member, Secp256k1MemberSolution};
    use chia_secp::{K1SecretKey, K1Signature};
    use clvmr::sha2::Sha256;
    use rstest::rstest;

    use crate::{Launcher, MemberSpend, MofN, StandardLayer};

    use super::*;

    fn mint_vault(
        sim: &mut Simulator,
        ctx: &mut SpendContext,
        custody_hash: TreeHash,
    ) -> anyhow::Result<Vault> {
        let (sk, pk, _puzzle_hash, coin) = sim.new_p2(1)?;
        let p2 = StandardLayer::new(pk);

        let (mint_vault, vault) =
            Launcher::new(coin.coin_id(), 1).mint_vault(ctx, custody_hash, ())?;
        p2.spend(ctx, coin, mint_vault)?;

        sim.spend_coins(ctx.take(), &[sk])?;

        Ok(vault)
    }

    fn k1_sign(
        ctx: &SpendContext,
        vault: &Vault,
        spend: &MipsSpend,
        k1: &K1SecretKey,
    ) -> anyhow::Result<K1Signature> {
        let mut hasher = Sha256::new();
        hasher.update(ctx.tree_hash(spend.delegated.puzzle));
        hasher.update(vault.coin.coin_id());
        Ok(k1.sign_prehashed(&hasher.finalize())?)
    }

    #[test]
    fn test_simple_vault() -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();

        let k1 = test_k1_key()?;
        let custody = Secp256k1Member::new(k1.public_key());
        let custody_hash = Vault::custody_hash(0, Vec::new(), custody.curry_tree_hash());

        let vault = mint_vault(&mut sim, ctx, custody_hash)?;

        let conditions = Conditions::new().create_coin(vault.custody_hash.into(), 1, None);
        let mut spend = MipsSpend::new(ctx.delegated_spend(conditions)?);

        let signature = k1_sign(ctx, &vault, &spend, &k1)?;
        let k1_puzzle = ctx.curry(custody)?;
        let k1_solution = ctx.alloc(&Secp256k1MemberSolution::new(
            vault.coin.coin_id(),
            signature,
        ))?;

        spend.members.insert(
            custody_hash,
            MemberSpend::new(0, Vec::new(), Spend::new(k1_puzzle, k1_solution)),
        );

        vault.spend(ctx, &spend)?;

        sim.spend_coins(ctx.take(), &[])?;

        Ok(())
    }

    #[rstest]
    #[case::vault_1_of_1(1, 1)]
    #[case::vault_1_of_2(1, 2)]
    #[case::vault_1_of_3(1, 3)]
    #[case::vault_1_of_4(1, 4)]
    #[case::vault_2_of_2(2, 2)]
    #[case::vault_2_of_3(2, 3)]
    #[case::vault_2_of_4(2, 4)]
    #[case::vault_3_of_3(3, 3)]
    #[case::vault_3_of_4(3, 4)]
    #[case::vault_4_of_4(4, 4)]
    fn test_m_of_n_vault(#[case] required: usize, #[case] key_count: usize) -> anyhow::Result<()> {
        let mut sim = Simulator::new();
        let ctx = &mut SpendContext::new();

        let keys = test_k1_keys(key_count)?;

        let members = keys
            .iter()
            .map(|k| Secp256k1Member::new(k.public_key()))
            .collect::<Vec<_>>();

        let hashes = members
            .iter()
            .map(|m| member_puzzle_hash(0, Vec::new(), m.curry_tree_hash(), false))
            .collect::<Vec<_>>();

        let custody = MofN::new(required, hashes.clone());
        let custody_hash = Vault::custody_hash(0, Vec::new(), custody.inner_puzzle_hash());

        let mut vault = mint_vault(&mut sim, ctx, custody_hash)?;

        for start in 0..key_count {
            let conditions = Conditions::new().create_coin(vault.custody_hash.into(), 1, None);
            let mut spend = MipsSpend::new(ctx.delegated_spend(conditions)?);

            spend.members.insert(
                custody_hash,
                MemberSpend::m_of_n(0, Vec::new(), custody.required, custody.items.clone()),
            );

            let mut i = start;

            for _ in 0..required {
                let signature = k1_sign(ctx, &vault, &spend, &keys[i])?;

                let k1_puzzle = ctx.curry(members[i])?;
                let k1_solution = ctx.alloc(&Secp256k1MemberSolution::new(
                    vault.coin.coin_id(),
                    signature,
                ))?;

                spend.members.insert(
                    hashes[i],
                    MemberSpend::new(0, Vec::new(), Spend::new(k1_puzzle, k1_solution)),
                );

                i += 1;

                if i >= key_count {
                    i = 0;
                }
            }

            vault.spend(ctx, &spend)?;
            vault = vault.child(vault.custody_hash);

            sim.spend_coins(ctx.take(), &[])?;
        }

        Ok(())
    }
}
