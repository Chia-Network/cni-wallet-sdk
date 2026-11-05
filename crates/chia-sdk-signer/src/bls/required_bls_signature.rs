use chia_bls::PublicKey;
use chia_consensus::make_aggsig_final_message::u64_to_bytes;
use chia_protocol::{Bytes, Bytes32, Coin};
use chia_sdk_types::conditions::{AggSig, AggSigKind};

use super::AggSigConstants;

#[derive(Debug, Clone)]
pub struct RequiredBlsSignature {
    pub public_key: PublicKey,
    pub raw_message: Bytes,
    pub appended_info: Vec<u8>,
    pub domain_string: Option<Bytes32>,
}

impl RequiredBlsSignature {
    /// Converts a known [`AggSig`] condition to a `RequiredSignature` if possible.
    pub fn from_condition(coin: &Coin, condition: AggSig, constants: &AggSigConstants) -> Self {
        let domain_string;

        let public_key = condition.public_key;
        let message = condition.message;

        let appended_info = match condition.kind {
            AggSigKind::Parent => {
                domain_string = constants.parent();
                coin.parent_coin_info.to_vec()
            }
            AggSigKind::Puzzle => {
                domain_string = constants.puzzle();
                coin.puzzle_hash.to_vec()
            }
            AggSigKind::Amount => {
                domain_string = constants.amount();
                u64_to_bytes(coin.amount)
            }
            AggSigKind::PuzzleAmount => {
                domain_string = constants.puzzle_amount();
                let puzzle = coin.puzzle_hash;
                [puzzle.to_vec(), u64_to_bytes(coin.amount)].concat()
            }
            AggSigKind::ParentAmount => {
                domain_string = constants.parent_amount();
                let parent = coin.parent_coin_info;
                [parent.to_vec(), u64_to_bytes(coin.amount)].concat()
            }
            AggSigKind::ParentPuzzle => {
                domain_string = constants.parent_puzzle();
                [coin.parent_coin_info.to_vec(), coin.puzzle_hash.to_vec()].concat()
            }
            AggSigKind::Unsafe => {
                return Self {
                    public_key,
                    raw_message: message,
                    appended_info: Vec::new(),
                    domain_string: None,
                };
            }
            AggSigKind::Me => {
                domain_string = constants.me();
                coin.coin_id().to_vec()
            }
        };

        Self {
            public_key,
            raw_message: message,
            appended_info,
            domain_string: Some(domain_string),
        }
    }

    /// Sign one share of this condition using its aggregate public key as the
    /// augmentation context. This is not ordinary individual-key signing. The
    /// caller must authorize the participant and the complete transaction first.
    pub fn sign_partial(
        &self,
        secret_key: &chia_bls::SecretKey,
    ) -> Result<chia_bls::Signature, crate::SignerError> {
        if self.public_key.is_inf() || secret_key.public_key().is_inf() {
            return Err(crate::SignerError::InfinityPublicKey);
        }
        let mut augmented = self.public_key.to_bytes().to_vec();
        augmented.extend(self.message());
        Ok(chia_bls::sign_raw(secret_key, augmented))
    }

    /// Verify a participant's share in this condition's common augmentation
    /// context. Ordinary `verify(participant, message)` uses a different context.
    pub fn verify_partial(&self, participant: &PublicKey, signature: &chia_bls::Signature) -> bool {
        if self.public_key.is_inf()
            || participant.is_inf()
            || signature == &chia_bls::Signature::default()
        {
            return false;
        }
        let mut augmented = self.public_key.to_bytes().to_vec();
        augmented.extend(self.message());
        chia_bls::hash_to_g2(&augmented).pair(participant)
            == signature.pair(&PublicKey::generator())
    }

    /// Computes the message that needs to be signed.
    pub fn message(&self) -> Vec<u8> {
        let mut message = Vec::from(self.raw_message.as_ref());
        message.extend(&self.appended_info);
        if let Some(domain_string) = self.domain_string {
            message.extend(domain_string.to_bytes());
        }
        message
    }
}

#[cfg(test)]
mod partial_tests {
    use super::*;
    use chia_bls::{SecretKey, Signature, aggregate, verify};

    #[test]
    fn shares_use_the_condition_augmentation_key() -> anyhow::Result<()> {
        let first = SecretKey::from_seed(&[1; 32]);
        let second = SecretKey::from_seed(&[2; 32]);
        let required = RequiredBlsSignature {
            public_key: first.public_key() + &second.public_key(),
            raw_message: vec![1, 2, 3].into(),
            appended_info: vec![4],
            domain_string: Some([5; 32].into()),
        };
        let a = required.sign_partial(&first)?;
        let b = required.sign_partial(&second)?;
        assert!(required.verify_partial(&first.public_key(), &a));
        assert!(required.verify_partial(&second.public_key(), &b));
        assert!(!required.verify_partial(&second.public_key(), &a));
        assert!(!verify(&a, &first.public_key(), required.message()));
        assert!(verify(
            &aggregate([a.clone(), b]),
            &required.public_key,
            required.message()
        ));
        let mut different = required.clone();
        different.raw_message = vec![9].into();
        assert!(!different.verify_partial(&first.public_key(), &a));
        different = required.clone();
        different.public_key = first.public_key();
        assert!(!different.verify_partial(&first.public_key(), &a));
        assert!(!required.verify_partial(&PublicKey::default(), &a));
        assert!(!required.verify_partial(&first.public_key(), &Signature::default()));
        different.public_key = PublicKey::default();
        assert!(different.sign_partial(&first).is_err());
        Ok(())
    }
}
