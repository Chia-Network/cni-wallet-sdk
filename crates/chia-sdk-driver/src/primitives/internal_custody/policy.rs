use crate::{DriverError, InternalCustodyError};
use chia_bls::PublicKey;
use chia_protocol::Bytes32;
use chia_sdk_types::MerkleProof;
use std::collections::HashSet;

/// Public parameters curried into a legacy custody singleton. Supplying these
/// parameters does not establish their origin; callers must supply trusted data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalCustodyInfo {
    pub launcher_id: Bytes32,
    pub puzzle_root: Bytes32,
    pub withdrawal_timelock: u64,
    pub payment_clawback: u64,
    pub rekey_clawback: u64,
    pub rekey_increment: u64,
    pub slow_rekey: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalCustodyThresholds {
    pub required: u32,
    pub maximum: u32,
    pub minimum: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalCustodyProof {
    pub leaf: Bytes32,
    pub proof: MerkleProof,
}
/// Bounded public derivation data for authorizing a selected subset. The puzzle
/// root and inclusion proofs, not the public-key list alone, enforce authorization.
#[derive(Debug, Clone)]
pub struct InternalCustodyPolicy {
    info: InternalCustodyInfo,
    keys: Vec<PublicKey>,
    thresholds: InternalCustodyThresholds,
    pub(super) filter_proofs: Vec<InternalCustodyProof>,
    pub(super) leaf_proofs: Vec<InternalCustodyProof>,
}
impl InternalCustodyPolicy {
    pub fn new(
        info: InternalCustodyInfo,
        keys: Vec<PublicKey>,
        thresholds: InternalCustodyThresholds,
        filter_proofs: Vec<InternalCustodyProof>,
        leaf_proofs: Vec<InternalCustodyProof>,
    ) -> Result<Self, DriverError> {
        let unique: HashSet<_> = keys.iter().map(PublicKey::to_bytes).collect();
        if keys.is_empty()
            || keys.len() > 16
            || unique.len() != keys.len()
            || keys.iter().any(PublicKey::is_inf)
            || thresholds.minimum == 0
            || thresholds.minimum > thresholds.required
            || thresholds.required > thresholds.maximum
            || thresholds.maximum as usize > keys.len()
            || filter_proofs.len() > 1024
            || leaf_proofs.len() > 1024
            || filter_proofs
                .iter()
                .chain(&leaf_proofs)
                .any(|p| p.proof.root(p.leaf).is_none())
        {
            return Err(InternalCustodyError::InvalidPolicy.into());
        }
        Ok(Self {
            info,
            keys,
            thresholds,
            filter_proofs,
            leaf_proofs,
        })
    }
    pub fn info(&self) -> InternalCustodyInfo {
        self.info
    }
    pub fn keys(&self) -> &[PublicKey] {
        &self.keys
    }
    pub fn thresholds(&self) -> InternalCustodyThresholds {
        self.thresholds
    }

    /// Decode the bounded, big-endian streamable `RootDerivation` format emitted
    /// by Chia-Network/internal-custody. This is public configuration data, not
    /// a signing request. The optional next-root field is metadata and is not
    /// used to authorize a payment under the current root.
    pub fn from_legacy_bytes(raw: &[u8]) -> Result<Self, DriverError> {
        if raw.len() > 128 * 1024 {
            return Err(InternalCustodyError::InvalidPolicy.into());
        }
        let mut r = Reader { raw, pos: 0 };
        let info = InternalCustodyInfo {
            launcher_id: r.take::<32>()?.into(),
            puzzle_root: r.take::<32>()?.into(),
            withdrawal_timelock: r.u64()?,
            payment_clawback: r.u64()?,
            rekey_clawback: r.u64()?,
            rekey_increment: r.u64()?,
            slow_rekey: r.u64()?,
        };
        let count = r.count(16)?;
        let mut keys = Vec::with_capacity(count);
        for _ in 0..count {
            keys.push(
                PublicKey::from_bytes(&r.take()?)
                    .map_err(|_| InternalCustodyError::InvalidPolicy)?,
            );
        }
        let thresholds = InternalCustodyThresholds {
            required: r.u32()?,
            maximum: r.u32()?,
            minimum: r.u32()?,
        };
        match r.take::<1>()?[0] {
            0 => (),
            1 => {
                r.take::<32>()?;
            }
            _ => return Err(InternalCustodyError::InvalidPolicy.into()),
        }
        let filters = r.proofs()?;
        let leaves = r.proofs()?;
        if r.pos != raw.len() {
            return Err(InternalCustodyError::InvalidPolicy.into());
        }
        Self::new(info, keys, thresholds, filters, leaves)
    }
}
struct Reader<'a> {
    raw: &'a [u8],
    pos: usize,
}
impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], DriverError> {
        let end = self
            .pos
            .checked_add(N)
            .ok_or(InternalCustodyError::InvalidPolicy)?;
        let bytes = self
            .raw
            .get(self.pos..end)
            .ok_or(InternalCustodyError::InvalidPolicy)?;
        self.pos = end;
        bytes
            .try_into()
            .map_err(|_| InternalCustodyError::InvalidPolicy.into())
    }
    fn u32(&mut self) -> Result<u32, DriverError> {
        Ok(u32::from_be_bytes(self.take()?))
    }
    fn u64(&mut self) -> Result<u64, DriverError> {
        Ok(u64::from_be_bytes(self.take()?))
    }
    fn count(&mut self, max: usize) -> Result<usize, DriverError> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(InternalCustodyError::InvalidPolicy.into());
        }
        Ok(n)
    }
    fn proofs(&mut self) -> Result<Vec<InternalCustodyProof>, DriverError> {
        let count = self.count(1024)?;
        let mut proofs = Vec::with_capacity(count);
        for _ in 0..count {
            let leaf = self.take::<32>()?.into();
            let path = self.u32()?;
            let depth = self.count(32)?;
            let mut siblings = Vec::with_capacity(depth);
            for _ in 0..depth {
                siblings.push(self.take::<32>()?.into());
            }
            proofs.push(InternalCustodyProof {
                leaf,
                proof: MerkleProof::new(path, siblings),
            });
        }
        Ok(proofs)
    }
}
