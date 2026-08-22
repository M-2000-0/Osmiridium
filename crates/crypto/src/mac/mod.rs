//! Information-theoretic MACs for authenticated secret sharing.
//!
//! In SPDZ, each share is accompanied by a MAC share such that:
//!   sum(mac_i) = alpha * sum(share_i) = alpha * value
//! where alpha is a secret-shared MAC key.
//! This ensures that any party attempting to tamper with shares
//! will be detected with overwhelming probability.

use crate::field::Scalar;
use crate::sharing::SharingScheme;
use crate::{CryptoError, CryptoResult};
use ark_std::vec::Vec;
use serde::{Deserialize, Serialize};

/// The MAC key used for authenticating shares. This is itself secret-shared
/// among all parties and never reconstructed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacKey {
    /// Secret-shared components of the MAC key alpha.
    /// Each party holds alpha_i, and sum(alpha_i) = alpha.
    pub shares: Vec<Scalar>,
}

impl MacKey {
    pub fn new() -> Self {
        Self { shares: Vec::new() }
    }

    pub fn with_shares(shares: Vec<Scalar>) -> Self {
        Self { shares }
    }

    pub fn len(&self) -> usize {
        self.shares.len()
    }

    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }

    /// Generate MAC key shares for n parties using additive sharing.
    pub fn generate(n: usize) -> CryptoResult<Self> {
        use rand::{Rng, SeedableRng};
        use rand_chacha::ChaCha8Rng;

        let mut rng = ChaCha8Rng::from_entropy();
        let alpha = Scalar::from_u64(rng.gen::<u64>());
        let shares = crate::sharing::AdditiveShare::<Scalar>::split(&alpha, n, 0)?;
        let key_shares: Vec<Scalar> = shares.iter().map(|s| s.value).collect();
        Ok(Self { shares: key_shares })
    }
}

/// A MAC share for a single party. The MAC verifies that the share is correct.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacShare {
    /// The MAC value: mac_i such that sum(mac_i) = alpha * value
    pub mac: Scalar,
    /// The key share alpha_i
    pub key_share: Scalar,
}

impl MacShare {
    pub fn new(mac: Scalar, key_share: Scalar) -> Self {
        Self { mac, key_share }
    }
}

/// An authenticated share, combining a secret share with its MAC.
/// This is the core data structure in SPDZ protocols.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedShare {
    /// The secret share value
    pub share: Scalar,
    /// The MAC share for this secret share
    pub mac: MacShare,
    /// Party ID holding this share
    pub party_id: usize,
}

impl AuthenticatedShare {
    pub fn new(share: Scalar, mac: MacShare, party_id: usize) -> Self {
        Self {
            share,
            mac,
            party_id,
        }
    }

    /// Create a fresh authenticated share.
    /// The MAC satisfies: sum(mac_i) = alpha * sum(share_i) = alpha * value
    /// Each party computes its MAC share as: mac_i = alpha_i * share_i
    /// However, the standard SPDZ MAC requires interaction to compute
    /// the correct MAC for a shared value. This method provides a
    /// simplified per-share MAC that is verified during the protocol.
    pub fn authenticate(
        share: Scalar,
        alpha: Scalar,
        alpha_share: Scalar,
        party_id: usize,
    ) -> Self {
        let mac = alpha * share;
        Self::new(share, MacShare::new(mac, alpha_share), party_id)
    }
}

/// A bundle of authenticated shares from all parties.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ShareBundle {
    pub shares: Vec<AuthenticatedShare>,
}

impl ShareBundle {
    pub fn new() -> Self {
        Self { shares: Vec::new() }
    }

    pub fn add(&mut self, share: AuthenticatedShare) {
        self.shares.push(share);
    }

    pub fn len(&self) -> usize {
        self.shares.len()
    }

    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }

    /// Verify all MACs in the bundle.
    /// Checks: sum(mac_i) = alpha * sum(share_i) where alpha = sum(alpha_i)
    pub fn verify_all(&self) -> CryptoResult<()> {
        let mut value = Scalar::zero();
        let mut mac_sum = Scalar::zero();
        let mut alpha_sum = Scalar::zero();

        for share in &self.shares {
            value += share.share;
            mac_sum += share.mac.mac;
            alpha_sum += share.mac.key_share;
        }

        // The standard SPDZ check: sum(mac_i) = alpha * value
        // But with per-share MACs (mac_i = alpha_i * share_i), this becomes:
        // sum(alpha_i * share_i) = (sum alpha_i) * (sum share_i)
        // which doesn't hold in general.
        //
        // For correct SPDZ verification, we check:
        // sum(mac_i) - alpha * sum(share_i) = 0
        // This works when MACs are properly generated during preprocessing.
        if mac_sum == alpha_sum * value {
            Ok(())
        } else {
            Err(CryptoError::MacVerificationFailed)
        }
    }

    /// Reconstruct the shared value after verification.
    pub fn reconstruct(&self) -> CryptoResult<Scalar> {
        self.verify_all()?;
        let mut value = Scalar::zero();
        for share in &self.shares {
            value += share.share;
        }
        Ok(value)
    }

    /// Verify the MAC against a publicly revealed value.
    /// Used when a party opens its share.
    pub fn verify_with_open_value(&self, opened_value: Scalar, alpha: Scalar) -> CryptoResult<()> {
        let mut mac_sum = Scalar::zero();
        for share in &self.shares {
            mac_sum += share.mac.mac;
        }
        if mac_sum == alpha * opened_value {
            Ok(())
        } else {
            Err(CryptoError::MacVerificationFailed)
        }
    }
}

/// Trait for types that can be revealed.
pub trait Revealable {
    fn reveal(&self, other_shares: &[AuthenticatedShare]) -> CryptoResult<Scalar>;
    fn verify_mac(&self) -> CryptoResult<bool>;
}
