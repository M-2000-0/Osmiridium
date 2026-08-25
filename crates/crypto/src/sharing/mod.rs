//! Secret sharing schemes used in SMPC protocols.
//!
//! Supports both additive sharding (for SPDZ-style protocols) and
//! Shamir sharing (for threshold-based computations).

use crate::field::Scalar;
use crate::{CryptoError, CryptoResult};
use ark_std::vec::Vec;

/// A generic share type.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Share<T = Scalar> {
    /// The share value
    pub value: T,
    /// Party index that holds this share
    pub party_id: usize,
}

/// Trait for secret sharing schemes.
pub trait SharingScheme: Sized {
    type ShareType;
    type ValueType;

    /// Split a secret into n shares with threshold t.
    fn split(
        secret: &Self::ValueType,
        n: usize,
        threshold: usize,
    ) -> CryptoResult<Vec<Self::ShareType>>;

    /// Reconstruct the secret from a set of shares.
    fn reconstruct(shares: &[Self::ShareType]) -> CryptoResult<Self::ValueType>;

    /// Add two shares locally (for additive sharing).
    fn add_shares(a: &Self::ShareType, b: &Self::ShareType) -> CryptoResult<Self::ShareType>;

    /// Multiply a share by a scalar.
    fn scalar_mul(
        share: &Self::ShareType,
        scalar: &Self::ValueType,
    ) -> CryptoResult<Self::ShareType>;
}

/// Additive secret sharing over a prime field.
///
/// A value x is split into shares x_1, x_2, ..., x_n such that
/// x_1 + x_2 + ... + x_n = x (mod p).
/// This is the basis for SPDZ-style protocols.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdditiveShare<T = Scalar> {
    pub value: T,
    pub party_id: usize,
    pub num_parties: usize,
}

impl<T: Copy + Default> AdditiveShare<T> {
    pub fn new(value: T, party_id: usize, num_parties: usize) -> Self {
        Self {
            value,
            party_id,
            num_parties,
        }
    }
}

impl SharingScheme for AdditiveShare<Scalar> {
    type ShareType = Self;
    type ValueType = Scalar;

    fn split(secret: &Scalar, n: usize, _threshold: usize) -> CryptoResult<Vec<Self>> {
        use rand::{Rng, SeedableRng};
        use rand_chacha::ChaCha8Rng;

        let mut rng = ChaCha8Rng::from_entropy();
        let mut shares = Vec::with_capacity(n);
        let mut sum = Scalar::zero();

        for i in 0..n - 1 {
            let r = Scalar::from_u64(rng.gen::<u64>());
            sum += r;
            shares.push(Self::new(r, i, n));
        }

        // Last share = secret - sum
        let last = *secret - sum;
        shares.push(Self::new(last, n - 1, n));

        Ok(shares)
    }

    fn reconstruct(shares: &[Self]) -> CryptoResult<Scalar> {
        let mut sum = Scalar::zero();
        for share in shares {
            sum += share.value;
        }
        Ok(sum)
    }

    fn add_shares(a: &Self, b: &Self) -> CryptoResult<Self> {
        if a.party_id != b.party_id {
            return Err(CryptoError::InvalidShare(
                "Party IDs do not match".to_string(),
            ));
        }
        Ok(Self::new(a.value + b.value, a.party_id, a.num_parties))
    }

    fn scalar_mul(share: &Self, scalar: &Scalar) -> CryptoResult<Self> {
        Ok(Self::new(
            share.value * *scalar,
            share.party_id,
            share.num_parties,
        ))
    }
}

/// Shamir secret sharing over a prime field.
///
/// A value s is split into n shares such that any t+1 shares can reconstruct s,
/// but t shares reveal no information (information-theoretic security).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShamirShare<T = Scalar> {
    pub value: T,
    pub party_id: usize,
    pub threshold: usize,
}

impl<T: Copy + Default> ShamirShare<T> {
    pub fn new(value: T, party_id: usize, threshold: usize) -> Self {
        Self {
            value,
            party_id,
            threshold,
        }
    }
}

impl SharingScheme for ShamirShare<Scalar> {
    type ShareType = Self;
    type ValueType = Scalar;

    fn split(secret: &Scalar, n: usize, threshold: usize) -> CryptoResult<Vec<Self>> {
        if threshold >= n {
            return Err(CryptoError::InvalidThreshold {
                threshold,
                total: n,
            });
        }

        use rand::{Rng, SeedableRng};
        use rand_chacha::ChaCha8Rng;

        let mut rng = ChaCha8Rng::from_entropy();

        // Generate random polynomial coefficients: a_0 = secret, a_1, ..., a_threshold
        let mut coeffs = Vec::with_capacity(threshold + 1);
        coeffs.push(*secret);
        for _ in 0..threshold {
            coeffs.push(Scalar::from_u64(rng.gen::<u64>()));
        }

        // Evaluate polynomial at points 1, 2, ..., n
        let mut shares = Vec::with_capacity(n);
        for i in 1..=n {
            let x = Scalar::from_u64(i as u64);
            let mut y = coeffs[0];
            let mut xpow = Scalar::one();
            for c in &coeffs[1..] {
                xpow *= x;
                y += *c * xpow;
            }
            shares.push(Self::new(y, i - 1, threshold));
        }

        Ok(shares)
    }

    fn reconstruct(shares: &[Self]) -> CryptoResult<Scalar> {
        if shares.len() <= shares[0].threshold {
            return Err(CryptoError::InsufficientShares {
                needed: shares[0].threshold + 1,
                have: shares.len(),
            });
        }

        // Lagrange interpolation
        let mut result = Scalar::zero();

        for (i, si) in shares.iter().enumerate() {
            let xi = Scalar::from_u64((si.party_id + 1) as u64);
            let mut numerator = Scalar::one();
            let mut denominator = Scalar::one();

            for (j, sj) in shares.iter().enumerate() {
                if i == j {
                    continue;
                }
                let xj = Scalar::from_u64((sj.party_id + 1) as u64);
                numerator *= Scalar::zero() - xj;
                denominator *= xi - xj;
            }

            let lambda = numerator * denominator.invert()?;
            result += si.value * lambda;
        }

        Ok(result)
    }

    fn add_shares(a: &Self, b: &Self) -> CryptoResult<Self> {
        Ok(Self::new(a.value + b.value, a.party_id, a.threshold))
    }

    fn scalar_mul(share: &Self, scalar: &Scalar) -> CryptoResult<Self> {
        Ok(Self::new(
            share.value * *scalar,
            share.party_id,
            share.threshold,
        ))
    }
}

/// Trait for Shamir sharing, extending the general sharing scheme.
pub trait ShamirSharing: SharingScheme {
    fn verify_share(&self, _expected_threshold: usize) -> bool {
        true
    }
}

/// Share type alias for convenience.
pub type ShamirScalar = ShamirShare<Scalar>;

/// Additive share type alias.
pub type AdditiveScalar = AdditiveShare<Scalar>;

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_additive_roundtrip(v in 0u64..u64::MAX) {
            let secret = Scalar::from_u64(v);
            for n in [2usize, 3, 5, 10] {
                let shares = AdditiveShare::<Scalar>::split(&secret, n, 0).unwrap();
                assert_eq!(shares.len(), n);
                let recon = AdditiveShare::<Scalar>::reconstruct(&shares).unwrap();
                prop_assert_eq!(recon, secret);
            }
        }

        #[test]
        fn prop_shamir_roundtrip(v in 0u64..u64::MAX, n in 2usize..8, t in 1usize..4) {
            let n = n.max(t + 1);
            let t = t.min(n - 1);
            let secret = Scalar::from_u64(v);
            let shares = ShamirShare::<Scalar>::split(&secret, n, t).unwrap();
            let subset = &shares[..t + 1];
            let recon = ShamirShare::<Scalar>::reconstruct(subset).unwrap();
            prop_assert_eq!(recon, secret);
        }

        #[test]
        fn prop_additive_add_shares(v1 in 0u64..1000, v2 in 0u64..1000) {
            let s1 = Scalar::from_u64(v1);
            let s2 = Scalar::from_u64(v2);
            let n = 3;
            let shares1 = AdditiveShare::<Scalar>::split(&s1, n, 0).unwrap();
            let shares2 = AdditiveShare::<Scalar>::split(&s2, n, 0).unwrap();
            let mut sum_shares = Vec::new();
            for (a, b) in shares1.iter().zip(shares2.iter()) {
                sum_shares.push(AdditiveShare::<Scalar>::add_shares(a, b).unwrap());
            }
            let recon = AdditiveShare::<Scalar>::reconstruct(&sum_shares).unwrap();
            prop_assert_eq!(recon, s1 + s2);
        }
    }

    #[test]
    fn test_additive_zero() {
        let secret = Scalar::zero();
        let shares = AdditiveShare::<Scalar>::split(&secret, 3, 0).unwrap();
        let recon = AdditiveShare::<Scalar>::reconstruct(&shares).unwrap();
        assert_eq!(recon, Scalar::zero());
    }
}
