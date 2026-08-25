//! Prime field arithmetic for SMPC operations.
//!
//! Uses ark-ff for constant-time, assembly-optimized field arithmetic.
//! The scalar field of BN254 is used, providing ~128-bit security.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use ark_std::{vec::Vec, Zero};
use serde::{Deserialize, Serialize};

use crate::traits::{FromBytes, ToBytes};
use crate::CryptoResult;

/// Scalar field element used in MPC computations.
/// Wraps ark_bn254::Fr (the scalar field of BN254 curve).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scalar {
    pub inner: Fr,
}

impl Scalar {
    pub fn new(val: Fr) -> Self {
        Self { inner: val }
    }

    pub fn zero() -> Self {
        Self {
            inner: Fr::from(0u64),
        }
    }

    pub fn one() -> Self {
        Self {
            inner: Fr::from(1u64),
        }
    }

    pub fn from_u64(val: u64) -> Self {
        Self {
            inner: Fr::from(val),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() < 32 {
            return Err(crate::CryptoError::Deserialization(
                "insufficient bytes for scalar".to_string(),
            ));
        }
        let fr = Fr::from_le_bytes_mod_order(&bytes[..32]);
        Ok(Self { inner: fr })
    }

    pub fn invert(&self) -> CryptoResult<Self> {
        if self.inner.is_zero() {
            return Err(crate::CryptoError::InvalidFieldElement(
                "cannot invert zero".to_string(),
            ));
        }
        let inv = self.inner.inverse().ok_or_else(|| {
            crate::CryptoError::InvalidFieldElement("inverse failed unexpectedly".to_string())
        })?;
        Ok(Self { inner: inv })
    }

    pub fn is_zero(&self) -> bool {
        self.inner.is_zero()
    }

    pub fn double(&self) -> Self {
        Self {
            inner: self.inner.double(),
        }
    }

    pub fn square(&self) -> Self {
        Self {
            inner: self.inner.square(),
        }
    }

    pub fn negate(&self) -> Self {
        Self { inner: -self.inner }
    }
}

impl From<Fr> for Scalar {
    fn from(val: Fr) -> Self {
        Self { inner: val }
    }
}

impl From<Scalar> for Fr {
    fn from(val: Scalar) -> Self {
        val.inner
    }
}

impl From<u64> for Scalar {
    fn from(val: u64) -> Self {
        Self::from_u64(val)
    }
}

impl ark_std::ops::Add for Scalar {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self {
            inner: self.inner + rhs.inner,
        }
    }
}

impl ark_std::ops::Sub for Scalar {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self {
            inner: self.inner - rhs.inner,
        }
    }
}

impl ark_std::ops::Mul for Scalar {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        Self {
            inner: self.inner * rhs.inner,
        }
    }
}

impl ark_std::ops::Div for Scalar {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        Self {
            inner: self.inner / rhs.inner,
        }
    }
}

impl ark_std::ops::Neg for Scalar {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self { inner: -self.inner }
    }
}

impl ark_std::ops::AddAssign for Scalar {
    fn add_assign(&mut self, rhs: Self) {
        self.inner += rhs.inner;
    }
}

impl ark_std::ops::SubAssign for Scalar {
    fn sub_assign(&mut self, rhs: Self) {
        self.inner -= rhs.inner;
    }
}

impl ark_std::ops::MulAssign for Scalar {
    fn mul_assign(&mut self, rhs: Self) {
        self.inner *= rhs.inner;
    }
}

impl ark_std::ops::DivAssign for Scalar {
    fn div_assign(&mut self, rhs: Self) {
        self.inner /= rhs.inner;
    }
}

impl ark_std::ops::AddAssign<Scalar> for &mut Scalar {
    fn add_assign(&mut self, rhs: Scalar) {
        self.inner += rhs.inner;
    }
}

impl ToBytes for Scalar {
    fn to_bytes(&self) -> Vec<u8> {
        let bigint = self.inner.into_bigint();
        bigint.to_bytes_le()
    }
}

impl FromBytes for Scalar {
    fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        Self::from_bytes(bytes)
    }
}

impl Serialize for Scalar {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.to_bytes();
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = <Vec<u8> as Deserialize>::deserialize(deserializer)?;
        Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// A secret key type for client-side encryption.
/// In the Osmiridium architecture, each party manages its own secret keys
/// for data at rest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretKey {
    data: Vec<u8>,
}

impl SecretKey {
    pub fn generate() -> Self {
        use rand::{Rng, SeedableRng};
        use rand_chacha::ChaCha8Rng;

        let mut rng = ChaCha8Rng::from_entropy();
        let data: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Default for SecretKey {
    fn default() -> Self {
        Self::generate()
    }
}

impl zeroize::Zeroize for SecretKey {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharing::{AdditiveShare, ShamirShare, SharingScheme};

    #[test]
    fn test_scalar_arithmetic() {
        let a = Scalar::from_u64(10);
        let b = Scalar::from_u64(20);
        let c = a + b;
        assert_eq!(c, Scalar::from_u64(30));

        let d = a * b;
        assert_eq!(d, Scalar::from_u64(200));
    }

    #[test]
    fn test_scalar_invert() {
        let a = Scalar::from_u64(5);
        let inv = a.invert().unwrap();
        let product = a * inv;
        assert_eq!(product, Scalar::one());
    }

    #[test]
    fn test_additive_sharing() {
        let secret = Scalar::from_u64(42);
        let shares = AdditiveShare::<Scalar>::split(&secret, 3, 0).unwrap();
        assert_eq!(shares.len(), 3);

        let reconstructed = AdditiveShare::<Scalar>::reconstruct(&shares).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_shamir_sharing() {
        let secret = Scalar::from_u64(99);
        let shares = ShamirShare::<Scalar>::split(&secret, 5, 2).unwrap();
        assert_eq!(shares.len(), 5);

        let reconstructed = ShamirShare::<Scalar>::reconstruct(&shares[..3]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_field_serialization() {
        let original = Scalar::from_u64(12345);
        let bytes = original.to_bytes();
        let recovered = Scalar::from_bytes(&bytes).unwrap();
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_secret_key_generation() {
        let key = SecretKey::generate();
        assert_eq!(key.len(), 32);
        assert!(!key.is_empty());
    }
}
