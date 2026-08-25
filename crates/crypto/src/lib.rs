//! Cryptographic primitives for Osmiridium SMPC.
//!
//! BN254 scalar field (ark-ff), additive/Shamir sharing, information-theoretic
//! MACs, PRSS, OT, and hashing. Re-exports `ark_ff` for field arithmetic.
//!
//! ```rust
//! use osmiridium_crypto::field::Scalar;
//! use osmiridium_crypto::sharing::{AdditiveShare, SharingScheme};
//! let secret = Scalar::from_u64(42);
//! let shares = AdditiveShare::<Scalar>::split(&secret, 3, 0).unwrap();
//! let recon = AdditiveShare::<Scalar>::reconstruct(&shares).unwrap();
//! assert_eq!(recon, secret);
//! ```

pub mod error;
pub mod field;
pub mod hash;
pub mod mac;
pub mod ot;
pub mod prss;
pub mod sharing;
pub mod traits;

pub use error::{CryptoError, CryptoResult};
pub use field::{Scalar, SecretKey};
pub use hash::Hash256;
pub use mac::{AuthenticatedShare, MacKey, MacShare, ShareBundle};
pub use ot::{BaseOT, OTReceiver, OTSender, COT, IKNPUOT, OT1N};
pub use prss::{Prss, PrssParty, PrssState};
pub use sharing::{
    AdditiveScalar, AdditiveShare, ShamirScalar, ShamirShare, ShamirSharing, Share, SharingScheme,
};
pub use traits::{FromBytes, ToBytes};

pub use ark_ff as ff;
