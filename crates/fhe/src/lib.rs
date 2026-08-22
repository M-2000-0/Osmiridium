//! Hybrid Fully Homomorphic Encryption (FHE) components.
//!
//! Provides:
//! - Basic threshold FHE scheme for non-interactive computation
//! - Interface for hybrid SPDZ+FHE protocols
//! - Ciphertext type for encrypted computation
//!
//! This crate complements the SPDZ protocol by handling:
//! - Non-interactive outsourcing of computations to an untrusted server
//! - Long-term encrypted storage
//! - Specific sub-computations where interaction is undesirable

pub mod ciphertext;
pub mod error;
pub mod hybrid;
pub mod scheme;

pub use ciphertext::{Ciphertext, DecryptionKey, EncryptionKey, Plaintext, PublicKey};
pub use error::{FheError, FheResult};
pub use hybrid::{HybridComputation, HybridConfig, HybridMode, HybridResult};
pub use scheme::{FheOps, FheParams, ThresholdFhe};
