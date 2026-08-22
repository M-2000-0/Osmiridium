//! Ciphertext and key types for the threshold FHE scheme.

use osmiridium_crypto::field::Scalar;
use serde::{Deserialize, Serialize};

/// A plaintext value for FHE computation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plaintext {
    pub value: Scalar,
}

impl Plaintext {
    pub fn new(value: Scalar) -> Self {
        Self { value }
    }

    pub fn from_u64(val: u64) -> Self {
        Self {
            value: Scalar::from_u64(val),
        }
    }
}

/// An encryption key for the threshold FHE scheme.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptionKey {
    /// Public parameters
    pub params: Vec<u8>,
    /// Public evaluation key for homomorphism
    pub eval_key: Vec<u8>,
}

/// A key share for threshold decryption.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionKey {
    /// This party's secret share
    pub secret_share: Vec<u8>,
    /// Public key for verification
    pub public_key: Vec<u8>,
    /// Party ID
    pub party_id: usize,
}

/// Public key for FHE operations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKey {
    pub encryption_key: EncryptionKey,
    pub num_parties: usize,
    pub threshold: usize,
}

/// A ciphertext in the threshold FHE scheme.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ciphertext {
    /// Encrypted value
    pub data: Vec<u8>,
    /// Randomness used for encryption (for verification)
    pub randomness: Vec<u8>,
    /// Ciphertext degree (for relinearization)
    pub level: usize,
    /// Threshold required for decryption
    pub threshold: usize,
    /// Number of parties
    pub num_parties: usize,
}

impl Ciphertext {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            randomness: Vec::new(),
            level: 0,
            threshold: 2,
            num_parties: 3,
        }
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Default for Ciphertext {
    fn default() -> Self {
        Self::new()
    }
}
