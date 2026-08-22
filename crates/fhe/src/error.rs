//! FHE error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum FheError {
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),
    #[error("Homomorphic operation not supported: {0}")]
    UnsupportedOperation(String),
    #[error("Insufficient shares for threshold decryption")]
    InsufficientShares,
    #[error("Key generation error: {0}")]
    KeyGen(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Crypto error: {0}")]
    Crypto(#[from] osmiridium_crypto::CryptoError),
}

pub type FheResult<T> = Result<T, FheError>;
