//! Protocol error types for the SPDZ MPC protocol.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("Not enough parties: {0}")]
    NotEnoughParties(usize),
    #[error("Invalid party ID: {0}")]
    InvalidPartyId(String),
    #[error("Not enough shares for reconstruction: need {needed}, got {have}")]
    InsufficientShares { needed: usize, have: usize },
    #[error("MAC verification failed at step {0}")]
    MacVerification(String),
    #[error("Preonline phase error: {0}")]
    Preonline(String),
    #[error("Online phase error: {0}")]
    Online(String),
    #[error("Offline phase error: {0}")]
    Offline(String),
    #[error("Circuit evaluation error: {0}")]
    Circuit(String),
    #[error("Invalid circuit: {0}")]
    InvalidCircuit(String),
    #[error("Share computation error: {0}")]
    ShareComputation(String),
    #[error("Reconstruction error: {0}")]
    Reconstruction(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Deserialization error: {0}")]
    Deserialization(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Crypto error: {0}")]
    Crypto(#[from] osmiridium_crypto::CryptoError),
    #[error("Unknown error: {0}")]
    Unknown(String),
}

pub type ProtocolResult<T> = Result<T, ProtocolError>;
