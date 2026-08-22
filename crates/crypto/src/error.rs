use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid field element: {0}")]
    InvalidFieldElement(String),

    #[error("Invalid share: {0}")]
    InvalidShare(String),

    #[error("MAC verification failed")]
    MacVerificationFailed,

    #[error("Insufficient shares for reconstruction: need {needed}, got {have}")]
    InsufficientShares { needed: usize, have: usize },

    #[error("Invalid threshold: t={threshold}, n={total}")]
    InvalidThreshold { threshold: usize, total: usize },

    #[error("Point not on curve")]
    PointNotOnCurve,

    #[error("Invalid point encoding")]
    InvalidPointEncoding,

    #[error("Scalar multiplication error")]
    ScalarMultiplication,

    #[error("Oblivious transfer error: {0}")]
    OtError(String),

    #[error("PRSS error: {0}")]
    PrssError(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Random number generation error")]
    RngError,

    #[error("Zeroization error")]
    Zeroize,

    #[error("Unknown error: {0}")]
    Unknown(String),
}

pub type CryptoResult<T> = Result<T, CryptoError>;
