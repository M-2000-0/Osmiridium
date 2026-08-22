//! Network error types for the Osmiridium communication layer.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Authentication failed")]
    AuthFailed,
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Timeout")]
    Timeout,
    #[error("No message available")]
    NoMessage,
    #[error("Peer not found: {0}")]
    PeerNotFound(String),
    #[error("QUIC error: {0}")]
    Quic(String),
    #[error("WebSocket error: {0}")]
    WebSocket(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type NetworkResult<T> = Result<T, NetworkError>;
