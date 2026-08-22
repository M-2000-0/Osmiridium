//! Network transport implementations for secure MPC communication.

use crate::error::NetworkResult;
use serde::{Deserialize, Serialize};

/// Transport protocol choice for MPC sessions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportType {
    /// QUIC transport (default)
    Quic,
    /// WebSocket over TLS
    WebSocket,
    /// Direct TCP with noise
    TcpNoise,
}

/// A generic transport interface for MPC message passing.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, peer_id: &str, data: &[u8]) -> NetworkResult<()>;
    async fn recv(&self, peer_id: &str) -> NetworkResult<Vec<u8>>;
    async fn broadcast(&self, data: &[u8]) -> NetworkResult<()>;
    async fn close(&self, peer_id: &str) -> NetworkResult<()>;
}

/// Session configuration for MPC protocols.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionConfig {
    pub protocol: TransportType,
    pub num_parties: usize,
    pub party_id: usize,
    pub timeout_secs: u64,
    pub max_message_size: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            protocol: TransportType::Quic,
            num_parties: 3,
            party_id: 0,
            timeout_secs: 60,
            max_message_size: 64 * 1024 * 1024,
        }
    }
}
