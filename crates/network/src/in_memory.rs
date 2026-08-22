//! In-memory transport for single-process testing and simulation.
//!
//! Provides a simple message-passing transport that routes messages between
//! in-process party endpoints using a shared registry.

use crate::error::{NetworkError, NetworkResult};
use crate::transport::SessionConfig;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;

/// An in-memory transport that uses a shared message router.
#[derive(Clone)]
pub struct InMemoryTransport {
    pub config: SessionConfig,
    pub router: Arc<Mutex<MessageRouter>>,
}

/// Routes messages between parties in the same process.
#[derive(Default)]
pub struct MessageRouter {
    /// channels: peer_id -> pending messages
    channels: std::collections::HashMap<String, Vec<Vec<u8>>>,
}

impl MessageRouter {
    pub fn new() -> Self {
        Self {
            channels: std::collections::HashMap::new(),
        }
    }

    pub fn deliver(&mut self, peer_id: &str, data: Vec<u8>) {
        self.channels
            .entry(peer_id.to_string())
            .or_default()
            .push(data);
    }

    pub fn recv(&mut self, peer_id: &str) -> Option<Vec<u8>> {
        let channel = self.channels.get_mut(peer_id)?;
        if channel.is_empty() {
            return None;
        }
        Some(channel.remove(0))
    }
}

impl InMemoryTransport {
    pub fn new(config: SessionConfig, router: Arc<Mutex<MessageRouter>>) -> Self {
        Self { config, router }
    }

    pub fn peer_key(&self, party_id: usize) -> String {
        format!("party_{}", party_id)
    }
}

#[async_trait]
impl crate::transport::Transport for InMemoryTransport {
    async fn send(&self, peer_id: &str, data: &[u8]) -> NetworkResult<()> {
        let mut router = self.router.lock().await;
        router.deliver(peer_id, data.to_vec());
        Ok(())
    }

    async fn recv(&self, peer_id: &str) -> NetworkResult<Vec<u8>> {
        let mut router = self.router.lock().await;
        router.recv(peer_id).ok_or(NetworkError::NoMessage)
    }

    async fn broadcast(&self, data: &[u8]) -> NetworkResult<()> {
        let mut router = self.router.lock().await;
        for i in 0..self.config.num_parties {
            let key = format!("party_{}", i);
            router.deliver(&key, data.to_vec());
        }
        Ok(())
    }

    async fn close(&self, _peer_id: &str) -> NetworkResult<()> {
        Ok(())
    }
}
