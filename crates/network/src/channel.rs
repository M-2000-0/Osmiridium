//! Round-based message channel for distributed MPC.
//!
//! Wraps a [`Transport`] and provides sender-addressed send/receive primitives
//! with per-sender inbox demuxing, so protocol phases can address messages to
//! specific parties and read them back in a consistent order regardless of the
//! underlying transport (in-memory or TCP).

use crate::error::{NetworkError, NetworkResult};
use crate::transport::Transport;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Envelope wrapping every message: carries the sender party ID so recipients
/// can demux per-sender without relying on transport-level routing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageEnvelope {
    pub from: usize,
    pub body: Vec<u8>,
}

/// A message channel bound to one party, providing per-sender inboxes.
#[derive(Clone)]
pub struct PartyChannel {
    transport: Arc<dyn Transport>,
    party_id: usize,
    num_parties: usize,
    /// inbox[from] -> queued message bodies from party `from`
    inbox: Arc<Mutex<HashMap<usize, VecDeque<Vec<u8>>>>>,
}

impl PartyChannel {
    pub fn new(transport: Arc<dyn Transport>, party_id: usize, num_parties: usize) -> Self {
        Self {
            transport,
            party_id,
            num_parties,
            inbox: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn party_id(&self) -> usize {
        self.party_id
    }

    pub fn num_parties(&self) -> usize {
        self.num_parties
    }

    fn peer_key(&self, party_id: usize) -> String {
        format!("party_{}", party_id)
    }

    /// Send a serialized body to a specific party.
    pub async fn send_to(&self, to: usize, body: &[u8]) -> NetworkResult<()> {
        let envelope = MessageEnvelope {
            from: self.party_id,
            body: body.to_vec(),
        };
        let bytes = bincode::serialize(&envelope)
            .map_err(|e| NetworkError::Serialization(e.to_string()))?;
        self.transport.send(&self.peer_key(to), &bytes).await
    }

    /// Send a serializable message to a specific party.
    pub async fn send_msg<T: Serialize>(&self, to: usize, msg: &T) -> NetworkResult<()> {
        let body =
            bincode::serialize(msg).map_err(|e| NetworkError::Serialization(e.to_string()))?;
        self.send_to(to, &body).await
    }

    /// Broadcast a serialized body to all other parties.
    pub async fn broadcast(&self, body: &[u8]) -> NetworkResult<()> {
        for to in 0..self.num_parties {
            if to == self.party_id {
                continue;
            }
            self.send_to(to, body).await?;
        }
        Ok(())
    }

    /// Broadcast a serializable message to all other parties.
    pub async fn broadcast_msg<T: Serialize>(&self, msg: &T) -> NetworkResult<()> {
        let body =
            bincode::serialize(msg).map_err(|e| NetworkError::Serialization(e.to_string()))?;
        self.broadcast(&body).await
    }

    /// Receive the next raw body from a specific sender, draining the
    /// transport mailbox until one arrives. Retries while the mailbox is
    /// temporarily empty.
    pub async fn recv_from(&self, from: usize) -> NetworkResult<Vec<u8>> {
        loop {
            {
                let mut inbox = self.inbox.lock().await;
                if let Some(queue) = inbox.get_mut(&from) {
                    if let Some(body) = queue.pop_front() {
                        return Ok(body);
                    }
                }
            }

            // Blocking drain: pull one message from our own mailbox and route it.
            let raw = match self.transport.recv(&self.peer_key(self.party_id)).await {
                Ok(raw) => raw,
                Err(NetworkError::NoMessage) => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(e) => return Err(e),
            };
            let envelope: MessageEnvelope = bincode::deserialize(&raw)
                .map_err(|e| NetworkError::Serialization(e.to_string()))?;
            self.inbox
                .lock()
                .await
                .entry(envelope.from)
                .or_default()
                .push_back(envelope.body);
        }
    }

    /// Receive and deserialize a message from a specific sender.
    pub async fn recv_msg<T: for<'de> Deserialize<'de>>(&self, from: usize) -> NetworkResult<T> {
        let body = self.recv_from(from).await?;
        bincode::deserialize(&body).map_err(|e| NetworkError::Serialization(e.to_string()))
    }

    /// Receive one message from each other party, returned as `(party_id, body)`.
    pub async fn recv_all(&self) -> NetworkResult<Vec<(usize, Vec<u8>)>> {
        let mut out = Vec::with_capacity(self.num_parties.saturating_sub(1));
        for from in 0..self.num_parties {
            if from == self.party_id {
                continue;
            }
            let body = self.recv_from(from).await?;
            out.push((from, body));
        }
        Ok(out)
    }

    /// Receive one message from each other party and deserialize it.
    pub async fn recv_all_msg<T: for<'de> Deserialize<'de>>(
        &self,
    ) -> NetworkResult<Vec<(usize, T)>> {
        let mut out = Vec::with_capacity(self.num_parties.saturating_sub(1));
        for from in 0..self.num_parties {
            if from == self.party_id {
                continue;
            }
            let body = self.recv_from(from).await?;
            let msg = bincode::deserialize(&body)
                .map_err(|e| NetworkError::Serialization(e.to_string()))?;
            out.push((from, msg));
        }
        Ok(out)
    }

    /// Round: broadcast a message and collect one response from every peer.
    /// Used for all-to-all exchanges such as key agreement and open rounds.
    pub async fn all_to_all<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        send: &T,
    ) -> NetworkResult<Vec<(usize, R)>> {
        self.broadcast_msg(send).await?;
        self.recv_all_msg::<R>().await
    }
}
