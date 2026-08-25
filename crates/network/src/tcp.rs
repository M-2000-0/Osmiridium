//! TCP transport implementation for secure MPC communication.
//!
//! Provides a real network transport using tokio TCP streams with:
//! - Message framing via length-prefixed protocol
//! - Mailbox routing: each party's listener receives all messages addressed
//!   to it and routes them into its own mailbox (`party_{self_id}`)
//! - Optional TLS encryption with certificate-fingerprint pinning (see
//!   [`crate::tls::TlsConfig`]); without TLS the wire is plaintext
//! - Async message send/receive
//! - Connection management

use crate::error::{NetworkError, NetworkResult};
use crate::identity::Identity;
use crate::tls::TlsConfig;
use crate::transport::SessionConfig;
use crate::transport::Transport;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock};

/// A length-prefixed message frame.
struct FramedMessage {
    data: Vec<u8>,
}

impl FramedMessage {
    fn serialize(&self) -> Vec<u8> {
        let len = (self.data.len() as u32).to_be_bytes();
        let mut out = Vec::with_capacity(4 + self.data.len());
        out.extend_from_slice(&len);
        out.extend_from_slice(&self.data);
        out
    }
}

/// TCP transport with message framing and mailbox routing.
///
/// Mailbox model (consistent with the in-memory transport):
/// - `send(peer_id, data)` delivers `data` to the mailbox of `peer_id`
///   (the recipient's party key).
/// - `recv(peer_id)` pops the next message from `peer_id`'s mailbox. When a
///   party calls `recv`, it passes its own party key to read its inbox.
pub struct TcpTransport {
    pub config: SessionConfig,
    pub identity: Identity,
    pub self_endpoint: String,
    /// TLS settings; `None` means plaintext TCP.
    pub tls: Option<TlsConfig>,
    peer_endpoints: Arc<RwLock<HashMap<usize, String>>>,
    /// inbound mailboxes keyed by recipient party key (`party_{self_id}`)
    inbound: Arc<Mutex<HashMap<String, Vec<Vec<u8>>>>>,
    /// this party's own mailbox key
    self_mailbox: String,
}

impl TcpTransport {
    pub fn new(config: SessionConfig, identity: Identity, self_endpoint: String) -> Self {
        let self_mailbox = format!("party_{}", identity.party_id);
        Self {
            config,
            identity,
            self_endpoint,
            tls: None,
            peer_endpoints: Arc::new(RwLock::new(HashMap::new())),
            inbound: Arc::new(Mutex::new(HashMap::new())),
            self_mailbox,
        }
    }

    /// Enable encrypted transport with certificate-fingerprint pinning.
    ///
    /// The local cert/key pair terminates incoming TLS; outgoing connections
    /// verify peers against `pinned_fingerprints`.
    pub fn with_tls(mut self, tls: TlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    pub fn has_tls(&self) -> bool {
        self.tls.is_some()
    }

    pub async fn add_peer(&self, party_id: usize, endpoint: String) {
        self.peer_endpoints.write().await.insert(party_id, endpoint);
    }

    /// Bind a listener that routes all incoming messages into this party's
    /// own mailbox. All messages received on this listener are addressed to
    /// this party. When TLS is configured, incoming connections must
    /// complete a handshake before frames are accepted.
    pub async fn start_listener(&self) -> NetworkResult<()> {
        let listener = TcpListener::bind(&self.self_endpoint)
            .await
            .map_err(|e| NetworkError::Connection(e.to_string()))?;

        let inbound = self.inbound.clone();
        let self_mailbox = self.self_mailbox.clone();
        let tls_acceptor = self.tls.as_ref().map(|t| t.acceptor());
        let max_message_size = self.config.max_message_size;

        tokio::spawn(async move {
            while let Ok((stream, _addr)) = listener.accept().await {
                let inbound = inbound.clone();
                let self_mailbox = self_mailbox.clone();
                let tls_acceptor = tls_acceptor.clone();

                tokio::spawn(async move {
                    use tokio::io::AsyncRead;
                    let reader: Box<dyn AsyncRead + Unpin + Send> = match tls_acceptor {
                        Some(acceptor) => match acceptor.accept(stream).await {
                            Ok(tls_stream) => Box::new(tls_stream),
                            Err(e) => {
                                tracing::warn!(error = %e, "TLS handshake rejected");
                                return;
                            }
                        },
                        None => Box::new(stream),
                    };
                    let mut reader = BufReader::new(reader);

                    loop {
                        let mut len_buf = [0u8; 4];
                        if reader.read_exact(&mut len_buf).await.is_err() {
                            break;
                        }
                        let len = u32::from_be_bytes(len_buf) as usize;
                        if len > MAX_WIRE_MESSAGE_SIZE {
                            tracing::warn!(len, "frame length exceeds absolute limit");
                            break;
                        }
                        // Enforce the session's configured per-message cap so a
                        // hostile length prefix cannot force oversized reads.
                        if len > max_message_size {
                            tracing::warn!(
                                len,
                                max_message_size,
                                "frame exceeds configured max_message_size; dropping connection"
                            );
                            break;
                        }
                        let mut data = vec![0u8; len];
                        if reader.read_exact(&mut data).await.is_err() {
                            break;
                        }
                        let mut map = inbound.lock().await;
                        map.entry(self_mailbox.clone()).or_default().push(data);
                    }
                });
            }
        });

        Ok(())
    }

    fn server_name_for(endpoint: &str) -> NetworkResult<rustls::pki_types::ServerName<'static>> {
        let host = endpoint
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(endpoint);
        let host = host.trim_start_matches('[').trim_end_matches(']');
        rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| NetworkError::Connection(format!("invalid endpoint host {host:?}: {e}")))
    }

    /// Open a connection to `endpoint`, upgrading to TLS when configured.
    async fn open_stream(
        &self,
        endpoint: &str,
    ) -> NetworkResult<Box<dyn tokio::io::AsyncWrite + Unpin + Send>> {
        let stream = tokio::net::TcpStream::connect(endpoint)
            .await
            .map_err(|e| NetworkError::Connection(e.to_string()))?;

        match &self.tls {
            None => Ok(Box::new(stream)),
            Some(tls) => {
                let server_name = Self::server_name_for(endpoint)?;
                let tls_stream =
                    tls.connector()
                        .connect(server_name, stream)
                        .await
                        .map_err(|e| {
                            NetworkError::Connection(format!("TLS connect to {endpoint}: {e}"))
                        })?;
                Ok(Box::new(tls_stream))
            }
        }
    }

    async fn connect_and_send(&self, endpoint: &str, data: &[u8]) -> NetworkResult<()> {
        if data.len() > self.config.max_message_size {
            return Err(NetworkError::Connection(format!(
                "Message size {} exceeds max allowed {}",
                data.len(),
                self.config.max_message_size
            )));
        }

        let mut stream = self.open_stream(endpoint).await?;

        let msg = FramedMessage {
            data: data.to_vec(),
        };
        let serialized = msg.serialize();
        stream
            .write_all(&serialized)
            .await
            .map_err(|e| NetworkError::Connection(e.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|e| NetworkError::Connection(e.to_string()))?;
        Ok(())
    }
}

/// Absolute cap on any single wire frame regardless of configuration.
const MAX_WIRE_MESSAGE_SIZE: usize = 64 * 1024 * 1024;

#[async_trait]
impl Transport for TcpTransport {
    async fn send(&self, peer_id: &str, data: &[u8]) -> NetworkResult<()> {
        let peer_num: usize = peer_id
            .strip_prefix("party_")
            .and_then(|n| n.parse().ok())
            .or_else(|| peer_id.parse().ok())
            .ok_or_else(|| NetworkError::Connection(format!("Invalid peer id: {}", peer_id)))?;

        let endpoint = {
            let endpoints = self.peer_endpoints.read().await;
            endpoints.get(&peer_num).cloned()
        };

        let endpoint = endpoint
            .ok_or_else(|| NetworkError::Connection(format!("Unknown peer: {}", peer_id)))?;

        self.connect_and_send(&endpoint, data).await
    }

    async fn recv(&self, peer_id: &str) -> NetworkResult<Vec<u8>> {
        let mailbox = if peer_id.starts_with("party_") {
            peer_id.to_string()
        } else {
            format!("party_{}", peer_id)
        };
        let mut map = self.inbound.lock().await;
        let channel = map.get_mut(&mailbox).ok_or(NetworkError::NoMessage)?;
        if channel.is_empty() {
            return Err(NetworkError::NoMessage);
        }
        let data = channel.remove(0);
        if data.len() > self.config.max_message_size {
            return Err(NetworkError::Connection(format!(
                "Received message size {} exceeds max allowed {}",
                data.len(),
                self.config.max_message_size
            )));
        }
        Ok(data)
    }

    async fn broadcast(&self, data: &[u8]) -> NetworkResult<()> {
        if data.len() > self.config.max_message_size {
            return Err(NetworkError::Connection(format!(
                "Broadcast message size {} exceeds max allowed {}",
                data.len(),
                self.config.max_message_size
            )));
        }

        let endpoints: Vec<(usize, String)> = {
            let ep = self.peer_endpoints.read().await;
            ep.iter().map(|(&k, v)| (k, v.clone())).collect()
        };

        for (_party_id, endpoint) in &endpoints {
            self.connect_and_send(endpoint, data).await?;
        }
        Ok(())
    }

    async fn close(&self, _peer_id: &str) -> NetworkResult<()> {
        Ok(())
    }
}

/// Create a TCP listener for receiving incoming connections.
pub async fn listen(addr: &str) -> NetworkResult<TcpListener> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| NetworkError::Connection(e.to_string()))
}

/// Send a framed message to an endpoint over TCP.
pub async fn send_message(addr: &str, data: &[u8]) -> NetworkResult<()> {
    if data.len() > 64 * 1024 * 1024 {
        // 64MB absolute limit
        return Err(NetworkError::Connection(
            "Message exceeds absolute size limit".to_string(),
        ));
    }
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| NetworkError::Connection(e.to_string()))?;
    let msg = FramedMessage {
        data: data.to_vec(),
    };
    let serialized = msg.serialize();

    stream
        .write_all(&serialized)
        .await
        .map_err(|e| NetworkError::Connection(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| NetworkError::Connection(e.to_string()))?;
    Ok(())
}

/// Receive a single framed message from a TCP stream.
pub async fn recv_message(stream: &mut tokio::net::TcpStream) -> NetworkResult<Vec<u8>> {
    let mut reader = BufReader::new(stream);
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| NetworkError::Connection(e.to_string()))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 64 * 1024 * 1024 {
        // 64MB absolute limit
        return Err(NetworkError::Connection(
            "Message length exceeds absolute limit".to_string(),
        ));
    }
    let mut data = vec![0u8; len];
    reader
        .read_exact(&mut data)
        .await
        .map_err(|e| NetworkError::Connection(e.to_string()))?;
    Ok(data)
}
