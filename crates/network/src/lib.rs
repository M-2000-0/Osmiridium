//! Secure network communication layer for SMPC parties.
//!
//! Provides authenticated, encrypted channels with support for both
//! QUIC (primary) and WebSocket (fallback) transports.

pub mod cert;
pub mod channel;
pub mod error;
pub mod identity;
pub mod in_memory;
pub mod session;
pub mod tcp;
pub mod tls;
pub mod transport;

pub use cert::{
    cert_fingerprint, create_ca, generate_self_signed, load_cert, make_client_config,
    make_server_config, save_cert, CertConfig, GeneratedCert, PartyCert,
};
pub use channel::{MessageEnvelope, PartyChannel};
pub use error::{NetworkError, NetworkResult};
pub use identity::{Identity, PeerIdentity};
pub use in_memory::{InMemoryTransport, MessageRouter};
pub use session::SessionConfig;
pub use tcp::TcpTransport;
pub use tls::TlsConfig;
pub use transport::TransportType;
