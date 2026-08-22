//! Environment-based configuration for Osmiridium.

use serde::{Deserialize, Serialize};
use std::env;

/// Top-level configuration loaded from environment variables.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Network settings
    pub network: NetworkConfig,
    /// Protocol settings
    pub protocol: ProtocolConfig,
    /// API settings
    pub api: ApiConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub listen_addr: String,
    pub listen_port: u16,
    pub num_parties: usize,
    pub party_id: usize,
    pub tls_enabled: bool,
    pub cert_dir: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProtocolConfig {
    pub security_bits: usize,
    pub max_rounds: usize,
    pub malicious: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiConfig {
    pub enabled: bool,
    pub listen_addr: String,
    pub listen_port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                listen_addr: "0.0.0.0".to_string(),
                listen_port: 9000,
                num_parties: 3,
                party_id: 0,
                tls_enabled: false,
                cert_dir: "./data/certs".to_string(),
            },
            protocol: ProtocolConfig {
                security_bits: 128,
                max_rounds: 100,
                malicious: false,
            },
            api: ApiConfig {
                enabled: true,
                listen_addr: "0.0.0.0".to_string(),
                listen_port: 8080,
            },
        }
    }
}

impl Config {
    /// Load configuration from environment variables.
    pub fn from_env() -> Self {
        let mut config = Config::default();

        if let Ok(addr) = env::var("OSMOSMPC_LISTEN_ADDR") {
            config.network.listen_addr = addr;
        }
        if let Some(port) = env::var("OSMOSMPC_LISTEN_PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
        {
            config.network.listen_port = port;
        }
        if let Some(n) = env::var("OSMOSMPC_NUM_PARTIES")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
        {
            config.network.num_parties = n;
        }
        if let Some(id) = env::var("OSMOSMPC_PARTY_ID")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
        {
            config.network.party_id = id;
        }
        if let Ok(tls) = env::var("OSMOSMPC_TLS_ENABLED").map(|v| v == "true") {
            config.network.tls_enabled = tls;
        }
        if let Ok(dir) = env::var("OSMOSMPC_CERT_DIR") {
            config.network.cert_dir = dir;
        }

        if let Some(bits) = env::var("OSMOSMPC_SECURITY_BITS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
        {
            config.protocol.security_bits = bits;
        }
        if let Some(api_port) = env::var("OSMOSMPC_API_PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
        {
            config.api.listen_port = api_port;
        }

        config
    }

    /// Get the endpoint string for this party's peer.
    #[allow(dead_code)]
    pub fn peer_endpoint(&self, party_id: usize) -> String {
        let port = self.network.listen_port + party_id as u16;
        format!("127.0.0.1:{}", port)
    }
}
