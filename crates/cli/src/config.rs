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
        Self::from_env_with_file(None)
    }

    /// Load from optional TOML file, with env vars overriding file values.
    /// File path can be passed explicitly or via `OSMOSMPC_CONFIG` env var.
    pub fn from_env_with_file(path: Option<&str>) -> Self {
        let mut config = if let Some(p) = path
            .map(|s| s.to_string())
            .or_else(|| env::var("OSMOSMPC_CONFIG").ok())
        {
            Self::from_file(&p).unwrap_or_else(|e| {
                tracing::warn!(path = %p, error = %e, "failed to load config file, using defaults");
                Config::default()
            })
        } else {
            // Auto-discover ./config.toml or ./osmiridium.toml if present
            for candidate in ["./config.toml", "./osmiridium.toml", "./data/config.toml"] {
                if std::path::Path::new(candidate).exists() {
                    if let Ok(c) = Self::from_file(candidate) {
                        tracing::info!(path = %candidate, "loaded config file");
                        // Break after first found, but still apply env overrides below
                        // Instead of returning early, set config and break
                        let mut cfg = c;
                        Self::apply_env_overrides(&mut cfg);
                        return cfg;
                    }
                }
            }
            Config::default()
        };

        Self::apply_env_overrides(&mut config);
        config
    }

    /// Load configuration from a TOML (or JSON) file.
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let trimmed = content.trim_start();
        // JSON file
        if trimmed.starts_with('{') {
            let cfg: Config = serde_json::from_str(&content)?;
            return Ok(cfg);
        }
        // Simple TOML parser (sections + key=value) — avoids `toml` crate to keep build lean.
        let mut json = serde_json::json!({
            "network": {},
            "protocol": {},
            "api": {}
        });
        let mut section = String::new();
        for raw_line in content.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].trim().to_lowercase();
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim().to_string();
                let val_raw = v.trim().trim_matches('"').trim_matches('\'').to_string();
                // Try to infer type
                let val_json = if val_raw.eq_ignore_ascii_case("true") {
                    serde_json::Value::Bool(true)
                } else if val_raw.eq_ignore_ascii_case("false") {
                    serde_json::Value::Bool(false)
                } else if let Ok(n) = val_raw.parse::<u64>() {
                    serde_json::Value::Number(n.into())
                } else if let Ok(n) = val_raw.parse::<i64>() {
                    serde_json::Value::Number(n.into())
                } else {
                    serde_json::Value::String(val_raw)
                };
                let target = match section.as_str() {
                    "network" => &mut json["network"],
                    "protocol" => &mut json["protocol"],
                    "api" => &mut json["api"],
                    _ => &mut json,
                };
                target[key] = val_json;
            }
        }
        // Merge with defaults for missing keys
        let mut cfg: Config = serde_json::from_value(json)?;
        // Fill any missing strings with defaults (serde will use default if missing? but we built partial)
        // Ensure defaults for empty strings
        if cfg.network.listen_addr.is_empty() {
            cfg.network.listen_addr = "0.0.0.0".into();
        }
        if cfg.network.cert_dir.is_empty() {
            cfg.network.cert_dir = "./data/certs".into();
        }
        if cfg.api.listen_addr.is_empty() {
            cfg.api.listen_addr = "0.0.0.0".into();
        }
        Ok(cfg)
    }

    fn apply_env_overrides(config: &mut Config) {
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
        if let Some(rounds) = env::var("OSMOSMPC_MAX_ROUNDS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
        {
            config.protocol.max_rounds = rounds;
        }
        if let Ok(mal) = env::var("OSMOSMPC_MALICIOUS").map(|v| v == "true" || v == "1") {
            config.protocol.malicious = mal;
        }
        if let Some(enabled) = env::var("OSMOSMPC_API_ENABLED")
            .ok()
            .map(|v| v == "true" || v == "1")
        {
            config.api.enabled = enabled;
        }
        if let Ok(addr) =
            env::var("OSMOSMPC_API_ADDR").or_else(|_| env::var("OSMOSMPC_API_LISTEN_ADDR"))
        {
            config.api.listen_addr = addr;
        }
        if let Some(api_port) = env::var("OSMOSMPC_API_PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
        {
            config.api.listen_port = api_port;
        }
        // Also support OSMOSMPC_API_LISTEN_PORT alias
        if let Some(api_port) = env::var("OSMOSMPC_API_LISTEN_PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
        {
            config.api.listen_port = api_port;
        }
    }

    /// Get the endpoint string for this party's peer.
    #[allow(dead_code)]
    pub fn peer_endpoint(&self, party_id: usize) -> String {
        let port = self.network.listen_port + party_id as u16;
        format!("127.0.0.1:{}", port)
    }
}
