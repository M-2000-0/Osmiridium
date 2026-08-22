//! TLS certificate management for secure MPC communication.

use crate::error::{NetworkError, NetworkResult};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Configuration for generating certificates.
#[derive(Clone, Debug)]
pub struct CertConfig {
    pub common_name: String,
    pub org: String,
}

impl Default for CertConfig {
    fn default() -> Self {
        Self {
            common_name: "osmiridium".to_string(),
            org: "Osmiridium".to_string(),
        }
    }
}

/// Generated certificate and private key (raw DER bytes).
#[derive(Clone, Debug)]
pub struct GeneratedCert {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub cert_pem: String,
    pub key_pem: String,
}

/// Generate a self-signed certificate.
pub fn generate_self_signed(config: &CertConfig) -> NetworkResult<GeneratedCert> {
    let params =
        rcgen::CertificateParams::new(vec![config.common_name.clone(), "localhost".to_string()])
            .map_err(|e| NetworkError::Connection(format!("Params error: {}", e)))?;

    let key_pair = rcgen::KeyPair::generate()
        .map_err(|e| NetworkError::Connection(format!("Key gen error: {}", e)))?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| NetworkError::Connection(format!("Self-signed error: {}", e)))?;

    let cert_der = cert.der().to_vec();
    let key_der = key_pair.serialize_der();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    Ok(GeneratedCert {
        cert_der,
        key_der,
        cert_pem,
        key_pem,
    })
}

/// A managed certificate for a party.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyCert {
    pub party_id: usize,
    pub common_name: String,
    pub cert_pem: String,
    pub cert_fingerprint: [u8; 32],
}

/// Store a certificate to disk.
pub fn save_cert(cert: &GeneratedCert, dir: &Path, name: &str) -> NetworkResult<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)
            .map_err(|e| NetworkError::Connection(format!("Dir error: {}", e)))?;
    }

    let cert_path = dir.join(format!("{}.crt", name));
    let key_path = dir.join(format!("{}.key", name));

    fs::write(&cert_path, &cert.cert_pem)
        .map_err(|e| NetworkError::Connection(format!("Write cert error: {}", e)))?;
    fs::write(&key_path, &cert.key_pem)
        .map_err(|e| NetworkError::Connection(format!("Write key error: {}", e)))?;

    Ok(())
}

/// Load a certificate from disk.
pub fn load_cert(dir: &Path, name: &str) -> NetworkResult<GeneratedCert> {
    let cert_path = dir.join(format!("{}.crt", name));
    let key_path = dir.join(format!("{}.key", name));

    let cert_pem = fs::read_to_string(&cert_path)
        .map_err(|e| NetworkError::Connection(format!("Read cert error: {}", e)))?;
    let key_pem = fs::read_to_string(&key_path)
        .map_err(|e| NetworkError::Connection(format!("Read key error: {}", e)))?;

    let cert_der = pem_to_der(&cert_pem)
        .map_err(|e| NetworkError::Connection(format!("PEM to DER error: {}", e)))?;
    let key_der = pem_to_der(&key_pem)
        .map_err(|e| NetworkError::Connection(format!("PEM to DER key error: {}", e)))?;

    Ok(GeneratedCert {
        cert_der,
        key_der,
        cert_pem,
        key_pem,
    })
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let lines: Vec<&str> = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let joined = lines.join("");
    B64.decode(&joined)
        .map_err(|e| format!("Base64 error: {}", e))
}

/// Create a server TLS config from a certificate.
pub fn make_server_config(cert: &GeneratedCert) -> NetworkResult<ServerConfig> {
    let cert_chain = CertificateDer::from(cert.cert_der.clone());

    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_der.clone().into());

    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_chain], key)
        .map_err(|e| NetworkError::Connection(format!("Server config error: {}", e)))?;

    Ok(cfg)
}

/// Create a client TLS config that trusts a CA cert.
pub fn make_client_config(ca_cert_pem: &str) -> NetworkResult<ClientConfig> {
    let ca_der = pem_to_der(ca_cert_pem)
        .map_err(|e| NetworkError::Connection(format!("CA cert error: {}", e)))?;

    let mut root_store = RootCertStore::empty();
    root_store
        .add(CertificateDer::from(ca_der))
        .map_err(|_| NetworkError::Connection("Failed to add CA cert".to_string()))?;

    let cfg = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(cfg)
}

/// Create a CA and return its certificate and root store.
pub fn create_ca() -> NetworkResult<(GeneratedCert, RootCertStore)> {
    let config = CertConfig {
        common_name: "osmiridium-ca".to_string(),
        org: "Osmiridium CA".to_string(),
    };
    let cert = generate_self_signed(&config)?;

    let mut root_store = RootCertStore::empty();
    root_store
        .add(CertificateDer::from(cert.cert_der.clone()))
        .map_err(|_| NetworkError::Connection("Failed to add CA to store".to_string()))?;

    Ok((cert, root_store))
}

/// Compute SHA-256 fingerprint of a certificate.
pub fn cert_fingerprint(cert_der: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    let result = hasher.finalize();
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&result);
    fingerprint
}
