//! TLS support for the TCP transport.
//!
//! Parties run closed networks, so peer authentication is done by
//! certificate pinning: the client accepts a server only if the SHA-256
//! fingerprint of its leaf certificate matches one of the configured pins.
//! Handshake signatures are still fully verified, so presenting a copied
//! certificate without the matching private key fails. mTLS (client certs)
//! can be layered on later.

use crate::cert::cert_fingerprint;
use crate::error::{NetworkError, NetworkResult};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use std::sync::Arc;

/// TLS configuration for a party's transport.
#[derive(Clone)]
pub struct TlsConfig {
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
    /// SHA-256 fingerprints this client will accept from peers.
    pub pinned_fingerprints: Vec<[u8; 32]>,
}

impl std::fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConfig")
            .field("pinned", &self.pinned_fingerprints.len())
            .finish_non_exhaustive()
    }
}

impl TlsConfig {
    /// Build a TLS config from a local cert/key pair and the set of peer
    /// fingerprints to pin.
    pub fn new(
        local_cert_der: Vec<u8>,
        local_key_der: Vec<u8>,
        pinned_fingerprints: Vec<[u8; 32]>,
    ) -> NetworkResult<Self> {
        let server = crate::cert::make_server_config(&crate::cert::GeneratedCert {
            cert_der: local_cert_der.clone(),
            key_der: local_key_der,
            cert_pem: String::new(),
            key_pem: String::new(),
        })?;

        let verifier = Arc::new(FingerprintVerifier::new(pinned_fingerprints.clone()));
        let client = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        Ok(Self {
            server: Arc::new(server),
            client: Arc::new(client),
            pinned_fingerprints,
        })
    }

    pub fn acceptor(&self) -> tokio_rustls::TlsAcceptor {
        tokio_rustls::TlsAcceptor::from(self.server.clone())
    }

    pub fn connector(&self) -> tokio_rustls::TlsConnector {
        tokio_rustls::TlsConnector::from(self.client.clone())
    }
}

/// A `ServerCertVerifier` that authenticates servers by fingerprint pinning.
///
/// Certificates are self-signed within a closed party set; chain validation
/// against a public CA would be meaningless here. Handshake signatures are
/// still checked with the standard provider so the presented certificate
/// must correspond to the private key in use.
#[derive(Debug)]
pub struct FingerprintVerifier {
    pins: Vec<[u8; 32]>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl FingerprintVerifier {
    pub fn new(pins: Vec<[u8; 32]>) -> Self {
        let provider = rustls::crypto::CryptoProvider::get_default()
            .expect("crypto provider not installed; install ring provider");
        let algorithms = provider.signature_verification_algorithms;
        Self { pins, algorithms }
    }
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp = cert_fingerprint(end_entity.as_ref());
        if self.pins.contains(&fp) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "peer certificate fingerprint {fp:02x?} is not pinned"
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Convenience: build a [`RootCertStore`] trusting exactly one CA cert
/// (kept for future mTLS work).
#[allow(dead_code)]
fn root_store_with(ca_pem: &str) -> NetworkResult<RootCertStore> {
    let mut store = RootCertStore::empty();
    let der = pem_to_der_lossy(ca_pem)?;
    store
        .add(CertificateDer::from(der))
        .map_err(|_| NetworkError::Connection("failed to add CA".to_string()))?;
    Ok(store)
}

fn pem_to_der_lossy(pem: &str) -> NetworkResult<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    B64.decode(body.trim())
        .map_err(|e| NetworkError::Connection(format!("bad PEM: {e}")))
}
