//! Party identity management for authenticated MPC sessions.

use crate::error::{NetworkError, NetworkResult};
use serde::{Deserialize, Serialize};

/// A peer identity in the MPC network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerIdentity {
    pub party_id: usize,
    pub name: String,
    pub cert_fingerprint: Option<[u8; 32]>,
    pub endpoint: String,
}

/// Local identity with credentials for signing protocol messages.
#[derive(Clone, Debug)]
pub struct Identity {
    pub party_id: usize,
    pub name: String,
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl Identity {
    pub fn generate(party_id: usize, name: &str) -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let private_key: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let public_key = blake3::hash(&private_key).as_bytes().to_vec();

        Self {
            party_id,
            name: name.to_string(),
            private_key,
            public_key,
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mut mac = HmacSha256::new_from_slice(&self.private_key).unwrap();
        mac.update(msg);
        mac.finalize().into_bytes().to_vec()
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> NetworkResult<bool> {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<sha2::Sha256>;
        let mut mac =
            HmacSha256::new_from_slice(&self.private_key).map_err(|_| NetworkError::AuthFailed)?;
        mac.update(msg);
        mac.verify_slice(sig)
            .map(|_| true)
            .map_err(|_| NetworkError::AuthFailed)
    }
}
