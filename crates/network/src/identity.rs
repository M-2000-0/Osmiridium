//! Party identity management for authenticated MPC sessions.
//!
//! Identities are Ed25519 key pairs. `sign` produces a real signature and
//! `verify_signature` validates a message against any peer's public key,
//! replacing the earlier self-HMAC scheme which could only authenticate a
//! party's own messages.

use crate::error::{NetworkError, NetworkResult};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// A peer identity in the MPC network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerIdentity {
    pub party_id: usize,
    pub name: String,
    pub cert_fingerprint: Option<[u8; 32]>,
    pub endpoint: String,
}

/// Local identity with Ed25519 credentials for signing protocol messages.
///
/// The signing seed is wrapped in `Zeroizing` and the `SigningKey` zeroes
/// itself on drop; secret material is never exposed after use.
#[derive(Clone)]
pub struct Identity {
    pub party_id: usize,
    pub name: String,
    /// Ed25519 verifying key, 32 bytes. Distribute this to peers.
    public_key: Vec<u8>,
    signing_key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render private key material.
        f.debug_struct("Identity")
            .field("party_id", &self.party_id)
            .field("name", &self.name)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Generate a fresh random key pair.
    pub fn generate(party_id: usize, name: &str) -> Self {
        let mut seed = Zeroizing::new(vec![0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        Self::from_seed(party_id, name, &seed).expect("random 32-byte seed is always valid")
    }

    /// Deterministic identity from a 32-byte Ed25519 seed (for tests).
    pub fn from_seed(party_id: usize, name: &str, seed: &[u8]) -> NetworkResult<Self> {
        let seed_arr: &[u8; 32] = seed
            .get(..32)
            .and_then(|s| s.try_into().ok())
            .ok_or(NetworkError::AuthFailed)?;
        let signing = ed25519_dalek::SigningKey::from_bytes(seed_arr);

        Ok(Self {
            party_id,
            name: name.to_string(),
            public_key: signing.verifying_key().to_bytes().to_vec(),
            signing_key: Zeroizing::new(signing.to_bytes().to_vec()),
        })
    }

    /// This party's public verification key (Ed25519, 32 bytes).
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Sign `msg` with this identity's Ed25519 key (64-byte signature).
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.signing_key().sign(msg).to_bytes().to_vec()
    }

    /// Verify a message signed by *this* identity (round-trip convenience).
    ///
    /// To verify messages from another party use [`Self::verify_signature`]
    /// with that party's public key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> NetworkResult<bool> {
        Self::verify_signature(self.public_key(), msg, sig)
    }

    /// Verify `sig` over `msg` against an arbitrary Ed25519 public key.
    ///
    /// This is the trust primitive between parties: each participant holds
    /// every other participant's public key out of band.
    pub fn verify_signature(public_key: &[u8], msg: &[u8], sig: &[u8]) -> NetworkResult<bool> {
        let vk_bytes: &[u8; 32] = public_key
            .get(..32)
            .and_then(|k| k.try_into().ok())
            .ok_or(NetworkError::AuthFailed)?;
        let vk = VerifyingKey::from_bytes(vk_bytes).map_err(|_| NetworkError::AuthFailed)?;

        let sig_arr: [u8; SIGNATURE_LENGTH] = sig
            .get(..SIGNATURE_LENGTH)
            .and_then(|s| s.try_into().ok())
            .ok_or(NetworkError::AuthFailed)?;
        let sig = Signature::from_bytes(&sig_arr);

        vk.verify(msg, &sig)
            .map(|_| true)
            .map_err(|_| NetworkError::AuthFailed)
    }

    fn signing_key(&self) -> ed25519_dalek::SigningKey {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&self.signing_key);
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        // Scrub the stack copy immediately; the stored copy is zeroized on drop.
        seed.fill(0);
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_round_trip() {
        let id = Identity::generate(0, "p0");
        let msg = b"round message";
        let sig = id.sign(msg);
        assert_eq!(sig.len(), 64);
        assert!(id.verify(msg, &sig).unwrap());
    }

    #[test]
    fn tampered_message_fails_verification() {
        let id = Identity::generate(1, "p1");
        let sig = id.sign(b"authentic");
        assert!(id.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn cross_party_verification_with_public_keys() {
        let alice = Identity::generate(0, "alice");
        let bob = Identity::generate(1, "bob");

        let msg = b"hello from alice";
        let sig = alice.sign(msg);

        // Bob verifies Alice's message using her public key.
        assert!(Identity::verify_signature(alice.public_key(), msg, &sig).expect("valid signature"));

        // A signature from Bob does not validate under Alice's key.
        let forged = bob.sign(msg);
        assert!(Identity::verify_signature(alice.public_key(), msg, &forged).is_err());
    }

    #[test]
    fn deterministic_from_seed() {
        let a = Identity::from_seed(2, "x", &[7u8; 32]).unwrap();
        let b = Identity::from_seed(2, "x", &[7u8; 32]).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.sign(b"m"), b.sign(b"m"));
    }

    #[test]
    fn rejects_bad_public_key_length() {
        let id = Identity::generate(0, "p");
        let sig = id.sign(b"m");
        assert!(Identity::verify_signature(&[0u8; 8][..], b"m", &sig).is_err());
    }
}
