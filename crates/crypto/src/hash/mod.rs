//! Hash functions used in the SMPC protocol for commitments and key derivation.

use blake3;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// Standard 256-bit hash (SHA-256).
pub struct Hash256;

impl Hash256 {
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    pub fn hash_concat(data: &[&[u8]]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for d in data {
            hasher.update(d);
        }
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

/// Keccak-256 hash (used for Ethereum-compatible commitments).
pub struct KeccakHash;

impl KeccakHash {
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

/// Blake3 hash (fast, used for commitment schemes).
pub struct Blake3Hash;

impl Blake3Hash {
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(result.as_bytes());
        out
    }

    pub fn derive_key(info: &[u8], key_material: &[u8], out_len: usize) -> Vec<u8> {
        let context = std::str::from_utf8(info).unwrap_or("osmiridium");
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(key_material);
        let result = hasher.finalize();
        result.as_bytes().iter().take(out_len).copied().collect()
    }
}

/// A commitment to a value, used in MPC protocols for binding
/// parties to their inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub hash: [u8; 32],
    pub nonce: [u8; 32],
}

impl Commitment {
    pub fn new(data: &[u8]) -> Self {
        use rand::Rng;
        let nonce: [u8; 32] = rand::thread_rng().gen();
        let hash = Blake3Hash::hash(&[&nonce[..], data].concat());
        Self { hash, nonce }
    }

    pub fn verify(&self, data: &[u8]) -> bool {
        let computed = Blake3Hash::hash(&[&self.nonce[..], data].concat());
        computed == self.hash
    }
}
