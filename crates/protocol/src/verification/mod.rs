//! Verification and audit facilities for the SPDZ protocol.
//!
//! Provides:
//! - MAC verification for detecting malicious behavior
//! - Protocol transcript for auditing
//! - Verification result types

use crate::crypto::field::Scalar;
use crate::crypto::mac::ShareBundle;
use crate::{ProtocolError, ProtocolResult};
use ark_std::vec::Vec;
use serde::{Deserialize, Serialize};

/// A single entry in the protocol transcript.
/// Used for auditing and compliance verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TranscriptEntry {
    /// The round/step number
    pub step: u64,
    /// The type of operation performed
    pub operation: String,
    /// Party ID that performed the operation
    pub party_id: usize,
    /// Hash of the operation data (for integrity verification)
    pub data_hash: [u8; 32],
    /// Timestamp (as Unix epoch seconds)
    pub timestamp: u64,
    /// Whether this operation passed verification
    pub verified: bool,
}

impl TranscriptEntry {
    pub fn new(
        step: u64,
        operation: &str,
        party_id: usize,
        data_hash: [u8; 32],
        verified: bool,
    ) -> Self {
        Self {
            step,
            operation: operation.to_string(),
            party_id,
            data_hash,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            verified,
        }
    }

    pub fn hash(&self) -> [u8; 32] {
        crate::crypto::hash::Blake3Hash::hash(
            &[
                &self.step.to_le_bytes(),
                self.operation.as_bytes(),
                &self.party_id.to_le_bytes(),
                &self.data_hash,
                &self.timestamp.to_le_bytes(),
            ]
            .concat(),
        )
    }
}

/// Full protocol transcript for auditing.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Transcript {
    pub entries: Vec<TranscriptEntry>,
    /// Current round number
    pub round: u64,
}

impl Transcript {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            round: 0,
        }
    }

    pub fn add(&mut self, entry: TranscriptEntry) {
        self.entries.push(entry);
    }

    pub fn next_round(&mut self) {
        self.round += 1;
    }

    /// Compute a hash of the entire transcript for integrity verification.
    pub fn hash(&self) -> [u8; 32] {
        let mut combined = Vec::new();
        for entry in &self.entries {
            combined.extend_from_slice(&entry.hash());
        }
        crate::crypto::hash::Blake3Hash::hash(&combined)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Result of a MAC verification check.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the verification passed
    pub passed: bool,
    /// The wire that was checked
    pub wire_id: usize,
    /// Expected MAC value
    pub expected_mac: Scalar,
    /// Actual MAC value
    pub actual_mac: Scalar,
    /// Error message if verification failed
    pub error: Option<String>,
}

impl VerificationResult {
    pub fn success(wire_id: usize) -> Self {
        Self {
            passed: true,
            wire_id,
            expected_mac: Scalar::zero(),
            actual_mac: Scalar::zero(),
            error: None,
        }
    }

    pub fn failure(wire_id: usize, expected: Scalar, actual: Scalar, msg: String) -> Self {
        Self {
            passed: false,
            wire_id,
            expected_mac: expected,
            actual_mac: actual,
            error: Some(msg),
        }
    }
}

/// MAC verifier for checking share integrity.
pub struct MacVerifier {
    pub alpha: Scalar,
    pub num_parties: usize,
}

impl MacVerifier {
    pub fn new(alpha: Scalar, num_parties: usize) -> Self {
        Self { alpha, num_parties }
    }

    /// Verify a single share bundle.
    pub fn verify(&self, bundle: &ShareBundle) -> ProtocolResult<VerificationResult> {
        let mut value = Scalar::zero();
        let mut mac_sum = Scalar::zero();
        let mut alpha_sum = Scalar::zero();

        for share in &bundle.shares {
            value += share.share;
            mac_sum += share.mac.mac;
            alpha_sum += share.mac.key_share;
        }

        let expected_mac = alpha_sum * value;
        if mac_sum == expected_mac {
            Ok(VerificationResult::success(0))
        } else {
            Ok(VerificationResult::failure(
                0,
                expected_mac,
                mac_sum,
                "MAC mismatch".to_string(),
            ))
        }
    }

    /// Verify multiple bundles.
    pub fn verify_all(&self, bundles: &[ShareBundle]) -> ProtocolResult<bool> {
        for bundle in bundles {
            let result = self.verify(bundle)?;
            if !result.passed {
                return Err(ProtocolError::MacVerification(
                    "MAC verification failed in batch".to_string(),
                ));
            }
        }
        Ok(true)
    }

    /// Check a batch of MACs using vector-MAC optimization (PRF-based).
    /// This is used for efficient batch verification in the SPDZ protocol.
    pub fn batch_verify(&self, bundles: &[ShareBundle]) -> ProtocolResult<bool> {
        // For each bundle, we verify: sum(mac_i) = alpha * sum(share_i)
        // Batch verification uses random linear combinations to check all at once
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut combined_check = Scalar::zero();
        for bundle in bundles {
            let challenge = Scalar::from_u64(rng.gen::<u64>());
            let mut value = Scalar::zero();
            let mut mac_sum = Scalar::zero();

            for share in &bundle.shares {
                value += share.share;
                mac_sum += share.mac.mac;
            }

            // mac_sum should equal alpha * value
            // We check: challenge * (mac_sum - alpha * value) == 0
            combined_check += challenge * (mac_sum - self.alpha * value);
        }

        if combined_check.is_zero() {
            Ok(true)
        } else {
            Err(ProtocolError::MacVerification(
                "Batch MAC verification failed".to_string(),
            ))
        }
    }
}
