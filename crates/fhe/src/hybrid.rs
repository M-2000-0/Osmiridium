//! Hybrid FHE + SPDZ computation orchestration.
//!
//! Allows seamless switching between FHE (for non-interactive computation)
//! and SPDZ (for interactive multi-party computation with malicious security).

use crate::ciphertext::Ciphertext;
use crate::error::{FheError, FheResult};
use crate::scheme::{FheOps, ThresholdFhe};
use osmiridium_crypto::field::Scalar;
use serde::{Deserialize, Serialize};

/// Determines which mode to use for a computation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HybridMode {
    /// Use SPDZ for interactive multi-party computation
    Spdz,
    /// Use FHE for non-interactive computation
    Fhe,
    /// Use FHE for preprocessing, SPDZ for online evaluation
    Hybrid,
}

/// Configuration for hybrid computation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridConfig {
    pub mode: HybridMode,
    pub num_parties: usize,
    pub threshold: usize,
    /// Threshold in the FHE scheme
    pub fhe_threshold: usize,
    /// Switch to FHE when circuit depth exceeds this
    pub fhe_depth_threshold: usize,
    /// Switch to SPDZ when interaction cost exceeds this
    pub spdz_interaction_threshold: usize,
}

impl Default for HybridConfig {
    fn default() -> Self {
        Self {
            mode: HybridMode::Hybrid,
            num_parties: 3,
            threshold: 1,
            fhe_threshold: 2,
            fhe_depth_threshold: 5,
            spdz_interaction_threshold: 10,
        }
    }
}

/// A computation step in the hybrid protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ComputationStep {
    /// A step to be computed using SPDZ
    Spdz {
        /// Gate indices in the circuit
        gates: Vec<usize>,
    },
    /// A step to be computed using FHE
    Fhe {
        /// Ciphertexts to compute on
        ciphertexts: Vec<Ciphertext>,
        /// Operation to perform: "add", "mul", "scalar_mul"
        operation: String,
    },
}

/// The result of a hybrid computation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HybridResult {
    pub mode_used: HybridMode,
    /// Output values (revealed to authorized parties)
    pub outputs: Vec<Scalar>,
    /// Which mode was used for each step
    pub modes: Vec<HybridMode>,
    /// Verification status
    pub verified: bool,
}

/// Orchestrator for hybrid FHE+SPDZ computation.
pub struct HybridComputation {
    pub config: HybridConfig,
    pub fhe: Option<ThresholdFhe>,
}

impl HybridComputation {
    pub fn new(config: HybridConfig, fhe: Option<ThresholdFhe>) -> Self {
        Self { config, fhe }
    }

    /// Evaluate a step using the appropriate protocol.
    pub fn evaluate_step(&self, step: &ComputationStep) -> FheResult<Vec<Scalar>> {
        match (&self.config.mode, step) {
            (
                HybridMode::Fhe | HybridMode::Hybrid,
                ComputationStep::Fhe {
                    ciphertexts,
                    operation,
                },
            ) => {
                let fhe = self
                    .fhe
                    .as_ref()
                    .ok_or_else(|| FheError::Encryption("FHE not initialized".to_string()))?;

                let result = match operation.as_str() {
                    "add" => {
                        if ciphertexts.len() < 2 {
                            return Err(FheError::InvalidCiphertext(
                                "need 2 ciphertexts for add".into(),
                            ));
                        }
                        let ct = fhe.add(&ciphertexts[0], &ciphertexts[1])?;
                        let pt = fhe.decrypt(&ct)?;
                        vec![pt.value]
                    }
                    "mul" => {
                        if ciphertexts.len() < 2 {
                            return Err(FheError::InvalidCiphertext(
                                "need 2 ciphertexts for mul".into(),
                            ));
                        }
                        let ct = fhe.mul(&ciphertexts[0], &ciphertexts[1])?;
                        let pt = fhe.decrypt(&ct)?;
                        vec![pt.value]
                    }
                    "scalar_mul" => {
                        if ciphertexts.is_empty() {
                            return Err(FheError::InvalidCiphertext("need a ciphertext".into()));
                        }
                        let scalar = osmiridium_crypto::field::Scalar::from_u64(2u64);
                        let ct = fhe.scalar_mul(&ciphertexts[0], &scalar)?;
                        let pt = fhe.decrypt(&ct)?;
                        vec![pt.value]
                    }
                    _ => return Err(FheError::UnsupportedOperation(operation.clone())),
                };

                Ok(result)
            }
            _ => {
                // For SPDZ steps, we return empty — these would be handled
                // by the SPDZ protocol layer
                Ok(Vec::new())
            }
        }
    }

    /// Determine the optimal mode for a given gate based on circuit analysis.
    pub fn select_mode(&self, gate_depth: usize, requires_interaction: bool) -> HybridMode {
        match self.config.mode {
            HybridMode::Spdz => HybridMode::Spdz,
            HybridMode::Fhe => HybridMode::Fhe,
            HybridMode::Hybrid => {
                if gate_depth > self.config.fhe_depth_threshold && !requires_interaction {
                    HybridMode::Fhe
                } else if requires_interaction {
                    HybridMode::Spdz
                } else {
                    HybridMode::Fhe
                }
            }
        }
    }
}
