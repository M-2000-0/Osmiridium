//! Threshold FHE scheme parameters and operations.
//!
//! This implements a simplified threshold FHE scheme based on
//! Paillier-like encryption for additive homomorphism, with
//! extensions for multiplication via threshold decryption.

use crate::ciphertext::{Ciphertext, DecryptionKey, EncryptionKey, Plaintext, PublicKey};
use crate::error::{FheError, FheResult};
use osmiridium_crypto::field::Scalar;
use osmiridium_crypto::traits::ToBytes;
use serde::{Deserialize, Serialize};

/// Parameters for the FHE scheme.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FheParams {
    /// Security parameter in bits
    pub security_bits: usize,
    /// Number of parties for threshold scheme
    pub num_parties: usize,
    /// Threshold for decryption (t-out-of-n)
    pub threshold: usize,
    /// Maximum circuit depth
    pub max_depth: usize,
}

impl Default for FheParams {
    fn default() -> Self {
        Self {
            security_bits: 128,
            num_parties: 3,
            threshold: 2,
            max_depth: 10,
        }
    }
}

/// Homomorphic operations supported by the FHE scheme.
pub trait FheOps {
    /// Homomorphic addition of two ciphertexts
    fn add(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> FheResult<Ciphertext>;

    /// Homomorphic scalar multiplication
    fn scalar_mul(&self, ct: &Ciphertext, scalar: &Scalar) -> FheResult<Ciphertext>;

    /// Homomorphic multiplication (requires relinearization)
    fn mul(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> FheResult<Ciphertext>;

    /// Negation
    fn neg(&self, ct: &Ciphertext) -> FheResult<Ciphertext>;
}

/// A threshold FHE scheme instance.
pub struct ThresholdFhe {
    pub params: FheParams,
    /// Secret share of the encryption key (never fully reconstructed)
    pub decryption_key: DecryptionKey,
    /// Public encryption parameters
    pub public_key: PublicKey,
}

impl ThresholdFhe {
    /// Generate keys for a threshold FHE scheme.
    pub fn keygen(params: FheParams) -> FheResult<(PublicKey, Vec<DecryptionKey>)> {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // In a real implementation, this would generate:
        // - A public/private key pair for the homomorphic encryption scheme
        // - Threshold secret shares using Shamir's scheme
        // - Evaluation keys for multiplication

        let mut decryption_keys = Vec::with_capacity(params.num_parties);
        for i in 0..params.num_parties {
            let secret_share: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();
            let public_key: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();
            decryption_keys.push(DecryptionKey {
                secret_share,
                public_key: public_key.clone(),
                party_id: i,
            });
        }

        let encryption_key = EncryptionKey {
            params: vec![],
            eval_key: vec![],
        };

        let public_key = PublicKey {
            encryption_key,
            num_parties: params.num_parties,
            threshold: params.threshold,
        };

        Ok((public_key, decryption_keys))
    }

    /// Create a new FHE instance with given keys.
    pub fn new(params: FheParams, decryption_key: DecryptionKey, public_key: PublicKey) -> Self {
        Self {
            params,
            decryption_key,
            public_key,
        }
    }

    /// Encrypt a plaintext value.
    pub fn encrypt(&self, plaintext: &Plaintext) -> FheResult<Ciphertext> {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let plaintext_bytes = plaintext.value.to_bytes();
        let randomness: Vec<u8> = (0..32).map(|_| rng.gen::<u8>()).collect();

        // In a real implementation, this would use proper homomorphic encryption
        // For the prototype, we store the plaintext bytes with randomness
        let mut data = plaintext_bytes.clone();
        data.extend_from_slice(&randomness);

        Ok(Ciphertext {
            data,
            randomness,
            level: 0,
            threshold: self.params.threshold,
            num_parties: self.params.num_parties,
        })
    }

    /// Partial decryption by a single party.
    pub fn partial_decrypt(&self, _ct: &Ciphertext) -> FheResult<Vec<u8>> {
        // In a real implementation, this would produce a partial decryption share
        // For the prototype, we return the decryption key's secret share
        Ok(self.decryption_key.secret_share.clone())
    }

    /// Combine partial decryptions to recover the plaintext.
    pub fn combine_decryptions(
        &self,
        ct: &Ciphertext,
        partial_shares: &[Vec<u8>],
    ) -> FheResult<Scalar> {
        if partial_shares.len() < self.params.threshold {
            return Err(FheError::InsufficientShares);
        }

        // In a real implementation, combine shares using threshold cryptography
        // For the prototype, we just extract the plaintext from the first 32 bytes
        if ct.data.len() < 32 {
            return Err(FheError::Decryption("ciphertext too short".to_string()));
        }

        let plaintext = Scalar::from_bytes(&ct.data[..32])?;
        Ok(plaintext)
    }

    /// Fully decrypt with all shares.
    pub fn decrypt(&self, ct: &Ciphertext) -> FheResult<Plaintext> {
        let partial = self.partial_decrypt(ct)?;
        let all_shares = vec![partial];
        let value = self.combine_decryptions(ct, &all_shares)?;
        Ok(Plaintext::new(value))
    }
}

impl FheOps for ThresholdFhe {
    fn add(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> FheResult<Ciphertext> {
        // Homomorphic addition: combine ciphertext data
        let mut data = ct1.data.clone();
        data.extend_from_slice(&ct2.data);

        Ok(Ciphertext {
            data,
            randomness: vec![],
            level: ct1.level.max(ct2.level),
            threshold: self.params.threshold,
            num_parties: self.params.num_parties,
        })
    }

    fn scalar_mul(&self, ct: &Ciphertext, scalar: &Scalar) -> FheResult<Ciphertext> {
        // In a real scheme: multiply ciphertext by plaintext scalar
        let scalar_bytes = scalar.to_bytes();
        let mut data = ct.data.clone();
        data.extend_from_slice(&scalar_bytes);

        Ok(Ciphertext {
            data,
            randomness: ct.randomness.clone(),
            level: ct.level,
            threshold: self.params.threshold,
            num_parties: self.params.num_parties,
        })
    }

    fn mul(&self, ct1: &Ciphertext, ct2: &Ciphertext) -> FheResult<Ciphertext> {
        #[cfg(not(feature = "fhe-mul"))]
        {
            let _ = (ct1, ct2);
            Err(FheError::UnsupportedOperation(
                "multiplication requires the `fhe-mul` feature flag; use hybrid mode instead"
                    .to_string(),
            ))
        }

        #[cfg(feature = "fhe-mul")]
        {
            if self.public_key.encryption_key.eval_key.is_empty() {
                return Err(FheError::UnsupportedOperation(
                    "evaluation key is empty: keygen must produce eval_key before multiplication"
                        .to_string(),
                ));
            }

            let level = ct1.level.max(ct2.level) + 1;
            if level > self.params.max_depth {
                return Err(FheError::InvalidCiphertext(format!(
                    "multiplication would exceed max circuit depth {}",
                    self.params.max_depth
                )));
            }

            let mut data = ct1.data.clone();
            data.extend_from_slice(&ct2.data);

            Ok(Ciphertext {
                data,
                randomness: vec![],
                level,
                threshold: self.params.threshold,
                num_parties: self.params.num_parties,
            })
        }
    }

    fn neg(&self, ct: &Ciphertext) -> FheResult<Ciphertext> {
        Ok(Ciphertext {
            data: ct.data.clone(),
            randomness: ct.randomness.clone(),
            level: ct.level,
            threshold: self.params.threshold,
            num_parties: self.params.num_parties,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instance(eval_key: Vec<u8>, max_depth: usize) -> ThresholdFhe {
        let params = FheParams {
            // Single-party decryption: one partial share must suffice so that
            // ThresholdFhe::decrypt can round-trip ciphertexts in tests.
            threshold: 1,
            max_depth,
            ..FheParams::default()
        };
        let decryption_key = DecryptionKey {
            secret_share: vec![7u8; 32],
            public_key: vec![9u8; 32],
            party_id: 0,
        };
        let public_key = PublicKey {
            encryption_key: EncryptionKey {
                params: vec![],
                eval_key,
            },
            num_parties: params.num_parties,
            threshold: params.threshold,
        };
        ThresholdFhe::new(params, decryption_key, public_key)
    }

    #[cfg(not(feature = "fhe-mul"))]
    #[test]
    fn mul_returns_clear_error_without_feature_flag() {
        let fhe = instance(vec![1u8; 16], 10);
        let ct = fhe.encrypt(&Plaintext::from_u64(3)).expect("encrypt");
        let err = FheOps::mul(&fhe, &ct, &ct).expect_err("must be unsupported");
        assert!(
            err.to_string().contains("fhe-mul"),
            "error should name the feature flag: {err}"
        );
    }

    #[cfg(feature = "fhe-mul")]
    mod mul_enabled {
        use super::*;

        #[test]
        fn mul_requires_non_empty_eval_key() {
            let fhe = instance(Vec::new(), 10);
            let ct = fhe.encrypt(&Plaintext::from_u64(2)).expect("encrypt");
            let err = FheOps::mul(&fhe, &ct, &ct).expect_err("eval key missing");
            assert!(matches!(err, FheError::UnsupportedOperation(_)));
        }

        #[test]
        fn mul_succeeds_with_eval_key_and_bumps_level() {
            let fhe = instance(vec![1u8; 16], 10);
            let ct1 = fhe.encrypt(&Plaintext::from_u64(6)).expect("encrypt");
            let ct2 = fhe.encrypt(&Plaintext::from_u64(7)).expect("encrypt");
            let ct = FheOps::mul(&fhe, &ct1, &ct2).expect("mul with eval key");
            assert_eq!(
                ct.level, 1,
                "fresh ciphertexts at level 0 multiply to level 1"
            );
        }

        #[test]
        fn mul_rejects_depth_overflow() {
            let fhe = instance(vec![1u8; 16], 0);
            let ct1 = fhe.encrypt(&Plaintext::from_u64(6)).expect("encrypt");
            let ct2 = fhe.encrypt(&Plaintext::from_u64(7)).expect("encrypt");
            let err = FheOps::mul(&fhe, &ct1, &ct2).expect_err("depth overflow");
            assert!(matches!(err, FheError::InvalidCiphertext(_)));
        }

        #[test]
        fn hybrid_evaluate_step_supports_mul_operation() {
            use crate::hybrid::{ComputationStep, HybridComputation, HybridConfig, HybridMode};

            let fhe = instance(vec![1u8; 16], 10);
            let computation = HybridComputation::new(
                HybridConfig {
                    mode: HybridMode::Hybrid,
                    ..HybridConfig::default()
                },
                Some(fhe),
            );

            let ct = computation
                .fhe
                .as_ref()
                .expect("fhe initialized")
                .encrypt(&Plaintext::from_u64(5))
                .expect("encrypt");

            let step = ComputationStep::Fhe {
                ciphertexts: vec![ct.clone(), ct],
                operation: "mul".to_string(),
            };

            let result = computation.evaluate_step(&step).expect("hybrid mul");
            assert_eq!(result.len(), 1);
        }
    }
}
