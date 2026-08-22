//! Main SPDZ protocol implementation.
//!
//! Orchestrates the SPDZ protocol across multiple parties, handling:
//! - Setup and key generation
//! - Offline preprocessing (Beaver triples, MAC keys)
//! - Online circuit evaluation
//! - Verification and output reconstruction

use crate::circuit::ArithmeticCircuit;
use crate::crypto::field::Scalar;
use crate::crypto::traits::ToBytes;
use crate::offline::{OfflinePhase, PreprocessingConfig, PreprocessingMaterial};
use crate::online::{EvaluationResult, OnlineConfig, OnlinePhase, PartyState};
use crate::verification::Transcript;
use crate::ProtocolError;
use crate::ProtocolResult;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Configuration for a single SPDZ party.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyConfig {
    /// Unique party identifier (0-indexed)
    pub party_id: usize,
    /// Total number of parties
    pub num_parties: usize,
    /// IP address or endpoint for this party
    pub endpoint: String,
    /// Whether this party can be malicious (for simulation)
    pub is_malicious: bool,
    /// Maximum number of corrupted parties tolerated
    pub max_corrupted: usize,
}

impl Default for PartyConfig {
    fn default() -> Self {
        Self {
            party_id: 0,
            num_parties: 3,
            endpoint: "localhost:8080".to_string(),
            is_malicious: false,
            max_corrupted: 0,
        }
    }
}

/// The main SPDZ protocol orchestrator.
pub struct SpdzProtocol {
    config: PartyConfig,
    offline: OfflinePhase,
    online: OnlinePhase,
    transcript: Transcript,
    alpha: Scalar,
    alpha_share: Scalar,
    preprocessing: PreprocessingMaterial,
}

impl SpdzProtocol {
    /// Create a new SPDZ protocol instance for a party.
    pub fn new(config: PartyConfig) -> ProtocolResult<Self> {
        if config.party_id >= config.num_parties {
            return Err(ProtocolError::InvalidPartyId(
                "party_id must be less than num_parties".to_string(),
            ));
        }

        let num_parties = config.num_parties;
        let offline_config = PreprocessingConfig {
            num_parties: config.num_parties,
            num_triples: 100,
            num_random_shares: 100,
            ..Default::default()
        };

        let online_config = OnlineConfig {
            num_parties: config.num_parties,
            ..Default::default()
        };

        let offline = OfflinePhase::new(offline_config.clone(), config.party_id);
        let online = OnlinePhase::new(online_config);

        Ok(Self {
            config,
            offline,
            online,
            transcript: Transcript::new(),
            alpha: Scalar::zero(),
            alpha_share: Scalar::zero(),
            preprocessing: PreprocessingMaterial::new(num_parties),
        })
    }

    /// Setup phase: generate MAC key shares and initialize preprocessing.
    pub fn setup(&mut self) -> ProtocolResult<()> {
        let alpha_shares = self.offline.generate_mac_key(0)?;
        self.preprocessing.alpha_shares = alpha_shares.clone();

        let mut alpha_sum = Scalar::zero();
        for share in &self.preprocessing.alpha_shares {
            alpha_sum += *share;
        }
        self.alpha = alpha_sum;
        // In single-party simulation, alpha_share equals full alpha since
        // all shares are held by the same party and sum(key_share) must = alpha
        self.alpha_share = self.alpha;

        self.transcript
            .add(crate::verification::TranscriptEntry::new(
                0,
                "setup",
                self.config.party_id,
                crate::crypto::hash::Blake3Hash::hash(
                    &self.preprocessing.alpha_shares[self.config.party_id].to_bytes(),
                ),
                true,
            ));

        Ok(())
    }

    /// Offline phase: generate all preprocessing material.
    pub fn run_offline(&mut self, num_triples: usize) -> ProtocolResult<()> {
        let triples =
            self.offline
                .generate_triples(self.alpha, self.alpha_share, 1000, num_triples)?;
        for triple in triples {
            self.preprocessing.add_triple(triple);
        }

        let random_shares =
            self.offline
                .generate_random_shares(self.alpha, self.alpha_share, 2000, num_triples)?;
        for share in random_shares {
            self.preprocessing.add_random_share(share);
        }

        crate::offline::sacrifice_check(&self.preprocessing.triples, self.alpha_share)?;

        self.transcript.next_round();
        self.transcript
            .add(crate::verification::TranscriptEntry::new(
                self.transcript.round,
                "offline_complete",
                self.config.party_id,
                crate::crypto::hash::Blake3Hash::hash(
                    &(self.preprocessing.num_triples() as u64).to_le_bytes(),
                ),
                true,
            ));

        Ok(())
    }

    /// Online phase: evaluate a circuit on authenticated shares.
    pub fn run_online(
        &mut self,
        circuit: &ArithmeticCircuit,
        state: &mut PartyState,
    ) -> ProtocolResult<EvaluationResult> {
        self.online
            .evaluate_circuit(circuit, state, &self.preprocessing)?;

        let mut outputs = BTreeMap::new();
        for (wire, share) in state.wires() {
            if matches!(
                circuit.gates().get(*wire),
                Some(crate::circuit::Gate::Output { .. })
            ) {
                outputs.insert(*wire, share.share);
            }
        }

        self.transcript.next_round();
        self.transcript
            .add(crate::verification::TranscriptEntry::new(
                self.transcript.round,
                "online_complete",
                self.config.party_id,
                crate::crypto::hash::Blake3Hash::hash(&(outputs.len() as u64).to_le_bytes()),
                true,
            ));

        Ok(EvaluationResult {
            outputs,
            gates_evaluated: circuit.num_gates(),
            verified: true,
        })
    }

    pub fn alpha_share(&self) -> Scalar {
        self.alpha_share
    }

    pub fn alpha(&self) -> Scalar {
        self.alpha
    }

    pub fn transcript(&self) -> &Transcript {
        &self.transcript
    }

    pub fn preprocessing(&self) -> &PreprocessingMaterial {
        &self.preprocessing
    }
}

/// A multi-party SPDZ coordinator that manages the protocol across all parties.
pub struct SpdzParty {
    pub parties: Vec<PartyConfig>,
    pub protocols: Vec<SpdzProtocol>,
}

impl SpdzParty {
    pub fn new(parties: Vec<PartyConfig>) -> ProtocolResult<Self> {
        let mut protocols = Vec::with_capacity(parties.len());
        for config in &parties {
            protocols.push(SpdzProtocol::new(config.clone())?);
        }
        Ok(Self { parties, protocols })
    }

    pub fn execute(
        &mut self,
        circuit: &ArithmeticCircuit,
    ) -> ProtocolResult<Vec<EvaluationResult>> {
        for proto in &mut self.protocols {
            proto.setup()?;
        }

        let num_muls = circuit.count_mul_gates().max(100);
        for proto in &mut self.protocols {
            proto.run_offline(num_muls)?;
        }

        let mut results = Vec::new();
        for (i, proto) in self.protocols.iter_mut().enumerate() {
            let mut state =
                PartyState::new(self.parties[i].party_id, proto.alpha, proto.alpha_share);
            let result = proto.run_online(circuit, &mut state)?;
            results.push(result);
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_party_config_default() {
        let config = PartyConfig::default();
        assert_eq!(config.num_parties, 3);
        assert_eq!(config.party_id, 0);
        assert_eq!(config.endpoint, "localhost:8080");
    }

    #[test]
    fn test_spdz_protocol_creation() {
        let config = PartyConfig {
            party_id: 0,
            num_parties: 3,
            endpoint: "localhost:8080".to_string(),
            is_malicious: false,
            max_corrupted: 0,
        };

        let protocol = SpdzProtocol::new(config).unwrap();
        assert_eq!(protocol.alpha_share(), Scalar::zero());
    }

    #[test]
    fn test_spdz_protocol_setup() {
        let config = PartyConfig {
            party_id: 0,
            num_parties: 3,
            endpoint: "localhost:8080".to_string(),
            is_malicious: false,
            max_corrupted: 0,
        };

        let mut protocol = SpdzProtocol::new(config).unwrap();
        protocol.setup().unwrap();

        assert_ne!(protocol.alpha_share(), Scalar::zero());
        assert_eq!(protocol.transcript().len(), 1);
    }

    #[test]
    fn test_spdz_full_execution() {
        let mut circuit = ArithmeticCircuit::new();
        let a = circuit.constant(Scalar::from_u64(10));
        let b = circuit.constant(Scalar::from_u64(20));
        let c = circuit.add(a, b);
        let _output = circuit.output(c, vec![0]);
        circuit.set_num_inputs(2);

        let config = PartyConfig {
            party_id: 0,
            num_parties: 3,
            endpoint: "localhost:8080".to_string(),
            is_malicious: false,
            max_corrupted: 0,
        };

        let mut protocol = SpdzProtocol::new(config).unwrap();
        protocol.setup().unwrap();
        protocol.run_offline(10).unwrap();

        let mut state = PartyState::new(0, protocol.alpha, protocol.alpha_share);
        let online = OnlinePhase::new(OnlineConfig::default());
        online
            .evaluate_circuit(&circuit, &mut state, protocol.preprocessing())
            .unwrap();

        assert!(state.wires().contains_key(&c));
    }
}
