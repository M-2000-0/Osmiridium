//! Session management for computation sessions.

use crate::audit::AuditLog;
use crate::error::{CoordinatorError, CoordinatorResult};
use crate::policy::SessionPolicy;
use crate::Participant;
use chrono::{DateTime, Utc};
use osmiridium_protocol::crypto::field::Scalar;
use osmiridium_protocol::ArithmeticCircuit;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Status of a computation session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    Created,
    Configured,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Session configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionConfig {
    pub num_parties: usize,
    pub threshold: usize,
    pub protocol: String,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            num_parties: 3,
            threshold: 1,
            protocol: "spdz".to_string(),
        }
    }
}

/// Manages a single computation session.
pub struct SessionManager {
    pub session_id: Uuid,
    pub name: String,
    pub status: SessionStatus,
    pub participants: Vec<Participant>,
    pub circuit: ArithmeticCircuit,
    pub config: SessionConfig,
    pub policy: SessionPolicy,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub audit_log: AuditLog,
    /// Execution results, stored after completion
    pub result: Option<Vec<Scalar>>,
}

impl SessionManager {
    pub fn new(
        session_id: Uuid,
        name: String,
        circuit: ArithmeticCircuit,
        policy: SessionPolicy,
    ) -> Self {
        Self {
            session_id,
            name,
            status: SessionStatus::Created,
            participants: Vec::new(),
            circuit,
            config: SessionConfig::default(),
            policy,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            audit_log: AuditLog::new(),
            result: None,
        }
    }

    pub fn add_participant(&mut self, participant: Participant) -> CoordinatorResult<()> {
        if self.status != SessionStatus::Created && self.status != SessionStatus::Configured {
            return Err(CoordinatorError::AlreadyStarted);
        }
        self.participants.push(participant);
        self.status = SessionStatus::Configured;
        Ok(())
    }

    pub fn set_status(&mut self, status: SessionStatus) -> CoordinatorResult<()> {
        // Validate state transitions per the session state machine:
        //   Created -> Configured -> Running -> Completed
        //                                           -> Failed
        //   Created -> Cancelled
        //   Configured -> Cancelled
        // Terminal states: Completed, Failed, Cancelled
        match (self.status, status) {
            (_, SessionStatus::Running) if self.status == SessionStatus::Configured => {}
            (_, SessionStatus::Completed) if self.status == SessionStatus::Running => {}
            (_, SessionStatus::Failed) if self.status == SessionStatus::Running => {}
            (_, SessionStatus::Cancelled)
                if self.status == SessionStatus::Created
                    || self.status == SessionStatus::Configured => {}
            (_, SessionStatus::Configured) if self.status == SessionStatus::Created => {}
            // Allow re-setting to the same state (idempotent)
            (a, b) if a == b => {}
            (from, to) => {
                return Err(CoordinatorError::Protocol(format!(
                    "invalid state transition: {:?} -> {:?}",
                    from, to
                )));
            }
        }
        self.status = status;
        if status == SessionStatus::Running {
            self.started_at = Some(Utc::now());
        }
        if status == SessionStatus::Completed || status == SessionStatus::Failed {
            self.completed_at = Some(Utc::now());
        }
        Ok(())
    }

    pub fn status(&self) -> SessionStatus {
        self.status
    }

    pub fn num_participants(&self) -> usize {
        self.participants.len()
    }

    /// Execute the computation for this session.
    pub async fn execute(&mut self) -> CoordinatorResult<Option<Vec<Scalar>>> {
        if self.status != SessionStatus::Configured {
            return Err(CoordinatorError::AlreadyStarted);
        }

        let party_configs = self
            .participants
            .iter()
            .enumerate()
            .map(|(i, p)| osmiridium_protocol::PartyConfig {
                party_id: i,
                num_parties: self.participants.len(),
                endpoint: p.endpoint.clone(),
                is_malicious: false,
                max_corrupted: 0,
            })
            .collect::<Vec<_>>();

        let mut spdz = osmiridium_protocol::SpdzParty::new(party_configs)
            .map_err(|e| CoordinatorError::Protocol(e.to_string()))?;

        let results = spdz
            .execute(&self.circuit)
            .map_err(|e| CoordinatorError::Protocol(e.to_string()))?;

        let result = if let Some(first_result) = results.first() {
            if !first_result.outputs.is_empty() {
                Some(first_result.outputs.values().cloned().collect())
            } else {
                None
            }
        } else {
            None
        };

        self.result = result.clone();
        Ok(result)
    }

    /// Execute the session as a real distributed protocol over TCP.
    ///
    /// Spins up one [`TcpTransport`] per participant, binds a listener on each
    /// participant's endpoint, wires the peer endpoints, and runs the full
    /// distributed protocol (key agreement, offline, online, reconstruction).
    ///
    /// `inputs` is the per-party input map (one entry per input wire owned by
    /// that party). All participants must be reachable at their endpoints.
    pub async fn execute_distributed(
        &mut self,
        inputs: &[std::collections::BTreeMap<usize, Scalar>],
    ) -> CoordinatorResult<Vec<std::collections::BTreeMap<usize, Scalar>>> {
        if self.status != SessionStatus::Configured && self.status != SessionStatus::Running {
            return Err(CoordinatorError::AlreadyStarted);
        }

        let num_parties = self.participants.len();
        if inputs.len() != num_parties {
            return Err(CoordinatorError::NotEnoughParticipants {
                need: num_parties,
                have: inputs.len(),
            });
        }

        use osmiridium_network::identity::Identity;
        use osmiridium_network::tcp::TcpTransport;
        use osmiridium_network::transport::Transport;
        use osmiridium_network::transport::TransportType;
        use std::collections::BTreeMap;
        use std::sync::Arc;

        // Build one transport per participant and register every peer endpoint
        // so `send(peer_id, ...)` can resolve destinations.
        let mut transports: Vec<Arc<dyn Transport>> = Vec::with_capacity(num_parties);
        for (i, p) in self.participants.iter().enumerate() {
            let identity = Identity::generate(i, &p.name);
            let config = osmiridium_network::SessionConfig {
                protocol: TransportType::TcpNoise,
                num_parties,
                party_id: i,
                ..Default::default()
            };
            let transport = Arc::new(TcpTransport::new(config, identity, p.endpoint.clone()));
            // Register all peers (including self so broadcast reaches everyone).
            for (j, peer) in self.participants.iter().enumerate() {
                transport.add_peer(j, peer.endpoint.clone()).await;
            }
            // Bind this participant's listener before any send can occur.
            transport
                .start_listener()
                .await
                .map_err(|e| CoordinatorError::Network(format!("bind {}: {}", p.endpoint, e)))?;
            transports.push(transport);
        }

        // Run the distributed protocol with real TCP message passing.
        let results =
            osmiridium_protocol::run_distributed(&self.circuit, inputs, transports, num_parties)
                .await
                .map_err(|e| CoordinatorError::Protocol(e.to_string()))?;

        // All parties reconstruct the same outputs; return them per party.
        Ok(results
            .into_iter()
            .map(|m| m.into_iter().collect::<BTreeMap<_, _>>())
            .collect())
    }

    /// Convert to ComputationSession for API responses
    pub fn to_computation_session(&self) -> crate::ComputationSession {
        crate::ComputationSession {
            id: self.session_id,
            name: self.name.clone(),
            status: self.status,
            participants: self.participants.clone(),
            circuit: self.circuit.clone(),
            created_at: self.created_at,
            started_at: self.started_at,
            completed_at: self.completed_at,
            result: self.result.clone(),
            policy: self.policy.clone(),
        }
    }

    /// Rebuild a manager from a persisted API DTO (session restore).
    ///
    /// The per-session audit log is not part of the persisted DTO and starts
    /// empty; the coordinator-level log is also rebuilt from scratch.
    pub fn from_computation_session(cs: crate::ComputationSession) -> Self {
        let mut mgr = SessionManager::new(cs.id, cs.name, cs.circuit, cs.policy);
        mgr.status = cs.status;
        mgr.participants = cs.participants;
        mgr.created_at = cs.created_at;
        mgr.started_at = cs.started_at;
        mgr.completed_at = cs.completed_at;
        mgr.result = cs.result;
        mgr
    }

    /// Get execution results
    pub fn get_results(&self) -> Option<&Vec<Scalar>> {
        self.result.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::SessionPolicy;
    use osmiridium_protocol::{Gate, WireId};
    use std::collections::BTreeMap;

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn build_session() -> SessionManager {
        let mut circuit = ArithmeticCircuit::new();
        let a = circuit.add_gate(Gate::Input {
            party_id: 0,
            value: Scalar::from_u64(10),
        });
        let b = circuit.add_gate(Gate::Input {
            party_id: 1,
            value: Scalar::from_u64(20),
        });
        let c = circuit.add_gate(Gate::Input {
            party_id: 2,
            value: Scalar::from_u64(3),
        });
        let sum = circuit.add(a, b);
        let mul = circuit.mul(sum, c);
        circuit.output(mul, vec![0, 1, 2]);
        circuit.set_num_inputs(0);

        let policy = SessionPolicy::new(circuit.num_gates(), "distributed_test".to_string());
        let mut session =
            SessionManager::new(Uuid::new_v4(), "distributed".to_string(), circuit, policy);

        let ports = [free_port(), free_port(), free_port()];
        for (i, port) in ports.iter().enumerate() {
            session.participants.push(crate::Participant {
                party_id: i,
                name: format!("party_{}", i),
                endpoint: format!("127.0.0.1:{}", port),
                role: crate::ParticipantRole::DataProvider,
                joined_at: Utc::now(),
            });
        }
        session.status = SessionStatus::Configured;
        session
    }

    #[tokio::test]
    async fn test_execute_distributed_tcp() {
        let mut session = build_session();
        let inputs: Vec<BTreeMap<WireId, Scalar>> = vec![
            BTreeMap::from([(0, Scalar::from_u64(10))]),
            BTreeMap::from([(1, Scalar::from_u64(20))]),
            BTreeMap::from([(2, Scalar::from_u64(3))]),
        ];

        let results = session
            .execute_distributed(&inputs)
            .await
            .expect("distributed execution failed");

        // Every party reconstructs the same result: (10 + 20) * 3 = 90.
        assert_eq!(results.len(), 3);
        for party_results in &results {
            for value in party_results.values() {
                assert_eq!(*value, Scalar::from_u64(90));
            }
        }
    }
}
