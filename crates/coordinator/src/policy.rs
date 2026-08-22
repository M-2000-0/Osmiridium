//! Policy engine for access control and computation governance.

use crate::error::{CoordinatorError, CoordinatorResult};
use crate::{Participant, ParticipantRole};
use osmiridium_protocol::ArithmeticCircuit;
use serde::{Deserialize, Serialize};

/// Defines who can access a session and what they can do.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessPolicy {
    /// List of allowed participant names
    pub allowed_participants: Vec<String>,
    /// Maximum number of participants
    pub max_participants: usize,
    /// Minimum number of participants required to start
    pub min_participants: usize,
    /// Whether new participants can join after the session starts
    pub allow_late_join: bool,
}

impl Default for AccessPolicy {
    fn default() -> Self {
        Self {
            allowed_participants: Vec::new(),
            max_participants: 10,
            min_participants: 3,
            allow_late_join: false,
        }
    }
}

/// Defines what computations are allowed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComputationPolicy {
    /// Maximum number of multiplication gates
    pub max_mul_gates: usize,
    /// Maximum circuit depth
    pub max_depth: usize,
    /// Allowed computation types (e.g., "trade_compliance", "supply_chain")
    pub allowed_types: Vec<String>,
    /// Whether comparison gates are allowed
    pub allow_comparisons: bool,
}

impl Default for ComputationPolicy {
    fn default() -> Self {
        Self {
            max_mul_gates: 10000,
            max_depth: 20,
            allowed_types: vec!["general".to_string()],
            allow_comparisons: true,
        }
    }
}

/// Policy governing a computation session.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SessionPolicy {
    pub access: AccessPolicy,
    pub computation: ComputationPolicy,
    pub num_gates: usize,
    pub description: String,
}

impl SessionPolicy {
    pub fn new(num_gates: usize, description: String) -> Self {
        Self {
            num_gates,
            description,
            ..Default::default()
        }
    }
}

/// The policy engine evaluates access policies for sessions.
pub struct PolicyEngine {
    policies: Vec<SessionPolicy>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Check if a participant is allowed to join a session.
    pub fn check_access(
        &self,
        policy: &SessionPolicy,
        participant: &Participant,
    ) -> CoordinatorResult<bool> {
        // Check if participant is in the allowed list
        if !policy.access.allowed_participants.is_empty()
            && !policy
                .access
                .allowed_participants
                .contains(&participant.name)
        {
            return Err(CoordinatorError::AccessDenied);
        }

        // Check participant role
        match &participant.role {
            ParticipantRole::Administrator => Ok(true),
            ParticipantRole::DataProvider => Ok(true),
            ParticipantRole::ComputationRunner => Ok(true),
            ParticipantRole::Auditor => Ok(true),
        }
    }

    /// Validate that a circuit complies with the computation policy.
    pub fn validate_circuit(
        &self,
        policy: &SessionPolicy,
        circuit: &ArithmeticCircuit,
    ) -> CoordinatorResult<()> {
        if circuit.count_mul_gates() > policy.computation.max_mul_gates {
            return Err(CoordinatorError::Execution(format!(
                "Circuit has {} multiplication gates, maximum is {}",
                circuit.count_mul_gates(),
                policy.computation.max_mul_gates
            )));
        }

        Ok(())
    }

    /// Check if a session has enough participants to start.
    pub fn check_ready(
        &self,
        policy: &SessionPolicy,
        num_participants: usize,
    ) -> CoordinatorResult<bool> {
        if num_participants < policy.access.min_participants {
            return Err(CoordinatorError::NotEnoughParticipants {
                need: policy.access.min_participants,
                have: num_participants,
            });
        }
        Ok(true)
    }

    pub fn register_policy(&mut self, policy: SessionPolicy) {
        self.policies.push(policy);
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}
