//! Collaboration layer coordinator and policy engine.
//!
//! The coordinator manages:
//! - Session lifecycle (create, join, execute, close)
//! - Policy enforcement (who can join, what computations are allowed)
//! - Audit logging for compliance
//! - Multi-party session orchestration

pub mod audit;
pub mod error;
pub mod policy;
pub mod session;

pub use audit::{AuditEntry, AuditLog};
pub use error::{CoordinatorError, CoordinatorResult};
pub use policy::{AccessPolicy, ComputationPolicy, PolicyEngine, SessionPolicy};
pub use session::{SessionConfig, SessionManager, SessionStatus};

use chrono::{DateTime, Utc};
use osmiridium_protocol::ArithmeticCircuit;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A computation session managed by the coordinator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComputationSession {
    pub id: Uuid,
    pub name: String,
    pub status: SessionStatus,
    pub participants: Vec<Participant>,
    pub circuit: ArithmeticCircuit,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub result: Option<Vec<osmiridium_protocol::crypto::field::Scalar>>,
    pub policy: SessionPolicy,
}

/// A participant in a computation session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Participant {
    pub party_id: usize,
    pub name: String,
    pub endpoint: String,
    pub role: ParticipantRole,
    pub joined_at: DateTime<Utc>,
}

/// Role of a participant in the computation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ParticipantRole {
    DataProvider,
    ComputationRunner,
    Auditor,
    Administrator,
}

/// The main coordinator service.
pub struct Coordinator {
    sessions: std::collections::HashMap<Uuid, SessionManager>,
    policy_engine: PolicyEngine,
    audit_log: AuditLog,
}

impl Coordinator {
    pub fn new() -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
            policy_engine: PolicyEngine::new(),
            audit_log: AuditLog::new(),
        }
    }

    pub fn create_session(
        &mut self,
        name: String,
        circuit: ArithmeticCircuit,
        policy: SessionPolicy,
    ) -> CoordinatorResult<Uuid> {
        let session_id = Uuid::new_v4();
        let num_gates = policy.num_gates;

        let manager = SessionManager::new(session_id, name.clone(), circuit, policy.clone());

        self.audit_log.log(AuditEntry {
            session_id,
            action: "session_created".to_string(),
            actor: "coordinator".to_string(),
            timestamp: Utc::now(),
            details: format!("Circuit with {} gates", num_gates),
        });

        self.sessions.insert(session_id, manager);
        Ok(session_id)
    }

    pub fn add_participant(
        &mut self,
        session_id: Uuid,
        participant: Participant,
    ) -> CoordinatorResult<()> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(CoordinatorError::SessionNotFound)?;

        if !self
            .policy_engine
            .check_access(&session.policy, &participant)?
        {
            return Err(CoordinatorError::AccessDenied);
        }

        session.add_participant(participant.clone())?;
        self.audit_log.log(AuditEntry {
            session_id,
            action: "participant_added".to_string(),
            actor: participant.name.clone(),
            timestamp: Utc::now(),
            details: format!(
                "Party ID: {}, Role: {:?}",
                participant.party_id, participant.role
            ),
        });

        Ok(())
    }

    pub async fn execute_session(
        &mut self,
        session_id: Uuid,
    ) -> CoordinatorResult<Option<Vec<osmiridium_protocol::crypto::field::Scalar>>> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(CoordinatorError::SessionNotFound)?;

        session.set_status(SessionStatus::Running)?;
        self.audit_log.log(AuditEntry {
            session_id,
            action: "session_started".to_string(),
            actor: "coordinator".to_string(),
            timestamp: Utc::now(),
            details: String::new(),
        });

        let result = session.execute().await?;

        if let Some(res) = &result {
            session.set_status(SessionStatus::Completed)?;
            self.audit_log.log(AuditEntry {
                session_id,
                action: "session_completed".to_string(),
                actor: "coordinator".to_string(),
                timestamp: Utc::now(),
                details: format!("{} output values", res.len()),
            });
        }

        Ok(result)
    }

    /// Execute a session as a real distributed protocol over TCP, with
    /// per-party input maps. Returns the reconstructed outputs per party.
    pub async fn execute_session_distributed(
        &mut self,
        session_id: Uuid,
        inputs: &[std::collections::BTreeMap<usize, osmiridium_protocol::crypto::field::Scalar>],
    ) -> CoordinatorResult<
        Vec<std::collections::BTreeMap<usize, osmiridium_protocol::crypto::field::Scalar>>,
    > {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(CoordinatorError::SessionNotFound)?;

        session.set_status(SessionStatus::Running)?;
        self.audit_log.log(AuditEntry {
            session_id,
            action: "session_started_distributed".to_string(),
            actor: "coordinator".to_string(),
            timestamp: Utc::now(),
            details: format!("{} parties", session.num_participants()),
        });

        let result = session.execute_distributed(inputs).await?;

        session.set_status(SessionStatus::Completed)?;
        self.audit_log.log(AuditEntry {
            session_id,
            action: "session_completed_distributed".to_string(),
            actor: "coordinator".to_string(),
            timestamp: Utc::now(),
            details: format!("{} parties produced outputs", result.len()),
        });

        Ok(result)
    }

    pub fn get_session_status(&self, session_id: Uuid) -> CoordinatorResult<SessionStatus> {
        let session = self
            .sessions
            .get(&session_id)
            .ok_or(CoordinatorError::SessionNotFound)?;
        Ok(session.status())
    }

    /// Attach a circuit definition to a session that was created without one.
    pub fn define_circuit(
        &mut self,
        session_id: Uuid,
        circuit: ArithmeticCircuit,
    ) -> CoordinatorResult<()> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(CoordinatorError::SessionNotFound)?;

        if session.status != SessionStatus::Created && session.status != SessionStatus::Configured {
            return Err(CoordinatorError::AlreadyStarted);
        }

        session.circuit = circuit;
        Ok(())
    }

    pub fn get_audit_log(&self, _session_id: Uuid) -> CoordinatorResult<&AuditLog> {
        Ok(&self.audit_log)
    }

    /// Get full session information for API responses
    pub fn get_session(&self, session_id: Uuid) -> CoordinatorResult<ComputationSession> {
        let session = self
            .sessions
            .get(&session_id)
            .ok_or(CoordinatorError::SessionNotFound)?;
        Ok(session.to_computation_session())
    }

    /// Get execution results for a completed session
    pub fn get_session_results(
        &self,
        session_id: Uuid,
    ) -> CoordinatorResult<Option<Vec<osmiridium_protocol::crypto::field::Scalar>>> {
        let session = self
            .sessions
            .get(&session_id)
            .ok_or(CoordinatorError::SessionNotFound)?;
        Ok(session.get_results().cloned())
    }
}

impl Default for Coordinator {
    fn default() -> Self {
        Self::new()
    }
}
