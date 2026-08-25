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
    /// Directory for durable session state; `None` keeps sessions in memory.
    persist_dir: Option<std::path::PathBuf>,
}

impl Coordinator {
    pub fn new() -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
            policy_engine: PolicyEngine::new(),
            audit_log: AuditLog::new(),
            persist_dir: None,
        }
    }

    /// Enable durable session storage under `dir`, restoring any sessions
    /// persisted by a previous run. Call before creating new sessions.
    ///
    /// Each session is written atomically to `{session_id}.json` on every
    /// mutation (create, participant add, circuit definition, execution).
    pub fn with_persistence(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        let dir = dir.into();
        if let Err(e) = std::fs::create_dir_all(&dir) {
            tracing::warn!(error = %e, dir = %dir.display(), "cannot create persistence dir");
            return self;
        }
        self.load_persisted(&dir);
        self.persist_dir = Some(dir);
        self
    }

    fn load_persisted(&mut self, dir: &std::path::Path) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let restored = std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|s| {
                    serde_json::from_str::<ComputationSession>(&s).map_err(|e| e.to_string())
                });
            match restored {
                Ok(cs) => {
                    tracing::info!(session = %cs.id, "restored persisted session");
                    self.sessions
                        .insert(cs.id, SessionManager::from_computation_session(cs));
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "skipping unreadable session file");
                }
            }
        }
    }

    /// Write the current state of one session to disk (atomic tmp+rename).
    fn persist_session(&self, session_id: Uuid) {
        let Some(dir) = &self.persist_dir else {
            return;
        };
        let Some(manager) = self.sessions.get(&session_id) else {
            return;
        };
        let Ok(json) = serde_json::to_string_pretty(&manager.to_computation_session()) else {
            tracing::warn!(session = %session_id, "cannot serialize session for persistence");
            return;
        };
        let final_path = dir.join(format!("{session_id}.json"));
        let tmp_path = dir.join(format!("{session_id}.json.tmp"));
        let write =
            std::fs::write(&tmp_path, json).and_then(|_| std::fs::rename(&tmp_path, &final_path));
        if let Err(e) = write {
            tracing::warn!(error = %e, session = %session_id, "failed to persist session");
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
        self.persist_session(session_id);
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
        self.persist_session(session_id);

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
        self.persist_session(session_id);

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
        self.persist_session(session_id);

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
        self.persist_session(session_id);
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

    /// List all sessions.
    pub fn list_sessions(&self) -> Vec<ComputationSession> {
        self.sessions
            .values()
            .map(|m| m.to_computation_session())
            .collect()
    }

    /// Cancel a session (only possible from Created or Configured state).
    pub fn cancel_session(&mut self, session_id: Uuid) -> CoordinatorResult<()> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or(CoordinatorError::SessionNotFound)?;
        session.set_status(SessionStatus::Cancelled)?;
        self.audit_log.log(AuditEntry {
            session_id,
            action: "session_cancelled".to_string(),
            actor: "api".to_string(),
            timestamp: Utc::now(),
            details: String::new(),
        });
        self.persist_session(session_id);
        Ok(())
    }

    /// Remove expired sessions and delete their persisted files.
    ///
    /// - `ttl_completed` applies to `Completed` sessions (measured from `completed_at`)
    /// - `ttl_failed` applies to `Failed`/`Cancelled` sessions (from `completed_at` or `created_at`)
    /// - `ttl_created` applies to `Created`/`Configured` sessions stuck without progress (from `created_at`)
    /// Returns the number of sessions removed. Logs an audit entry per removal.
    pub fn cleanup_expired(
        &mut self,
        ttl_completed: chrono::Duration,
        ttl_failed: chrono::Duration,
        ttl_created: chrono::Duration,
    ) -> usize {
        let now = Utc::now();
        let mut to_remove: Vec<Uuid> = Vec::new();
        for (id, mgr) in &self.sessions {
            let expired = match mgr.status {
                SessionStatus::Completed => mgr
                    .completed_at
                    .map(|t| now.signed_duration_since(t) > ttl_completed)
                    .unwrap_or(false),
                SessionStatus::Failed | SessionStatus::Cancelled => {
                    let anchor = mgr.completed_at.unwrap_or(mgr.created_at);
                    now.signed_duration_since(anchor) > ttl_failed
                }
                SessionStatus::Created | SessionStatus::Configured | SessionStatus::Running => {
                    now.signed_duration_since(mgr.created_at) > ttl_created
                }
            };
            if expired {
                to_remove.push(*id);
            }
        }
        let count = to_remove.len();
        for id in to_remove {
            self.sessions.remove(&id);
            if let Some(dir) = &self.persist_dir {
                let path = dir.join(format!("{id}.json"));
                let _ = std::fs::remove_file(&path);
            }
            self.audit_log.log(AuditEntry {
                session_id: id,
                action: "session_expired_gc".to_string(),
                actor: "coordinator".to_string(),
                timestamp: now,
                details: "removed by GC".to_string(),
            });
        }
        if count > 0 {
            tracing::info!(removed = count, "GC expired sessions");
        }
        count
    }

    /// Spawn a background GC task that runs every `interval` and calls `cleanup_expired`.
    /// Returns the JoinHandle; caller should keep it alive. Uses shared `Arc<Mutex<Coordinator>>` pattern
    /// expected by the API layer; this helper is for single-process use (tests).
    pub fn spawn_gc_task(
        coordinator: std::sync::Arc<tokio::sync::Mutex<Self>>,
        interval: std::time::Duration,
        ttl_completed: chrono::Duration,
        ttl_failed: chrono::Duration,
        ttl_created: chrono::Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let mut coord = coordinator.lock().await;
                coord.cleanup_expired(ttl_completed, ttl_failed, ttl_created);
            }
        })
    }
}

impl Default for Coordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osmiridium_protocol::ArithmeticCircuit;

    fn temp_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("osmiridium-coord-{}", Uuid::new_v4()))
    }

    #[test]
    fn sessions_survive_coordinator_restart() {
        let dir = temp_dir();
        let session_id = {
            let mut coord = Coordinator::new().with_persistence(&dir);
            coord
                .create_session(
                    "durable".to_string(),
                    ArithmeticCircuit::new(),
                    SessionPolicy::new(3, "persist_test".to_string()),
                )
                .unwrap()
        };

        // Simulate process restart.
        let coord = Coordinator::new().with_persistence(&dir);
        let restored = coord
            .get_session(session_id)
            .expect("session must be restored after restart");
        assert_eq!(restored.name, "durable");
        assert_eq!(restored.participants.len(), 0);
        assert_eq!(restored.status, SessionStatus::Created);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn participant_and_results_are_persisted() {
        let dir = temp_dir();
        let session_id = {
            let mut coord = Coordinator::new().with_persistence(&dir);
            let id = coord
                .create_session(
                    "with-participant".to_string(),
                    ArithmeticCircuit::new(),
                    SessionPolicy::new(2, "persist_test".to_string()),
                )
                .unwrap();
            coord
                .add_participant(
                    id,
                    Participant {
                        party_id: 0,
                        name: "alice".to_string(),
                        endpoint: "127.0.0.1:9000".to_string(),
                        role: ParticipantRole::DataProvider,
                        joined_at: Utc::now(),
                    },
                )
                .unwrap();
            id
        };

        let coord = Coordinator::new().with_persistence(&dir);
        let restored = coord.get_session(session_id).unwrap();
        assert_eq!(restored.participants.len(), 1);
        assert_eq!(restored.participants[0].name, "alice");
        assert_eq!(restored.status, SessionStatus::Configured);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupt_files_are_skipped_not_fatal() {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("not-a-real-uuid.json"), "{ broken").unwrap();

        let coord = Coordinator::new().with_persistence(&dir);
        assert_eq!(coord.sessions.len(), 0);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn gc_removes_expired_sessions_and_files() {
        let dir = temp_dir();
        let mut coord = Coordinator::new().with_persistence(&dir);
        let id = coord
            .create_session(
                "to-expire".to_string(),
                ArithmeticCircuit::new(),
                SessionPolicy::new(2, "gc_test".to_string()),
            )
            .unwrap();
        // Backdate the session so GC considers it expired
        {
            let mgr = coord.sessions.get_mut(&id).unwrap();
            mgr.created_at = Utc::now() - chrono::Duration::days(8);
            mgr.status = SessionStatus::Created;
        }
        coord.persist_session(id);
        assert!(dir.join(format!("{id}.json")).exists());

        let removed = coord.cleanup_expired(
            chrono::Duration::days(7),
            chrono::Duration::days(1),
            chrono::Duration::days(7),
        );
        assert_eq!(removed, 1);
        assert!(coord.get_session(id).is_err());
        assert!(!dir.join(format!("{id}.json")).exists());

        let _ = std::fs::remove_dir_all(dir);
    }
}
