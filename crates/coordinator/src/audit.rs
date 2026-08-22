//! Audit logging for compliance and transparency.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single audit log entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub session_id: Uuid,
    pub action: String,
    pub actor: String,
    pub timestamp: DateTime<Utc>,
    pub details: String,
}

/// An append-only audit log for all protocol operations.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditLog {
    pub entries: Vec<AuditEntry>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn log(&mut self, entry: AuditEntry) {
        self.entries.push(entry);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Filter entries by session ID.
    pub fn by_session(&self, session_id: Uuid) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.session_id == session_id)
            .collect()
    }

    /// Filter entries by action type.
    pub fn by_action(&self, action: &str) -> Vec<&AuditEntry> {
        self.entries.iter().filter(|e| e.action == action).collect()
    }

    /// Export the audit log as JSON for external storage.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Generate a cryptographic commitment to the audit log for integrity verification.
    pub fn commitment(&self) -> [u8; 32] {
        let json = self.to_json();
        osmiridium_crypto::hash::Blake3Hash::hash(json.as_bytes())
    }
}
