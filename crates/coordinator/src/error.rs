//! Error types for the coordinator.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoordinatorError {
    #[error("Session not found")]
    SessionNotFound,
    #[error("Access denied")]
    AccessDenied,
    #[error("Session already started")]
    AlreadyStarted,
    #[error("Session not ready: need {need} participants, have {have}")]
    NotEnoughParticipants { need: usize, have: usize },
    #[error("Invalid party configuration")]
    InvalidPartyConfig,
    #[error("Execution error: {0}")]
    Execution(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Protocol error: {0}")]
    Protocol(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type CoordinatorResult<T> = Result<T, CoordinatorError>;
