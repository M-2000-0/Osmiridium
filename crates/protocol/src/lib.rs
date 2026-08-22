//! SPDZ-family MPC protocol implementation.
//!
//! This module implements the SPDZ protocol for maliciously secure
//! multi-party computation with dishonest majority.
//!
//! The protocol follows the standard SPDZ architecture:
//! - Offline phase: Generate authenticated Beaver triples and MAC keys
//! - Online phase: Evaluate arithmetic circuits on secret-shared data
//! - Verification: MAC checks ensure correctness against malicious adversaries

pub mod circuit;
pub mod distributed;
pub mod error;
pub mod offline;
pub mod online;
pub mod spdz;
pub mod verification;

pub use circuit::{ArithmeticCircuit, Gate, WireId};
pub use distributed::{run_distributed, DistributedParty};
pub use error::{ProtocolError, ProtocolResult};
pub use offline::{BeaverTriple, PreprocessingMaterial, TripleStore};
pub use online::{EvaluationResult, OnlinePhase, PartyState};
pub use spdz::{PartyConfig, SpdzParty, SpdzProtocol};
pub use verification::{MacVerifier, TranscriptEntry, VerificationResult};

pub use osmiridium_crypto as crypto;
pub use osmiridium_crypto::mac::AuthenticatedShare;
