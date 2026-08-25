//! CLI crate for Osmiridium SMPC platform.
//!
//! Provides `osmiridium` binary commands: `test`, `keygen`, `create-session`,
//! `execute`, `verify` (REST+gRPC), `bench`, `config`. See `crates/cli/README.md`.
//!
//! ```rust,no_run
//! // Library re-exports commands for integration tests
//! use osmiridium_cli::commands;
//! ```

pub mod commands;
pub mod config;
