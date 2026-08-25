//! Testing crate for Osmiridium SMPC platform.
//!
//! Integration tests, benches, and utilities (`fixtures`, `harness`,
//! `proptest`, `e2e`, `bench`). See `crates/testing/README.md`.
//!
//! ```rust,no_run
//! use osmiridium_testing::{fixtures, harness};
//! ```

pub mod bench;
pub mod e2e;
pub mod fixtures;
pub mod harness;
pub mod proptest;
