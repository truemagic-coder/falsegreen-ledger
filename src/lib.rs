//! # falsegreen-ledger
//!
//! Tamper-evident, hash-chained audit ledger for AI-agent actions.
//!
//! Every record commits to the SHA-256 of the canonical form of the previous
//! record; sequence numbers are strictly increasing (gaps are detectable);
//! closed shards carry a Merkle root + Ed25519 seal as the external trust
//! anchor. The design notes are in `docs/DESIGN.md`.
//!
//! The pure decision rules live in [`rules`] and are deliberately
//! dependency-free: a bounded model checker includes that exact source file
//! into its harness, so what the proof checks is what the binary runs.

pub mod chain;
pub mod compact;
pub mod event;
pub mod integrity;
pub mod policy;
pub mod rules;
pub mod store;
pub mod verify;

pub mod spec;

pub use chain::{compute_record_hash, record_hash_input, Record, GENESIS_HASH};
pub use compact::{compact_last_sealed, seal_active_with};
pub use event::{Action, Actor, Correlation, Decision, Event};
pub use policy::{Policy, PolicyViolation, Rule};
pub use store::{Ledger, LedgerError, Seal, ShardData};
pub use verify::{verify_ledger, Failure, FailureKind, ShardReport, VerificationReport};
