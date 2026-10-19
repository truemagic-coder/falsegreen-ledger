//! # falsegreen-ledger-core
//!
//! Tamper-evident, hash-chained audit ledger core.
//!
//! Every record commits to the SHA-256 of the canonical form of the previous
//! record; sequence numbers are strictly increasing (gaps are detectable);
//! closed shards carry a Merkle root + Ed25519 seal as the external trust
//! anchor. Designed for AI-agent action trails (see `docs/DESIGN.md`).

pub mod chain;
pub mod compact;
pub mod event;
pub mod integrity;
pub mod policy;
pub mod store;
pub mod verify;

pub use chain::{compute_record_hash, record_hash_input, Record, GENESIS_HASH};
pub use compact::{compact_last_sealed, seal_active_with};
pub use event::{Action, Actor, Correlation, Decision, Event};
pub use policy::{Policy, PolicyViolation, Rule};
pub use store::{Ledger, LedgerError, Seal, ShardData};
pub use verify::{verify_ledger, Failure, FailureKind, ShardReport, VerificationReport};
