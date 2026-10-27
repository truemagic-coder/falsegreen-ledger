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

// The application modules are excluded from the PROOF build (`cargo
// creusot`): Creusot type-checks the whole crate it is pointed at, and the
// storage/CLI machinery (file IO, serde types) has no spec — it is not
// what the proof is about. The two modules that remain under `cfg(creusot)`
// are exactly the proof's subject: `rules` (the shipped decision rule a
// bounded model check includes verbatim) and `spec` (its unbounded,
// guarded specification). Under a normal build everything compiles as
// before; the contract macros simply erase.
#[cfg(not(creusot))]
pub mod chain;
#[cfg(not(creusot))]
pub mod compact;
#[cfg(not(creusot))]
pub mod event;
#[cfg(not(creusot))]
pub mod integrity;
#[cfg(not(creusot))]
pub mod policy;
pub mod rules;
#[cfg(not(creusot))]
pub mod store;
#[cfg(not(creusot))]
pub mod verify;

pub mod spec;

#[cfg(not(creusot))]
pub use chain::{compute_record_hash, record_hash_input, Record, GENESIS_HASH};
#[cfg(not(creusot))]
pub use compact::{compact_last_sealed, seal_active_with};
#[cfg(not(creusot))]
pub use event::{Action, Actor, Correlation, Decision, Event};
#[cfg(not(creusot))]
pub use policy::{Policy, PolicyViolation, Rule};
#[cfg(not(creusot))]
pub use store::{Ledger, LedgerError, Seal, ShardData};
#[cfg(not(creusot))]
pub use verify::{verify_ledger, Failure, FailureKind, ShardReport, VerificationReport};
