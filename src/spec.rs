//! The formal (Pearlite) specification of the chain-link successor
//! arithmetic — the same sentence [`crate::rules::links`] implements,
//! written as a machine-checkable contract. The Pearlite attributes are
//! erased by a plain `cargo build`, so this module ships inside the crate
//! and rides the source hash; the proof toolchain reads the same bytes.
//!
//! The claim's domain is GUARDED (`prev` below the u64 ceiling): the
//! unbounded proof covers every input in that guarded domain, while the
//! bounded proof over the shipped code covers the FULL u64 domain —
//! an unguarded successor that wraps at the ceiling is a violation there,
//! with a concrete counterexample. The two encodings together mean the
//! guarded specification and the shipped implementation cannot both be
//! quietly wrong.

use creusot_std::prelude::*;

/// The guarded successor predicate: proven for every `prev` below the u64
/// ceiling. The `requires` guard is what closes the body's overflow
/// obligation — without it the verification condition stays open.
#[requires(prev < 18446744073709551615u64)]
#[ensures(result == (seq == prev + 1u64))]
pub fn links(seq: u64, prev: u64) -> bool {
    seq == prev + 1
}
