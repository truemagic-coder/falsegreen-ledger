//! The proof ladder L2 (Creusot) encoding of the chain-link successor
//! arithmetic — the same sentence `ledger_rules::links` implements, written
//! as a formal contract over the predicate.
//!
//! The claim's domain is GUARDED (`prev` below the u64 ceiling): that is the
//! freeze-time judgement this encoding stands on. The machine's job is then
//! two-sided and honest:
//! * L2 proves the GUARDED spec UNBOUNDED (Why3 arithmetic, all inputs).
//! * L1 (Kani) checks the real code against the SAME sentence over the FULL
//!   u64 domain — an unguarded `prev + 1` that panics or wraps at the ceiling
//!   is a VIOLATION of "never wraps", with a concrete counterexample.
//! So the guarded spec and the unguarded implementation cannot both be
//! quietly wrong: the ladder itself is what forces the code to honour the
//! guard the spec states.

extern crate creusot_std;
use creusot_std::prelude::*;

/// The guarded successor predicate: proven for every `prev` below the u64
/// ceiling. Measured on Creusot v0.14: the `requires` guard is what closes
/// the body's overflow obligation — without it, `vc_links` stays open.
#[requires(prev < 18446744073709551615u64)]
#[ensures(result == (seq == prev + 1u64))]
pub fn links(seq: u64, prev: u64) -> bool {
    seq == prev + 1
}
