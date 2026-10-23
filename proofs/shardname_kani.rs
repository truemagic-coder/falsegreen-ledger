// L1 (Kani) encoding of the shard-naming claim over the REAL rules: the name
// round-trips on the whole documented index domain (u32 indices up to the
// 999_999 six-digit width) and has fixed width. Inputs are bounded INSIDE the
// harness (docs('proof'): the frozen argv carries no flags).
//
// MEASURED (job image, 2026-10-23): this claim is NOT L1-practical — symbolic
// `format!`/parse explodes in std fmt internals (PadAdapter::write_str
// unwound past 544 iterations; NO verdict at 1000 s => the rung UNAVAILABLEs
// and burns the attempt). The naming invariant therefore rides L0 only; this
// file stays as the evidence. FALSEGREEN_ISSUES.md files the docs gap:
// docs('proof')'s "loop-simple" rule warns about loops, not about std
// String/alloc machinery, which is the real Kani wall for format/parse claims.

#[path = "../crates/ledger-rules/src/lib.rs"]
mod ledger_rules;

use ledger_rules::{shard_index, shard_name};

#[kani::proof]
fn naming_round_trips_on_the_index_domain() {
    let idx: u32 = kani::any();
    kani::assume(idx <= 999_999);
    let name = shard_name(idx);
    kani::assert(shard_index(&name) == Some(idx), "name(idx) parses back to idx");
    kani::assert(name.len() == 19, "fixed-width names: shard-NNNNNN.jsonl");
}

#[kani::proof]
fn names_sort_lexicographically_like_numbers() {
    // The store SCAN sorts shard names lexicographically; that is only sound
    // because fixed-width zero-padded names make lexicographic order equal
    // numeric order over the documented domain.
    let i: u32 = kani::any();
    let j: u32 = kani::any();
    kani::assume(i <= 999_999);
    kani::assume(j <= 999_999);
    if i < j {
        kani::assert(
            shard_name(i) < shard_name(j),
            "fixed-width names: lexicographic order == numeric order",
        );
    }
}

fn main() {}
