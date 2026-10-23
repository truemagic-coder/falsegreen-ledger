// L1 (Kani) encoding of the shard-naming claim over the REAL rules: the name
// round-trips on the whole documented index domain (u32 indices up to the
// 999_999 six-digit width) and has fixed width. Inputs are bounded INSIDE the
// harness (docs('proof'): the frozen argv carries no flags).

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
