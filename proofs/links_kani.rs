// L1 (Kani) encoding of the chain-link successor claim — the harness proves
// the SHIPPED rules: `#[path]` pulls the real `ledger-rules` source into the
// harness crate root (docs('proof'): never copy the code into the harness).
// The claim under proof: the successor predicate NEVER WRAPS at the u64
// ceiling — no input can make a smaller seq link past u64::MAX — and on the
// guarded domain it equals the spec `seq == prev + 1`.
//
// Kani 0.68.0 models arithmetic overflow as a violation, so an unguarded
// `prev + 1` fails the FIRST proof with a concrete input; the frozen claim
// then forces the CODE to carry the guard.

#[path = "../crates/ledger-rules/src/lib.rs"]
mod ledger_rules;

use ledger_rules::links;

#[kani::proof]
fn successor_never_wraps_at_the_u64_ceiling() {
    let seq: u64 = kani::any();
    kani::assume(seq < u64::MAX);
    // A chain that wrapped would let seq=0 (or any small seq) link past the
    // ceiling. The claim: that is unreachable — `links` must say NO.
    let wrapped = links(seq, u64::MAX);
    kani::assert(
        !wrapped,
        "the hash chain never wraps: no seq links past the u64 ceiling",
    );
}

#[kani::proof]
fn successor_matches_the_spec_on_the_guarded_domain() {
    let seq: u64 = kani::any();
    let prev: u64 = kani::any();
    kani::assume(prev < u64::MAX);
    let got = links(seq, prev);
    kani::assert(
        got == (seq == prev.wrapping_add(1)),
        "on the guarded domain the predicate is exactly seq == prev + 1",
    );
}

fn main() {}
