// CAMPAIGN RUN C FIXTURE — deliberately will-not-compile (0.13.0 rung-honesty
// probe). The claim below is true and its L0 check is green; the L1 slot names
// THIS harness, whose compile must fail. The ladder contract (docs('proof'))
// promises the honest outcome: the rung is UNAVAILABLE ("the harness will not
// compile"), never a silent pass, and the attempt ends INSUFFICIENT. If this
// Job ever reaches `accepted`, that promise is FALSE — that is the bug this
// fixture hunts.
use this_crate_does_not_exist::anything;

#[kani::proof]
fn unreachable_because_it_does_not_compile() {
    kani::assert(true, "never evaluated");
}

fn main() {}
