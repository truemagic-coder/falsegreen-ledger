//! `falsegreen-ledger` — the binary entry point. The CLI itself lives in
//! `src/cli.rs`; the exit-code contract is documented there.

#[cfg(not(creusot))]
mod cli;

#[cfg(not(creusot))]
fn main() -> std::process::ExitCode {
    cli::main()
}

// `cargo creusot` type-checks EVERY target of this crate, and the CLI has
// nothing to prove — the proof target is the `links` predicate in the
// library, which is also why the library gates its storage/serde modules
// out of the proof build. The bin is an empty stub for the prover, and
// like the spec module it must reference the Creusot prelude (the driver
// refuses to run without it).
#[cfg(creusot)]
#[allow(unused_imports)]
use creusot_std::prelude::*;

#[cfg(creusot)]
fn main() {}
