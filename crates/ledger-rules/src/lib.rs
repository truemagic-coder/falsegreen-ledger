//! The ledger's PURE decision rules — extracted verbatim from `chain.rs` and
//! `store.rs` so the proof ladder can decide claims about the SHIPPED code.
//!
//! Why a separate dependency-free crate: `kani-driver <harness>` compiles the
//! harness as its OWN crate root, so any module that itself uses serde/sha2 is
//! out of L1 reach (`E0463`). Keeping the arithmetic and naming rules here,
//! with the real code CALLING them, means the Kani harness proves the same
//! bytes the binary runs — never a copy of them.
//!
//! ENCODING JUDGEMENT (recorded honestly at freeze): `links` below is the
//! ENCODING JUDGEMENT (recorded honestly at freeze): `links` below SHIPPED as
//! `prev + 1` unguarded. The ladder's invariant claims the successor relation
//! never wraps; the machine DISAGREED on attempt 1 (Kani counterexample at the
//! ceiling) — a real defect in real code — and the repair loop fixed the CODE
//! (the frozen claim stayed). That is the campaign's point, in evidence.

/// True when `seq` is the immediate successor of `prev`.
///
/// This is `check_link`'s arithmetic part moved out of `Record::check_link`.
/// RUN A REPAIR (attempt 1, Job 68239ac0): Kani's L1 rung DISPROVED the frozen
/// claim here — `prev + 1` overflowed at the ceiling (`ledger-rules/src/lib.rs:21`)
/// — so the CODE now carries the guard the claim always stated: no successor
/// exists past `u64::MAX`, and nothing links past it.
pub fn links(seq: u64, prev: u64) -> bool {
    match prev.checked_add(1) {
        Some(successor) => seq == successor,
        None => false,
    }
}

/// The file name one shard index serializes to (`store::shard_path`).
pub fn shard_name(index: u32) -> String {
    format!("shard-{:06}.jsonl", index)
}

/// The shard index one directory entry parses back to, if any
/// (`store::shard_indices`' per-entry logic).
pub fn shard_index(name: &str) -> Option<u32> {
    let rest = name.strip_prefix("shard-")?;
    let stem = rest.strip_suffix(".jsonl")?;
    stem.parse::<u32>().ok()
}

#[cfg(test)]
mod links {
    use super::links;

    #[test]
    fn successor() {
        assert!(links(2, 1));
        assert!(links(1, 0));
        assert!(links(u64::MAX, u64::MAX - 1));
    }

    #[test]
    fn non_successor() {
        assert!(!links(3, 1));
        assert!(!links(1, 1));
        assert!(!links(0, 1));
    }
}

#[cfg(test)]
mod shardname {
    use super::{shard_index, shard_name};

    #[test]
    fn roundtrip() {
        for i in [0u32, 1, 42, 999_998, 999_999] {
            assert_eq!(shard_index(&shard_name(i)), Some(i), "index {i}");
        }
    }

    #[test]
    fn rejects_strangers() {
        assert_eq!(shard_index("shard-00001.jsonl"), Some(1)); // width-tolerant parse (06 is a minimum)
        assert_eq!(shard_index("shard-000001.txt"), None); // wrong suffix
        assert_eq!(shard_index("notes.jsonl"), None); // wrong prefix
    }
}
