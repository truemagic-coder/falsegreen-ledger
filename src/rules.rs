//! The ledger's pure decision rules.
//!
//! These functions are deliberately free of external dependencies so a
//! bounded model checker can compile them into its harness: the harness
//! includes *this file* by path (`#[path = "../src/rules.rs"]`), never a
//! copy of it, and the library and CLI call the very same bytes the proof
//! checks. Keeping the arithmetic and naming rules in one small module is
//! what lets a formal proof speak about the shipped code.

/// True when `seq` is the immediate successor of `prev`.
///
/// The successor is never taken modulo the u64 ceiling: no link may exist
/// past `u64::MAX`. (A bounded proof over an earlier version of this
/// function found exactly that defect — `prev + 1` overflowing at the
/// ceiling — and the guard you see here is the fix it forced.)
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

    #[test]
    fn never_links_past_the_ceiling() {
        assert!(!links(0, u64::MAX)); // the wrapping candidate — rejected
        assert!(!links(u64::MAX, u64::MAX));
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
