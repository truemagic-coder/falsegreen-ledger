//! The hash chain: each record commits to the canonical form of the previous
//! record. Flipping any byte of any stored event changes exactly one record
//! hash and breaks every link after it.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::event::Event;

/// The hash a genesis record links to: 64 zeros.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One chained record: event + link + self-hash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub event: Event,
    /// SHA-256 (hex) of the previous record (or `GENESIS_HASH` / the
    /// previous shard's Merkle root for shard genesis records).
    pub prev_hash: String,
    /// SHA-256 (hex) over the canonical event form plus `prev_hash`.
    pub hash: String,
}

/// Canonical hash input: the event's canonical map plus `prev_hash`.
pub fn record_hash_input(event: &Event, prev_hash: &str) -> Value {
    let mut map: Map<String, Value> = event.canonical_map();
    map.insert("prev_hash".into(), Value::String(prev_hash.to_string()));
    Value::Object(map)
}

/// `sha256(canonical(event || prev_hash))` as hex.
pub fn compute_record_hash(event: &Event, prev_hash: &str) -> String {
    let bytes = serde_json::to_string(&record_hash_input(event, prev_hash))
        .expect("Value serialization cannot fail");
    let mut hasher = Sha256::new();
    hasher.update(bytes.as_bytes());
    hex::encode(hasher.finalize())
}

impl Record {
    pub fn new(event: Event, prev_hash: &str) -> Self {
        let hash = compute_record_hash(&event, prev_hash);
        Record {
            event,
            prev_hash: prev_hash.to_string(),
            hash,
        }
    }

    /// True when the stored `hash` recomputes over the stored event + link.
    pub fn check_hash(&self) -> bool {
        compute_record_hash(&self.event, &self.prev_hash) == self.hash
    }

    /// True when this record links to `prev` (hash match + no sequence gap).
    pub fn check_link(&self, prev: &Record) -> bool {
        self.prev_hash == prev.hash && ledger_rules::links(self.event.seq, prev.event.seq)
    }

    pub fn check_seq_start(&self, expected_seq: u64) -> bool {
        self.event.seq == expected_seq
    }
}

/// 64 lowercase hex chars.
pub fn is_valid_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Action, Actor, Correlation, Decision};

    fn ev(seq: u64) -> Event {
        Event {
            seq,
            ts_ms: 1_760_800_000_000 + seq as i64,
            actor: Actor {
                kind: "agent".into(),
                id: "agent-7".into(),
                version: None,
                on_behalf_of: None,
            },
            action: Action {
                kind: "tool_call".into(),
                name: "shell.exec".into(),
                target: None,
            },
            correlation: Correlation {
                session: "s-1".into(),
                request: None,
            },
            decision: Decision {
                outcome: "allowed".into(),
                policy_version: None,
                reason: None,
            },
            context: Value::Object(Map::new()),
        }
    }

    #[test]
    fn genesis_record_is_deterministic() {
        let r1 = Record::new(ev(1), GENESIS_HASH);
        let r2 = Record::new(ev(1), GENESIS_HASH);
        assert_eq!(r1.hash, r2.hash);
        assert!(is_valid_hash(&r1.hash));
        assert_eq!(r1.prev_hash, GENESIS_HASH);
    }

    #[test]
    fn hash_changes_when_any_event_field_changes() {
        let base = Record::new(ev(1), GENESIS_HASH);
        let mut e = ev(1);
        e.action.name = "other.action".into();
        let r = Record::new(e, GENESIS_HASH);
        assert_ne!(r.hash, base.hash);

        let mut e = ev(1);
        e.ts_ms += 1;
        let r = Record::new(e, GENESIS_HASH);
        assert_ne!(r.hash, base.hash);

        let mut e = ev(1);
        e.context = serde_json::json!({"k": "v"});
        let r = Record::new(e, GENESIS_HASH);
        assert_ne!(r.hash, base.hash);
    }

    #[test]
    fn prev_hash_is_committed() {
        let r1 = Record::new(ev(1), GENESIS_HASH);
        let r2 = Record::new(ev(2), &r1.hash);
        let r2_alt = Record::new(ev(2), "ab".repeat(32).as_str());
        assert!(r2.check_link(&r1));
        assert!(!r2_alt.check_link(&r1));
        assert!(is_valid_hash(&r2.hash));
    }

    #[test]
    fn tampered_record_fails_hash_check() {
        let mut r = Record::new(ev(1), GENESIS_HASH);
        r.event.action.name = "tampered".into();
        assert!(!r.check_hash());
    }

    #[test]
    fn sequence_gap_fails_link_check() {
        let r1 = Record::new(ev(1), GENESIS_HASH);
        let r3 = Record::new(ev(3), &r1.hash);
        assert!(!r3.check_link(&r1));
        assert!(r3.check_hash()); // self is fine; the LINK is broken
    }

    #[test]
    fn unknown_fields_rejected_in_record() {
        let r = Record::new(ev(1), GENESIS_HASH);
        let mut raw = serde_json::to_string(&r).unwrap();
        raw.insert(raw.len() - 1, ',');
        raw.push_str("\"injected\":1");
        assert!(serde_json::from_str::<Record>(&raw).is_err());
    }
}
