//! Compaction: a sealed shard's history is replaced by a single compaction
//! record whose context embeds the shard's original signed seal. The
//! record's hash re-enters the chain at the same sequence position, and the
//! next append continues from the ORIGINAL shard root (not the compact
//! record's) — so a ledger verifies identically before and after
//! compaction, and a consumer of the compacted shards alone holds a
//! complete, verifiable history via the embedded seals.

use serde_json::{Map, Value};

use crate::chain::Record;
use crate::event::{Action, Actor, Correlation, Decision, Event};
use crate::integrity::{merkle_root, sign_seal};
use crate::store::{Ledger, LedgerError, Seal};

/// The action kind a compaction record carries.
pub const COMPACT_ACTION_KIND: &str = "ledger.compact";
/// Context keys of a compaction record.
pub const SOURCE_SHARD: &str = "source_shard";
pub const SOURCE_RECORD_COUNT: &str = "source_record_count";
pub const SOURCE_SEAL: &str = "source_seal";

/// True when a shard holds exactly one compaction record.
pub fn is_compacted(records: &[Record]) -> bool {
    records.len() == 1 && records[0].event.action.kind == COMPACT_ACTION_KIND
}

/// The original shard root a compaction record stands in for (its embedded
/// `source_seal.merkle_root`).
pub fn source_root(records: &[Record]) -> Option<String> {
    let v = records.first()?.event.context.get(SOURCE_SEAL)?;
    v.get("merkle_root")?.as_str().map(|s| s.to_string())
}

/// Compact the last sealed shard. The shard file is replaced with one
/// compaction record plus a fresh seal; the chain continues from the
/// original root and the same final sequence number.
pub fn compact_last_sealed(ledger: &Ledger, private_key_hex: &str) -> Result<Record, LedgerError> {
    let indices = ledger.shard_indices()?;
    let Some(&last) = indices.last() else {
        return Err(LedgerError::Compaction("the ledger is empty".into()));
    };
    if ledger.active_shard()?.is_some() {
        return Err(LedgerError::Compaction(
            "the ledger has an unsealed shard — seal it first".into(),
        ));
    }
    let shard = ledger.load_shard(last)?;
    let source_seal = shard
        .seal
        .as_ref()
        .ok_or_else(|| LedgerError::Compaction(format!("shard {last} is not sealed")))?;
    if shard.records.is_empty() {
        return Err(LedgerError::Compaction(
            "a sealed shard has no records".into(),
        ));
    }
    if is_compacted(&shard.records) {
        return Err(LedgerError::Compaction(format!("shard {last} is already compacted")));
    }

    let last_record = shard.records.last().expect("non-empty checked");
    let genesis_prev = shard.records.first().expect("non-empty checked").prev_hash.clone();

    let mut context: Map<String, Value> = Map::new();
    context.insert(SOURCE_SHARD.into(), Value::from(last));
    context.insert(
        SOURCE_RECORD_COUNT.into(),
        Value::from(shard.records.len() as u64),
    );
    context.insert(
        SOURCE_SEAL.into(),
        serde_json::to_value(source_seal).expect("a Seal serializes"),
    );

    let event = Event {
        seq: last_record.event.seq,
        ts_ms: now_ms(),
        actor: Actor {
            kind: "system".into(),
            id: "compactor".into(),
            version: None,
            on_behalf_of: None,
        },
        action: Action {
            kind: COMPACT_ACTION_KIND.into(),
            name: "shard.compact".into(),
            target: Some(format!("shard-{:06}", last)),
        },
        correlation: Correlation {
            session: "compaction".into(),
            request: None,
        },
        decision: Decision {
            outcome: "allowed".into(),
            policy_version: None,
            reason: None,
        },
        context: Value::Object(context),
    };
    event
        .validate()
        .map_err(|e| LedgerError::Compaction(e.to_string()))?;
    let record = Record::new(event, &genesis_prev);

    let line = serde_json::to_string(&record).expect("a Record serializes");
    let path = ledger.shard_path(last);
    std::fs::write(&path, format!("{line}\n")).map_err(LedgerError::Io)?;

    let root = merkle_root(std::slice::from_ref(&record.hash))
        .map_err(LedgerError::Compaction)?;
    let new_seal = sign_seal(
        Seal {
            merkle_root: root,
            count: 1,
            prev_shard_root: source_seal.prev_shard_root.clone(),
            signature: String::new(),
            public_key: String::new(),
            sealed_at_ms: now_ms(),
        },
        private_key_hex,
    )
    .map_err(LedgerError::Compaction)?;
    ledger.seal_active(&new_seal)?;
    Ok(record)
}

fn now_ms() -> i64 {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    d.as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(seq: u64) -> Event {
        Event {
            seq,
            ts_ms: 1_700_000_000_000i64 + seq as i64,
            actor: Actor {
                kind: "agent".into(),
                id: "a1".into(),
                version: None,
                on_behalf_of: None,
            },
            action: Action {
                kind: "tool_call".into(),
                name: "op".into(),
                target: None,
            },
            correlation: Correlation {
                session: "s".into(),
                request: None,
            },
            decision: Decision {
                outcome: "allowed".into(),
                policy_version: None,
                reason: None,
            },
            context: Value::Object(Default::default()),
        }
    }

    fn keypair() -> String {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let key = SigningKey::generate(&mut OsRng);
        hex::encode(key.to_bytes())
    }

    fn seal_active_from(ledger: &Ledger, priv_hex: &str) {
        let active = ledger.active_shard().unwrap().expect("active shard");
        let hashes: Vec<String> = active.records.iter().map(|r| r.hash.clone()).collect();
        let root = merkle_root(&hashes).unwrap();
        let seal = sign_seal(
            Seal {
                merkle_root: root,
                count: active.records.len() as u64,
                prev_shard_root: None,
                signature: String::new(),
                public_key: String::new(),
                sealed_at_ms: 1_700_000_000_000,
            },
            priv_hex,
        )
        .unwrap();
        ledger.seal_active(&seal).unwrap();
    }

    fn build_and_seal(tmp: &std::path::Path, n: usize, priv_hex: &str) -> Ledger {
        let ledger = Ledger::init(tmp).unwrap();
        for i in 1..=n {
            ledger.append(std::slice::from_ref(&event(i as u64))).unwrap();
        }
        seal_active_from(&ledger, priv_hex);
        ledger
    }

    #[test]
    fn the_compacted_shard_verifies_and_reports_the_source_root() {
        let tmp = tempfile::tempdir().unwrap();
        let priv_hex = keypair();
        let ledger = build_and_seal(tmp.path(), 4, &priv_hex);
        let original_root = ledger.load_shard(1).unwrap().seal.unwrap().merkle_root;
        assert_eq!(ledger.head().unwrap().0, 4);

        let record = compact_last_sealed(&ledger, &priv_hex).unwrap();
        assert_eq!(record.event.seq, 4, "the compact record keeps the last seq");
        assert_eq!(record.event.action.kind, COMPACT_ACTION_KIND);

        let shard = ledger.load_shard(1).unwrap();
        assert_eq!(shard.records.len(), 1);
        assert!(is_compacted(&shard.records));
        assert_eq!(source_root(&shard.records), Some(original_root.clone()));

        let report = crate::verify::verify_ledger(&ledger, None).unwrap();
        assert!(
            report.verified,
            "compacted ledger must verify: {:?}",
            report.failures
        );
        assert!(report.shards[0].compacted);
        assert_eq!(
            report.shards[0].authoritative_root.as_deref(),
            Some(original_root.as_str())
        );
    }

    #[test]
    fn the_chain_continues_from_the_original_root_after_compaction() {
        let tmp = tempfile::tempdir().unwrap();
        let priv_hex = keypair();
        let ledger = build_and_seal(tmp.path(), 3, &priv_hex);
        let original_root = ledger.load_shard(1).unwrap().seal.unwrap().merkle_root;
        compact_last_sealed(&ledger, &priv_hex).unwrap();
        // head must continue from the ORIGINAL root, not the compact hash
        let (seq, prev) = ledger.head().unwrap();
        assert_eq!(seq, 3);
        assert_eq!(prev, original_root);
        // an append after compaction must link to the original root
        let records = ledger.append(std::slice::from_ref(&event(4))).unwrap();
        assert_eq!(records[0].prev_hash, original_root);
        let report = crate::verify::verify_ledger(&ledger, None).unwrap();
        assert!(report.verified, "{:?}", report.failures);
    }

    #[test]
    fn compaction_refuses_unsealed_empty_and_already_compacted() {
        let tmp = tempfile::tempdir().unwrap();
        let priv_hex = keypair();
        let ledger = Ledger::init(tmp.path()).unwrap();
        assert!(matches!(
            compact_last_sealed(&ledger, &priv_hex),
            Err(LedgerError::Compaction(_))
        ));
        // an unsealed shard cannot be compacted
        ledger.append(std::slice::from_ref(&event(1))).unwrap();
        assert!(matches!(
            compact_last_sealed(&ledger, &priv_hex),
            Err(LedgerError::Compaction(_))
        ));
        // sealed: first compaction succeeds, the second is refused
        seal_active_from(&ledger, &priv_hex);
        assert!(compact_last_sealed(&ledger, &priv_hex).is_ok());
        assert!(matches!(
            compact_last_sealed(&ledger, &priv_hex),
            Err(LedgerError::Compaction(_))
        ));
    }
}
