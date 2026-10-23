//! Shard storage: one ledger is a directory of append-only shard files
//! (`shard-000001.jsonl`, ...). A shard holds chained records; a closed
//! shard ends with a signed seal (the external trust anchor).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::chain::{is_valid_hash, Record, GENESIS_HASH};
use crate::event::Event;

/// A shard seal: the signed integrity anchor of a closed shard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seal {
    /// Merkle root over the shard's record hashes.
    pub merkle_root: String,
    /// Number of records in the sealed shard.
    pub count: u64,
    /// Merkle root of the previous shard (root-link; `None` for shard 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_shard_root: Option<String>,
    /// Ed25519 signature (hex) over [`Seal::canonical_bytes`].
    pub signature: String,
    /// Public key (hex) the signature is verifiable against.
    pub public_key: String,
    pub sealed_at_ms: i64,
}

/// The message a seal signs: canonical JSON, sorted keys.
pub fn seal_signing_message(seal: &Seal) -> Vec<u8> {
    let mut map: Map<String, Value> = Map::new();
    map.insert("count".into(), Value::from(seal.count));
    map.insert("kind".into(), Value::String("seal".into()));
    map.insert(
        "merkle_root".into(),
        Value::String(seal.merkle_root.clone()),
    );
    map.insert(
        "prev_shard_root".into(),
        seal.prev_shard_root
            .clone()
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    map.insert("sealed_at_ms".into(), Value::from(seal.sealed_at_ms));
    serde_json::to_string(&Value::Object(map))
        .expect("Value serialization cannot fail")
        .into_bytes()
}

/// One shard as loaded from disk.
#[derive(Debug, Clone, PartialEq)]
pub struct ShardData {
    pub index: u32,
    pub records: Vec<Record>,
    pub seal: Option<Seal>,
}

/// Errors raised by the store.
#[derive(Debug)]
pub enum LedgerError {
    Io(std::io::Error),
    Parse {
        shard: u32,
        line: usize,
        detail: String,
    },
    InvalidEvent(String),
    HeadMismatch {
        expected: String,
        found: String,
    },
    NoActiveShard,
    MalformedSeal(String),
    Compaction(String),
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LedgerError::Io(e) => write!(f, "io: {e}"),
            LedgerError::Parse {
                shard,
                line,
                detail,
            } => {
                write!(f, "shard {shard} line {line}: {detail}")
            }
            LedgerError::InvalidEvent(d) => write!(f, "invalid event: {d}"),
            LedgerError::HeadMismatch { expected, found } => {
                write!(f, "chain head mismatch: expected {expected}, found {found}")
            }
            LedgerError::NoActiveShard => write!(f, "no active shard to seal"),
            LedgerError::MalformedSeal(d) => write!(f, "malformed seal: {d}"),
            LedgerError::Compaction(d) => write!(f, "compaction refused: {d}"),
        }
    }
}

impl std::error::Error for LedgerError {}

impl From<std::io::Error> for LedgerError {
    fn from(e: std::io::Error) -> Self {
        LedgerError::Io(e)
    }
}

/// An append-only, hash-chained ledger on disk.
pub struct Ledger {
    root: PathBuf,
}

impl Ledger {
    /// Create (or open) the ledger directory.
    pub fn init(root: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn open(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn shard_path(&self, index: u32) -> PathBuf {
        self.root.join(ledger_rules::shard_name(index))
    }

    /// Shard indices present on disk, ascending.
    pub fn shard_indices(&self) -> Result<Vec<u32>, LedgerError> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let name = entry?.file_name().to_string_lossy().to_string();
            if let Some(index) = ledger_rules::shard_index(&name) {
                out.push(index);
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    /// Load one shard (records + optional seal).
    pub fn load_shard(&self, index: u32) -> Result<ShardData, LedgerError> {
        let path = self.shard_path(index);
        let content = fs::read_to_string(&path)?;
        let mut records = Vec::new();
        let mut seal = None;
        for (lineno, line) in content.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(line).map_err(|e| LedgerError::Parse {
                shard: index,
                line: lineno + 1,
                detail: e.to_string(),
            })?;
            match value.get("seal") {
                Some(s) => {
                    if seal.is_some() {
                        return Err(LedgerError::Parse {
                            shard: index,
                            line: lineno + 1,
                            detail: "multiple seal lines".into(),
                        });
                    }
                    seal = Some(parse_seal(s, index, lineno + 1)?);
                }
                None => {
                    let record: Record =
                        serde_json::from_value(value).map_err(|e| LedgerError::Parse {
                            shard: index,
                            line: lineno + 1,
                            detail: e.to_string(),
                        })?;
                    records.push(record);
                }
            }
        }
        Ok(ShardData {
            index,
            records,
            seal,
        })
    }

    /// All shards, ascending.
    pub fn load_all(&self) -> Result<Vec<ShardData>, LedgerError> {
        let indices = self.shard_indices()?;
        let mut out = Vec::with_capacity(indices.len());
        for &i in &indices {
            out.push(self.load_shard(i)?);
        }
        Ok(out)
    }

    /// The current (unsealed) shard, if any.
    pub fn active_shard(&self) -> Result<Option<ShardData>, LedgerError> {
        let indices = self.shard_indices()?;
        let Some(&last) = indices.last() else {
            return Ok(None);
        };
        let shard = self.load_shard(last)?;
        if shard.seal.is_some() {
            Ok(None)
        } else {
            Ok(Some(shard))
        }
    }

    /// `(last_seq, next prev_hash)` for the next append:
    /// - active shard: last record's (seq, hash)
    /// - sealed shards only: last shard's (max seq, merkle_root)
    /// - empty ledger: `(0, GENESIS_HASH)`
    pub fn head(&self) -> Result<(u64, String), LedgerError> {
        if let Some(active) = self.active_shard()? {
            let last = active.records.last().ok_or(LedgerError::Parse {
                shard: active.index,
                line: 0,
                detail: "active shard has no records".into(),
            })?;
            return Ok((last.event.seq, last.hash.clone()));
        }
        let indices = self.shard_indices()?;
        if indices.is_empty() {
            return Ok((0, GENESIS_HASH.to_string()));
        }
        let last = self.load_shard(*indices.last().unwrap())?;
        let seal = last.seal.ok_or(LedgerError::MalformedSeal(
            "final shard has no seal but no active shard".into(),
        ))?;
        let max_seq = last.records.iter().map(|r| r.event.seq).max().unwrap_or(0);
        let next_prev = if crate::compact::is_compacted(&last.records) {
            crate::compact::source_root(&last.records).ok_or_else(|| {
                LedgerError::MalformedSeal("compacted shard has no source root".into())
            })?
        } else {
            seal.merkle_root
        };
        Ok((max_seq, next_prev))
    }

    /// Append events, continuing the verified head. Validates each event and
    /// derives `seq` / `prev_hash`; rejects a continuation mismatch.
    pub fn append(&self, events: &[Event]) -> Result<Vec<Record>, LedgerError> {
        let (last_seq, prev_hash) = self.head()?;
        let mut next_prev = prev_hash;
        let mut out = Vec::with_capacity(events.len());
        let shard_index = self.next_shard_index()?;
        let path = self.shard_path(shard_index);

        for (seq, event) in (last_seq + 1..).take(events.len()).zip(events) {
            event
                .validate()
                .map_err(|e| LedgerError::InvalidEvent(e.to_string()))?;
            let event = Event {
                seq,
                ..event.clone()
            };
            let record = Record::new(event, &next_prev);
            next_prev = record.hash.clone();
            out.push(record);
        }
        if out.is_empty() {
            return Ok(out);
        }
        let mut content = String::new();
        for record in &out {
            content.push_str(
                &serde_json::to_string(record).expect("Record serialization cannot fail"),
            );
            content.push('\n');
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        file.write_all(content.as_bytes())?;
        Ok(out)
    }

    /// Number of the shard the next append goes to.
    fn next_shard_index(&self) -> Result<u32, LedgerError> {
        let indices = self.shard_indices()?;
        let Some(&last) = indices.last() else {
            return Ok(1);
        };
        let shard = self.load_shard(last)?;
        if shard.seal.is_some() {
            Ok(last + 1)
        } else {
            Ok(last)
        }
    }

    /// Close the active shard with `seal` (writes the seal line).
    pub fn seal_active(&self, seal: &Seal) -> Result<u32, LedgerError> {
        let Some(active) = self.active_shard()? else {
            return Err(LedgerError::NoActiveShard);
        };
        if !is_valid_hash(&seal.merkle_root) {
            return Err(LedgerError::MalformedSeal(
                "merkle_root is not a valid hash".into(),
            ));
        }
        if seal.count as usize != active.records.len() {
            return Err(LedgerError::MalformedSeal(format!(
                "seal count {} != records {}",
                seal.count,
                active.records.len()
            )));
        }
        let line = serde_json::json!({ "seal": seal });
        let path = self.shard_path(active.index);
        let mut content = String::from(&fs::read_to_string(&path).map_err(LedgerError::Io)?);
        if !content.ends_with('\n') && !content.is_empty() {
            content.push('\n');
        }
        content.push_str(&serde_json::to_string(&line).expect("seal serialization cannot fail"));
        content.push('\n');
        fs::write(&path, content).map_err(LedgerError::Io)?;
        Ok(active.index)
    }
}

fn parse_seal(v: &Value, shard: u32, lineno: usize) -> Result<Seal, LedgerError> {
    let seal: Seal = serde_json::from_value(v.clone()).map_err(|e| LedgerError::Parse {
        shard,
        line: lineno,
        detail: e.to_string(),
    })?;
    if !is_valid_hash(&seal.merkle_root) {
        return Err(LedgerError::MalformedSeal(
            "merkle_root is not a valid hash".into(),
        ));
    }
    Ok(seal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Action, Actor, Correlation, Decision};

    fn ev() -> Event {
        Event {
            seq: 0, // store overwrites
            ts_ms: 1_760_800_000_000,
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

    fn seal(root: &str, count: u64, prev: Option<&str>) -> Seal {
        Seal {
            merkle_root: root.to_string(),
            count,
            prev_shard_root: prev.map(str::to_string),
            signature: "ab".repeat(32),
            public_key: "cd".repeat(32),
            sealed_at_ms: 1_760_800_000_000,
        }
    }

    #[test]
    fn init_and_append_continues_from_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::init(dir.path()).unwrap();
        let head = ledger.head().unwrap();
        assert_eq!(head, (0, GENESIS_HASH.to_string()));

        let recs = ledger.append(&[ev(), ev()]).unwrap();
        assert_eq!(recs[0].event.seq, 1);
        assert_eq!(recs[0].prev_hash, GENESIS_HASH);
        assert_eq!(recs[1].event.seq, 2);
        assert_eq!(recs[1].prev_hash, recs[0].hash);
        assert!(recs.iter().all(|r| r.check_hash()));

        let loaded = ledger.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].records, recs);
    }

    #[test]
    fn append_after_seal_starts_new_shard_linked_to_merkle_root() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::init(dir.path()).unwrap();
        let root = "ab".repeat(32);
        let recs = ledger.append(&[ev(), ev(), ev()]).unwrap();
        let _ = recs;
        ledger.seal_active(&seal(&root, 3, None)).unwrap();
        let active = ledger.active_shard().unwrap();
        assert!(active.is_none());

        let head = ledger.head().unwrap();
        assert_eq!(head, (3, root.to_string()));

        let recs = ledger.append(&[ev()]).unwrap();
        assert_eq!(recs[0].event.seq, 4);
        assert_eq!(recs[0].prev_hash, root);
        let shards = ledger.load_all().unwrap();
        assert_eq!(shards.len(), 2);
        assert!(shards[0].seal.is_some());
        assert!(shards[1].seal.is_none());
    }

    #[test]
    fn seal_count_mismatch_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::init(dir.path()).unwrap();
        ledger.append(&[ev()]).unwrap();
        let err = ledger
            .seal_active(&seal(&"ab".repeat(32), 2, None))
            .unwrap_err();
        assert!(matches!(err, LedgerError::MalformedSeal(_)));
    }

    #[test]
    fn invalid_event_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::init(dir.path()).unwrap();
        let bad = Event {
            action: Action {
                kind: "".into(),
                name: "x".into(),
                target: None,
            },
            ..ev()
        };
        let err = ledger.append(&[bad]).unwrap_err();
        assert!(matches!(err, LedgerError::InvalidEvent(_)));
    }

    #[test]
    fn corrupt_line_is_a_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::init(dir.path()).unwrap();
        ledger.append(&[ev()]).unwrap();
        let path = ledger.shard_path(1);
        let content = fs::read_to_string(&path).unwrap();
        fs::write(&path, format!("{{\"broken\":\n{content}")).unwrap();
        let err = ledger.load_all().unwrap_err();
        assert!(matches!(err, LedgerError::Parse { .. }));
    }

    #[test]
    fn empty_append_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Ledger::init(dir.path()).unwrap();
        assert!(ledger.append(&[]).unwrap().is_empty());
        assert!(ledger.shard_indices().unwrap().is_empty());
    }
}
