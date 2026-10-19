//! The verification engine: a full re-check of every shard — record hashes,
//! chain links, sequence continuity, Merkle roots, seal signatures, root
//! links, and (optionally) policy compliance. Produces a canonical
//! [`VerificationReport`]. A missing shard, a parse failure, or a broken
//! link is a failure, never silently skipped: the report is fail-closed.

use std::fs;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::chain::{is_valid_hash, Record, GENESIS_HASH};
use crate::integrity::{merkle_root, verify_seal};
use crate::compact::COMPACT_ACTION_KIND;
use crate::policy::Policy;
use crate::store::{Ledger, LedgerError, Seal};

/// A single detected problem, addressed to a shard and (when known) a record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    pub kind: FailureKind,
    pub shard: u32,
    pub seq: Option<u64>,
    pub detail: String,
}

/// The classes of verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// A line in the shard file is not valid JSON / a valid record or seal.
    ParseLine,
    /// An event violates the event model (empty fields, bad timestamp, ...).
    InvalidEvent,
    /// A record's stored hash does not recompute over its event + link.
    BadRecordHash,
    /// A record does not link to the previous record's stored hash.
    BrokenLink,
    /// The sequence number is not strictly increasing by one.
    SequenceGap,
    /// The shard's seal root does not match the recomputed Merkle root.
    BadMerkleRoot,
    /// The seal's record count does not match the shard's records.
    BadSealCount,
    /// A seal (or an embedded source seal) does not verify.
    BadSignature,
    /// The next shard does not root-link to the previous shard's root.
    BrokenRootLink,
    /// A compaction record is structurally inconsistent.
    BadSealStructure,
    /// An event violates the policy.
    PolicyViolation,
}

/// Per-shard summary in the report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShardReport {
    pub shard: u32,
    pub records: u64,
    pub sealed: bool,
    /// `true` when the shard holds one compaction record that stands in for
    /// a sealed shard's full history.
    pub compacted: bool,
    pub failures: u64,
    /// The root that later shards must root-link to (the seal's root for
    /// sealed shards, the recomputed root otherwise; a compacted shard's
    /// original root).
    pub authoritative_root: Option<String>,
}

/// The verification verdict for a whole ledger.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationReport {
    pub verified: bool,
    pub shards: Vec<ShardReport>,
    pub total_records: u64,
    pub failures: Vec<Failure>,
    pub verified_at_ms: i64,
}

/// Verify the whole ledger. `policy`, when given, is evaluated over every
/// parsed event (violations are report failures of kind `PolicyViolation`).
pub fn verify_ledger(
    ledger: &Ledger,
    policy: Option<&Policy>,
) -> Result<VerificationReport, LedgerError> {
    let indices = ledger.shard_indices()?;
    if !indices.is_empty() && !indices.iter().enumerate().all(|(i, &s)| s == i as u32 + 1) {
        return Err(LedgerError::Parse {
            shard: 0,
            line: 0,
            detail: format!(
                "shard indices are not contiguous from 1: {:?}",
                indices
            ),
        });
    }

    let mut failures: Vec<Failure> = Vec::new();
    let mut shard_reports: Vec<ShardReport> = Vec::new();
    let mut expected_seq: u64 = 1;
    let mut expected_prev: String = GENESIS_HASH.to_string();
    let mut total_records: u64 = 0;

    for &shard in &indices {
        let path = ledger.shard_path(shard);
        let content = fs::read_to_string(&path).map_err(LedgerError::Io)?;
        let (records, seal) = parse_shard_lines(&content, shard, &mut failures);
        let mut shard_failures = 0u64;
        let mark = |failures: &mut Vec<Failure>,
                    f: Failure,
                    shard_failures: &mut u64| {
            *shard_failures += 1;
            failures.push(f);
        };

        for (i, record) in records.iter().enumerate() {
            if let Err(e) = record.event.validate() {
                mark(
                    &mut failures,
                    Failure {
                        kind: FailureKind::InvalidEvent,
                        shard,
                        seq: Some(record.event.seq),
                        detail: e.to_string(),
                    },
                    &mut shard_failures,
                );
            }
            if !record.check_hash() {
                mark(
                    &mut failures,
                    Failure {
                        kind: FailureKind::BadRecordHash,
                        shard,
                        seq: Some(record.event.seq),
                        detail: format!(
                            "stored hash {} does not recompute",
                            record.hash
                        ),
                    },
                    &mut shard_failures,
                );
            }
            let restarts_sequence = i == 0
                && is_compacted_shard(&records)
                && record.event.action.kind == COMPACT_ACTION_KIND;
            if !restarts_sequence && record.event.seq != expected_seq {
                mark(
                    &mut failures,
                    Failure {
                        kind: FailureKind::SequenceGap,
                        shard,
                        seq: Some(record.event.seq),
                        detail: format!(
                            "expected seq {expected_seq}, found {}",
                            record.event.seq
                        ),
                    },
                    &mut shard_failures,
                );
            }
            if record.prev_hash != expected_prev {
                mark(
                    &mut failures,
                    Failure {
                        kind: FailureKind::BrokenLink,
                        shard,
                        seq: Some(record.event.seq),
                        detail: format!(
                            "prev_hash {} does not link to expected {expected_prev}",
                            record.prev_hash
                        ),
                    },
                    &mut shard_failures,
                );
            }
            if let Some(p) = policy {
                for (rule_id, reason) in p.evaluate(&record.event) {
                    mark(
                        &mut failures,
                        Failure {
                            kind: FailureKind::PolicyViolation,
                            shard,
                            seq: Some(record.event.seq),
                            detail: format!("rule {rule_id}: {reason}"),
                        },
                        &mut shard_failures,
                    );
                }
            }
            if restarts_sequence {
                // The compact record replaces this shard's sealed history:
                // its seq is the old final seq, and continuation resumes
                // after it.
                expected_seq = record.event.seq + 1;
            } else {
                expected_seq += 1;
            }
            expected_prev = record.hash.clone();
        }

        let hashes: Vec<String> = records.iter().map(|r| r.hash.clone()).collect();
        let recomputed = merkle_root(&hashes).ok();
        let compacted = is_compacted_shard(&records);
        let mut authoritative = recomputed.clone();

        if let Some(seal) = &seal {
            check_seal(seal, &records, recomputed.as_deref(), shard, &mut failures, &mut shard_failures);
            if seal.count as usize == records.len()
                && recomputed.as_deref() == Some(seal.merkle_root.as_str())
            {
                authoritative = Some(seal.merkle_root.clone());
            }
            if compacted {
                check_compacted(&records, seal, shard, &mut failures, &mut shard_failures);
                if let Some(source_root) = compact_source_root(&records) {
                    authoritative = Some(source_root);
                }
            }
        } else if indices.last().copied() == Some(shard) {
            // An open (unsealed) final shard is expected; its root is the
            // recomputed one.
        } else {
            mark(
                &mut failures,
                Failure {
                    kind: FailureKind::BadSealStructure,
                    shard,
                    seq: None,
                    detail: "non-final shard has no seal".to_string(),
                },
                &mut shard_failures,
            );
        }

        total_records += records.len() as u64;
        let next_expected = authoritative.clone();
        shard_reports.push(ShardReport {
            shard,
            records: records.len() as u64,
            sealed: seal.is_some(),
            compacted,
            failures: shard_failures,
            authoritative_root: authoritative,
        });
        // The next shard must root-link to this shard's authoritative root —
        // the recorded (stored) root, even where checks above failed, so one
        // tamper is reported where it happened, not cascaded.
        if let Some(root) = next_expected {
            expected_prev = root;
        }
    }

    Ok(VerificationReport {
        verified: failures.is_empty(),
        shards: shard_reports,
        total_records,
        failures,
        verified_at_ms: now_ms(),
    })
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Parse one shard's lines, recording a `ParseLine` failure per bad line.
fn parse_shard_lines(
    content: &str,
    shard: u32,
    failures: &mut Vec<Failure>,
) -> (Vec<Record>, Option<Seal>) {
    let mut records = Vec::new();
    let mut seal = None;
    for (lineno, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                failures.push(Failure {
                    kind: FailureKind::ParseLine,
                    shard,
                    seq: None,
                    detail: format!("line {}: {e}", lineno + 1),
                });
                continue;
            }
        };
        match value.get("seal") {
            Some(s) => match s.clone().try_into() {
                Ok(parsed) => seal = Some(parsed),
                Err(detail) => failures.push(Failure {
                    kind: FailureKind::ParseLine,
                    shard,
                    seq: None,
                    detail: format!("line {}: seal: {detail}", lineno + 1),
                }),
            },
            None => match Record::try_from(value) {
                Ok(r) => records.push(r),
                Err(detail) => failures.push(Failure {
                    kind: FailureKind::ParseLine,
                    shard,
                    seq: None,
                    detail: format!("line {}: record: {detail}", lineno + 1),
                }),
            },
        }
    }
    (records, seal)
}

impl TryFrom<Value> for Record {
    type Error = String;
    fn try_from(v: Value) -> Result<Self, Self::Error> {
        serde_json::from_value(v).map_err(|e| e.to_string())
    }
}

impl TryFrom<Value> for Seal {
    type Error = String;
    fn try_from(v: Value) -> Result<Self, Self::Error> {
        let seal: Seal = serde_json::from_value(v).map_err(|e| e.to_string())?;
        if !is_valid_hash(&seal.merkle_root) {
            return Err("merkle_root is not a valid hash".to_string());
        }
        Ok(seal)
    }
}

fn is_compacted_shard(records: &[Record]) -> bool {
    records.len() == 1 && records[0].event.action.kind == "ledger.compact"
}

/// The original shard's root a compaction record stands in for.
fn compact_source_root(records: &[Record]) -> Option<String> {
    let v = records.first()?.event.context.get("source_seal")?;
    v.get("merkle_root")?.as_str().map(|s| s.to_string())
}

/// Seal checks: count, Merkle root, signature.
fn check_seal(
    seal: &Seal,
    records: &[Record],
    recomputed: Option<&str>,
    shard: u32,
    failures: &mut Vec<Failure>,
    shard_failures: &mut u64,
) {
    if seal.count as usize != records.len() {
        *shard_failures += 1;
        failures.push(Failure {
            kind: FailureKind::BadSealCount,
            shard,
            seq: None,
            detail: format!("seal count {} != records {}", seal.count, records.len()),
        });
    }
    if let Some(root) = recomputed {
        if root != seal.merkle_root {
            *shard_failures += 1;
            failures.push(Failure {
                kind: FailureKind::BadMerkleRoot,
                shard,
                seq: None,
                detail: format!(
                    "seal root {} != recomputed {root}",
                    seal.merkle_root
                ),
            });
        }
    }
    if let Err(e) = verify_seal(seal) {
        *shard_failures += 1;
        failures.push(Failure {
            kind: FailureKind::BadSignature,
            shard,
            seq: None,
            detail: e,
        });
    }
}

/// Compaction-record consistency: the embedded source seal must verify, and
/// the new seal must carry the source seal's prev_shard_root.
fn check_compacted(
    records: &[Record],
    seal: &Seal,
    shard: u32,
    failures: &mut Vec<Failure>,
    shard_failures: &mut u64,
) {
    let event = &records[0].event;
    let source_shard = event.context.get("source_shard");
    match source_shard {
        Some(Value::Number(n)) if n.as_u64() == Some(shard as u64) => {}
        _ => {
            *shard_failures += 1;
            failures.push(Failure {
                kind: FailureKind::BadSealStructure,
                shard,
                seq: Some(event.seq),
                detail: "source_shard does not name this shard".to_string(),
            });
        }
    }
    let Some(seal_value) = event.context.get("source_seal") else {
        *shard_failures += 1;
        failures.push(Failure {
            kind: FailureKind::BadSealStructure,
            shard,
            seq: Some(event.seq),
            detail: "missing embedded source_seal".to_string(),
        });
        return;
    };
    let source: Result<Seal, String> = seal_value.clone().try_into();
    let Ok(source) = &source else {
        *shard_failures += 1;
        failures.push(Failure {
            kind: FailureKind::BadSealStructure,
            shard,
            seq: Some(event.seq),
            detail: "embedded source_seal is malformed".to_string(),
        });
        return;
    };
    if let Err(e) = verify_seal(source) {
        *shard_failures += 1;
        failures.push(Failure {
            kind: FailureKind::BadSignature,
            shard,
            seq: Some(event.seq),
            detail: format!("source seal: {e}"),
        });
    }
    if seal.prev_shard_root != source.prev_shard_root {
        *shard_failures += 1;
        failures.push(Failure {
            kind: FailureKind::BadSealStructure,
            shard,
            seq: Some(event.seq),
            detail: "seal prev_shard_root does not match the source seal's".to_string(),
        });
    }
}

/// Canonical (sorted-keys, no whitespace) JSON of any serializable value.
pub fn canonical_json<T: Serialize>(value: &T) -> String {
    let v = serde_json::to_value(value).expect("serde_json Value cannot fail to build");
    serde_json::to_string(&v).expect("a Value serializes to a string")
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Action, Actor, Correlation, Decision, Event};
    use crate::integrity::sign_seal;
    use std::fs;
    use crate::store::Ledger as L;

    fn event(seq: u64, name: &str) -> Event {
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
                name: name.into(),
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

    fn build_ledger(tmp: &std::path::Path, n: usize, sign: Option<&str>) -> crate::store::Ledger {
        let ledger = L::init(tmp).unwrap();
        for i in 1..=n {
            let e = event(i as u64, "op");
            ledger.append(std::slice::from_ref(&e)).unwrap();
        }
        if let Some(key) = sign {
            let shard = ledger.load_shard(1).unwrap();
            let hashes: Vec<String> = shard.records.iter().map(|r| r.hash.clone()).collect();
            let root = merkle_root(&hashes).unwrap();
            let seal = sign_seal(
                Seal {
                    merkle_root: root,
                    count: n as u64,
                    prev_shard_root: None,
                    signature: String::new(),
                    public_key: String::new(),
                    sealed_at_ms: 1_700_000_000_000,
                },
                key,
            )
            .unwrap();
            ledger.seal_active(&seal).unwrap();
        }
        ledger
    }

    fn keypair() -> String {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let key = SigningKey::generate(&mut OsRng);
        hex::encode(key.to_bytes())
    }

    #[test]
    fn a_clean_ledger_verifies() {
        let tmp = tempfile::tempdir().unwrap();
        let priv_hex = keypair();
        let ledger = build_ledger(tmp.path(), 5, Some(priv_hex.as_str()));
        let report = verify_ledger(&ledger, None).unwrap();
        assert!(report.verified, "clean ledger must verify: {:?}", report.failures);
        assert_eq!(report.total_records, 5);
    }

    #[test]
    fn a_tampered_event_is_caught() {
        let tmp = tempfile::tempdir().unwrap();
        let priv_hex = keypair();
        let ledger = build_ledger(tmp.path(), 3, Some(priv_hex.as_str()));
        // flip the middle record's event content: the stored hash stays
        // authoritative, so ONLY the content check fails — no cascade.
        let path = ledger.shard_path(1);
        let content = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        let mut record: Record = serde_json::from_str(&lines[1]).unwrap();
        record.event.action.name = "other".into();
        lines[1] = serde_json::to_string(&record).unwrap();
        fs::write(&path, lines.join("\n")).unwrap();
        let report = verify_ledger(&ledger, None).unwrap();
        assert!(!report.verified);
        let kinds: Vec<FailureKind> = report.failures.iter().map(|f| f.kind).collect();
        assert!(kinds.contains(&FailureKind::BadRecordHash));
        assert!(
            !kinds.contains(&FailureKind::BrokenLink)
                && !kinds.contains(&FailureKind::BadMerkleRoot),
            "a content-only tamper must not cascade: {kinds:?}"
        );
    }

    #[test]
    fn a_tampered_record_hash_cascades_downstream() {
        let tmp = tempfile::tempdir().unwrap();
        let priv_hex = keypair();
        let ledger = build_ledger(tmp.path(), 3, Some(priv_hex.as_str()));
        // flip a byte of the middle record's STORED hash: this breaks every
        // integrity layer at once.
        let path = ledger.shard_path(1);
        let content = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        let mut record: Record = serde_json::from_str(&lines[1]).unwrap();
        let mut hash_bytes = hex::decode(&record.hash).unwrap();
        hash_bytes[0] ^= 0xff;
        record.hash = hex::encode(hash_bytes);
        lines[1] = serde_json::to_string(&record).unwrap();
        fs::write(&path, lines.join("\n")).unwrap();
        let report = verify_ledger(&ledger, None).unwrap();
        assert!(!report.verified);
        let kinds: Vec<FailureKind> = report.failures.iter().map(|f| f.kind).collect();
        assert!(kinds.contains(&FailureKind::BadRecordHash));
        assert!(
            kinds.contains(&FailureKind::BrokenLink)
                && kinds.contains(&FailureKind::BadMerkleRoot),
            "a hash tamper must cascade to the link and the seal: {kinds:?}"
        );
    }

    #[test]
    fn a_sequence_gap_is_caught() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = build_ledger(tmp.path(), 3, None);
        let path = ledger.shard_path(1);
        let content = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        lines.remove(1); // delete the middle record
        fs::write(&path, lines.join("\n")).unwrap();
        let report = verify_ledger(&ledger, None).unwrap();
        assert!(!report.verified);
        assert!(report
            .failures
            .iter()
            .any(|f| f.kind == FailureKind::SequenceGap));
    }

    #[test]
    fn a_bad_seal_signature_is_caught() {
        let tmp = tempfile::tempdir().unwrap();
        let priv_hex = keypair();
        let ledger = build_ledger(tmp.path(), 2, Some(priv_hex.as_str()));
        let path = ledger.shard_path(1);
        let content = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        let mut seal_line: Value = serde_json::from_str(&lines[2]).unwrap();
        let sig = seal_line["seal"]["signature"].as_str().unwrap().to_string();
        let mut bytes = hex::decode(&sig).unwrap();
        bytes[0] ^= 0xff;
        seal_line["seal"]["signature"] = Value::String(hex::encode(bytes));
        lines[2] = serde_json::to_string(&seal_line).unwrap();
        fs::write(&path, lines.join("\n")).unwrap();
        let report = verify_ledger(&ledger, None).unwrap();
        assert!(!report.verified);
        assert!(report
            .failures
            .iter()
            .any(|f| f.kind == FailureKind::BadSignature));
    }

    #[test]
    fn policy_violations_land_in_the_report() {
        let tmp = tempfile::tempdir().unwrap();
        let priv_hex = keypair();
        let ledger = build_ledger(tmp.path(), 2, Some(priv_hex.as_str()));
        let policy = Policy {
            version: "1".into(),
            rules: vec![crate::policy::Rule {
                id: "deny-op".into(),
                actor_kind: None,
                action_kind: Some("tool_call".into()),
                action_name: Some("op".into()),
                require_outcome: None,
                deny: true,
            }],
        };
        let report = verify_ledger(&ledger, Some(&policy)).unwrap();
        assert!(!report.verified);
        assert_eq!(
            report
                .failures
                .iter()
                .filter(|f| f.kind == FailureKind::PolicyViolation)
                .count(),
            2
        );
    }

    #[test]
    fn the_report_is_canonical_json() {
        let tmp = tempfile::tempdir().unwrap();
        let ledger = build_ledger(tmp.path(), 1, None);
        let report = verify_ledger(&ledger, None).unwrap();
        let json = canonical_json(&report);
        let v: Value = serde_json::from_str(&json).unwrap();
        assert!(v["verified"].is_boolean());
        // canonical: no whitespace outside strings
        let outside_strings = json
            .chars()
            .filter(|c| *c == ' ' || *c == '\n')
            .count();
        // the sample data has no spaces in strings, so none may appear
        assert_eq!(outside_strings, 0);
    }
}
