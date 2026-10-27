//! Event model v1 — the field set aligned with the IETF draft
//! `draft-sharif-agent-audit-trail`: actor (agent + user identity), action,
//! target, correlation, decision, policy version, timestamp.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Maximum accepted event timestamp (year ~5138 AD); rejects clock nonsense.
pub const MAX_TS_MS: i64 = 100_000_000_000_000;

/// Who acted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    /// `"agent"`, `"user"`, `"system"`, ...
    pub kind: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The human principal the agent acted on behalf of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
}

/// What was done.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    /// `"tool_call"`, `"query"`, `"update"`, `"delete"`, `"decision"`, ...
    pub kind: String,
    /// Concrete action name, e.g. `"shell.exec"`, `"db.write"`.
    pub name: String,
    /// Target description (command, path, table, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

/// Correlation identifiers tying the event back to a request/session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Correlation {
    pub session: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
}

/// The authorization decision recorded with the action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    /// `"allowed"`, `"denied"`, `"redacted"`, `"escalated"`.
    pub outcome: String,
    /// Version of the policy in force at decision time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    /// Human-readable decision reason (why denied, why escalated, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One audited event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    /// Strictly increasing per ledger; 1-based.
    pub seq: u64,
    /// Unix epoch milliseconds.
    pub ts_ms: i64,
    pub actor: Actor,
    pub action: Action,
    pub correlation: Correlation,
    pub decision: Decision,
    /// Free-form context; MUST be a JSON object.
    #[serde(default)]
    pub context: Value,
}

/// Validation / canonicalization errors.
#[derive(Debug)]
pub enum EventError {
    EmptyField(&'static str),
    ContextNotObject,
    BadTimestamp,
}

impl std::fmt::Display for EventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventError::EmptyField(field) => write!(f, "field {field:?} must be non-empty"),
            EventError::ContextNotObject => write!(f, "context must be a JSON object"),
            EventError::BadTimestamp => write!(f, "ts_ms out of accepted range"),
        }
    }
}

impl std::error::Error for EventError {}

fn non_empty(s: &str, field: &'static str) -> Result<(), EventError> {
    if s.trim().is_empty() {
        Err(EventError::EmptyField(field))
    } else {
        Ok(())
    }
}

impl Event {
    /// Canonical JSON map: sorted keys, no whitespace — the integrity input.
    pub fn canonical_map(&self) -> Map<String, Value> {
        // Derived from a `Value` tree so the byte form is independent of
        // struct field order. `serde_json`'s default `Map` is a `BTreeMap`,
        // so keys are already sorted. No normalization: any deviation in a
        // stored record (including a non-object `context`) changes the hash.
        let v = serde_json::to_value(self).expect("serde derive with default features cannot fail");
        v.as_object()
            .expect("an event serializes to an object")
            .clone()
    }

    /// Canonical UTF-8 bytes of the event (sorted keys, no whitespace).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_string(&Value::Object(self.canonical_map()))
            .expect("Value serialization cannot fail")
            .into_bytes()
    }

    pub fn validate(&self) -> Result<(), EventError> {
        non_empty(&self.actor.kind, "actor.kind")?;
        non_empty(&self.actor.id, "actor.id")?;
        non_empty(&self.action.kind, "action.kind")?;
        non_empty(&self.action.name, "action.name")?;
        non_empty(&self.correlation.session, "correlation.session")?;
        non_empty(&self.decision.outcome, "decision.outcome")?;
        if !matches!(self.context, Value::Object(_)) {
            return Err(EventError::ContextNotObject);
        }
        if self.ts_ms < 0 || self.ts_ms > MAX_TS_MS {
            return Err(EventError::BadTimestamp);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Event {
        Event {
            seq: 1,
            ts_ms: 1_760_800_000_000,
            actor: Actor {
                kind: "agent".into(),
                id: "agent-7".into(),
                version: Some("0.3.0".into()),
                on_behalf_of: Some("user-42".into()),
            },
            action: Action {
                kind: "tool_call".into(),
                name: "shell.exec".into(),
                target: Some("cmd=cargo test".into()),
            },
            correlation: Correlation {
                session: "s-1".into(),
                request: Some("r-9".into()),
            },
            decision: Decision {
                outcome: "allowed".into(),
                policy_version: Some("p-3".into()),
                reason: None,
            },
            context: serde_json::json!({"cwd": "/repo", "exit_code": 0}),
        }
    }

    #[test]
    fn context_null_is_canonicalized_as_null_and_rejected() {
        let e = Event {
            context: Value::Null,
            ..sample()
        };
        let bytes = String::from_utf8(e.canonical_bytes()).unwrap();
        // a non-object context stays in the canonical form, so the stored
        // hash cannot be recomputed — tamper evidence, not silent repair
        assert!(bytes.contains("\"context\":null"));
        assert!(matches!(e.validate(), Err(EventError::ContextNotObject)));
        let mut v = e;
        v.context = Value::Object(Map::new());
        assert!(v.validate().is_ok());
    }

    #[test]
    fn canonical_is_sorted_and_stable() {
        let a = sample();
        let b = sample();
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        let bytes = String::from_utf8(a.canonical_bytes()).unwrap();
        // no structural whitespace (data strings may legitimately contain spaces)
        assert!(!bytes.contains(": ") && !bytes.contains(", "));
        assert!(bytes.starts_with("{\"action\":"));
        let expected = serde_json::to_string(&Value::Object(a.canonical_map())).unwrap();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn canonical_round_trips_through_json_with_shuffled_keys() {
        let e = sample();
        let raw = serde_json::to_string(&e).unwrap();
        let parsed: Event = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.canonical_bytes(), e.canonical_bytes());
        assert_eq!(parsed, e);
    }

    #[test]
    fn validation_rejects_empty_required_fields() {
        let mut e = sample();
        e.actor.id = "  ".into();
        assert!(matches!(
            e.validate(),
            Err(EventError::EmptyField("actor.id"))
        ));
        let mut e = sample();
        e.action.name = "".into();
        assert!(matches!(
            e.validate(),
            Err(EventError::EmptyField("action.name"))
        ));
        let mut e = sample();
        e.decision.outcome = "".into();
        assert!(matches!(
            e.validate(),
            Err(EventError::EmptyField("decision.outcome"))
        ));
    }

    #[test]
    fn validation_rejects_bad_timestamp() {
        let mut e = sample();
        e.ts_ms = -1;
        assert!(matches!(e.validate(), Err(EventError::BadTimestamp)));
        let mut e = sample();
        e.ts_ms = MAX_TS_MS + 1;
        assert!(matches!(e.validate(), Err(EventError::BadTimestamp)));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let mut raw = serde_json::to_string(&sample()).unwrap();
        raw.insert(raw.len() - 1, ',');
        raw.push_str("\"injected\":\"x\"");
        assert!(serde_json::from_str::<Event>(&raw).is_err());
    }

    #[test]
    fn optionals_omit_none_in_canonical_form() {
        let e = Event {
            actor: Actor {
                version: None,
                on_behalf_of: None,
                ..sample().actor
            },
            action: Action {
                target: None,
                ..sample().action
            },
            correlation: Correlation {
                request: None,
                ..sample().correlation
            },
            decision: Decision {
                policy_version: None,
                reason: None,
                ..sample().decision
            },
            ..sample()
        };
        let bytes = String::from_utf8(e.canonical_bytes()).unwrap();
        assert!(!bytes.contains("version"));
        assert!(!bytes.contains("on_behalf_of"));
        assert!(!bytes.contains("target"));
        assert!(!bytes.contains("request"));
    }
}
