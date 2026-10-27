//! Compact policy evaluation: a small, version-pinned rule language over
//! ledger events. A `deny` rule flags a matching event outright; a rule with
//! `require_outcome` demands the recorded decision outcome. Evaluation is
//! deterministic and offline — the same events and policy give the same
//! violations.

use serde::{Deserialize, Serialize};

use crate::event::Event;

/// A version-pinned policy document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The policy language version, e.g. `"1"`.
    pub version: String,
    pub rules: Vec<Rule>,
}

/// One rule. All present matchers must match for the rule to apply.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_name: Option<String>,
    /// When set (and not `deny`), the event's decision outcome must equal it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_outcome: Option<String>,
    /// `true`: a matching event is a violation on its own.
    #[serde(default)]
    pub deny: bool,
}

/// A single policy violation, addressed to the violating event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyViolation {
    pub rule_id: String,
    pub shard: u32,
    pub seq: u64,
    pub reason: String,
}

impl Policy {
    /// Structural validation of a policy document.
    pub fn validate(&self) -> Result<(), String> {
        if self.version.trim().is_empty() {
            return Err("policy version must be non-empty".to_string());
        }
        let mut seen = std::collections::BTreeSet::new();
        for rule in &self.rules {
            if rule.id.trim().is_empty() {
                return Err("rule id must be non-empty".to_string());
            }
            if !seen.insert(&rule.id) {
                return Err(format!("duplicate rule id: {}", rule.id));
            }
            if rule.deny && rule.require_outcome.is_some() {
                return Err(format!(
                    "rule {} may not combine deny with require_outcome",
                    rule.id
                ));
            }
            let matchers = [
                rule.actor_kind.is_some(),
                rule.action_kind.is_some(),
                rule.action_name.is_some(),
            ]
            .iter()
            .filter(|b| **b)
            .count();
            if matchers == 0 && !rule.deny && rule.require_outcome.is_none() {
                return Err(format!("rule {} matches nothing", rule.id));
            }
        }
        Ok(())
    }

    /// Evaluate one event. Returns the reasons for each violated rule
    /// (an event can violate several rules; a rule violates once).
    pub fn evaluate(&self, event: &Event) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for rule in &self.rules {
            let matches = rule
                .actor_kind
                .as_deref()
                .map(|v| v == event.actor.kind)
                .unwrap_or(true)
                && rule
                    .action_kind
                    .as_deref()
                    .map(|v| v == event.action.kind)
                    .unwrap_or(true)
                && rule
                    .action_name
                    .as_deref()
                    .map(|v| v == event.action.name)
                    .unwrap_or(true);
            if !matches {
                continue;
            }
            if rule.deny {
                out.push((rule.id.clone(), "event matches a deny rule".to_string()));
            } else if let Some(wanted) = &rule.require_outcome {
                if event.decision.outcome != *wanted {
                    out.push((
                        rule.id.clone(),
                        format!(
                            "decision outcome {:?} must be {:?}",
                            event.decision.outcome, wanted
                        ),
                    ));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(outcome: &str) -> Event {
        Event {
            seq: 1,
            ts_ms: 1_700_000_000_000,
            actor: crate::event::Actor {
                kind: "agent".into(),
                id: "a1".into(),
                version: None,
                on_behalf_of: None,
            },
            action: crate::event::Action {
                kind: "tool_call".into(),
                name: "shell.exec".into(),
                target: Some("rm -rf /".into()),
            },
            correlation: crate::event::Correlation {
                session: "s".into(),
                request: None,
            },
            decision: crate::event::Decision {
                outcome: outcome.into(),
                policy_version: None,
                reason: None,
            },
            context: serde_json::Value::Object(Default::default()),
        }
    }

    #[test]
    fn deny_rule_fires_on_match() {
        let p = Policy {
            version: "1".into(),
            rules: vec![Rule {
                id: "no-shell".into(),
                actor_kind: None,
                action_kind: Some("tool_call".into()),
                action_name: Some("shell.exec".into()),
                require_outcome: None,
                deny: true,
            }],
        };
        p.validate().unwrap();
        let v = p.evaluate(&event("allowed"));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0, "no-shell");
    }

    #[test]
    fn deny_rule_fires_only_on_a_match() {
        let p = Policy {
            version: "1".into(),
            rules: vec![Rule {
                id: "no-shell".into(),
                actor_kind: None,
                action_kind: Some("tool_call".into()),
                action_name: Some("shell.exec".into()),
                require_outcome: None,
                deny: true,
            }],
        };
        assert_eq!(
            p.evaluate(&event("denied")).len(),
            1,
            "a matching event is flagged"
        );
        let mut ev = event("allowed");
        ev.action.name = "db.query".into();
        assert!(p.evaluate(&ev).is_empty());
    }

    #[test]
    fn require_outcome_enforces_the_decision() {
        let p = Policy {
            version: "1".into(),
            rules: vec![Rule {
                id: "shell-needs-denial".into(),
                actor_kind: Some("agent".into()),
                action_kind: Some("tool_call".into()),
                action_name: Some("shell.exec".into()),
                require_outcome: Some("denied".into()),
                deny: false,
            }],
        };
        assert!(p.evaluate(&event("allowed")).len() == 1);
        assert!(p.evaluate(&event("denied")).is_empty());
    }

    #[test]
    fn validation_rejects_malformed_policies() {
        let bad_empty_id = Policy {
            version: "1".into(),
            rules: vec![Rule {
                id: " ".into(),
                ..Rule {
                    id: "".into(),
                    actor_kind: Some("agent".into()),
                    action_kind: None,
                    action_name: None,
                    require_outcome: None,
                    deny: false,
                }
            }],
        };
        assert!(bad_empty_id.validate().is_err());
        let matching_nothing = Policy {
            version: "1".into(),
            rules: vec![Rule {
                id: "ghost".into(),
                actor_kind: None,
                action_kind: None,
                action_name: None,
                require_outcome: None,
                deny: false,
            }],
        };
        assert!(matching_nothing.validate().is_err());
        let both = Policy {
            version: "1".into(),
            rules: vec![Rule {
                id: "both".into(),
                actor_kind: Some("agent".into()),
                action_kind: None,
                action_name: None,
                require_outcome: Some("allowed".into()),
                deny: true,
            }],
        };
        assert!(both.validate().is_err());
        let dup = Policy {
            version: "1".into(),
            rules: vec![
                Rule {
                    id: "r".into(),
                    actor_kind: Some("agent".into()),
                    action_kind: None,
                    action_name: None,
                    require_outcome: None,
                    deny: false,
                },
                Rule {
                    id: "r".into(),
                    actor_kind: Some("user".into()),
                    action_kind: None,
                    action_name: None,
                    require_outcome: None,
                    deny: false,
                },
            ],
        };
        assert!(dup.validate().is_err());
    }

    #[test]
    fn an_event_can_violate_several_rules() {
        let p = Policy {
            version: "1".into(),
            rules: vec![
                Rule {
                    id: "no-shell".into(),
                    actor_kind: None,
                    action_kind: Some("tool_call".into()),
                    action_name: Some("shell.exec".into()),
                    require_outcome: None,
                    deny: true,
                },
                Rule {
                    id: "agent-must-be-allowed".into(),
                    actor_kind: Some("agent".into()),
                    action_kind: None,
                    action_name: None,
                    require_outcome: Some("allowed".into()),
                    deny: false,
                },
            ],
        };
        let ev = event("denied");
        let v = p.evaluate(&ev);
        assert_eq!(v.len(), 2);
    }
}
