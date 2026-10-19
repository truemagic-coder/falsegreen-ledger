//! `falsegreen-ledger` — the CLI over `falsegreen-ledger-core`.
//!
//! Exit codes (the CI contract): `0` ok · `1` tampered · `2` gap ·
//! `3` signature failed · `4` policy violation · `5` corrupt/parse ·
//! `255` usage error.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use falsegreen_ledger_core::{
    compact_last_sealed, verify_ledger, Event, Ledger, Policy, VerificationReport,
};

#[derive(Parser)]
#[command(name = "falsegreen-ledger", version, about = "tamper-evident audit ledger")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new empty ledger at ROOT.
    Init { root: PathBuf },
    /// Generate a fresh Ed25519 keypair (hex), printed as JSON.
    Keygen,
    /// Append events (full event JSON; `seq` may be omitted — it is derived).
    Append {
        root: PathBuf,
        #[arg(long, required = true)]
        event: Vec<String>,
    },
    /// Print the last N records across all shards (default 10).
    Tail {
        root: PathBuf,
        #[arg(short, long, default_value_t = 10)]
        n: usize,
    },
    /// Verify the whole ledger; prints the JSON report and sets the exit
    /// code from its failures (see the module docs for the mapping).
    Verify {
        root: PathBuf,
        /// Optional policy JSON file to evaluate over every event.
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Export the whole ledger as one JSON document (stdout or --out FILE).
    Export {
        root: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Import events from a JSONL file (one event per line) and append them.
    Import { root: PathBuf, file: PathBuf },
    /// Compact the last sealed shard (requires the private key, hex).
    Compact {
        root: PathBuf,
        #[arg(long)]
        key: String,
    },
    /// Evaluate POLICY_JSON against one EVENT_JSON; exit 4 on any violation.
    Policy { policy: PathBuf, event: PathBuf },
}

/// A CLI failure: usage (bad arguments/input) vs runtime (ledger state).
enum CliError {
    Usage(String),
    Runtime(String),
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Runtime(e.to_string())
    }
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let code = match e.kind() {
                clap::error::ErrorKind::DisplayHelp
                | clap::error::ErrorKind::DisplayVersion => {
                    print!("{e}");
                    ExitCode::SUCCESS
                }
                _ => {
                    eprintln!("falsegreen-ledger: {e}");
                    ExitCode::from(255)
                }
            };
            return code;
        }
    };
    match run(cli.cmd) {
        Ok(code) => code,
        Err(CliError::Usage(m)) => {
            eprintln!("falsegreen-ledger: {m}");
            ExitCode::from(255)
        }
        Err(CliError::Runtime(m)) => {
            eprintln!("falsegreen-ledger: {m}");
            ExitCode::from(5)
        }
    }
}

fn run(cmd: Cmd) -> Result<ExitCode, CliError> {
    match cmd {
        Cmd::Init { root } => {
            let ledger = Ledger::init(&root).map_err(|e| CliError::Runtime(e.to_string()))?;
            println!(
                "{}",
                serde_json::json!({ "root": ledger.root(), "genesis": falsegreen_ledger_core::GENESIS_HASH })
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Keygen => {
            use ed25519_dalek::SigningKey;
            use rand::rngs::OsRng;
            let key = SigningKey::generate(&mut OsRng);
            println!(
                "{}",
                serde_json::json!({
                    "private_key": hex::encode(key.to_bytes()),
                    "public_key": hex::encode(key.verifying_key().to_bytes()),
                })
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Append { root, event } => {
            let events = parse_events(&event)?;
            let ledger = Ledger::open(&root);
            let records = ledger.append(&events).map_err(|e| CliError::Runtime(e.to_string()))?;
            println!("{}", serde_json::to_string(&records).unwrap());
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Tail { root, n } => {
            let ledger = Ledger::open(&root);
            let shards = ledger.load_all().map_err(|e| CliError::Runtime(e.to_string()))?;
            let all: Vec<_> = shards.iter().flat_map(|s| s.records.iter()).collect();
            let start = all.len().saturating_sub(n);
            println!("{}", serde_json::to_string(&all[start..]).unwrap());
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Verify { root, policy } => {
            let ledger = Ledger::open(&root);
            let policy: Option<Policy> = match policy {
                Some(p) => Some(read_policy(&p)?),
                None => None,
            };
            let report = verify_ledger(&ledger, policy.as_ref())
                .map_err(|e| CliError::Runtime(e.to_string()))?;
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
            Ok(verify_exit_code(&report))
        }
        Cmd::Export { root, out } => {
            let ledger = Ledger::open(&root);
            let shards = ledger.load_all().map_err(|e| CliError::Runtime(e.to_string()))?;
            let doc = serde_json::json!({
                "shards": shards.iter().map(|s| serde_json::json!({
                    "index": s.index,
                    "records": s.records,
                    "seal": s.seal,
                })).collect::<Vec<_>>(),
            });
            let rendered = serde_json::to_string_pretty(&doc).unwrap();
            match out {
                Some(path) => std::fs::write(&path, &rendered).map_err(CliError::from)?,
                None => println!("{rendered}"),
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Import { root, file } => {
            let content = std::fs::read_to_string(&file).map_err(CliError::from)?;
            let events: Vec<String> = content.lines().filter(|l| !l.trim().is_empty()).map(|l| l.to_string()).collect();
            let events = parse_events(&events)?;
            let ledger = Ledger::open(&root);
            let records = ledger.append(&events).map_err(|e| CliError::Runtime(e.to_string()))?;
            println!("{}", serde_json::to_string(&records).unwrap());
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Compact { root, key } => {
            let ledger = Ledger::open(&root);
            if ledger
                .active_shard()
                .map_err(|e| CliError::Runtime(e.to_string()))?
                .is_some()
            {
                falsegreen_ledger_core::seal_active_with(&ledger, &key)
                    .map_err(|e| CliError::Runtime(e.to_string()))?;
            }
            let record =
                compact_last_sealed(&ledger, &key).map_err(|e| CliError::Runtime(e.to_string()))?;
            println!("{}", serde_json::to_string(&record).unwrap());
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Policy { policy, event } => {
            let policy = read_policy(&policy)?;
            let event = parse_event(&std::fs::read_to_string(&event).map_err(CliError::from)?)?;
            let violations = policy.evaluate(&event);
            println!(
                "{}",
                serde_json::json!({
                    "violations": violations
                        .iter()
                        .map(|(id, reason)| serde_json::json!({ "rule_id": id, "reason": reason }))
                        .collect::<Vec<_>>(),
                })
            );
            Ok(if violations.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(4)
            })
        }
    }
}

/// The CI exit code for a verification report. When several classes
/// coexist, the most specific diagnosis wins: corrupt (5) — parse fails
/// before any other check — then gap (2, records deleted/reordered),
/// signature (3), tampered (1, content altered), policy (4).
fn verify_exit_code(report: &VerificationReport) -> ExitCode {
    if report.verified {
        return ExitCode::SUCCESS;
    }
    let kinds: Vec<_> = report.failures.iter().map(|f| f.kind).collect();
    let has = |list: &[falsegreen_ledger_core::verify::FailureKind]| {
        list.iter().any(|k| kinds.contains(k))
    };
    const CORRUPT: &[falsegreen_ledger_core::verify::FailureKind] = &[
        falsegreen_ledger_core::verify::FailureKind::ParseLine,
        falsegreen_ledger_core::verify::FailureKind::InvalidEvent,
        falsegreen_ledger_core::verify::FailureKind::BadSealStructure,
    ];
    const TAMPERED: &[falsegreen_ledger_core::verify::FailureKind] = &[
        falsegreen_ledger_core::verify::FailureKind::BadRecordHash,
        falsegreen_ledger_core::verify::FailureKind::BrokenLink,
        falsegreen_ledger_core::verify::FailureKind::BadMerkleRoot,
        falsegreen_ledger_core::verify::FailureKind::BrokenRootLink,
    ];
    const SIGNATURE: &[falsegreen_ledger_core::verify::FailureKind] = &[
        falsegreen_ledger_core::verify::FailureKind::BadSignature,
        falsegreen_ledger_core::verify::FailureKind::BadSealCount,
    ];
    const GAP: &[falsegreen_ledger_core::verify::FailureKind] =
        &[falsegreen_ledger_core::verify::FailureKind::SequenceGap];
    const POLICY: &[falsegreen_ledger_core::verify::FailureKind] =
        &[falsegreen_ledger_core::verify::FailureKind::PolicyViolation];
    let code = if has(CORRUPT) {
        5
    } else if has(GAP) {
        2
    } else if has(SIGNATURE) {
        3
    } else if has(TAMPERED) {
        1
    } else if has(POLICY) {
        4
    } else {
        5 // defensive: failed report with an unmapped class
    };
    ExitCode::from(code as u8)
}

/// Parse event JSON; a missing `seq` defaults to 0 (append derives the
/// real one). Any other failure is a usage error.
fn parse_events(json: &[String]) -> Result<Vec<Event>, CliError> {
    json.iter().map(|s| parse_event(s)).collect()
}

fn parse_event(json: &str) -> Result<Event, CliError> {
    let mut v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| CliError::Usage(format!("event JSON: {e}")))?;
    if let Some(obj) = v.as_object_mut() {
        if !obj.contains_key("seq") {
            obj.insert("seq".into(), serde_json::json!(0));
        }
        if !obj.contains_key("context") {
            obj.insert("context".into(), serde_json::json!({}));
        }
    }
    serde_json::from_value(v).map_err(|e| CliError::Usage(format!("event JSON: {e}")))
}

fn read_policy(path: &std::path::Path) -> Result<Policy, CliError> {
    let policy: Policy = serde_json::from_str(&std::fs::read_to_string(path).map_err(CliError::from)?)
        .map_err(|e| CliError::Usage(format!("policy JSON: {e}")))?;
    policy
        .validate()
        .map_err(|e| CliError::Usage(format!("policy: {e}")))?;
    Ok(policy)
}
