//! Integration suite: the full lifecycle driven through the real CLI
//! binary (the actual command path), plus a per-class tamper matrix and
//! compaction continuity. Every test owns its temp ledger directory.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn fg() -> Command {
    Command::new(env!("CARGO_BIN_EXE_falsegreen-ledger"))
}

/// Run the binary, returning (exit code, stdout, stderr).
fn run(args: &[&str]) -> (i32, String, String) {
    let out = fg()
        .args(args)
        .output()
        .expect("falsegreen-ledger should run");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn run_ok(args: &[&str]) -> String {
    let (code, out, err) = run(args);
    assert_eq!(code, 0, "command {:?} failed: {err}", args);
    out
}

/// One event JSON with a distinct ts and target; `action` is the action
/// name (the kind is always `tool_call`).
fn event_json(i: u64, action: &str) -> String {
    format!(
        r#"{{"ts_ms":{},"actor":{{"kind":"agent","id":"agent-1"}},"action":{{"kind":"tool_call","name":"{}","target":"t-{}"}},"correlation":{{"session":"s-1"}},"decision":{{"outcome":"allowed"}}}}"#,
        1_760_000_000_000 + i,
        action,
        i
    )
}

/// Write `n` events (targets t0..tn) as JSONL to `file`.
fn write_events(file: &Path, n: u64) {
    let mut content = String::new();
    for i in 0..n {
        content.push_str(&event_json(i, "shell.exec"));
        content.push('\n');
    }
    std::fs::write(file, content).expect("write events");
}

/// A private key that signs the given ledger root.
fn keygen() -> String {
    let out = run_ok(&["keygen"]);
    serde_json::from_str::<Value>(&out).expect("keygen JSON")["private_key"]
        .as_str()
        .expect("private key")
        .to_string()
}

/// Build a 200-event ledger across 3 shards: two compacted (sealed)
/// shards, one active. Returns the root path.
fn three_shard_ledger(dir: &Path) -> String {
    let root = dir.join("ledger");
    let key = keygen();
    run_ok(&["init", root.to_str().unwrap()]);
    for (batch, n) in [(1u64, 67), (2, 66), (3, 67)] {
        let file = dir.join(format!("events-{batch}.jsonl"));
        write_events(&file, n);
        run_ok(&["import", root.to_str().unwrap(), file.to_str().unwrap()]);
        if batch < 3 {
            run_ok(&["compact", root.to_str().unwrap(), "--key", &key]);
        }
    }
    let (code, report, err) = run(&["verify", root.to_str().unwrap()]);
    assert_eq!(code, 0, "fresh ledger must verify clean: {report}{err}");
    key
}

fn shard_path(root: &Path, index: u32) -> PathBuf {
    root.join(format!("shard-{:06}.jsonl", index))
}

/// Read a shard file's lines as parsed JSON values.
fn shard_lines(root: &Path, index: u32) -> Vec<Value> {
    let content = std::fs::read_to_string(shard_path(root, index)).expect("shard file");
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("shard line parses"))
        .collect()
}

fn write_shard(root: &Path, index: u32, lines: &[Value]) {
    let mut content = String::new();
    for line in lines {
        content.push_str(&serde_json::to_string(line).expect("value serializes"));
        content.push('\n');
    }
    std::fs::write(shard_path(root, index), content).expect("write shard");
}

#[test]
fn the_cli_help_lists_every_command() {
    let out = run_ok(&["--help"]);
    for cmd in [
        "init", "append", "verify", "tail", "export", "import", "compact", "keygen", "policy",
    ] {
        assert!(out.contains(cmd), "--help missing {cmd}");
    }
}

#[test]
fn the_full_lifecycle_verifies_clean() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ledger");
    three_shard_ledger(tmp.path());

    // tail reports the last records
    let out = run_ok(&["tail", root.to_str().unwrap(), "-n", "5"]);
    let records: Vec<Value> = serde_json::from_str(&out).expect("tail JSON");
    assert_eq!(records.len(), 5);

    // verify is clean, with a readable report
    let (code, report, _) = run(&["verify", root.to_str().unwrap()]);
    assert_eq!(code, 0);
    let rep: Value = serde_json::from_str(&report).expect("report JSON");
    assert_eq!(rep["verified"], true);
}

#[test]
fn a_tampered_event_field_is_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ledger");
    three_shard_ledger(tmp.path());

    // flip the action name of the last record in shard 3
    let mut lines = shard_lines(&root, 3);
    let last = lines.last_mut().expect("shard 3 has records");
    last["event"]["action"]["name"] = Value::String("shell.rm -rf".into());
    write_shard(&root, 3, &lines);

    let (code, report, _) = run(&["verify", root.to_str().unwrap()]);
    assert_eq!(code, 1, "tampered event must exit 1, got {code}: {report}");
    assert!(report.contains("bad_record_hash"));
}

#[test]
fn a_tampered_prev_hash_is_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ledger");
    three_shard_ledger(tmp.path());

    // flip one byte of the prev_hash of the second record in shard 3
    let mut lines = shard_lines(&root, 3);
    let prev = lines[1]["prev_hash"]
        .as_str()
        .expect("prev hash")
        .to_string();
    let flip = |c: char| if c == 'a' { 'b' } else { 'a' };
    let mut chars = prev.chars();
    let first = chars.next().unwrap();
    let flipped = flip(first).to_string() + chars.as_str();
    lines[1]["prev_hash"] = Value::String(flipped);
    write_shard(&root, 3, &lines);

    let (code, report, _) = run(&["verify", root.to_str().unwrap()]);
    assert_eq!(code, 1, "tampered link must exit 1, got {code}: {report}");
    assert!(report.contains("broken_link"));
}

#[test]
fn a_tampered_seal_signature_is_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ledger");
    three_shard_ledger(tmp.path());

    // flip one byte of the signature in shard 2's seal
    let mut lines = shard_lines(&root, 2);
    let seal_line = lines
        .iter_mut()
        .find(|l| l.get("seal").is_some())
        .expect("shard 2 is sealed");
    let sig = seal_line["seal"]["signature"]
        .as_str()
        .expect("signature")
        .to_string();
    let flip = |c: char| if c == 'a' { 'b' } else { 'a' };
    let mut chars = sig.chars();
    let first = chars.next().unwrap();
    let flipped = flip(first).to_string() + chars.as_str();
    seal_line["seal"]["signature"] = Value::String(flipped);
    write_shard(&root, 2, &lines);

    let (code, report, _) = run(&["verify", root.to_str().unwrap()]);
    assert_eq!(
        code, 3,
        "bad seal signature must exit 3, got {code}: {report}"
    );
    assert!(report.contains("bad_signature"));
}

#[test]
fn a_tampered_cross_shard_link_is_detected() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ledger");
    three_shard_ledger(tmp.path());

    // flip one byte of shard 2's first record's prev_hash (the root link
    // from shard 1)
    let mut lines = shard_lines(&root, 2);
    let prev = lines[0]["prev_hash"]
        .as_str()
        .expect("prev hash")
        .to_string();
    let flip = |c: char| if c == 'a' { 'b' } else { 'a' };
    let mut chars = prev.chars();
    let first = chars.next().unwrap();
    let flipped = flip(first).to_string() + chars.as_str();
    lines[0]["prev_hash"] = Value::String(flipped);
    write_shard(&root, 2, &lines);

    let (code, report, _) = run(&["verify", root.to_str().unwrap()]);
    assert_eq!(
        code, 1,
        "tampered root link must exit 1, got {code}: {report}"
    );
    assert!(report.contains("broken_link"));
}

#[test]
fn compaction_keeps_the_ledger_verifiable() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ledger");
    let key = three_shard_ledger(tmp.path());

    // seal + compact the active shard 3
    let out = run_ok(&["compact", root.to_str().unwrap(), "--key", &key]);
    let record: Value = serde_json::from_str(&out).expect("compact record");
    assert_eq!(record["event"]["action"]["kind"], "ledger.compact");

    let (code, report, _) = run(&["verify", root.to_str().unwrap()]);
    assert_eq!(
        code, 0,
        "ledger must still verify after compaction: {report}"
    );

    // appends continue past the compacted shard
    run_ok(&[
        "append",
        root.to_str().unwrap(),
        "--event",
        &event_json(999, "shell.echo"),
    ]);
    let (code, report, _) = run(&["verify", root.to_str().unwrap()]);
    assert_eq!(code, 0, "append after compact must verify: {report}");
}

#[test]
fn the_export_import_roundtrip_is_hash_stable() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ledger");
    run_ok(&["init", root.to_str().unwrap()]);
    for i in 0..5 {
        run_ok(&[
            "append",
            root.to_str().unwrap(),
            "--event",
            &event_json(i, "shell.cat"),
        ]);
    }

    // export → extract the events → import into a fresh ledger
    let export = run_ok(&["export", root.to_str().unwrap()]);
    let doc: Value = serde_json::from_str(&export).expect("export JSON");
    let events: Vec<String> = doc["shards"]
        .as_array()
        .expect("shards array")
        .iter()
        .flat_map(|s| s["records"].as_array().expect("records"))
        .map(|r| serde_json::to_string(&r["event"]).expect("event serializes"))
        .collect();
    assert_eq!(events.len(), 5);

    let fresh = tmp.path().join("ledger-2");
    run_ok(&["init", fresh.to_str().unwrap()]);
    let file = tmp.path().join("events.jsonl");
    std::fs::write(&file, events.join("\n") + "\n").expect("write jsonl");
    run_ok(&["import", fresh.to_str().unwrap(), file.to_str().unwrap()]);

    let export2 = run_ok(&["export", fresh.to_str().unwrap()]);
    let doc2: Value = serde_json::from_str(&export2).expect("export JSON");
    let hashes: Vec<String> = doc["shards"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|s| s["records"].as_array().unwrap())
        .map(|r| r["hash"].as_str().unwrap().to_string())
        .collect();
    let hashes2: Vec<String> = doc2["shards"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|s| s["records"].as_array().unwrap())
        .map(|r| r["hash"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        hashes, hashes2,
        "import must reproduce the same record hashes"
    );

    let (code, _, _) = run(&["verify", fresh.to_str().unwrap()]);
    assert_eq!(code, 0);
}

#[test]
fn a_corrupt_shard_exits_corrupt() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ledger");
    run_ok(&["init", root.to_str().unwrap()]);
    run_ok(&[
        "append",
        root.to_str().unwrap(),
        "--event",
        &event_json(0, "shell.ls"),
    ]);
    std::fs::write(shard_path(&root, 1), "not json at all {{{").expect("corrupt shard");

    let (code, report, _) = run(&["verify", root.to_str().unwrap()]);
    assert_eq!(code, 5, "corrupt shard must exit 5, got {code}: {report}");
}

#[test]
fn a_policy_violation_exits_policy() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("ledger");
    run_ok(&["init", root.to_str().unwrap()]);
    run_ok(&[
        "append",
        root.to_str().unwrap(),
        "--event",
        &event_json(0, "shell.exec"),
    ]);

    let pol = tmp.path().join("policy.json");
    std::fs::write(
        &pol,
        r#"{"version":"1","rules":[{"id":"no-shell","action_kind":"tool_call","deny":true}]}"#,
    )
    .expect("write policy");

    let (code, report, _) = run(&[
        "verify",
        root.to_str().unwrap(),
        "--policy",
        pol.to_str().unwrap(),
    ]);
    assert_eq!(
        code, 4,
        "policy violation must exit 4, got {code}: {report}"
    );
    assert!(report.contains("policy_violation"));
}
