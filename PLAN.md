# FalseGreen Ledger — Build & Verification Plan

**Project:** `falsegreen-ledger` — a tamper-evident, hash-chained audit ledger for AI-agent actions (and any high-stakes operations), built in Rust.
**Deliverable this run:** a complete, tested Rust workspace, verified end-to-end through the FalseGreen MCP workflow to a **signed verification report** (polling overnight).
**Positioning:** open-core (MIT). FalseGreen paid-product candidate: the compliance/audit-trail layer ("FalseGreen Ledger").

Date: 2026-10-18 · Budget: ~12 h · Repo: this directory (fresh git repo).

---

## 1. Why this project

Research (tavily, 2026-10-18):

- The **IETF draft `draft-sharif-agent-audit-trail` (rev 05, updated 2026-09)** proposes a standard logging format for autonomous AI systems — the format exists on paper, but there is **no production tool implementing the storage/integrity layer** (hash chaining, gap detection, external anchoring).
- The **EU AI Act's Aug-2026 deadline** turned "show me what your agent did" into a fineable compliance question; 2026 tooling comparisons (lyzr.ai, mind-core) list the gap as open: existing GRC platforms (Vanta/Drata) handle *documentation*, not *tamper-evident evidence*.
- **Tracekit (arXiv 2609.35659)** validates the design (intent/self-report/action channels, hash-chained, externally anchorable) but is a research prototype, not a product.
- The supply-chain/SCA space (Snyk, Trivy, cargo-audit, cargo-vet) is saturated — a generic SCA tool has no moat; a **compliance-grade evidence tool** does.

What the product gives a team: one binary that turns "an agent did X" from an editable log line into **evidence**:

| Property | Mechanism |
|---|---|
| No retroactive edit survives | every record commits to `sha256(previous record)`; flipping any byte breaks the chain |
| No silent deletion survives | strictly increasing `seq`; gaps are detected and reported |
| Chain replacement is detectable | per-shard **Merkle root** + **Ed25519 seal** (trust anchor stored outside the ledger) |
| No injection of forged records | append requires continuation of the verified chain head; seals are signature-checked |
| Auditable decisions | every event carries actor (agent + user), action, target, correlation id, decision (allowed/denied), policy version |
| CI-ready | deterministic JSON reports + stable exit codes for pipelines |

## 2. Architecture

Cargo workspace, two crates:

```
falsegreen-ledger/
├── Cargo.toml                 # workspace
├── falsegreen.toml            # the FalseGreen contract (definition of done)
├── .gitignore                 # /target
├── .falsegreenignore          # (no re-includes needed; lockfile IS committed)
├── README.md
├── docs/DESIGN.md
├── crates/
│   ├── falsegreen-ledger-core/  # library: the ledger engine
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── event.rs       # event model + canonical serialization
│   │       ├── chain.rs       # record hashing, linking, gap detection
│   │       ├── merkle.rs      # per-shard Merkle root + membership proofs
│   │       ├── sign.rs        # Ed25519 shard seals (trust anchor)
│   │       ├── store.rs       # shard store: init / append / load / archive
│   │       ├── verify.rs      # verification engine → VerificationReport
│   │       ├── policy.rs      # policy engine: actors, actions, versions
│   │       ├── compact.rs     # signed compaction / re-root across shards
│   │       └── report.rs      # report model + canonical JSON
│   └── falsegreen-ledger/       # binary `falsegreen-ledger` (clap)
│       └── src/
│           ├── main.rs        # dispatch + exit codes
│           └── cmd/           # init, append, verify, tail, export,
│                              # import, compact, keygen, policy
└── (tests: unit in-core; integration in crates/falsegreen-ledger/tests/)
```

### 2.1 Event model (v1, aligned with the IETF draft's field set)

```json
{
  "schema": 1,
  "seq": 123,
  "ts_ms": 1760800000000,
  "actor":    { "type": "agent", "id": "agent-7", "version": "1.4.0", "on_behalf_of": "user-42" },
  "action":   { "kind": "tool_call", "name": "shell.exec", "target": "cmd=cargo test" },
  "correlation": { "session": "s-1", "request": "r-9" },
  "decision": { "outcome": "allowed", "policy_version": "p-3", "reason": null },
  "context":  { "arbitrary": "values, canonicalized" }
}
```

- `ts_ms` = SystemTime epoch milliseconds (no chrono dependency).
- **Canonical serialization** (the integrity primitive): UTF-8 JSON, sorted keys, no whitespace, numeric/bool/string types only — `sha256(canonical_bytes)` is the record hash input. Determinism is unit-tested byte-for-byte.

### 2.2 Chain & storage

- A **shard** is one append-only JSONL file: `shard-000001.jsonl`, one record per line:
  `{ "event": …, "prev_hash": "…", "hash": "…" }`
  where `hash = sha256(canonical(schema, seq, ts_ms, actor, action, correlation, decision, context, prev_hash))`.
- Genesis: `prev_hash = 64×"0"`. `seq` starts at 1 and is strictly +1 — **gaps are tamper evidence**.
- **Seal** (last line of a closed shard): `{ "seal": { "merkle_root", "count", "prev_shard_root", "signature", "public_key", "sealed_at_ms" } }` — Ed25519-signed over the shard's Merkle root. The public key / seal is the **external trust anchor** (the "protect the anchor separately" requirement).
- `store.rs` enforces: append only extends the current shard (continuing the verified head); a mismatched head → `ChainMismatch` error; shards are immutable once sealed.

### 2.3 Merkle & verification

- `merkle.rs`: binary Merkle tree over record hashes; odd nodes duplicated (standard); root + per-leaf membership proof; proof verification.
- `verify.rs` → `VerificationReport` (JSON):
  - checks: `record_hashes`, `link_integrity`, `sequence_gaps`, `merkle_root`, `seal_signature`, `cross_shard_links`, `policy_violations[]` (when a policy is supplied);
  - `status`: `ok | tampered | gap | signature_failed | policy_violation | corrupt`;
  - first/last seq, record counts per shard, per-shard results.
- **CLI exit codes** (CI contract): `0` ok · `1` tampered · `2` gap · `3` signature failed · `4` policy violation · `5` corrupt/parse · `255` usage error.

### 2.4 Compaction

`compact` seals the active shard, archives it, and starts a new shard whose genesis `prev_hash` = previous shard's Merkle root (root-linked traversal keeps the whole history verifiable; archived shards stay in `archive/`). The seal of the new shard commits to `prev_shard_root`, making **chain replacement detectable**.

### 2.5 Policy engine

`policy.toml`: allowed actor ids/types, allowed action kinds/names, required fields, `policy_version` string, max-context-size. `append` and `verify --policy` flag violations (they are recorded in the report; the decision is the operator's — the tool reports, it does not redact).

## 3. Dependency budget (lean = auditable)

`serde`, `serde_json`, `sha2`, `ed25519-dalek`, `clap`, `hex`; dev: `tempfile`. No network I/O anywhere in library code (tests included). No `unsafe`. `Cargo.lock` committed (reproducible build; the job image fetches deps in its fetch leg).

## 4. FalseGreen verification contract

`falsegreen.toml` (frozen at Job creation — editing it after means a new Job):

```toml
schema = 1
language = "rust"
wall_seconds = 1800

[[criterion]]
id = "build"
title = "the workspace compiles"
required = true
  [[criterion.command]]
  argv = ["cargo", "build", "--workspace", "--release"]
  timeout_seconds = 600
  allowed_exit_codes = [0]

[[criterion]]
id = "tests"
title = "the full test suite passes offline"
required = true
  [[criterion.command]]
  argv = ["cargo", "test", "--workspace"]
  timeout_seconds = 900
  allowed_exit_codes = [0]

[[criterion]]
id = "lint"
title = "clippy and fmt are clean"
required = false
  [[criterion.command]]
  argv = ["cargo", "clippy", "--workspace", "--all-targets", "--", "-D", "warnings"]
  timeout_seconds = 600
  [[criterion.command]]
  argv = ["cargo", "fmt", "--all", "--check"]
  timeout_seconds = 120
  allowed_exit_codes = [0]
```

## 5. The FalseGreen TaskPlan (frozen)

Work-item DAG (each item names the criteria it serves):

| id | outcome | deps | serves |
|---|---|---|---|
| `workspace-scaffold` | git repo + 2-crate workspace + contract + lockfile | — | build |
| `event-model` | event schema v1 + canonical serialization, byte-deterministic | scaffold | tests |
| `hash-chain` | record hashing, linking, gap detection | event-model | tests |
| `shard-store` | init/append/load, append-only head continuity | hash-chain | tests |
| `merkle-seal` | Merkle root + proofs + Ed25519 shard seal | hash-chain | tests |
| `verification-engine` | full verify → JSON report + exit codes | shard-store, merkle-seal | tests, build |
| `policy-engine` | policy file + violation detection | event-model | tests |
| `compaction` | signed compact/re-root + root-linked traversal | shard-store, merkle-seal | tests |
| `cli` | 9 subcommands: init, append, verify, tail, export, import, compact, keygen, policy | verification-engine, policy-engine, compaction | build, tests |
| `test-suite` | unit + integration: determinism, tamper, gaps, compact-invariance, policy, export, clippy/fmt | cli | tests |
| `docs` | README + docs/DESIGN.md | cli | inspection |

Overall acceptance:
- `contract-green` — required criteria `build` + `tests` pass against the frozen source (behavioral_test → `build`, `tests`).
- `tamper-evidence` — flipping any byte of any record makes `verify` report `tampered` (exit 1); deleting a record reports `gap` (exit 2) (regression_test → `tests`).
- `seal-integrity` — a wrong Merkle root / wrong key fails the seal check (exit 3) (regression_test → `tests`).

Frozen security policy (all five witness classes are supported by the 0.7.0 job image — gitleaks, syft, osv-scanner, semgrep):

```json
{
  "id": "falsegreen-ledger-security-policy",
  "version": "1",
  "required": ["dependency_vulnerability", "static_analysis", "secret", "supply_chain", "license"],
  "required_standards": ["soc-2-tsc", "iso-27001", "cis-controls", "nist-csf-2.0", "cra"],
  "fail_on_severities": ["critical"],
  "secrets_fail_on_any_unexcepted": true,
  "unknown_severity": "insufficient",
  "unavailable_behavior": "insufficient",
  "minimum_witnesses": 1
}
```

(`digest` is computed by the freeze — not hand-written. The report gets a posture row per required standard: SOC 2 TSC, ISO 27001, CIS Controls, NIST CSF 2.0, CRA.)

## 6. Workflow (the overnight run)

Every step is free; the single entitlement spends once at the terminal verdict.

1. `falsegreen_status` — done (authenticated, shim 0.7.0).
2. git init → scaffold → `falsegreen.toml` + lockfile → commit.
3. `falsegreen_create_task(goal, workspace)` → task in `planning`.
4. `falsegreen_save_plan_draft(task_id, plan)` → `falsegreen_validate_plan` → **`falsegreen_freeze_plan`** (automatic, immutable; `plan_sha256` enters the boundary).
5. **Build** the project against the frozen plan (waves below); commit as it lands; run affected tests per change (full suite is the final gate, not the commit gate).
6. Final full suite green locally → commit → `falsegreen_create_job(task_id)` (publishes the workspace, freezes the source boundary) → `falsegreen_verify_job` (dispatch).
7. Poll `falsegreen_get_report(job_id)` overnight → terminal verdict (target: **accepted**).
8. `falsegreen_verify_report(report)` — local Ed25519 signature check, no network. Deliver the signed report.

## 7. Build waves (12 h)

| Hour | Wave | Who | Content |
|---|---|---|---|
| 0–1 | — | me | this plan, scaffold, git, task + frozen plan |
| 1–4 | W1 | me | core spine: `event`, canonical, `chain`, `store` (init/append/load) + unit tests |
| 4–7 | W2 | 2 agents ∥ | A: `merkle` + `sign` + `verify` + `report`; B: CLI skeleton against the documented core API |
| 7–9 | W3 | 2 agents ∥ | A: `policy` + `compact` + `export`; B: integration test suite (tamper/gap/seal/policy/compact-invariance) |
| 9–10 | W4 | me | integration pass, clippy/fmt clean, full workspace suite, README/DESIGN review, final commit |
| 10–11 | — | me | `create_job` → `verify_job` → dispatch |
| 11–12+ | — | me | poll `get_report`; if non-accepted: read the report, fix, `repair_job` (free, ≤7 rounds); verify signature on the final report |

Failure budget is generous: 8 attempts total, all inside one price.

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Image toolchain ≠ local (new clippy lints) | required criteria are `build` + `tests` only; `lint` is optional/recorded |
| Test wall time vs worker budget | suite is offline + fast (<5 min); `wall_seconds=1800` advisory, command timeouts set per command |
| Integrity gate (contract re-derivation) | `falsegreen.toml` is frozen before any build; never edited after create; a contract change would need a new Job (by design) |
| Dep fetch in job image (leg 1) | `Cargo.lock` committed; deps are mainstream, no git deps, no build scripts needing network |
| Subagent drift on the core API | I own the core spine (W1); agents work against the frozen API surface, reviewed before merge |
| Secrets in repo (D0-style scan) | no keys in tests (fresh keygen per test); `.gitignore` standard |

## 9. Definition of done

- The signed report returns **`accepted`**: `build` + `tests` evidence on the frozen source, per-criterion command evidence, frozen boundary digests, environment fingerprint, valid Ed25519 signature (locally verified), full Security & Standards section (5 evidence classes + 5 posture rows).
- The repo contains the committed workspace, contract, plan reference, and the saved report (JSON) for the record.
## 10. FalseGreen trouble log
Standalone record: `FALSEGREEN_ISSUES.md` (root).
Running record of the friction met with the FalseGreen tooling in THIS project — the record is the point (D-RT scanner behavior, MCP surface ergonomics), so future projects can file the same bugs.

| # | When | Trouble | Workaround | Status |
|---|---|---|---|---|
| T1 | 2026-10-19, `create_job` (1st attempt) | **D0 secret gate false positive**: the high-entropy `secret_token` rule flagged the slash-joined CLI subcommand list in PLAN.md (`init/append/verify/tail/export/import/compact/keygen/policy` — one 64-char alphanumeric token) → publish refused, Job never started | Split the list into prose (5e69e29); re-scan clean; `create_job` succeeded | WORKAROUND. The 0.7.0 fix (348d3a1) allowlisted pure-hex digests ≥40 chars and raised the minimum length to 40, but long ALPHANUMERIC compound tokens (non-hex) still trip it — second occurrence of this FP class (first: Cargo.lock SHA-256 checksums). Filed below. |
| T2 | 2026-10-19, `verify_report` step | **MCP `falsegreen_verify_report` is impractical for large reports**: the argument is the report JSON as a STRING in the tool call (no file path). At v5 schema with a full Security/Standards section the report is ~84KB — the `read` tool truncates lines to 768 chars, bash cannot write to `xd://` MCP paths (read-only fs), so the only route is transcribing the full JSON through model context (corruption risk at that size) | Used the CLI `falsegreen verify-report docs/REPORT-4a69d00c.json` — the same `verify_report_json` implementation the MCP tool wraps, reading the file directly. Result: **VERIFIED** (verdict accepted, key `fg-report-9fc1a2c5-…-20261018-1`, digest `82c92878…`, schema v5) | WORKAROUND. Recommend the MCP tool accept a file path (or a `report_ref`) for ≥64KB reports. |
| T3 | 2026-10-19, `get_report` polling | **Artifact wrapper is multi-line**: the terminal-verdict output is a JSON document where the first line is the payload and trailing lines are display wrappers (84,031 bytes total, 105 trailing) — `json.load` on the whole file fails with "Extra data" | Parse with `json.JSONDecoder().raw_decode` (first object wins) | NOTE. Cosmetic; one wasted parse round. |

**Bugs to file upstream (falsegreen, 0.7.0):**

1. D0 `secret_token` high-entropy rule still false-positives on long non-hex alphanumeric compound tokens (slash-joined identifiers). 348d3a1 covered hex digests only. Suggest: exclude tokens composed of a small identifier alphabet joined by `/` `-` `.` when they match known word lists, or raise the entropy floor above 4.0 bits/char for non-hex.
2. MCP `falsegreen_verify_report`: accept a file path / artifact reference, not an inline string.

## 11. Outcome

- Job `4a69d00c-cc83-48e8-9267-510996677031`: **accepted**, attempt 1, 28.5s — `build` exit 0, `tests` exit 0 (51 tests: 41 core + 10 integration), `lint` exit 0 (clippy `-D warnings` + fmt), all security classes pass.
- Signed report: `docs/REPORT-4a69d00c.json` — locally verified (T2), Ed25519 schema v5.
