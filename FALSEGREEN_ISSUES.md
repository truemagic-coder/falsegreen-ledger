# FalseGreen Issues Log

Running the `falsegreen-ledger` project through the FalseGreen MCP workflow
end-to-end is a real-world exercise of the system. This log records every
friction point hit — symptom, root cause, resolution, and the gap it
exposes — as they occur. Newest entries at the bottom of each section.

Session: task `task_6b78e45e6332764d9a32b2293defaf1a`, Job
`4a69d00c-cc83-48e8-9267-510996677031` (accepted, attempt 1), 2026-10-19.

## Issues

### #1 — `security.policy_digest` mechanics are undocumented

- **Where**: `falsegreen_save_plan_draft` → `falsegreen_validate_plan`.
- **Symptom**: a plan draft with a `security` block was rejected with
  `INVALID_PLAN` and no field-level detail. `falsegreen_docs` has no topic
  covering the security block or its digest (`falsegreen_docs('security')`
  → `UNKNOWN_DOCS_TOPIC`; the available topics do not cover it). The digest
  algorithm was only recoverable from the `falsegreen-protocol` source on
  this machine (`crates/falsegreen-protocol/src/security.rs`):
  SHA-256 over the canonical JSON (sorted keys, compact) of a fixed
  10-field policy projection, with `freshness_hours: null` included even
  when unset. Two natural guesses failed first (a placeholder digest, and
  the server's parsed struct with defaults expanded and an id field
  omitted) — about an hour of local archaeology to reach the passing value.
- **Resolution**: computed the digest from the protocol crate's canonical
  form; the full 10-item plan then validated with zero errors and zero
  warnings and froze cleanly (`canonical_sha256` returned).
- **Gap**: the digest computation must be documented in `falsegreen_docs`
  (field set, ordering, normalization), or the shim should expose a
  "compute this digest" helper. The binary embeds a `want vs got` digest
  message (visible via `strings`), and the Job gate uses it — but the
  plan-validation surface does not.

### #2 — `INVALID_PLAN` error guidance is a dead end

- **Where**: `falsegreen_save_plan_draft`.
- **Symptom**: the rejection detail says
  `the draft fails the plan invariants (falsegreen_validate_plan names
  them)` — but because the save failed, no draft exists, and
  `falsegreen_validate_plan` answers `NO_PLAN: no draft and no frozen plan
  yet`. The error points at a tool that cannot be called. The only way to
  isolate the failing invariant (the security block) was to save a
  reduced draft (without the block, which saved) and diff.
- **Resolution**: manual bisection — save the plan minus the suspected
  block, then re-add blocks one at a time.
- **Gap**: `INVALID_PLAN` should carry the invariant failures inline (the
  shim already parses the draft — the pre-check runs locally). Alternatively
  save the draft as-is in a `dirty` state and let `validate_plan` name the
  problems.

### #3 — `NO_PLAN_SHAPE` names the field but not the instance

- **Where**: `falsegreen_save_plan_draft`.
- **Symptom**: `missing field 'id'` — accurate, but with five
  `overall_acceptance` entries the error does not say which one (it was
  the 5th). One extra round trip.
- **Resolution**: inspected the payload; added the missing id.
- **Gap**: serde-style `line X` / index / sibling-id in the message would
  make this a non-event. (Minor — the error class is otherwise good:
  specific, machine-readable.)

### #4 — D0 secret gate false positive on non-hex high-entropy tokens
(T1 in PLAN.md §10)

- **Where**: `falsegreen_create_job` (1st attempt), 2026-10-19.
- **Symptom**: publish refused by the D0 `secret_token` high-entropy rule.
  The flagged "token" was the slash-joined CLI subcommand list in PLAN.md —
  `init/append/verify/tail/export/import/compact/keygen/policy` — one
  64-char alphanumeric string. No secret was present.
- **Resolution**: split the list into prose (commit 5e69e29);
  `falsegreen security scan` then clean; `create_job` succeeded.
- **Root cause**: the 0.7.0 fix (348d3a1) allowlisted pure-hex digests
  ≥40 chars and raised the rule's minimum length to 40, but long **non-hex**
  alphanumeric compound tokens still trip it. Second occurrence of this FP
  class (first: SHA-256 checksums in Cargo.lock — the case 348d3a1 fixed).
- **Gap**: exclude tokens built from a small identifier alphabet joined by
  `/` `-` `.` (e.g. dictionary check on the segments), or raise the entropy
  floor above ~4.0 bits/char for non-hex strings.

### #5 — MCP `falsegreen_verify_report` impractical for large reports
(T2 in PLAN.md §10)

- **Where**: report-verification step, 2026-10-19.
- **Symptom**: the tool's only input is the report JSON **as a string in
  the tool call** — no file path or artifact reference. With schema v5 and
  a full Security/Standards section the report is ~84KB. In an agent
  session that size cannot be passed reliably: `read` truncates lines to
  768 chars, bash cannot write to `xd://` MCP paths (read-only filesystem),
  and transcribing ~84KB through model context risks corruption.
- **Resolution**: the CLI `falsegreen verify-report docs/REPORT-4a69d00c.json`
  — the same `verify_report_json` implementation the MCP tool wraps,
  reading the file directly. Result: VERIFIED (verdict accepted, key
  `fg-report-9fc1a2c5-…-20261018-1`, digest `82c92878…`, schema v5).
- **Gap**: accept a file path / artifact reference in addition to the
  inline string.

### #6 — `get_report` artifact is multi-line JSON
(T3 in PLAN.md §10)

- **Where**: polling `falsegreen_get_report` to the terminal verdict, 2026-10-19.
- **Symptom**: the terminal-verdict output artifact is a JSON document where
  the first line is the payload and trailing lines are display wrappers
  (84,031 bytes total, 105 trailing). `json.load` on the whole file fails
  with `JSONDecodeError: Extra data`.
- **Resolution**: `json.JSONDecoder().raw_decode` — take the first object.
- **Gap**: cosmetic — one wasted parse round; no change required.

## Working well (for contrast)

- The `next:` line after every success is the exact next step — no guessing
  the workflow.
- `falsegreen_validate_plan` cleanly separates `errors` (blocking) from
  `warnings` (non-blocking); a clean result is `{"errors":[],"valid":true,"warnings":[]}`.
- `falsegreen_freeze_plan` is automatic (no approval round trip) and
  returns the `canonical_sha256` that enters the Job boundary.
- `falsegreen_docs` is versioned with the shim — the docs and behavior
  cannot drift.
- `NO_PLAN_SHAPE` / `NO_PLAN` / `UNKNOWN_DOCS_TOPIC` refusals are specific
  and machine-readable.
- Job execution was fast and clean: attempt 1, 28.5s, all required criteria
  green against the frozen source (build + 51 tests + clippy `-D` + fmt).
- CLI `falsegreen verify-report` reads the signed report file directly and
  checks the embedded Ed25519 signature with no network / operator key —
  the practical local surface (see #5).

## Job-run observations (pending items from the planning phase, filled in)

- [x] `falsegreen_create_job`: boundary freeze / entitlement behavior —
  publish ran the D0 gate (see #4), then froze source/contract/criteria
  (source_sha256 `3756efdf…`) and started verification; entitlement spent
  at the terminal verdict.
- [x] `falsegreen_get_report` polling while `verifying` — polled after the
  run; terminal report returned with `queue: null`. Queue-wait estimate
  accuracy was not observed (the Job was not queued long enough to see one).
- [x] Terminal verdict + signed report + local verification — **accepted**,
  attempt 1; signed report saved to `docs/REPORT-4a69d00c.json` and
  verified locally via the CLI (see #5).
- [x] Repair path — NOT exercised: the verdict was `accepted` on attempt 1,
  so `falsegreen_repair_job` / attempt budget / re-publish behavior remain
  untested by this run.

## Upstream bug summary (falsegreen 0.7.0)

1. **`security.policy_digest`** (#1): document the digest computation (field
   set, ordering, normalization) in `falsegreen_docs`, or expose a
   "compute this digest" helper in the shim.
2. **`INVALID_PLAN`** (#2): carry the invariant failures inline — the pre-check
   already runs locally in the shim.
3. **D0 `secret_token`** (#4): false-positives on long non-hex alphanumeric
   compound tokens; the 348d3a1 hex-digest allowlist does not cover it.
4. **MCP `falsegreen_verify_report`** (#5): accept a file path / artifact
   reference for ≥64KB reports.
