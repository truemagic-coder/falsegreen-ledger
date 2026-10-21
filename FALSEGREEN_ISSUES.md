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

## 0.9.0 smoke test — 2026-10-20

Session: task `task_9aca01d5501071ccf6703428f16204bc`, Job
`d4d5ab1f-3b61-42ad-be7c-563eac82f8fd` (accepted, attempt 1, 29.1s), shim
0.9.0, report schema v6. Same workspace, re-verified against the 0.9.0
server + rebuilt job image. New surface exercised: contract
`[[invariant]]` sections (DP-A), `falsegreen_compute_policy_digest`,
schema-v6 report with embedded SBOM/VEX/OSCAL exports, PDF rendering.

### #7 — contract `invariants` are silently dropped by the server (DP-A)

- **Where**: `falsegreen_create_job` → report (the frozen contract object).
- **Symptom**: `falsegreen.toml` carried three `[[invariant]]` entries
  (committed as 74813b8 before `create_job`; the report's
  `contract_sha256 fccb4ab9…` matches that file BYTE-FOR-BYTE — the
  integrity binding includes them). The report's `contract.invariants` is
  `[]` — empty — and the three names/descriptions/plan_refs appear NOWHERE
  in the 162KB signed report (grep: 0 hits each). The server's contract
  model has the field (it serializes `invariants: []`), so the section is
  parsed but discarded.
- **Why it matters**: `falsegreen_docs('contract')` documents the section
  in full ("the CLAIMS this change is about — what the report maps to the
  plan and shows on the cover"), and the 0.9.0 `next:` hint after
  `create_task` explicitly tells the user to declare `[[invariant]]`
  sections before drafting. The data is silently lost from the signed
  report with zero errors and zero warnings (`validate_plan` was clean).
  Silent loss of a documented field is the worst failure mode: the user
  writes claims into the contract and the report proves nothing about them.
- **Gap**: fix the server's contract parse/canonicalization to carry
  `invariants` through to the frozen contract + the report cover mapping;
  or, until then, remove the `[[invariant]]` docs + the `next:` hint
  (an advertised no-op is worse than an advertised absence).
- **Not testable this run**: the plan↔invariant cover mapping (DP-A's
  visible output) — nothing to map, the invariants never arrived.

### #8 — D0 secret gate: high-entropy FP on base64 Ed25519 key + signature
in a FalseGreen-signed report

- **Where**: `falsegreen_create_job` (1st attempt), 2026-10-20.
- **Symptom**: publish refused `SECRET_REFUSED — 2 secret(s)`:
  `docs/REPORT-4a69d00c.json:1644 high-entropy ie4e…` and `:1810
  high-entropy CTAq…`. The flagged tokens are the 0.7.0 report's
  `public_key` (base64 Ed25519, 44 chars) and `signature_ed25519` (base64
  Ed25519, 88 chars) — PUBLIC cryptographic artifacts the report is
  designed to carry (the whole `verify-report` workflow embeds the key).
  The hex `signature` field passed (the 0.7.0 hex allowlist works);
  base64 public key material is a NEW false-positive class.
- **Workflow trap**: the 0.7.0 log's own guidance was "save the signed
  report to docs/ and commit it" — doing so (pretty-printed at 7c7f67c)
  then blocks EVERY future publish in the same workspace until the report
  is excluded. The gate caught exactly what FalseGreen itself told the
  user to keep.
- **Resolution**: excluded `docs/REPORT-4a69d00c.json` via
  `.falsegreenignore` (verification artifact, not source under
  verification); `falsegreen security scan` clean (21 files); retry
  succeeded. Exclusion widened to `docs/REPORT-*.json` for future runs.
- **Gap**: allowlist base64 Ed25519 public keys (44 chars) and signatures
  (88 chars) as public-by-design material, or exempt
  `falsegreen verify-report`-compatible report files; at minimum the
  high-entropy rule should not fire on the output of its own system.

#9 — the D0 refusal's remediation does not exist in the 0.9.0 CLI

- **Where**: the `SECRET_REFUSED` error text, `falsegreen_create_job`.
- **Symptom**: the error directs: "add a scoped local allowlist entry
  (never uploaded): `falsegreen security allow <path> --reason "…"`".
  `falsegreen security allow` → `error: unrecognized subcommand 'allow'`.
  The 0.9.0 CLI's `security` group is `scan | help` only. Same failure
  class as 0.7.0 #2: an error pointing at a surface that cannot be
  called.
- **Also**: the refusal code `SECRET_REFUSED` (and the `PUBLISH_FAILED`
  wrapper) is ABSENT from `falsegreen_docs('errors')`, which bills itself
  as "every refusal code with cause + next action"; and the gate message
  names ruleset `secret-rules-v1 @ 2026-10-19` while the CLI scan output
  reports `secret-engine-v1` — two names for the secret ruleset in one
  binary (detection behavior is in sync: the local scan reproduced the
  exact same 2 rows, state `refused`).
- **Gap**: ship `security allow` (or remove the instruction); add
  `SECRET_REFUSED`/`PUBLISH_FAILED` to the errors docs; align the
  ruleset names.

### Observations (not counted as issues)

- **Unknown `plan_refs` are carried, never validated — as documented.**
  The probe invariant (`plan_refs = ["no-such-work-item-probe"]`) passed
  `validate_plan` with 0 errors AND 0 warnings. Behavior matches
  `falsegreen_docs('contract')` ("CARRIED DATA — never validated") — but
  the 0.9.0 planning notes had DP-A as "unknown ref BLOCKS (error);
  invariant with no refs = coherence WARNING". Flagging the
  docs/behavior-vs-planning-note mismatch for confirmation of the final
  intended semantics.
- **`falsegreen_docs('security')` vs the DP-E spec**: the docs say "NO
  POLICY = the platform-default policy (no required classes…)" while the
  0.9.0 spec makes all five evidence classes mandatory
  (`SecurityPolicy::platform_default()` requires `SecurityClass::ALL`).
  This run cannot disambiguate — the plan's policy explicitly required
  all five. Either the docs are stale or DP-E landed differently than
  specified; worth a look.
- **`falsegreen_docs('verdicts')`** does not mention the v6 report
  changes (the embedded SBOM/VEX/OSCAL exports, the per-export digests);
  'security' covers the section prose but not the export refs. Minor.
- **DP-C display surface**: there is NO HTML page —
  `https://falsegreen.com/report/<job_id>` serves the SIGNED JSON itself
  (content-type application/json, byte-identical size), and `/pdf` serves
  the 8-page PDF. So "PDF and HTML render identical sections" (the DP-C
  requirement) can only be read as "PDF renders a subset of the JSON" —
  which it does, correctly (see below). Consistent with the 0.8.0
  baseline (report_url = JSON). Confirming that HTML was dropped by
  design, not missing.
- **One unexplained stderr line** during a `falsegreen security scan`
  (`Error: failed to parse: value expected`) while swapping
  `.falsegreenignore` mid-flow; NOT reproducible in 3+ clean runs after.
  Root cause unknown — logged for completeness.

### Working well (0.9.0)

- **`falsegreen_compute_policy_digest` resolves 0.7.0 #1**: the digest is
  now computable from the surface, and it returned
  `34fe1472c058e78d…` — IDENTICAL to the digest the 0.7.0 server froze for
  the same policy content. Canonical form is stable across 0.7.0→0.9.0.
- **`falsegreen_verify_report` now takes `file_path`** (0.8.0) — 0.7.0 #5
  is closed: 162KB report verified locally, no inline-string gymnastics.
- **`get_report` structuredContent is clean** (0.7.0 #6 is closed): the
  `report` is a JSON OBJECT (not a string), with `report_url`,
  `report_pdf_url`, and `verdict` alongside it.
- **Schema v6 report, 162KB** (vs 84KB v5): four embedded exports, each
  with its own `ref` + content `digest` — `spdx-3.0` (54.8KB),
  `cyclonedx-1.7` (26.3KB), `oscal-assessment-results-1.1.2` (5.1KB),
  `cyclonedx-1.7-vex` (631B). The SBOM job-image fix is confirmed in the
  artifact: 72 components, ALL `pkg:cargo/…` purls (0 `pkg:pypi`), tool
  `cargo` (not the old hardcoded `pip`), licenses populated (e.g.
  "MIT OR Apache-2.0"), SHA-256 hashes.
- **Security section, DP-E-shaped**: all five classes `required: true`
  and `pass` (osv-scanner 2.7.0, semgrep 1.181.0, gitleaks 8.30.1, syft
  1.54.1 ×2), each witness row carries binary + config digests; the OSV
  snapshot is identified in the report (`osv-dev-20261020-0d2f74a5`,
  `observed_at` 2026-10-20T13:21:06Z, `freshness_hours: 24`).
- **Standards section**: all five required profiles `satisfied`
  (soc-2-tsc, iso-27001, cis-controls, nist-csf-2.0, cra), each with
  per-requirement evidence_refs + rationale + the "mapping, not
  certification" disclaimer.
- **PDF (8 pages) honors the DP-C/DP-D display rules**: VEX section is
  exactly `No vulnerability findings.` + "The full SBOM, VEX and OSCAL
  are in the signed JSON report." + the report URL; NO SBOM section, NO
  OSCAL section (the EXPORTS page is a ref+digest manifest, not content);
  per-requirement `evidence_sha256` absent from the PDF (present once in
  the signed JSON, as intended).
- **Money model**: entitlement `consumed` exactly once at the terminal
  verdict, `refund_state: null` (accepted); the `next:` hint after
  `verify_report` names both public URLs.
- **Integrity binding**: `contract_sha256` = sha256 of the raw
  `falsegreen.toml` bytes (invariants included); worker re-derivation
  passed (verdict accepted, no integrity gate trip).
- Job execution: attempt 1, 29.1s wall — build 16.4s, tests 7.4s,
  clippy 4.2s + fmt 0.1s (3/3 criteria, lint's non-required status
  respected).

### Upstream bug summary (falsegreen 0.9.0)

1. **Contract `invariants` dropped** (#7): the server's contract model
   serializes `invariants: []` for a file whose raw bytes (bound by
   `contract_sha256`) carry three `[[invariant]]` entries — silent data
   loss of a documented section that the `next:` hint actively
   instructs. Highest-priority 0.9.0 finding.
2. **D0 high-entropy FP on base64 Ed25519** (#8): public key + signature
   in FalseGreen's own signed reports trip the new
   `secret-rules-v1 @ 2026-10-19` ruleset; the "save your report"
   workflow now blocks future publishes.
3. **Dead-end D0 remediation** (#9): `falsegreen security allow` does not
   exist in the 0.9.0 CLI; `SECRET_REFUSED`/`PUBLISH_FAILED` are missing
   from `falsegreen_docs('errors')`; ruleset naming is inconsistent
   between gate and scan.
4. **`compute_policy_digest` input contract** (#7-pre, minor): the
   documented "without a digest" input is rejected
   (`INVALID_POLICY: missing field 'digest'`); a placeholder digest is
   required — fix the deserializer or the docs.
