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
- **DP-C display surface — CORRECTION to the note above**: the HTML
  page EXISTS at `https://falsegreen.com/report/<job_id>/html` (the
  bare URL serves the signed JSON; `/pdf` the PDF — the 0.8.0 report_url
  behavior is unchanged). Divergence found by direct comparison of the
  VEX section: the PDF renders `No vulnerability findings.` + "The full
  SBOM, VEX and OSCAL are in the signed JSON report." + `JSON report:
  https://falsegreen.com/report/<job_id>`; the HTML renders the first two
  lines but **omits the JSON-report URL** (0 occurrences of
  `falsegreen.com/report/<job_id>` anywhere in the HTML page). DP-C
  required both to carry the `<site_base>/report/<job_id>` link — the
  HTML renderer does not. See #13.
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

## Security-class break campaign — 2026-10-20 (continued)

Goal: try to break each of the five DP-E-mandatory evidence classes
against the deployed 0.9.0 and observe the actual behavior. Method:
reproduce each witness with the EXACT binary from the deployed job image
(`falsegreen-job:rust1`: osv-scanner 2.7.0, semgrep 1.181.0, gitleaks
8.30.1, syft 1.54.1) + the prod OSV store, then run live Jobs.

**Headline: of the five mandatory classes, only `static_analysis` is
actually inspecting anything.** The green run's witness raw-output
digests (report `d4d5ab1f`) prove it — `e3b0c442…` is sha256 of the EMPTY
string:

| class | tool | raw_output_digest | evidence |
|---|---|---|---|
| dependency_vulnerability | osv-scanner | `54345d51…` | real output, but the parser extracts 0 findings from it (#10) |
| static_analysis | semgrep | `80c185ac…` | real, and the parser matches the format |
| secret | gitleaks | `e3b0c442…` | scanner scanned 0 bytes (#12) |
| supply_chain | syft | `e3b0c442…` | scanner crashed on its own argv (#11) |
| license | syft | `e3b0c442…` | same crashed scanner (#11) |

All three empty-output classes evaluate to `pass` — a vacuous pass,
indistinguishable in the report from a real pass except via the raw
digest.

### #10 — SCA class vacuous: `parse_osv` reads the legacy OSV batch-API
format; the witness's own osv-scanner 1.x emits `results[].packages[]`

- **Where**: `falsegreen-verifier/src/witness.rs` — `parse_osv`
  (expects a top-level `"vulnerabilities"` map: ID → per-package rows,
  the OSV *batch API* shape) vs the argv the witness actually runs
  (`osv-scanner scan --recursive --format json --offline
  --offline-vulnerabilities <dir>`, osv-scanner 2.7.0 output =
  `{"results":[{"source":…,"packages":[{…,"groups":[…],
  "vulnerabilities":[…]}]}]}`).
- **Symptom**: reproduced with the image binary + prod OSV store:
  (a) the GREEN workspace's exact repro output hashes to
  `54345d5194d2…` — byte-identical to the green run's
  `raw_output_digest` (its `results` is `[]` — offline mode only emits
  packages matched in the local DB); (b) a workspace with
  `time = "=0.3.9"` (RUSTSEC-2026-0009 / CVE-2026-25727, CVSS 6.8) emits
  the `results[].packages[]` shape → `parse_osv` finds no top-level
  `vulnerabilities` key → returns 0 findings. `normalize_osv_severity`'s
  fields (`row.severity`, `row.database_specific.severity`) do not
  exist in that shape either (severity lives in
  `packages[].groups[].max_severity`) — so even with the shape fixed,
  every finding would fall through to the `high` default.
- **Why it matters**: a signed `accepted` verdict is reachable with a
  KNOWN vulnerable dependency. The SCA class can never fail on the
  deployed 0.9.0; DP-E's `dependency_vulnerability` requirement is
  unenforced end-to-end.
- **Gap**: parse the osv-scanner 1.x shape (map
  `packages[].groups[].max_severity` → the canonical severity set; note
  6.8 buckets to medium and would NOT gate under
  `fail_on_severities = [critical, high]` — a separate policy question:
  the frozen platform policy's fail-on bar may be higher than most
  advisories, making the class pass-by-default in practice).
- **Live proof pending**: run 1 of the campaign (workspace
  `/tmp/scabreak`, commit `ffd02ed`) — expect SCA `pass` + overall
  `accepted`.

### #11 — supply_chain + license vacuous: the syft witness argv crashes
the scanner

- **Where**: the witness argv `syft dir --output json dir:/<src>`
  (syft 1.54.1, from the job image).
- **Symptom**: `syft dir --output json dir:/src` exits 1 — "accepts at
  most 1 arg(s), received 2" — stdout empty; `parse_syft_*("")` → 0
  findings → raw digest `e3b0c442…` (both witnesses, green run). The
  correct argv is `syft dir:/src --output json` (or positional first).
- **Why it matters**: two of the five mandatory classes (supply_chain,
  license) pass on a CRASHED scanner, on every run, in every workspace.
  Even with the argv fixed, the syft lockfile cataloger emits 0 license
  facts for Rust, so `license` would still never fail for rust
  workspaces (the class is unbreakable for this ecosystem either way —
  the report should at least say that honestly).
- **Gap**: fix the argv (flags after the positional `dir:<path>`);
  re-derive the SBOM component findings from the working catalog; decide
  the license class's semantics for lockfile-only ecosystems.

### #12 — secret class vacuous: gitleaks runs without `--no-git` against
a non-git published tree and scans 0 bytes

- **Where**: the witness argv `gitleaks detect --source <dir>
  --report-format json --no-banner --exit-code 0` (gitleaks 8.30.1) +
  the publish selection (`falsegreen/crates/falsegreen/src/shim/workspace.rs`):
  the tar carries EXACTLY the selected files and `.git` is
  root-ignored by design → the job's source dir is NOT a git repository.
- **Symptom**: reproduced in the image: on a non-git dir gitleaks logs
  `fatal: not a git repository`, `0 commits scanned`, `scanned ~0
  bytes`, `no leaks found` — while `AKIA…`/`ghp_…`/PEM files sit in the
  tree. With `--no-git` (or a real git repo) the same files are scanned
  (212 bytes read in the probe). Green run's secret witness raw digest =
  `e3b0c442…` (empty output) — consistent with 0 bytes scanned.
- **Note**: gitleaks' built-in rules are otherwise fine — the probe
  misses were its own allowlist (`.+EXAMPLE$` for the AWS doc key) and
  charset (`[A-Z2-7]{16}`), not a rule gap.
- **Why it matters**: a secret in the published source cannot fail the
  `secret` class at verify time. The D0 gate (client-side, at publish)
  remains the ONLY secret control — and it is advisory-grade (pattern +
  entropy heuristics; a below-threshold key like `FALLBACK_KEY =
  "xK9m…2c" (masked — since 0.10.0 the gitleaks witness catches this unmasked form in-job)` passes it, see run 2). DP-E's `secret`
  requirement is unenforced end-to-end.
- **Gap**: add `--no-git` to the witness argv (scan the tree as files);
  the D4 no-raw-secret retention already holds in `parse_gitleaks`.
- **Live proof pending**: run 2 (workspace `/tmp/smoke-sast`, commit
  `c3a8687`) carries a D0-clean secret-like value + a semgrep-gated C
  `gets()`; expect secret `pass` (vacuous) + static_analysis `fail` +
  overall `failed`.

### #13 — HTML report page omits the signed-JSON report URL (DP-C)

- **Where**: `GET https://falsegreen.com/report/<job_id>/html` (the HTML
  renderer) vs `/pdf`.
- **Symptom**: the PDF's VEX section ends with `JSON report:
  https://falsegreen.com/report/<job_id>`; the HTML VEX section has the
  same two preceding lines but no URL (0 occurrences of the report path
  in the whole HTML page). DP-C: both renderings carry
  "full SBOM/VEX/OSCAL in the signed JSON report" + the
  `<site_base>/report/<job_id>` link.
- **Gap**: emit the URL line in the HTML VEX section (one-line fix,
  server-side renderer); add a render-parity check (PDF vs HTML section
  text) to the canaries.

### Campaign runs

| run | workspace / commit | payload | expectation |
|---|---|---|---|
| 1 | `/tmp/scabreak` `ffd02ed` | `time = "=0.3.9"` (RUSTSEC-2026-0009, CVSS 6.8) | SCA `pass` (parser drops the finding, #10) → `accepted` |
| 2 | `/tmp/smoke-sast` `c3a8687` | C `gets()` (semgrep error→high) + D0-clean `FALLBACK_KEY` | static_analysis `fail` → `failed`; secret `pass` vacuous (#12) |
| 3 | `/tmp/smoke-bidi` `d6f77a7` | bidi control char (semgrep warning→medium) | a MEDIUM finding recorded, class `pass` (below the fail-on bar) → `accepted` |

Semgrep note (pre-tested with 1.181.0 `--config auto`, the witness
config): the OSS auto set has NO error-level rule for Rust itself (max
warning→medium) — the only reachable static_analysis failure for a rust
workspace is a multilang rule (`generic.secrets.*`, `c.lang.*`, etc.);
D0 blocks the `generic.secrets.*` payloads (it pattern-matches AWS/JWT
itself), so the C-file `gets()` is the clean SAST break.

### Campaign results (live, deployed 0.9.0) — 2026-10-20 ~18:15–18:45

| run | job | verdict | observed |
|---|---|---|---|
| 1 | `7b1af65a` | `accepted` | time 0.3.9 compiled in the sandbox (build tail `Compiling time v0.3.9`); SCA `pass`, `findings: []` — but the osv raw digest `e52f7880…` ≠ the empty-tree one (`54345d51…`, which run 2 reproduced exactly with its clean lockfile) → the scanner DID output the advisory, `parse_osv` dropped it. **#10 confirmed live**: signed `accepted` on a known-vulnerable dependency. Report `docs/REPORT-7b1af65a.json`, Ed25519 verified. |
| 2 | `521b9b31` | `accepted` | `gets()` recorded: rule `c.lang.security.insecure-use-gets-fn`, severity **`medium`** (NOT high — see #14), state open, `open_findings: 1` → below `fail_on=[critical,high]` → class `pass`, overall `accepted`. **A recorded finding on an accepted report — by design** (finding-vs-verdict separation works). secret raw `e3b0c442…` with `FALLBACK_KEY` in-tree (#12 live), supply_chain/license raw `e3b0c442…` (#11 live). Report `docs/REPORT-521b9b31.json`, Ed25519 verified. |
| 3 | `e7f44f0f` | `failed` → **repaired** → `accepted` | Raw U+202E in a string literal → rustc `text_direction_codepoint_in_literal` is **deny-by-default** → `cargo build` fails (exit 101, locally reproduced) → attempt 1 `failed` in 17 s, Job parked at `repairing`. That is CORRECT verdict semantics (build is a required criterion; the SAST probe never got to run — bidi chars are a compile error in Rust, a Trojan-Source defense, not a semgrep-only signal). Fix = `"\u{202e}"` escape (identical semantics, compiles, all 4 contract commands green locally) → `repair_job` → attempt 2 `accepted` (55 s, source `fac47938…`) — **first live exercise of the repair loop** (free, same Job; report carries BOTH attempts `[1 Failed c6d9b2e8, 2 Accepted fac47938]`). Attempt-2 semgrep raw `80c185ac…` (non-empty wrapper, 0 findings — no bidi char once escaped, as expected). Report `docs/REPORT-e7f44f0f.json`, Ed25519 verified; entitlement `consumed` (one price across the two attempts, per the money model). |

Correction of the pre-campaign semgrep note above: the assumption
`--config auto` errors gate was WRONG — see #14; the `gets()` rule has
registry severity ERROR but its SARIF result carries no `level`, and the
witness defaults missing levels to `warning`→`medium`. Run 2's
expectation (`static_analysis fail → failed`) was therefore unfounded;
the deployed system recorded the finding and accepted.

### #14 — `parse_sarif` ignores SARIF's rule-level severity default → semgrep findings can NEVER gate the verdict

- **Where**: `falsegreen-verifier/src/witness.rs` — `parse_sarif`
  (`let level = r.get("level").and_when… unwrap_or("warning")` at ~502 +
  `normalize_sarif_level` error→high/warning→medium/note→low).
- **Ground truth** (semgrep 1.181.0 = the witness's pinned version,
  `--config auto --sarif`, same as the witness argv): the SARIF
  **results NEVER carry `level`** — verified against ERROR-severity
  registry rules (`python…eval-detected`, `subprocess-shell-true`,
  `pickle.avoid-pickle`), the whole `generic.secrets.*` family
  (JWT/stripe/slack/github/gitlab/npm/pypi/sendgrid/google/heroku/
  digitalocean/mailgun/square/shopify/azure), and the C `gets()` rule
  (deployed run 2 recorded it as `medium`). Severity instead lives in
  `runs[0].tool.driver.rules[].defaultConfiguration.level` — e.g.
  `trailofbits.python.pickles-in-numpy` = `error`; most community rules
  = `warning`. Per SARIF 2.1.0, an absent `result.level` MEANS the rule
  descriptor's default applies.
- **Consequence**: the witness records EVERY semgrep finding as
  `medium` (or never at all) → `fail_on=[critical,high]` can never
  match → **`static_analysis` cannot fail the verdict on the deployed
  0.9.0**, for any workspace in any language. The class is not vacuous
  (it really scans, and findings land in the report), but its failure
  path is unreachable — 4 of the 5 DP-E classes cannot block.
- **Fix**: `parse_sarif` should build `ruleId →
  defaultConfiguration.level` from `tool.driver.rules` and use it when
  `result.level` is absent (fallback `warning` remains SARIF's default).
  No new dependency; ~10 lines + one test fixture with
  `defaultConfiguration: {"level":"error"}`.
- **Bonus observation**: `unknown_severity = "insufficient"` never fires
  via SAST because the fallback always yields a known severity.

### Campaign money + lifecycle notes

- 3 Jobs fired from one frozen plan (identical `plan_sha256
  de42ce46…`); queue ran them sequentially (~40 s each, 1 slot).
- The repair loop worked as documented: `repairing` → fix workspace →
  `repair_job` → attempt 2, free, contract+plan stay frozen
  (`contract_sha256 fccb4ab9…` unchanged across attempts).
- `/tmp` got cleaned mid-campaign (workspaces under /tmp vanished —
  host tmpfiles policy); rebuilt run 3 at
  `/mnt/308ef833-…/smoke-bidi`. Keep campaign workspaces on the data
  drive.
- `contract.invariants: []` in all three reports — re-confirmed #7 on
  every run.
- The HTML-page gap (#13) re-observed: run 3's `report_url` serves the
  signed JSON (PDF at `/pdf`) — render parity still only via PDF.
- `normalized_evidence_digest 4f53cda1…` = sha256(`"[]"`) — every
  witness normalizes to the empty findings array in all three runs;
  a raw digest difference (e.g. semgrep `80c185ac…`) with findings `[]`
  is a non-empty WRAPPER, not dropped findings — except for SCA, where
  #10's parse drop is independently proven.

---

## 0.10.0 re-smoke campaign — 2026-10-21

Setup: shim 0.10.0; contract extended to **ten `[[invariant]]` sections**
capturing the ledger's whole implemented behavior (DESIGN.md §§1-10 +
README exit-code table + threat-model scope), each `plan_refs`-linked to
the plan work items that pin it; frozen policy digest `14a6293f…`
(computed WITHOUT a placeholder digest — the 0.10.0 serde-default fix
works); `freshness_hours: 24` now exercised; plan `fc5315fc…` reused
across all tasks (validate: 0 errors, 0 warnings — the plan↔contract
coherence path is clean now).

### #15 — shim `security scan` SCA row misses a CRITICAL advisory it checked

- **Where**: `falsegreen security scan` (client SCA, `sca.source:
  osv.dev`), workspace `smoke-sca`.
- **Symptom**: `"smallvec"@"1.6.0"` appears in `checked` but
  `vulnerable: []`. `api.osv.dev/v1/query` for the same
  package+version returns GHSA-43w2-9j62-hq99 / RUSTSEC-2021-0003,
  **CRITICAL, CVSS 9.8** (curl, 2026-10-21). The job-image witness (0.10.0
  `parse_osv` 2.x shape) DID flag it — the coordinator downgrade log for
  `f3ce10a7` proves the class was unsatisfied. So client and server
  disagree on the same package at the same moment.
- **Why it matters**: the client row is the pre-publish early-warning
  surface; a vacuous `vulnerable: []` there is the same class of bug as
  #10, on the other side of the wire.
- **Gap**: check the shim's OSV query path (batch API? cached DB?
  response-shape parse — likely the same 2.x `results[]` vs
- **ROOT CAUSE (source)**: `crates/falsegreen/src/shim/security.rs:411`
  parses `v["vulnerabilities"]` out of the **`/v1/querybatch`** response —
  but querybatch returns `{"results": [{"matches": [{"osv_id", …}]}]}`
  (position-aligned with the queries); `vulnerabilities[]` is the
  single-package `/v1/query` field. The lookup silently misses →
  `vulnerable: []` for every input — fail-open (no IE branch on the
  shape mismatch; line 343 even prints bare `source: "osv.dev"` when
  the list is empty). Same bug family as #10, shim-side; predates
  0.10.0, invisible until a payload was actually vulnerable.
- **Gap**: parse `results[].matches[].osv_id` positionally (or use
  per-package `/v1/query`); treat an unexpected shape as Insufficient
  Evidence, never an empty list.

### #16 — a PROVEN policy violation downgrades to `insufficient_evidence`, not `failed`

- **Where**: `falsegreen-server/src/coordinator/mod.rs:847-854` — the
  `passed wire` + `!section.satisfied` branch emits
  `negative_attempt_event(Insufficient)` unconditionally.
- **Ground truth** (live, `f3ce10a7` attempt 1, smallvec CRITICAL
  pinned): worker wire `verdict=passed` (all criteria green — the
  vulnerable dep compiles); server log `WARN "passed wire: the five
  mandatory security classes are not satisfied; downgraded to
  insufficient_evidence"` → `ATTEMPT_INSUFFICIENT`. Budget-exhaustion
  path (`domain/repair.rs:43-55`) lands the Job terminal
  `insufficient_evidence`.
- **Why it matters**: `docs('verdicts')` defines
  `insufficient_evidence` = "the evidence could NOT establish the full
  boundary". Here the evidence established the OPPOSITE of done — a
  critical advisory — which is precisely the `failed` shape ("which
  criterion/commands failed — this is your repair input"). The label
  also collapses two opposite postures (UNAVAILABLE vs demonstrated-
  violation) into one downgrade event; the WARN text says "not
  satisfied" without naming which class or why.
- **Fix**: in the passed-wire branch, distinguish
  any-class-`fail` (→ `AttemptFailed` / `RepairExhaustedFailed`) from
  any-class-`insufficient` (→ Insufficient); log the offending classes
  + severities in the WARN.

### #17 — HIGH: `repair_job` re-publishes the PINNED workspace; a `workspace` argument is silently ignored, and the repair closed a payload job `accepted` on a tree without the payload

- **Live incident** (`f3ce10a7`, run B): attempt 1 `insufficient` on
  source `bf9ae70b…` (smallvec pinned — build tail shows `Compiling
  smallvec v1.6.0`). I committed a marker to `smoke-sca` and called
  `repair_job` with `workspace=/mnt/…/smoke-sca`. Attempt 2 ran
  `source_sha256 cd5952a3…` — **the rust-demo tree** (the shim's pinned
  workspace, byte-identical to the earlier baseline run), NOT smoke-sca.
  The job closed **`accepted`** — the payload was never re-verified, and
  the paid-for determination answers for a different source than the
  one that failed.
- **Where**: the MCP `repair_job` surface takes only `job_id`
  (0.10.0 schema); the shim re-snapshots `falsegreen pin`'s workspace
  regardless of the job's task-bound workspace from `create_job`.
- **Why it matters**: the repair contract is "the next attempt runs
  exactly what you fixed" — pin-vs-task-workspace divergence makes that
  silently false. A user with several workspaces (exactly the campaign
  pattern) can pay for an `accepted` verdict that never saw the payload.
- **Gap**: (a) the tool should accept/remember the job's workspace (the
  task binds it server-side — the server knows; the shim ignores it);
  (b) at minimum, refuse or warn loudly when the pinned workspace's
  re-derived source differs from the job's create-time workspace; (c)
  the docs' "fix the code in the workspace" should say THE pinned
  workspace.
- **Process workaround used for the rest of this campaign**:
  `falsegreen pin <job-workspace>` before every repair.

### #18 — the signed report carries only the TERMINAL attempt's security section; gate-firing findings of earlier attempts are not in the audit artifact

- **Ground truth**: `f3ce10a7`'s signed report shows attempts
  `[1 Insufficient bf9ae70b, 2 Accepted cd5952a3]` but the Security
  section (findings, witnesses, class postures) is **only attempt 2's**
  — the clean tree: 0 dependency findings, `satisfied: true`. The
  CRITICAL smallvec gate-fire of attempt 1 exists ONLY in server logs.
- **Why it matters**: the signed report is THE audit artifact ("the per-
  attempt history (each attempt's own source identity)" is all it
  carries); a customer proving "we caught the advisory" from the
  artifact alone cannot — the fail-closed evidence evaporated. Combined
  with #16 the campaign's core claim ("critical findings now gate") is
  true in behavior but invisible in the signed record.
- **Gap**: persist the security section per attempt (at least for
  negative attempts) — or make the terminal report of an
  exhausted/blocked Job carry the FIRST negative attempt's section.

### Minor notes (0.10.0 process smoothness)

- `verification_ms: 0` on the first-attempt-accepted report (b663b119)
  vs `259073` on B — the field is only filled on multi-attempt/repaired
  jobs (cosmetic, but `0` reads like "instant").
- Draft-save is the one heavy payload repeated per break task (no
  "copy plan from task X" surface); fine at 4 tasks, note for
  campaign ergonomics.
- `repair_job` with NO source change is refused (`NO_SOURCE_CHANGE`) —
  correct; to drive the attempt budget on purpose the workspace must
  churn between repairs (markers).
- `supersede_job` on a terminal job works as documented (fresh id, same
  boundary; `f3ce10a7 → 520d2155`).
- Fixed and re-confirmed live (0.10.0): **#7** ten invariants echoed
  verbatim in every report; **#11** syft raw digests real
  (`d9d3b082…`/`28676e27…`), 74 supply-chain + 72 license fact rows,
  `dependency-manifest` v1 as the license witness; **#12** gitleaks raw
  `37517e5f…` (not the empty digest); **#13** the JSON-report URL line
  now present in BOTH HTML and PDF VEX sections; **#9/DP-10.4** the
  publish scan is gate-clean over the saved signed reports (ruleset v2,
  21 files); **#10** the advisory parses and gates (via the #16 path —
  signed-artifact visibility pending on the exhausted re-run
  `520d2155`).

### Run B2 close (`520d2155`, supersede of `f3ce10a7`) — exhausted budget, findings NOW visible in the signed artifact

- Full 8-attempt budget driven with pinned `smoke-sca` (every repair's
  `source_sha256` matches the marker-churned payload tree — the #17
  workaround holds end-to-end). Terminal: `insufficient_evidence`
  (RepairExhausted), entitlement consumed ONCE (verified
  `jobent_3052d586…` → consumed).
- **Signed-artifact visibility (#18 partially healed for this shape)**:
  the terminal report carries `security.findings` = 2 rows —
  `osv/RUSTSEC-2021-0003` + `osv/GHSA-43w2-9j62-hq99`, component
  `pkg:crates.io/smallvec@1.6.0` — and the `dependency_vulnerability`
  class posture is **`fail`** with per-finding
  reasons (`severity 'high' is frozen-fail`). `open_findings: 2`.
  Ed25519 VERIFIED locally (`docs/REPORT-520d2155.json`).
  #18's residual gap stands for MIXED histories (accepted-terminal
  jobs like `f3ce10a7` still hide the earlier negative attempt's section).
- **#16 confirmed decisively here**: class postures are
  dv=`fail` + all four others `pass` — ZERO insufficient classes — and
  the verdict is still `insufficient_evidence`, not `failed`. A policy
  violation proven by every witness cannot produce a `failed` verdict.
- **Severity-fidelity note**: GHSA-43w2-9j62-hq99 is CRITICAL
  (CVSS 9.8) upstream; the server snapshot
  (`osv-dev-20261021-457e10c8`) + witness record it as `high`. Gating
  is unaffected here (`high ∈ fail_on`), but a `fail_on=[critical]`
  policy would MISS a CVSS-9.8 advisory — check the snapshot's
  severity derivation (ecosystem `severity` field vs CVSS band).
  Also: one advisory = TWO findings rows (RUSTSEC + GHSA ids, same
  component) — not deduplicated; cosmetically inflates `open_findings`.
- **New #19 — the terminal report's `attempts[]` omits its own final
  attempt**: B2 ran 8 attempts (repair responses `attempt:1..8`), the
  report binds source `e8006c3f…` (= attempt 8's tree) and its witness
  rows carry `observed_at` 18:02:17 (attempt 8's run), but the signed
  `attempts[]` history lists only indices 1-7 (`de6b2e18…` last). The
  audit artifact does not enumerate the run whose evidence it carries.

### Campaign run ledger (0.10.0)

| run | job | payload | verdict path | signed artifact |
|---|---|---|---|---|
| A baseline | `b663b119` | clean tree | attempt 1 `accepted` | `docs/REPORT-b663b119.json` ✓ 5 real witnesses, 10 invariants |
| B SCA | `f3ce10a7` | smallvec 1.6.0 | 1 Insufficient → (pin race, #17) → 2 `accepted` on the WRONG source — closed by supersede | `docs/REPORT-f3ce10a7.json` ✓ (documents the #17 incident) |
| B2 SCA | `520d2155` | same, pinned | 8× Insufficient (dv `fail` every attempt) → exhausted `insufficient_evidence` | `docs/REPORT-520d2155.json` ✓ findings + class fail in the artifact |
| C SAST | `6123964d` | `np.load(allow_pickle=True)` | in flight | — |
| E invariant | `35adbe16` | signature exits 1; suite pinned then realigned | 1 `Failed` (tests) → 2 Insufficient (log self-poison) → 3 `Accepted` with the FALSE invariant echoed | `docs/REPORT-35adbe16.json` ✓ |
| D secret | `d17bafca` → superseded `ec3ef0d8` | low-entropy token → gitleaks-invisible (accepted, payload lesson) → `glpat-` probe | 8× Insufficient (secret `fail`, critical) → exhausted | `docs/REPORT-ec3ef0d8.json` ✓ secret class fail in artifact |

### Run C close (`6123964d`) — SAST class now GATES; #14 fixed live; #19 reproduced

- 8 attempts driven with pinned `smoke-sast`. Signed terminal
  `insufficient_evidence` (`docs/REPORT-6123964d.json`, Ed25519 VERIFIED,
  one entitlement `jobent_8281948a…` consumed).
- **`static_analysis` class posture `fail`**: finding
  `semgrep/trailofbits.python.pickles-in-numpy.pickles-in-numpy` recorded
  at severity **`high`** (rule `defaultConfiguration.level = error` →
  high, per the 0.10.0 `parse_sarif` fix) with class reason
  "severity `high` is frozen-fail". All four other classes `pass`.
  → 0.9.0's #14 (every finding `medium`, failure path unreachable) is
  GONE; the class blocks. (Verdict label still `insufficient_evidence`
  rather than `failed` — that's #16, unchanged.)
- **#19 reproduced**: report binds source `44620131…` (attempt 8's tree)
  but `attempts[]` again ends at index 7 (`95265b4b…`). Consistent across
  both exhausted Jobs.

### Run D (`d17bafca`) — secret class: gate works BOTH sides, but detection is ruleset-bounded (payload lesson + #20)

- Attempt 1 `accepted` with `FALLBACK_KEY = "xK9mPq3vRt8wLz2c"` in-tree:
  gitleaks witness scanned REAL bytes (1.07 MB — #12 fixed) but its
  default ruleset does not match a 16-char low-entropy token → secret
  class `pass`, Job `accepted`. NOT a code defect: end-to-end detection
  is bounded by the union of ruleset-v2 (gates) and gitleaks 8.30 rules
  (witness). A token below both is invisible everywhere. Worth a docs
  line ("what the secret class does NOT catch").
- Server-side gate re-confirmed HARD: planting a `ghp_…` PAT made
  `supersede_job` fail `PUBLISH_FAILED / UPLOAD_DIGEST_MISMATCH /
  SECRET_REFUSED` — ruleset-v2 `github-token` fired at upload, store
  entry NOT created, "the server gate has NO allowlist" (matches the
  CLI remedy text; client `security allow` provably cannot except a
  server-leg refusal). #9/DP-10.4 hold.
- **NEW #20 — gate/witness ruleset asymmetry**: differential probe —
  `glpat-Qv7t…` and `AIzaSyD…`: ruleset-v2 client scan = `clean`;
  job-image gitleaks 8.30 = `gitlab-pat` + `gcp-api-key` HIT. So a
  secret can sail through both publish gates (client + server) yet be
  caught by the Job witness — defensible (witness is independent and
  broader), but nothing documents the asymmetry, and the client
  `security scan` "secret: clean" row is a false all-clear for those
  shapes. Fix direction: document the two rule surfaces + surface the
  witness rule ids back to the client docs, or align v2 ⊇ gitleaks
  defaults for the major PAT shapes.
- `security allow` CLI now EXISTS (0.9.0 gap fixed): path + mandatory
  `--reason`, LOCAL ONLY, and the refusal it prevents is exactly the
  local gate. Verified end-to-end (allow → scan clean → publish OK →
  server gate independent).
- Run D2 (`ec3ef0d8`, supersede of `d17bafca`) carries the asymmetric
  glpat payload: attempt 1 verifying.

### Run D2 close (`ec3ef0d8`) — the secret class NOW GATES live; #16 + #19 third reproduction

- 8 attempts, pinned `smoke-secret`. Signed terminal
  `insufficient_evidence` (`docs/REPORT-ec3ef0d8.json`, Ed25519 VERIFIED,
  consumed once).
- **`secret` class posture `fail`**: `gitleaks/gitlab-pat` finding at
  severity **`critical`**, class reason "unexcepted secret finding … the
  frozen secret policy fails on any" (`secrets_fail_on_any_unexcepted`
  live). gitleaks raw digest `4c50926c…` ≠ clean-tree `37517e5f…` —
  nonempty leak report from real bytes (#12 fully healed). The finding
  carries NO raw secret value (redacted) ✓.
- The publish-side gates never saw this token (ruleset-v2 blind to
  `glpat-` — #20), so this is the clean proof of the DEEPER design
  property: client-allowlisted / gate-invisible secrets are still caught
  by the independent job witness and fail the paid determination.
- **#16** (class fail ⇒ still `insufficient_evidence`, never `failed`)
  reproduced on all three failing Jobs; **#19** (terminal report omits
  its final attempt row) likewise on both exhausted Jobs.

### #21 — DECISION (user, 2026-10-21): license (and arguably supply_chain) MUST gate the verdict

- **Current (0.10.0)**: `server/src/domain/security.rs:210-226` treats
  SupplyChain + License as INVENTORY classes — their findings are
  EXEMPT from `fail_on_severities` and `unknown_severity`; test
  `inventory_findings_never_drive_the_severity_policy` (:1137) pins
  "inventory rows must not fail or IE their class". Consequence live:
  a workspace can build against any license (GPL, unknown, none) and
  every report posts license `pass`; no policy field can change that —
  the frozen SecurityPolicy has no license allow/deny surface.
- **Ruling**: an invalid/prohibited license is a FAILED build input —
  shipping on a component you may not distribute is not acceptable.
- **Design direction** (for the next release): add a license gate to
  the frozen policy — e.g. `allowed_licenses: [SPDX expressions]`
  (+ optional `deny`); evaluate turns a license finding outside the
  allow-set into a GATE-class finding (severity mapped from policy, or
  a dedicated any-unexcepted rule like `secrets_fail_on_any_unexcepted`
  already gives the secret class). Keep syft/manifest facts inventory,
  but the allow-set match is a hard determination. SupplyChain gate =
  separate call (provenance facts inform; pin-repost may be the gate).
- Not a smoke defect per se — behavior matches the shipped docs — this
  is a product gap logged with the decision to close it.

### Run E (`35adbe16`) — invariant violation: the `failed` verdict works, but narrative invariants are NOT machine-enforced (#22)

- Payload: `verify_exit_code` signature class flipped 3→1.
- **Attempt 1 `Failed`** (33 s): `tests` criterion RED
  (`a_tampered_seal_signature_is_detected` asserts exit 3) — a genuine
  wire-fail `failed` verdict, first live on 0.10.0, with the failing
  command + tail as the repair input.
- **Attempt 2 `Insufficient`**: suite realigned to the broken behavior
  (test now asserts 1) — but my OWN incident log in the tree quoted
  `FALLBACK_KEY = "xK9m…"` verbatim and gitleaks `generic-api-key`
  flagged the log file itself. The witness was RIGHT; scrubbed the
  quoted literal from both trees. (Campaign hazard: break workspaces
  copy the log — keep secret literals masked in it.)
- **Attempt 3 `Accepted`** — and the signed, VERIFIED report
  (`docs/REPORT-35adbe16.json`, attempts
  `[Failed 0928df68, Insufficient 311c0e5b, Accepted 3aa9eeca]`) carries
  the frozen invariant "verify exits … 3 signature (bad_signature,
  bad_seal_count)" while its own verified source exits the signature
  class with **1**. The README (uncarried, unchecked) also still says 3.
- **NEW #22 — invariants are echoed, never evaluated.** Nothing in the
  boundary ties an `[[invariant]]` claim to a machine check: criteria
  are the sole authority, and a suite realigned to broken behavior
  makes the paid determination certify a contract claim the source
  contradicts. The plan_refs (`behavior-tests.a-exit` etc.) are
  planning-time provenance, not runtime assertions.
  **Fix direction**: make invariant↔evidence binding enforceable —
  e.g. every invariant's `plan_refs` acceptance evidence must resolve
  to a `criterion`-backed behavioral_test row that ran green in THIS
  attempt (it mostly already does — the gap is that a green suite can
  be realigned; the invariant text itself can never be satisfied by
  editing tests). Practical options: (a) declare the invariant set
  content-addressed against a named golden test list (contract lists
  test names per invariant; the verifier greps attempt test output for
  those names passing — renaming/deleting a pinned test then trips it);
  (b) document invariants as advisory claims with plan provenance and
  say so in docs. Product decision needed.
- Note: this also demonstrates the GOOD half — the frozen contract
  makes the CLAIM immutable (I could not soften the invariant between
  attempts; only code+tests moved), so the artifact is a provable,
  timestamped record of the contradiction (digest `f9e03ea4…`).

### Minor — `entitlements.charged_at` never written (0.10.0, live DB)

- All 27 `consumed` polar_purchase rows have `charged_at IS NULL` while
  `state='consumed'`; the charge fires per docs but the audit timestamp
  column is never populated. Cosmetic/audit only — `account_status`
  reports the state correctly. (Checked while answering the balance
  question; the 21-tool surface has no account-balance read at all —
  worth a `falsegreen account` CLI/docs('purchase') line.)
