# FalseGreen Issues Log

Running the `falsegreen-ledger` project through the FalseGreen MCP workflow
end-to-end is a real-world exercise of the system. This log records every
friction point hit — symptom, root cause, resolution, and the gap it
exposes — as they occur. Newest entries at the bottom of each section.

Session: task `task_6b78e45e6332764d9a32b2293defaf1a`, 2026-10-19.

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

## Pending observations (to be filled as the Job runs)

- [ ] `falsegreen_create_job`: boundary freeze / entitlement behavior.
- [ ] `falsegreen_get_report` polling while `verifying` (NO_VERDICT shape,
      queue estimate accuracy).
- [ ] Terminal verdict + signed report + local `falsegreen_verify_report`
      (Ed25519 self-verification).
- [ ] Repair path (if the verdict is not `accepted`): `falsegreen_repair_job`
      semantics, attempt budget, re-publish behavior.
