# Report field map — what to read to review a full report

Audited 2026-10-23 against every report JSON this workspace holds
(`reports/*.json`, `docs/REPORT-*.json` — 17 files, all `report_schema` 9).
Nothing here is inferred: each row names the artifact that actually contains
the field, and the two renderings (HTML + PDF) were fetched from prod into
`docs/review/` so they can be read offline.

## Read these three, in this order

| # | Artifact | Why |
|---|---|---|
| 1 | `docs/review/7e1c9441.html` / `.pdf` (+ `docs/REPORT-7e1c9441.json`) | **The clean specimen.** One Job, one attempt, one claim carried by all three proof rungs in the same attempt: L0 executable check ×2, L1 Kani (`proven`, bounded), L2 Creusot (`proven`, 2/2 goals, empty trust set). Every rendered section is present and nothing is red. Shortest path to "what does a good report look like". |
| 2 | `docs/review/d54370e9.html` / `.pdf` (+ `reports/runB-d54370e9.json`) | **The full-shape specimen.** Three attempts (fix-and-recheck rounds), the supply-chain drift gate and the licence gate fired live, final verdict `accepted`. This is also where **the current defect (F25) is visible** — see the last section. |
| 3 | `docs/review/520d2155.html` / `.pdf` (+ `docs/REPORT-520d2155.json`) | The only report here whose **VEX section carries real findings** (2 vulnerability rows). Everything else in this workspace has an empty VEX. |

Supporting specimens, if you want a specific behaviour:

- `reports/runA-68239ac0.json` — a **Kani counterexample**: the rung found a real
  arithmetic violation and failed the attempt; the repair made it pass. The
  counterexample itself is JSON-only by design (the HTML/PDF show the decision,
  not the trace).
- `reports/runC-15201f76.json` — **unknowable rungs never pass**: 8 attempts,
  every one `insufficient_evidence` because the L1 harness cannot compile and the
  L2 target names a nonexistent item. Proof failure is never `failed`.
- `docs/REPORT-789b62d9.json` — the ten-invariant incident corpus (L0 checks
  only), 2 attempts.

## Field coverage — which artifact proves the field exists

| Report section (as rendered) | Shown in | Notes |
|---|---|---|
| Cover: verdict badge, claim, facts table | all three | |
| Contract (frozen): criteria, invariants, run slots | 7e1c9441, d54370e9, 789b62d9, runA/B/C | Older `REPORT-*` files without invariant sections legitimately show none. |
| Plan (frozen): work items, dependencies, acceptance + evidence requirements | all three | |
| Environment (job image, toolchain, source fingerprint) | all three | |
| Evidence manifest: per-attempt rows, wall clock, per-criterion argv/exit/output | all three | In JSON, the invariant decisions hang off **each attempt**, not the report root — that is why a top-level grep for `invariants` in the older reports looked empty. |
| Vulnerability Findings (VEX) — real findings | **520d2155** (2 rows) | The other reports render "no vulnerability findings". |
| Invariant Checks table — all three rungs green | **7e1c9441** | Renders `check`, `kani (bounded)`, `creusot (unbounded)` as distinct rows with the goal tally (2/2). |
| Invariant Checks — a violated rung + counterexample | runA (JSON) | `counterexample` field; deliberately not printed in HTML/PDF. |
| Invariant Checks — UNAVAILABLE rungs | runC | 8/8 attempts. |
| Security & Standards — all five classes, real findings, witnesses + digests | d54370e9 (180 findings on the clean attempt) | The Standards posture rows (2 rows) appear in 7e1c9441 and 789b62d9; most other reports carry an empty standards list. |
| Exports — SBOM embedded (SPDX 3.0 + CycloneDX 1.7), OSCAL assessment results, VEX | d54370e9 (spdx 66.9 kB, cdx 32.2 kB, oscal, vex) | Embedded in the signed JSON; the HTML/PDF show VEX only and point at the JSON. |
| Signature — `public_key`, `key_id`, `signature_ed25519`, digest | all | 17/17 VERIFIED locally, keyless, with the installed 0.13.0 shim (2026-10-23): `falsegreen verify-report <file>`. |
| Money posture — `refund_state`, `refunded_amount_cents`, one spend | all | `null`/`null` on accepted Jobs; the refund rows are populated on the pre-execution cancel probe. |

## The one field no report in this workspace has ever shown

A **non-empty Creusot trust set**. The rule (DP-13.9): the set of admitted
assumptions a proof leaned on is *derived by the tool* from the run and recorded
per attempt; a clean proof records none, and 7e1c9441 renders exactly that —
"proven with 2/2 goals and an **empty trust set**". No run here has ever proved
something *through* a `#[trusted]` helper, so the non-empty case is undocumented
by example. (A `#[trusted]` item named as a **target** can never be proven at
all — it emits no encoding — so the example needs a trusted *helper* on the path
of a proven target.)

## Where the live defect (F25) is visible — read it in artifact 2

`reports/runB-d54370e9.json`, `attempts[0].security.classes` and
`attempts[1].security.classes`:

- Attempt 1 (its own source `8e7bde15…`, the Job's current source is
  `f22021f4…`): **every** class reads
  `insufficient_evidence — witness … scanned a different subject (untrusted)`.
  Yet the same attempt records the genuine supply-chain finding
  (`undeclared-component`, `pkg:cargo/byteorder@1.5.0`) and the attempt's own
  outcome is `Failed`. So the report says "not enough evidence" for a round that
  actually *demonstrated* a violation.
- Attempt 2: the `license` class is untrusted and its findings list is **empty** —
  the GPL-3.0-or-later dependency that failed that round has vanished from the
  derived section (it survives only in the raw evidence).
- Attempt 3 (source matches the Job): all five classes `pass`, no complaint.

That is the exact asymmetry 0.14.0 fixes (per-attempt source used per attempt),
and fixing it is followed by re-issuing these reports, so the same artifact
becomes the after-picture.

## Do we need a new paid Job to review a full report?

No — with one caveat. Artifacts 1 + 2 + 3 together cover every rendered and
embedded section, all three proof rungs, both gate firings, the multi-attempt
shape, and a populated VEX. The single thing no existing report shows is the
non-empty trust set, and one field does not justify a paid run when the case is
already specified precisely enough to fixture. A run would only be worth it if
you want **one** artifact containing everything at once (including the trust
set) rather than three cross-referenced ones.
