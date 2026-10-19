# FalseGreen Issues

Trouble encountered while using FalseGreen (shim 0.7.0) to verify this project — Job `4a69d00c-cc83-48e8-9267-510996677031`, 2026-10-19. Mirrors PLAN.md §10; this file is the standalone issue record for filing upstream.

## T1 — D0 secret gate false positive on non-hex high-entropy tokens

- **When:** `create_job` (1st attempt), 2026-10-19.
- **Symptom:** publish refused by the D0 `secret_token` high-entropy rule. The flagged "token" was the slash-joined CLI subcommand list in PLAN.md — `init/append/verify/tail/export/import/compact/keygen/policy` — one 64-char alphanumeric string. No secret was present.
- **Workaround:** split the list into prose (commit 5e69e29); `falsegreen security scan` then clean; `create_job` succeeded.
- **Root cause:** the 0.7.0 fix (348d3a1) allowlisted pure-hex digests ≥40 chars and raised the rule's minimum length to 40, but long **non-hex** alphanumeric compound tokens still trip it. This is the second occurrence of this FP class (first: SHA-256 checksums in Cargo.lock — the case 348d3a1 fixed).
- **Suggested upstream fix:** exclude tokens built from a small identifier alphabet joined by `/` `-` `.` (e.g. dictionary check on the segments), or raise the entropy floor above ~4.0 bits/char for non-hex strings.

## T2 — MCP `falsegreen_verify_report` impractical for large reports

- **When:** report-verification step, 2026-10-19.
- **Symptom:** the tool's only input is the report JSON **as a string in the tool call** — no file path or artifact reference. With schema v5 and a full Security/Standards section the report is ~84KB. In an agent session that size cannot be passed reliably: `read` truncates lines to 768 chars, bash cannot write to `xd://` MCP paths (read-only filesystem), and transcribing ~84KB through model context risks corruption.
- **Workaround:** the CLI `falsegreen verify-report docs/REPORT-4a69d00c.json` — the same `verify_report_json` implementation the MCP tool wraps, reading the file directly. Result: VERIFIED (verdict accepted, key `fg-report-9fc1a2c5-…-20261018-1`, digest `82c92878…`, schema v5).
- **Suggested upstream fix:** accept a file path / artifact reference in addition to the inline string.

## T3 — `get_report` artifact is multi-line JSON

- **When:** polling `get_report` to the terminal verdict, 2026-10-19.
- **Symptom:** the terminal-verdict output artifact is a JSON document where the first line is the payload and trailing lines are display wrappers (84,031 bytes total, 105 trailing). `json.load` on the whole file fails with `JSONDecodeError: Extra data`.
- **Workaround:** `json.JSONDecoder().raw_decode` — take the first object.
- **Suggested upstream fix:** none required — cosmetic; one wasted parse round.

## Upstream bug summary (falsegreen 0.7.0)

1. **D0 `secret_token`**: still false-positives on long non-hex alphanumeric compound tokens (see T1).
2. **MCP `falsegreen_verify_report`**: add a file-path / artifact-reference argument for ≥64KB reports (see T2).
