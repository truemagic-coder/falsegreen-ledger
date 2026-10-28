# falsegreen-ledger

A tamper-evident, hash-chained audit ledger for AI-agent actions, in Rust.

Every record commits to the SHA-256 of the canonical form of its predecessor;
sequence numbers are strictly increasing, so deletions and reorders are
detectable. Closed shards carry a Merkle root signed with Ed25519 — the
external trust anchor. A ledger verifies offline with only the shard files
and no signer present.

## Independently verified

This program, exactly as published here, was verified by FalseGreen:
build, the full test suite, clippy and formatting as frozen criteria, and
one claim — chain linking is exact successor arithmetic that never wraps
at the u64 ceiling — proven twice by machines over encodings that live in
this repo (a bounded Kani model check over the shipped `src/rules.rs`,
and an unbounded Creusot/Why3 proof of the guarded Pearlite spec in
`src/spec.rs`). Accepted on the first attempt in 93.5 s; the signed report
verifies offline, no account or network needed:

- Human report: <https://falsegreen.com/report/645a6360-4a48-4323-9cc6-aaf06d4a706f>
- Signed JSON + PDF in this repo: `reports/`
- Offline check: `falsegreen verify-report reports/645a6360-4a48-4323-9cc6-aaf06d4a706f.json`

## Build

```sh
cargo build --release
```

The full test suite runs offline from the committed `Cargo.lock`:

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

## Quick start

```sh
FL=falsegreen-ledger

# 1. keypair (the private key signs shard seals; keep it off the verifier)
$FL keygen
# → {"private_key":"…","public_key":"…"}

# 2. ledger
$FL init /var/log/ledger

# 3. append events (seq is derived — the CLI continues the verified head)
$FL append /var/log/ledger --event '{
  "ts_ms": 1760800000000,
  "actor":      {"kind": "agent", "id": "a-1"},
  "action":     {"kind": "tool_call", "name": "shell.exec", "target": "ls -la"},
  "correlation":{"session": "s-1"},
  "decision":   {"outcome": "allowed"}
}'

# 4. verify (exit 0 = clean; report on stdout)
$FL verify /var/log/ledger

# 5. seal + compact a shard (needs the signing key)
$FL compact /var/log/ledger --key <private_key_hex>

# 6. policy check on one event
$FL policy '{"version":"1","rules":[{"id":"no-shell","action_kind":"tool_call","action_name":"shell.exec","deny":true}]}' '<event json>'
```

Bulk import from JSONL (one event per line, no `seq`):

```sh
$FL import /var/log/ledger events.jsonl
```

## CLI exit codes (the CI contract)

| Code | Meaning |
| --- | --- |
| 0 | ok / clean ledger |
| 1 | tampered (record hash, link, Merkle root, or root link fails) |
| 2 | gap (sequence not consecutive) |
| 3 | signature failed (seal signature or count mismatch) |
| 4 | policy violation |
| 5 | corrupt / parse (unreadable shard line, invalid event, inconsistent compaction) |
| 255 | usage error |

When several classes coexist, the most specific diagnosis wins: corrupt (5),
then gap (2), signature (3), tampered (1), policy (4).

## Threat model (short version)

The chain detects content edits, deletions, reorders, and seal forgery —
**given the verifier owns an uncorrupted copy of the sealed shards and knows
the public key**. It does not detect: simultaneous replacement of a shard
file *and* its seal with a matching re-signed pair (requires the private
key), an all-shards rewrite by someone with write access to every shard
before any external party anchors a seal (publish a seal — e.g. in a CI
report or an external log — to fix that window), or loss of shards. The
full threat model is in [`docs/DESIGN.md`](docs/DESIGN.md).

## Design

Canonical forms, chain and Merkle construction, seal message, policy
semantics, compaction, report schema, and the threat model:
[`docs/DESIGN.md`](docs/DESIGN.md).

## Proofs

The core linking rule is carried by two formal encodings, executed by
[`falsegreen.toml`](falsegreen.toml) as a FalseGreen Job:

- a bounded model check (`proofs/links_kani.rs`) over the shipped code in
  `src/rules.rs` — the harness includes that file by path, so the proof
  and the binary run the same bytes;
- an unbounded Why3 proof of the guarded specification in `src/spec.rs`
  (`#[requires]` / `#[ensures]`, erased by a plain `cargo build`).

Together they pin one claim: *chain linking is exact successor arithmetic
and never wraps at the u64 ceiling.*

## License

MIT — see [`LICENSE`](LICENSE).
