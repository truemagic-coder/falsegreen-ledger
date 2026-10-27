# falsegreen-ledger — design

The integrity design of `falsegreen-ledger`: the canonical form, the
hash chain, the shard store, the Merkle seal, policy evaluation,
compaction, and the verification report. Every statement below is the
implemented behavior; the test suite pins it.

## 1. Canonical form

All hashed and signed material is **canonical JSON**: object keys sorted
lexicographically, no whitespace. Invalid values (empty required fields,
non-object context, out-of-range timestamps, unknown fields) are rejected
by validation — never silently normalized, because normalizing would make
some tampering undetectable.

The canonical bytes of an object are its stable identity: key-order edits
change the stored JSON but not the canonical form, so they are *not* tamper
events; any byte change to a value is.

`Event::canonical_map()` produces the sorted map; hashing and signing always
run over canonical bytes, never over raw stored JSON.

## 2. Event model

```
Event {
  seq: u64,          // 1-based, strictly increasing per ledger
  ts_ms: i64,        // unix epoch milliseconds, range-checked
  actor: Actor { kind, id, version?, on_behalf_of? },
  action: Action { kind, name, target? },
  correlation: Correlation { session, request? },
  decision: Decision { outcome, policy_version?, reason? },
  context: object,   // free-form; MUST be a JSON object
}
```

All structs are `deny_unknown_fields`. Validation rejects: empty required
fields, a non-object `context`, out-of-range timestamps, and unknown fields.
An invalid event is a **corrupt-class** failure at verify time, not a silent
normalization.

## 3. Hash chain

A stored record is:

```
Record { event: Event, prev_hash: String, hash: String }
```

- `hash = SHA-256(canonical(event) ∪ { "prev_hash" })` — the canonical map
  of the event plus the `prev_hash` field, one object, hashed.
- `prev_hash` of the ledger's first record is `GENESIS_HASH`; the first
  record of every later shard is the **root link** to the previous shard's
  root (its Merkle root — or the source root of a compacted shard, §6).
- Link rule: record N links to record N−1 iff `prev_hash == record(N−1).hash`
  **and** `seq == record(N−1).seq + 1`. Any mismatch is a named failure:
  `bad_record_hash`, `broken_link`, or `sequence_gap`.

## 4. Shard store

- One file per shard: `shard-NNNNNN.jsonl` (zero-padded index), append-only.
- One line per record; the final line of a closed shard is the seal line
  `{"seal": {…}}`.
- Append continues the verified head: the CLI derives `seq` from the head
  record and `prev_hash` from the head record's hash (or the previous
  shard's root). Append never rewrites existing shard content.
- Line-level parse errors report the shard and line number.

## 5. Merkle root + Ed25519 seal

**Merkle**: pairwise SHA-256 over the shard's record hashes, hex, leaves
concatenated in order; an odd final leaf is duplicated to even it out. The
root is deterministic for a given shard.

**Seal** (stored on the shard's last line):

```
Seal {
  merkle_root: String,
  count: u64,             // must equal the shard's record count
  prev_shard_root: Option<String>,  // root link into this shard
  signature: String,      // Ed25519, hex
  public_key: String,     // hex; embedded so a verifier can pin it
  sealed_at_ms: u64,
}
```

**Seal message** (what is signed): canonical JSON of

```
{ "count", "kind": "seal", "merkle_root", "prev_shard_root", "sealed_at_ms" }
```

(sorted keys). The `signature`/`public_key` fields are not part of the
message. Verification with the embedded key is `verify_seal`; pinning a
trusted external key is `verify_seal_with`.

## 6. Compaction

`compact_last_sealed` replaces the **last sealed** shard in place:

- the original sealed shard's full event content is gone from that file;
- a single **compaction record** takes its place: an `Event` with
  `action = { kind: "ledger.compact", name: "shard.compact", target:
  "shard-NNNNNN" }`, `actor = { kind: "system", id: "compactor" }`,
  `seq` = the source shard's last seq, and a `context` carrying
  `source_shard`, `source_record_count`, and `source_seal` (the original
  seal, verbatim);
- the compaction record's `prev_hash` is the original shard's genesis
  `prev_hash`, so the **root link** into the next shard is unchanged;
- a new seal is computed over the compaction record (`count: 1`) and
  re-signed; its `prev_shard_root` equals the source seal's
  `prev_shard_root`.

Verify treats a compacted shard structurally: the embedded `source_seal`
must match a recomputation of the original root link and must itself verify;
the new seal commits to the compaction record. Because the embedded source
seal is inside the signed context, rewriting a compacted shard breaks the
seal signature; the original *content* of a compacted shard is no longer
reconstructible from the ledger — anchor (export/publish) before compacting
if you need the raw records to outlive compaction.

If the active shard is not sealed, `compact` seals it first.

## 7. Policy engine

```
Policy { version: String, rules: [Rule] }
Rule {
  id: String,
  actor_kind?, action_kind?, action_name?,   // matchers; unset = any
  require_outcome?: String,  // matching event's decision.outcome must equal it
  deny?: bool,               // true: a matching event is a violation on its own
}
```

Every event of the ledger is evaluated against every rule at verify time
(`verify --policy`). A rule with `deny: true` flags any event whose fields
match its set matchers; a rule with `require_outcome` flags a matching event
whose outcome differs. Violations appear in the report as
`policy_violation` failures with the `rule_id`.

## 8. Verification report

`verify_ledger` walks **every** shard and produces canonical JSON:

```
VerificationReport {
  verified: bool,
  shards: [ ShardReport ],
  total_records: u64,
  failures: [ Failure { kind: FailureKind, shard: u32, detail: String } ],
  verified_at_ms: i64,
}
```

`ShardReport { shard, records, sealed, compacted, failures,
authoritative_root }` — `authoritative_root` is the root later shards must
root-link to (the seal's root for sealed shards, the recomputed root
otherwise, the original root for compacted shards).

The CLI exit code is the most specific failing class:

| Class | Failure kinds | Exit |
| --- | --- | --- |
| corrupt | `parse_line`, `invalid_event`, `bad_seal_structure` | 5 |
| gap | `sequence_gap` | 2 |
| signature | `bad_signature`, `bad_seal_count` | 3 |
| tampered | `bad_record_hash`, `broken_link`, `bad_merkle_root`, `broken_root_link` | 1 |
| policy | `policy_violation` | 4 |

## 9. Export / import

- `export` → one JSON document: `{ "shards": [ { index, records, seal } ] }`
  — deterministic typed serialization (not the raw stored lines, so key
  order in the file can never leak differences), pretty-printed on output.

- `import` → a JSONL file of events (no `seq`; it is derived) re-appended
  to a ledger. Re-importing an exported ledger's events into a fresh ledger
  reproduces **identical record hashes** — the round trip is hash-stable.

## 10. Threat model

**What the ledger proves, given an uncorrupted copy of the sealed shards
and a known public key:**

1. **Content integrity** — any byte change to any event, `prev_hash`, or
   `hash` field fails `bad_record_hash` or `broken_link` (the hash commits
   to the canonical event *and* the link).
2. **Ordering and completeness within a shard** — sequence gaps
   (`sequence_gap`) and reorders (`broken_link`) are detected; the seal's
   `count` must match the shard's records.
3. **Seal integrity** — the Merkle root commits to every record hash; a
   seal signature over the canonical seal message commits to root, count,
   and the root link. Flipping any seal field breaks the signature.
4. **Cross-shard continuity** — each shard's genesis record root-links to
   the previous shard's root, and each seal commits to `prev_shard_root`;
   replacing or reordering whole shards breaks `broken_root_link` or the
   signature.
5. **Compaction boundary** — the embedded source seal inside a compaction
   record keeps the original root link verifiable through compaction.

**What it does NOT prove:**

- **Total replacement with a re-signed shard** — an attacker with the
  *private key* can seal a rewritten shard legitimately. Mitigation: keep
  the signing key offline, separate from any process that could be coerced
  into rewriting shards.
- **Unanchored pre-seal history** — nothing is tamper-evident until a seal
  is published somewhere an attacker cannot edit. The first append-to-seal
  window is open. Mitigation: publish seals (CI report, external log,
  git-tagged export) as soon as they are made.
- **Shard loss** — the store has no redundancy; losing a shard file breaks
  the chain for its successors (detected, not repaired).
- **Event semantics** — the ledger records what the writer told it to; it
  cannot detect a false event written by the logging process itself.
- **Policy** — policy checks are evaluated at verify time against the
  given policy; the policy file is not part of the signed boundary.

## 11. Formal proofs

The chain-link rule is carried by two frozen formal encodings, listed as
one `[[invariant]]` in `falsegreen.toml` and discharged by external
toolchains (never by this program):

- **Kani** (bounded, over the SHIPPED code): `proofs/links_kani.rs`
  includes `src/rules.rs` by path, so what is model-checked is byte-for
  byte what the binary runs, over the full u64 domain.
- **Creusot** (unbounded, over the guarded specification):
  `src/spec.rs` states the same sentence in Pearlite
  (`#[requires]`/`#[ensures]`), erased under a plain build. The proof
  obligations cover both `rules::links` and `spec::links`.

Proof-build plumbing: the application modules and the CLI stub out under
`--cfg creusot` (`cargo creusot` type-checks every target, and the
storage/IO machinery has no spec — see the gating comments in `src/lib.rs`
and `src/main.rs`). `why3find.json` is the Why3 project configuration the
proof runner reads (it imports the `creusot` Why3 package and sets search
budgets; the frozen contract passes its own budget flags on top).
