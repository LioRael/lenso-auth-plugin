# OAuth cross-environment conformance

`workers/oauth-conformance.matrix.json` is the executable inventory for the
single shared OAuth scenario:

> OAuth state may only be consumed once.

Every composition records the same business invariants:

```text
success_count == 1
state_consumed == true
second_attempt != success
```

The matrix deliberately separates those business results from the
infrastructure-specific evidence that makes an adapter qualified. A passing
test in one cell does not qualify another cell, and a local callback stand-in
does not become an infrastructure claim merely because it has the same API.

## Matrix

| Composition | Shared scenario source | Qualification required before target claim |
| --- | --- | --- |
| Simulated + deterministic private store | `tests/simulated_reference.rs` | exact ordering, virtual time, fault injection, deterministic entropy |
| Native + PostgreSQL | `local-native-postgresql`: `tests/native_postgres_reference.rs` against an explicitly supplied disposable URL | PostgreSQL transaction, native connection, timeout, cancellation, restart persistence |
| Workers + D1 | actual Worker/D1 target receipt only | D1 semantics, Fetch, Worker lifecycle, Wasm lifecycle, failure recovery |
| Workers + Hyperdrive + PostgreSQL | `experiments/workers-g4/qualify-oauth-postgres-workerd.mjs` is a local composition cohort | Hyperdrive connection, PostgreSQL transaction, transient network failure, timeout, cancellation, uncertain commit |

The Worker/PostgreSQL cohort executes real local `workerd`, generated Auth
Wasm, a fresh Kernel App per operation, and an event-owned Host callback. Its
store is intentionally an in-memory Host stand-in. Therefore it can establish
the shared scenario for the local composition, but it cannot establish
Hyperdrive, a live PostgreSQL transaction, deployment, or production behavior.

## Produce a local candidate receipt

Run this from the Auth repository root:

```sh
node workers/oauth-conformance.mjs run-local --output /tmp/oauth-conformance.local.json
node workers/oauth-conformance.mjs validate --receipt /tmp/oauth-conformance.local.json
```

The default runner executes only the existing deterministic reference test and
the local `workerd` cohort. It leaves Native PostgreSQL opt-in and Workers D1
not run. Therefore both the all-cell `business_conformance` and
`qualification` summaries are normally `"incomplete"`: the local cells passed,
but the matrix has no evidence for the unrun cells. That is the truthful
result, not a failed target qualification.

To exercise a deliberately selected disposable Native PostgreSQL target,
provide the URL through the existing test interface and opt in explicitly:

```sh
LENSO_POSTGRES_TEST_URL='postgresql://…' \
  node workers/oauth-conformance.mjs run-local \
  --native-postgres \
  --output /tmp/oauth-conformance.native-postgres.json
```

This produces `runs[].evidence[].reference = "local-native-postgresql"` with
`qualification.level = "local"` and a passing shared scenario when the command
passes. It still records local candidate evidence rather than a target
qualification: the current native reference test does not yet exercise every
listed timeout and cancellation requirement. It also says nothing about
Workers D1 or Workers Hyperdrive. Do not put the URL, credentials, or command
output into a receipt; the runner records only a command identifier, exit
code, and output digest.

The reference owns an isolated PostgreSQL schema. Its expiry probe names that
schema explicitly and sets `created_at` before `expires_at`, preserving the
database constraint while exercising the expired-state path. A task-owned
PostgreSQL 18 run can therefore be retained as `local-native-postgresql`
evidence for its exact worktree snapshot, but must not be reused as a target,
release, or production claim.

The checked-in [local PostgreSQL receipt](evidence/oauth-conformance-a5687bc.local.json)
records the disposable PostgreSQL 18 run for clean Auth candidate
`a5687bcbe4be06ca3ff84e3839c17303805683db`. It passes the shared OAuth
consume-once invariants and records only local command digests; its native
target requirements remain pending, so it is not a Native target, Workers D1,
Hyperdrive, release, or production claim.

Set `LENSO_CARGO` to an executable path when a repository-specific Cargo
wrapper is required. It is deliberately an executable path, not a shell
fragment, so the receipt runner never evaluates arbitrary shell text.

## Source identity and snapshots

Each generated receipt contains both:

- `source.base_revision`: the Git commit used as the base; and
- `source.worktree_snapshot`: state plus a digest of the tracked binary diff
  and all non-ignored untracked source files.

The runner captures this snapshot before and after its local commands and
refuses to emit a receipt if it changed while they ran. This prevents a
concurrent edit from being represented as evidence for an earlier source view.

A dirty snapshot is a useful local candidate record, but it is not an exact
clean candidate revision. The validator rejects any `target` qualification in
a receipt with a dirty snapshot. Ignored build outputs and private deployment
configuration are intentionally not captured; they must be rebuilt or
attested by the real target procedure instead of being silently implied by a
Git SHA.

## Attach actual-target evidence

Only a clean, exact candidate can attach a target receipt. The target receipt
is an operator-produced, secret-free JSON document with this shape (the
values below are illustrative placeholders, not evidence):

```json
{
  "schema": "lenso.auth.oauth-flow-target-receipt@1",
  "composition_id": "workers-d1",
  "scenario_id": "oauth-state-consume-once",
  "source": {
    "base_revision": "<the exact clean candidate SHA>",
    "worktree_state": "clean"
  },
  "business_invariants": {
    "success-count-is-one": "passed",
    "state-is-consumed": "passed",
    "second-attempt-is-not-success": "passed"
  },
  "qualification_requirements": {
    "d1-semantics": "passed",
    "fetch": "passed",
    "worker-lifecycle": "passed",
    "wasm-lifecycle": "passed",
    "failure-recovery": "passed"
  },
  "evidence": {
    "scope": "actual-target",
    "reference": "secret-free immutable run identifier"
  }
}
```

Pass a receipt only for the composition it actually exercised:

```sh
node workers/oauth-conformance.mjs run-local \
  --output /tmp/oauth-conformance.target.json \
  --target-receipt workers-d1 /path/to/workers-d1.target-receipt.json
```

The runner checks composition, scenario, exact base revision, clean-worktree
status, all shared invariants, all requirements, and `actual-target` evidence.
It will not attach target receipts while the current working tree is dirty.

Use the strict mode only where an all-cell target gate is intended:

```sh
node workers/oauth-conformance.mjs validate \
  --receipt /tmp/oauth-conformance.target.json \
  --require-qualified
```

Strict validation passes only when Simulator is locally qualified and every
target-required composition has a matching actual-target receipt. It does not
promote an older receipt, an arbitrary base SHA, a local-only Worker cohort,
or a release/production assertion. `--require-qualified` also compares the
receipt's full source snapshot to the current worktree. Use
`--require-current-source` alone when a gate needs that source-binding check
without requiring all target qualifications.
