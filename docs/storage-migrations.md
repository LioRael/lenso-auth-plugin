# Plugin-owned storage migrations

All seven persistent Auth Plugins organize their immutable SQL under
`migrations/postgres/` and `migrations/d1/`. Each backend has its own ordered
history; version numbers need not correspond across backends. Existing SQL bytes,
PostgreSQL migration names, and D1 baseline fingerprints are preserved.

## Shared mechanism, owned data

`lenso-migration` supplies immutable definitions, historical checksums and history
comparison. `lenso-postgres-kit` retains native schema ownership, locking and SQLx
pool preparation. `lenso-migration-d1` provides explicit primary-batch D1 operators.
The crates live in the Postgres Kit repository workspace but are independent
packages. Neither migration crate introduces a Capability or shared business SQL.

Each owner packages `src/migration.rs`, generated from its SQL by:

```sh
python3 workers/generate-migrations.py
python3 workers/generate-migrations.py --check
```

The generator uses SQLite statement completeness, not semicolon splitting, and
preserves exact bytes via statement offsets. It needs Python with `sqlite3` and
the pinned Rust 1.94 formatter. `workers/check-packages.py` checks actual archives
for exact migration plans and SQL content, then compiles them outside this tree.

## Runtime and deployment

Runtime preparation calls the owning Plugin's `migration::verify(&binding)`.
It reads the complete `_lenso_migrations` history and checks the legacy baseline
marker. It never creates a ledger, adopts legacy state, or changes tables.

An explicitly authorized deployment Host creates the owner's event-scoped
`workers::D1Binding` and calls one of:

- `migration::setup`: fresh dedicated D1 database only.
- `migration::adopt_legacy`: register the exact existing v1 fingerprint without
  replaying SQL or modifying business rows. Required once for prior proof databases.
- `migration::upgrade`: apply a pending suffix after verifying the full history.

These are Rust deployment interfaces, not new public HTTP routes. Supply the exact
target binding and migration authority explicitly. Existing Wrangler-applied v1
databases need adoption before the updated application can become Ready. Do not
continue applying subsequent files through a separate Wrangler-only ledger: use
the owner operator to maintain the common history. Back up and review the target
through the owning product's deployment workflow before any real rollout.

A failed or interrupted write may already have committed. Inspect primary history;
do not blindly retry. D1 batch atomicity does not imply a transaction across
Plugins, databases or storage backends. PostgreSQL-to-D1 data transfer remains a
separate operation.

## Registry dependency verification

The workspace requires `lenso-migration` 0.1.0, `lenso-migration-d1` 0.1.0 and
`lenso-postgres-kit` 0.1.1. The Workers fixtures require
`@lenso/workers-runtime` 0.1.2, which exports the shared HTTP Host.
Consumer lockfiles resolve these packages from their registries.

Run `workers/check-packages.py` to verify actual package containment: each private
owner and its private Capability dependencies are extracted from real archives;
all external dependencies resolve from the registry. For future unpublished
cohorts, the optional OS-path-separated `RUNTIME_ARCHIVES` variable accepts actual
`.crate` files. Every non-registry dependency must resolve to an extracted archive.
Do not commit machine-specific source patches.

For workerd qualification, install the locked G4 npm dependencies and build:

```sh
pnpm --dir experiments/workers-g4 install --frozen-lockfile
CARGO=/path/to/lenso-cargo bash experiments/workers-g4/build.sh
node experiments/workers-g4/migration-proof.mjs
```

The new proof uses `createWorkersHttpHost`, actual generated Rust/Wasm, and fifteen
in-memory D1 bindings (fresh + legacy for each owner, plus a pending-upgrade
fixture). It checks missing history,
explicit setup/adoption, current and pending upgrades, atomic failed-upgrade
rollback, checksum drift and recovery. It disposes
workerd and all ephemeral storage after completion. It never reads remote proof
credentials or provisions Cloudflare resources.

Registry adoption does not run a database migration. Existing application
storage still requires an explicit, separately operated upgrade or legacy adoption.

The Account D1 history's v2 migration adds the compound
`auth_sessions(subject_id, session_id)` index used by subject-filtered session
pagination. Existing v1 databases must be explicitly upgraded after legacy
adoption; the v1 SQL and fingerprint remain unchanged.

OAuth Flow has a separate D1 v2 and PostgreSQL v3 `add-oauth-revocation`
migration. It retains `revoked_at` so consume/revoke races and an App restart
can report a terminal domain outcome rather than treating a revoked OAuth state
as unknown. See [OAuth reference composition](oauth-reference-composition.md)
for its Environment × Infrastructure qualification matrix.

## Recorded local verification

- 52 native Auth tests passed, including real PostgreSQL acceptance tests for all
  seven persistent owners. Disposable database resources were removed.
- Seven real extracted owner packages compiled for Workers, with exact packaged
  migration plans and SQL and archive-only non-registry dependency graphs.
- Native and Workers strict Clippy passed on Rust 1.94.0; generated bridge and
  migration checks passed, including SQLite quoted/trigger/UTF-8 boundaries.
- [Local workerd receipts](storage-migration-workerd.json) record all 15 successful
  compositions and the tested Wasm hash. These are local runtime results, not a
  production deployment or external identity/SMS vendor qualification.
- [Password preparation measurements](password-performance.md) separately record
  native setup/hash/verification costs. Wasm password hashing remains synchronous;
  no Workers throughput or end-to-end latency claim is made.
