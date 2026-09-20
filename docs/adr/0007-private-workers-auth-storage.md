# ADR 0007: Private Workers storage for Auth method owners

- Status: implemented and qualified in an isolated Workers composition; production rollout is separate
- Baseline: Auth `b68d87654e18910e8d14649e48e3166636fa99a1`
- Upstream: Lenso ADRs 0039, 0041, 0042, 0064, 0066

## Decision

Keep Account, OAuth Flow, Router and Web Session Plugin identities and Capability
ownership boundaries unchanged. Account owns identities, sessions, administration
and delegated sessions; OAuth Flow owns encrypted PKCE custody and single-use
state. Private operation-oriented storage has PostgreSQL and D1 implementations.
There is no public SQL Capability. Shared Rust retains token/HMAC/assertion logic,
credential validation, caller authorization, grant scope and flow rejection policy.
D1 conditional SQL enforces corresponding transaction predicates before writes.
OAuth Flow's subsequent version 1.2 Contract and its Workers PostgreSQL
transport are specified by ADR 0008; this ADR remains the D1 ownership and
migration baseline.

PostgreSQL is the default Cargo feature. Workers disables defaults and enables
`workers`; SQLx, Postgres Kit and native operators remain behind `postgres`.
Account and OAuth Flow add default-empty `d1_binding` configuration. Absence/empty selects
Postgres and requires database_url_secret. Named D1 requires that reference empty
or omitted and an exact injected binding. Missing support fails preparation.
Account configuration schema now derives from Rust like OAuth Flow. Declared empty-string/list defaults preserve omitted native fields and avoid nullable schema combinations. The existing
schema namespace remains an owner label; it cannot select another database.
Deploy each storage owner with a separate D1 database by default.

The owner factory receives a fresh D1 bridge for each event. That bridge invokes
D1Database.batch directly, never Sessions API or replicas. No global binding lookup,
request-I/O cache, or persistent App instance exists. Factory injection reuses the
public `ConfiguredPluginFactory` projection and normal lifecycle. Package-level
`link_plugin()` retains private Plugin types. `with_factory_override` selects the
owner's event factory explicitly and validates its identity independently of linked
registration order. No generated Capability projection is edited.

## Durable semantics

Each operation uses one atomic D1 batch. Identity subject and binding insertion
commit together, without duplicate/orphan subjects. Issuance checks effective status
in its conditional insertion; disable and revoke-all commit together. Revocation
uses conditional updates. Authentication reads current subject and parent state.
Grant and parent relationship insertion are atomic and require active root user,
non-revocation, parent expiry, exact audience containment, and no nested delegation.
Shared Rust projects domain failures; SQL guards prevent denied grants from writing.

OAuth consume reads and conditionally marks state in one batch. Only matching,
unexpired, unconsumed state succeeds. Rust decrypts after commit; corrupt ciphertext
never restores single-use state.

D1 stores normalized UTC timestamps with nine fractional digits as text, preserving
precision across JavaScript. API values use the same Rust RFC3339 formatter. Grant
validation uses one sampled time across all guarded statements. D1 database time
checks effective subject disable status at authentication/issuance.

Migrations under each owner's migrations/d1 directory run explicitly. Preparation
verifies the version and migration fingerprint, never creates or upgrades tables.
Fingerprints hash schema text preceding the final fingerprint insertion statement;
they verify the applied migration record, not arbitrary later manual DDL.

Transport failures become redacted Runtime Failures. Credentials, signing keys,
peppers and encryption keys never enter diagnostics or public configuration.
Entropy uses getrandom's Web Crypto backends (including transitive 0.2 crypto).
time/wasm-bindgen supplies Worker wall time; pinned JWT validation independently
selects JS Date. Password security parameters and verification execution are unchanged; preparation
validates a precomputed public dummy hash instead of hashing it per App.

## Qualification and limits

Require native PostgreSQL and real D1 proof of duplicate identity, disable/issue
races, root/child revocation, expired credentials, restricted grants, denied writes,
single-use state, storage failure, restart persistence and clean event receipts.
Verify signed assertions at the target seam. Browser evidence must use actual Web
Session and shared ingress; fixture Federated providers are not external OIDC proof.

A write can commit before event failure. Issuance lacks idempotency input; never
blindly retry ambiguous issuance or claim exactly-once semantics. D1 has no query
cancellation API: local abandonment is not rollback. No destructor performs durable
writes. Password, Phone, Device, API Token and OIDC Provider now use the same private
storage boundary. Password/Phone retain native Argon2 parameters and bounded job
admission. Phone consumes OTP state conditionally; Device uses an atomic primary
transition; API Token joins token/session expiry and revocation; OIDC consumes
codes with exact client, redirect and PKCE predicates and retains RS256 signing.
These changes do not authorize production migration.

The JS bridge forwards native completion through a separate event-owned Promise.
Before a Wasm generation resets, invalidate clears its resolve/reject references
without invoking Rust or native I/O. A late D1 response cannot resume an abandoned
JsFuture. Cleanup waits at most 250 ms and returns false when native work remains;
the shared HTTP handler reports storage_cleanup_unconfirmed. This is uncertainty,
not a claim of rollback or successful cancellation.

Normal Plugin Root qualification also exposed legacy config validation rejecting
canonical `plugin_id/instance_key` names. Account caller allowlists and Router
provider names now accept one validated slash-separated pair as well as legacy
short names. Credential schemes and all exact provider/allowlist comparisons retain
their previous rules. This corrects composition independently of the storage target.

OIDC Client configuration removes URI `format` annotations unsupported by the
normal HostCatalog restricted-schema validator. Existing Rust HTTPS, fragment,
credential, issuer and redirect validation remains mandatory before Ready.

## Package self-containment

Each storage owner packages its own `src/workers.rs`. These byte-identical copies
are generated from Auth-owned `workers/d1.rs` by
`node workers/generate-bridges.mjs`; the generated header identifies the authoring
source. `node workers/generate-bridges.mjs --check` rejects drift without writing
files, and CI runs that check before compilation. This small
transport module contains no Account or OAuth business policy. It avoids a new
public support crate and never resolves a Rust source file outside its package.
The JS binding remains an explicit Host asset copied from `workers/d1-binding.mjs`.

`workers/check-packages.py` creates actual Cargo archives, extracts them outside
the repository, and checks both owners with only `workers` enabled for
`wasm32-unknown-unknown`. The three unpublished Capability dependencies are also
packaged and supplied exclusively from extracted archives; the check rejects any
source-workspace dependency in the resolved graph. Matching dependency versions
permit packaging while every existing `publish = false` setting remains intact.
This proves archive self-containment, not registry availability or publication
readiness for those private crates. Packaging uses isolated inputs and leaves the
repository lockfile unchanged.

## Complete-method qualification

The isolated `lenso-workers-auth-complete-proof` deployment
`ff78dedc-5803-4679-b6d0-3c9ded68f95a` passed 117 recorded checks: 36 method flows,
22 method failures/expiry/storage checks, and 59 Account/OAuth/Web Session
regressions. Existing native PostgreSQL suites passed 33 tests for the five added
owners. Receipts are under `experiments/workers-g4/evidence/`. SMS delivery and
upstream identity providers are controlled fixtures; this does not qualify an
external vendor. OIDC RS256 signatures and API Token target assertions are checked
independently by Node crypto.

`workers/check-packages.py` now covers all seven storage owners. An unpublished
Runtime cohort can be supplied using `RUNTIME_ARCHIVES` (OS path-separated actual
`.crate` archives); every resolved non-registry dependency must be extracted under
the isolated proof directory. Package versions do not imply registry publication.
The shared `createEventScope` now owns binding settlement and callback fencing;
D1 adapters no longer compose their own cleanup hooks.

## Password preparation cost

Password and Phone use a public precomputed dummy PHC hash. Preparation parses
and checks its exact Argon2 algorithm, version, cost parameters and output length
against the same `Argon2::default()` policy used for real hashes; mismatch fails
preparation. Tests regenerate each fixture from its public input and salt.
This removes one Argon2 hash from every owner preparation, including fresh
Workers event Apps, without caching App state, credentials, or event I/O.
Every App still receives its own bounded semaphore. Real password hashes keep
fresh random salts. A missing credential still runs one full verification and
always rejects, even when its input equals the public dummy input.

Native hash/verify jobs still run on `spawn_blocking`; Wasm still runs the same
Argon2 job synchronously on its execution thread. Admission is bounded but does
not make Wasm hashing nonblocking or promise an isolate CPU budget. See
[`../password-performance.md`](../password-performance.md) for the reproducible
local measurements and scope.

## Unified migration histories

Auth now packages backend-specific SQL under `migrations/postgres` and
`migrations/d1`. Both adapters consume the portable `lenso-migration` history
model. D1 uses the explicit `lenso-migration-d1` setup/upgrade/adoption operators;
Ready only verifies. Existing v1 databases require explicit legacy adoption.
See [storage migration operations](../storage-migrations.md) for package
qualification, target ownership and the separate release/rollout requirements.
