# ADR 0007: Private Workers storage for the representative Auth composition

- Status: experimental implementation; target qualification is separate
- Baseline: Auth `b68d87654e18910e8d14649e48e3166636fa99a1`
- Upstream: Lenso ADRs 0039, 0041, 0042, 0064, 0066

## Decision

Keep Account, OAuth Flow, Router and Web Session Plugin identities and Capability
operation schemas unchanged. Account owns identities, sessions, administration
and delegated sessions; OAuth Flow owns encrypted PKCE custody and single-use
state. Private operation-oriented storage has PostgreSQL and D1 implementations.
There is no public SQL Capability. Shared Rust retains token/HMAC/assertion logic,
credential validation, caller authorization, grant scope and flow rejection policy.
D1 conditional SQL enforces corresponding transaction predicates before writes.

PostgreSQL is the default Cargo feature. Workers disables defaults and enables
`workers`; SQLx, Postgres Kit and native operators remain behind `postgres`.
Account and OAuth Flow add default-empty `d1_binding` configuration. Absence/empty selects
Postgres and requires database_url_secret. Named D1 requires that reference empty
or omitted and an exact injected binding. Missing support fails preparation.
Account configuration schema now derives from Rust like OAuth Flow. Declared empty-string/list defaults preserve omitted native fields and avoid nullable schema combinations. The existing
schema namespace remains an owner label; it cannot select another database.
Deploy the two owners with separate D1 databases by default.

The owner factory receives a fresh D1 bridge for each event. That bridge invokes
D1Database.batch directly, never Sessions API or replicas. No global binding lookup,
request-I/O cache, or persistent App instance exists. Factory injection reuses the
pinned generated constructor, typed endpoint macros and lifecycle; these private
generated names are an experimental integration dependency to review on upgrade.
Register event factories before with_linked_factories; stable identity dedup retains
the explicit implementation. No generated Capability projection is edited.

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
selects JS Date. Password security parameters/execution are unchanged.

## Qualification and limits

Require native PostgreSQL and real D1 proof of duplicate identity, disable/issue
races, root/child revocation, expired credentials, restricted grants, denied writes,
single-use state, storage failure, restart persistence and clean event receipts.
Verify signed assertions at the target seam. Browser evidence must use actual Web
Session and shared ingress; fixture Federated providers are not external OIDC proof.

A write can commit before event failure. Issuance lacks idempotency input; never
blindly retry ambiguous issuance or claim exactly-once semantics. D1 has no query
cancellation API: local abandonment is not rollback. No destructor performs durable
writes. Password, Phone, Device, API Token and OIDC Provider are separate slices.
These changes do not authorize production migration or claim general Auth support.

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
come from Auth-owned `workers/d1.rs`; the Node CI test rejects drift. This small
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
