# G4 representative Auth qualification

Status: representative experimental slice qualified; production rollout and
unlisted Auth Plugins are not qualified by this record.

Auth baseline: `b68d87654e18910e8d14649e48e3166636fa99a1`. Verification completed
2026-09-14 UTC (2026-09-15 Asia/Shanghai). The cohort pins the resulting owner commit
separately. See provenance.json for exact artifact and shared runtime hashes.

## Real target

Worker: `lenso-workers-g4-proof` at
https://lenso-workers-g4-proof.lenso.workers.dev.
Final version: `e840b9ae-2f7a-4c5e-9ca6-d2d3ef3c289d`.
Upload 5458.42 KiB, gzip 1489.70 KiB; observed startup 3 ms. These are deployment
receipts, not a latency or capacity benchmark. Wasm SHA-256:
`916c1986d2af00b076bee7c8b7a475490bc6990ab0272fa320e9740ee31439ce`.

D1 resources are task-owned and separate:

- Account `lenso-workers-g4-account-proof`, `764b88ca-e1ee-4e0d-b707-a70b8949067f`.
- OAuth Flow `lenso-workers-g4-oauth-proof`, `c590163d-3f05-4ddc-af52-a21b13775658`.

Both owner migrations were applied explicitly using Wrangler; preparation verifies
version/fingerprint. Direct verification returned served_by_primary=true and zero
orphan identity subjects. No production resource was used or changed.

## Verified behavior

`storage.json` records 30 passed checks. Eight concurrent events demonstrate one
identity, one revocation change, and one OAuth consumption. Further checks cover
Router authentication, caller allowlists, exact grant scope and nesting, parent
revocation, disable/issuance races, reactivation without revival, credential
revocation, pagination, forbidden-write absence, session/state expiry, temporary
disable expiry, and state queued past expiry. The last case deliberately delays
native batch execution by 3 seconds; the D1-time guard rejects the expired flow.

`session.json` records 13 passed checks using actual WebIngress, WebSession, OIDC
Client, HttpEgress, OAuthFlow, Account and Router. A controlled fixture performs
real HTTPS token/JWKS exchange and RS256 verification, PKCE and nonce handling.
Checks cover safe return paths, two secure cookie fields, HttpOnly policy, target
SDK signature/audience verification, replay rejection, CSRF protection, logout,
and revocation visible in a fresh event. Target SDK projection is a qualification
boundary; this does not implement a product's target authorization policy.

`failure.json` records 11 passed checks. Forced generation abandonment returns a
failure, and the issued session survives replacement. An actual D1 missing-table
error fails preparation without Ready or secret leakage; the next event recovers.
A deliberately mismatched migration fingerprint also fails preparation; restoring
the task-owned record recovers. The test restores it in finally. Corrupt encrypted
PKCE custody also fails closed, and a second consume remains already_consumed.

Every normal request constructs the graph through HostCatalog + Plugin Root using
owner-generated Descriptors, canonical instance keys, explicit provider bindings,
and event-owned factories. Request receipts require Ready and clean shutdown.
No test reconstructs business behavior in JavaScript. JavaScript owns platform I/O
and the synthetic IdP fixture only.

## Local validation

All local Cargo used lenso-cargo +1.94.0. Passed:

- Locked workspace check, all targets.
- Locked workspace tests with include-ignored and one test thread: 77 passed,
  zero failed, zero ignored. The task-owned PostgreSQL 18 instance ran at
  127.0.0.1:55432, including native schema, disable/issue and delegation tests.
- Locked workspace Clippy, all targets, with -D warnings.
- Strict wasm32-unknown-unknown Clippy for all five affected Auth Plugins using
  workers and no default features, plus the composed proof host.
- Root and experiment rustfmt checks, repository ownership tests and diff checks.
- Three Node lifetime tests: admission closes, pending native work settles,
  cleanup is bounded, and late completion cannot forward into abandoned Wasm.

Native default PostgreSQL remains enabled. Public Capability projections and
password parameters are unchanged; no public crate release is part of this work.
CI now checks the Workers owner build and private event storage lifetime.

## Limits and incident notes

This qualifies the representative session/administration/delegation/OAuth-flow
slice. Password, Phone, Device, API Token and OIDC Provider need separate storage,
crypto, provider and composition qualification. The external IdP ecosystem, real
user login, production traffic and multi-region latency/capacity are unqualified.

D1 cannot abort an in-flight query. Writes may commit before event failure; there
is no issuance idempotency key. The event bridge disconnects forwarding before
Wasm reset and returns cleanup uncertainty after 250 ms, never a rollback claim.
Do not blindly retry ambiguous writes. Reads always target the primary.

The shared runner's generation replacement is experimental, using pinned
wasm-bindgen reset support. Owner event factories also depend on pinned generated
constructor/lifecycle names. Native request contracts must share one Cargo source
in a host; duplicate registry/path copies caused a typed ProtocolViolation during
integration and were unified in the experiment's patch set.

Normal resolution exposed pre-existing configuration incompatibilities: slash
separated canonical Plugin keys were rejected by Account/Router, and OIDC's URI
format schema annotation was unsupported. Owner validation now accepts canonical
keys in those positions and retains strict URL validation in Rust. No credential
scheme or authentication policy was relaxed.

Intermittent local TLS handshake failures interrupted earlier runs. The private
Python client retries connection setup only, before HTTP request bytes are sent;
no request or mutation is replayed. Earlier partial runs remain synthetic rows in
the task-owned databases. Final evidence contains no credential or key values.

The coordinator retains the dedicated resources and private secret-file custody
for cohort rollout/rollback checks. Delete these resources and the private file
when that qualification ends. They are not a production installation.

### Package self-containment follow-up

The initial qualification used workspace source paths. Delivery review found that
Account and OAuth Flow imported `workers/d1.rs` from outside their package roots.
Each owner now includes a byte-identical `src/workers.rs`; the Node freshness test
locks both copies to the private canonical transport source.

`CARGO='/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo +1.94.0'
python3 workers/check-packages.py` passed for both owners. It packages and extracts
real Cargo archives, then runs locked `wasm32-unknown-unknown` checks with default
features disabled and `workers` enabled. Account Admin, Auth Delegation and OAuth
Flow Capability archives supply the existing unpublished dependencies. Resolved
metadata confirms every local dependency comes from an extracted archive; no
owner or Capability workspace path substitutes for package contents. All existing
`publish = false` settings remain unchanged. This is a packaging check, not a
claim that these private crates are available from the registry.

Formatting, four Node storage/freshness tests and the repository ownership tests
also pass. This source inclusion correction does not change storage/business
policy. No new deployment was performed; the recorded remote version and Wasm
hash above continue to identify the original G4 qualification artifact.
