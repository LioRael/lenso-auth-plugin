# OAuth Flow reference composition

This document is the executable reference for a security-sensitive, atomic
Auth operation across environments. It applies to the `create`, `consume`, and
`revoke` operations in `lenso.auth.oauth-flow@1` descriptor version 1.2.0.

## Invariants

- One state can reach only one terminal transition: consumed or revoked.
- A provider mismatch never consumes or revokes the state.
- An expired state reaches neither terminal success path.
- A caller may observe an uncertain runtime failure after a durable commit. It
  must reconcile by reading/retrying through the same business operation, not
  blindly replay the original mutation.
- Restart recreates Plugin-owned resources but retains state in the selected
  private persistence implementation.

## Local executable evidence

Run the deterministic reference, including a real resolved Plan and generated
native endpoint:

```sh
cargo test --locked -p lenso-auth-oauth-flow-plugin \
  --features simulator-test-support --test simulated_reference
```

The test owns no production clock, entropy, database, Worker, or network
resource. It is therefore repeatable and suitable for fault exploration, but
is not a target-platform qualification.

`test_app_receipt_records_an_uncertain_consume_through_the_real_kernel_path`
uses Runtime's `TestApp` and `TestSimulator`, rather than a simulator-only
provider call. It starts the resolved Plan through the native Adapter, invokes
the OAuth Capability through Kernel routing, supplies explicit `TestEntropy`,
injects a one-shot post-commit dropped-connection fault at the Auth-private
boundary, restarts the App, and asserts the bounded `ScenarioReceipt`:
virtual timestamp, generation, operation, durable transition, injected fault,
and terminal result. The receipt contains no state value, secret, or payload.

The exact Contract projection is locked by its authoring source:

```sh
cargo test --locked -p lenso-capability-oauth-flow
lenso-contract-codegen check crates/lenso-capability-oauth-flow/capability.json \
  --rust crates/lenso-capability-oauth-flow/src/generated.rs
```

## Target gates

| Composition | Required additional evidence | Current local command |
| --- | --- | --- |
| Native + PostgreSQL | real migration, transaction, timeout/cancellation and restart behavior against disposable PostgreSQL | `LENSO_POSTGRES_TEST_URL=... cargo test --locked --workspace -- --include-ignored --test-threads=1` |
| Workers + D1 | workerd lifecycle, D1 batch outcomes, event abandonment and owner migration readiness | `node experiments/workers-g4/qualify-oauth-d1-workerd.mjs` for bounded local evidence; an operator target receipt for promotion |
| Workers + PostgreSQL transport | event-owned callback, PostgreSQL transaction, transient failure, timeout, cancellation and uncertain commit | Workers Host qualification harness with an explicit target-owned PostgreSQL/Hyperdrive resource |

The last two rows do not become passing merely because the Rust Workers target
compiles. They require a Host receipt that identifies the exact target,
artifact, migration state, and failure observation without recording secrets or
OAuth payloads.

## Hyperdrive rule

Hyperdrive is a Workers transport to PostgreSQL, not another OAuth database
kind. Only a Workers Host is allowed to know its binding name, connection
configuration, and lifecycle. The OAuth Plugin receives one event-owned
private callback and cannot fall back from it to D1 or direct SQLx.

## Local workerd callback cohort

The Auth-owned local workerd cohort executes generated G4 Rust/Wasm, starts a
fresh OAuth App for each operation, and injects the exact
`workers_postgres_factory(execute)` private callback. It proves create,
consume-once, revocation, expiry, restart persistence, post-commit response
loss reconciliation, and factory rejection of a D1/direct-secret conflict.

```sh
pnpm --dir experiments/workers-g4 install --frozen-lockfile
node experiments/workers-g4/qualify-oauth-postgres-workerd.mjs
```

It emits one credential-free `AUTH_POSTGRES_COHORT_EVIDENCE` line for the
Runtime cohort wrapper. The fixture's private callback is deliberately an
in-memory Host stand-in, so its passing result is **local workerd callback
composition only**. It is not PostgreSQL, Hyperdrive, deployed Worker, client
disconnect, or production qualification. A target-owned Host must separately
run the same contract against its actual Hyperdrive/PostgreSQL resource and
attach that receipt before the combination is promoted.

## Local workerd D1 cohort

The D1 cohort uses the same generated G4 Rust/Wasm Host and real Kernel
Capability invocation path, but injects two ephemeral Miniflare/workerd D1
bindings through the Auth-owned `createD1Binding` boundary. It first applies
the Account and OAuth owner migrations through the generated migration entry,
then checks create persistence, concurrent consume-once, revocation across a
fresh workerd and Kernel App, expiry, and a test-only post-durable application
response loss followed by a terminal-state retry:

```sh
pnpm --dir experiments/workers-g4 install --frozen-lockfile
node experiments/workers-g4/qualify-oauth-d1-workerd.mjs
```

When an exact local source-closure configuration is required, pass its
credential-free Cargo configuration path through `LENSO_CARGO_CONFIG`; the
cohort forwards it only to the locked Wasm build and never records its path or
contents in the receipt.

It emits `AUTH_D1_COHORT_EVIDENCE` with source and Wasm digests, case names,
and no credentials or OAuth payloads. This remains **local workerd evidence**:
it does not satisfy the Workers+D1 target requirements or make a deployed,
release, or production claim. In particular, deployed D1 behavior, external
client disconnect, long-session lifecycle, and target failure recovery require
their own exact candidate receipt.
