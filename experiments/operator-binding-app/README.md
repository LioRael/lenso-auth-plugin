# Synthetic operator binding App acceptance

This independent fixture composes two actual Account Instances, the current
Operator Session workflow, real Access Control PostgreSQL at Git
`94b6d06cff1e6f17a06e771df232f662cae28ad5`, real Audit Log PostgreSQL at Git
`83b4e52e8c6eaf2bbe5356dccd1e3a59b872c8e9`, and Registry Kernel `0.3.12` with
Facade `0.5.29`. Its own Cargo lock identifies the complete graph. There is no
mock Auth, Access, Audit, storage, migration or Kernel implementation.

The synthetic Host supplies explicit composition, canonical caller Instances and
public synthetic Secrets. Workflow authoring v2 uses each generated named
requirement. The operators Account's optional Directory requirement resolves
exactly to `lenso.auth.account/accounts`. Each protocol endpoint and operation
list comes from the actual generated Role projection. There is no Relay plugin,
HTTP ingress, Cookie or CSRF qualification in this protocol-neutral proof.

## Run

Use Rust `1.94.0` and the isolated local PostgreSQL fixture:

```sh
cargo fetch --manifest-path experiments/operator-binding-app/Cargo.toml --locked
LENSO_POSTGRES_TEST_URL=postgres://renewal_fixture@127.0.0.1:55494/postgres \
LENSO_OPERATOR_BINDING_RECEIPT=/outside/source/native-app.json \
  cargo test --manifest-path experiments/operator-binding-app/Cargo.toml \
  --locked --offline --test native_binding -- --ignored --nocapture
```

Only that exact local URL is admitted. CI additionally permits the exact URL
`postgres://postgres@localhost:5432/postgres` with `GITHUB_ACTIONS=true`. The
synthetic role needs CREATE DATABASE authority. Each scenario creates a database
named `operator_app_<process-id>_<scenario>`, explicitly runs Account's ordinary
accounts setup and new `setup_operator_bound` for operators, and invokes the
existing Access/Audit setup operators. Successful scenarios clean up only their
own database. The fixed Audit `audit_log` schema never touches another test's
schema. Runtime Ready does not migrate. All keys, pepper and credentials are
synthetic; actual issued credentials never enter logs or evidence receipts.

## Verified behavior

The 12 groups cover exact owner caller and confirmed source subject, rejection
of unbound ordinary users, distinct operators identity and issuer, current
source-account disable, binding mode disabled, narrower credential ceiling,
current scoped Access permission, pending bindings after Access/Audit failures,
durable revoke-before-cleanup, and controlled owner revocation recovery. A
bootstrap has a ten-minute synthetic window. The explicit business role grants
exactly `synthetic.settings.write`, `access-control.bindings.manage`, and the
workflow-owned login permission. The protected Access bootstrap role retains
only its existing finite Access administration authority. Arbitrary business
permissions and wildcard requests receive no grant.

The test narrows the current operators credential ceiling to business-only
permissions and proves it cannot revoke even while the protected Access grants
remain. Separately removing the live Access management grant denies a credential
whose own ceiling permits management. This tests both authorization boundaries.

Failure injection uses temporary PostgreSQL triggers to fail the real Audit
append or Access role insert. These are deliberate RuntimeFailures; Kernel
supervision closes admission. The fixture then shuts that App down and starts a
fresh real App against the same durable state. It verifies pending bindings deny
exchange and revoked bindings deny Auth/Inspect. The synthetic failure trigger
is removed before confirmed source-owner recovery. Recovery completes cleanup
and durable audit, preserves the original operators revoker, and never grants a
new operators session. No cross-database transaction or automatic retry is
claimed.

## Qualification limits

This is local synthetic Native acceptance, not candidate CI or production
bootstrap consent. Real source subject, deployment scope and finite permission
list still belong to the separate owner confirmation and deployment workflow.
No remote writes, publication or production migration occurred.

Full Workers D1 acceptance is not included. The supplied Access and Audit D1 Git
packages pin Wasm Bindgen `0.2.127`/futures `0.4.77`; the previously qualified Auth
Workers graph uses `0.2.128`/`0.4.78`. A compatible declared D1 graph and matching
CLI need their own qualification. This fixture does not patch those owners or
substitute a generic store abstraction.
