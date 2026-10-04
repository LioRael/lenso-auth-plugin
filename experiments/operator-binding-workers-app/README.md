# Operator binding Workers graph qualification

This independent, unpublished fixture compiles the actual two Account instances,
OperatorSession workflow, Access D1 and Audit D1 owners with their generated Role
contracts and linked factories. It uses Registry Facade 0.5.29, Kernel 0.3.12,
App Plan 0.4.6 and Native Adapter 0.3.20. `Native` in the public adapter/start API
name does not select PostgreSQL; this fixture selects Account's `workers` feature.

The isolated lock selects the official compatible transport cohort:
`wasm-bindgen = 0.2.127`, `js-sys = 0.3.104`, and
`wasm-bindgen-futures = 0.4.77`. Access is pinned to
`94b6d06cff1e6f17a06e771df232f662cae28ad5`; Audit is pinned to
`83b4e52e8c6eaf2bbe5356dccd1e3a59b872c8e9`. There is no Cargo patch or replace.
Access's immutable revision selects Registry Auth SDK 0.2.3 while the local Auth
owners select SDK 0.2.4; both use the same resolved Kernel. The full selected
dependency inventory and source hashes are in `workers-cohort.json` under the
task's `artifacts/auth-operator-account-binding` directory.

Account business configuration declares logical references `auth/accounts` and
`auth/operators` through `with_storage_ref`, then serializes directly. The Host
passes private per-instance D1 attachments through each actual owner facility
parser. Account attachments must carry their matching `storage_ref` and owner
JS `{ name, batch }` interface. No Host helper rewrites business configuration
according to target. Access and Audit retain their existing external owner
interfaces: Access still has its legacy `ACCESS_DB` binding configuration and
Audit has a private store attachment. This fixture does not change those owners.

`plan` authors the lower-level synthetic Host composition with the workflow's
seven authoring-v2 named dependencies. Operators Directory binds exactly to the
source Account instance. `registry` links all four actual owner factories and
their typed facilities. `start_app` compiles the public Kernel start seam for a
Host-supplied RuntimeDriver; `bootstrap_binding` compiles the actual generated
OperatorSession operation. Only caller placeholders and a public synthetic
Secrets provider are fixture implementations. All key/pepper values in this
source are public test inputs.

From this directory, using Rust 1.94.0 with its installed Wasm target:

```sh
cargo check --locked --offline --target wasm32-unknown-unknown
cargo clippy --locked --offline --target wasm32-unknown-unknown -- -D warnings
```

Both commands passed for the final logical-reference source. Their logs are
`workers-cohort.log` and `workers-cohort-clippy.log` in the same artifact directory.
The lock contains 191 entries (190 dependencies plus this fixture);
platform-filtered Wasm metadata selects 164 packages including the fixture.
Compared with the separate Native fixture manifest, this manifest removes its
PG runner/test dependencies, selects the actual D1 owners and Account workers
feature, and pins the three compatible official transport versions.

This is narrow graph and source compilation evidence. It does not execute
workerd, migrate D1, prove D1 transaction behavior, or prove the Native and Workers
Hosts use an identical serialized App graph. Runtime qualification still needs
a real event Driver, owner JS adapters and migrated synthetic D1 bindings. The
frozen renewal fixtures, Root lock and production Auth implementation were not
changed by this qualification.
