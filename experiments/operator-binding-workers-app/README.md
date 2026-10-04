# Operator binding Workers actual App acceptance

This independent, unpublished synthetic Host resolves each actual owner's
`PLUGIN_DESCRIPTOR_JSON` through Registry HostCatalog and PluginRoot. It starts
real Kernel Apps with two Account instances, the OperatorSession workflow,
Access D1, Audit D1, generated Roles/factories, real owner JS adapters and local
workerd/Miniflare D1. The 11 acceptance groups passed; their assertions and real
fault outcomes are recorded in `workers-app.json` and `workers-app.log` under the
task's `artifacts/auth-operator-account-binding` directory.

The Host declares `HostSlot::optional("source_accounts")` with no occupant.
Source Account's Directory requirement selects this empty Slot. Enabled
Operators selects exactly the configured Source Account instance; disabled
Operators also selects the empty Slot. The workflow uses its seven actual
named dependencies. These are Host declarations before PluginRoot resolution;
no handwritten owner Descriptor, capability set or Plan hides the Directory
requirement. Custom Caller and public synthetic Secrets factories declare their
exact fixture version.

Account business configuration uses `with_storage_ref("auth/accounts")` and
`with_storage_ref("auth/operators")` and serializes directly. Target-private D1
attachments carry matching logical references and pass through the actual
Account facility parser. Access retains its existing `ACCESS_DB` configuration
and private state facility, and Audit retains its policy and private store
facility. Those external owner interfaces were not changed.

The run uses actual explicit owner setup: legacy Source Account, operator-bound
Operators Account D1 v4, Access's Rust migration plan and Audit's JS setup.
Readiness does not migrate. All fixture keys, pepper and subjects are public
synthetic inputs. Three SQLite trigger faults interrupt actual owner writes,
without replacing an owner or mocking its storage result. The workflow reports
its actual `audit_unavailable` / `access_unavailable` domain result; a subsequent
same-App request proves Kernel `AdmissionClosed`. Actual shutdown was `Clean`
after that admission closure. Each later operation starts a fresh App in a new
event. Recovery uses a new real Source credential after the source-disable gate
has invalidated the old one, drains the durable Audit outbox and grants no login.

The groups cover formal empty/exact Slot selection, controlled bootstrap,
unbound/wrong-owner/wrong-caller rejection, a finite Access role and durable
requested/applied Audit, distinct credential realms, Auth/Inspect, live login
permission, narrowed management permission, source/feature disable, durable
revocation and recovery, and pending denial after Access or Audit write faults.

The isolated lock selects official Registry Facade 0.5.29, Kernel 0.3.12,
App Plan 0.4.6, Native Adapter 0.3.20 and transport versions
`wasm-bindgen = 0.2.127`, `js-sys = 0.3.104`, `wasm-bindgen-futures = 0.4.77`.
Access is pinned to `94b6d06cff1e6f17a06e771df232f662cae28ad5`; Audit to
`83b4e52e8c6eaf2bbe5356dccd1e3a59b872c8e9`. There is no patch or replace.
Access selects Registry Auth SDK 0.2.3 while local Auth selects SDK 0.2.4; both
use the same Kernel. Wasm-filtered metadata selects 164 packages. The lock has
191 entries, including this fixture. Full versions, features, dependencies and
source hashes are in `workers-cohort.json`. Locked offline check and strict
clippy passed with Rust 1.94.0.

The npm lock pins runtime 0.1.2 and Wrangler 4.136.3. Actual resolved tools were
Miniflare 5.20260921.0-alpha and workerd 1.20260921.1, on Node 26.10.0.
After installing Rust 1.94.0 with its Wasm target, matching wasm-bindgen CLI
0.2.127, and Node 22 or newer, the shortest reproduction from this directory is:

```sh
export RUSTUP_TOOLCHAIN=1.94.0
npm ci --ignore-scripts
npm run test:workers -- /absolute/artifacts/workers-app.json
cargo check --locked --offline --target wasm32-unknown-unknown
cargo clippy --locked --offline --target wasm32-unknown-unknown -- -D warnings
```

The script builds locked Wasm, checks the CLI cohort, resolves the actual owner
JS adapters from Cargo metadata, starts isolated temporary D1 databases, runs
all groups, then disposes workerd and deletes persistence. Cache-only compilation
requires the lock's Registry/Git dependencies already available. Optional
`LENSO_CARGO`, `LENSO_WASM_BINDGEN`, `LENSO_WRANGLER_PACKAGE` and
`LENSO_WORKERS_RUNTIME_PACKAGE` select cached tools; overrides are inventoried in
the receipt. The recorded run used existing cached npm dependencies read-only.

The public RuntimeDriver here supplies only task/timer mechanics reused from
the frozen renewal fixture; Kernel owns scheduling, admission and shutdown. This
is not qualification of the older Registry WorkersDriver package. The synthetic
private bridge invokes protocol-neutral APIs and proves no Relay/HTTP
Ingress/CSRF behavior. The earlier Native acceptance uses a separate graph;
this run does not claim identical serialized Native/Workers graphs. No frozen
renewal run, Root lock, production Auth source, real credential/database,
remote write, deployment or publication is part of this fixture.
