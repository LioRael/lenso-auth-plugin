# Account and Password storage references

Account and Password accept the same target-neutral `storage_ref` configuration
field. Each Instance names its own logical storage resource. Keep the existing
schema namespace and all issuer, signing/pepper, TTL, audience and caller settings.
Do not put a connection string or credential in this field.

A nonempty `storage_ref` excludes both `database_url_secret` and `d1_binding`.
The default-empty field preserves old serialized configurations and constructors.
`with_storage_ref(reference)` explicitly switches an existing config to the new
mode; Account's existing `with_d1_binding` explicitly switches back to legacy D1.

## Private attachment

The source-owned `state` facility retains these target entrypoints:

- Native: `state(&serde_json::Value) -> Result<EventStorageBinding, RuntimeFailure>`
- Workers: `state(&wasm_bindgen::JsValue) -> Result<EventStorageBinding, RuntimeFailure>`

For Native with `postgres`, the owner payload contains only logical references:

```json
{"storage_ref":"auth/account","database_url_secret":"auth/account/database"}
```

Parsing does no Secrets or database I/O. During activation, the attachment's
reference must equal the Instance config. Account also requires the database
Secrets reference to differ from its signing and pepper references. The original
Secrets capability resolves the database location, then the original
`OwnedPostgres::prepare` verifies the owner schema and constructs the original
Account/Password Store. It never applies migrations.

Workers calls the package-local `src/host_facilities/state.mjs` with its actual
D1 binding, its fresh event scope, and the owner configuration:

```json
{"profile":"workers-d1","binding":"ACCOUNT_D1","storage_ref":"auth/account"}
```

The returned value contains `storage_ref`, the original physical `name`, and the
original event-scoped `batch` transport. The Rust factory constructs the private
attachment. Activation checks the logical reference and performs the original
`migration::verify` before exposing the original D1 Store. The bridge uses the
primary database batch transport and retains event-scope cleanup ownership.

Target resource-selection metadata belongs to the App's resource projection;
it is not an additional Auth configuration or owner payload field. The owner
parsers reject extra payload fields. Relay's existing Workers resource projection
can continue stripping its `implementation` metadata before calling this adapter.
Native resource projection must pass the two owner fields above.

## Compatibility and ownership

Legacy PG configurations do not require a facility. Legacy D1 configurations
still require their exact physical binding name. Existing `workers_factory`
signatures remain unchanged and construct legacy attachments; they do not accept
the new logical mode. The adapter's old two-field `profile`/`binding` configuration
remains accepted. A legacy attachment cannot satisfy a logical config, and a
logical attachment cannot silently override a legacy config.

Missing/mismatched attachments fail activation before Secrets or database I/O.
No failed selection falls back to another transport or memory. Account and
Password retain their distinct schemas and access authority even if an operator
chooses one physical cluster. Deactivation closes the original owner Store.

This change does not modify SQL, migrations, portable Capability contracts,
Role identities, authorization, assertion issuance, password verification, or
session expiration. It needs no data migration. Operators update only App
configuration and private target attachments when opting into logical mode.

## Source cohort and consumption

The task worktree was created from main `8bc57d12063a2616863dbc4fb8428f8936775e14`
and fast-forwarded to its direct existing candidate successor
`699bd9621bc2e7f8581f6c0ff0bcbfcb6e3c2167`. That prerequisite changes only the root
manifest/lock and Human API Token manifest. This storage slice is a successor of
Auth699 and leaves that declared dependency cohort and lock unchanged, including
HTTPEndpoint 0.3.7. Main has not been changed. The candidate's own locked Native
and Workers checks provide its compile evidence; Core c47 source consumption is
an independent App integration check.

Relay should replace its exact Auth699 owner snapshot with the admitted successor
Account/Password sources (including their new local facility files), preserve its
existing nominal Role/source patch policy, then update the common Instance config
and both target resource grants. Do not overlay the old D1-only facility patch
on the successor. If Relay retains its Cargo path-to-Git projection for shared
Auth Role crates, reapply that dependency-only projection to the new exact source;
do not change the portable Role source. This local candidate is not a package
publication, remote landing, or full App qualification.

## Focused validation

The candidate is checked directly with Rust 1.94.0 and its committed Cargo.lock:

```sh
cargo fmt --all -- --check
cargo clippy --offline --locked -p lenso-auth-account-plugin -p lenso-auth-password-plugin --all-targets -- -D warnings
cargo test --offline --locked -p lenso-auth-account-plugin -p lenso-auth-password-plugin --lib storage_reference
cargo test --offline --locked -p lenso-auth-account-plugin --test source_configuration
cargo clippy --offline --locked --target wasm32-unknown-unknown --no-default-features --features workers -p lenso-auth-account-plugin -p lenso-auth-password-plugin -- -D warnings
cargo test --offline --locked --no-default-features --features workers -p lenso-auth-account-plugin -p lenso-auth-password-plugin --lib storage_reference
node --test crates/lenso-auth-account-plugin/tests/source-facility.test.mjs crates/lenso-auth-password-plugin/tests/source-facility.test.mjs
```

Native tests verify typed payloads, mutual exclusion, missing/mismatched attachment
rejection, distinct secret references and legacy config/schema acceptance without
I/O. Workers feature tests on Native use an uncalled reserved JS handle to test
the real D1 selection branch; they do not exercise JavaScript transport or D1 SQL.
Node tests exercise each real adapter with in-memory database/event-scope stubs.
The Wasm check compiles the actual Workers factory and activation paths. No real
PG/D1, production secret, network database, full App build or candidate CI has
been used in this slice. Database readiness/migration and complete session/Auth
runtime qualification remain required downstream evidence.

The additional no-storage-feature check fails in both the original Auth699 and
this candidate (Password's missing Tokio `spawn_blocking`, empty Store match
coverage and inferred Store type). That unselected combination is not qualified
here. The requested Native `postgres` and Workers `workers` combinations pass;
no unrelated empty-Store or password-work feature refactor is included.
