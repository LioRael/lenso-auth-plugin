# Synthetic complete managed-session App acceptance

This fixture uses actual candidate Account, Password, ManagedSession generated
clients and Session Renewal plugins, the actual Registry Kernel `0.3.12`, and
Registry Web Ingress `0.4.11` with nominal HTTP Endpoint `0.3.7`. Its independent
Cargo lock identifies the full test graph. No Core patch or duplicated Auth,
CSRF, migration or Store implementation is used.

The fixture Host owns only composition, public synthetic Secrets, invocation
framing and temporary resource custody. Account and Password remain removable
linked plugins. The browser renewal request goes through the real Ingress
Cookie selection, credential ambiguity rejection and double-submit CSRF checks.
Account admits only canonical `lenso.auth.password/default` issuance and
`lenso.auth.session-renewal/default` renewal callers. A separately bound caller
cannot renew despite having the capability binding.

## Native PostgreSQL

Run against the isolated temporary fixture only:

```sh
LENSO_POSTGRES_TEST_URL=postgres://renewal_fixture@127.0.0.1:55494/postgres \
  cargo test --manifest-path experiments/managed-session-app/Cargo.toml \
  --locked --offline --test native_ingress -- --ignored
```

The test permits that local URL prefix, or the exact ephemeral CI service URL
`postgres://postgres@localhost:5432/postgres` only with `GITHUB_ACTIONS=true`. It
explicitly invokes `setup_managed` for
Account and the ordinary Password setup operator, and drops only its newly
created schemas. Runtime Ready never migrates. Only this test needs local socket
access through the execution sandbox. Test credentials and signing material are
public synthetic inputs.

## Local Workers D1

```sh
cd experiments/managed-session-app
LENSO_CARGO=/absolute/path/to/cargo \
LENSO_WASM_BINDGEN=/absolute/path/to/wasm-bindgen-0.2.128 \
LENSO_WRANGLER_PACKAGE=/absolute/path/to/wrangler/package.json \
LENSO_WORKERS_RUNTIME_PACKAGE=/absolute/path/to/workers-runtime/index.mjs \
  node qualify-workers.mjs /outside/source/acceptance.json
```

Run `npm ci --ignore-scripts` first. The script requires the frozen npm
dependencies in `package-lock.json` (`wrangler
4.136.3`, Workers Runtime `0.1.2`); the two package overrides support existing
local installations without writing them. It builds the actual candidate with
Wasm Bindgen `0.2.128`, starts local workerd with two dedicated temporary D1
databases, explicitly invokes both owners' Rust setup operators, tests through
fresh complete Apps, and deletes only its temporary resource directory. It
neither publishes nor deploys anything.

The synthetic Workers Host implements the released public `RuntimeDriver`
trait with ordinary Wasm local spawning and JS timer mechanics. This is needed
because cached Registry Workers Driver `0.1.1` pins Kernel `0.3.11` and Wasm
Bindgen `0.2.127`. This proof does **not** qualify that older Driver package or a
production Host. Ingress, Auth lifecycle, generated capability dispatch, D1
transport, migration verification and durable session operations remain actual
candidate implementations. Event scopes settle every bridge before return.

## Acceptance scope

The complete chain proves renewal success and secure Cookies, rotated old-token
authentication rejection, one-winner concurrent refresh with retryable stale
and zero failure `Set-Cookie`, real CSRF/ambiguity rejection before mutation,
exact Origin rejection, canonical caller isolation, TooEarly no writes, current
Cookie GET validation, absolute expiry without revival, and narrower fixed
Account policy after App restart. The generated CredentialState client reports
inactive sessions and the same clipped expiry used by Auth. Local D1 also checks
historical-digest revocation through the existing generated issuer, persistent
replay rejection after local runtime restart, and successful rotation followed
by response loss. That lost response cannot reconstruct the new plaintext token:
one old-Cookie state read is stale, and re-login is required. No failed response
clears or replaces a newer browser Cookie, and no business operation is retried.

Private `/fixture/*` routes and fixture operations are local harness framing,
never production endpoints. Historical-digest logout here exercises the existing
protocol-neutral issuer from the explicitly bound synthetic caller. A product's
HTTP logout must retain its real Ingress CSRF admission and caller binding; this
fixture does not authorize exposing the private fixture issuer operation.

## Local verification evidence

Native real App acceptance passed with Rust `1.94.0` (also `1.99.0`); Workers
full App passed
12 acceptance groups with Rust `1.94.0` and Wasm Bindgen `0.2.128`. External
receipts retain exact lock and Wasm hashes; no binaries or test credentials are
tracked. CI uses the same source and locked graph with Rust `1.94.0`.

An earlier fixture revision incorrectly authored the stateless renewal Instance
as authoring v1 and failed during Ingress activation. The corrected Host uses
the actual plugin's authoring v2 and named `managed_sessions` dependency. That
obsolete fixture failure was resolved without changing Core or Ingress.

CI entry points are the Native command above (using the guarded CI URL), and
`node experiments/managed-session-app/qualify-workers.mjs /tmp/acceptance.json`
after `npm ci --ignore-scripts` in this fixture. Set `LENSO_WASM_BINDGEN` to the
matching `0.2.128` CLI if it is outside PATH; package overrides are unnecessary
with the frozen npm installation. For isolated local toolchains also set
`RUSTUP_HOME`, `RUSTUP_TOOLCHAIN`, `RUSTC`, and `LENSO_CARGO` consistently.
