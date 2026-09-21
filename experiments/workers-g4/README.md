# Representative Workers Auth qualification

This experiment exercises the actual Account, OAuth Flow, Router, Web Session and
OIDC Client Plugins, with Web's event ingress/egress and the shared Workers Driver.
Every event resolves owner-generated Descriptors through HostCatalog and Plugin
Root, creates its own graph and D1 bindings, reaches Ready, invokes typed operations,
and shuts down. Native PostgreSQL is a separate composition with its own evidence;
this experiment does not make a production-default or production-support claim.

The controlled OIDC fixture uses actual HTTP token/JWKS exchange, PKCE and RS256.
It represents a synthetic qualification identity, not a verified external provider
integration. Its signing key lives in a Worker secret, outside the Wasm bundle.
The RPC and browser routes require the dedicated proof key; only fixture JWKS and
client-authenticated token exchange are independently reachable. This is not an
application login service or a production deployment template.

## Local D01 characterization

```sh
# From the repository root; local resources only, no Wrangler deployment config.
bash experiments/workers-g4/profile.sh
```

See [the D01 protocol and current status](../../docs/workers-g4-d01.md) for pinned
tools, cold/warm definitions, the completed matrix and machine-readable evidence.

## OAuth PostgreSQL transport callback cohort

This local `workerd test` builds the generated G4 Rust/Wasm Host and invokes
OAuth through `workers_postgres_factory(execute)`. It covers create,
consume-once, revoke, expiry, fresh-App persistence, a dropped callback response
after its fixture's durable transition, and rejection of a conflicting D1/direct
secret configuration.

```sh
pnpm install --frozen-lockfile
node qualify-oauth-postgres-workerd.mjs
```

The emitted `AUTH_POSTGRES_COHORT_EVIDENCE` is intentionally credential-free
and can be passed to the Runtime target-cohort wrapper. The callback fixture is
an in-memory Host stand-in: this command proves the real generated Workers/Auth
composition and private callback contract under local workerd, but does **not**
qualify a real PostgreSQL server, Hyperdrive, a deployed Worker, client
disconnect behavior, or production operations.

## Fused business session cohort

`qualify-fused-session-workerd.mjs` closes the local session branch of the
real-business-composition slice in one source-pinned G4 HTTP plan. It starts
the generated Host through Miniflare/workerd, applies Account and OAuth owner
migrations through event-owned D1 bindings, and routes real HTTP ingress to a
separate generated `proof.business` Plugin whose typed Auth Port accepts only
the Router-selected App session. Browser navigation reaches a separate local
workerd IdP service directly; the generated HTTP Egress capability uses its
service binding for the OIDC token/JWKS exchange, rather than any direct Auth
or business handler call.

```sh
LENSO_CARGO_CONFIG=/private/source-closure.toml CARGO_NET_OFFLINE=true \
  node qualify-fused-session-workerd.mjs --output /private/fused-session.local.json
```

The credential-free receipt covers unauthenticated rejection, OIDC session
recovery, fresh-workerd D1 recovery, callback replay rejection, CSRF rejection,
and logout cleanup. It proves the **session** branch only: it does not qualify
long-lived streams/WebSockets, deployment, target D1, external identity
providers, or production behavior. See
[`docs/workers-g4-fused-business-session.md`](../../docs/workers-g4-fused-business-session.md)
for the exact composition boundary.

## Build and run

The workspace intentionally uses the reviewed Runtime and Web owner worktrees
shown in Cargo.toml and the JS imports. Assemble these exact owners before building;
source dependencies must be unified, including HTTP Capability crates. A registry
and path copy of the same Capability crate produces distinct native Rust type IDs.

```sh
CARGO=/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo bash build.sh
pnpm install --frozen-lockfile
node_modules/.bin/wrangler d1 migrations apply ACCOUNT_DB --remote
node_modules/.bin/wrangler d1 migrations apply OAUTH_DB --remote
node prepare-secrets.mjs /private/path/g4-secrets.json
node_modules/.bin/wrangler secret bulk /private/path/g4-secrets.json
node --test egress-scope.test.mjs
node_modules/.bin/wrangler deploy
G4_SECRETS=/private/path/g4-secrets.json python3 qualify-egress.py
G4_SECRETS=/private/path/g4-secrets.json python3 qualify.py
G4_SECRETS=/private/path/g4-secrets.json python3 qualify-session.py
G4_SECRETS=/private/path/g4-secrets.json python3 qualify-failure.py
```

Wrangler is pinned to 4.107.0, Rust to 1.94.0, wasm-bindgen CLI to 0.2.127. The
migration commands target the two named task-owned D1 databases in wrangler.jsonc.
Create separate resources and change those IDs when reproducing elsewhere; never
point this fixture at production. `qualify-failure.py` temporarily changes the
Account migration fingerprint and restores it in finally. Run it exclusively after
the other suites. A failed operator command requires inspecting/restoring that
record before using the proof resource again.

Python qualification retries only TLS handshake setup, before HTTP application
bytes are sent. It never retries requests or ambiguous writes. Evidence contains
check names and booleans, not credentials, PKCE values, assertion proofs or keys.
The fixture has explicit private injection switches for missing-table failure,
delayed consume, pending-egress abandonment and generation abandonment; they are not shipped Auth operations.

## Event storage lifetime

Create `createD1StorageScope()` for each event, pass `.bind(database)` into the
owner Rust factory, and wire `.close()`, `.invalidate()` and `.settled()` to the
shared runner. D1 uses primary `batch` reads/writes; there is no Sessions API or
replica read. Invalidation disconnects promise forwarding before Wasm reset without
calling Rust or native I/O. Unabortable native work may still commit; cleanup returns
false after 250 ms, yielding `storage_cleanup_unconfirmed`. Never replay issuance
after uncertainty. Native completion and application cancellation are distinct.

Egress also belongs to this event boundary. `createEgressScope` wraps Web's actual
transport with a separate Rust-facing Promise, clears both callback references
before reset, and aborts Fetch only from the owning finalizer. It tracks raw Fetch,
body reads, reader cancellation and the Web operation. Cleanup checks that no new
pending cancellation remains after its snapshot settles; otherwise it fails closed
under the same 250 ms bound. `invalidate` itself never invokes native I/O or Rust.
The wrapper projects the response fields consumed by the pinned Web adapter; HTTP
validation and response policy remain in Web's shared implementation.

Secrets and test-generated credentials must remain outside the repository. Delete
the private local secrets file and task-owned remote resources after cohort
qualification/rollback work no longer needs them. This experiment disables logging
and Worker preview URLs and does not provision or modify production resources.

See [qualification evidence](evidence/qualification.md) and
[the backend ADR](../../docs/adr/0007-private-workers-auth-storage.md) for exact
scope, results and limitations. Password, Phone, Device, API Token and OIDC Provider
are separate unqualified slices; password parameters have not changed.

## Unified migration qualification

The updated owner Ready gates require common migration history. Existing proof
databases must be explicitly adopted through the owner migration operator before
running these older application suites; Wrangler alone does not establish that
history. Do not run adoption against retained remote resources without a separate
rollout decision. The local-only `migration-proof.mjs` verifies fresh and legacy
paths using fifteen ephemeral D1 databases and the new packaged HTTP Host entry.
See [migration operations](../../docs/storage-migrations.md).
