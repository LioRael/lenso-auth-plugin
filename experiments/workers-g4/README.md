# Representative Workers Auth qualification

This experiment exercises the actual Account, OAuth Flow, Router, Web Session and
OIDC Client Plugins, with Web's event ingress/egress and the shared Workers Driver.
Every event resolves owner-generated Descriptors through HostCatalog and Plugin
Root, creates its own graph and D1 bindings, reaches Ready, invokes typed operations,
and shuts down. Native PostgreSQL remains the production default.

The controlled OIDC fixture uses actual HTTP token/JWKS exchange, PKCE and RS256.
It represents a synthetic qualification identity, not a verified external provider
integration. Its signing key lives in a Worker secret, outside the Wasm bundle.
The RPC and browser routes require the dedicated proof key; only fixture JWKS and
client-authenticated token exchange are independently reachable. This is not an
application login service or a production deployment template.

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
node_modules/.bin/wrangler deploy
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
delayed consume and generation abandonment; they are not shipped Auth operations.

## Event storage lifetime

Create `createD1StorageScope()` for each event, pass `.bind(database)` into the
owner Rust factory, and wire `.close()`, `.invalidate()` and `.settled()` to the
shared runner. D1 uses primary `batch` reads/writes; there is no Sessions API or
replica read. Invalidation disconnects promise forwarding before Wasm reset without
calling Rust or native I/O. Unabortable native work may still commit; cleanup returns
false after 250 ms, yielding `storage_cleanup_unconfirmed`. Never replay issuance
after uncertainty. Native completion and application cancellation are distinct.

Secrets and test-generated credentials must remain outside the repository. Delete
the private local secrets file and task-owned remote resources after cohort
qualification/rollback work no longer needs them. This experiment disables logging
and Worker preview URLs and does not provision or modify production resources.

See [qualification evidence](evidence/qualification.md) and
[the backend ADR](../../docs/adr/0007-private-workers-auth-storage.md) for exact
scope, results and limitations. Password, Phone, Device, API Token and OIDC Provider
are separate unqualified slices; password parameters have not changed.
