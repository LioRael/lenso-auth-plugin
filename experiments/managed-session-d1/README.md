# Managed session local D1 proof

This isolated fixture compiles the actual Account-owned
`src/storage/d1.rs`, `src/storage/d1_managed.rs`, and `src/workers.rs` through
Rust source paths. It uses the actual Auth-owned JS D1 bridge and primary D1
batch transactions in local workerd/Miniflare. Only model and request framing
are fixture shims; SQL is not copied or reimplemented. This proves the storage
transition, not the generated Capability, Kernel caller ACL, Password login,
CSRF ingress, Cookie adapter, or complete App composition.

Install the declared local Node development dependencies, use Rust 1.94 with
the `wasm32-unknown-unknown` target, and use `wasm-bindgen-cli` 0.2.127 (matching
this independent fixture's committed Cargo lock). Run:

```sh
node qualify.mjs /tmp/managed-session-d1-receipt.json
```

The local listener may need the execution environment's sandbox permission.
No remote Cloudflare account, service, credentials, or production database is
used. Every run creates an ephemeral local D1 database, applies the actual owner
SQL migrations explicitly, and deletes the fixture persistence directory after
the test. This is not an automatic production migration workflow.

When already-installed read-only tool packages are outside this directory,
`LENSO_WRANGLER_PACKAGE` may identify their `wrangler/package.json` and
`LENSO_WORKERS_RUNTIME_PACKAGE` the Workers Runtime `index.mjs` entry. The
fixture records the actual Wrangler, Miniflare, and wasm-bindgen versions.
`LENSO_CARGO` and `LENSO_WASM_BINDGEN` can select matching executables.

The receipt records actual owner source hashes and 25 grouped scenarios:
single-winner concurrent rotation, write-free stale/TooEarly/expiry rejection,
historical-token revocation after multiple rotations, revocation/disable races
in both orders, narrower policy and frozen upper bounds, atomic constraint
rollback, legacy issue/revoke and delegated-child compatibility, response loss,
and restart persistence. Read-only managed metadata is credential-free, performs
no durable writes, works before renewal is due, and rejects the same stale,
revoked, expired, legacy, and delegated credentials. Current idle-policy
narrowing also rejects already-idle sessions; it cannot revive them by issuing
a new shorter window. New rotation digests cannot equal the current or a
historical digest. The private read-only policy bound also applies a managed
parent's narrowed idle or absolute deadline to its delegated child, while
preserving the child's own earlier expiry and legacy behavior. Delegated
credentials remain unsupported for renewal and public managed metadata.

The browser must interpret stale as retryable competition, preserve the newer
Cookie, and at most revalidate the current Cookie once. The fixture does not
retry a renewal or authentication-side business mutation. If the winning
rotation response is lost before the browser receives the new Cookie, the old
credential cannot recover a plaintext replacement from a digest-only ledger:
the user must sign in again. Browser and Cookie behavior has its own adapter
tests outside this storage fixture.

This fixture's private Wasm transport tool versions are independent from the
candidate's declared facade/Capability cohort. Candidate Native/Workers checks
must separately compile the actual declared dependencies; the fixture is not a
substitute for those checks or full candidate CI.
