# Operator binding local D1 proof

This independent fixture compiles the actual Account-owned
`src/storage/operator_binding.rs`, generated `src/migration.rs`, and packaged
`src/workers.rs` through Rust paths. The original Auth D1 JavaScript bridge
executes their real SQL in an ephemeral local workerd D1 database. It does not
copy or reimplement binding SQL or migration verification.

`AccountStore`, `OperatorBindingConfig`, `Record` and request framing are explicit
fixture shims. Synthetic operator identities are seeded directly in the local
base schema to satisfy its foreign key. This proves the private binding storage
transitions and actual generated migration operators. It does not prove the
Kernel, generated Capability, caller ACL, bootstrap time admission, Account
session authentication, Access/Audit workflow, complete App or browser/Ingress.

The standalone Cargo lock pins wasm-bindgen 0.2.127 and matching transport crates,
independent of the candidate's declared Auth .128 cohort. It does not import or
modify external Access/Audit packages. The known .127/.128 full App incompatibility
must be resolved and qualified separately by the relevant owners; this storage
fixture cannot satisfy that gate.

Use Rust 1.94 or newer with the Wasm target, wasm-bindgen CLI 0.2.127, and the
declared local Node tool packages. Run:

```sh
node qualify.mjs /tmp/operator-binding-d1-receipt.json
```

`LENSO_CARGO`, `LENSO_WASM_BINDGEN`, and `CARGO_TARGET_DIR` can select installed
executables and a disposable target directory. `LENSO_WRANGLER_PACKAGE` can
point to an existing Wrangler `package.json`; `LENSO_WORKERS_RUNTIME_PACKAGE`
can point to the installed Workers Runtime `index.mjs`. No production database,
Cloudflare account, real identity, credential or secret is used. Each invocation
cleans up its local persistence and requires event settlement after every call.

The evidence records 14 grouped scenarios, source and fixture hashes before compilation and refuses
to report success if any changes during execution. It covers actual generated
v2/v3 admission without binding mode, missing-v4 refusal without writes, explicit
upgrade and fresh-v4 setup, pending concurrency/idempotency, activation receipt
CAS, issuer/deployment/scope isolation, monotonic revoke revision and first
actor/time, durable pending completion state, completion receipt CAS, and
restart persistence. The `pending`/`complete` revocation fields are an owner
outbox state; this proof does not simulate successful external cleanup or Audit.
