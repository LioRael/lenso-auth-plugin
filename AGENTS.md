# Agent instructions

The default `main` branch is Lenso vNext-only. The `v0.3` branch and existing
package tags retain the previous implementation and release history.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before preparing or importing changes.

Before architecture or implementation changes, read `CONTEXT.md`, the local
ADRs under `docs/adr/`, and the normative Lenso ADRs linked from them. Before
changing or executing a release, read `docs/release-process.md`.

Create task worktrees from the latest `origin/main` with `wt switch --create`.
Preserve unrelated dirty work and run Cargo through
`/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo` when
available.

Keep the Auth Interface protocol-neutral. Ingress Adapters own credential
extraction; Auth owns authentication and assertion issuance; target Plugins own
authorization. Do not add HTTP, database, Redis, Console, v0.3 platform, or
product release concerns to the portable Auth crates.

The annotated Rust contract in each native Capability crate is the authoring
source. Its Descriptor, Schemas, and Rust projection are committed locked
artifacts and must never be hand-edited. Set
`LENSO_UPDATE_CONTRACT_SNAPSHOT=1` only for an intentional contract change,
then regenerate the Rust projection through `lenso-contract-codegen`. The
supported Bun SDK owns and locks its independent TypeScript projection.

Use a concise imperative Conventional Commit subject under 72 characters.
Validate with focused checks for the changed files. Candidate CI is the
authoritative full Auth lifecycle/session/credential/authorization/native/WASM/
database proof; use package dry-runs only for changed public crates.
